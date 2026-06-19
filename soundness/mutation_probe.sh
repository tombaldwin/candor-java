#!/usr/bin/env bash
# mutation_probe.sh — META-soundness: does candor-java's OWN soundness suite actually CATCH soundness
# regressions? A test suite that only ever passes proves nothing. This harness INJECTS a curated list of
# known soundness bugs into the engine (Candor.java), rebuilds, runs the probe that SHOULD catch each, and
# records CAUGHT (probe went red) or MISSED. A MISSED mutation is a blind spot in our tooling — the valuable
# finding. It prints a results table + a detection rate and lists every blind spot.
#
# Each mutation is a PRECISE text edit on a unique multi-line anchor in Candor.java (applied via the embedded
# python `patch` helper, which ASSERTS the anchor is present-and-unique so a refactor that moves the code
# fails loud instead of silently no-op'ing). The ORIGINAL file is snapshotted once up front and restored
# after every mutation (and on any exit), so the working tree is left exactly as found.
#
#   bash soundness/mutation_probe.sh            # run the full curated list
#   MUT="net_dns exec_pb" bash soundness/mutation_probe.sh   # run only the named mutations
#
# Runtime: ~one incremental gradle build + one targeted probe per mutation (~60-70s total). Not wired into
# the default run.sh (it rebuilds the engine N times) — run it on demand / in a dedicated CI lane, and
# ADD A PAIRED MUTATION whenever a new κ leaf or analysis hook is added (that keeps the suite teethed).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SRC="src/main/java/io/poly/candor/Candor.java"
ORIG="$(mktemp)"
cp "$SRC" "$ORIG"
restore() { cp "$ORIG" "$SRC"; }
trap 'restore; rm -f "$ORIG"' EXIT

GRADLE="./gradlew"; [ -x "$GRADLE" ] || GRADLE="gradle"
CJ="$ROOT/build/install/candor-java/bin/candor-java"

# ---- patch helper: apply a unique-anchor replacement, asserting the anchor exists exactly once ----
apply_patch() {  # $1 = OLD, $2 = NEW
  OLD="$1" NEW="$2" python3 - "$SRC" <<'PY'
import os, sys
p = sys.argv[1]
old = os.environ["OLD"]; new = os.environ["NEW"]
s = open(p).read()
n = s.count(old)
if n != 1:
    sys.stderr.write(f"ANCHOR ERROR: found {n} occurrences (need exactly 1) of:\n{old}\n")
    sys.exit(3)
open(p, "w").write(s.replace(old, new, 1))
PY
}

rebuild() { "$GRADLE" -q installDist shadowJar >/tmp/mut_build.log 2>&1; }

# ---- probe runners: return 0 if the probe PASSED (green), non-zero if it FAILED (red = mutation caught) ----
run_kappa()       { CJ="$CJ" python3 "$ROOT/soundness/kappa_probe.py"           >/tmp/mut_probe.log 2>&1; }
run_kappa_libs()  { CJ="$CJ" python3 "$ROOT/soundness/kappa_libs_probe.py"      >/tmp/mut_probe.log 2>&1; }
run_smear()       { CJ="$CJ" python3 "$ROOT/soundness/smear_probe.py"           >/tmp/mut_probe.log 2>&1; }
run_funcsam()     { bash "$ROOT/soundness/functional_sam_probe.sh"              >/tmp/mut_probe.log 2>&1; }
run_fuzzer()      { SEEDS="$(seq 1 40)" bash "$ROOT/soundness/run.sh"           >/tmp/mut_probe.log 2>&1; }
run_sweeptest()   { "$GRADLE" test --tests io.poly.candor.SoundnessSweepTest -q >/tmp/mut_probe.log 2>&1; }
run_junit()       { "$GRADLE" test --tests io.poly.candor.HelpersTest -q         >/tmp/mut_probe.log 2>&1; }

# ---------------------------------------------------------------------------------------------------------
# CURATED MUTATIONS. NAME | PROBE | EXPECT (caught/silent) | description.
# ---------------------------------------------------------------------------------------------------------
declare -a NAMES PROBES EXPECTS DESCS
add() { NAMES+=("$1"); PROBES+=("$2"); EXPECTS+=("$3"); DESCS+=("$4"); }

add net_dns      run_kappa       caught "InetAddress.getByName DNS lookup -> pure (silent Net under-report)"
add net_socket   run_kappa       caught "java.net.Socket-family / NIO socket-channel Net rule -> null"
add fs_files     run_kappa       caught "java.nio.file.Files / FileChannel / file-stream Fs rule -> null"
add exec_pb      run_kappa       caught "ProcessBuilder.start/startPipeline -> null (silent Exec)"
add log_syslogger run_kappa      caught "drop java.lang.System\$Logger from the Log gate (silent System.Logger.log)"
add env_getenv   run_kappa       caught "System.getenv -> null (silent Env)"
add rand_uuid    run_kappa       caught "UUID.randomUUID -> null (silent Rand)"
add jackson_file run_kappa_libs  caught "jackson ObjectMapper File/Path->Fs, URL->Net rule -> disabled (library κ gap)"
add named_sam    run_sweeptest   caught "functionalSamSurface() returns empty (named SAM/Comparator into HOF goes pure)"
add cha_edges    run_fuzzer      caught "skip edges.addAll(targets) — CHA-resolved bodies never linked (chain under-report)"
add cb_unknown   run_funcsam     caught "disable the JDK-functional-SAM callback:Unknown gate (lambda-only dispatch silent)"
add deferred     run_smear       caught "disable bindDeferredFields — stored/deferred lambda invocation silent"
add clock_now    run_junit       caught "java.time .now() (OffsetDateTime/LocalTime/Year) Clock rule -> null"
add sanity_noop  run_kappa       silent "no-op comment insertion (control: probe must stay green)"

patch_for() {
  case "$1" in
  net_dns)
    apply_patch \
'|| (owner.equals("java.net.InetAddress")
                    && (method.equals("getByName") || method.equals("getAllByName")
                        || method.equals("getLocalHost") || method.equals("getCanonicalHostName")))' \
'|| (owner.equals("java.net.InetAddress")
                    && (method.equals("__MUTANT_never__")))' ;;
  net_socket)
    apply_patch \
'                || (owner.equals("javax.management.remote.JMXConnector")
                    && (method.equals("connect") || method.equals("getMBeanServerConnection"))))
            return "Net";' \
'                || (owner.equals("javax.management.remote.JMXConnector")
                    && (method.equals("connect") || method.equals("getMBeanServerConnection"))))
            return null; // MUTANT (was "Net")' ;;
  fs_files)
    apply_patch \
'                || owner.equals("java.util.zip.ZipFile") || owner.equals("java.util.jar.JarFile"))
            return "Fs";' \
'                || owner.equals("java.util.zip.ZipFile") || owner.equals("java.util.jar.JarFile"))
            return null; // MUTANT (was "Fs")' ;;
  exec_pb)
    apply_patch \
'if (owner.equals("java.lang.ProcessBuilder")
                && (method.equals("start") || method.equals("startPipeline"))) return "Exec";' \
'if (owner.equals("java.lang.ProcessBuilder")
                && (method.equals("start") || method.equals("startPipeline"))) return null; // MUTANT' ;;
  log_syslogger)
    apply_patch \
'|| owner.equals("java.lang.System$Logger")) {' \
'|| owner.equals("java.lang.System$__MUTANT_never__")) {' ;;
  env_getenv)
    apply_patch \
'if (owner.equals("java.lang.System") && method.equals("getenv")) return "Env";' \
'if (owner.equals("java.lang.System") && method.equals("getenv")) return null; // MUTANT' ;;
  rand_uuid)
    apply_patch \
'if (owner.equals("java.util.UUID") && method.equals("randomUUID")) return "Rand";' \
'if (owner.equals("java.util.UUID") && method.equals("randomUUID")) return null; // MUTANT' ;;
  jackson_file)
    apply_patch \
'            if (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")) return "Fs";
            if (desc.startsWith("(Ljava/net/URL;")) return "Net";' \
'            if (false) return "Fs"; // MUTANT
            if (false) return "Net"; // MUTANT' ;;
  named_sam)
    apply_patch \
'static Set<String> functionalSamSurface(String classInternal) {' \
'static Set<String> functionalSamSurface(String classInternal) {
        if (true) return new java.util.HashSet<>(); // MUTANT' ;;
  cha_edges)
    apply_patch \
'                        List<String> targets = broad ? List.of() : cha;
                        edges.get(id).addAll(targets);' \
'                        List<String> targets = broad ? List.of() : cha;
                        // MUTANT: edges.get(id).addAll(targets);' ;;
  cb_unknown)
    apply_patch \
'if (!broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                                && isJdkFunctionalSam(min.owner, min.name)) {' \
'if (false && !broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                                && isJdkFunctionalSam(min.owner, min.name)) {' ;;
  deferred)
    apply_patch \
'            if (mn.name.equals("<init>") || mn.name.equals("<clinit>"))
                bindDeferredFields(cn, mn);' \
'            if (false && (mn.name.equals("<init>") || mn.name.equals("<clinit>")))
                bindDeferredFields(cn, mn); // MUTANT' ;;
  clock_now)
    apply_patch \
'        if (method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")' \
'        if (false && method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")' ;;
  sanity_noop)
    apply_patch \
'    static String classify(String owner, String method, String desc) {' \
'    static String classify(String owner, String method, String desc) { /* MUTANT: harmless no-op */' ;;
  *) echo "unknown mutation: $1" >&2; return 9 ;;
  esac
}

# ---------------------------------------------------------------------------------------------------------
SELECT="${MUT:-}"
declare -a RESULTS
caught=0; total=0; blindspots=()
START=$(date +%s)

for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"; probe="${PROBES[$i]}"; expect="${EXPECTS[$i]}"; desc="${DESCS[$i]}"
  if [ -n "$SELECT" ] && ! grep -qw "$name" <<<"$SELECT"; then continue; fi
  total=$((total+1))
  printf '[%2d/%d] %-14s ' "$total" "${#NAMES[@]}" "$name"

  restore
  if ! patch_for "$name"; then
    echo "PATCH-ERROR (anchor moved?) — investigate"
    RESULTS+=("$name|${probe#run_}|$expect|PATCH-ERROR|$desc"); continue
  fi
  if ! rebuild; then
    echo "BUILD-FAIL (mutation didn't compile) — see /tmp/mut_build.log"
    RESULTS+=("$name|${probe#run_}|$expect|BUILD-FAIL|$desc"); restore; continue
  fi

  if "$probe"; then went="green"; else went="red"; fi   # red == probe failed == mutation detected

  if [ "$expect" = "caught" ]; then
    if [ "$went" = "red" ]; then verdict="CAUGHT"; caught=$((caught+1));
    else verdict="MISSED"; blindspots+=("$name : $desc"); fi
  else
    if [ "$went" = "green" ]; then verdict="OK-SILENT"; caught=$((caught+1));
    else verdict="FLAKE!"; blindspots+=("$name : sanity no-op went RED — harness/flake problem"); fi
  fi

  echo "$verdict   ($went)"
  RESULTS+=("$name|${probe#run_}|$expect|$verdict|$desc")
  restore
done

END=$(date +%s)

echo
echo "============================================================================================"
printf '%-15s %-12s %-8s %-11s %s\n' "MUTATION" "PROBE" "EXPECT" "VERDICT" "DESCRIPTION"
echo "--------------------------------------------------------------------------------------------"
for r in "${RESULTS[@]}"; do
  IFS='|' read -r n p e v d <<<"$r"
  printf '%-15s %-12s %-8s %-11s %s\n' "$n" "$p" "$e" "$v" "$d"
done
echo "============================================================================================"
echo
echo "Detection rate: $caught / $total"
echo "Wall time: $((END-START))s"
if [ "${#blindspots[@]}" -gt 0 ]; then
  echo
  echo "BLIND SPOTS (mutations NOT caught — tooling gaps):"
  for b in "${blindspots[@]}"; do echo "  - $b"; done
fi
restore
[ "${#blindspots[@]}" -eq 0 ]
