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
# A verdict needs the probe's OWN words, not just its exit code: CAUGHT requires a line naming a detected
# defect, OK-SILENT requires the probe's OK line, and a probe that crashed (wrong JDK, fixture that does not
# compile, no report) is PROBE-ERROR and fails the run. Before any mutation is scored, every probe the run
# uses must be a real green on the UNMUTATED engine (exit 2 otherwise). Needs JDK 21 on PATH.
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
# Two mutable targets: the analysis hooks live in Candor.java; the κ classify rules were EXTRACTED to
# Classifier.java (refactor P1) and are now typed (`return Effect.FS`, not `return "Fs"`) — the anchors
# below track that. Each mutation names its target via TGT before apply_patch (default: Candor.java).
# A third target since 40473d9 (SOUNDNESS R492/R727): FrameworkReach.java loads the GENERATED framework
# member -> effect table, which charges some library members a hand-written rule also charges. A mutation
# that removes a charge must remove it from EVERY source, or the table masks it (jackson_file did, 2026-10-12).
SRC="src/main/java/io/poly/candor/Candor.java"
CLS="src/main/java/io/poly/candor/Classifier.java"
FWR="src/main/java/io/poly/candor/FrameworkReach.java"
ORIG="$(mktemp)"; ORIGCLS="$(mktemp)"; ORIGFWR="$(mktemp)"
cp "$SRC" "$ORIG"; cp "$CLS" "$ORIGCLS"; cp "$FWR" "$ORIGFWR"
restore() { cp "$ORIG" "$SRC"; cp "$ORIGCLS" "$CLS"; cp "$ORIGFWR" "$FWR"; }
trap 'restore; rm -f "$ORIG" "$ORIGCLS" "$ORIGFWR"' EXIT
TGT="$SRC"
# Per-run log directory (kept after the run: it is the evidence for every verdict). Was a fixed /tmp path,
# which two concurrent runs share.
LOGDIR="${MUT_LOGDIR:-$(mktemp -d "${TMPDIR:-/tmp}/mutation_probe.XXXXXX")}"
mkdir -p "$LOGDIR"
BUILD_LOG="$LOGDIR/build.log"; PROBE_LOG="$LOGDIR/probe.log"

GRADLE="./gradlew"; [ -x "$GRADLE" ] || GRADLE="gradle"
CJ="$ROOT/build/install/candor-java/bin/candor-java"

# ---- patch helper: apply a unique-anchor replacement, asserting the anchor exists exactly once ----
apply_patch() {  # $1 = OLD, $2 = NEW (applied to $TGT — set per mutation, reset each loop)
  OLD="$1" NEW="$2" python3 - "$TGT" <<'PY'
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

rebuild() { "$GRADLE" -q installDist shadowJar >"$BUILD_LOG" 2>&1; }

# ---- probe runners: write the probe's output to $PROBE_LOG and return its exit status ----
run_kappa()       { CJ="$CJ" python3 "$ROOT/soundness/kappa_probe.py"           >"$PROBE_LOG" 2>&1; }
run_kappa_libs()  { CJ="$CJ" python3 "$ROOT/soundness/kappa_libs_probe.py"      >"$PROBE_LOG" 2>&1; }
run_smear()       { CJ="$CJ" python3 "$ROOT/soundness/smear_probe.py"           >"$PROBE_LOG" 2>&1; }
run_funcsam()     { bash "$ROOT/soundness/functional_sam_probe.sh"              >"$PROBE_LOG" 2>&1; }
run_fuzzer()      { SEEDS="$(seq 1 40)" bash "$ROOT/soundness/run.sh"           >"$PROBE_LOG" 2>&1; }
run_sweeptest()   { "$GRADLE" test --tests io.poly.candor.SoundnessSweepTest -q >"$PROBE_LOG" 2>&1; }
run_junit()       { "$GRADLE" test --tests io.poly.candor.HelpersTest -q         >"$PROBE_LOG" 2>&1; }

# ---- what a REAL verdict looks like, per probe ----
# A non-zero exit is NOT evidence a mutation was detected: every probe also exits non-zero when it CRASHES
# (a fixture that does not compile, no report, no launcher, a build failure). Measured 2026-10-12: on JDK 17
# kappa_libs_probe dies with "GEN BUG — fixture does not compile" (exit 2), and the harness, reading any
# non-zero exit as red, scored a run in which no probe measured anything as 14/14 CAUGHT. So a verdict now
# needs the probe's own words:
#   RED   = non-zero exit AND a line naming a detected defect (red_marker)
#   GREEN = exit 0       AND the probe's own OK line (green_marker; gradle tests have none, exit 0 is the verdict)
# Anything else is PROBE-ERROR, which fails the harness — never CAUGHT, never OK-SILENT.
red_marker() {
  case "$1" in
    run_kappa)      echo '^  (GAP|FABRICATION)  K\.' ;;
    run_kappa_libs) echo '^  (GAP|SILENT-PURE|FLOOR-SUPPRESSED|INVISIBLE-pkg|FABRICATION)  KL\.' ;;
    run_smear)      echo '^  \[[A-Za-z]+\] (SMEAR|UNDER-REPORT): ' ;;
    run_funcsam)    echo '^  .*(read PURE|gained Unknown)' ;;
    run_fuzzer)     echo '^  seed [0-9]+: FAIL ' ;;   # check.py's own verdict, not a GEN ERROR / NO REPORT
    run_sweeptest|run_junit) echo 'There were failing tests' ;;
    *) echo '__no_marker_defined_for_this_probe__' ;;
  esac
}
green_marker() {
  case "$1" in
    run_kappa)      echo '^kappa-probe: OK' ;;
    run_kappa_libs) echo '^kappa-libs: OK' ;;
    run_smear)      echo '^smear-probe: OK' ;;
    run_funcsam)    echo '^functional-sam-probe: OK' ;;
    run_fuzzer)     echo '^soundness: [0-9]+ passed, 0 failed' ;;
    run_sweeptest|run_junit) echo '' ;;
    *) echo '__no_marker_defined_for_this_probe__' ;;
  esac
}
# run_probe NAME -> sets WENT to green | red | error
run_probe() {
  local p="$1" rc rm gm
  "$p"; rc=$?
  rm="$(red_marker "$p")"; gm="$(green_marker "$p")"
  if [ "$rc" -eq 0 ]; then
    if [ -z "$gm" ] || grep -Eq "$gm" "$PROBE_LOG"; then WENT=green; else WENT=error; fi
  else
    if grep -Eq "$rm" "$PROBE_LOG"; then WENT=red; else WENT=error; fi
  fi
  PROBE_RC=$rc
}
probe_error_detail() {  # a few lines of the probe's own output, so a PROBE-ERROR says what broke
  echo "      exit $PROBE_RC; probe log: $1"
  grep -E 'GEN BUG|GENERATOR BUG|FAIL|ERROR|Error|error:|NO REPORT|Exception|What went wrong' "$1" 2>/dev/null \
    | head -4 | sed 's/^/      | /'
}

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
add jackson_file run_kappa_libs  caught "jackson File/Path->Fs, URL->Net: both classifier rules AND the generated framework-table rows -> disabled (library κ gap)"
add named_sam    run_sweeptest   caught "functionalSamSurface() returns empty (named SAM/Comparator into HOF goes pure)"
add cha_edges    run_fuzzer      caught "skip edges.addAll(targets) — CHA-resolved bodies never linked (chain under-report)"
add cb_unknown   run_funcsam     caught "disable the JDK-functional-SAM callback:Unknown gate (lambda-only dispatch silent)"
add deferred     run_smear       caught "disable bindDeferredFields — stored/deferred lambda invocation silent"
add clock_now    run_junit       caught "java.time .now() (OffsetDateTime/LocalTime/Year) Clock rule -> null"
add sanity_noop  run_kappa       silent "no-op comment insertion (control: probe must stay green)"

patch_for() {
  case "$1" in
    net_dns)
      TGT="$CLS"
      apply_patch \
  '                || ((owner.equals("java.net.InetAddress") || owner.equals("java.net.Inet4Address")
                        || owner.equals("java.net.Inet6Address"))
                    && (method.equals("getByName") || method.equals("getAllByName")
                        || method.equals("getLocalHost") || method.equals("getCanonicalHostName")
                        || method.equals("getHostName")))' \
  '                || ((owner.equals("java.net.InetAddress") || owner.equals("java.net.Inet4Address")
                        || owner.equals("java.net.Inet6Address"))
                    && (method.equals("__MUTANT_never__")))' ;;
  net_socket)
    TGT="$CLS"
    apply_patch \
'                || (owner.equals("javax.management.remote.JMXConnector")
                    && (method.equals("connect") || method.equals("getMBeanServerConnection"))))
            return Effect.NET;' \
'                || (owner.equals("javax.management.remote.JMXConnector")
                    && (method.equals("connect") || method.equals("getMBeanServerConnection"))))
            return null; // MUTANT (was Effect.NET)' ;;
  fs_files)
    TGT="$CLS"
    apply_patch \
'                || owner.equals("java.util.zip.ZipFile") || owner.equals("java.util.jar.JarFile"))
            return Effect.FS;' \
'                || owner.equals("java.util.zip.ZipFile") || owner.equals("java.util.jar.JarFile"))
            return null; // MUTANT (was Effect.FS)' ;;
  exec_pb)
    # ⟨2026-08-29⟩ The rule this targeted was itself upgraded from an ALLOWLIST of launch verbs
    # (start/startPipeline) to a whole-owner-with-denylist stance (Classifier.java, "the WHOLE TYPE is
    # Exec, with the proven-pure surface carved out as a named DENYLIST") — the old anchor text no
    # longer exists at all, so this mutation silently stopped applying. Retarget the SAME question
    # (does a bare, unconfigured `pb.start()` still classify Exec?) at the current mechanism: flip its
    # terminal `return Effect.EXEC` to `return null`.
    TGT="$CLS"
    apply_patch \
'            boolean objectProto = isObjectProtocolExempt(method, desc);
            if (!env && !readBack && !objectProto) return Effect.EXEC;' \
'            boolean objectProto = isObjectProtocolExempt(method, desc);
            if (!env && !readBack && !objectProto) return null; // MUTANT (was Effect.EXEC)' ;;
  log_syslogger)
    TGT="$CLS"
    apply_patch \
'|| owner.equals("java.lang.System$Logger");' \
'|| owner.equals("java.lang.System$__MUTANT_never__");' ;;
  env_getenv)
    TGT="$CLS"
    apply_patch \
'if (owner.equals("java.lang.System") && method.equals("getenv")) return Effect.ENV;' \
'if (owner.equals("java.lang.System") && method.equals("getenv")) return null; // MUTANT' ;;
  rand_uuid)
    TGT="$CLS"
    apply_patch \
'if (owner.equals("java.util.UUID") && method.equals("randomUUID")) return Effect.RAND;' \
'if (owner.equals("java.util.UUID") && method.equals("randomUUID")) return null; // MUTANT' ;;
  jackson_file)
    # THREE sources charge the jackson File/URL surface (the old readValue/readTree/writeValue-specific rule,
    # κ batch 30's whole-package descriptor rule, which subsumes it, and — since 40473d9, SOUNDNESS R492/R727
    # — the GENERATED framework table, which charges ObjectMapper/XmlMapper/YAMLMapper/CsvMapper
    # readValue/readTree/writeValue(File|Path|URL) Fs / Fs,Net from the jars' own bodies). Each masks a mutation
    # of the others, so a real "jackson File-κ gone" mutation must disable ALL THREE. Measured 2026-10-12: with
    # only the two rules off, all 10 jackson effect cases still reported Fs (URL: Fs,Net) off the table and the
    # weekly run reported MISSED. The table half skips com/fasterxml/jackson rows on load — scoped to jackson,
    # NOT -Dcandor.frameworkReach=off, which would switch every framework off. The hedge (A/U lines) is left in
    # place: it adds a DISCLOSED Unknown, never a charge, and the probe correctly accepts a disclosure.
    TGT="$FWR"
    apply_patch \
'                if (line.isEmpty() || line.charAt(0) == '"'"'#'"'"') continue;
                int tab = line.indexOf('"'"'\t'"'"');
                EnumSet<Effect> es = EnumSet.noneOf(Effect.class);' \
'                if (line.isEmpty() || line.charAt(0) == '"'"'#'"'"') continue;
                if (line.startsWith("com/fasterxml/jackson/")) continue; // MUTANT (table rows for jackson dropped)
                int tab = line.indexOf('"'"'\t'"'"');
                EnumSet<Effect> es = EnumSet.noneOf(Effect.class);' \
    && TGT="$CLS" \
    && apply_patch \
'                && (method.equals("readValue") || method.equals("readTree") || method.equals("writeValue"))) {
            if (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")) return Effect.FS;
            if (desc.startsWith("(Ljava/net/URL;")) return Effect.NET;' \
'                && (method.equals("readValue") || method.equals("readTree") || method.equals("writeValue"))) {
            if (false) return Effect.FS; // MUTANT
            if (false) return Effect.NET; // MUTANT' \
    && apply_patch \
'        if (owner.startsWith("com.fasterxml.jackson")) {
            String params = paramsOf(desc);
            if (params.contains("Ljava/net/URL;")) return Effect.NET;
            if (params.contains("Ljava/io/File;") || params.contains("Ljava/nio/file/Path;")) return Effect.FS;
            return null;
        }' \
'        if (owner.startsWith("com.fasterxml.jackson")) {
            return null; // MUTANT (batch-30 descriptor rule disabled)
        }' ;;
  named_sam)
    apply_patch \
'static Set<String> functionalSamSurface(String classInternal) {' \
'static Set<String> functionalSamSurface(String classInternal) {
        if (true) return new java.util.HashSet<>(); // MUTANT' ;;
  cha_edges)
    # ⟨2026-08-29⟩ re-anchored: the P7 decomposition moved this out of the old monolithic method,
    # de-indenting it one level, and `ctx()` (the ThreadLocal singleton call) became the plain `ctx`
    # parameter handleMethodInsn now threads through — both textual, not behavioural, changes, but
    # they moved the anchor off the source, so this mutation silently stopped applying.
    apply_patch \
'            List<String> targets = broad ? List.of() : cha;
            ctx.edges.get(id).addAll(targets);' \
'            List<String> targets = broad ? List.of() : cha;
            // MUTANT: ctx.edges.get(id).addAll(targets);' ;;
  cb_unknown)
    # ⟨2026-08-29⟩ re-anchored: same P7 de-indentation (16/32-space continuation → 12/20).
    apply_patch \
'            if (!broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                    && isJdkFunctionalSam(min.owner, min.name)) {' \
'            if (false && !broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                    && isJdkFunctionalSam(min.owner, min.name)) {' ;;
  deferred)
    # ⟨2026-08-29⟩ re-anchored: same P7 de-indentation (12/16-space → 8/12) from registerMethod's
    # extraction out of the old inline per-method loop.
    apply_patch \
'        if (mn.name.equals("<init>") || mn.name.equals("<clinit>"))
            bindDeferredFields(cn, mn);' \
'        if (false && (mn.name.equals("<init>") || mn.name.equals("<clinit>")))
            bindDeferredFields(cn, mn); // MUTANT' ;;
  clock_now)
    TGT="$CLS"
    apply_patch \
'        if (method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")' \
'        if (false && method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")' ;;
  sanity_noop)
    TGT="$CLS"
    apply_patch \
'    static Effect classify(String owner, String method, String desc) {' \
'    static Effect classify(String owner, String method, String desc) { /* MUTANT: harmless no-op */' ;;
  *) echo "unknown mutation: $1" >&2; return 9 ;;
  esac
}

# ---------------------------------------------------------------------------------------------------------
SELECT="${MUT:-}"
declare -a RESULTS
caught=0; total=0; blindspots=()
START=$(date +%s)
echo "mutation_probe: logs in $LOGDIR"

# ---- BASELINE: every probe this run uses must be a REAL green on the UNMUTATED engine ----
# Without this, a probe that is red (or crashing) for reasons unrelated to any mutation scores every
# mutation paired with it as CAUGHT. A wrong JDK, a missing jar corpus, a probe broken by an unrelated
# change — all of them used to look like a perfect detection rate.
restore
if ! rebuild; then
  echo "mutation_probe: FAIL — the UNMUTATED engine does not build (see $BUILD_LOG). Nothing was measured." >&2
  exit 2
fi
declare -a BASE_DONE=()
base_bad=0
for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"; probe="${PROBES[$i]}"
  if [ -n "$SELECT" ] && ! grep -qw "$name" <<<"$SELECT"; then continue; fi
  case " ${BASE_DONE[*]-} " in *" $probe "*) continue ;; esac
  BASE_DONE+=("$probe")
  printf '[baseline] %-16s ' "${probe#run_}"
  run_probe "$probe"; cp "$PROBE_LOG" "$LOGDIR/baseline.${probe#run_}.log"
  if [ "$WENT" = "green" ]; then echo "green"
  else
    echo "NOT GREEN ($WENT) on the unmutated engine"
    probe_error_detail "$LOGDIR/baseline.${probe#run_}.log"
    base_bad=1
  fi
done
if [ "$base_bad" -ne 0 ]; then
  echo >&2
  echo "mutation_probe: FAIL — a probe is not green on the UNMUTATED engine, so it cannot attest that any" >&2
  echo "mutation was caught. No detection rate is reported. (Wrong JDK? This harness needs JDK 21 on PATH —" >&2
  echo "java -version says: $(java -version 2>&1 | head -1))" >&2
  exit 2
fi

for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"; probe="${PROBES[$i]}"; expect="${EXPECTS[$i]}"; desc="${DESCS[$i]}"
  if [ -n "$SELECT" ] && ! grep -qw "$name" <<<"$SELECT"; then continue; fi
  total=$((total+1))
  printf '[%2d/%d] %-14s ' "$total" "${#NAMES[@]}" "$name"

  restore
  TGT="$SRC"   # default target; a classify-rule mutation resets it to $CLS in its case arm
  if ! patch_for "$name"; then
    echo "PATCH-ERROR (anchor moved?) — investigate"
    # A moved anchor means this mutation could not be APPLIED, so the probe it names was never actually
    # exercised this run — indistinguishable, for verification purposes, from a MISSED mutation (the
    # thing this whole harness exists to catch). Previously this fell through to `continue` without
    # touching `blindspots`, so the harness's own final `[ "${#blindspots[@]}" -eq 0 ]` exit code stayed
    # 0 — a refactor that silently detached 4 of 14 mutations from their anchors still reported the
    # weekly soundness-gate GREEN. MEASURED 2026-08-29: after the P7 Candor.java decomposition
    # re-indented (and in one case renamed `ctx()`→`ctx`) the guards these anchors target, exec_pb/
    # cha_edges/cb_unknown/deferred all went PATCH-ERROR while `mutation_probe.sh` still exited 0.
    blindspots+=("$name : anchor no longer matches source — mutation NOT applied, probe NOT verified")
    RESULTS+=("$name|${probe#run_}|$expect|PATCH-ERROR|$desc"); restore; continue
  fi
  if ! rebuild; then
    echo "BUILD-FAIL (mutation didn't compile) — see $BUILD_LOG"
    blindspots+=("$name : mutation did not compile — probe NOT verified")
    RESULTS+=("$name|${probe#run_}|$expect|BUILD-FAIL|$desc"); restore; continue
  fi

  run_probe "$probe"; went="$WENT"   # red == the probe NAMED a defect; error == it crashed or said nothing
  cp "$PROBE_LOG" "$LOGDIR/$name.probe.log"

  if [ "$went" = "error" ]; then
    echo "PROBE-ERROR (the probe crashed or gave no verdict — NOT a detection)"
    probe_error_detail "$LOGDIR/$name.probe.log"
    blindspots+=("$name : probe ${probe#run_} gave no real verdict (exit $PROBE_RC, see $LOGDIR/$name.probe.log) — NOT verified")
    RESULTS+=("$name|${probe#run_}|$expect|PROBE-ERROR|$desc"); restore; continue
  fi

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
