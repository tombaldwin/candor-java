#!/usr/bin/env bash
# run.sh — candor-java's adversarial soundness fuzzer (sibling of the Rust impl's soundness/run.sh).
#
# For each seed: generate a Java class (gen.py) that threads a KNOWN effect from `sink` up through a
# random chain of JVM call forms, compile it, run candor-java over it, and assert EVERY method the
# generator knows reaches the effect is reported with that effect OR `Unknown` (a sound
# over-approximation). A reachable method reported PURE — or omitted (candor omits pure methods) — is a
# SILENT UNDER-REPORT, the bug class this harness exists to catch. `Unknown` is a PASS: this tests
# SOUNDNESS (never silent-pure), not precision.
#
#   bash soundness/run.sh [N]                 # fuzz the first N seeds (default 40)
#   SEEDS="1 2 99" bash soundness/run.sh      # specific seeds
#   CANDOR_FUZZ_FORMS="ctor clinit" bash soundness/run.sh   # restrict the call forms
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "soundness: building candor-java…"
GRADLE="./gradlew"; [ -x "$GRADLE" ] || GRADLE="gradle"   # prefer the wrapper (CI has no system gradle)
# installDist → the `$CJ` launcher the fuzzer/fabrication probe drive; shadowJar → the fat `-all.jar`
# the entrypoint + functional-SAM probes scan. Both are needed: in a FRESH checkout (CI) the soundness
# step runs BEFORE the self-gate's shadowJar, so without building it here those two probes found no jar
# and failed the lane (the rename release surfaced it — the jar happened to exist from a prior local
# build before).
"$GRADLE" -q installDist shadowJar >/dev/null 2>&1 || { echo "FAIL: candor-java did not build"; exit 1; }
CJ="$ROOT/build/install/candor-java/bin/candor-java"
[ -x "$CJ" ] || { echo "FAIL: no launcher at $CJ"; exit 1; }

N="${1:-40}"
SEEDS="${SEEDS:-$(seq 1 "$N")}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0; failed_seeds=""
for s in $SEEDS; do
  d="$WORK/s$s"; mkdir -p "$d"
  python3 "$ROOT/soundness/gen.py" "$s" "$d" || { echo "  seed $s: GEN ERROR"; fail=$((fail+1)); continue; }
  # Compile first: a non-compiling class is a generator bug (no report ⇒ false "all pure"), not candor's.
  if ! javac -d "$d/cls" "$d/Gen.java" >/dev/null 2>&1; then
    echo "  seed $s: GENERATOR BUG — class does not compile"; fail=$((fail+1)); continue
  fi
  "$CJ" "$d/cls" --json "$d/report.json" >/dev/null 2>&1
  if [ ! -f "$d/report.json" ]; then
    echo "  seed $s: NO REPORT"; fail=$((fail+1)); continue
  fi
  result="$(python3 "$ROOT/soundness/check.py" "$d")"
  if [ "${result%% *}" = "OK" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1)); failed_seeds="$failed_seeds $s"
    echo "  seed $s: $result"
  fi
done

echo
echo "soundness: $pass passed, $fail failed"
[ -n "$failed_seeds" ] && echo "soundness: failing seeds:$failed_seeds"

# Fabrication probe — the precision counterpart to the soundness fuzzer above. The fuzzer guards against
# UNDER-reporting (a reachable effect going silent-pure); this guards against OVER-reporting (a PURE
# accessor/factory of an effect-bearing owner being fabricated effectful — candor's cardinal sin). It
# reuses the launcher we just built. A failure here gates the run exactly like a soundness failure.
echo
echo "soundness: running fabrication probe…"
CJ="$CJ" python3 "$ROOT/soundness/fabrication_probe.py"; fab=$?

echo
echo "soundness: running entry-point probe (runtime-invoked-callback rooting)…"
if bash "$ROOT/soundness/entrypoint_probe.sh"; then ep=0; else ep=1; fi

echo
echo "soundness: running functional-SAM probe (lambda-only dispatch → Unknown, no flood)…"
if bash "$ROOT/soundness/functional_sam_probe.sh"; then fs=0; else fs=1; fi

# Smear probe — the deferred/stored-lambda FABRICATION counterpart. The fuzzer above threads an effect UP
# a call chain (under-report direction); this checks the orthogonal escape direction: a lambda STORED in a
# field/collection/deferred-container or RETURNED by a factory in an initializer must NOT smear its effect
# via <clinit> onto unrelated methods, while its eventual invocation still discloses (effect or Unknown).
echo
echo "soundness: running smear probe (deferred/stored-lambda no-<clinit>-smear)…"
CJ="$CJ" python3 "$ROOT/soundness/smear_probe.py"; sm=$?

[ "$fail" -eq 0 ] && [ "$fab" -eq 0 ] && [ "$ep" -eq 0 ] && [ "$fs" -eq 0 ] && [ "$sm" -eq 0 ]
