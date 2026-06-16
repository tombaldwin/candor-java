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
"$GRADLE" -q installDist >/dev/null 2>&1 || { echo "FAIL: candor-java did not build"; exit 1; }
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

[ "$fail" -eq 0 ] && [ "$fab" -eq 0 ] && [ "$ep" -eq 0 ]
