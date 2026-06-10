#!/usr/bin/env bash
# run_kotlin.sh — Kotlin-bytecode soundness probe (the JVM engine's Kotlin lane).
#
# Kotlin compiles the same semantics through DIFFERENT bytecode shapes than javac — suspend functions
# (CPS transform: every suspend fn gains a Continuation param + a state-machine synthetic), lambdas
# (invokedynamic by default since 2.0), object/companion initializers (<clinit> of a synthetic class),
# extension functions (static with receiver param), default-arg $default wrappers, property getters,
# callable references (a synthetic class with <clinit>), and inline functions (the body lands in the
# caller). KotlinProbe.kt threads a known Fs effect through each form; every chain function must report
# the effect or Unknown — a silent-pure chain fn is the under-report this lane hunts.
#
# Skips (exit 0 with a notice) when kotlinc isn't installed, so the suite never blocks on the toolchain.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v kotlinc >/dev/null 2>&1 || { echo "soundness(kotlin): kotlinc not installed — SKIPPED"; exit 0; }

GRADLE="$ROOT/gradlew"; [ -x "$GRADLE" ] || GRADLE="gradle"
( cd "$ROOT" && "$GRADLE" -q installDist >/dev/null 2>&1 ) || { echo "FAIL: candor-java did not build"; exit 1; }
CJ="$ROOT/build/install/candor-java/bin/candor-java"

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
kotlinc "$ROOT/soundness/KotlinProbe.kt" -d "$W/out" 2>/dev/null || { echo "FAIL: kotlinc on KotlinProbe.kt"; exit 1; }
"$CJ" "$W/out" --json "$W/r.json" >/dev/null 2>&1
[ -f "$W/r.json" ] || { echo "FAIL: no report"; exit 1; }

python3 - "$W/r.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
fns = d["functions"] if isinstance(d, dict) else d
got = {e["fn"]: e["inferred"] for e in fns}
# every chain entry point must carry the effect (or Unknown) on the FUNCTION ITSELF
CHAINS = ["plain", "lambda_call", "susp_leaf", "susp_mid", "susp_start", "inline_call",
          "object_init", "companion_init", "ext_call", "default_call", "getter_call", "ref_call", "kio_read", "kio_rand", "named_call"]
bad = []
# negative: pure path manipulation must NOT classify
if got.get("KotlinProbeKt.kio_path") is not None:
    bad.append(f"kio_path={got['KotlinProbeKt.kio_path']} (pure path manipulation over-tagged)")
for c in CHAINS:
    inf = got.get(f"KotlinProbeKt.{c}")
    if inf is None or not (set(inf) & {"Fs", "Rand", "Unknown"}):
        bad.append(f"{c}={inf}")
print(f"soundness(kotlin): {len(CHAINS)-len(bad)}/{len(CHAINS)} forms attribute"
      + (f"  FAILURES: {bad}" if bad else ""))
sys.exit(1 if bad else 0)
PY
