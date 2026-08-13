#!/usr/bin/env bash
# candor-java self-gate (SPEC §7.12): candor-java analyzes ITSELF and holds its own declared boundary.
# An effect-gate vendor whose own gate is red has no business gating anyone else.
#
# TWO HALVES, because a policy file cannot say "deny Exec everywhere except io.poly.candor.verify":
#   (1) the WHOLE tool under .candor/policy — `deny Net Db Ipc`, no package excluded;
#   (2) the Exec-performing methods are EXACTLY the declared list below.
#
# WHY THIS REPLACED THE PREVIOUS ARRANGEMENT. The old half (1) proved the analyzer core clean by
# COPYING build/classes and DELETING io/poly/candor/verify — carving the Exec exemption out a whole
# PACKAGE at a time. Everything in that package was then outside the Exec gate entirely: half (2) only
# asked about Net/Db/Ipc, so a new subprocess added anywhere under io.poly.candor.verify was caught by
# nothing. Declaring the two METHODS instead keeps every class inside the gate, which is strictly
# stronger. candor-ts and candor-swift use the same shape, for the same reason.
#
# Half (2) is a CARVE-OUT OF PROVEN-SAFE METHODS, not an allowlist of exempt packages: an Exec
# appearing anywhere else fails, and so does a DECLARED entry that STOPS performing Exec — a stale
# exemption is a gate that has quietly stopped asserting anything.
#
# EVERY WRITE GOES TO A TEMP DIR — nothing under the working tree is touched (candor-rust's self-gate
# learned this the hard way: it deleted eight tracked report files and got caught in a `git add -A`).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLASSES="$ROOT/build/classes/java/main"
[ -d "$CLASSES" ] || { echo "self-gate: no classes at $CLASSES (run \`./gradlew shadowJar\` first)"; exit 2; }
JAR="${CANDOR_JAVA_JAR:-$(ls -t "$ROOT"/build/libs/candor-java-*-all.jar 2>/dev/null | head -1)}"
[ -n "$JAR" ] && [ -f "$JAR" ] || { echo "self-gate: no shadow jar in $ROOT/build/libs"; exit 2; }
WS="$(mktemp -d "${TMPDIR:-/tmp}/candor-java-self-gate.XXXXXX")"
trap 'rm -rf "$WS"' EXIT

# The subprocess sites, by method. `Candor.main` is the CLI entry, which inherits Exec transitively
# from the verify path it can dispatch into; `VerifyCli.main` is the dynamic honesty oracle, which runs
# YOUR program under a -javaagent to check candor's static claim against reality. That Exec is the
# feature, not a hidden effect.
DECLARED_EXEC="io.poly.candor.Candor.main
io.poly.candor.verify.VerifyCli.main"

CANDOR_POLICY="$ROOT/.candor/policy" java -jar "$JAR" "$CLASSES" --json "$WS/self.json" > "$WS/scan.log" 2>&1
gate_rc=$?
# Trim the per-method Unknown advisory — it buries the verdict in CI. The COUNT stays on the summary
# line, so the advisory is still visible as a number; violations are never filtered.
grep -v '^    `' "$WS/scan.log"
[ -s "$WS/self.json" ] || { echo "self-gate: candor-java produced no report"; exit 2; }

DECLARED="$DECLARED_EXEC" python3 - "$WS/self.json" <<'PY'
import json, os, sys
declared = {l.strip() for l in os.environ["DECLARED"].splitlines() if l.strip()}
d = json.load(open(sys.argv[1]))
fns = d["functions"] if isinstance(d, dict) else d
found = {e["fn"] for e in fns if "Exec" in set(e.get("inferred", []))}
new, stale = sorted(found - declared), sorted(declared - found)
for f in new:
    print(f"  AS-EFF-006  {f} performs Exec — not a declared subprocess site.")
    print( "              candor-java spawns a process only for `verify`, and says so in .candor/policy.")
    print( "              If this one is legitimate, add it there AND to ci/self-gate.sh's list.")
for f in stale:
    print(f"  STALE       {f} is declared Exec-exempt but no longer performs Exec — drop it.")
    print( "              An exemption nothing exercises is a gate that has stopped asserting.")
sys.exit(1 if (new or stale) else 0)
PY
exec_rc=$?

if [ "$gate_rc" -eq 0 ] && [ "$exec_rc" -eq 0 ]; then
  echo "self-gate: OK — candor-java reaches no Net/Db/Ipc, and spawns a process only where it declares it does"
  exit 0
fi
[ "$gate_rc" -ne 0 ] && echo "self-gate: FAILED — the declared boundary in .candor/policy is red (exit $gate_rc)"
[ "$exec_rc" -ne 0 ] && echo "self-gate: FAILED — the Exec set does not match the declared subprocess list"
exit 1
