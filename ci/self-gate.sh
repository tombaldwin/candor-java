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
# The jar is named from the PROJECT VERSION, not picked newest-by-mtime. A bump leaves the previous
# `-all.jar` in build/libs, and `ls -t` would hand this gate a stale ANALYZER over fresh classes the
# moment that older file's mtime got refreshed (a copy, an unpack, a restore) — greening on
# classification behaviour the tree no longer has.
if [ -n "${CANDOR_JAVA_JAR:-}" ]; then JAR="$CANDOR_JAVA_JAR"; else
  GV="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$ROOT/build.gradle.kts" | head -1)"
  [ -n "$GV" ] || { echo "self-gate: cannot read the project version from build.gradle.kts"; exit 2; }
  JAR="$ROOT/build/libs/candor-java-$GV-all.jar"
fi
[ -f "$JAR" ] || { echo "self-gate: $JAR is not built (run \`./gradlew shadowJar\`)"; exit 2; }
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
# Trim the per-method Unknown advisory ONLY — matched on its own `→ add  ` shape, not on indentation.
# `^    \`` also matched the ⟨0.23⟩ `interfaceUnion` rows, which name synthetic entries that MATCHED A
# POLICY RULE and were not gated as functions. Those are near-violations; collapsing them to a bare
# count means a chained-dep dispatch surface reaching a denied effect reaches CI as a number with no
# names. Violations themselves are `[AS-EFF-006] …` and were never at risk.
grep -vE '^    `.*→ add  `' "$WS/scan.log"
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
    # candor's `fn` gains a parameter list as soon as a name is overloaded, so adding a second `main`
    # renames the report key and this entry goes stale while the real site reports as new. Failing
    # closed is right; naming four unrelated problems instead of "the key format changed" is not.
    kin = sorted(k for k in found if k.startswith(f + "("))
    if kin:
        print(f"  RENAMED     {f} is now parameter-qualified as {kin} — an overload did that, not you.")
        print( "              UPDATE the declared name; do NOT drop it, or the exemption silently widens.")
    else:
        print(f"  STALE       {f} is declared Exec-exempt but no longer performs Exec — drop it.")
        print( "              An exemption nothing exercises is a gate that has stopped asserting.")
sys.exit(1 if (new or stale) else 0)
PY
exec_rc=$?

if [ "$gate_rc" -eq 0 ] && [ "$exec_rc" -eq 0 ]; then
  echo "self-gate: OK — candor-java reaches no Net/Db/Ipc, and spawns a process only where it declares it does"
  exit 0
fi
# Exit 2 is NOT a violation. It is the ⟨0.21⟩ fail-closed "could not evaluate" verdict (an unanalyzable
# class in build/classes), and this codebase treats that distinction as load-bearing everywhere else —
# including in this script's own preconditions. Reporting it as "violates its own boundary" sends the
# reader hunting for a subprocess that does not exist, and collapsing it to exit 1 tells CI a violation
# was ESTABLISHED. Preserved as 2.
if [ "$gate_rc" -eq 2 ]; then
  echo "self-gate: COULD NOT EVALUATE — candor-java exited 2 over its own classes (unanalyzable input,"
  echo "  not a violation: the boundary was never judged). Fix the input, then re-run."
  exit 2
fi
[ "$gate_rc" -ne 0 ] && echo "self-gate: FAILED — the declared boundary in .candor/policy is red (exit $gate_rc)"
[ "$exec_rc" -ne 0 ] && echo "self-gate: FAILED — the Exec set does not match the declared subprocess list"
exit 1
