#!/usr/bin/env bash
# reentrancy.sh — proves candor-java's analysis state is per-scan, not per-process.
#
# The engine's state lives in ~33 static collections (edges, repoTypes, entityTables, clinit sets,
# policy rules, the κ ledger, …). runScan() calls resetState() before each scan so a SECOND in-process
# scan starts clean. This gate catches a missed accumulator: if any static leaks from one scan into the
# next, the leaked edges/repo/entity/rule state would FABRICATE effects (or shift κ) on the second scan.
#
# Method: scan a "real" target in a FRESH process (the baseline), then scan it again in a process that
# FIRST scanned an unrelated, effect-heavy "dirty" target (selftest-reentrant). The two reports must be
# byte-identical — any divergence is leaked state. Two distinct sample dirs make the leak observable:
# the dirty scan's edges/repos must not appear in the real scan's report.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GRADLE="./gradlew"; [ -x "$GRADLE" ] || GRADLE="gradle"
"$GRADLE" -q installDist >/dev/null 2>&1 || { echo "FAIL: candor-java did not build"; exit 1; }
CJ="$ROOT/build/install/candor-java/bin/candor-java"
[ -x "$CJ" ] || { echo "FAIL: no launcher at $CJ"; exit 1; }

# Pick two distinct, already-compiled sample trees so the dirty scan really exercises different state
# (Spring repos/entities, clinit, policy) than the real scan. Fall back gracefully if a sample is absent.
real_src="$ROOT/spring-sample"; dirty_src="$ROOT/sample"
[ -d "$real_src" ]  || real_src="$ROOT/sample"
[ -d "$dirty_src" ] || dirty_src="$ROOT/cha-sample"
if [ ! -d "$real_src" ] || [ ! -d "$dirty_src" ] || [ "$real_src" = "$dirty_src" ]; then
  echo "reentrancy: no two distinct sample trees — SKIPPED"; exit 0
fi

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

# Compile each sample's .java (if any) so we scan real bytecode; if a tree already holds .class files
# (or a jar), scan it as-is.
compile_tree() {
  local src="$1" out="$2"; mkdir -p "$out"
  local javas; javas=$(find "$src" -name '*.java' 2>/dev/null)
  if [ -n "$javas" ]; then
    # shellcheck disable=SC2086
    javac -d "$out" $javas 2>/dev/null || { echo "$src"; return 1; }
    echo "$out"
  else
    echo "$src"   # already classes/jar
  fi
}

real_tree="$(compile_tree "$real_src" "$W/real")"  || { echo "reentrancy: cannot compile $real_src — SKIPPED"; exit 0; }
dirty_tree="$(compile_tree "$dirty_src" "$W/dirty")" || { echo "reentrancy: cannot compile $dirty_src — SKIPPED"; exit 0; }

# Baseline: real target in a fresh process.
"$CJ" "$real_tree" --json "$W/fresh.json" >/dev/null 2>&1 || { echo "FAIL: fresh scan errored"; exit 1; }
# Dirty-then-real in one process.
"$CJ" selftest-reentrant "$dirty_tree" "$real_tree" --json "$W/dirty.json" >/dev/null 2>&1 \
  || { echo "FAIL: selftest-reentrant scan errored"; exit 1; }

[ -f "$W/fresh.json" ] && [ -f "$W/dirty.json" ] || { echo "FAIL: a report is missing"; exit 1; }

if diff -q "$W/fresh.json" "$W/dirty.json" >/dev/null; then
  echo "reentrancy: OK — in-process re-scan byte-identical to a fresh-process scan (no state leak)"
  exit 0
else
  echo "reentrancy: FAIL — in-process re-scan diverges from a fresh scan; state leaked across runs:"
  diff "$W/fresh.json" "$W/dirty.json" | head -40
  exit 1
fi
