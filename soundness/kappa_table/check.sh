#!/usr/bin/env bash
# SOUNDNESS R492/R727 -- the weekly gate: do the checked-in framework tables reproduce from their pinned inputs?
#
#   bash soundness/kappa_table/check.sh <candor-java-all.jar>
#
# Same verdict as `derive.sh --check` (exit 0 = byte-identical, 1 = drift), but the drift is REPORTED IN FULL.
# `derive.sh --check` prints `diff | head -20`: it hides everything past the twentieth line, and when `head`
# closes the pipe `diff` dies on SIGPIPE ("diff: standard output: Broken pipe", exit 2 under pipefail) -- a
# 500-line drift read as six lines. derive.sh cannot be edited to fix that without moving the generator checksum
# stamped into both tables (it is one of the four hashed inputs), so this wrapper runs the UNCHANGED derive.sh in
# a scratch copy of the layout, WRITE mode, and compares the result itself.
#
# In the report, a `-` line is in the checked-in table and NOT generated: a REMOVED hedge or charge. Read those
# first -- a removal is where a silence hides; an addition only discloses more. DERIVE_CHECK_LINES (default 400)
# bounds the additions listed; removals are always listed in full.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
JAR="${1:?usage: check.sh <candor-java-all.jar>}"
RES=src/main/resources/candor
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/soundness" "$T/$RES"
cp -R "$HERE" "$T/soundness/kappa_table"; rm -f "$T/soundness/kappa_table/witness.tsv"
cp "$ROOT/$RES/framework-reach.tsv" "$ROOT/$RES/framework-hedge.tsv" "$T/$RES/"
CANDOR_SOUNDNESS_LIB="${CANDOR_SOUNDNESS_LIB:-$ROOT/soundness/lib}" bash "$T/soundness/kappa_table/derive.sh" "$JAR" >&2

bad=0
for name in reach hedge; do
  f="$RES/framework-$name.tsv"
  if cmp -s "$ROOT/$f" "$T/$f"; then echo "check: $f reproduces byte-identically"; continue; fi
  bad=1
  diff "$ROOT/$f" "$T/$f" > "$T/$name.diff" || true
  echo "check: $f is NOT what its inputs generate (hand-edited, or stale against this engine):" >&2
  echo "check:   $(grep -c '^> [^#]' "$T/$name.diff" || true) generated-not-checked-in, $(grep -c '^< [^#]' "$T/$name.diff" || true) checked-in-not-generated; by kind: $(grep '^[<>] [^#]' "$T/$name.diff" | cut -c1-3 | sort | uniq -c | tr '\n' ' ')" >&2
  echo "check: REMOVED (checked in, no longer generated):" >&2
  grep '^< [^#]' "$T/$name.diff" >&2 || true
  echo "check: ADDED (generated, not checked in), first ${DERIVE_CHECK_LINES:-400}:" >&2
  { grep '^> [^#]' "$T/$name.diff" || true; } | head -n "${DERIVE_CHECK_LINES:-400}" >&2 || true
done
exit "$bad"
