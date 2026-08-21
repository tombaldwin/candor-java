#!/usr/bin/env bash
# THE REPORT-REFRESH ACCEPTANCE ORACLE.
#
# The refresh's entire safety case is one sentence: a refreshed report must be BYTE-IDENTICAL to the
# full scan it replaces. A cache that is merely "close" is a silent under-report wearing a normal
# report's shape — this project's cardinal sin — so equality is checked on BYTES, across the report
# AND every sidecar the scan writes, never on a summary or a violation count. The sidecars matter
# on their own account: the callgraph and hierarchy documents are exactly what a per-class cache
# reconstructs, and a stale one is invisible in the main document.
#
# Two arms, and BOTH are load-bearing:
#
#   EQUIVALENCE  cold scan vs refreshed scan of the same tree   → must be IDENTICAL
#   CONTROL      perturb one class, refresh again              → must DIFFER, and must equal a
#                cold scan of the perturbed tree
#
# The control is not decoration. The equivalence arm alone is passed perfectly by a "refresh" that
# ignores its input and replays the previous report — the strongest imaginable cache and a totally
# blind one. The control is what gives the equality its meaning, and it is checked against a cold
# scan of the SAME perturbed tree so that "it changed" cannot be satisfied by changing WRONGLY.
#
# A perturbation that moves no report is reported INCONCLUSIVE and does not count as coverage. A
# control that cannot fail must never be reported as a control that passed.
#
# Usage: refresh-equiv.sh <jar> <target>...        (targets: class dirs or .jar files)
set -uo pipefail

JAR="${1:?usage: refresh-equiv.sh <candor-jar> <target>...}"; shift
[ $# -gt 0 ] || { echo "refresh-equiv: no targets given" >&2; exit 2; }
[ -f "$JAR" ] || { echo "refresh-equiv: no such jar: $JAR" >&2; exit 2; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0; checked=0; controls=0

# Concatenate the report and every sidecar written at a prefix, in a stable order, with the file
# name in the stream — so a diff names the document that moved rather than just a byte offset.
snap() {  # snap <dir>
  ( cd "$1" && find . -type f -name '*.json' | LC_ALL=C sort | while read -r f; do
      printf '=== %s\n' "$f"; cat "$f"; printf '\n'
    done )
}

# One scan. The cache is addressed by CANDOR_REFRESH: unset/0 = disabled (the cold reference path),
# a directory = use it as the per-class cache.
scan() {  # scan <cache-spec> <target> <out-prefix> <log>
  local cache="$1" target="$2" prefix="$3" log="$4"
  mkdir -p "$(dirname "$prefix")"
  CANDOR_REFRESH="$cache" java -jar "$JAR" "$target" --json "$prefix.json" >"$log" 2>&1
  return $?
}

for target in "$@"; do
  name="$(basename "$target" .jar)"
  d="$WORK/$name"; mkdir -p "$d"
  printf '── %-22s' "$name"

  # A private copy of the tree, so the perturbation arm never touches the caller's files. A jar is
  # expanded, because the control needs to rewrite ONE class and a jar entry cannot be perturbed in
  # place without rewriting the archive (which would change every class's bytes and prove nothing).
  tree="$d/tree"; mkdir -p "$tree"
  if [ -d "$target" ]; then cp -R "$target/." "$tree/"
  else ( cd "$tree" && unzip -qq -o "$target" ) || { echo "FAIL — cannot expand $target"; fail=1; continue; }
  fi

  scan 0 "$tree" "$d/cold/report" "$d/cold.log";  ccold=$?
  scan "$d/cache" "$tree" "$d/prime/report" "$d/prime.log" >/dev/null 2>&1
  scan "$d/cache" "$tree" "$d/warm/report"  "$d/warm.log";  cwarm=$?
  checked=$((checked+1))

  if [ "$ccold" != "$cwarm" ]; then
    echo "FAIL — exit differs: cold=$ccold warm=$cwarm"; fail=1; continue
  fi
  snap "$d/cold" >"$d/a"; snap "$d/warm" >"$d/b"
  if ! diff -u "$d/a" "$d/b" >"$d/diff" 2>&1; then
    echo "FAIL — refreshed report differs from the cold scan"
    sed 's/^/     /' "$d/diff" | head -40
    fail=1; continue
  fi

  # THE WARM RUN MUST PROVE IT TOOK THE REFRESH PATH. Without this the whole harness is vacuous:
  # against a build that ignores CANDOR_REFRESH entirely, every arm above is a cold scan compared
  # with a cold scan, and it reports OK while measuring nothing. So the engine discloses its reuse
  # on stderr and the harness REQUIRES a non-zero one — the oracle has to be able to fail before a
  # pass from it is worth anything.
  read -r rn rtot < <(sed -n 's/^candor-java: refresh — reused \([0-9]*\) of \([0-9]*\) .*/\1 \2/p' "$d/warm.log" | tail -1)
  if [ -z "${rn:-}" ]; then
    echo "FAIL — the warm run disclosed no refresh reuse (the cache never engaged; the comparison above is vacuous)"
    fail=1; continue
  fi
  if [ "$rn" = 0 ]; then
    echo "FAIL — the warm run reused 0 of $rtot classes (nothing was cached; the comparison above is vacuous)"
    fail=1; continue
  fi

  # THE CONTROL. REMOVE a class from the tree, then refresh against the cache primed on the tree
  # that still had it. The refresh must land exactly where a cold scan of the reduced tree lands.
  #
  # Deletion rather than a byte-append, and the reason is a measurement: ASM's ClassReader parses a
  # classfile by internal offsets, so trailing garbage is simply never read. Appending a byte moves
  # the file's hash — so a content-addressed cache dutifully re-analyses the class — and produces a
  # byte-identical analysis, leaving the report unmoved and the control permanently INCONCLUSIVE. It
  # would have looked like a control for as long as nobody checked which half of it was working.
  #
  # A deletion is the strongest cheap perturbation because it must move BOTH halves: the class's own
  # functions leave the report, and every caller's transitive closure has to be recomputed without
  # them. The narrower case — a method body edited while the signature set is unchanged, where the
  # refresh must re-analyse exactly one class and reuse the rest — needs a recompile, so it lives in
  # the JUnit fixture test where javac is on hand.
  victim="$(find "$tree" -name '*.class' | LC_ALL=C sort | head -1)"
  if [ -z "$victim" ]; then echo "equivalence OK · control SKIP (no .class to perturb)"; continue; fi
  rm -f "$victim"
  scan 0 "$tree" "$d/pcold/report" "$d/pcold.log"
  scan "$d/cache" "$tree" "$d/pwarm/report" "$d/pwarm.log"
  snap "$d/pcold" >"$d/pa"; snap "$d/pwarm" >"$d/pb"

  if diff -q "$d/a" "$d/pa" >/dev/null 2>&1; then
    echo "equivalence OK · control INCONCLUSIVE (perturbation moved no report — not counted)"
    continue
  fi
  if diff -u "$d/pa" "$d/pb" >"$d/pdiff" 2>&1; then
    controls=$((controls+1))
    echo "equivalence OK · control OK"
  else
    echo "equivalence OK · FAIL control — after perturbation the refresh left the cold scan"
    sed 's/^/     /' "$d/pdiff" | head -40
    fail=1
  fi
done

echo
if [ "$fail" != 0 ]; then
  echo "refresh-equiv: FAILED — see the diffs above"
  exit 1
fi
if [ "$controls" = 0 ]; then
  # Every equivalence arm passing with no armed control is the exact shape a blind replay produces.
  echo "refresh-equiv: INCONCLUSIVE — $checked target(s) equivalent, but NO control was armed."
  echo "  A refresh that replays the previous report unconditionally passes every arm above."
  exit 2
fi
echo "refresh-equiv: OK — $checked target(s), refreshed == cold on bytes; $controls control(s) armed and tracking"
exit 0
