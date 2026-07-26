#!/usr/bin/env bash
# The GENUINELY-FROZEN run (see FROZEN.md). Enforces the pinned jar hash, runs the full frozen manifest
# once, and tabulates EVERY manifest repo with a disposition. Aborts if the binary isn't the frozen one.
#
#   CANDOR_JAR=/path/to/candor-java-0.23.1-all.jar  bash run_frozen.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Default to the ARCHIVED copy, never to a build output. The archive used to live in `build/libs`, which is
# a gradle target: eight ordinary development commits silently rebuilt over it, so a reproducer at HEAD
# could no longer meet the hash gate below. It now lives where no build can write to it.
# (`ls -t … | head -1` is itself a hazard — with two jars present it picks by mtime, which is how a stale
# binary produced two false negatives during the scan-boundary work. Kept only as a fallback.)
JAR="${CANDOR_JAR:-$HERE/../corpus-confirmatory/frozen/candor-java-0.23.1-all.jar}"
[ -f "$JAR" ] || JAR="$(ls -t "$HERE"/../../build/libs/*-all.jar 2>/dev/null | head -1)"
EXPECT="bf572eb32db56ef419c8ad7d8f118cfe225f859320252c6969299434263e10d8"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"|cut -d' ' -f1; else shasum -a 256 "$1"|cut -d' ' -f1; fi; }
GOT="$(sha "$JAR")"
if [ "$GOT" != "$EXPECT" ]; then
  echo "FROZEN ABORT: jar hash mismatch"; echo "  got  $GOT"; echo "  want $EXPECT (FROZEN.md)"; exit 1
fi
echo "FROZEN: binary hash verified ($EXPECT)"

# Run the full frozen manifest (all rows; no name args).
CANDOR_JAR="$JAR" bash "$HERE/run_corpus.sh"

# Build the complete per-repo disposition: every manifest repo gets a row (SUMMARY row if present, else its
# SHALOCK clone status, else 'no-disposition'). Attrition tabulated, not narrated.
FS="$HERE/results/FROZEN-SUMMARY.tsv"
printf 'repo\tdisposition\tanalyzed\tchecked\tsound_complete\tdisclosed\tviolations\n' > "$FS"
grep -vE '^\s*#|^\s*$' "$HERE/manifest.tsv" | cut -f1 | while read -r name; do
  row=$(awk -F'\t' -v n="$name" 'NR>1 && $1==n {print; exit}' "$HERE/results/SUMMARY.tsv" 2>/dev/null)
  if [ -n "$row" ]; then
    IFS=$'\t' read -r _ _ an ch so di vi _ _ vd <<<"$row"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$vd" "$an" "$ch" "$so" "$di" "$vi" >> "$FS"
  elif grep -q "^$name	.*CLONE-FAILED" "$HERE/results/SHALOCK.tsv" 2>/dev/null; then
    printf '%s\tclone-failed\t-\t-\t-\t-\t-\n' "$name" >> "$FS"
  else
    printf '%s\tno-disposition\t-\t-\t-\t-\t-\n' "$name" >> "$FS"
  fi
done
echo; echo "======================= FROZEN PER-REPO DISPOSITION (all manifest repos) ======================="
column -t -s "$(printf '\t')" "$FS" 2>/dev/null || cat "$FS"
echo
echo "sound-complete (falsifiable) total: $(awk -F'\t' 'NR>1 && $5 ~ /^[0-9]+$/ {s+=$5} END{print s+0}' "$FS")"
echo "checked total: $(awk -F'\t' 'NR>1 && $4 ~ /^[0-9]+$/ {s+=$4} END{print s+0}' "$FS")"
echo "violations total: $(awk -F'\t' 'NR>1 && $7 ~ /^[0-9]+$/ {s+=$7} END{print s+0}' "$FS")"
