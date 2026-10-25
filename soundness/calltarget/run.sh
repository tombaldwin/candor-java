#!/usr/bin/env bash
# The exhaustive call-target matrix for candor-java (call kind x placement x implementor count x effect x arm),
# with EXECUTED ground truth and the verdict read at the caller app.Main.go.
#
#   bash soundness/calltarget/run.sh <engine.jar> <tag> <workdir> [--only substr]
#
# Generates the cells into <workdir> (once; compiled builds are reused across tags, so two jars are compared over
# the SAME bytecode), runs every arm, writes <workdir>/verdicts-<tag>.tsv and gates it against baseline.tsv beside
# this script (0 transitions toward SILENT, 0 new FABRICATED). Needs JDK 21 (CT_JAVA_HOME) and kotlinc
# (CT_KOTLIN_HOME) for the Kotlin cells. ~25 min at --jobs 2. NOT wired into per-commit CI.
#
# A change that MOVES cells commits the new table as baseline.tsv in the same commit.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
jar=$1 tag=$2 work=$3; shift 3
only=()
if [ "${1:-}" = "--only" ]; then only=(--only "$2"); fi
mkdir -p "$work"
[ -f "$work/m/manifest.json" ] || python3 -I "$here/gen.py" "$work/m"
[ -f "$work/m3/manifest.json" ] || python3 -I "$here/gen.py" "$work/m3" extra
[ -f "$work/m2/manifest.json" ] || python3 -I "$here/gen2.py" "$work/m2"
for m in m m3 m2; do
  rm -f "$work/$m/results-$tag.jsonl"
  python3 -I "$here/run.py" "$work/$m" "$jar" "$tag" --jobs "${CT_JOBS:-2}" ${only[@]+"${only[@]}"}
done
python3 -I "$here/verdicts.py" "$work/verdicts-$tag.tsv" "$work/m/results-$tag.jsonl" "$work/m3/results-$tag.jsonl" "$work/m2/results-$tag.jsonl"
if [ ${#only[@]} -eq 0 ] && [ -f "$here/baseline.tsv" ]; then
  python3 -I "$here/gate.py" "$here/baseline.tsv" "$work/verdicts-$tag.tsv"
fi
