#!/usr/bin/env bash
# SOUNDNESS R508/R509 — run, or CALIBRATE, the "does the rule still fire?" probe.
#
#   bash soundness/rule_fires.sh              # the probe: every in-scope library, latest release
#   bash soundness/rule_fires.sh --calibrate  # prove the instrument can FIRE and can be SILENT
#   bash soundness/rule_fires.sh --offline    # probe whatever is already downloaded
#
# See soundness/kappa_census/rule_fires.py for what it measures and why the scope stops at the
# kappa-COVERED prefixes.  Exit 0 = every in-scope rule set still matches its library's current
# release; 1 = one went to zero; 2 = the instrument could not run.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=${OUT:-$ROOT/build/rule-fires}
mkdir -p "$OUT/classes"

# The candor all-jar.  Picked by MODIFICATION TIME, and its identity is printed, because
# `ls | head` once selected a stale 0.27 jar (AGENT-CORPUS-BRIEF rule 3).
if [ -z "${CJ_ALL:-}" ]; then
  CJ_ALL=$(ls -t "$ROOT"/build/libs/*-all.jar 2>/dev/null | head -1)
fi
if [ ! -f "${CJ_ALL:-/nonexistent}" ]; then
  echo "rule_fires: no candor all-jar — run ./gradlew shadowJar first" >&2; exit 2
fi
echo "rule_fires: classifier under test = $CJ_ALL"
ls -lT "$CJ_ALL" >&2

javac -nowarn -cp "$CJ_ALL" -d "$OUT/classes" soundness/kappa_census/RuleFireProbe.java || exit 2
export CJ_ALL PROBE="$OUT/classes"

# ---------------------------------------------------------------------------------------------
# CALIBRATION.  An instrument that has not been shown to FAIL is not evidence (SOUNDNESS R500 —
# a census this project published a wrong lesson from, because its oracle could not return a
# negative).  So both directions are asserted here, against the defect that motivated the probe.
#
#   ARM B  the PRE-R509-FIX classifier (the rules exactly as SHIPPED) x Exposed 1.5.0  -> MUST be 0
#   ARM A  the classifier under test                x Exposed 1.5.0  -> MUST be > 0
#   CTRL   the PRE-FIX classifier                   x Exposed 0.52.0 -> MUST be > 0
#
# CTRL is the half that makes arm B mean anything: without it, "arm B printed 0" is equally
# explained by a probe that prints 0 for everything.
# ---------------------------------------------------------------------------------------------
PREFIX_COMMIT=${PREFIX_COMMIT:-92994fd}          # the commit BEFORE R509's fix (9667565)
if [ "${1:-}" = "--calibrate" ]; then
  rm -rf "$OUT/prefix-src" "$OUT/prefix-classes"
  mkdir -p "$OUT/prefix-src/io/poly/candor" "$OUT/prefix-classes"
  if ! git cat-file -e "$PREFIX_COMMIT:src/main/java/io/poly/candor/Classifier.java" 2>/dev/null; then
    echo "CALIBRATION CANNOT RUN: $PREFIX_COMMIT is unreachable. Do not read this as a pass." >&2
    exit 2
  fi
  git show "$PREFIX_COMMIT:src/main/java/io/poly/candor/Classifier.java" \
      > "$OUT/prefix-src/io/poly/candor/Classifier.java"
  # Only Classifier.java changed in 9667565's main source, so the pre-fix file compiles against the
  # current all-jar and, placed FIRST on the classpath, shadows the fixed one.  No second build.
  javac -nowarn -cp "$CJ_ALL" -d "$OUT/prefix-classes" \
      "$OUT/prefix-src/io/poly/candor/Classifier.java" || exit 2

  EX=soundness/kappa_census/latest_jars
  mkdir -p "$EX"
  for a in exposed-core exposed-jdbc exposed-dao; do
    [ -f "$EX/$a-1.5.0.jar" ] || curl -sSfL -o "$EX/$a-1.5.0.jar" \
      "https://repo1.maven.org/maven2/org/jetbrains/exposed/$a/1.5.0/$a-1.5.0.jar" || exit 2
  done

  probe() { java -cp "$1:$PROBE:$CJ_ALL" io.poly.candor.RuleFireProbe "${@:2}" | awk -F'\t' \
              '$1=="JAR"{printf "    %-28s covered=%-6s matched=%s\n",$2,$3,$4; t+=$4} END{print "  TOTAL MATCHED "t}'; }
  sum() { java -cp "$1:$PROBE:$CJ_ALL" io.poly.candor.RuleFireProbe "${@:2}" | awk -F'\t' '$1=="JAR"{t+=$4} END{print t+0}'; }

  echo
  echo "ARM B — PRE-FIX classifier ($PREFIX_COMMIT) x exposed 1.5.0   [expect 0: MUST FIRE]"
  probe "$OUT/prefix-classes" $EX/exposed-core-1.5.0.jar $EX/exposed-jdbc-1.5.0.jar $EX/exposed-dao-1.5.0.jar
  B=$(sum "$OUT/prefix-classes" $EX/exposed-core-1.5.0.jar $EX/exposed-jdbc-1.5.0.jar $EX/exposed-dao-1.5.0.jar)

  echo "ARM A — classifier UNDER TEST x exposed 1.5.0                 [expect >0: MUST BE SILENT]"
  probe "$OUT/classes" $EX/exposed-core-1.5.0.jar $EX/exposed-jdbc-1.5.0.jar $EX/exposed-dao-1.5.0.jar
  A=$(sum "$OUT/classes" $EX/exposed-core-1.5.0.jar $EX/exposed-jdbc-1.5.0.jar $EX/exposed-dao-1.5.0.jar)

  echo "CTRL  — PRE-FIX classifier x exposed 0.52.0 (its OWN version) [expect >0: not vacuously 0]"
  probe "$OUT/prefix-classes" soundness/lib/exposed-core-0.52.0.jar soundness/lib/exposed-jdbc-0.52.0.jar soundness/lib/exposed-dao-0.52.0.jar
  C=$(sum "$OUT/prefix-classes" soundness/lib/exposed-core-0.52.0.jar soundness/lib/exposed-jdbc-0.52.0.jar soundness/lib/exposed-dao-0.52.0.jar)

  # ARM D — the GATE, end to end, not just the counter.  Arms A-C prove RuleFireProbe can count zero
  # and can count non-zero; this proves rule_fires.py TURNS that into the right exit code, including
  # past the ADJUDICATED exposed-core entry (which must not swallow its two siblings).
  echo "ARM D — the GATE itself, --offline --only exposed, both rule sets"
  PROBE="$OUT/prefix-classes:$OUT/classes" python3 soundness/kappa_census/rule_fires.py \
      --offline --only exposed >/dev/null 2>&1; D_PRE=$?
  PROBE="$OUT/classes" python3 soundness/kappa_census/rule_fires.py \
      --offline --only exposed >/dev/null 2>&1; D_FIX=$?
  echo "    pre-fix rules -> exit $D_PRE (expect 1)    fixed rules -> exit $D_FIX (expect 0)"

  echo
  rc=0
  [ "$D_PRE" -eq 1 ] || { echo "CALIBRATION FAILED: the GATE exited $D_PRE on the shipped R509 rules, expected 1"; rc=1; }
  [ "$D_FIX" -eq 0 ] || { echo "CALIBRATION FAILED: the GATE exited $D_FIX on the fixed rules, expected 0"; rc=1; }
  [ "$B" -eq 0 ] || { echo "CALIBRATION FAILED: arm B matched $B, expected 0 — the probe would NOT have caught R509"; rc=1; }
  [ "$A" -gt 0 ] || { echo "CALIBRATION FAILED: arm A matched 0 — the probe fires on the CURRENT rules too"; rc=1; }
  [ "$C" -gt 0 ] || { echo "CALIBRATION FAILED: control matched 0 — arm B's zero says nothing"; rc=1; }
  if [ $rc -eq 0 ]; then
    echo "CALIBRATED: fires on the shipped R509 rules ($B), silent on the fixed ones ($A), control $C."
  fi
  exit $rc
fi

python3 soundness/kappa_census/rule_fires.py "$@"
