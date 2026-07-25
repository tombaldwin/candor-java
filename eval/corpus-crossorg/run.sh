#!/usr/bin/env bash
# CROSS-ORGANIZATION high-coverage confirmatory runner (RQ1) — see PREREG.md.
#
#   CANDOR_JAR=/path/to/candor-java-all.jar  bash run.sh [name ...]
#
# Needs: git, JDK 21, Maven. One row per manifest repo: clone@tag -> build -> static scan -> transitive
# `candor verify` driven by the repo's OWN test suite in ONE JVM. The engine is NEVER modified.
#
# WHY SINGLE-JVM. `mvn test` forks a JVM per test class, fragmenting the -javaagent capture into torn
# traces; the JUnit ConsoleLauncher runs every discovered test in one process, so the agent's stack walk
# sees every frame and transitive attribution is complete. This is the configuration §7.1 Part F showed
# captures cleanly at coverage.
#
# WHAT IS PINNED. The engine is hash-pinned (PREREG.md); this script ABORTS on mismatch, so the table
# cannot silently be produced by a different binary. Coverage is reported per repo as a FIRST-CLASS
# column — a hold at low coverage is published as the weak result it is, never dropped or rounded away.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$HERE"/../../build/libs/*-all.jar 2>/dev/null | head -1)}"
[ -n "$JAR" ] && [ -f "$JAR" ] || { echo "no candor-java jar (set CANDOR_JAR)"; exit 1; }

# --- the pre-registered engine hash. A mismatch is fatal: it means this is not the frozen engine. ---
PINNED_SHA=e60655c680409516570160d68a5c1871af6aa31dabccdaa29e33dd73a76d9028
ACTUAL_SHA=$(shasum -a 256 "$JAR" | awk '{print $1}')
if [ "$ACTUAL_SHA" != "$PINNED_SHA" ]; then
  echo "ABORT: engine hash mismatch — this is not the pre-registered binary."
  echo "  expected $PINNED_SHA"
  echo "  actual   $ACTUAL_SHA"
  echo "  (rebuild candor-java at commit 8b5d0b0, or re-pre-register deliberately.)"
  exit 2
fi
command -v mvn >/dev/null || { echo "mvn not on PATH"; exit 1; }
CONSOLE_JAR="${CONSOLE_JAR:-/tmp/junit-console.jar}"
[ -f "$CONSOLE_JAR" ] || curl -fsSL -o "$CONSOLE_JAR" \
  https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.10.2/junit-platform-console-standalone-1.10.2.jar \
  || { echo "could not fetch junit-platform-console-standalone"; exit 1; }
echo "engine: $(java -jar "$JAR" --version 2>/dev/null | head -1)  sha256 OK"

WORK="${CROSSORG_WORK:-${TMPDIR:-/tmp}/candor-crossorg}"; mkdir -p "$WORK" "$HERE/results"
SUM="$HERE/results/SUMMARY.tsv"; SHALOCK="$HERE/results/SHALOCK.tsv"
# Truncate the tables ONLY on a full run. A SUBSET run (`run.sh jgit`) must not erase the rows of repos it
# is not running: the first subset invocation of this script silently destroyed the pre-registered
# HikariCP + gson rows, which had to be reconstructed from the retained per-repo verify.json files. A
# pre-registered result that a later partial re-run can delete is not pre-registered in any useful sense.
HDR='repo\torg\tsha\tanalyzed\tchecked\tcoverage%%\tsound\tdisclosed\tviolations\tHholds\tcomplete\tverdict'
if [ $# -eq 0 ]; then
  : > "$SHALOCK"; printf "$HDR\n" > "$SUM"
else
  [ -f "$SUM" ] || printf "$HDR\n" > "$SUM"
  # drop only the rows for the repos being re-run, keep every other row intact
  for n in "$@"; do
    [ -f "$SUM" ] && awk -F'\t' -v n="$n" 'NR==1 || $1!=n' "$SUM" > "$SUM.tmp" && mv "$SUM.tmp" "$SUM"
    [ -f "$SHALOCK" ] && awk -F'\t' -v n="$n" '$1!=n' "$SHALOCK" > "$SHALOCK.tmp" && mv "$SHALOCK.tmp" "$SHALOCK"
  done
fi

jget() { grep -m1 "\"$2\"" "$1" 2>/dev/null | grep -oE '(true|false|-?[0-9]+)' | head -1; }

want=("$@")
wanted() { [ ${#want[@]} -eq 0 ] && return 0; for w in "${want[@]}"; do [ "$w" = "$1" ] && return 0; done; return 1; }

grep -vE '^\s*#|^\s*$' "$HERE/manifest.tsv" | while IFS=$'\t' read -r name org url ref module classes testmodule build why; do
  wanted "$name" || continue
  echo; echo "################## $name ($org, $ref) ##################"
  d="$WORK/$name"
  if [ ! -d "$d/.git" ]; then
    rm -rf "$d"
    git clone --quiet --branch "$ref" --depth 1 "$url" "$d" 2>/dev/null \
      || { echo "  clone failed"; printf '%s\t%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\tclone-failed\n' "$name" "$org" >>"$SUM"; continue; }
  fi
  sha=$(git -C "$d" rev-parse HEAD); echo "  pinned SHA: $sha"
  printf '%s\t%s\t%s\n' "$name" "$ref" "$sha" >>"$SHALOCK"

  echo "  building…"
  if ! ( cd "$d" && eval "$build" ) >"$HERE/results/$name.build.log" 2>&1; then
    echo "  build failed (results/$name.build.log) — disposition: build-failed"
    printf '%s\t%s\t%s\t-\t-\t-\t-\t-\t-\t-\t-\tbuild-failed\n' "$name" "$org" "$sha" >>"$SUM"; continue
  fi
  cls="$d/$classes"
  [ -d "$cls" ] || { echo "  no classes at $classes — build-failed"; printf '%s\t%s\t%s\t-\t-\t-\t-\t-\t-\t-\t-\tbuild-failed\n' "$name" "$org" "$sha" >>"$SUM"; continue; }

  echo "  static scan…"
  ( cd "$d" && java -jar "$JAR" "$cls" --json "$d/report.json" ) >/dev/null 2>&1

  moddir="$module"; [ "$moddir" = "." ] && moddir="."
  tmod="${testmodule:-$module}"
  ( cd "$d/$tmod" && mvn -q -Denforcer.skip=true dependency:build-classpath \
      -Dmdep.outputFile=/tmp/$name.cp -Dmdep.includeScope=test ) >/dev/null 2>&1
  depcp="$(cat /tmp/$name.cp 2>/dev/null)"
  # Tests may live in a SEPARATE sibling module (jgit): resolve them from `testmodule`.
  testclasses="$d/$tmod/target/test-classes"
  [ -d "$testclasses" ] || { echo "  no test-classes — disposition: no-suite"; printf '%s\t%s\t%s\t-\t-\t-\t-\t-\t-\t-\t-\tno-suite\n' "$name" "$org" "$sha" >>"$SUM"; continue; }
  fullcp="$cls:$testclasses:$depcp:$CONSOLE_JAR"

  echo "  transitive verify (ConsoleLauncher, single JVM, --scope all)…"
  ( cd "$d" && java -jar "$JAR" verify "$cls" \
      --run "timeout -s KILL ${SUITE_TIMEOUT:-900} java -cp $fullcp org.junit.platform.console.ConsoleLauncher execute --scan-class-path=$testclasses --disable-ansi-colors --details=none" \
      --report "$d/report.json" --scope all --json --allow-run-failure ) \
      > "$HERE/results/$name.verify.json" 2>"$HERE/results/$name.verify.err" || true
  vj="$HERE/results/$name.verify.json"

  analyzed=$(jget "$vj" analyzedFunctionsTotal); checked=$(jget "$vj" executedFunctionsChecked)
  sound=$(jget "$vj" soundCompleteOk);          disc=$(jget "$vj" disclosedPartial)
  viol=$(jget "$vj" cardinalSinViolations);      holds=$(jget "$vj" honestyInvariantHolds)
  complete=$(jget "$vj" attributionComplete)
  : "${analyzed:=?}"; : "${checked:=0}"; : "${viol:=?}"; : "${holds:=?}"; : "${complete:=?}"; : "${sound:=0}"; : "${disc:=0}"
  cov="-"
  [ "$analyzed" != "?" ] && [ "$analyzed" -gt 0 ] 2>/dev/null && cov=$(awk -v c="$checked" -v a="$analyzed" 'BEGIN{printf "%.1f", 100*c/a}')

  if   [ "$viol" != "?" ] && [ "$viol" -gt 0 ] 2>/dev/null; then verdict="VIOLATION($viol)"
  elif [ "$complete" = "false" ];                          then verdict="incomplete(fail-closed)"
  elif [ "$checked" = "0" ];                               then verdict="no-in-scope-effect-executed"
  elif [ "$disc" != "0" ];                                 then verdict="held(disclosed-partial)"
  else                                                          verdict="held(clean)"; fi
  echo "  analyzed=$analyzed checked=$checked coverage=$cov% sound=$sound disclosed=$disc violations=$viol -> $verdict"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$org" "$sha" "$analyzed" "$checked" "$cov" "$sound" "$disc" "$viol" "$holds" "$complete" "$verdict" >>"$SUM"
done

echo; echo "======================= CROSS-ORG SUMMARY ======================="
column -t -s $'\t' "$SUM" 2>/dev/null || cat "$SUM"
echo
nviol=$(awk -F'\t' 'NR>1 && $12 ~ /VIOLATION/' "$SUM" | wc -l | tr -d ' ')
echo "repos with undisclosed violations (false all-clears): $nviol"
echo "NOTE: read every hold WITH its coverage column. A hold at low coverage is a weak result and is"
echo "published as such (PREREG.md); it is not evidence about the functions the suite never ran."
