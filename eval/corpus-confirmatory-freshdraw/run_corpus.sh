#!/usr/bin/env bash
# Frozen confirmatory corpus runner (RQ1, JVM arm). See PREREG.md. Manifest-driven; one row per repo.
#
#   CANDOR_JAR=/path/to/candor-java-0.23.1-all.jar  bash run_corpus.sh [name ...]
#
# Needs: git, JDK 21, Maven (`mvn`) on PATH, and the FROZEN candor-java v0.23.1 -all.jar. Designed for the
# maven:3-eclipse-temurin-21 image (no python needed — verdicts are extracted from `verify --json` with
# grep). With no args runs every manifest row; with args only those names (for a smoke run). Each repo is
# clone@tag -> build -> static scan -> verify; the engine is never modified.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$HERE"/../../build/libs/*-all.jar 2>/dev/null | head -1)}"
[ -n "$JAR" ] && [ -f "$JAR" ] || { echo "no candor-java jar (set CANDOR_JAR or build the v0.23.1 -all.jar)"; exit 1; }
command -v mvn >/dev/null || { echo "mvn not on PATH — run in maven:3-eclipse-temurin-21"; exit 1; }
# The single-JVM test driver (see the dynamic-verify step). Fetched once from Maven Central if absent.
CONSOLE_JAR="${CONSOLE_JAR:-/tmp/junit-console.jar}"
if [ ! -f "$CONSOLE_JAR" ]; then
  curl -fsSL -o "$CONSOLE_JAR" \
    https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.10.2/junit-platform-console-standalone-1.10.2.jar \
    || { echo "could not fetch junit-platform-console-standalone"; exit 1; }
fi
VER=$(java -jar "$JAR" --version 2>/dev/null | head -1)
echo "engine (frozen): $VER"
case "$VER" in *0.23.*) : ;; *) echo "WARNING: PREREG pins v0.23.1; got '$VER' — record the deviation.";; esac

WORK="${CORPUS_WORK:-${TMPDIR:-/tmp}/candor-corpus}"; mkdir -p "$WORK" "$HERE/results"
SHALOCK="$HERE/results/SHALOCK.tsv"; SUM="$HERE/results/SUMMARY.tsv"
: > "$SHALOCK"; printf 'repo\tsha\tanalyzed\tchecked\tsound\tdisclosed\tviolations\tHholds\tcomplete\tverdict\n' > "$SUM"

# Extract one numeric/boolean field from a pretty-printed JSON file (first match).
jget() { grep -m1 "\"$2\"" "$1" 2>/dev/null | grep -oE '(true|false|-?[0-9]+)' | head -1; }

want=("$@")
wanted() { [ ${#want[@]} -eq 0 ] && return 0; for w in "${want[@]}"; do [ "$w" = "$1" ] && return 0; done; return 1; }

grep -vE '^\s*#|^\s*$' "$HERE/manifest.tsv" | while IFS=$'\t' read -r name url ref classes build test why; do
  wanted "$name" || continue
  echo; echo "################## $name ($ref) ##################"
  d="$WORK/$name"
  if [ ! -d "$d/.git" ]; then
    rm -rf "$d"
    git clone --quiet --branch "$ref" --depth 1 "$url" "$d" 2>/dev/null \
      || { echo "  clone failed — disposition: clone-failed"; printf '%s\t%s\tCLONE-FAILED\n' "$name" "$ref" >>"$SHALOCK"; continue; }
  fi
  sha=$(git -C "$d" rev-parse HEAD); echo "  pinned SHA: $sha"
  printf '%s\t%s\t%s\n' "$name" "$ref" "$sha" >>"$SHALOCK"

  # Pristine tree before each build: our own report/log artifacts (and .candor/) otherwise trip a repo's
  # build-hygiene check (e.g. Apache RAT license-check) on re-runs. Clean removes untracked incl. stale target.
  git -C "$d" clean -fdxq 2>/dev/null || true
  # Compat only (not a code change): JDK 21 rejects source/target 6-7. Bump any hardcoded <source>/<target>
  # 1.6/1.7 in the repo's poms to 8 so pre-JDK-8 libraries compile. Recorded as a build-compat deviation.
  find "$d" -name pom.xml -exec sed -i -E 's#<(source|target)>1\.[67]</(source|target)>#<\1>8</\2>#g' {} + 2>/dev/null || true
  echo "  building…"
  if ! ( cd "$d" && eval "$build" ) >"/tmp/$name.build.log" 2>&1; then
    cp "/tmp/$name.build.log" "$HERE/results/$name.build.log" 2>/dev/null || true
    echo "  build failed (see results/$name.build.log) — disposition: build-failed"
    printf '%s\t%s\t-\t-\t-\t-\t-\t-\t-\tbuild-failed\n' "$name" "$sha" >>"$SUM"; continue
  fi
  cls="$d/$classes"
  [ -d "$cls" ] || { echo "  no classes at $classes — build-failed"; printf '%s\t%s\t-\t-\t-\t-\t-\t-\t-\tbuild-failed\n' "$name" "$sha" >>"$SUM"; continue; }

  echo "  static scan…"
  ( cd "$d" && java -jar "$JAR" "$cls" --json "$d/report.json" ) >/dev/null 2>&1

  # DYNAMIC VERIFY via the JUnit Platform ConsoleLauncher in ONE JVM — NOT `mvn test`. Surefire forks the
  # test JVMs and the -javaagent (wired through JAVA_TOOL_OPTIONS by `candor verify`) does not propagate into
  # the forks, so mvn-test yields checked=0 even on effect-performing code (verified on commons-io). The
  # ConsoleLauncher runs the whole suite in the single JVM the agent attaches to. Needs the repo's test
  # classpath: its own main+test classes + all (test-scope) dependencies + the console-standalone jar.
  moddir="${classes%/target/classes}"; [ "$moddir" = "$classes" ] && moddir="."
  ( cd "$d/$moddir" && mvn -q -Drat.skip=true dependency:build-classpath \
      -Dmdep.outputFile=/tmp/$name.cp -Dmdep.includeScope=test ) >/dev/null 2>&1
  depcp="$(cat /tmp/$name.cp 2>/dev/null)"
  testclasses="$d/$moddir/target/test-classes"
  fullcp="$cls:$testclasses:$depcp:$CONSOLE_JAR"
  echo "  dynamic verify (ConsoleLauncher, single JVM, --scope all)…"
  ( cd "$d" && java -jar "$JAR" verify "$cls" \
      --run "timeout -s KILL 480 java -cp $fullcp org.junit.platform.console.ConsoleLauncher execute --scan-class-path=$testclasses --disable-ansi-colors --details=none" \
      --report "$d/report.json" --scope all --json --allow-run-failure ) \
      > "$HERE/results/$name.verify.json" 2>"$d/verify.err" || true
  vj="$HERE/results/$name.verify.json"

  analyzed=$(jget "$vj" analyzedFunctionsTotal); checked=$(jget "$vj" executedFunctionsChecked)
  sound=$(jget "$vj" soundCompleteOk);          disc=$(jget "$vj" disclosedPartial)
  viol=$(jget "$vj" cardinalSinViolations);      holds=$(jget "$vj" honestyInvariantHolds)
  complete=$(jget "$vj" attributionComplete)
  : "${analyzed:=?}"; : "${checked:=0}"; : "${viol:=?}"; : "${holds:=?}"; : "${complete:=?}"; : "${sound:=0}"; : "${disc:=0}"

  if   [ "$viol" != "?" ] && [ "$viol" -gt 0 ] 2>/dev/null; then verdict="VIOLATION($viol)"
  elif [ "$complete" = "false" ];                          then verdict="incomplete(fail-closed)"
  elif [ "$checked" = "0" ];                               then verdict="no-in-scope-effect-executed"
  elif [ "$disc" != "0" ];                                 then verdict="disclosed-partial"
  else                                                          verdict="clean"; fi
  echo "  analyzed=$analyzed checked=$checked sound=$sound disclosed=$disc violations=$viol Hholds=$holds complete=$complete -> $verdict"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$sha" "$analyzed" "$checked" "$sound" "$disc" "$viol" "$holds" "$complete" "$verdict" >>"$SUM"
done

echo; echo "======================= CONFIRMATORY SUMMARY ======================="
column -t -s $'\t' "$SUM" 2>/dev/null || cat "$SUM"
echo
nviol=$(awk -F'\t' 'NR>1 && $10 ~ /VIOLATION/' "$SUM" | wc -l | tr -d ' ')
echo "repos with undisclosed violations (false all-clears): $nviol"
[ "$nviol" = 0 ] && echo "=> No false all-clear on the completed corpus (coverage per-repo above; a 'clean' row with checked=0 is a pure library, not a coverage claim)." \
                 || { echo "=> Violations (reported, NOT fixed in this run):"; awk -F'\t' 'NR>1 && $10 ~ /VIOLATION/ {print "   "$1" ("$10")"}' "$SUM"; }
