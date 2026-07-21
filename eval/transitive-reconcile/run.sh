#!/usr/bin/env bash
# Transitive reconcile-against-reality runner (RQ1, JVM arm) — the paper's §7.1 Part F. Manifest-driven; one
# row per repo. Reuses the proven single-JVM ConsoleLauncher + `candor verify` transitive-attribution path of
# ../corpus-confirmatory/run_corpus.sh.
#
#   CANDOR_JAR=/path/to/candor-java-all.jar  bash run.sh [name ...]
#
# Needs: git, JDK 21, Maven (`mvn`) on PATH. Designed for the maven:3-eclipse-temurin-21 image. With no args
# runs every manifest row; with args only those names. Each repo: clone@tag -> build -> static scan ->
# transitive verify. The engine is NEVER modified.
#
# WHAT THIS REPRODUCES. On the CURRENT (post-fix) engine this reproduces the HOLDS: 0 undisclosed violations
# across the corpus, because the five classifier fixes (RECONCILE.md) are in the engine. To re-witness the 15
# CATCHES, rebuild the engine at the pre-fix commit RECONCILE.md gives per vein and re-run only that repo:
# the previously-silent frames then flag. The catches are additionally attested, without a re-run, by the
# named per-vein regression tests (RECONCILE.md) — a failing pre-fix engine is exactly what each gates.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$HERE"/../../build/libs/*-all.jar 2>/dev/null | head -1)}"
[ -n "$JAR" ] && [ -f "$JAR" ] || { echo "no candor-java jar (set CANDOR_JAR or build the -all.jar)"; exit 1; }
command -v mvn >/dev/null || { echo "mvn not on PATH — run in maven:3-eclipse-temurin-21"; exit 1; }
CONSOLE_JAR="${CONSOLE_JAR:-/tmp/junit-console.jar}"
if [ ! -f "$CONSOLE_JAR" ]; then
  curl -fsSL -o "$CONSOLE_JAR" \
    https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.10.2/junit-platform-console-standalone-1.10.2.jar \
    || { echo "could not fetch junit-platform-console-standalone"; exit 1; }
fi
echo "engine: $(java -jar "$JAR" --version 2>/dev/null | head -1)"

WORK="${RECONCILE_WORK:-${TMPDIR:-/tmp}/candor-reconcile}"; mkdir -p "$WORK" "$HERE/results"
SHALOCK="$HERE/results/SHALOCK.tsv"; SUM="$HERE/results/SUMMARY.tsv"
: > "$SHALOCK"; printf 'repo\tsha\tanalyzed\tchecked\tsound\tdisclosed\tviolations\tHholds\tcomplete\tverdict\n' > "$SUM"

# Extract one numeric/boolean field from pretty-printed JSON (first match).
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

  git -C "$d" clean -fdxq 2>/dev/null || true
  # Compat only (not a code change): JDK 21 rejects source/target 6-7. Bump hardcoded <source>/<target> 1.6/1.7.
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

  # DYNAMIC TRANSITIVE VERIFY via the JUnit Platform ConsoleLauncher in ONE JVM (NOT `mvn test` — Surefire
  # forks the test JVMs and the -javaagent does not propagate into the forks). The agent walks the live stack
  # and charges each effect to every analyzed frame on it (transitive attribution), so a caller that reaches
  # an effect through a dropped/dynamic edge is checked, not only the leaf.
  moddir="${classes%/target/classes}"; [ "$moddir" = "$classes" ] && moddir="."
  ( cd "$d/$moddir" && mvn -q -Drat.skip=true dependency:build-classpath \
      -Dmdep.outputFile=/tmp/$name.cp -Dmdep.includeScope=test ) >/dev/null 2>&1
  depcp="$(cat /tmp/$name.cp 2>/dev/null)"
  testclasses="$d/$moddir/target/test-classes"
  fullcp="$cls:$testclasses:$depcp:$CONSOLE_JAR"
  echo "  transitive verify (ConsoleLauncher, single JVM, --scope all)…"
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

echo; echo "======================= RECONCILE SUMMARY (post-fix engine) ======================="
column -t -s $'\t' "$SUM" 2>/dev/null || cat "$SUM"
echo
nviol=$(awk -F'\t' 'NR>1 && $10 ~ /VIOLATION/' "$SUM" | wc -l | tr -d ' ')
echo "repos with undisclosed violations (false all-clears) on the post-fix engine: $nviol"
[ "$nviol" = 0 ] && echo "=> Holds reproduced: the five fixes cover the caught veins (0 undisclosed violations). To re-witness the catches, rebuild the pre-fix engine per RECONCILE.md and re-run the fix-driving repo." \
                 || { echo "=> Unexpected violations (would indicate a regression or a NEW vein):"; awk -F'\t' 'NR>1 && $10 ~ /VIOLATION/ {print "   "$1" ("$10")"}' "$SUM"; }
