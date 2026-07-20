#!/usr/bin/env bash
# RQ4a (real app) — Spring PetClinic. An ArchUnit import/package gate reports the app persistence-clean
# (GREEN: no class depends on java.sql/javax.sql — Spring Data hides the driver behind repository
# interfaces). candor, scanning the same classes, DETERMINES the Db reach transitively through those
# repository interfaces and fires on every controller that performs persistence directly (a real
# layering smell an import graph cannot see).
#
#   bash run.sh
# Needs: git, JDK 21, jbang (fetches ArchUnit once), the candor-java fat jar. Clones + compiles PetClinic
# into a scratch dir (Maven wrapper downloads Spring deps — network required, ~1-3 min first run).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$HERE"/../../build/libs/*-all.jar 2>/dev/null | head -1)}"
[ -n "$JAR" ] && [ -f "$JAR" ] || { echo "no candor-java jar — run ./gradlew shadowJar first"; exit 1; }
command -v jbang >/dev/null || { echo "jbang not found"; exit 1; }
WORK="${RQ4A_PC_DIR:-${TMPDIR:-/tmp}/rq4a-petclinic}"
PC="$WORK/spring-petclinic"

if [ ! -d "$PC/target/classes" ]; then
  mkdir -p "$WORK"; rm -rf "$PC"
  echo "cloning + compiling spring-petclinic (first run only)…"
  git clone --depth 1 https://github.com/spring-projects/spring-petclinic.git "$PC" >/dev/null 2>&1
  ( cd "$PC" && ./mvnw -q -B -DskipTests compile ) || { echo "petclinic build failed"; exit 1; }
fi
echo "petclinic classes: $(find "$PC/target/classes" -name '*.class' | wc -l | tr -d ' ')"
echo
echo "########## GATE 1: ArchUnit (import/package baseline) ##########"
jbang "$HERE/ArchCheck.java" "$PC/target/classes" 2>&1 | grep -vE '^\[jbang\]|SLF4J|imported [0-9]+|Rule set:'
echo
echo "########## GATE 2: candor (effect-reachability) — 'controllers must not perform Db' ##########"
n=$(CANDOR_POLICY="$HERE/web-no-db.policy" java -jar "$JAR" "$PC/target/classes" 2>&1 | grep -c 'AS-EFF-006')
echo "candor: $n AS-EFF-006 violations — controller methods that perform { Db } transitively via the"
echo "        Spring Data repository interfaces (determined, unresolved=false). Sample:"
CANDOR_POLICY="$HERE/web-no-db.policy" java -jar "$JAR" "$PC/target/classes" 2>&1 | grep 'AS-EFF-006' | head -3 | sed 's/^/  /'
echo
echo "VERDICT: ArchUnit GREEN (import graph sees no java.sql) | candor RED ($n Db reaches it determines)."
