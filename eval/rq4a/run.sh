#!/usr/bin/env bash
# RQ4a — the motivating claim of §2, run on code: an architecture-conformance gate (ArchUnit) passes
# GREEN exactly where candor fires RED, because the effect reaches the guarded layer through an injected
# port that the import graph cannot see through. A control (the same effect inlined) shows the ArchUnit
# rule has teeth — so its green on the ported version is the DI blindness, not a toothless rule.
#
#   bash run.sh
# Needs: JDK 21 (javac/java), jbang (fetches ArchUnit 1.3.0 from Maven Central on first run), and the
# candor-java fat jar (build/libs/*-all.jar). Deterministic; no network needed except jbang's one-time
# dependency fetch.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$HERE"/../../build/libs/*-all.jar 2>/dev/null | head -1)}"
[ -n "$JAR" ] && [ -f "$JAR" ] || { echo "no candor-java jar — run ./gradlew shadowJar first"; exit 1; }
command -v jbang >/dev/null || { echo "jbang not found — install from https://jbang.dev"; exit 1; }

arch() { jbang "$HERE/ArchCheck.java" "$1" 2>&1 | grep -vE '^\[jbang\]|SLF4J'; }
candor() { CANDOR_POLICY="$2" java -jar "$JAR" "$1" 2>&1 | grep -E 'AS-EFF-006|OK —'; }

build() { rm -rf "$1/out" && mkdir -p "$1/out" && javac -d "$1/out" $(find "$1/src" -name '*.java'); }

echo "###################### RQ4a: ArchUnit vs candor on the SAME classes ######################"
echo
echo "======================= PORTED domain (java.net behind an injected port) ================="
build "$HERE/fixture"
arch    "$HERE/fixture/out"
echo "--- candor (effect-reachability) ---"
candor  "$HERE/fixture/out" "$HERE/fixture/.candor/policy"
echo
echo "======================= CONTROL: INLINE domain (direct java.net dependency) =============="
build "$HERE/control-inline"
arch    "$HERE/control-inline/out"
echo "--- candor (effect-reachability) ---"
candor  "$HERE/control-inline/out" "$HERE/control-inline/.candor/policy"
echo
echo "########################################################################################"
echo "Expected 2x2:"
echo "  ported : ArchUnit GREEN | candor RED  (candor catches what the import graph cannot see)"
echo "  inline : ArchUnit RED   | candor RED  (control — the ArchUnit rule has teeth)"
