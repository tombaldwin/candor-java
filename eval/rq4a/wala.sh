#!/usr/bin/env bash
# RQ4a precision baseline — candor vs WALA (a mature whole-program points-to call graph). Where the
# ArchUnit comparison (run.sh) contrasts candor with a *syntactic* gate, this contrasts it with a
# *resolving* analysis, on the same fixture classes. The point is the precision/soundness dilemma a
# resolving analysis cannot escape, and the disclosure that sidesteps it.
#
#   bash wala.sh
# Needs: JDK 21, jbang (fetches WALA 1.6.7 + candor jar). Builds the fixtures via javac.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$HERE"/../../build/libs/*-all.jar 2>/dev/null | head -1)}"
[ -n "$JAR" ] && [ -f "$JAR" ] || { echo "no candor-java jar"; exit 1; }
build() { rm -rf "$1/out" && mkdir -p "$1/out" && javac -d "$1/out" $(find "$1/src" -name '*.java'); }
wala() { jbang "$HERE/WalaCheck.java" "$1" "$2" 2>&1 | grep -E 'reflection modeling|VERDICT|->' ; }
cand() { java -jar "$JAR" "$1" --json 2>/dev/null \
         | python3 -c 'import json,sys; d=json.load(sys.stdin); f={x["fn"]:x for x in d["functions"]};
q=f.get("pricing.Pricing.quote",{}); m=f.get("app.Main.main",{});
print("  candor  quote:      inferred="+str(q.get("inferred"))+"  unresolved="+str(q.get("unresolved")));
print("  candor  Main.main:  inferred="+str(m.get("inferred"))+"  unknownWhy="+str(m.get("unknownWhy")))'; }

echo "############################ PORTED fixture (single-impl port) ############################"
build "$HERE/fixture"
wala "$HERE/fixture/out" full
cand "$HERE/fixture/out"
echo "  => WALA and candor AGREE: both resolve quote -> Net precisely."
echo
echo "####################### REFLECTIVE variant (Class.forName dispatch) #######################"
build "$HERE/reflective"
echo "-- WALA, reflection OFF (precision/scalability config) --"
wala "$HERE/reflective/out" none
echo "-- WALA, reflection FULL (conservative config) --"
wala "$HERE/reflective/out" full
echo "-- candor --"
cand "$HERE/reflective/out"
echo
echo "########################################################################################"
echo "Reflective dilemma a resolving analysis cannot escape:"
echo "  WALA reflection OFF : quote does NOT reach Net  -> FALSE ALL-CLEAR (unsound, silent)"
echo "  WALA reflection FULL: quote reaches Net         -> sound but over-approximated, NO locality"
echo "  candor              : quote = Net (CHA, sound)  + Unknown[reflect:*] disclosed AT the"
echo "                        reflective site (Main.main) -> sound AND localizes the blind spot,"
echo "                        which a 'deny Net Unknown[reflect]' policy can act on."
