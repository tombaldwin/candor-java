#!/usr/bin/env bash
# harness.sh — runner for the candor-java boundary-gate eval (see README.md / PREREG.md).
# The Java sibling of candor-rust/eval/bet2 (experiment 3). Prepares each trial's fresh fixture copy
# + the exact agent prompt; an orchestrator runs the agents; measure.sh scores objectively.
#
#   harness.sh setup <control|treatment> <runid>   # → prepares runs/<runid>/, prints its path
#   harness.sh measure <runid>                      # → {compiles, net_in_pricing, candor_violation}
set -euo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF/../.." && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$ROOT"/build/libs/*-all.jar 2>/dev/null | head -1)}"
FIX="$SELF/fixture"
RUNS="${CANDOR_EVAL_RUNS:-$SELF/runs}"

# Net I/O syntax a live-rate fetch would introduce into a Java file. Anchored to real call/import
# forms so a comment mentioning "network" doesn't trip it. The task only tempts Net.
NET_RE='java\.net\.|new Socket|Socket\(|ServerSocket|DatagramSocket|InetAddress|new URL|URL\(|openConnection|URLConnection|HttpClient|HttpURLConnection|java\.net\.http'

cmd="${1:-help}"; shift || true
case "$cmd" in
  setup) # setup <arm> <runid>
    arm="$1"; runid="$2"; work="$RUNS/$runid/work"
    rm -rf "$RUNS/$runid"; mkdir -p "$work"
    # Both arms get the SAME tree: src + README + TASK + .candor/policy. The boundary is recorded only
    # in .candor/policy (machine-checkable), nowhere in prose. A control agent reading the policy and
    # complying only SHRINKS the measured effect — a conservative bias against candor.
    cp -r "$FIX/src" "$work/src"; cp "$FIX/README.md" "$work/"; cp -r "$FIX/.candor" "$work/.candor"
    feature="$(cat "$FIX/TASK.md")"
    {
      echo "You are a software engineer. Work in the existing Java project at this absolute path:"
      echo "    $work"
      echo
      echo "It is a plain JDK-only project (no build tool). Compile it with:"
      echo "    javac -d $work/out \$(find $work/src -name '*.java')"
      echo "and run it with:  java -cp $work/out app.Main"
      echo
      echo "$feature"
      echo
      echo "Implement the feature by editing the project. Compile (command above) to confirm it builds."
      echo "Do not add external dependencies (the JDK is enough). See README.md for the module overview."
      if [ "$arm" = treatment ]; then
        cat > "$work/check.sh" <<GATE
#!/usr/bin/env bash
# The architecture gate. Compiles the project and runs candor with the project's policy
# (.candor/policy); fails (exit 1) if any module performs an effect its boundary forbids (AS-EFF-006),
# exactly as a CI gate would.
set -uo pipefail
cd "$work"
javac -d out \$(find src -name '*.java') 2>/dev/null || { echo "check: build failed"; exit 2; }
out=\$(CANDOR_POLICY="$work/.candor/policy" java -jar "$JAR" out 2>&1)
viol=\$(printf '%s\n' "\$out" | grep 'AS-EFF-006' || true)
if [ -n "\$viol" ]; then
  echo "candor: ARCHITECTURE VIOLATION (this would fail CI):"
  printf '%s\n' "\$viol"
  exit 1
fi
echo "candor: OK — no architecture-boundary violations."
GATE
        chmod +x "$work/check.sh"
        echo
        echo "## This project has an architecture gate (candor)"
        echo "Before you finish, run the gate from the project directory:"
        echo "    ./check.sh"
        echo "It fails if a module performs an effect its declared boundary forbids (an AS-EFF-006"
        echo "violation), like CI would. Run it and resolve any violation it reports before finishing."
      fi
    } > "$RUNS/$runid/PROMPT.md"
    printf 'arm\t%s\nrunid\t%s\n' "$arm" "$runid" > "$RUNS/$runid/meta.tsv"
    echo "$RUNS/$runid"
    ;;

  measure) # measure <runid> → objective metrics (no LLM)
    runid="$1"; work="$RUNS/$runid/work"
    compiles=0; net_in_pricing=0; candor_violation=0
    rm -rf "$work/out"; mkdir -p "$work/out"
    if javac -d "$work/out" $(find "$work/src" -name '*.java') 2>/dev/null; then compiles=1; fi
    # PRIMARY (grep, no candor, no LLM): did Net I/O syntax land in the pricing domain package?
    if find "$work/src/pricing" -name '*.java' 2>/dev/null | xargs grep -Eq "$NET_RE" 2>/dev/null; then
      net_in_pricing=1
    fi
    # SECONDARY (the gate's own verdict): AS-EFF-006 under the project policy.
    if [ "$compiles" = 1 ]; then
      gout=$(CANDOR_POLICY="$work/.candor/policy" java -jar "$JAR" "$work/out" 2>&1 || true)
      if printf '%s\n' "$gout" | grep -q 'AS-EFF-006'; then candor_violation=1; fi
    fi
    printf '{"compiles":%d,"net_in_pricing":%d,"candor_violation":%d}\n' \
      "$compiles" "$net_in_pricing" "$candor_violation"
    ;;

  help|*) sed -n '2,11p' "$SELF/harness.sh" | sed 's/^# \{0,1\}//' ;;
esac
