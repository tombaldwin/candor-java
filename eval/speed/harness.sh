#!/usr/bin/env bash
# harness.sh — runner for the candor-java token/speed eval (see README.md / PREREG.md).
# Java sibling of candor-rust/eval/scaled/{PREREG-speed,harness}. The blast-radius ANALYSIS question
# (not an edit): both arms answer "every transitive caller of pricing.Pricing.quote"; treatment has a
# candor report + query, control works from source. The orchestrator spawns the agents and records
# subagent_tokens / tool_uses / duration_ms from the harness, plus recall vs the 16-fn ground truth.
#
#   harness.sh setup <control|treatment> <runid>   # → prepares runs/<runid>/, prints its path
#   harness.sh truth                                # → the candor-computed 16-fn transitive-caller set
set -euo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF/../.." && pwd)"
JAR="${CANDOR_JAR:-$(ls -t "$ROOT"/build/libs/*-all.jar 2>/dev/null | head -1)}"
FIX="$SELF/fixture"
RUNS="${CANDOR_EVAL_RUNS:-$SELF/runs}"
TARGET="pricing.Pricing.quote"

build_report(){ # <dest .candor dir> — compile the fixture + write report.json there
  local d="$1"; rm -rf /tmp/speed_build && mkdir -p /tmp/speed_build/out
  javac -d /tmp/speed_build/out $(find "$FIX/src" -name '*.java') 2>/dev/null
  mkdir -p "$d"; java -jar "$JAR" /tmp/speed_build/out --json "$d/report.json" >/dev/null 2>&1
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  truth) build_report /tmp/speed_truth
    java -jar "$JAR" callers /tmp/speed_truth/report.json "$TARGET" 2>/dev/null \
      | grep -oE '[a-z]+\.[A-Za-z]+\.[A-Za-z]+' | sort -u ;;

  setup) # setup <arm> <runid>
    arm="$1"; runid="$2"; work="$RUNS/$runid/work"
    rm -rf "$RUNS/$runid"; mkdir -p "$work"
    cp -r "$FIX/src" "$work/src"     # both arms can read the source
    {
      echo "You are analyzing the Java project at this absolute path:"
      echo "    $work"
      echo
      echo "Question: if the function \`pricing.Pricing.quote\` gained the \`Net\` effect (it starts"
      echo "performing network I/O), which OTHER functions in this project would transitively perform"
      echo "\`Net\` as a result — i.e. every transitive caller of \`Pricing.quote\`? Be exhaustive: list"
      echo "EVERY affected function across the whole project. Return ONLY a list of function names"
      echo "(package.Type.method), one per line, no commentary."
      echo
      if [ "$arm" = treatment ]; then
        build_report "$work/.candor"
        echo "candor is set up: an effect report is at \`$work/.candor/report.json\`, and the query tool"
        echo "answers transitive callers directly. Run:"
        echo "    java -jar $JAR callers $work/.candor/report.json $TARGET"
        echo "(or \`java -jar $JAR whatif $work/.candor/report.json $TARGET Net\` for the blast radius). Use it."
      else
        echo "Work from the source code."
      fi
    } > "$RUNS/$runid/PROMPT.md"
    printf 'arm\t%s\nrunid\t%s\n' "$arm" "$runid" > "$RUNS/$runid/meta.tsv"
    echo "$RUNS/$runid"
    ;;

  help|*) sed -n '2,12p' "$SELF/harness.sh" | sed 's/^# \{0,1\}//' ;;
esac
