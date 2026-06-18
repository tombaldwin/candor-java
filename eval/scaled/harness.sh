#!/usr/bin/env bash
# harness.sh — reproducible runner for the candor-JAVA scaled edit-quality eval (see README.md).
#
# The Java sibling of candor-rust/eval/scaled/harness.sh. It does NOT call an LLM (the one
# non-scriptable part). It prepares each trial's fresh fixture copy + the exact agent prompt, verifies
# task completion objectively with candor-java (compile bytecode → scan → diff vs baseline), and emits
# the blind judge prompt. An orchestrator (a human, or an agent-spawning harness) runs the agents.
#
#   harness.sh setup <task> <control|treatment> <runid>   # → prepares runs/<runid>/, prints its path
#   harness.sh verify <runid>                              # → did the edit introduce the effect? (objective)
#   harness.sh judge-prompt <task> <summary-file>          # → prints the blind judge prompt for a summary
#   harness.sh tasks                                       # → list tasks + their target effect
#
# Tasks: catalog (Fs), geo (Net), render (Exec). Each is a 6-file layered Java app (repo→service→
# controller→report→main) where one natural edit makes a low-level method gain an effect that
# propagates to 7 functions (see each task's GROUND_TRUTH.md). JDK-only: javac compiles offline.
set -euo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF/../.." && pwd)"
# The candor-java fat jar. Overridable; defaults to the newest -all.jar the gradle build produced.
JAR="${CANDOR_JAR:-$(ls -t "$ROOT"/build/libs/*-all.jar 2>/dev/null | head -1)}"
TASKS="${CANDOR_EVAL_TASKS:-$SELF/tasks}"
RUNS="${CANDOR_EVAL_RUNS:-$SELF/runs}"
CACHE="$SELF/.cache/$(basename "$TASKS")"

effect_of(){ case "$1" in
  catalog) echo Fs ;; geo) echo Net ;; render) echo Exec ;;
  *) echo "harness: unknown task '$1' (catalog|geo|render)" >&2; exit 2 ;;
esac; }

# The NON-LOCAL functions each task's effect propagates to (the edited fn excluded) — the
# completeness denominator. Class.method form, matched against the agent's summary by the judge.
nonlocal_of(){ case "$1" in
  catalog) echo "CatalogService.lookup CatalogService.batch CatalogController.getOne CatalogController.getMany DashboardReport.build Main.main" ;;
  geo)     echo "GeoService.locate GeoService.batch GeoController.lookupOne GeoController.lookupMany GeoReport.summary Main.main" ;;
  render)  echo "Page.renderToken Page.render RenderController.renderOne RenderController.renderMany RenderReport.buildAll Main.main" ;;
esac; }

# Compile a src tree to <dir>/out (JDK-only; no build tool). Echoes nothing; returns javac's status.
compile(){ # <work-dir>
  local w="$1"; rm -rf "$w/out"; mkdir -p "$w/out"
  javac -d "$w/out" $(find "$w/src" -name '*.java') 2>/dev/null
}

# Cache a pristine pre-edit baseline report per task (the fixture never changes).
baseline_for(){ # <task> → echoes path to baseline.json
  local task="$1" d="$CACHE/$task"
  if [ ! -f "$d/baseline.json" ]; then
    rm -rf "$d"; mkdir -p "$d/src"; cp -r "$TASKS/$task/src/." "$d/src/"
    compile "$d"
    java -jar "$JAR" "$d/out" --json "$d/baseline.json" >/dev/null 2>&1
  fi
  echo "$d/baseline.json"
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  tasks)
    for t in catalog geo render; do printf '  %-8s %s\n' "$t" "$(effect_of "$t")"; done ;;

  setup) # setup <task> <condition> <runid>
    task="$1"; cond="$2"; runid="$3"; effect="$(effect_of "$task")"
    work="$RUNS/$runid/work"
    rm -rf "$RUNS/$runid"; mkdir -p "$work/src"
    # Copy ONLY src into the agent's working dir — never GROUND_TRUTH.md / TASK.md, which would hand it
    # the answer. The task reaches the agent via the prompt only.
    cp -r "$TASKS/$task/src/." "$work/src/"
    bl="$(baseline_for "$task")"; cp "$bl" "$RUNS/$runid/baseline.json"
    feature="$(cat "$TASKS/$task/TASK.md")"
    {
      echo "You are a software engineer. Work in the existing Java project at this absolute path:"
      echo "    $work"
      echo
      echo "It is a plain JDK-only project (no build tool). Compile it with:"
      echo "    javac -d $work/out \$(find $work/src -name '*.java')"
      echo
      echo "## Task"
      echo "$feature"
      echo
      echo "Implement the feature by editing the project. Compile (command above) to confirm it builds."
      echo "Do not add external dependencies (the JDK is enough)."
      echo
      echo "When done, end your reply with a section titled exactly '## Summary' — 3 to 6 sentences"
      echo "describing what you changed and any consequences for the rest of the codebase that a"
      echo "reviewer should know about."
      if [ "$cond" = treatment ]; then
        mkdir -p "$work/.candor"; cp "$bl" "$work/.candor/baseline.json"
        # One-shot diff script: recompile, scan, diff vs the pre-edit baseline — the candor-java
        # analogue of the Rust arm's single `cargo candor diff .candor/baseline`.
        cat > "$work/candor-diff.sh" <<DIFF
#!/usr/bin/env bash
set -e
cd "$work"
javac -d out \$(find src -name '*.java')
java -jar "$JAR" out --json .candor/cur.json >/dev/null
java -jar "$JAR" diff .candor/cur.json .candor/baseline.json
DIFF
        chmod +x "$work/candor-diff.sh"
        echo
        echo "## This project uses candor (an effect/capability checker)"
        echo "A baseline of the pre-edit effects is saved at .candor/baseline.json. After you finish"
        echo "editing, run this from the project directory:"
        echo "    ./candor-diff.sh"
        echo "It reports, per function, the effects each one gained versus the baseline. Read it and"
        echo "fold anything relevant into your '## Summary'."
      fi
    } > "$RUNS/$runid/PROMPT.md"
    printf 'task\t%s\ncondition\t%s\nrunid\t%s\neffect\t%s\n' "$task" "$cond" "$runid" "$effect" \
      > "$RUNS/$runid/meta.tsv"
    echo "$RUNS/$runid"
    ;;

  verify) # verify <runid> — objective: did the agent's edit introduce the task's effect?
    runid="$1"; work="$RUNS/$runid/work"
    effect="$(awk -F'\t' '$1=="effect"{print $2}' "$RUNS/$runid/meta.tsv")"
    if ! compile "$work"; then echo "ERROR: could not evaluate (build failure)"; exit 0; fi
    java -jar "$JAR" "$work/out" --json "$RUNS/$runid/cur.json" >/dev/null 2>&1 || true
    dj="$(java -jar "$JAR" diff "$RUNS/$runid/cur.json" "$RUNS/$runid/baseline.json" --json 2>/dev/null || true)"
    gained="$(printf '%s' "$dj" | python3 -c "import json,sys
try:
    d=json.load(sys.stdin); e='$effect'
    print(len([c for c in d.get('changes',[]) if e in c.get('gained',[])]))
except Exception:
    print('')" 2>/dev/null || true)"
    if [ -z "$dj" ] || case "$gained" in ''|*[!0-9]*) true ;; *) false ;; esac; then
      echo "ERROR: could not evaluate (scan/diff produced no usable output)"
    elif [ "$gained" -gt 0 ]; then
      echo "COMPLETED: $gained function(s) gained $effect (task implemented)"
    else
      echo "INCOMPLETE: no function gained $effect (task not implemented as expected)"
    fi
    ;;

  judge-prompt) # judge-prompt <task> <summary-file>
    task="$1"; sumf="$2"; effect="$(effect_of "$task")"
    # Redact the tool's identity so the judge is BLIND to condition. Map every candor reference to a
    # neutral "the analysis" — a phrase an agent could equally use for manual call-graph reasoning.
    redacted="$(sed -E \
      -e 's#\./candor-diff\.sh#the analysis#g' \
      -e 's#candor-diff\.sh#the analysis#g' \
      -e 's#\.candor/[A-Za-z.]*#the baseline#g' \
      -e "s#[Cc]andor'\''s( diff)?#the analysis#g" \
      -e 's#[Cc]andor#the analysis#g' "$sumf")"
    nl="$(nonlocal_of "$task")"; k="$(echo "$nl" | wc -w | tr -d ' ')"
    nl_lines="$(for f in $nl; do echo "  - $f"; done)"
    cat <<EOF
You are grading ONE software-engineering summary, BLIND, strictly and mechanically.

The engineer made a change that makes a low-level function gain the effect "$effect". That effect then
propagates transitively to these $k OTHER functions (the "propagation set"):
$nl_lines

PART 1 — COMPLETENESS (primary). For EACH function in the propagation set above, decide whether the
summary identifies it as now performing "$effect" — i.e. the function is named explicitly (the method
name is enough; class qualifier optional), OR it is covered by an explicit blanket statement ("all
callers", "every caller", "the whole call chain up to main"). A function merely existing in the code
does NOT count; the summary must indicate IT gains the effect. Output one line per function, in order:
  <function>: yes
  <function>: no
Then a single line:
  COMPLETENESS: <number-of-yes>/$k

PART 2 — BINARY AWARENESS (secondary). One line:
  VERDICT: yes|partial|no
where yes = names >=1 specific non-local caller OR the full set; partial = notes a generic
"callers/performance are affected" WITHOUT naming a specific non-local caller; no = only the local change.

Output ONLY the per-function lines, the COMPLETENESS line, and the VERDICT line. No other text.

--- SUMMARY TO GRADE ---
$redacted
--- END SUMMARY ---
EOF
    ;;

  help|*) sed -n '2,16p' "$SELF/harness.sh" | sed 's/^# \{0,1\}//' ;;
esac
