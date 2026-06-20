#!/usr/bin/env bash
# ============================================================================================
# corpus.sh — the candor-java dynamic model-gap CORPUS HARNESS.
#
# Runs candor-java's two RUNTIME oracles over a LIST of real programs automatically, so model-gap
# discovery is systematic instead of hand-picked. For each corpus entry it:
#   (1) produces candor's STATIC report on the entry's classpath,
#   (2) runs jfr_diff.py   (Fs / Net — JFR oracle),
#   (3) runs agent_diff.py (Exec / Db / Env / Clock / Rand / Log — leaf-instrumenting agent),
#   (4) collects any CONFIRMED under-report (effect observed at runtime that candor's static report
#       predicts as neither that effect nor Unknown).
# At the end it prints a per-entry summary + an aggregate, and EXITS NON-ZERO if any confirmed
# under-report was found (so it can gate / be wired into a sweep).
#
# An under-report here is the candor MODEL-GAP signal: the program really did the effect, candor missed
# it AND did not disclose Unknown. `Unknown` in the static report is a PASS (sound disclosure). A known/
# accepted gap (e.g. the abstract-java.io.Reader boundary) will surface here too — that is the harness
# working, not a regression; triage decides real-vs-accepted.
#
# ADDING A PROGRAM IS ONE LINE: append an `entry ...` call in corpus_entries() below (see its header).
# That extensibility is the deliverable — new programs are a single line.
#
# Does NOT touch candor's gradle build or Candor.java. Uses the EXISTING -all.jar. Never runs ./gradlew.
# ============================================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
JFR_DIFF="$HERE/jfr_diff.py"
AGENT_DIFF="$HERE/agent/agent_diff.py"
AGENT_JAR="$HERE/agent/build/candor-agent.jar"
CORPUS_SRC="$HERE/corpus"                       # seed program sources live here (checked in)
SELFTEST_DIR="$HERE"                            # SelfTest.java lives one level up from corpus/
AGENT_SELFTEST_DIR="$HERE/agent"               # AgentSelfTest.java + StubDriver.java

# Work area — only under /tmp, per the brief (another process may be using the repo concurrently).
WORK="${CORPUS_WORK:-/tmp/candor-corpus}"

# Locate the existing candor -all.jar (highest version). Never rebuilds.
CANDOR_JAR="$(ls -1 "$HERE"/../../build/libs/candor-java-*-all.jar 2>/dev/null | sort -V | tail -1)"

# ---------------------------------------------------------------------------------------------
# COMPILE STEP — build every source we need into per-program classes dirs under $WORK.
# Editable: add a javac line for any new seed source. Self-tests are reused verbatim.
# ---------------------------------------------------------------------------------------------
compile_all() {
  rm -rf "$WORK"
  mkdir -p "$WORK"

  echo "== compiling corpus programs into $WORK =="

  # Existing self-tests (reused as corpus entries).
  javac -d "$WORK/selftest"       "$SELFTEST_DIR/SelfTest.java"
  javac -d "$WORK/agentselftest"  "$AGENT_SELFTEST_DIR/AgentSelfTest.java" "$AGENT_SELFTEST_DIR/StubDriver.java"

  # New seed programs (package corpus.*). Each compiled to its OWN classes dir so candor's static
  # report and the runtime cp are scoped to exactly that program.
  javac -d "$WORK/hofio"          "$CORPUS_SRC/HofIo.java"
  javac -d "$WORK/strategy"       "$CORPUS_SRC/Strategy.java"
  javac -d "$WORK/absreader"      "$CORPUS_SRC/AbstractReaderParse.java"
  javac -d "$WORK/asyncnetfs"     "$CORPUS_SRC/AsyncNetFs.java"
  javac -d "$WORK/asyncexec"      "$CORPUS_SRC/AsyncExec.java"

  echo "== compiled =="
}

# ---------------------------------------------------------------------------------------------
# THE CORPUS — one `entry` line per program. THIS is the editable manifest.
#
#   entry <label> <classes-dir-or-jar> <MainClass> <tool> <pkg-prefix> [program args...]
#
#     label        short id printed in the summary
#     classpath    compiled classes dir (under $WORK) or a jar
#     MainClass    fully-qualified main class to run
#     tool         jfr | agent | both   (which oracle(s) to run)
#     pkg-prefix   frame-attribution filter (only project frames under this prefix are diffed)
#     args...      optional program args (passed through to the program)
#
# To add a program: compile it in compile_all() (one javac line) and add one `entry` line here.
# ---------------------------------------------------------------------------------------------
corpus_entries() {
  # --- existing self-tests, reused ---
  entry selftest        "$WORK/selftest"       SelfTest        jfr   SelfTest
  entry agent-selftest  "$WORK/agentselftest"  AgentSelfTest   agent AgentSelfTest

  # --- new seeds: real I/O through interesting paths ---
  entry hof-io          "$WORK/hofio"          corpus.HofIo                  jfr   corpus
  entry strategy        "$WORK/strategy"       corpus.Strategy               agent corpus
  entry abstract-reader "$WORK/absreader"      corpus.AbstractReaderParse    jfr   corpus

  # --- session-mechanism confirmation: real Net/Fs/Exec through virtual threads / CompletableFuture /
  #     parallel streams — runtime ground truth for the lambda-attribution the synthetic sweep checked statically ---
  entry async-netfs     "$WORK/asyncnetfs"     corpus.AsyncNetFs             jfr   corpus
  entry async-exec      "$WORK/asyncexec"      corpus.AsyncExec              agent corpus
}

# ---------------------------------------------------------------------------------------------
# Runner internals.
# ---------------------------------------------------------------------------------------------
TOTAL_ENTRIES=0
TOTAL_UNDERREPORTS=0
declare -a SUMMARY_LINES=()     # "label: STATUS detail"
declare -a GAP_LINES=()         # confirmed under-report lines (program-attributed)

# Run one oracle, capture output, count UNDER-REPORT lines, append them (prefixed by label) to GAP_LINES.
# Echoes the oracle output live. Returns the number of under-reports it found via the global LAST_GAPS.
LAST_GAPS=0
run_oracle() {
  local label="$1" tool="$2"; shift 2
  local out rc gaps
  out="$("$@" 2>&1)"; rc=$?
  echo "$out" | sed 's/^/    /'
  # Count CONFIRMED under-reports (the oracle prints "UNDER-REPORT:" lines for each).
  gaps="$(echo "$out" | grep -c 'UNDER-REPORT:')"
  if [ "$gaps" -gt 0 ]; then
    while IFS= read -r line; do
      GAP_LINES+=("[$label/$tool] ${line#*UNDER-REPORT: }")
    done < <(echo "$out" | grep 'UNDER-REPORT:')
  fi
  LAST_GAPS="$gaps"
  return $rc
}

# entry: process one corpus program.
entry() {
  local label="$1" cp="$2" main="$3" tool="$4" pkg="$5"; shift 5
  local prog_args=("$@")
  TOTAL_ENTRIES=$((TOTAL_ENTRIES + 1))

  echo
  echo "============================================================"
  echo "ENTRY: $label   (main=$main, tool=$tool, pkg=$pkg)"
  echo "  cp=$cp"
  echo "============================================================"

  if [ ! -e "$cp" ]; then
    SUMMARY_LINES+=("$label: ERROR (classpath missing: $cp)")
    echo "  ERROR: classpath does not exist: $cp"
    return
  fi

  # (1) candor static report.
  local report="$WORK/$label.candor.json"
  echo "  [static] candor report -> $report"
  if ! java -jar "$CANDOR_JAR" "$cp" --json "$report" >/dev/null 2>&1; then
    SUMMARY_LINES+=("$label: ERROR (candor static analysis failed)")
    echo "  ERROR: candor static analysis failed"
    return
  fi

  local entry_gaps=0

  # (2) jfr_diff (Fs / Net).
  if [ "$tool" = "jfr" ] || [ "$tool" = "both" ]; then
    echo "  [jfr]   Fs/Net oracle:"
    local jfr_cmd=(python3 "$JFR_DIFF" --cp "$cp" --main "$main" --report "$report" --pkg "$pkg")
    [ "${#prog_args[@]}" -gt 0 ] && jfr_cmd+=(--args "${prog_args[@]}")
    run_oracle "$label" jfr "${jfr_cmd[@]}"
    entry_gaps=$((entry_gaps + LAST_GAPS))
  fi

  # (3) agent_diff (Exec / Db / Env / Clock / Rand / Log).
  if [ "$tool" = "agent" ] || [ "$tool" = "both" ]; then
    echo "  [agent] Exec/Db/Env/Clock/Rand/Log oracle:"
    local agent_cmd=(python3 "$AGENT_DIFF" --cp "$cp" --main "$main" --report "$report" --pkg "$pkg" --agent "$AGENT_JAR")
    [ "${#prog_args[@]}" -gt 0 ] && agent_cmd+=(--args "${prog_args[@]}")
    run_oracle "$label" agent "${agent_cmd[@]}"
    entry_gaps=$((entry_gaps + LAST_GAPS))
  fi

  TOTAL_UNDERREPORTS=$((TOTAL_UNDERREPORTS + entry_gaps))
  if [ "$entry_gaps" -gt 0 ]; then
    SUMMARY_LINES+=("$label: GAP ($entry_gaps under-report(s) — VERIFY: real model-gap vs known/accepted)")
  else
    SUMMARY_LINES+=("$label: CLEAN")
  fi
}

# ---------------------------------------------------------------------------------------------
# EXPECTED / ACCEPTED gaps — substrings of under-report lines that are KNOWN, documented best-effort gaps,
# NOT regressions. A gap matching one of these is reported but does NOT fail the run; only a NEW (unmatched)
# under-report exits non-zero. This turns the harness from a one-shot discovery run into a repeatable
# REGRESSION GATE. Add a line here only after triaging a gap as genuinely accepted (with a doc pointer).
# ---------------------------------------------------------------------------------------------
EXPECTED_GAPS=(
  # The abstraction-boundary κ-gap: a parser reading a file through an abstract java.io.Reader field whose
  # concrete (file-backed) impl candor can't pin (dynamic/README "First real finding"; jsoup CharacterReader).
  "AbstractReaderParse\$Parser.parse ran Fs"
)
is_expected_gap() {  # $1 = a gap line; returns 0 if it matches an accepted pattern
  local g="$1" pat
  for pat in "${EXPECTED_GAPS[@]}"; do [[ "$g" == *"$pat"* ]] && return 0; done
  return 1
}

# ---------------------------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------------------------
main() {
  if [ -z "${CANDOR_JAR:-}" ] || [ ! -f "$CANDOR_JAR" ]; then
    echo "FATAL: no candor-java-*-all.jar under build/libs (build it once outside this harness)." >&2
    exit 2
  fi
  if [ ! -f "$AGENT_JAR" ]; then
    echo "FATAL: agent jar missing ($AGENT_JAR). Build once: (cd agent && ./build.sh)" >&2
    exit 2
  fi
  echo "candor jar : $CANDOR_JAR"
  echo "agent jar  : $AGENT_JAR"
  echo "work dir   : $WORK"

  compile_all
  corpus_entries

  echo
  echo "############################################################"
  echo "# CORPUS SUMMARY"
  echo "############################################################"
  for l in "${SUMMARY_LINES[@]}"; do echo "  $l"; done
  echo
  # Split gaps into NEW (regressions) vs EXPECTED (known/accepted, allowlisted above).
  local new_gaps=() expected=()
  for g in "${GAP_LINES[@]:-}"; do
    [ -z "$g" ] && continue
    if is_expected_gap "$g"; then expected+=("$g"); else new_gaps+=("$g"); fi
  done
  echo "  total entries ............. $TOTAL_ENTRIES"
  echo "  under-reports ............. ${#new_gaps[@]} new, ${#expected[@]} expected/accepted"
  if [ "${#expected[@]}" -gt 0 ]; then
    echo "  expected/accepted (documented gaps, not regressions):"
    for g in "${expected[@]}"; do echo "    ~ $g"; done
  fi
  if [ "${#new_gaps[@]}" -gt 0 ]; then
    echo "  NEW model-gap under-report(s):"
    for g in "${new_gaps[@]}"; do echo "    - $g"; done
    echo
    echo "RESULT: ${#new_gaps[@]} NEW under-report(s) — candor model-gap regression(s). Exit 1."
    exit 1
  fi
  echo
  echo "RESULT: CLEAN — no NEW model gaps (every observed effect statically predicted, or an accepted gap)."
  exit 0
}

main "$@"
