# Pre-registration — token/speed eval, batch 2: a real deep codebase (jsoup)

Committed **before any batch-2 trial runs** (see git history). Batch 1 (`PREREG.md` / `RESULTS.md`)
was a pre-registered **floor**: on a 10-class synthetic fixture a frontier model traces the whole graph
in ~3 reads, so candor's query saved little (tokens 1.16×, time 1.35×, at equal 16/16 completeness).
Batch 1's own caveat was the cause: *"savings scale with codebase size and closure depth; this fixture
is a floor."* Batch 2 tests that directly on a **real, deep codebase**.

## Target

**jsoup** (github.com/jhy/jsoup, cloned to `/tmp/jsoup`), compiled with plain `javac` (jspecify + re2j
on the classpath) → **306 classes, 1502 functions**. candor report at `/tmp/jsoup_report.json`.

Question function: **`org.jsoup.nodes.Element.select(String)`** — the iconic jsoup CSS-select API.
candor computes **34 transitive callers** across the `nodes` / `helper` / `select` / `examples`
packages (`/tmp/jsoup_truth.txt`; 18 distinct `Class.method` after collapsing overloads,
`/tmp/jsoup_truth_norm.txt`). Tracing that by hand means reading across a 306-class tree; one candor
query returns it.

## The CHA caveat (why cost is primary, not completeness)

jsoup is interface/dispatch-heavy, so candor's transitive-caller set is a **CHA over-approximation**:
it may include callers whose path to `select` only exists under conservative dispatch assumptions. That
makes "recall vs candor's set" **circular** (treatment trusts candor; a control agent tracing real
source may correctly *exclude* a CHA-spurious caller and look "incomplete" when it is right). So:

- **PRIMARY = cost**, which does not depend on CHA soundness: `subagent_tokens`, `tool_uses`,
  `duration_ms`. A control agent must *read* many files to attempt the trace regardless of whether the
  final set is CHA-exact; treatment runs one query. Statistic: median(control)/median(treatment).
- **SECONDARY = completeness**, reported as **overlap with candor's 18 distinct `Class.method`**, with
  any control-found function NOT in candor's set listed separately as a possible CHA-over-approximation
  catch — **not** scored as a control error. We do not lead with completeness and we flag the
  circularity explicitly.

## Arms (identical question, tool clause differs)

Read-only analysis, so both arms share the one `/tmp/jsoup` tree (no per-trial copies — nothing is
written).

- **control** — "Work from the source code at `/tmp/jsoup/src/main/java`."
- **treatment** — "candor report at `/tmp/jsoup_report.json`; run
  `candor callers /tmp/jsoup_report.json 'org.jsoup.nodes.Element.select(String)'`."

## Sample size, model, bars

- **N = 6 per arm** → 12 trials. Fixed; no data-dependent stopping.
- Agent: session default (Opus-class), both arms.
- **Cost claim refuted** if median(treatment tokens) ≥ median(control tokens). **Trivial** if treatment
  cheaper but its completeness-overlap is materially below control's. Expectation (vs batch 1's 1.16×):
  a larger token/tool/time ratio, because the control trace cost scales with the codebase and the query
  does not.
