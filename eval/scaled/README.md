# candor-java scaled edit-quality eval — pre-registered

**Status: protocol + harness + fixtures + ground truth, pre-registered.** This is the **Java
replication** of the Rust `scaled` study (`candor-rust/eval/scaled/`), run on the candor-java
(bytecode/ASM) engine — the reference implementation. The Rust study found, on de-leaked fixtures
with a weaker agent model, that candor's edit-feedback turns *partial/local* awareness of an edit's
effect consequence into *complete, specific, non-local* awareness (control completeness 0.42 →
treatment 0.92 in its batch-2 design). This eval tests whether **the same mechanism holds when the
analysis is candor-java reading compiled bytecode**, on the JVM stack the project now leads with.

It is **pre-registered**: this file, `PREREG.md`, the fixtures, and each task's `GROUND_TRUTH.md` are
committed *before* any trial runs (see git history), so the metric and falsification clause can't be
retrofitted to the result.

## The question

When an agent makes an edit with a **non-local effect consequence** — a low-level method gains an
effect (`Fs`/`Net`/`Exec`) that then propagates transitively to callers in other files — does giving
the agent candor-java's edit-feedback (`./candor-diff.sh`, i.e. recompile → scan bytecode → `candor
diff` vs the pre-edit baseline) make it **notice and report the full propagation**, which capable
agents otherwise tend to under-report?

This is the P0 thesis (candor changes what the agent *does*, not just how fast it analyses). It is
**not** "is candor-java's report accurate" (the conformance suite + soundness probes cover that).

## Design

Each **task** is a 6-file layered Java app (repo → service → controller → report → main), JDK-only so
`javac` compiles it offline and candor-java classifies it deterministically from bytecode. One natural
edit makes a low-level method gain a single effect that propagates to a known set of caller functions.
The propagation set is **deterministic ground truth**, verified by actually making the edit and
running `candor diff` (each task's `GROUND_TRUTH.md`), NOT by hand.

Two **conditions**, each agent on a fresh copy of the fixture, identical prompt except the candor
clause:

- **control** — the task only (told how to compile, given equal license to investigate callers).
- **treatment** — the task **+** "after editing, run `./candor-diff.sh` and fold what it reports into
  your summary."

The tasks mirror the Rust trio one-for-one for cross-engine comparability:

| Task | App | Effect gained | Edited method | Natural impl (JDK-only) | Rust analogue |
|---|---|---|---|---|---|
| `catalog` | product catalog (6 files) | `Fs` (read) | `CatalogRepository.find` | `Files.readString` on a miss | `minicache` |
| `geo`     | geo-IP lookup (6 files)    | `Net`        | `GeoResolver.resolve`    | `new Socket(host,port)` on a miss | `geoip` |
| `render`  | template engine (6 files)  | `Exec`       | `TemplateEngine.expand`  | `ProcessBuilder` for an `exec:` token | `renderer` |

Each task's effect propagates to **7 functions**; the completeness denominator is the **6 non-local**
ones (`harness.sh nonlocal_of <task>`).

## Metrics

**Primary — completeness.** For each task, the blind judge marks, per non-local function, whether the
summary identifies it as now performing the effect (named, or covered by an explicit "all callers"
statement) → `COMPLETENESS: n/6`. Primary outcome = mean completeness per arm.

**Secondary — binary awareness** (yes/partial/no), and **task completion** (objective: `harness.sh
verify` confirms candor-java's own diff shows the edit introduced the effect — an agent that didn't
implement the task is excluded from the primary metric, recorded separately, not silently dropped).

## Blinding

The judge receives **only** the agent's final summary with the tool's identity redacted (every candor
reference → "the analysis", a phrase an agent could equally use for manual call-graph reasoning), plus
the ground-truth propagation set and the rubric. The condition↔summary mapping is revealed only after
all judgements are in. One judge call per summary; the judge never sees which arm produced it.

## Running it

`harness.sh` is the reproducible runner. It does **not** call an LLM (the one non-scriptable part);
it prepares each trial's fresh fixture copy + the exact prompt, verifies completion objectively with
candor-java, and emits the blind judge prompt. An orchestrator (a human, or an agent-spawning harness)
runs the agents. Raw prompts, summaries, judgements, and the condition mapping are recorded under
`runs/`, summarised in `RESULTS.md`.

## Honesty constraints (carried from the Rust study)

- Ground truth is **independent of candor** (it's what the source actually does post-edit; candor is
  only used to *enumerate* it mechanically, and the enumeration is human-checkable against the call
  graph in each fixture).
- The judge is blind to condition and scores ONE axis on a fixed rubric.
- The treatment is *told to run candor* — so part of any lift is "we pointed it at the propagation".
  The control has equal license to investigate callers; whether it does is exactly what's measured.
- Summary-as-proxy-for-edit-quality is a known limitation (an agent might know more than it writes);
  we measure what it *reports*, which is what a human reviewer would act on.
