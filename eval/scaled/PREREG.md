# Pre-registration — candor-java scaled edit-quality eval

Committed **before any trial runs** (see git history). Locks the design, sample size, models, and
falsification clause so the result cannot be retrofitted. Mirrors the Rust `scaled` batch-2
pre-registration (`candor-rust/eval/scaled/README.md` §"Batch 2") on the candor-java engine.

## Primary metric

**Completeness.** Per task, denominator = the **6 non-local functions** in the propagation set (the
edited method excluded; `harness.sh nonlocal_of <task>`). The blind judge marks, per function, whether
the summary identifies it as now performing the effect (named explicitly, or covered by an explicit
"all callers"/"every caller"/"whole call chain" statement). `COMPLETENESS: n/6`. **Primary outcome =
mean completeness per arm**, pooled across the 3 tasks, and reported per task.

Secondary (cross-check, not the headline): binary awareness (yes=1/partial=0.5/no=0).

## Sample size

- **3 tasks**: `catalog` (Fs), `geo` (Net), `render` (Exec).
- **N = 3 trials per arm per task** → 3 tasks × 2 arms × 3 = **18 agent trials**, 18 blind judgements.

## Models

- **Agent under test: Sonnet** (claude-sonnet-4-6). Mirrors the Rust batch-2 choice: a non-frontier
  agent is where the propagation-awareness gap is predicted to be widest; a strong agent can ceiling
  the control arm and mask the effect.
- **Judge: Haiku** (claude-haiku-4-5), blind to condition, fixed rubric.

## Falsification clause (committed before the run)

- If **control completeness ≥ 0.80** (pooled), candor-java's marginal value on this axis is low — we
  report that as the headline, not the lift.
- If **treatment − control < 0.20** (pooled completeness), the mechanism does not replicate on the
  bytecode engine with a weaker model under pre-registration — we say so plainly.

The Rust batch-2 result this replicates: control 0.42 / treatment 0.92 completeness. The Java
prediction is a comparable gap; either falsification condition firing is a publishable negative.

## What "completion" means (objective gate, pre-committed)

`harness.sh verify <runid>` recompiles the agent's edited copy, scans the bytecode, and diffs vs the
pre-edit baseline. COMPLETED = ≥1 function gained the task's effect (the edit was actually
implemented). An INCOMPLETE/ERROR trial is excluded from the primary completeness metric and recorded
separately — never silently scored as a model false-negative.

## Run plan

1. `harness.sh setup <task> <arm> <runid>` for all 18 cells.
2. Spawn one Sonnet agent per cell on its `PROMPT.md`, in its `work/` dir; capture the `## Summary`.
3. `harness.sh verify` each (objective completion).
4. `harness.sh judge-prompt` each summary → one Haiku judge call → `COMPLETENESS n/6` + `VERDICT`.
5. Reveal the condition map; aggregate per arm / per task / pooled into `RESULTS.md`; evaluate the
   falsification clause.
