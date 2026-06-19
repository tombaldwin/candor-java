# candor-java token/speed eval — pre-registered

The **Java replication** of the Rust speed/token A/B (`candor-rust/eval/scaled/PREREG-speed.md`) on the
candor-java (bytecode/ASM) flagship engine. It measures the cost side of the value proposition: on the
**blast-radius analysis question**, does an agent with candor's report + query answer at lower token /
tool-call cost than an agent working from source — at equal completeness?

Pre-registered: this file, `PREREG.md`, the fixture, and the harness are committed *before* any trial
runs (see git history).

## The question (an analysis task, not an edit)

> If `pricing.Pricing.quote` gained the `Net` effect, which OTHER functions would transitively perform
> `Net` — i.e. every transitive caller of `Pricing.quote`? List every affected function.

This is asked **explicitly and exhaustively**, so both arms are working toward the same complete
answer; the dependent variable is the *cost* of getting there, not whether the agent volunteers it
(that's the `eval/scaled` completeness study).

## Fixture

`fixture/` — a 10-class layered Java app (`pricing → cart → discount → checkout → order → api →
report → admin → app`), JDK-only. `pricing.Pricing.quote` is transitively reached by **16 functions**
across 3–5 call-graph layers — the candor-computed ground truth (`harness.sh truth`). A deep graph is
the point: a shallow one is cheap to trace by hand and would understate the difference.

## Arms (identical prompt except the tool clause)

- **control** — the question + "Work from the source code."
- **treatment** — the question + a candor report at `.candor/report.json` and the query
  `candor callers .candor/report.json pricing.Pricing.quote` (transitive callers) / `whatif … Net`
  (blast radius).

## Metrics

From the agent harness, per trial: **`subagent_tokens`**, **`tool_uses`**, **`duration_ms`**. Plus
**completeness** = recall against the 16-function ground-truth set (leaf `package.Type.method` match).
Primary statistic = **median(control) / median(treatment)** for tokens, reported alongside the
tool-call and wall-clock ratios and per-arm completeness.

See `PREREG.md` for sample size, model, falsification bars, and the honesty caveats.
