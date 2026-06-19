# Pre-registration — candor-java token/speed eval

Committed **before any trial runs** (see git history). Mirrors the Rust `PREREG-speed.md` on the
candor-java engine.

## Metrics (priority order)

1. **Tokens** — `subagent_tokens` per trial. Primary statistic: **median(control) / median(treatment)**.
2. **Tool calls** — `tool_uses` per trial; same ratio.
3. **Wall-clock** — `duration_ms` per trial; same ratio (reported, but absolutes are unreliable under
   concurrent trial load — the *ratio* is the statistic, not the seconds).
4. **Completeness** — recall against the 16-function transitive-caller ground truth (`harness.sh
   truth`); leaf `package.Type.method` match. The target `pricing.Pricing.quote` itself is not scored.

## Sample size & model

- **N = 8 per arm** → 16 trials. Fixed; no data-dependent stopping.
- **Agent: the session default subagent model (Opus-class)**, identical for both arms — same choice as
  the Rust speed eval. A frontier model keeps the *control* arm complete, so the comparison is "same
  answer, lower cost" rather than confounded by a fast-but-wrong control. One shot per trial; a
  harness error (empty return) is rerun once and noted.

## Falsification bars (committed before the run)

- **Token claim refuted** if median(treatment tokens) ≥ median(control tokens).
- **Trivial / fast-but-wrong** if treatment uses fewer tokens but its median completeness is below
  control's — reported as such, not as a win.
- If **control median completeness < ~0.8** (the model won't trace the full graph even when asked),
  this becomes a completeness story like `eval/scaled`, not a pure cost story — we say so and report
  both arms' recall prominently rather than leading with the token ratio.

## Scope / honesty caveats (carried from the Rust study)

- **Small, clean fixture.** 10 classes, 16-fn radius. Token/tool-call savings scale with codebase size
  and closure depth; this fixture is deep enough to require real tracing but far smaller than a real
  repo, so the *ratio here is a floor, not a headline for large codebases* — and the fixed per-agent
  harness overhead compresses end-to-end token ratios (the marginal cost of the question is a much
  larger multiple than the end-to-end ratio).
- **Best-case adoption.** The treatment is handed the exact query. That measures the value when the
  tool is used, not whether an agent reaches for it unprompted.
- `subagent_tokens` is the harness's per-trial total; its input/output composition is not separated
  here. We report the end-to-end ratio and the tool-call ratio together so neither carries the claim
  alone.
