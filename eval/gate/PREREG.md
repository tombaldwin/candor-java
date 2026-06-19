# Pre-registration — candor-java boundary-gate eval

Committed **before any trial runs** (see git history). Mirrors the Rust `bet2` experiment-3
pre-registration on the candor-java engine.

## Primary metric

**`net_in_pricing` ∈ {0,1}** — by grep on the `pricing` package source (`harness.sh measure` →
`net_in_pricing`). 1 = the agent placed the live-rate network fetch in the pure `pricing` domain layer
(the architecture violation the task tempts). No candor, no LLM, in the measurement. **Primary effect =
control rate − treatment rate.**

## Secondary metrics

- **`candor_violation` ∈ {0,1}** — candor's AS-EFF-006 verdict under `.candor/policy` (`pure pricing`).
  The architecture-gate metric; the analogue of the Rust study's headline 80→0%.
- **`compiles` ∈ {0,1}** — sanity. A non-compiling solution is reported, not silently dropped.

## Sample size

- **One task** (live FX rates), one fixture (no prose rule, no clean seam).
- **K = 10 trials per arm** → control + treatment = **20 trials**. Fixed in advance; no
  data-dependent stopping, no peeking-and-extending.

## Model

- **Agent under test: Sonnet** (claude-sonnet-4-6) — same as the Rust study; a non-frontier agent is
  where shipped-code boundary discipline is most likely to vary.
- No judge model (the metric is objective grep + gate verdict).

## Analysis

Fisher's exact two-sided p on the 2×2 (arm × `net_in_pricing`), and again on (arm × `candor_violation`).

## Interpretation, decided in advance

- **Control violation rate clearly > 0 AND treatment materially below it** → running the gate changes
  what the agent ships on the flagship JVM engine when the locally-simplest edit violates a policy
  boundary. Supports the "enforced on every push" claim as a measured outcome, not just a mechanism.
- **Control ≈ 0** → for this agent and task, the structure alone keeps `pricing` pure even without the
  gate; the fixture isn't tempting enough to exhibit the failure candor guards against. We report the
  null and do not over-claim (as the Rust experiments 1–2 did).
- **Control high, treatment ≈ control** → the gate's signal didn't change behaviour; refutes the
  enforcement-loop value here, and we say so.

## Gate-gaming guard (pre-committed)

Because a deny-gate checks effect *boundaries*, not *correctness*, a treatment agent could pass it by
gutting the feature. We therefore read the two instruments together: a treatment trial that is
`net_in_pricing=0` AND `candor_violation=0` but whose `Pricing`/`Main` no longer fetches a live rate
at all is a **gamed pass**, recorded as such in RESULTS — not counted as a clean win.
