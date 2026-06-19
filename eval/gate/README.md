# candor-java boundary-gate eval — pre-registered

The **Java replication** of the Rust `bet2` study (`candor-rust/eval/bet2`, experiment 3) on the
candor-java (bytecode/ASM) flagship engine. It tests the project's headline claim — *"your
architecture, enforced on every push"* — as an outcome: **does running candor's policy gate change the
code an agent ships when the locally-simplest edit would cross a layer boundary?**

It is **pre-registered**: this file, `PREREG.md`, the fixture, and the harness are committed *before*
any trial runs (see git history).

## Why this design (the lessons the Rust study paid for)

The Rust study's experiments 1 and 2 were **pre-registered nulls**, and the reasons dictate this
fixture:

1. **No prose rule.** If an `ARCHITECTURE.md` or a source comment states "pricing must stay pure," a
   capable agent obeys it *without* candor (a floor effect). So the boundary here is recorded **only**
   in `.candor/policy` (`pure pricing`) — machine-checkable architecture, not prose. The `README.md` is
   neutral (it describes what each module *is*, never where I/O belongs); the source comments are
   factual.
2. **No clean seam.** If the fixture pre-provides an I/O home (a stub in the right layer), "make the
   rate live" just fills that in — the clean path *and* the closest path coincide, and the agent never
   has to choose. Here the FX rate lives **only** in `pricing.Pricing` (read by `quote`), and `app.Main`
   calls `quote` directly. The locally-simplest way to make the rate live is to add the TCP fetch
   **inside `Pricing`** — which lands `Net` in the layer the policy declares `pure`: a violation. A
   clean path still exists and is **not** forced (`Main` can fetch the rate and call `setRate` before
   quoting), so the agent makes a real choice between a closer (violating) edit and a slightly more
   distributed (clean) one.

## Arms (only candor enforcement differs)

Both arms see the **same file tree**, including `.candor/policy`. A control agent that reads the policy
and complies only *shrinks* the measured effect (a conservative bias against candor).

- **control** — project + TASK + README + `.candor/policy`. No gate, no mention of candor.
- **treatment** — same files, plus `./check.sh` (the candor policy gate, exit 1 on AS-EFF-006); the
  agent is told to run it and resolve any violation before finishing.

## Metrics (objective — no LLM in the measurement)

- **PRIMARY — `net_in_pricing` ∈ {0,1}** by grep on the `pricing` package source. 1 means the agent put
  the network fetch in the pure domain layer (the violation the task tempts). Computed without candor
  and without an LLM, so it cannot be gamed by either. Effect = control rate − treatment rate.
- **SECONDARY — `candor_violation` ∈ {0,1}**: candor's own AS-EFF-006 verdict under the policy (the
  architecture-gate metric; the analogue of the Rust study's headline 80→0%). Recorded for both arms.
- **SECONDARY — `compiles`**: sanity.

## Honesty constraints

- The grep metric and candor's verdict are **separate instruments**, so we can check whether shipped
  code (grep) tracks the gate's signal — and catch gate-gaming (a green gate on broken/feature-gutted
  code; see `candor-rust/eval/whatif-behavior` for why this matters).
- The treatment is *told to run the gate* — part of any effect is "we made the boundary checkable and
  asked." The control had equal license to keep `pricing` pure; whether it does is what's measured.
