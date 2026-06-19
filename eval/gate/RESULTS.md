# Results — candor-java boundary-gate eval

Run per [PREREG.md](PREREG.md). One task, two arms, **K=10 per arm = 20 trials** (agent: Sonnet).
Pre-registration committed before any trial (`git log` — commit `06a73db`). Metrics are objective
(grep + candor's gate verdict); no LLM in the measurement.

## Headline

| metric | control | treatment | effect | Fisher 2-sided |
|---|---|---|---|---|
| **`net_in_pricing`** (primary, grep) | **70%** (7/10) | **0%** (0/10) | 0.70 | **p = 0.003** |
| **`candor_violation`** (AS-EFF-006 gate) | **100%** (10/10) | **0%** (0/10) | 1.00 | **p = 1.1e-5** |
| compiles | 10/10 | 10/10 | — | — |
| feature implemented (gaming guard) | 10/10 | 10/10 | — | — |

**Running the gate changes what the agent ships.** Without it, every control agent put live-rate
network I/O on a path through the pure `pricing` domain (the locally-simplest edit); the architecture
boundary was violated in **10 of 10** trials. With the gate, **0 of 10** — every treatment agent moved
the fetch into the `app` layer and injected the rate through the existing `setRate`, keeping `pricing`
pure. This is the flagship's "enforced on every push" claim as a measured **outcome**, not just a
mechanism — and it clears the bar the Rust study set (`bet2` exp3: 80% → 0% on the gate metric; Java is
100% → 0%).

## The result is not gate-gaming

A deny-gate checks effect *boundaries*, not *correctness*, so a treatment agent could pass it by
deleting the feature. Pre-committed guard: every trial was checked for a live TCP fetch present
*somewhere* in the tree. **All 20** implement it (`feature implemented` above). The treatment arm
passed by **correct refactoring** — fetch in `app`, inject via `setRate` — in all 10 cases, not by
gutting the feature. No gamed passes.

## Transitive analysis beats a file-location lint (the load-bearing nuance)

The two control metrics diverge — 7/10 on the grep, 10/10 on candor — and the gap is the whole point.
Three control agents (08, 09, 10) put the socket in a **new `rates` package** rather than literally
inside a `pricing/*.java` file, so the textual grep of the pricing source comes back clean
(`net_in_pricing=0`). But they wired `pricing.Pricing.quote` to **call** that new class, so the pure
domain method still performs `Net` **transitively**. candor's effect analysis follows the call graph
and flags all three (`candor_violation=1`); a lint that only greps the domain *folder* — or a reviewer
skimming the pricing files — would pass them. The boundary was violated in all 10 control trials; only
candor's transitive view sees all 10.

## Threats to validity

- The treatment is *told to run the gate* — part of the effect is "we made the boundary checkable and
  asked." The control had equal license to keep `pricing` pure (and the `.candor/policy` file was in
  its tree too); it didn't, 10/10.
- One task, one fixture, one agent model, K=10/arm. The fixture is deliberately constructed with no
  prose rule and no clean seam — the regime where the Rust study's experiments 1–2 were nulls. On
  easier regimes (a prose rule, or a pre-built I/O seam) a capable agent keeps the layer pure
  unprompted, and the gate's marginal value is lower; this eval measures the regime where it bites.
- `net_in_pricing` is a grep proxy for "I/O in the domain"; `candor_violation` is candor's own verdict.
  We report both, and the divergence above is exactly why the transitive instrument is the honest one.

## Reproduce

```
cd candor-java/eval/gate
./gradlew -q shadowJar -p ../..
for a in control treatment; do for n in $(seq -w 1 10); do ./harness.sh setup $a $a-$n; done; done
# run one Sonnet agent per runs/*/PROMPT.md in its work/ dir (treatment also runs ./check.sh)
for d in runs/*/; do r=$(basename $d); ./harness.sh measure $r; done
```

Per-trial prompts, metadata, and measurements are under `runs/<arm>-NN/`.
