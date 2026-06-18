# Results — candor-java scaled edit-quality eval

Run per [PREREG.md](PREREG.md). 3 tasks × 2 arms × N=3 = **18 agent trials** (agent: Sonnet), 18
**blind** judgements (judge: Haiku, condition redacted). Pre-registration committed before any trial
(`git log` — commit `4d9a594`).

## Headline

| | pooled completeness | binary awareness |
|---|---|---|
| **control** (no candor) | **0.11** (0.67/6) | 0.11 |
| **treatment** (candor-java diff) | **1.00** (6.00/6) | 1.00 |
| **lift** | **+0.89** | +0.89 |

**The mechanism replicates on the bytecode engine.** Neither pre-registered falsification condition
fired: control completeness 0.11 is far below the 0.80 "low value" threshold, and the treatment−control
gap of 0.89 far exceeds the 0.20 "no replication" threshold. The lift is, if anything, **cleaner than
the Rust study** it replicates (Rust batch-2: control 0.42 / treatment 0.92): here every treatment
trial named the **complete** 6-function propagation set, and 8 of 9 control trials named **none** of it.

## Per task

| task | effect | control n/6 | treatment n/6 | lift |
|---|---|---|---|---|
| `catalog` | Fs | 0.00 (0/0/0) | 6.00 (6/6/6) | +1.00 |
| `geo` | Net | 2.00 (0/**6**/0) | 6.00 (6/6/6) | +0.67 |
| `render` | Exec | 0.00 (0/0/0) | 6.00 (6/6/6) | +1.00 |

All 18 trials passed the objective completion gate (`harness.sh verify`: the agent's edit actually
introduced the effect — 7–8 functions gained it, the +1 being the helper method most agents extracted).
No trial was excluded.

## What the arms actually wrote

The split is qualitative, not marginal. **Every control summary** described the local change and then
asserted the rest of the codebase was untouched — e.g. *"No other classes were changed; CatalogService,
CatalogController … require no changes since they already consume Optional<Product>."* The edit is
correct; the **blast radius is invisible to the author**. **Every treatment summary** enumerated the
propagation — e.g. *"the Fs effect propagates transitively through CatalogService.lookup,
CatalogService.batch, CatalogController.getOne, CatalogController.getMany, DashboardReport.build, and
Main.main — callers that were previously pure are no longer so."*

This is the P0 thesis: candor changes **what the agent reports**, turning a locally-correct edit into a
blast-radius-aware one. On the JVM that radius crosses service/controller/report layers — exactly the
boundary an architecture gate cares about.

## The one control success (reported, not suppressed)

`geo-control-2` scored 6/6 — the lone control trial the blind judge marked complete. Its summary named
the caller **classes** (GeoService, GeoController, GeoReport) and added a generic *"callers … will now
block briefly on network I/O."* The judge read that class-level + blanket-callers phrasing as
identifying the propagation set and counted all six. It pulls geo's control mean up to 0.33 and is the
entire reason pooled control isn't 0.00. We keep it: it works **against** the hypothesis, and the lift
survives it overwhelmingly. It also marks the ceiling of what a capable control agent occasionally does
unprompted — gesture at "callers are affected" without tracing the graph.

## Threats to validity (carried from the Rust study)

- **The treatment is *told* to run candor.** Part of the lift is "we pointed it at the propagation."
  The control had equal license to investigate callers and a JDK call graph it could trace by hand;
  whether it does is exactly what's measured, and 8/9 times it didn't.
- **Summary-as-proxy.** We score what the agent *reports*, not all it might know — but the report is
  what a human reviewer acts on.
- **N=3/arm/task, one agent model, one judge model, 3 fixtures.** The effect size (0.89, with control
  near-floor and treatment at ceiling) is large enough that the small N is not load-bearing, but this
  is a replication of a mechanism, not a population estimate.
- **Fixtures are JDK-only and deliberately layered.** They isolate transitive propagation cleanly; a
  real codebase has more noise (and more Unknown), where the `blindspots` query matters more.

## Reproduce

```
cd candor-java/eval/scaled
./gradlew -q shadowJar -p ../..        # build the candor-java fat jar
for t in catalog geo render; do for a in control treatment; do for n in 1 2 3; do
  ./harness.sh setup $t $a $t-$a-$n; done; done; done
# run one Sonnet agent per runs/*/PROMPT.md in its work/ dir; capture its ## Summary to summary.md
for d in runs/*/; do r=$(basename $d); ./harness.sh verify $r; done
for d in runs/*/; do r=$(basename $d); t=${r%%-*}
  ./harness.sh judge-prompt $t $d/summary.md  # → one blind Haiku judge call → COMPLETENESS n/6
done
```

Per-trial prompts, summaries, and judgements are under `runs/<task>-<arm>-<n>/`.
