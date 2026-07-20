# RQ4a precision baseline — candor vs. WALA (a resolving whole-program analysis)

Where `RESULTS.md` contrasts candor with a *syntactic* architecture gate (ArchUnit), this contrasts it
with a *resolving* one: **WALA**'s 0-CFA points-to call graph (IBM T.J. Watson Libraries for Analysis,
1.6.7), the standard mature baseline for Java call-graph construction. Same fixture classes, same
question — does `pricing.Pricing.quote` reach `java.net.Socket`? Reproduce: `bash wala.sh`.
(WALA builds a full call graph under JDK 21 — 32.5k classes in the hierarchy, ~21k call-graph nodes.)

## Datapoint A — resolvable dispatch (the ported fixture): candor matches the baseline

Single-implementor port (`RateSource` → one `HttpRateSource`). WALA 0-CFA resolves the chain
`quote → HttpRateSource.current → java.net.Socket.<init>` precisely (23 nodes reachable from `quote`);
candor **determines `Net`** on `quote` (`unresolved=false`). **They agree, both precise.** candor's
determination is not a weaker signal than a mature points-to analysis on the code the points-to
analysis can resolve — the RQ4a determination is sound and baseline-confirmed, not a shortcut.

## Datapoint B — unresolvable dispatch (reflective variant): the dilemma, and disclosure

The adapter is chosen at runtime by reflection: `Class.forName(config).getDeclaredConstructor()
.newInstance()`, with two implementors present (`HttpRateSource`, effectful; `PureRateSource`, pure).
No `new HttpRateSource()` allocation exists in the bytecode, so a points-to analysis has nothing to
flow into `Pricing`'s `RateSource` field.

| Approach                              | `quote` reaches `Net`? | Reflective site flagged?                          | Failure mode |
|---------------------------------------|------------------------|---------------------------------------------------|--------------|
| WALA 0-CFA, **reflection off**        | **NO**                 | no                                                | **unsound — a false all-clear** (drops the edge silently) |
| WALA 0-CFA, **reflection full**       | yes (3,452-node reach) | no                                                | sound but **over-approximated, no locality** |
| **candor**                            | **yes** (`Net`)        | **yes** — `Unknown[reflect:Class.forName, reflect:Constructor.newInstance]` at `Main.main` | **sound, and localizes the blind spot** |

WALA's reflection knob forces the classic dilemma. Off (the precision/scalability-oriented config)
**drops the reflective edge and reports `quote` as not reaching the network — the exact false all-clear
this project exists to prevent.** Full (conservative) recovers soundness but blows the reachable set up
by ~150× and gives **no signal about which edges were guessed** — a consumer cannot tell the real Net
reach from the over-approximation.

candor sidesteps the dilemma. It stays **sound** — `quote` carries `Net` (a class-hierarchy
over-approximation over the in-project implementors; the control below confirms this) — **and** it
**discloses** the reflective dispatch as `Unknown` *at the exact site*, `Main.main`, with the precise
reasons `reflect:java.lang.Class.forName` and `reflect:java.lang.reflect.Constructor.newInstance`. A
`deny Net Unknown[reflect]` policy acts on precisely that blind spot; WALA emits nothing a policy could
gate on. The disclosure is load-bearing, not cosmetic: the CHA `Net` covers the implementors candor can
see, but an implementor loaded from an **unanalyzed** jar would escape CHA — which is exactly what the
`Unknown` at the reflective site discloses.

### Honest mechanism note

candor's `Net` on `quote` is a **CHA over-approximation** over the in-project implementors, not a
resolution of the reflective target. Control: with `HttpRateSource` removed (only the pure implementor
present), candor reports `quote` as **pure** — confirming the `Net` comes from unioning the effectful
implementor into the hierarchy dispatch, and is dropped when no effectful implementor is in scope. So
on this example candor is on the sound-but-imprecise side *for the effect itself* (it never yields the
false all-clear WALA-off does), with the residual uncertainty — an implementor outside the analyzed set
— pushed into an explicit, reason-tagged `Unknown` at the dispatch site rather than left silent.

This is the precision-vs-disclosure thesis on a mature baseline: a resolving analysis must pick a point
on the soundness/precision curve and commits silently; candor reports the effect it can over-approximate
soundly and *discloses* the residual, so the blind spot is named and gate-able instead of being either a
silent miss or an unmarked over-approximation.
