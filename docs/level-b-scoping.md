# Level B — scoping: instance `AnalysisContext` (de-globalize the engine)

Status: **scoping only** (not started). This sizes the work to convert candor-java's global mutable
static state into a per-scan instance, so the recommendation can be made with real numbers.

## Goal & what it buys

Today the engine's analysis state lives in ~40 mutable `static` fields (`AnalysisState`), cleared
between scans by `resetState()`. Level B moves that state into an instance (`AnalysisContext`) threaded
through the engine, so each scan owns its state.

**What it buys**
- **Re-entrancy / concurrency** — two scans can run in the same JVM (or in parallel) without clobbering
  each other. Today only `resetState()` makes sequential in-process scans safe (the conformance harness
  relies on it).
- **No `resetState()`** — the global-clear smell goes away; a fresh scan is a fresh object.
- **Per-scan unit-testability** — the analyzer can be driven on a synthetic context in a test without
  the whole static-world setup/teardown.
- **Removes the root cause** of the two aliasing seams the code review flagged (a value `Effector`
  could hold a live reference into the static maps).

**What it does NOT buy** — zero change to soundness, precision, the report bytes, or any user-visible
behavior. This is purely an internal architecture change. It is the "proper OO" the value-types work
sits on top of, not a capability.

## Current surface (measured)

| | |
|---|---|
| Mutable state fields (`AnalysisState`) | **38** |
| Stateful engine classes | **7** — Candor, Cha, Interp, Policy, Loader, ReportWriter, Literals |
| Field references to migrate | **~326** (Candor 213, Cha 27, ReportWriter 26, Interp 23, Policy 14, Loader 13, Literals 7, Classifier 3) |
| Static methods in stateful classes | **~157** (Candor 101 + 56 others) — not all touch state, but most either touch it or call something that does |
| `resetState()` clear sites | 23 fields cleared |
| **Already decoupled** | `Query` (0 state refs — consumes model types), the `model` package, `Classifier` (≈pure) |

The good news from the measurement: `Query` and the `model` package are **already** instance-clean, and
the state is **already centralized** in `AnalysisState` (the P6 work). The remaining coupling is the
~326 bare-name accesses + the static call graph among the 7 stateful classes.

## The irreducible cost

There is **no cheap path** to true re-entrancy: a static handle that re-points static fields at a
"current" context keeps bare-name access but is still globally aliased (two contexts share it) — i.e.
not re-entrant. Real Level B requires replacing every bare-name access (`direct`) with instance access
(`ctx.direct`) and giving every stateful method access to the context. That ~326-site conversion +
method-signature/object-graph change is the work; it can't be shimmed away.

## Approaches for the end-state

1. **Context-as-parameter** — every stateful static method gains an `AnalysisContext ctx` first
   parameter; `direct` → `ctx.direct`; every call site passes `ctx`. Keeps the file layout and static
   methods (still easy to unit-test). Cost: `ctx` threaded through ~150 methods and *every* call site —
   pervasive noise, a "god parameter" everywhere.
2. **Instance object graph (recommended end-state)** — the 7 stateful classes become instance classes,
   each constructed with the shared `AnalysisContext` (and references to the sub-engines they call);
   `direct` → `ctx.direct` via a held field; cross-class calls become instance calls. Instantiated once
   per scan. This is idiomatic OO and the cleanest end state. Cost: wiring the object graph (who holds
   whom) on top of the ~326-site conversion.
3. **Hybrid** — `AnalysisContext` holds the state *and* the sub-engine instances (`ctx.cha`,
   `ctx.policy`, …); each sub-engine holds the `ctx`. A single object owns the scan. Same cost as (2),
   slightly simpler wiring (one owner).

## Recommended phased path (each phase byte-identity-gated, committed alone)

- **LB-0 — introduce `AnalysisContext`, access via a static singleton.** Move the 38 fields into
  `AnalysisContext`; `AnalysisState` keeps a `static AnalysisContext ctx`. Mechanically rewrite the
  ~326 `field` → `ctx.field` accesses (compiler-driven, exactly like the EffectSet migration).
  `resetState()` → `ctx = new AnalysisContext()`. **Behavior identical** (still one global instance,
  NOT yet re-entrant) — a large but mechanical, fully-gated step that does all the field-access churn up
  front. *Delivers: state as a named object; sets up LB-1.*
- **LB-1 — remove the singleton; thread/inject the context.** Convert the 7 stateful classes to the
  instance object graph (approach 2/3): construct an `AnalysisContext` + sub-engines per scan in
  `runScan`, drop the static `ctx`. *Delivers: re-entrancy, no `resetState`, per-scan testability.* This
  is the conceptual change and the higher-risk phase; LB-0 having done the field-access conversion keeps
  it focused on wiring + signatures.
- **LB-2 (optional) — a public `Analysis`/`Engine` entry point** taking inputs and returning a
  `Report`, so candor is embeddable as a library (the natural payoff of LB-1).

## Risk register

1. **Byte-identity across ~326 edits + signature churn** — the dominant risk. Mitigated exactly as the
   prior migrations: the same gates (pc/jsoup/gson reports identical, every AS-EFF gate mode, Query
   output, soundness 40, kappa_libs 438, conformance) run after each phase; compiler-driven worklists.
2. **The CI binary-identity self-guard** (in-process re-scan == fresh-process) — Level B *helps* here
   (a fresh context per scan is cleaner than `resetState`), but the transition must keep it green.
3. **Static initialization order / `<clinit>`** — moving fields off statics removes a class of init-order
   coupling, but the move itself must not introduce a cycle.
4. **Large diff, hard to review** — split LB-0 (mechanical) from LB-1 (design) so each is reviewable.

## Effort & recommendation

- **LB-0**: ~half a day, low-medium risk (mechanical + gated).
- **LB-1**: ~1–2 days, high risk (object-graph wiring + ~150 method signatures, under byte-identity).
- **LB-2**: small, once LB-1 lands.

**Recommendation.** This is a genuine, worthwhile architecture improvement, but candor-java is a
single-shot CLI today and the value types already deliver the user-facing model. The concrete triggers
that make LB-1 pay for itself are: (a) **embedding candor as a library**, (b) **concurrent / parallel
multi-package scanning**, or (c) a real need for **per-scan analyzer unit tests**. Until one of those is
live, the cost/risk of LB-1 outweighs the benefit.

Suggested posture: **do LB-0 if you want the state owned by a named object now** (cheap, sets the seam);
**defer LB-1/LB-2 until a re-entrancy/embedding need is concrete** — at which point this scope makes it
a planned, incremental, gated change rather than a rewrite.
