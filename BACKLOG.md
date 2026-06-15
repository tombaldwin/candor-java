# candor-java backlog

## Precision

### Homogeneous broad-dispatch collapse (reduce Unknown from polymorphic pure accessors)

**What:** when a virtual/interface call's CHA fan-out exceeds `CHA_FANOUT_LIMIT` (12), candor soundly
falls back to `Unknown` rather than guess which impl runs. Refine that fallback: before raising
`Unknown`, check whether the candidate impl set is **homogeneous** — every resolved impl shares the same
effect (or all are pure). If so, use that shared effect instead of `Unknown`. candor has already
analysed those impls; it just discards them at the fan-out limit.

**Why it's sound:** the fallback to `Unknown` exists for *precision/perf* (bounding fan-out work), not
soundness — when every candidate impl agrees, the dispatch's effect is determined regardless of which
one runs, so using it is sound. This layers a precision refinement *on top of* the §4 soundness floor
(broad-fan-out → Unknown, hardened in 0.5.4), it does not weaken it: a heterogeneous fan-out still goes
`Unknown`.

**Measured impact (uFlexi, 8287 fns):** Unknown is **35%** of effect incidences and touches 57% of
functions — but it traces almost entirely to ONE root. `IdentifiableEnum::getId` (a method reference in
`buildIdMap`, an interface accessor implemented by ~40 enums → broad fan-out → Unknown) has blast radius
**2560**; the union of all 23 Unknown roots is **2588**. Every `getId()` impl is a pure field accessor,
so a homogeneous-pure collapse would resolve that one site and drop Unknown to low single digits.
Generalises to any codebase with polymorphic pure accessors (`getId`/`getName`/value objects).

**Not the cause: unscanned deps.** Verified — chaining the real dependency reports (Hibernate, Spring,
JDBC, ehcache) via `CANDOR_DEPS` moved Unknown only 35% → 32% and *widened* its reach (the frameworks
are themselves reflection-heavy). The residue is genuine framework reflection (`MethodInvocation` +
`BeanUtils.findMethod`, `Class.getEnumConstants()`) which should stay `Unknown`.

**Fuzzer gate:** add a `homogeneous_fanout` form to `soundness/gen.py` — a broad dispatch (>12 impls of
an interface) where ALL impls share one effect; assert the caller gets that effect, not `Unknown`. Pair
it with a `heterogeneous_fanout` form (impls disagree) that MUST stay `Unknown`, so the refinement can't
regress the soundness floor. May generalise cross-engine (swift/ts CHA) — coordinate via the spec.

**Lesser levers considered & rejected:** raising `CHA_FANOUT_LIMIT` globally (blunt, perf risk, doesn't
distinguish homogeneous from heterogeneous); app-side refactor (can't — it's an interface contract);
accepting it (Unknown is honest and gate-safe, but it dominates the signal here).
