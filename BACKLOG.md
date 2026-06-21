# candor-java backlog

## Precision

### Homogeneous broad-dispatch collapse (reduce Unknown from polymorphic pure accessors)

**What:** when a virtual/interface call's CHA fan-out exceeds `CHA_FANOUT_LIMIT` (12), candor soundly
falls back to `Unknown` rather than guess which impl runs. Refine that fallback: before raising
`Unknown`, check whether the candidate impl set is **homogeneous** — every resolved impl shares the same
effect (or all are pure). If so, use that shared effect instead of `Unknown`. candor has already
analysed those impls; it just discards them at the fan-out limit.

**Why it's sound — WITH A CLOSED-WORLD CAVEAT (important, established 2026-06-21).** When every candidate
impl agrees, the dispatch's effect is determined *for the impls candor can see*. The catch: collapsing a
>12-impl **open** interface to **pure** assumes the visible set is COMPLETE — a future/external impl with
an effect would then read silent-pure (the cardinal sin). So the sound version must gate on a CLOSED world:
a `sealed` interface/class, a package-private type, or all impls being a closed enum set. The closed-ENUM
subset is ALREADY shipped (the 0.7.1 `isClosedEnumOwner` carve-out + the 0.7.0 sealed-CHA resolution); this
item is the GENERALISATION to other closed hierarchies. A heterogeneous fan-out always stays `Unknown`;
collapsing to a non-pure shared effect is safe regardless (over-approx), only collapse-to-pure needs the
closed-world gate.

**Scope — this is an APP lever, not a library one (measured 2026-06-21).** On real LIBRARIES (jsoup/gson/
HikariCP) the dominant Unknown is `reflect:`/`task-handoff:` — genuinely irreducible, this lever doesn't
help. On APPS (the architecture-gate's primary target) it's a homogeneous-pure interface accessor — see
below. So pursue it for app-precision, knowing libraries stay Unknown by nature.

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

## Soundness (cross-jar)

### Opaque interface-typed dep call → silent-pure (no interface→impl map in the dep report)

**What:** with `--deps`, a dep call inherits the dep method's effects via the §2 hash. The
concrete-typed call (`new FileStore().save()`) and the *monomorphic* interface-typed call
(`Store s = new FileStore(); s.save()` — fixed in this pass via the monomorphic-receiver retry)
both inherit correctly. But a GENUINELY OPAQUE interface receiver — `void run(Store s) { s.save(); }`
where the impl type isn't visible at the call site (DI-wired, a param, a field) — still reads
**silent-pure**: `min.owner` is the external interface `lib/Store`, the dep report keys the body by
its concrete owner `lib/FileStore.save`, and there is no interface→impl mapping in the dep report to
bridge them. A within-project version of this gets honest `Unknown` (the `isProjectIfaceOrAbstract` +
`projectDeclaresMethod` missing-impl gate), but an EXTERNAL/dep interface does not.

**Why it's the harder case:** the fix can't be a hash retry — the concrete type is unknown at the call
site. Two sound options: (a) when a dep call's owner is an interface the dep report declares impls of,
inherit the UNION of those impls' effects (needs the dep report to carry a supertype→impl index, a
spec/envelope addition — coordinate cross-engine); or (b) treat an unresolved external-interface dep
call as honest `Unknown` (mirrors the project-interface missing-impl rule, but risks Unknown-flood on
every `List`/`Map`/`Iterator` stdlib interface call, so it must be gated to interfaces the dep report
actually covers — again needing the report to name its interfaces). Both touch the report envelope, so
this is a cross-engine spec item, not a local patch. Repro: the `viaParam` fixture in the audit
(interface param, no visible `new`) — absent from the report under `--deps`.

## Done (recent — for context)

- **κ persistence coverage, batches 24–27 (0.7.9 / 0.7.10).** Closed the inherited-into-project silent-pure
  vein CLASS across all major JVM persistence: Hibernate-6 / Jakarta Data (StatelessSession/SelectionQuery/
  MutationQuery + `jakarta.data` repos), Quarkus Panache (active-record + repository + PanacheQuery),
  Micronaut Data, Ebean, ActiveJDBC, jOOQ DAO, and the GENERAL "subclass a classify-modeled external
  effectful type" fix (re-classify inherited calls against the external supertype). Verified NOT a shared
  cross-engine blind spot (candor-ts/scan disclose Unknown; SOUNDNESS.md §8.3).
- **Repo pure-`default`-method `Db` fabrication fix** — the repoTypes blanket Db now skips a method with a
  visible (non-abstract) body, so a default helper stays pure.
- **Declarative HTTP-client interfaces → Net** (Retrofit / Micronaut `@Client` / MicroProfile
  `@RegisterRestClient` / Spring `@*Exchange`) — the OpenFeign analog; Unknown → precise Net.
- **`containment` in the cross-engine conformance differential** (candor-spec PART 11, Java vs candor-query).
- **Test coverage**: KappaBatch24/25, InheritedPersistenceVeins, InheritedModeledBase, HttpClientNet,
  ContainmentRatchet, PolicyParser, PolicyGate, LayerOf (the policy gate + κ rules were under-tested).
