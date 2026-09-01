# candor-java backlog

## Precision

### Homogeneous broad-dispatch collapse (reduce Unknown from polymorphic pure accessors)

**SHIPPED 2026-06-21 as the sound opt-in `CANDOR_CLOSED_WORLD` (Option B).** Under the flag, a broad
(>`CHA_FANOUT_LIMIT`) dispatch over a **project-defined** type (in `byName`) is treated as not-broad and
resolves to the EXACT UNION of its impls via the fixpoint — more precise than the homogeneous-only
collapse this item proposed (it resolves heterogeneous fan-outs too: `getId` over 40 pure enums → pure;
a mixed interface → the union of its impls' effects, e.g. `{Fs}`, never silent-pure). OFF by default
(byte-identical to before — PetClinic/jsoup/gson unchanged); gated to project types, so an EXTERNAL/
library broad hierarchy (Comparator, a Kotlin FunctionN — the perf-pathological ones the bound exists for)
stays bounded even under the flag. The user asserts "the scanned classes are the complete world"; a library
author doesn't set it and stays sound. Sealed/enum closed hierarchies already resolve UNconditionally
(0.7.0/0.7.1) — those self-verify completeness and need no flag. Tests: `ClosedWorldTest` (default → Unknown;
flag → pure for the all-pure interface and `{Fs}` for the heterogeneous one). Decision rationale (Option B
over the automatic Option A) recorded in the session: A would plant a silent-pure bug in SPI/plugin code
where candor can't tell app from library; B keeps the floor honest by default. The analysis below is kept
for context.

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

## Soundness (field-lambda dispatch, ⟨0.35⟩ PART 87 vein)

**Context:** `a294b86` closed PART 87 for the same-class INSTANCE FIELD shape only. A follow-up session
(2026-09-01) closed STATIC fields and INHERITED fields (`Cha.fieldKey`, tagging GETSTATIC with
`fieldOrigin`) — both verified cardinal sins, four-way-checked against `candor-spec`'s
`cha_completeness_check.py`, revert-tested, and A/B'd against 325 real jars (`soundness/lib`). Two
further instances of the same property were found and VERIFIED but NOT fixed in that pass — logged here
so the next session starts ahead rather than re-discovering them.

### Field provenance does not survive a call through a GETTER — a broader, pre-existing gap than
### PART 87's own two fixed shapes, and out of scope for that fix

**MEASURED at HEAD (⟨0.35⟩ + the static/inherited field-lambda-binding fix), and reproduces on the
PUBLISHED 0.34.0 jar too — i.e. this predates BOTH fixes and is unrelated to either.** `ProvValue
.fieldOrigin` (the tag `Cha.fieldBoundImplementors` reads to complete a field-held-lambda dispatch) is
set only when the call's RECEIVER is itself a GETFIELD/GETSTATIC result — see `Interp.ProvInterpreter
.unaryOperation`/`newOperation`. It does not propagate through a method call: a value returned from a
getter carries no `fieldOrigin`, `newType`, or any other provenance tag (a bare `ProvValue` from
`naryOperation`). So the ordinary Java idiom of a private field plus a public getter defeats field-lambda
completion entirely, with NO inheritance needed:

    private Runnable task;
    public void install(Store s) { this.task = () -> s.write(); }
    public Runnable getTask() { return task; }
    public void fire() { Runnable t = getTask(); if (t != null) t.run(); }

`Widget.fire` is ABSENT from `functions[]` — same-class, same published-0.34.0 jar, zero inheritance.
The dispatch falls straight to the pre-existing CHA path (fieldBoundImplementors returns null since the
receiver's `fieldOrigin` is null), and if the project happens to have exactly one PURE implementor of
`Runnable` in scope, CHA silently resolves to it — PART 87's own signature, through a THIRD chokepoint
neither the review nor this session's fix touched.

**Why this is out of scope for the static/inherited-field fix in this pass.** That fix normalizes the
KEY two field accesses are recorded/looked-up under (`Cha.fieldKey`); this gap is about provenance not
surviving AT ALL past a call boundary — a different, much larger mechanism (interprocedural value
provenance: does a function's RETURN value carry the provenance of what it returns). This is the same
class of problem the standing `[[candor-value-provenance]]` design item names ("recover a value's
concrete origin across construction/fields" — design doc written, impl pending); a real fix here needs
that groundwork (summarizing a method's return provenance and propagating it to each call site), not a
local patch to `Interp`/`Cha`.

**Repro:** `.../scratchpad/repro35/getter2` in the review session (compile `Store.java`/`Widget.java`
above + `Repaint implements Runnable { public void run(){ n++; } }`, scan, `deny Fs Widget.fire` → exit
0 on both the published 0.34.0 jar and HEAD).

### The static/inherited-field over-charge is closed for a CLEAN write-set; a TAINTED write-set
### (an unresolvable, off-project method reference) still falls through to CHA and can still
### fabricate

**MEASURED at HEAD, post-fix.** `collectFieldLambdaBindings` taints (excludes from binding) a field the
moment ANY write to it is not a recognisable project lambda/method-ref — by design, since the write
could be anything (see that method's own TAINT doc). A field written ONLY via an off-project method
reference (`this.fn = String::length;` — `indyLambdaTarget`'s project-only filter returns null for it)
degrades to "tainted", falls through to the OLD CHA path exactly like a genuinely opaque
(parameter-sourced) write, and if the interface has exactly one EFFECTFUL unrelated implementor in
scope, that implementor's effect is attributed to the caller — even though the field's true runtime
value (the JDK method reference) can never reach it. This is the SAME over-charge shape reported for
static fields in this session (now closed for a clean write-set), surviving through a THIRD trigger:

    private ToIntFunction<String> fn;
    public void install() { this.fn = String::length; }   // clean spelling, but the target is off-project
    public int fire() { return fn != null ? fn.applyAsInt("hi") : -1; }
    // + `class Other implements ToIntFunction<String> { ... writes a file ... }` elsewhere in the project

`Widget.fire` gains `Fs` from `Other` — a fabrication — on both the published 0.34.0 jar and HEAD
(unaffected by this session's static/inherited fix, since `fn`'s write was never tainted BY the
static/inherited bug; it is tainted by construction, deliberately, because the target is unresolvable).

**Why not fixed in this pass.** Closing it needs a THIRD field state beyond "bound" (clean project
write-set) and "tainted" (fall through to CHA, unconstrained): a field whose every write is a
RECOGNISABLE lambda/method-ref bootstrap but at least one target is off-project. Such a field's true
runtime value set is PROVABLY `{known project bodies} ∪ {specific external targets}` — never an
unrelated project implementor — so the sound completion is the project bodies' effects unioned with
`Unknown` (disclosed), not a fall-through to unconstrained CHA. That is a new mechanism (a third taint
state plus a dispatch-site consumer for it), not a one-line change, and it needs its own over-charge
controls before shipping — flagging it here rather than rushing it into this pass.

**Repro:** `soundness/lib` corpus round via `soundness/dynamic/agent` is not needed — a two-class fixture
reproduces it directly (see `.../scratchpad/AttackFieldLambda2Test.java`'s
`taintedFieldFallsThroughToNarrowCHAAndMayOvercharge`, written during the review that found this vein;
promote it to `FieldLambdaCompletionTest` alongside a fix when this is picked up).

## Equivalence (scan --policy ≡ gate --report)

### A MERGED `interfaceUnion` entry still breaks §3.1 byte-equality — needs a format rung

**What (MEASURED 2026-07-28, `CANDOR_WORKSPACE_CHAIN=1`).** `ReportWriter.appendInterfaceUnions` has two
arms. When the interface method's hash is UNCLAIMED it appends a fresh entry marked `interfaceUnion: true`
— `Policy.gateInputFromReport` now reads that marker and the gate does not report it as a violator (fixed
2026-07-28, verified byte-equal). When a REAL entry already claims the hash (an effectful `default` method,
or an abstract class's concrete member) the union is MERGED INTO IT and the entry stays **UNMARKED**,
deliberately: it is a real analysed unit counted in ⟨0.21⟩ `analyzed`, and marking it would make a consumer
subtract it twice from the pure count.

Measured on `interface Store { default void save(String s){ Files.writeString(…); } }` +
`class S3Store implements Store` overriding with an HTTP call, under `deny Net`:

| route | violations |
|---|---|
| `scan --policy` | 1 — `impl.S3Store.save` |
| `gate --report` over the report that scan just wrote | 2 — `impl.S3Store.save`, `lib.Store.save` |

`lib.Store.save`'s BODY performs `{Fs}`; the report publishes `{Fs, Net}` because the merge widened it for
a chained consumer. The gate is a pure function of the report, so it is faithfully reading a widened set —
the divergence is that a producer's own gate verdict moves because it published more for its consumers.

**Why it is not patched around.** The report carries no way to tell a widened entry's BODY effects from its
dispatch union, and there is no marker to key off (adding one is what the merge arm deliberately rejected).
Guessing — e.g. skipping any entry whose hash names an interface member — would drop a real `default`-body
violation: a fabrication traded for a silent under-report. As it stands the defect is in the FABRICATION
direction (an extra violation row, never a missing one), so it fails safe.

**Shape of the fix:** a third state on the wire — either the body's own effect set beside the widened one,
or a `unionWidened: true` flag distinct from `interfaceUnion` and excluded from the pure-count arithmetic.
Cross-engine (rust/ts/swift all ship the rung), so it is a spec item, not a local patch.

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
- **Test coverage**: HibernateJakartaPersistence (κ batch 24), Panache, InheritedPersistenceVeins, InheritedModeledBase, HttpClientNet,
  ContainmentRatchet, PolicyParser, PolicyGate, LayerOf (the policy gate + κ rules were under-tested).
