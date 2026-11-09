# The generated framework table — SOUNDNESS R492 / R727

`Rules.KAPPA_COVERED_PREFIXES` grants ~51 namespaces: a call into one that the classifier does not name
was certified pure. For language runtimes that is defensible; for frameworks it silenced real I/O
(groovy `deleteDir`, commons-csv `parse(File)`, Spring `FileSystemResource`, JNA `loadLibrary`, …).
This directory replaces the grant's blanket claim for the **surveyed** frameworks with two generated
resources:

| resource | what a line says |
|---|---|
| `src/main/resources/candor/framework-reach.tsv` | `owner.name+desc → effects`: the body the JVM resolves for that call reaches, along statically resolved edges, a body this engine's own scan charged with those effects (`direct`, concrete only). |
| `src/main/resources/candor/framework-hedge.tsv` | the RESIDUE: `A` — a member with no surveyed body (abstract/interface/native) some surveyed implementer of which is charged or unreadable, or which has none; `U` — every resolved body is one the scan read only as `Unknown`; `S` — a surveyed framework class (a class under a framework prefix and NOT listed is unsurveyed, `X`); `J` — a JDK package (keeps the grant). |

A member in neither file was **examined and found pure**: its silence is now a measurement.

    bash soundness/kappa_table/derive.sh build/libs/candor-java-*-all.jar          # regenerate
    bash soundness/kappa_table/derive.sh --check build/libs/candor-java-*-all.jar  # weekly CI

Inputs are `sources.tsv` (Maven coordinate + SHA-256 per jar; a mismatch is refused), `derive.sh`,
`FrameworkReachGen.java`, `jdk-packages.txt` and the engine jar (scanning with `-Dcandor.frameworkReach=off`,
so the table never feeds itself). Same inputs → byte-identical outputs. `KappaFrameworkReachTest` checks the
content and generator checksums on every push. `witness.tsv` (gitignored) gives every charge's path to its body.

**Nothing else is an input — in particular not the machine.** Until 2026-10-09 two more were, unpinned, and the
committed table could not be reproduced by CI: the `J` lines came from the module list of whatever JDK ran the
generator (a JDK 17 `JAVA_HOME` wrote `com.sun.jarsigner`/`com.sun.tools.sjavac*` and omitted
`java.lang.foreign`; a Linux image adds `sun.awt.X11`, a macOS one `sun.lwawt.macosx`), and the scans read the
caller's `CANDOR_*` environment (a chained `CANDOR_DEPS` report turns `CaffeineCache.get`'s `Unknown` into
effects, which deletes its `U` line and the `A` line above it). Now `jdk-packages.txt` is the union of the JDK 21
images for Linux, macOS and Windows — the release whose 227 exported packages SOUNDNESS R814's census read; a
JDK 17-only or JDK 22+ package stays `X` (an Unknown, not a silence) — and `derive.sh` unsets every `CANDOR_*`
and the JVM option variables and pins config discovery to an empty file. Verified: `--check` passes under
Homebrew JDK 21 (macOS), Amazon Corretto 17 (macOS) with a `CANDOR_DEPS` seeded into the shell, and Temurin 21
on Linux. Regenerate the package list with `FrameworkReachGen --jdk-packages` (see its header).

## The named miss — the JDK is OPAQUE, framework bodies are TRANSPARENT

The closure stops at the JDK: there are no JDK bodies here, only the classifier's name rules. A framework
member whose effect happens inside a JDK body the classifier leaves uncharged is missed exactly as a
direct call to that JDK member is. R814 (`KappaJdkSinks`) is that frontier; this table does not move it.

## What it costs, measured (823-jar corpus vs published v0.40.1)

* **Charges are hub-shaped, not uniform.** 55,229 rows newly carry a concrete effect; **51.8% gain only
  cross-cutting effects** (Clock/Log/Rand — reported, not scored, SPEC §6.1). The hubs:
  * geode-core **16,224** rows from **5** `com.sun.jna.Native.register` call sites (Native's static
    initialiser loads the native library: Exec/Fs/Env — genuine, once per JVM);
  * `new ObjectMapper()` → **Clock** (`ByteQuadsCanonicalizer.createRoot` seeds from the clock):
    adyen 3,923 rows, kubernetes-model 1,609;
  * jna-platform `Structure.<init>` → **Log** (JUL warnings in `Native.getCharset`): ~2,200 rows per
    jna-platform jar;
  * groovy `ScriptBytecodeAdapter.castToType` → [Clock, Fs, Log, Net] — the largest PRECISION cost: its
    row is the union over Groovy's whole type ladder (`asCollection → ResourceGroovyMethods.readLines(File)`,
    SAM coercion → `ProxyGenerator`). `Candor.groovyCastArm` takes the ladder arm when the class argument
    is an `ldc` of `Object`/`String`/`Character`/`Boolean`/`Class` (javap-derived, sound); that removed
    812 of rest-assured's 1,802 flips. Casts to other classes keep the full row.
* **A correct scoped `allow` can go red.** A side charge with no captured locator marks the surface
  `incomplete` (`allow Fs in f /real/path` then fails): **21 strict rows** that had a captured locator for
  the effect (bcjmail ×15, spring-beans ×6), **1,883 Fs / 132 Net / 3 Exec loose** rows. A call whose
  File/Path operand IS a captured locator (`deleteDir(new File("/tmp/x/sub"))`) is judged by it instead.
* **The residue hedge** puts `Unknown` on **31,520** analysed units (**0.79%** of 3,976,208; 18,379 of
  them `Unknown`-only, the rest already effectful) — `deny Unknown` flips on those scopes, nothing else.
  Its imprecision is the library scan's own: `U` inherits every `Unknown` that scan reported, e.g.
  Spring `StringUtils.cleanPath` (it iterates a `Collection`).
* **Version drift.** A charge is a claim about the surveyed version. Measured against a second version:
  minor/patch 0 of 877 pairs differ; major 3.9% (groovy 3→4) / 8.7% (spring-core 5.3→6.1) — always an
  over-charge on the other version, never a purity claim. Charges in only one of two surveyed versions
  (61, all struts 1.2.9 vs 1.3.10) are made nowhere.

## Overrides are dispatched, at the call a consumer makes (SOUNDNESS R1096)

A member's row used to be the closure of the body JVMS RESOLUTION picks for the static owner — the declared or
inherited one. A consumer holding the base type runs whatever the receiver overrides, so
`AbstractSqlPagingQueryProvider.init(ds)` read pure while the `DerbyPagingQueryProvider` it was handed opened a
connection (EXECUTED; `deny Db` exited 0). `FrameworkReachGen#overriders` now applies the engine's own bounded CHA
(Cha#chaTargets, Candor#virtualDispatch) at every consumer-facing instance member, over the same jar's hierarchy: the
bodies of the subtypes that DECLARE the member are unioned into the row when there are at most
`Rules.CHA_FANOUT_LIMIT` of them; a BROADER fan-out is not smeared into the row but disclosed (an `A` line), and only
where an override can do what the declared body cannot. Exempt as in the engine: the Object protocol, a CHA-exempt verb
past the bound, and closure-object dispatch (Scala `AbstractPartialFunction.applyOrElse` & co. — unioned, it put Exec
on 8,578 scala-compiler rows through R1078's declined `scala.sys.process` bridge charge). A `U` member charged only
through an override keeps its `U` line; the engine applies `U` and `A` beside a table charge.

Measured against the previous table: 808 rows gain an effect (453 a non-cross-cutting one), none loses one, 30 `A` lines
are added, and every gained charge's witness starts at an override body.

NOT done, and why: the same union on the table's INTERNAL edges (a framework body's own virtual calls). Built
unbounded and measured (`-Dframework.dispatch=edges`): 31,814 rows gain an effect (Exec on 17,001). And a subtype in
ANOTHER surveyed jar (spring-rabbit's `RabbitMessagingTemplate` over spring-messaging's
`AbstractMessageReceivingTemplate.receive`) is not unioned: the table cannot know that jar is present.

## Inherited leaf over-charges, and the `P` lines (SOUNDNESS R1052)

Three over-charges rode through the table from LEAF rules that fire at a direct call (v0.40.1/0.40.2). Each is
fixed in the leaf; the table inherits the fix by regeneration.

* **`URL.openStream`/`openConnection` → `Net` whatever the scheme.** A URL provably obtained from the program's
  OWN class loaders (`X.class.getResource`, `this.getClass()…`, `X.class.getClassLoader().getResource(s)`,
  `ClassLoader.getSystemResource(s)`, an element of their `getResources`, and the `URLConnection` its no-arg
  `openConnection()` returns) is read as `Fs` — the `getResourceAsStream` read by another spelling. Provenance
  is `Interp.ProvValue#urlOrigin`. A loader that arrives as a parameter, a field, from
  `Thread.getContextClassLoader()` or from `new URLClassLoader(…)` is NOT trusted: a remote loader's
  `getResource(..).openStream()` was EXECUTED sending `HEAD`+`GET` to its server. So groovy
  `URLStreams.openUncachedStream(URL)` (a parameter) and JNA `Native.extractFromResourcePath` (a caller's loader
  or the context loader) keep `Net` — undecidable from the body, charged, not silent.
* **A whole-owner rule on members that do nothing**, and **Spring AI's model-SDK blanket on getters** — one
  mechanism, the `P` lines of `framework-hedge.tsv`: a member a NAME rule charges (an owner-blanket classifier rule
  or the model-SDK blanket) whose surveyed body, and everything it can run, `FrameworkReachGen#computePure`
  PROVES pure (an allowlist of JDK members, statically-resolved surveyed bodies, no lambdas, no unresolved
  dispatch). The engine drops the name rule there and nowhere else. It is NOT "any private helper inside the
  owner": that was built first and measured losing `KafkaTemplate.receive`'s Net through a private helper whose
  real I/O sits behind an interface (and the java κ lane lost Mongo `deleteAll` the same way). A pure member
  whose RETURN type carries the I/O to a later call the hedge can only disclose (`MongoTemplate.query(X.class)`
  → `.all()` on an interface) keeps the rule, which is why derive.sh iterates the P list to a fixed point over
  the closed effects. And inside a LIBRARY body the drop is honoured only where the table can see the whole
  closure (`FrameworkReachGen` step 5a): measured, `RabbitMessagingTemplate.receiveAndConvert(Class)` reaches the
  broker through the abstract `doReceive`, and its only table charge was the blanket on its own (pure)
  `resolveDestination()` — dropping it removed the row and `RabbitMessageOperations.receiveAndConvert`'s `A`
  hedge. A body whose closure reaches such an unfollowable dispatch keeps the rule's charge (81 bodies).
  RestTemplate's three constructors are also carved out of its whole-owner rule by hand (javap: they only
  allocate).
* **The 5a stand-in is a charge only where the hidden dispatch can perform it (SOUNDNESS R1468).** Put back
  unconditionally, step 5a charged `new RestTemplate()` `Net` — EXECUTED, no connection on spring-web 5.3.39 or
  6.1.10 — because its converter set-up reaches a dispatch the table cannot follow, and 100 (member, effect) pairs had
  only that stand-in as their charge. The generator now records, per body, the concrete effects
  of the surveyed implementers of the unfollowable dispatches in its closure, and keeps the rule's charge only where one
  of them carries it (RabbitMessagingTemplate.receiveAndConvert: EXECUTED, it connects; pinned by
  `OpaqueClosureStandInR1468Test`). Elsewhere the member gets a `C` line naming an unfollowable member of its closure,
  and the engine discloses `Unknown[dispatch:<that member>]` at the call, beside a charge or alone. A disclosed stand-in
  still counts as unvouched everywhere a charged one did (A lines, the P fixed point, BROAD, O lines).
  `Llm` is a label no body performs, so a model request whose body is charged `Net` keeps a stand-in `Llm`. Measured:
  75 pairs removed (Net 33, Llm 22, Db 20; 39 `C` lines, 14 `U` lines where the member's bodies now read only
  `Unknown`), 25 kept; every removal executed or read as performing nothing at that call (R1468 lane evidence).

* **The return-type guard asks what the hidden later call can do (SOUNDNESS R1476).** A P member whose RETURN type has an
  abstract member the hedge discloses kept its name rule whatever that member could do, so once R1471 hedged every
  implementer carrying `Unknown`, `RestTemplate.getUriTemplateHandler()` (`getfield; areturn`) lost its P line because
  `UriTemplateHandler.expand` is hedged, and a consumer reading the handler read `Net` again (EXECUTED: an expand opens
  nothing). The guard now keeps the rule only where such a member can perform the rule's effect
  (`FrameworkReachGen#canPerform`): it has no surveyed implementer, or one reaches the effect, or reaches code outside the
  surveyed jars and the JDK. The reach is the implementer's statically-resolved closure plus the concrete effects of one
  level of surveyed dispatch, the level step 5a reads. The consumer's later call keeps its `Unknown[dispatch:...]`.
  Kept by it, and pinned: `KafkaTemplate.getProducerFactory()`. The factory's surveyed implementers read Clock/Log, and the
  producer `createProducer()` builds opens its connections inside kafka-clients, which is not surveyed (EXECUTED: 9
  connections). Not restored, for the same reason: `ReactiveMongoTemplate.createCollectionPreparer` (its preparer calls
  the unsurveyed Mongo driver through method references). Measured: 5 P lines restored (`getUriTemplateHandler`,
  `ResultSetIterator.getDynaClass`, `JCache.getCodec` and two Couchbase `getEntityInformation`), each executed or read as
  doing nothing at the later call; no reach row and no A/U/C line moved. The same pass resolves a FINAL `Enum`/`Object`
  member a surveyed class only inherits (`EncodingMode.equals`) as the JDK call it is (SOUNDNESS R1479); in step 5a
  that changes 2,463 of 110,469 opaque bodies, none of which calls a P member, so neither table moves through it.

The residual is the table's own: a P line is a claim about the body the JVM resolves in the SURVEYED version, not
an override shipped in another jar (a PROJECT override is still reached by CHA — pinned in
`LeafOverChargeR1052Test`).

## A receiver the consumer supplies, and the `D` lines (SOUNDNESS R1565 / R1569)

The generator scans each framework jar ALONE, so to that scan the jar is the whole program. SOUNDNESS R1299 bounds an
`Object`-owned `hashCode`/`equals`/`toString` by the receiver's declared PROJECT type, which is right for a closed-world
scan, and here it made joda's `PreciseDurationField.hashCode` (`getType().hashCode()`) read pure: CHA over
`DurationFieldType` finds only joda's own pure implementers. A consumer that hands in its own `DurationFieldType` whose
`hashCode` reads a file runs that read (EXECUTED), and since the 2026-11-07 regeneration dropped the stale `U` line the
call read pure: `deny Fs Unknown` 1 -> 0 against 0.40.18, on 13 members (ehcache `EventListenerWrapper`, jakarta.mail
`AddressTerm`/`FromTerm`, joda's duration fields, `DateTimeComparator` and the `Period` family). The same shape without
the `Object` protocol: spring-data-mongodb `AggregationSpELExpression.toDocument(ctx)` wraps `ctx` into a context object it
creates and calls `ctx.getReference(..)` through it (R1569). R1511's `T` lines cover a callback on `this` or on a direct
parameter only.

The scan already names every such dispatch on its row (`dispatchesOn`, SPEC §4 obligation 1), and a CHAINED consumer
joins its own implementers of it. The `D` lines give the unchained arm the same key: per consumer-callable member, the
union over the bodies the call can run of each body's `dispatchesOn`, closed over the report's own `calls` (the closure
`Candor#depTransitiveDispatch` takes), kept where a consumer can implement the member (`FrameworkReachGen#openKey`: a
public, non-final surveyed type with an accessible constructor or an interface, the member overridable). An abstract
member's keys come from its implementers in EVERY surveyed jar: limiting them to the declaring jar reintroduced the silence
across a jar boundary (spring-session's `HttpSessionAdapter.getAttribute` runs the consumer's `Session`, and servlet's
`HttpSession.getAttribute` has no `A` line because that implementer reads pure in its own scan; executed, `deny Fs` 0).
The precision of the closure, each rule measured before it was made and checked by the over-join audit:

* a dispatch on the body's own `this` is not a key when EVERY call of that member in the body is on `this` (`#onThis`;
  a `super.m()` counts as neither): that is R1511's `T` line. A decorator's `inner.m()` keeps it (dbunit's
  `ConditionalSetBiValueComparer.toString`, executed: 2 reads, silent before);
* a `calls` edge counts only where the caller's bytecode has a call on a non-JDK owner related to the callee's class,
  or creates the lambda or method reference (`#edges`): the scan also edges every in-jar implementer of a JDK interface;
* a class initialiser IS followed: what one dispatches on can be the consumer's (kotlinx's `MainDispatcherLoader.<clinit>`
  loads the consumer's `MainDispatcherFactory` through `ServiceLoader` one call down; executed, it was charged on c819779
  and silent when initialisers were cut);
* the closure is taken per (body, receiver bound) (`#resolvePending`): a call on `this` reaches only bodies of classes
  related to what that receiver can be (the member's class at a root, a call's static owner after it). `Errors.hasErrors()`
  reached for a `BindingResult` cannot run `ParameterErrors.getGlobalErrors`, whose delegate put `Errors.getGlobalErrors()`
  on `BindingResult.hasErrors` and charged spring-web's `EscapedErrors` (not a `BindingResult`) at 11 callers;
* a key on a PARAMETER (or on an element of a parameter array) does not reach a caller that fills that parameter with an
  object it makes itself (a `new`, a lambda, a constant, an enum's own `values()` or constant):
  `BridgeMethodResolver.findBridgedMethod` hands `ReflectionUtils.doWithMethods` its own callback (executed: 0 reads; it
  was charged a consumer lambda's `Fs`), and jackson's `JsonParser.<clinit>` hands `JacksonFeatureSet.fromDefaults` its
  own `StreamReadCapability.values()` (it put `JacksonFeature.enabledByDefault()` on every parser member);
* a key whose every call site in the body is on a final class or an enum is not one (`#onlyClosedSites`).

Closing over this generator's own edges plus R1096's override union was measured too: the lists grew to 40 MB.
Residual: a CONSUMER class that extends a framework class and implements a framework interface the class does not, whose
inherited body an interface default reaches on `this` -- the receiver bound sees only surveyed classes combining the two.
`E` lines are
the distinct lists (by `K` number), `K` lines the dispatched members; a `D` line is written only where it differs from
what the walk up the `H` lines reads, as for `T`. `Cha#frameworkDispatchJoin` edges the consumer's implementers of each
member (its CHA, its lambdas, and the classes that reach the owner only through a framework class), past the CHA bound
discloses `Unknown[dispatch]`, and adds nothing where the consumer implements none -- the framework's own implementers are
already in the row, exactly as in the chained join. A resolution, additive; `CANDOR_R1565=0` switches the join off.
A project receiver that inherits a framework body is looked up under its nearest framework superclass AND every framework
interface it implements: `class C implements AutowireCandidateResolver {}` runs the interface's default
`isAutowireCandidate(holder, descriptor)`, which calls the consumer's `BeanDefinition` (executed: 1 read, silent before).

Its precision is the chained join's: the key says the body dispatches on that abstraction, not that the receiver is the
consumer's. `Days.hashCode` hashes a joda singleton field type, and a consumer with a file-reading `DurationFieldType`
anywhere in its scan is charged it there too (an over-charge, never a silence).
