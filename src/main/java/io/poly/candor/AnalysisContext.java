package io.poly.candor;

import java.util.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Frame;
import io.poly.candor.model.*;

/** The engine's per-scan analysis state — the mutable accumulators a scan fills (effect/edge/literal
 *  maps, the call graph, the CHA/overload indices, the κ-ledger, the deferred-lambda + functional-param
 *  forwarding bookkeeping). One INSTANCE per scan: a fresh {@code AnalysisContext} is a fresh slate, so
 *  no global clear is needed.
 *
 *  <p>The fields moved here from {@code AnalysisState} (LB-0/LB-1a); the engine reaches them through the
 *  {@link AnalysisState#ctx()} accessor ({@code ctx().direct} …), which is backed by a per-thread
 *  {@link ThreadLocal} (LB-1b). Each scanning thread therefore owns its own context, so concurrent /
 *  parallel scans are isolated. Spec-vocabulary + Spring-marker CONSTANTS stay in Candor. See
 *  docs/level-b-scoping.md. */
final class AnalysisContext {
    final Map<String, EffectSet> direct = new HashMap<>();
    final Map<String, Set<String>> edges = new HashMap<>();
    final Map<String, String> loc = new HashMap<>();
    final Map<String, String> hashOf = new HashMap<>();           // fn -> stable method-ref hash (owner.name+desc)
    final Map<String, EffectSet> viaCross = new HashMap<>();       // fn -> effects inherited from a dependency report
    Map<String, DepFn> crossDeps = new HashMap<>();          // method-ref hash -> DepFn (from CANDOR_DEPS)
    // Memoized `crossDeps` grouped by declaring type (internal name) — the hand-off join has no descriptor
    // to key on (see Candor#depFnsOfType), and scanning every hash per site would be quadratic.
    Map<String, List<DepFn>> depFnsByOwner = new HashMap<>();
    // Memoized `crossDeps` grouped by declaring type AND member name ("owner.name" -> desc -> DepFn). The
    // by-NAME reentry contracts (compareTo/append/write/read) resolve over ANY descriptor, so there is no
    // single hash to key on; the DESCRIPTOR is kept because per-overload shadowing decides which of a
    // dependency's same-named methods a project override actually replaces (Candor#nearestDepFnsNamed).
    Map<String, Map<String, DepFn>> depFnsByOwnerName = new HashMap<>();
    // `crossDeps` inverted by SIGNATURE (`name+desc` -> the dep owners declaring an EFFECTFUL body with
    // it) — the evidence the untyped-dep-receiver disclosure needs (Candor#untypedDepReceiver). Built
    // once, lazily, on the first interface dispatch that gets that far; empty when nothing is chained.
    Map<String, Set<String>> depOwnersBySig = new HashMap<>();
    boolean depOwnersBySigBuilt = false;
    final Map<String, TreeSet<String>> fsDirect = new HashMap<>(); // fn -> Fs read/write kind performed directly
    final Map<String, TreeSet<UnknownReason>> unknownWhy = new HashMap<>(); // fn -> why Unknown emitted directly
    // VALUE-PROVENANCE Phase 2: instance stream fields ("owner#name") PROVEN bound only to in-scope concrete
    // opens across the whole program — so a stream-consuming read of one is pure-relative and the Phase-1
    // Unknown is suppressed. Computed once in a pre-pass; empty unless a field is provably all-concrete
    // (conservative: any doubt leaves it out, keeping the sound Phase-1 disclosure).
    Set<String> suppressibleStreamFields = new HashSet<>();
    // Provenance frames the Phase-2 pre-pass computed, handed to the main analyze pass so a stream-touching
    // method's ASM dataflow is not re-run (consume-once: provFrames removes on read). Bounded to the few
    // stream-relevant methods the pre-pass visits; freed as the main pass consumes each.
    Map<String, Frame<Interp.ProvValue>[]> provFramesCache = new HashMap<>();
    // ⟨0.19⟩ user-defined reason-class aliases from `.candor/config` (`unknown-alias <name> = <class,…>`),
    // consulted by the §6.2 deny parser for an `Unknown[<name>]` filter. Populated before parsePolicy.
    Map<String, Set<ReasonClass>> unknownAliases = new HashMap<>();
    // ⟨0.24⟩ SPEC §3.1 — THE AMBIENCE MUST BE DISCLOSED. `vocabularySource` is the config file the aliases
    // above were read from; `vocabularyUsed` is the alias names a POLICY RULE actually referenced. When
    // both are set the file PARTICIPATED IN THE VERDICT, and the --gate-json document MUST name it: a
    // verdict changed by a file the operator cannot see named in the output is the ambient-input failure
    // this format exists to refuse. Emitted whether the rule FIRED or not — the measured harm was a GREEN
    // verdict that a vocabulary file made green.
    String vocabularySource;
    final java.util.TreeSet<String> vocabularyUsed = new java.util.TreeSet<>();
    // ⟨0.20⟩ project-declared partner hosts from `.candor/config` (`net-partner <host>`), consulted by the
    // Net destination-class classifier (Literals.netDestClass) to refine a visible host to `known-partner`.
    // Populated alongside unknownAliases (before parsePolicy / after runScan). Empty = telemetry-only asserts.
    Set<String> netPartners = new HashSet<>();
    /** ⟨0.31⟩ the declared partners that actually MOVED a classification in this run — the provenance the
     *  report's `netPartners` key discloses. A declaration that changed nothing is not provenance, so this
     *  holds what PARTICIPATED rather than what was written down. */
    final java.util.TreeSet<String> netPartnersUsed = new java.util.TreeSet<>();
    /** ⟨0.31⟩ the config file the partners were READ FROM — taken from the same {@code Config} object,
     *  exactly as {@code vocabularySource} is for `unknown-alias`, so the disclosure cannot name a
     *  different file from the one that supplied the vocabulary. */
    String netPartnersSource;
    // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): the TARGET's own class files candor could NOT analyze — a .class
    // ASM couldn't parse (a future-major bytecode version, a corrupt entry). path → reason. Their effects are
    // absent NOT because pure but because never seen; carried into the report + the gate verdict (a gate over
    // skipped classes must fail closed, never green). LinkedHashMap: disclosure order = discovery order.
    java.util.LinkedHashMap<String, String> unanalyzed = new java.util.LinkedHashMap<>();
    // ⟨0.29⟩ THE SCOPE (candor-spec/FILE-SET-DESIGN.md): what the walk chose not to OPEN — as opposed to
    // `unanalyzed` above, which is what it opened and could not read. A consumer cannot tell those two
    // apart from `analyzed.count` alone, because the denominator is this engine's file selector and the
    // selector is invisible. Recorded AT THE SKIP (Loader#collectClasses) plus the source sweep, which
    // cannot run earlier because "has this source got a compiled class?" needs the analyzed set. path →
    // class token; disclosed as a COUNT per class, never a file list.
    java.util.LinkedHashMap<String, String> excluded = new java.util.LinkedHashMap<>();
    // ⟨0.29⟩ the ARCHIVES the walk passed over. A directory walk filters `.class`, so a `.jar` under the
    // scan root (`build/libs/app.jar`, a vendored `libs/*.jar`) is bytecode this engine reads perfectly
    // well and never opened. THE PEEK's target: `load()` already reads a jar, so peeking one is this
    // engine's own entry point over a different file rather than a second pass.
    java.util.List<java.nio.file.Path> archives = new java.util.ArrayList<>();
    // ⟨0.29⟩ JVM-language SOURCE seen during the walk, as `path\0package` (package empty when undeclared).
    // The java arm of the ⟨0.29⟩ measurement is a source whose class was never built: candor-java reads
    // BYTECODE, so such a file is invisible to it and to the peek alike.
    java.util.List<String> sourceFiles = new java.util.ArrayList<>();
    // ⟨CHA-widening⟩ per-class DIRECTORY ROOTS this scan actually found `.class` files under (see
    // Loader#collectClasses), derived from each class's own file path rather than assumed from the scan
    // root — the peek's source-compile arm needs the REAL root(s) to resolve a project symbol, which the
    // literal scan-root path is not once classes sit under a nested `build/classes/java/main`.
    java.util.Set<java.nio.file.Path> classpathRoots = new java.util.LinkedHashSet<>();
    // ⟨0.29⟩ what this scan was pointed AT — so the scope block and the peek's findings can name a file
    // the way the operator does. An absolute path in a report says where the CI runner's checkout was.
    java.nio.file.Path scanRoot;
    // ⟨0.29⟩ what THE PEEK found: an effect the policy DENIES, in a file the gate did not judge. Its own
    // kind, never a violation — it moves no verdict. Null when no policy was configured (nothing asked).
    java.util.List<Report.OutOfScope> outOfScope = null;
    // ⟨0.33⟩ …and the QUESTION it was put: the deny rules this scan held, expanded. `peeked: true` is true
    // only relative to a deny set (the ⟨0.29⟩ bound filters the peek to what the policy DENIES), so a
    // consumer gating the report with a DIFFERENT deny set is answering a question nobody asked. Null under
    // exactly `outOfScope`'s rule — no policy, or a policy this engine refused — and set beside it, on the
    // main thread, from the rules the PEEK THREAD actually matched with.
    Report.ScannedUnder scannedUnder = null;
    // ⟨0.29⟩ the exclusion classes THE PEEK ACTUALLY READ this run. `excluded[].peeked` is derived from
    // this rather than from a per-class table, so a peek that never ran, or one whose files could not be
    // opened, cannot publish `peeked: true` beside an empty `outOfScope` — which would be byte-identical
    // to a clean peek and is the overclaim the flag exists to prevent.
    Set<String> peekedClasses = new HashSet<>();
    final Set<String> entryPoints = new HashSet<>();               // framework-invoked methods
    Set<String> projectClasses = new HashSet<>();
    /** ⟨0.32⟩ internal class name → the mtime of the .class FILE it was read from, for loose class files
     *  only (a jar entry's timestamp is the packaging moment, not the compile, so it answers a different
     *  question and is deliberately absent here rather than approximated).
     *
     *  <p>Exists for one comparison: a source file NEWER than the class compiled from it means this scan
     *  judged the code as it was BEFORE the edit. That verdict is about a program that no longer exists,
     *  and nothing in this engine used to say so — the source counted as "compiled" and the gate went
     *  green over stale bytecode. Taken at the read, because that is the moment whose bytes were analysed. */
    final Map<String, Long> classMtime = new HashMap<>();
    /** ⟨0.32⟩ root-relative source path → its mtime, the other half of the staleness comparison. */
    final Map<String, Long> sourceMtime = new HashMap<>();
    Set<String> repoTypes = new HashSet<>();                 // Spring Data repository interfaces (internal names)
    // JPA's declarative tables: @Table(name="users") names a table (LITERAL name attr only); a repo's
    // generic signature names its entity. Together a Spring-Data call carries its table into `tables`.
    Map<String, String> entityTables = new HashMap<>();      // entity internal name -> table
    Map<String, String> repoTables = new HashMap<>();        // repository internal name -> table
    Set<String> feignTypes = new HashSet<>();                // @FeignClient interfaces (internal names)
    Set<String> httpClientTypes = new HashSet<>();           // declarative HTTP-client interfaces -> Net
    List<ClassNode> ALL = List.of();                               // all loaded classes (for CHA)
    Map<String, ClassNode> byName = new HashMap<>();         // internal name -> node
    Map<String, Set<String>> transSupersCache = new HashMap<>();
    /** Reverse-subtype index for CHA: owner -> loaded classes that are owner-or-a-subtype. Built once
     *  after load so chaTargets() consults O(subtypes-of-owner) candidates, not ALL classes per call. */
    Map<String, List<String>> subtypeIndex = new HashMap<>();
    /** ⟨0.35⟩ SPEC §4 "A NON-EMPTY CANDIDATE SET IS NOT A COMPLETE ONE": {@code owner#name} (the same key
     *  {@link Interp.ProvValue#fieldOrigin} carries for a GETFIELD read) -> the project method ids of every
     *  LambdaMetafactory-produced implementor (an inline lambda's synthetic body, a method reference's real
     *  target, a constructor reference's {@code <init>}) EVER written into that field — present ONLY when
     *  every write this scan saw to that field was one of those, never an opaque value (see
     *  {@link Cha#collectFieldLambdaBindings}'s doc for why a per-FIELD binding, not a project-wide
     *  per-interface union, is the sound scope: the wider version broke the private functional-param
     *  forwarding tests by making an unrelated lambda anywhere in the project silently complete a call
     *  whose real receiver could have been an opaque value). Lets {@link Cha#fieldBoundImplementors}
     *  resolve `this.task = () -> …; … task.run();` to the real body instead of the dispatch falling
     *  silently pure the moment some UNRELATED class also implements the interface — without touching
     *  {@link Cha#chaTargets} or any general CHA/Unknown branch at all. Built ONCE by
     *  {@code collectFieldLambdaBindings} right after {@code subtypeIndex}, before any per-class analyze
     *  overlay starts — a shared INPUT, not an accumulator, exactly like {@code subtypeIndex} beside it
     *  (see the overlay constructor + MEMOS below: this is deliberately NOT a memo, because it is not a
     *  cache of a pure function recomputed on demand — it is enumerated once, up front, over the whole
     *  program). */
    Map<String, List<String>> fieldLambdaBindings = new HashMap<>();
    /** Memoized chaTargets(owner,name,desc) results. chaTargets is a PURE function of the (post-load,
     *  fixed) class hierarchy — the same call-key recurs across the many call sites that invoke a method
     *  on a given declared type — so caching collapses the analyze pass's dominant super-linear cost
     *  (CHA fan-out × super-walk, re-done per call site). Immutable values → safe to share. */
    Map<String, List<String>> chaTargetsCache = new HashMap<>();
    /** Overload index: `dottedClass.methodName` -> the distinct JVM descriptors declared under that name,
     *  so an overloaded node gets a param-type suffix and a pure overload never unions an effectful one. */
    Map<String, Set<String>> overloadDescs = new HashMap<>();
    Set<String> classesWithClinit = new HashSet<>();         // project classes with a `<clinit>`
    boolean taintEnabled = false;                                  // CANDOR_TAINT — run the intraprocedural taint pass
    boolean unknownRatchet = false;                                // CANDOR_UNKNOWN_RATCHET — a NEW Unknown vs the
                                                                   // baseline FAILS (AS-EFF-005), grandfathering the
                                                                   // existing Unknown surface (makes deny-E-Unknown adoptable)
    boolean closedWorld = false;                                   // CANDOR_CLOSED_WORLD — the scanned classes ARE the
                                                                   // complete world: a broad (>CHA_FANOUT_LIMIT) dispatch
                                                                   // over a PROJECT-defined type resolves to all its
                                                                   // impls (exact union) instead of dropping to Unknown
    // The dispatch owners where closed-world ACTUALLY CHANGED THE ANSWER — a broad fan-out that would
    // have disclosed Unknown was resolved to the visible impls because the flag asserted the world is
    // complete. This, not the κ ledger, is the precise trigger for the closed-world hazard warning: it
    // fires exactly when the flag moved a verdict, and stays quiet when the flag was inert. If that
    // assertion is wrong for any owner here (an implementor lives in code the scan never loaded), the
    // resolved answer can read PURE where a real effect lives — the cardinal sin, caused by a config
    // flag rather than a classifier bug.
    final Set<String> closedWorldResolvedOwners = new TreeSet<>(); // owner internal names, distinct
    final Map<String, EffectSet> tainted = new HashMap<>();        // fn -> injection-class effects on caller-derived args
    final Map<String, TreeSet<String>> hostsDirect = new HashMap<>();  // fn -> literal Net endpoints
    final Map<String, TreeSet<String>> cmdsDirect = new HashMap<>();   // fn -> literal Exec commands
    final Map<String, TreeSet<String>> pathsDirect = new HashMap<>();  // fn -> literal Fs paths
    final Map<String, TreeSet<String>> tablesDirect = new HashMap<>(); // fn -> literal Db tables
    // fn -> effects whose literal SURFACE is INCOMPLETE (a structurally-invisible reach); fail-closed so a
    // benign visible literal can't MASK an invisible forbidden endpoint. Propagated like the literal surfaces.
    final Map<String, TreeSet<String>> surfaceIncomplete = new HashMap<>();

    /** ⟨0.30⟩ THE PEEK'S VERSIONED PASS. When true, {@link Loader} INVERTS its multi-release rule: the
     *  base classes are skipped (the ordinary scan already judged them) and only the
     *  {@code META-INF/versions/<N>/} overrides are analysed. That is the same "ordinary path over a
     *  different FILE SET" the rest of the peek uses — not a second walk — so the two cannot drift. */
    boolean peekVersioned = false;
    // The κ-coverage ledger: external packages this code calls where the classifier never fires are
    // INVISIBLE, not Unknown — counted here, named in the receipt.
    final Map<String, Integer> kappaSeen = new TreeMap<>();        // external package -> call count
    /** Packages reached by a NON-CALL site (a static read forcing an unseen `<clinit>`). Kept apart from
     *  `kappaSeen` because that map's wire field is literally `calls` and its SUM drives the pinned
     *  scan-completeness threshold: counting `Cls.INSTANCE.m()` as two reaches (the GETSTATIC and the call)
     *  double-counts one reach and moved that threshold — measured, it nearly doubled a 49-call fixture. */
    final java.util.Set<String> kappaBlindPkgs = new TreeSet<>();
    // fn -> external packages it DIRECTLY calls into where κ floored the call; post-filtered to genuinely
    // blind packages + propagated transitively -> the per-method `invisible` disclosure.
    final Map<String, TreeSet<String>> blindDirect = new HashMap<>();
    // reflective calls with a LITERAL method name in the same body: a unique project match gets an EDGE
    // alongside the honest Unknown (recall without guessing).
    final List<String[]> reflectPairs = new ArrayList<>();         // [callerId, literalName]
    // Packages a CANDOR_DEPS sibling report covers: chained, not blind (even an omitted pure dep fn).
    // TRUST-GATED (§2.1): only a report whose producing build VERIFIES registers here, because coverage
    // is what turns the κ ledger's silence into a purity claim about every key the report omits.
    Set<String> depCoveredPkgs = new HashSet<>();
    // Packages a CANDOR_DEPS report was CHAINED for, trusted or not. Deliberately NOT trust-gated: it
    // answers "was a report configured for this package", a fact no version check unsettles, and it is
    // used only as the anti-flood conjunct of the untyped-receiver disclosure
    // ({@link Candor#untypedDepReceiver}) — never as an authority for silence. Gating it on trust cost 2
    // disclosed Unknowns on logback-classic (`ContextInitializer.printConfiguratorOrder` went
    // ['Unknown'] -> []) with no `invisible` to replace them, because `ch.qos.logback` is a κ-CURATED
    // covered prefix so the ledger is silent there either way. See StaleDepTrustTest.
    Set<String> depChainedPkgs = new HashSet<>();
    /** ⟨0.29⟩ How many CANDOR_DEPS reports this run actually READ — independent of what they contained.
     *  `crossDeps` counts entries JOINED and `depChainedPkgs` counts packages a report NAMED; an ALL-PURE
     *  dependency has neither (no effectful entry to join, and a class-directory report carries no
     *  `package` key), so both left the ⟨0.29⟩ `forbid`/`only` boundary disclosure silent in exactly the
     *  case it exists for. The operator chained a dep either way. */
    int depReportsRead = 0;
    // A chained dependency's OWN effect-relevant call graph and direct Unknown reasons, keyed by the §2
    // report QUAL (`fn`) — which is what `calls` names. Together they let a consumer recover the reason
    // class of an Unknown the dep INHERITED rather than emitted, which `unknownWhy` cannot carry because
    // it is direct-by-contract. Memoised closure in Candor#depTransitiveWhy.
    Map<String, List<String>> depCallsByFn = new HashMap<>();
    Map<String, List<String>> depWhyByFn = new HashMap<>();
    Map<String, List<String>> depTransWhyMemo = new HashMap<>();
    // TRUE-FORWARDING for deferred-execution containers (`by lazy`, ThreadLocal.withInitial, …): per
    // field, the lambda(s) stored into a recognised container, edged to the forcing site. FIELD-SCOPED
    // (key `internalOwner/fieldName:fieldDesc`), so a pure-init lazy stays pure.
    final Map<String, Set<String>> deferredFieldLambdas = new HashMap<>(); // field-key -> lambda body ids
    final List<String[]> deferredForcePairs = new ArrayList<>();           // [callerId, field-key]
    // PRIVATE FUNCTIONAL-PARAM FORWARDING. A `private` method invoking its single functional-param is a
    // CLOSED sink (all call sites are nestmates): when every site passes a fresh project lambda, the SAM
    // resolves EXACTLY to those bodies — no callback:Unknown. Suppressed only when no site passed an
    // unresolvable arg (fwdSinkOpaque).
    final Map<String, Set<String>> fwdSinkLambdas = new HashMap<>();       // sink id -> project lambda bodies
    final Set<String> fwdSinkOpaque = new HashSet<>();                     // sink id with >=1 non-lambda-arg site
    final Set<String> fwdSinkPending = new HashSet<>();                    // sink id whose param-SAM Unknown was DEFERRED
    final Map<String, String[]> fwdSinkPendingWhy = new HashMap<>();       // sink id -> [unknownWhy tag] to RESTORE

    // ---- folded in for LB-1 (were per-scan statics on Candor/Cha/Policy) ----
    Map<String, List<AnnotationNode>> annoMetaCache = new HashMap<>(); // meta/composed-annotation resolution cache
    Map<String, Boolean> sealedClosedMemo = new HashMap<>();           // Cha: sealed-closure verdict memo
    Map<String, Boolean> sealedUnseenMemo = new HashMap<>();           // Cha: sealed-permit-unseen memo
    Map<String, Cha.ExtSupers> externalSupersCache = new HashMap<>();  // Cha: external-class supers (classpath) cache
    // Cha: memoized JVM METHOD-RESOLUTION ORDER per type (superclass chain first, then interfaces —
    // see Cha#resolutionOrder). Keyed by `P\t`/`D\t` + internal name, the two `useDepHierarchy` arms.
    Map<String, List<String>> resolutionOrderCache = new HashMap<>();
    // A CHAINED dependency's own class hierarchy, read from the `<report>.hierarchy.json` sidecar every
    // scan already writes (internal name -> direct supers + interfaces, internal names). A dep's classes
    // are not on candor's classpath, so `Cha.externalSupers` could not see them and every question about a
    // dep type's supertypes answered "no supers" — the blocker under the receiver-driven write/read
    // residual and the abstract-dep-CLASS row. Empty when nothing is chained or the dep predates the sidecar.
    Map<String, List<String>> depSupers = new HashMap<>();
    // ⟨the superclass split⟩ The dep types whose sidecar carried the `@superclass` marker, and their
    // superclass where they have one other than java/lang/Object. A type in `depSupers` but NOT in
    // `depSplitKnown` came from a sidecar written before the marker existed: its kinds are unknown and
    // `Cha.resolutionOrder` keeps the depth-ordered behaviour that shipped, rather than guessing. Membership
    // of `depSplitKnown` with no `depSuperclass` entry is a FACT — every listed supertype is an interface.
    Set<String> depSplitKnown = new HashSet<>();
    Map<String, String> depSuperclass = new HashMap<>();
    // The SHA-256 of each class's bytes AS READ, keyed by internal name — the refresh cache's per-class
    // key. Filled by the loader at the one point where bytes exist, because after ASM has parsed them
    // the bytes are gone and only a re-read could recover them. CONTENT, never mtime: a wrong hit here
    // does not self-correct the way the Stop-hook's mtime skip does.
    Map<String, String> classHash = new HashMap<>();
    /** Memo for {@link Literals#literalFixpoint} over the LIVE scan graph, keyed by the identity of the
     *  `*Direct` map it propagates. MEASURED (JFR, uflexi): literalFixpoint is the hottest frame of a
     *  warm gate run — six of these fixpoints (hosts, cmds, paths, tables, blind, surfaceIncomplete) run
     *  over the whole call graph, and the report path and the gate path each computed their own set, so
     *  a `--json --policy` run did all twelve. Identity-keyed because the inputs are the context's own
     *  accumulators, and they are finished before any of this runs. */
    Map<Map<String, TreeSet<String>>, Map<String, TreeSet<String>>> literalFixpointMemo = new IdentityHashMap<>();
    List<PolicyRule.Deny> denyRules = new ArrayList<>();               // CANDOR_POLICY deny/pure (AS-EFF-006)
    List<PolicyRule.Allow> allowRules = new ArrayList<>();             // CANDOR_POLICY allow (AS-EFF-008)
    List<PolicyRule.Forbid> forbidRules = new ArrayList<>();           // CANDOR_POLICY forbid (AS-EFF-009)
    // ⟨0.29⟩ CANDOR_POLICY `only` (AS-EFF-011) — the PERMISSION form. Its own list, not folded into
    // `forbidRules`, because the two read OPPOSITE ways: a `forbid` names what must not happen, an `only`
    // names the complete set of what may, so a route handling one as the other inverts the verdict.
    List<PolicyRule.Only> onlyRules = new ArrayList<>();

    // ---- THE REFRESH OVERLAY (the report-refresh cache; candor/BACKLOG.md "a cheap report REFRESH") ----
    //
    // The refresh needs, for one class, exactly what that class's `analyze` WROTE — its delta — so the
    // delta can be cached against the class's content hash and replayed instead of recomputed. The
    // measurement says that is the work worth caching: parse+analyze is ~90% of a scan on every target
    // measured, while the fixpoint is 1.3–3.4% and the whole-program indexes ~37 ms, so the closure and
    // the indexes are simply recomputed each run and only the per-class work is cached.
    //
    // THE HAZARD, AND WHY THE DEFAULT IS INVERTED. Capturing a delta means dividing ~70 accumulators
    // into "shared inputs" and "per-class outputs". Getting ONE output wrong in the shared direction
    // means its writes land in the master during the priming run, never enter the delta, and vanish on
    // every refresh after it — a silent under-report, inside a report that looks entirely normal. That
    // is this project's cardinal sin, and no amount of care makes a 70-way hand classification safe.
    //
    // So the classification is not a list anyone has to maintain. A field is an OUTPUT unless it is
    // explicitly named as an input, and that naming is carried by `final` vs non-`final`:
    //
    //   non-final  →  INPUT/MEMO. The overlay is pointed at the MASTER's object, so analyze reads (and
    //                 memoizes into) the real whole-program state. Assigned in the overlay constructor.
    //   final      →  OUTPUT. Its initialiser runs, so the overlay gets a FRESH empty collection, and
    //                 whatever analyze leaves there IS this class's delta. Folded by {@link #mergeInto}.
    //
    // ALL THREE WAYS OF GETTING IT WRONG NOW FAIL LOUDLY, which is the whole reason for inverting it:
    //
    //   · an INPUT left final      → the overlay hands analyze an EMPTY index, the analysis changes, and
    //                                the cold arm of bin/refresh-equiv.sh fails on the spot.
    //   · an OUTPUT made non-final → its writes reach the master DURING analyze instead of through the
    //                                merge, which {@link #assertNoInputGrowth} detects directly.
    //   · a NEW field of any kind  → defaults to final, i.e. to OUTPUT, i.e. to being carried in the
    //                                delta. A field nobody thought about is merged, never dropped.
    //
    // The remaining case — an output whose TYPE the reflective merge does not recognise — refuses to
    // merge rather than skipping it, and the caller abandons the incremental path for a full scan.

    /** The ordinary per-scan context. */
    AnalysisContext() {}

    /** An OVERLAY over {@code master} for analysing ONE class: every input and memo is the master's own
     *  object (so analyze sees the whole program, and memoizes once globally rather than per class),
     *  while every accumulator is freshly empty — so what lands in it is exactly this class's delta. */
    AnalysisContext(AnalysisContext master) {
        crossDeps = master.crossDeps;                       depFnsByOwner = master.depFnsByOwner;
        depFnsByOwnerName = master.depFnsByOwnerName;       depOwnersBySig = master.depOwnersBySig;
        depOwnersBySigBuilt = master.depOwnersBySigBuilt;   unknownAliases = master.unknownAliases;
        netPartners = master.netPartners;                   suppressibleStreamFields = master.suppressibleStreamFields;
        provFramesCache = master.provFramesCache;           ALL = master.ALL;
        byName = master.byName;                             projectClasses = master.projectClasses;
        repoTypes = master.repoTypes;                       entityTables = master.entityTables;
        repoTables = master.repoTables;                     feignTypes = master.feignTypes;
        httpClientTypes = master.httpClientTypes;           subtypeIndex = master.subtypeIndex;
        fieldLambdaBindings = master.fieldLambdaBindings;
        overloadDescs = master.overloadDescs;               classesWithClinit = master.classesWithClinit;
        depCoveredPkgs = master.depCoveredPkgs;             depChainedPkgs = master.depChainedPkgs;
        depCallsByFn = master.depCallsByFn;                 depWhyByFn = master.depWhyByFn;
        depSupers = master.depSupers;                       depSplitKnown = master.depSplitKnown;
        depSuperclass = master.depSuperclass;               classHash = master.classHash;
        literalFixpointMemo = master.literalFixpointMemo;
        denyRules = master.denyRules;
        allowRules = master.allowRules;                     forbidRules = master.forbidRules;
        onlyRules = master.onlyRules;                       excluded = master.excluded;
        archives = master.archives;                         sourceFiles = master.sourceFiles;
        classpathRoots = master.classpathRoots;
        unanalyzed = master.unanalyzed;                     peekedClasses = master.peekedClasses;
        transSupersCache = master.transSupersCache;         chaTargetsCache = master.chaTargetsCache;
        annoMetaCache = master.annoMetaCache;               sealedClosedMemo = master.sealedClosedMemo;
        sealedUnseenMemo = master.sealedUnseenMemo;         externalSupersCache = master.externalSupersCache;
        resolutionOrderCache = master.resolutionOrderCache; depTransWhyMemo = master.depTransWhyMemo;
        // Scalars — read by analyze, never an output of it.
        taintEnabled = master.taintEnabled;                 unknownRatchet = master.unknownRatchet;
        closedWorld = master.closedWorld;                   peekVersioned = master.peekVersioned;
        scanRoot = master.scanRoot;                         vocabularySource = master.vocabularySource;
        netPartnersSource = master.netPartnersSource;       depReportsRead = master.depReportsRead;
        outOfScope = master.outOfScope;                     scannedUnder = master.scannedUnder;
    }

    /** The accumulator fields: every {@code final} instance field, i.e. everything the overlay
     *  constructor did NOT point at the master. The inversion above means this set grows by itself when
     *  someone adds a field, which is exactly the maintenance burden it exists to remove.
     *
     *  <p>AN EMPTY ANSWER IS A BROKEN INSTRUMENT, NOT AN EMPTY DELTA — and it MUST NOT be allowed to
     *  read as one. {@code getDeclaredFields()} does not fail when reflection is unavailable; it returns
     *  a ZERO-LENGTH ARRAY. In a GraalVM native image a class with no reflection metadata answers
     *  exactly that (MEASURED on GraalVM CE 21.0.2: 5 fields on the JVM, 0 in the image, no exception),
     *  so {@link #mergeInto}'s loop ran zero times, every class's delta was dropped on the floor, and
     *  the binary reported "0 functions reach effects" over a tree the jar found 210 in — a false
     *  all-clear, exit 0, with nothing on stderr. That shipped as far as the release's parity gate,
     *  which is the only thing that caught it (candor-java v0.32.0 native.yml).
     *
     *  <p>The type-refusal in {@code mergeInto} covers an accumulator whose TYPE is unrecognised; it
     *  cannot cover an accumulator that was never enumerated, because a loop over nothing throws
     *  nothing. This class demonstrably HAS final accumulators, so zero of them means the enumeration
     *  itself failed — and the delta merge is load-bearing for every effect the scan reports. */
    static java.lang.reflect.Field[] outputFields() {
        if (OUTPUTS == null) {
            List<java.lang.reflect.Field> fs = new ArrayList<>();
            for (var f : AnalysisContext.class.getDeclaredFields()) {
                int m = f.getModifiers();
                if (java.lang.reflect.Modifier.isStatic(m) || !java.lang.reflect.Modifier.isFinal(m)) continue;
                f.setAccessible(true);
                fs.add(f);
            }
            if (fs.isEmpty()) throw new UnmergeableDelta(
                    "AnalysisContext.class.getDeclaredFields() returned NOTHING, so the per-class delta merge "
                    + "would fold nothing and every effect this scan found would be silently discarded. "
                    + "This build cannot analyse anything and must not answer. Cause: reflection metadata is "
                    + "missing — in a GraalVM native image, register io.poly.candor.AnalysisContext with "
                    + "\"allDeclaredFields\": true (src/main/resources/META-INF/native-image/io.poly.candor/"
                    + "candor-java/reflect-config.json) and rebuild; see docs/native-image.md.");
            OUTPUTS = fs.toArray(new java.lang.reflect.Field[0]);
        }
        return OUTPUTS;
    }
    private static java.lang.reflect.Field[] OUTPUTS;

    /** Raised when a delta cannot be folded faithfully. Never handled narrowly: the caller abandons the
     *  incremental path and runs a full scan, because a partial merge IS a silent under-report. */
    static final class UnmergeableDelta extends RuntimeException {
        private static final long serialVersionUID = 1L;
        UnmergeableDelta(String m) { super(m); }
    }

    /** Fold this overlay's accumulators into {@code master}, exactly as sequential in-place analysis
     *  would have accumulated them. Additive throughout — union for sets, per-key union for maps of
     *  sets, SUM for the κ counters — so folding the per-class deltas in class order reproduces the
     *  monolithic pass rather than approximating it.
     *
     *  <p>Refuses, rather than guesses, on a field type it does not recognise: a merge that quietly
     *  skipped an unfamiliar accumulator would drop that accumulator on every refresh. */
    @SuppressWarnings("unchecked")
    void mergeInto(AnalysisContext master) {
        // The lazily-built dep index is guarded by a flag this overlay may have flipped; carry it back,
        // or the next class rebuilds what is already sitting in the (shared) map.
        master.depOwnersBySigBuilt |= this.depOwnersBySigBuilt;
        for (var f : outputFields()) {
            Object mine, theirs;
            try { mine = f.get(this); theirs = f.get(master); }
            catch (IllegalAccessException e) { throw new UnmergeableDelta(f.getName() + ": " + e); }
            if (mine == null) continue;
            if (mine instanceof Map<?, ?> src) {
                if (src.isEmpty()) continue;
                Map<Object, Object> dst = (Map<Object, Object>) theirs;
                for (var e : ((Map<Object, Object>) mine).entrySet()) foldValue(f, dst, e.getKey(), e.getValue());
            } else if (mine instanceof Collection<?> src) {
                if (src.isEmpty()) continue;
                ((Collection<Object>) theirs).addAll((Collection<Object>) mine);
            } else {
                throw new UnmergeableDelta("accumulator '" + f.getName() + "' is a "
                        + mine.getClass().getName() + ", which the refresh merge cannot fold");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void foldValue(java.lang.reflect.Field f, Map<Object, Object> dst, Object k, Object v) {
        Object cur = dst.get(k);
        if (cur == null) { dst.put(k, v); return; }
        if (v instanceof EffectSet a && cur instanceof EffectSet b) { b.addAll(a); return; }
        if (v instanceof Collection<?> && cur instanceof Collection<?>) {
            ((Collection<Object>) cur).addAll((Collection<Object>) v); return;
        }
        // The κ ledger counts REACHES, so two classes reaching the same package must ADD. A `put` here
        // would keep one class's count and discard the other's — and that sum is what the pinned
        // scan-completeness threshold reads, so the loss would move a published number.
        if (v instanceof Integer a && cur instanceof Integer b) { dst.put(k, a + b); return; }
        if (v instanceof String || v instanceof String[]) { dst.put(k, v); return; }  // per-method key, no contention
        throw new UnmergeableDelta("accumulator '" + f.getName() + "' holds a "
                + v.getClass().getName() + " value, which the refresh merge cannot fold");
    }

    /** The memos: shared state that legitimately GROWS during analyze, because caching a pure function
     *  of the (fixed) hierarchy is the whole reason they are shared. Everything else non-final is an
     *  input and must hold still — see {@link #assertNoInputGrowth}. */
    private static final Set<String> MEMOS = Set.of(
            "transSupersCache", "chaTargetsCache", "annoMetaCache", "sealedClosedMemo",
            "sealedUnseenMemo", "externalSupersCache", "resolutionOrderCache", "depTransWhyMemo",
            "provFramesCache", "depOwnersBySig", "literalFixpointMemo");

    /** Sizes of the shared inputs, for {@link #assertNoInputGrowth}.
     *
     *  <p>Derived by reflection from the same fact the overlay constructor uses — non-final means shared
     *  — rather than from a hand-written list. A hand-written list would cover only the fields someone
     *  remembered, and the field most likely to be missing from it is precisely the one just misfiled:
     *  the check would then be blindest exactly where it is needed. Anything non-final and not a memo is
     *  included automatically, so misfiling an accumulator as shared enrols it in its own detection. */
    java.util.List<Integer> inputSizes() {
        java.util.List<Integer> out = new ArrayList<>();
        for (var f : AnalysisContext.class.getDeclaredFields()) {
            int m = f.getModifiers();
            if (java.lang.reflect.Modifier.isStatic(m) || java.lang.reflect.Modifier.isFinal(m)) continue;
            if (MEMOS.contains(f.getName())) continue;
            f.setAccessible(true);
            Object o;
            try { o = f.get(this); } catch (IllegalAccessException e) { throw new UnmergeableDelta(f.getName() + ": " + e); }
            out.add(o instanceof Map<?, ?> mm ? mm.size() : o instanceof Collection<?> c ? c.size() : -1);
        }
        return out;
    }

    /** Field names in {@link #inputSizes} order, so a growth report can NAME the misfiled field instead
     *  of printing a slot number at whoever has to fix it. */
    static java.util.List<String> inputNames() {
        java.util.List<String> out = new ArrayList<>();
        for (var f : AnalysisContext.class.getDeclaredFields()) {
            int m = f.getModifiers();
            if (java.lang.reflect.Modifier.isStatic(m) || java.lang.reflect.Modifier.isFinal(m)) continue;
            if (MEMOS.contains(f.getName())) continue;
            out.add(f.getName());
        }
        return out;
    }

    /** THE CHECK THAT CATCHES THE DANGEROUS MISCLASSIFICATION. An accumulator wrongly named as a shared
     *  input writes straight into the master during analyze: right on the priming run, and missing from
     *  every delta after it — the one error the cold byte-equality arm cannot see, precisely because the
     *  priming run gets the right answer. The inputs proper are all fixed before the analyze loop
     *  starts, so ANY growth across it means a field is on the wrong side of the split.
     *
     *  <p>Verification only (CANDOR_REFRESH_VERIFY), and it throws rather than warns. */
    static void assertNoInputGrowth(java.util.List<Integer> before, java.util.List<Integer> after) {
        java.util.List<String> names = inputNames();
        for (int i = 0; i < before.size(); i++) {
            if (!before.get(i).equals(after.get(i)))
                throw new UnmergeableDelta("the shared INPUT '" + names.get(i) + "' grew during analyze ("
                        + before.get(i) + " -> " + after.get(i) + "): it is an accumulator on the wrong "
                        + "side of the refresh split. Its writes reach the master directly, so they are "
                        + "absent from every per-class delta and would be lost on every refresh. Make it "
                        + "final (an output), or add it to MEMOS if growing is genuinely its job.");
        }
    }
}
