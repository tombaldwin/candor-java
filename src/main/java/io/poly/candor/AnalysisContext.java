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
    final Map<String, DepFn> crossDeps = new HashMap<>();          // method-ref hash -> DepFn (from CANDOR_DEPS)
    // Memoized `crossDeps` grouped by declaring type (internal name) — the hand-off join has no descriptor
    // to key on (see Candor#depFnsOfType), and scanning every hash per site would be quadratic.
    final Map<String, List<DepFn>> depFnsByOwner = new HashMap<>();
    // Memoized `crossDeps` grouped by declaring type AND member name ("owner.name" -> desc -> DepFn). The
    // by-NAME reentry contracts (compareTo/append/write/read) resolve over ANY descriptor, so there is no
    // single hash to key on; the DESCRIPTOR is kept because per-overload shadowing decides which of a
    // dependency's same-named methods a project override actually replaces (Candor#nearestDepFnsNamed).
    final Map<String, Map<String, DepFn>> depFnsByOwnerName = new HashMap<>();
    // `crossDeps` inverted by SIGNATURE (`name+desc` -> the dep owners declaring an EFFECTFUL body with
    // it) — the evidence the untyped-dep-receiver disclosure needs (Candor#untypedDepReceiver). Built
    // once, lazily, on the first interface dispatch that gets that far; empty when nothing is chained.
    final Map<String, Set<String>> depOwnersBySig = new HashMap<>();
    boolean depOwnersBySigBuilt = false;
    final Map<String, TreeSet<String>> fsDirect = new HashMap<>(); // fn -> Fs read/write kind performed directly
    final Map<String, TreeSet<UnknownReason>> unknownWhy = new HashMap<>(); // fn -> why Unknown emitted directly
    // VALUE-PROVENANCE Phase 2: instance stream fields ("owner#name") PROVEN bound only to in-scope concrete
    // opens across the whole program — so a stream-consuming read of one is pure-relative and the Phase-1
    // Unknown is suppressed. Computed once in a pre-pass; empty unless a field is provably all-concrete
    // (conservative: any doubt leaves it out, keeping the sound Phase-1 disclosure).
    final Set<String> suppressibleStreamFields = new HashSet<>();
    // Provenance frames the Phase-2 pre-pass computed, handed to the main analyze pass so a stream-touching
    // method's ASM dataflow is not re-run (consume-once: provFrames removes on read). Bounded to the few
    // stream-relevant methods the pre-pass visits; freed as the main pass consumes each.
    final Map<String, Frame<Interp.ProvValue>[]> provFramesCache = new HashMap<>();
    // ⟨0.19⟩ user-defined reason-class aliases from `.candor/config` (`unknown-alias <name> = <class,…>`),
    // consulted by the §6.2 deny parser for an `Unknown[<name>]` filter. Populated before parsePolicy.
    final Map<String, Set<ReasonClass>> unknownAliases = new HashMap<>();
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
    final Set<String> netPartners = new HashSet<>();
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
    final java.util.LinkedHashMap<String, String> unanalyzed = new java.util.LinkedHashMap<>();
    // ⟨0.29⟩ THE SCOPE (candor-spec/FILE-SET-DESIGN.md): what the walk chose not to OPEN — as opposed to
    // `unanalyzed` above, which is what it opened and could not read. A consumer cannot tell those two
    // apart from `analyzed.count` alone, because the denominator is this engine's file selector and the
    // selector is invisible. Recorded AT THE SKIP (Loader#collectClasses) plus the source sweep, which
    // cannot run earlier because "has this source got a compiled class?" needs the analyzed set. path →
    // class token; disclosed as a COUNT per class, never a file list.
    final java.util.LinkedHashMap<String, String> excluded = new java.util.LinkedHashMap<>();
    // ⟨0.29⟩ the ARCHIVES the walk passed over. A directory walk filters `.class`, so a `.jar` under the
    // scan root (`build/libs/app.jar`, a vendored `libs/*.jar`) is bytecode this engine reads perfectly
    // well and never opened. THE PEEK's target: `load()` already reads a jar, so peeking one is this
    // engine's own entry point over a different file rather than a second pass.
    final java.util.List<java.nio.file.Path> archives = new java.util.ArrayList<>();
    // ⟨0.29⟩ JVM-language SOURCE seen during the walk, as `path\0package` (package empty when undeclared).
    // The java arm of the ⟨0.29⟩ measurement is a source whose class was never built: candor-java reads
    // BYTECODE, so such a file is invisible to it and to the peek alike.
    final java.util.List<String> sourceFiles = new java.util.ArrayList<>();
    // ⟨0.29⟩ what this scan was pointed AT — so the scope block and the peek's findings can name a file
    // the way the operator does. An absolute path in a report says where the CI runner's checkout was.
    java.nio.file.Path scanRoot;
    // ⟨0.29⟩ what THE PEEK found: an effect the policy DENIES, in a file the gate did not judge. Its own
    // kind, never a violation — it moves no verdict. Null when no policy was configured (nothing asked).
    java.util.List<Report.OutOfScope> outOfScope = null;
    // ⟨0.29⟩ the exclusion classes THE PEEK ACTUALLY READ this run. `excluded[].peeked` is derived from
    // this rather than from a per-class table, so a peek that never ran, or one whose files could not be
    // opened, cannot publish `peeked: true` beside an empty `outOfScope` — which would be byte-identical
    // to a clean peek and is the overclaim the flag exists to prevent.
    final Set<String> peekedClasses = new HashSet<>();
    final Set<String> entryPoints = new HashSet<>();               // framework-invoked methods
    final Set<String> projectClasses = new HashSet<>();
    final Set<String> repoTypes = new HashSet<>();                 // Spring Data repository interfaces (internal names)
    // JPA's declarative tables: @Table(name="users") names a table (LITERAL name attr only); a repo's
    // generic signature names its entity. Together a Spring-Data call carries its table into `tables`.
    final Map<String, String> entityTables = new HashMap<>();      // entity internal name -> table
    final Map<String, String> repoTables = new HashMap<>();        // repository internal name -> table
    final Set<String> feignTypes = new HashSet<>();                // @FeignClient interfaces (internal names)
    final Set<String> httpClientTypes = new HashSet<>();           // declarative HTTP-client interfaces -> Net
    List<ClassNode> ALL = List.of();                               // all loaded classes (for CHA)
    final Map<String, ClassNode> byName = new HashMap<>();         // internal name -> node
    final Map<String, Set<String>> transSupersCache = new HashMap<>();
    /** Reverse-subtype index for CHA: owner -> loaded classes that are owner-or-a-subtype. Built once
     *  after load so chaTargets() consults O(subtypes-of-owner) candidates, not ALL classes per call. */
    final Map<String, List<String>> subtypeIndex = new HashMap<>();
    /** Memoized chaTargets(owner,name,desc) results. chaTargets is a PURE function of the (post-load,
     *  fixed) class hierarchy — the same call-key recurs across the many call sites that invoke a method
     *  on a given declared type — so caching collapses the analyze pass's dominant super-linear cost
     *  (CHA fan-out × super-walk, re-done per call site). Immutable values → safe to share. */
    final Map<String, List<String>> chaTargetsCache = new HashMap<>();
    /** Overload index: `dottedClass.methodName` -> the distinct JVM descriptors declared under that name,
     *  so an overloaded node gets a param-type suffix and a pure overload never unions an effectful one. */
    final Map<String, Set<String>> overloadDescs = new HashMap<>();
    final Set<String> classesWithClinit = new HashSet<>();         // project classes with a `<clinit>`
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
    final Set<String> depCoveredPkgs = new HashSet<>();
    // Packages a CANDOR_DEPS report was CHAINED for, trusted or not. Deliberately NOT trust-gated: it
    // answers "was a report configured for this package", a fact no version check unsettles, and it is
    // used only as the anti-flood conjunct of the untyped-receiver disclosure
    // ({@link Candor#untypedDepReceiver}) — never as an authority for silence. Gating it on trust cost 2
    // disclosed Unknowns on logback-classic (`ContextInitializer.printConfiguratorOrder` went
    // ['Unknown'] -> []) with no `invisible` to replace them, because `ch.qos.logback` is a κ-CURATED
    // covered prefix so the ledger is silent there either way. See StaleDepTrustTest.
    final Set<String> depChainedPkgs = new HashSet<>();
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
    final Map<String, List<String>> depCallsByFn = new HashMap<>();
    final Map<String, List<String>> depWhyByFn = new HashMap<>();
    final Map<String, List<String>> depTransWhyMemo = new HashMap<>();
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
    final Map<String, List<AnnotationNode>> annoMetaCache = new HashMap<>(); // meta/composed-annotation resolution cache
    final Map<String, Boolean> sealedClosedMemo = new HashMap<>();           // Cha: sealed-closure verdict memo
    final Map<String, Boolean> sealedUnseenMemo = new HashMap<>();           // Cha: sealed-permit-unseen memo
    final Map<String, Cha.ExtSupers> externalSupersCache = new HashMap<>();  // Cha: external-class supers (classpath) cache
    // Cha: memoized JVM METHOD-RESOLUTION ORDER per type (superclass chain first, then interfaces —
    // see Cha#resolutionOrder). Keyed by `P\t`/`D\t` + internal name, the two `useDepHierarchy` arms.
    final Map<String, List<String>> resolutionOrderCache = new HashMap<>();
    // A CHAINED dependency's own class hierarchy, read from the `<report>.hierarchy.json` sidecar every
    // scan already writes (internal name -> direct supers + interfaces, internal names). A dep's classes
    // are not on candor's classpath, so `Cha.externalSupers` could not see them and every question about a
    // dep type's supertypes answered "no supers" — the blocker under the receiver-driven write/read
    // residual and the abstract-dep-CLASS row. Empty when nothing is chained or the dep predates the sidecar.
    final Map<String, List<String>> depSupers = new HashMap<>();
    // ⟨the superclass split⟩ The dep types whose sidecar carried the `@superclass` marker, and their
    // superclass where they have one other than java/lang/Object. A type in `depSupers` but NOT in
    // `depSplitKnown` came from a sidecar written before the marker existed: its kinds are unknown and
    // `Cha.resolutionOrder` keeps the depth-ordered behaviour that shipped, rather than guessing. Membership
    // of `depSplitKnown` with no `depSuperclass` entry is a FACT — every listed supertype is an interface.
    final Set<String> depSplitKnown = new HashSet<>();
    final Map<String, String> depSuperclass = new HashMap<>();
    final List<PolicyRule.Deny> denyRules = new ArrayList<>();               // CANDOR_POLICY deny/pure (AS-EFF-006)
    final List<PolicyRule.Allow> allowRules = new ArrayList<>();             // CANDOR_POLICY allow (AS-EFF-008)
    final List<PolicyRule.Forbid> forbidRules = new ArrayList<>();           // CANDOR_POLICY forbid (AS-EFF-009)
    // ⟨0.29⟩ CANDOR_POLICY `only` (AS-EFF-011) — the PERMISSION form. Its own list, not folded into
    // `forbidRules`, because the two read OPPOSITE ways: a `forbid` names what must not happen, an `only`
    // names the complete set of what may, so a route handling one as the other inverts the verdict.
    final List<PolicyRule.Only> onlyRules = new ArrayList<>();
}
