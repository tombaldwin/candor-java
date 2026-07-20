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
    // ⟨0.20⟩ project-declared partner hosts from `.candor/config` (`net-partner <host>`), consulted by the
    // Net destination-class classifier (Literals.netDestClass) to refine a visible host to `known-partner`.
    // Populated alongside unknownAliases (before parsePolicy / after runScan). Empty = telemetry-only asserts.
    final Set<String> netPartners = new HashSet<>();
    // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): the TARGET's own class files candor could NOT analyze — a .class
    // ASM couldn't parse (a future-major bytecode version, a corrupt entry). path → reason. Their effects are
    // absent NOT because pure but because never seen; carried into the report + the gate verdict (a gate over
    // skipped classes must fail closed, never green). LinkedHashMap: disclosure order = discovery order.
    final java.util.LinkedHashMap<String, String> unanalyzed = new java.util.LinkedHashMap<>();
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
    final Map<String, EffectSet> tainted = new HashMap<>();        // fn -> injection-class effects on caller-derived args
    final Map<String, TreeSet<String>> hostsDirect = new HashMap<>();  // fn -> literal Net endpoints
    final Map<String, TreeSet<String>> cmdsDirect = new HashMap<>();   // fn -> literal Exec commands
    final Map<String, TreeSet<String>> pathsDirect = new HashMap<>();  // fn -> literal Fs paths
    final Map<String, TreeSet<String>> tablesDirect = new HashMap<>(); // fn -> literal Db tables
    // fn -> effects whose literal SURFACE is INCOMPLETE (a structurally-invisible reach); fail-closed so a
    // benign visible literal can't MASK an invisible forbidden endpoint. Propagated like the literal surfaces.
    final Map<String, TreeSet<String>> surfaceIncomplete = new HashMap<>();
    // The κ-coverage ledger: external packages this code calls where the classifier never fires are
    // INVISIBLE, not Unknown — counted here, named in the receipt.
    final Map<String, Integer> kappaSeen = new TreeMap<>();        // external package -> call count
    // fn -> external packages it DIRECTLY calls into where κ floored the call; post-filtered to genuinely
    // blind packages + propagated transitively -> the per-method `invisible` disclosure.
    final Map<String, TreeSet<String>> blindDirect = new HashMap<>();
    // reflective calls with a LITERAL method name in the same body: a unique project match gets an EDGE
    // alongside the honest Unknown (recall without guessing).
    final List<String[]> reflectPairs = new ArrayList<>();         // [callerId, literalName]
    final Set<String> kappaClassified = new HashSet<>();           // packages with >=1 classification
    // Packages a CANDOR_DEPS sibling report covers: chained, not blind (even an omitted pure dep fn).
    final Set<String> depCoveredPkgs = new HashSet<>();
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
    final Map<String, List<String>> externalSupersCache = new HashMap<>();   // Cha: external-class supers (classpath) cache
    final List<PolicyRule.Deny> denyRules = new ArrayList<>();               // CANDOR_POLICY deny/pure (AS-EFF-006)
    final List<PolicyRule.Allow> allowRules = new ArrayList<>();             // CANDOR_POLICY allow (AS-EFF-008)
    final List<PolicyRule.Forbid> forbidRules = new ArrayList<>();           // CANDOR_POLICY forbid (AS-EFF-009)
}
