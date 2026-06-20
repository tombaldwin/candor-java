package io.poly.candor;

import java.util.*;
import org.objectweb.asm.tree.*;
import io.poly.candor.model.*;

/** The engine's per-scan analysis state — the mutable accumulators a scan fills (effect/edge/literal
 *  maps, the call graph, the CHA/overload indices, the κ-ledger, the deferred-lambda + functional-param
 *  forwarding bookkeeping). One INSTANCE per scan: a fresh {@code AnalysisContext} is a fresh slate, so
 *  no global clear is needed.
 *
 *  <p>LB-0: the fields moved here from {@code AnalysisState} (instance, no longer static); the engine
 *  reaches them through the {@link AnalysisState#ctx} handle ({@code ctx.direct} …). LB-1 removes that
 *  static handle and threads the context per scan, making the engine re-entrant. Spec-vocabulary +
 *  Spring-marker CONSTANTS stay in Candor. See docs/level-b-scoping.md. */
final class AnalysisContext {
    final Map<String, EffectSet> direct = new HashMap<>();
    final Map<String, Set<String>> edges = new HashMap<>();
    final Map<String, String> loc = new HashMap<>();
    final Map<String, String> hashOf = new HashMap<>();           // fn -> stable method-ref hash (owner.name+desc)
    final Map<String, EffectSet> viaCross = new HashMap<>();       // fn -> effects inherited from a dependency report
    final Map<String, DepFn> crossDeps = new HashMap<>();          // method-ref hash -> DepFn (from CANDOR_DEPS)
    final Map<String, TreeSet<String>> fsDirect = new HashMap<>(); // fn -> Fs read/write kind performed directly
    final Map<String, TreeSet<UnknownReason>> unknownWhy = new HashMap<>(); // fn -> why Unknown emitted directly
    final Set<String> entryPoints = new HashSet<>();               // framework-invoked methods
    final Set<String> projectClasses = new HashSet<>();
    final Set<String> repoTypes = new HashSet<>();                 // Spring Data repository interfaces (internal names)
    // JPA's declarative tables: @Table(name="users") names a table (LITERAL name attr only); a repo's
    // generic signature names its entity. Together a Spring-Data call carries its table into `tables`.
    final Map<String, String> entityTables = new HashMap<>();      // entity internal name -> table
    final Map<String, String> repoTables = new HashMap<>();        // repository internal name -> table
    final Set<String> feignTypes = new HashSet<>();                // @FeignClient interfaces (internal names)
    List<ClassNode> ALL = List.of();                               // all loaded classes (for CHA)
    final Map<String, ClassNode> byName = new HashMap<>();         // internal name -> node
    final Map<String, Set<String>> transSupersCache = new HashMap<>();
    /** Reverse-subtype index for CHA: owner -> loaded classes that are owner-or-a-subtype. Built once
     *  after load so chaTargets() consults O(subtypes-of-owner) candidates, not ALL classes per call. */
    final Map<String, List<String>> subtypeIndex = new HashMap<>();
    /** Overload index: `dottedClass.methodName` -> the distinct JVM descriptors declared under that name,
     *  so an overloaded node gets a param-type suffix and a pure overload never unions an effectful one. */
    final Map<String, Set<String>> overloadDescs = new HashMap<>();
    final Set<String> classesWithClinit = new HashSet<>();         // project classes with a `<clinit>`
    boolean taintEnabled = false;                                  // CANDOR_TAINT — run the intraprocedural taint pass
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
}
