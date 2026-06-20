package io.poly.candor;

import java.util.*;
import org.objectweb.asm.tree.*;
import io.poly.candor.model.*;

/** The engine's shared analysis state — the mutable accumulators a scan fills (effect/edge/literal
 *  maps, the call graph, the CHA/overload indices, the κ-ledger, the deferred-lambda + functional-param
 *  forwarding bookkeeping) plus the DepFn cross-dependency record. EXTRACTED verbatim from Candor.java
 *  (refactor P6); re-exposed to every engine class as bare names via
 *  `import static io.poly.candor.AnalysisState.*`. Candor.resetState() clears these between scans. The
 *  static-global model is unchanged — it is now NAMED + centralized rather than declared inline in the
 *  6.5k-line monolith. Spec-vocabulary + Spring-marker CONSTANTS stay in Candor. See REFACTOR_PLAN.md. */
final class AnalysisState {
    static final Map<String, EffectSet> direct = new HashMap<>();
    static final Map<String, Set<String>> edges = new HashMap<>();
    static final Map<String, String> loc = new HashMap<>();
    static final Map<String, String> hashOf = new HashMap<>();           // fn -> stable method-ref hash (owner.name+desc)
    static final Map<String, EffectSet> viaCross = new HashMap<>();// fn -> effects inherited from a dependency report
    /** One chained dependency function (CANDOR_DEPS): effects + the four literal surfaces — the
     *  spec (§2) says a consumer inherits BOTH (effects alone made every chained `allow Db` fail
     *  the new lits=∅ branch with an empty surface no rule could cover — /code-review). */
    static class DepFn {
        EffectSet effects = EffectSet.empty();
        List<String> hosts = new ArrayList<>(), cmds = new ArrayList<>(),
                paths = new ArrayList<>(), tables = new ArrayList<>();
    }
    static final Map<String, DepFn> crossDeps = new HashMap<>();  // method-ref hash -> DepFn (from CANDOR_DEPS)
    static final Map<String, TreeSet<String>> fsDirect = new HashMap<>();// fn -> Fs read/write kind performed directly
    static final Map<String, TreeSet<UnknownReason>> unknownWhy = new HashMap<>();// fn -> why Unknown was emitted directly (native:/reflect:/dispatch:)
    static final Set<String> entryPoints = new HashSet<>(); // framework-invoked methods
    static final Set<String> projectClasses = new HashSet<>();
    static final Set<String> repoTypes = new HashSet<>();    // Spring Data repository interfaces (internal names)
    // JPA's declarative tables: @Table(name="users") on an entity names its table (LITERAL name attr
    // only — a bare @Entity's default is naming-strategy-dependent, so it contributes nothing, never a
    // guess); a repository's generic signature names its entity. Together a Spring-Data call carries
    // its table into the `tables` surface with no SQL string anywhere — the same declarative move as
    // the TS engine's @Entity decorators (JPA apps are THE Db-heavy JVM shape with no SQL literals).
    static final Map<String, String> entityTables = new HashMap<>(); // entity internal name -> table
    static final Map<String, String> repoTables = new HashMap<>();   // repository internal name -> table
    static final Set<String> feignTypes = new HashSet<>();   // @FeignClient interfaces (internal names)
    static List<ClassNode> ALL = List.of();                  // all loaded classes (for CHA)
    static final Map<String, ClassNode> byName = new HashMap<>();      // internal name -> node
    static final Map<String, Set<String>> transSupersCache = new HashMap<>();
    /** Reverse-subtype index for CHA: owner internal name -> loaded classes that are owner-or-a-subtype
     *  (the transitive subclasses + interface implementors). Built ONCE after load, before analyze, so
     *  chaTargets() consults O(subtypes-of-owner) candidates instead of scanning ALL classes per call
     *  site — collapsing the old O(call-sites × all-classes) quadratic. Membership is exactly the old
     *  per-class predicate `c.name == owner || transSupers(c.name).contains(owner)`, inverted. */
    static final Map<String, List<String>> subtypeIndex = new HashMap<>();
    /** Overload index: `dottedClass.methodName` -> the set of distinct JVM descriptors declared under
     *  that name in that class. A report/edge node is keyed `class.method` (descriptor-LESS); when a
     *  name has MORE THAN ONE descriptor here the overloads would collapse into one node whose effects
     *  are the UNION of every overload — a PURE `hmac(byte[])` inheriting an effectful `hmac(File)`'s
     *  Fs (commons-codec, the cardinal sin: a pure byte[] HMAC reported as a filesystem read). So an
     *  OVERLOADED name gets a readable param-type suffix (`hmac(byte[])`) appended to its id at EVERY
     *  build/lookup site; a UNIQUE name keeps the bare `class.method` — so non-overloaded methods (incl.
     *  every conformance fixture, matched by leaf name) are byte-for-byte unchanged. */
    static final Map<String, Set<String>> overloadDescs = new HashMap<>();
    static final Set<String> classesWithClinit = new HashSet<>(); // project classes with a `<clinit>`
    static boolean taintEnabled = false;             // CANDOR_TAINT — run the intraprocedural taint pass
    // fn -> injection-class effects performed on a parameter-derived (caller-controlled) argument.
    static final Map<String, EffectSet> tainted = new HashMap<>();
    static final Map<String, TreeSet<String>> hostsDirect = new HashMap<>(); // fn -> literal Net endpoints
    static final Map<String, TreeSet<String>> cmdsDirect = new HashMap<>();  // fn -> literal Exec commands
    static final Map<String, TreeSet<String>> pathsDirect = new HashMap<>(); // fn -> literal Fs paths
    static final Map<String, TreeSet<String>> tablesDirect = new HashMap<>(); // fn -> literal Db tables
    // fn -> the set of effects whose literal SURFACE is INCOMPLETE: the method has a reach for that effect
    // whose endpoint is structurally invisible (a host-less Net owner like gRPC/WebSocket, or a host-
    // establishing Net call with a RUNTIME string host). The AS-EFF-008 gate treats an incomplete surface
    // as uncertifiable EVEN when other (benign) literals are present — else a benign literal MASKS the
    // invisible forbidden endpoint (a gate evasion; the empty-surface failsafe alone is per-method, missing
    // the partial case). Propagated transitively like the literal surfaces.
    static final Map<String, TreeSet<String>> surfaceIncomplete = new HashMap<>();
    // The κ-coverage ledger (the Rust/TS move): external packages this code calls where the
    // classifier never fires are INVISIBLE, not Unknown — counted here, named in the receipt.
    static final Map<String, Integer> kappaSeen = new TreeMap<>();      // external package -> call count
    // fn -> the external packages it DIRECTLY calls into where the classifier FLOORED the call (returned
    // pure). Post-filtered to the genuinely-blind packages (κ never fired anywhere) + propagated transitively
    // → the per-method `invisible` disclosure: a method's effect set is reported HONESTLY (it carries the
    // packages candor couldn't see through, so a `pure`/partial effect set is never an unqualified claim).
    static final Map<String, TreeSet<String>> blindDirect = new HashMap<>();
    // reflective calls with a LITERAL method name in the same body (`getMethod("x")` … `invoke`):
    // the literal names the target, so a unique project match gets an EDGE alongside the honest
    // Unknown (the density review's JVM slice — recall without guessing).
    static final List<String[]> reflectPairs = new ArrayList<>();        // [callerId, literalName]
    static final Set<String> kappaClassified = new HashSet<>();         // packages with >=1 classification
    // Packages a CANDOR_DEPS sibling report covers: chained, not blind — even a call that joins
    // nothing (the dep fn is pure and omitted) is the report's honest purity claim.
    static final Set<String> depCoveredPkgs = new HashSet<>();
    // TRUE-FORWARDING for deferred-execution containers (`by lazy`, ThreadLocal.withInitial, …). A
    // deferred lambda stored in a FIELD and FORCED at a getter/reader otherwise reads silent-pure — the
    // effect is charged only to the constructor (the lambda-construction over-approximation) and the
    // lambda body, NOT the forcing site (the read that actually RUNS it). We bind, per field, the
    // lambda(s) stored into a recognised container when that field is assigned in `<init>`/`<clinit>`,
    // then at a FORCING call site (the container's value-getter, on a receiver that is a GET* of a bound
    // field — possibly in ANOTHER class) edge the enclosing method to those lambdas. The existing effect
    // propagation then carries the lambda's REAL effect to the forcing method. FIELD-SCOPED (key includes
    // the field), so a pure-init lazy contributes nothing and stays pure — this is what prevents flooding.
    // Key form: `internalOwner/fieldName:fieldDesc` (e.g. `Holder/data$delegate:Lkotlin/Lazy;`).
    static final Map<String, Set<String>> deferredFieldLambdas = new HashMap<>(); // field-key -> lambda body ids
    static final List<String[]> deferredForcePairs = new ArrayList<>();           // [callerId, field-key]
    // PRIVATE FUNCTIONAL-PARAM FORWARDING. A `private` method that invokes its single functional-interface
    // parameter is a CLOSED sink: a private method's call sites are all nestmates (the same top-level class
    // candor analyses), so the set of values that can reach the param is FULLY ENUMERABLE. When every call
    // site passes a fresh lambda/method-ref whose body is a project method, the param's SAM resolves EXACTLY
    // to those bodies — no callback: Unknown. This collapses the common "private helper invoked only with
    // inline lambdas" smear (jsoup Tag.setupTags(String[], Consumer): 6 <clinit> call sites, all pure
    // lambdas — its callback Unknown propagated to every function that touches Tag via the <clinit> trigger).
    // SOUND BY CONSTRUCTION: edging the sink to the collected lambdas can only ADD their (real) effects; the
    // Unknown is suppressed ONLY when the sink is a candidate (the param is its lone value of that functional
    // type — see isForwardableFunctionalSink) AND no call site passed an unresolvable arg (fwdSinkOpaque).
    static final Map<String, Set<String>> fwdSinkLambdas = new HashMap<>(); // sink id -> project lambda bodies passed at its call sites
    static final Set<String> fwdSinkOpaque = new HashSet<>();               // sink id with >=1 call site passing a non-lambda arg
    static final Set<String> fwdSinkPending = new HashSet<>();              // sink id whose param-SAM Unknown was DEFERRED (suppress unless restored)
    static final Map<String, String[]> fwdSinkPendingWhy = new HashMap<>();  // sink id -> [unknownWhy string] to RESTORE if not resolvable
}
