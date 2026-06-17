package io.poly.candor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.Interpreter;
import org.objectweb.asm.tree.analysis.Value;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

/**
 * candor-java (prototype) — a candor-spec implementation for the JVM, via ASM bytecode.
 *
 * Resolves each call to its concrete target, classifies it, records per-method DIRECT effects +
 * call edges, then propagates to a transitive fixpoint. See https://github.com/tombaldwin/candor-spec.
 *
 * SPRING-AWARE: Spring hides effects in framework-woven/generated code (proxies for @Transactional,
 * synthesized Spring Data repositories) and breaks the call graph (reflective ingress). Pure bytecode
 * tracing misses all of it. So we read Spring's DECLARATIONS — annotations and template/repository
 * types — as effect sources. The framework's magic becomes the signal.
 *
 * TRUST CONTRACT (SPEC §4): what candor can't see is reported as `Unknown`, never assumed pure —
 * reflection / dynamic invocation, a `native` (JNI) body, and dispatch over a project interface/abstract
 * with no visible impl. CHA resolves interface/virtual dispatch over project types; constructors,
 * static initializers (`<clinit>`, via class-load trigger edges), and lambdas/method-refs all propagate
 * their effects. Conformance (CANDOR_STRICT) treats a bean's injected dependencies as its capabilities.
 * Residual gap (PRINCIPLES #7): dispatch over unrecognised non-project types is assumed pure (else
 * every `list.add()` floods) — known-effectful libraries are caught by the classifier.
 */
public class Candor {
    /** The candor-spec contract version this build implements (the report SCHEMA + AS-EFF codes),
     *  distinct from the engine build id (the report's `version`). Emitted as the envelope's `spec` so a
     *  consumer can see which contract a report conforms to; MUST match the Rust impl's
     *  `candor_report::SPEC_VERSION` and candor-spec's stated version (§2.1). */
    static final String SPEC_VERSION = "0.5";

    static final Map<String, TreeSet<String>> direct = new HashMap<>();
    static final Map<String, Set<String>> edges = new HashMap<>();
    static final Map<String, String> loc = new HashMap<>();
    static final Map<String, String> hashOf = new HashMap<>();           // fn -> stable method-ref hash (owner.name+desc)
    static final Map<String, TreeSet<String>> viaCross = new HashMap<>();// fn -> effects inherited from a dependency report
    /** One chained dependency function (CANDOR_DEPS): effects + the four literal surfaces — the
     *  spec (§2) says a consumer inherits BOTH (effects alone made every chained `allow Db` fail
     *  the new lits=∅ branch with an empty surface no rule could cover — /code-review). */
    static class DepFn {
        List<String> effects = new ArrayList<>();
        List<String> hosts = new ArrayList<>(), cmds = new ArrayList<>(),
                paths = new ArrayList<>(), tables = new ArrayList<>();
    }
    static final Map<String, DepFn> crossDeps = new HashMap<>();  // method-ref hash -> DepFn (from CANDOR_DEPS)
    static final Map<String, TreeSet<String>> fsDirect = new HashMap<>();// fn -> Fs read/write kind performed directly
    static final Map<String, TreeSet<String>> unknownWhy = new HashMap<>();// fn -> why Unknown was emitted directly (native:/reflect:/dispatch:)
    static final String FS_UNKNOWN = "?";   // Fs reached with no recorded kind (cross-jar) -> make no read/write claim
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

    // --- Spring markers (internal names / annotation-desc substrings) ---
    static final Set<String> REPO_MARKERS = Set.of(
            "org/springframework/data/repository/Repository",
            "org/springframework/data/repository/CrudRepository",
            "org/springframework/data/repository/ListCrudRepository",
            "org/springframework/data/repository/PagingAndSortingRepository",
            "org/springframework/data/jpa/repository/JpaRepository");
    /** Any Spring Data repository BASE interface — under `org/springframework/data/` and ending in
     *  `Repository`. Covers JPA, reactive (ReactiveCrudRepository), and every store module
     *  (Mongo/Cassandra/Elasticsearch/R2dbc)
     *  without enumerating each: the framework bases all live under this package and end in "Repository".
     *  REPO_MARKERS stays as the JPA/JDBC-core fast set; this catches the rest (those bases are framework
     *  interfaces NOT in the scanned classes, so the transitive marker chain breaks at them → silent-pure
     *  inherited CRUD on reactive/NoSQL repos). */
    static boolean isSpringDataRepoBase(String internal) {
        return internal.startsWith("org/springframework/data/") && internal.endsWith("Repository");
    }
    static final String TX = "springframework/transaction/annotation/Transactional";
    static final String SCHEDULED = "springframework/scheduling/annotation/Scheduled";
    // Jackson invokes a @JsonCreator-annotated constructor/factory REFLECTIVELY during deserialization,
    // with no in-project call site — an effectful creator body (validation that logs, a resource opened
    // on construction) is orphaned from every root, the serialization-callback shape. Root it.
    static final String JSON_CREATOR = "JsonCreator";
    static final String FEIGN = "openfeign/FeignClient";
    // Ambient authorities for AS-EFF-004 / CANDOR_NO_AMBIENT — the spec's `Ambient = 𝔼 \ {Log}`
    // (SEMANTICS.md §, every effect except cross-cutting Log; Unknown is not an authority). Was missing
    // Ipc + Clipboard, so direct Unix-socket/clipboard reaches slipped the no-ambient check (the Rust
    // reference flags them).
    static final Set<String> AMBIENT =
            Set.of("Net", "Fs", "Db", "Exec", "Env", "Clock", "Rand", "Ipc", "Clipboard");
    // The effect vocabulary candor-java emits — spec §1: 𝔼 = {Net,Fs,Db,Exec,Env,Clock,Ipc,Log,Rand,
    // Clipboard}. Used to split a `deny <Effect…> [scope]` rule's effects from its trailing scope token,
    // so a missing entry (Clipboard was absent) would mis-parse `deny Clipboard …` as a scope.
    static final Set<String> KNOWN_EFFECTS =
            Set.of("Net", "Fs", "Db", "Exec", "Env", "Clock", "Rand", "Log", "Ipc", "Clipboard");
    // AS-EFF-007 (CANDOR_TAINT): the injection-class effects whose argument, if caller-derived, is an
    // injection surface (path traversal / command / SQL / SSRF). Clock/Rand/Log/Clipboard aren't injectable.
    static final Set<String> INJECTION = Set.of("Fs", "Exec", "Db", "Net", "Env", "Ipc");
    static boolean taintEnabled = false;             // CANDOR_TAINT — run the intraprocedural taint pass
    // fn -> injection-class effects performed on a parameter-derived (caller-controlled) argument.
    static final Map<String, TreeSet<String>> tainted = new HashMap<>();
    // java.io types whose <init> takes a file PATH as its first String arg (for AS-EFF-008 `paths`).
    static final Set<String> PATH_CTOR_OWNERS = Set.of("java.io.File", "java.io.FileInputStream",
            "java.io.FileOutputStream", "java.io.FileReader", "java.io.FileWriter", "java.io.RandomAccessFile");

    // CANDOR_POLICY rules (architecture-as-code, candor-spec §5). `deny`/`pure` = AS-EFF-006 (what a
    // layer may do); `allow … in …` = AS-EFF-008 (which endpoints); `forbid A -> B` = AS-EFF-009 (who
    // a layer may depend on).
    static final List<DenyRule> denyRules = new ArrayList<>();
    static final List<AllowRule> allowRules = new ArrayList<>();
    static final List<ForbidRule> forbidRules = new ArrayList<>();
    static final Map<String, TreeSet<String>> hostsDirect = new HashMap<>(); // fn -> literal Net endpoints
    static final Map<String, TreeSet<String>> cmdsDirect = new HashMap<>();  // fn -> literal Exec commands
    static final Map<String, TreeSet<String>> pathsDirect = new HashMap<>(); // fn -> literal Fs paths
    static final Map<String, TreeSet<String>> tablesDirect = new HashMap<>(); // fn -> literal Db tables
    // The κ-coverage ledger (the Rust/TS move): external packages this code calls where the
    // classifier never fires are INVISIBLE, not Unknown — counted here, named in the receipt.
    static final Map<String, Integer> kappaSeen = new TreeMap<>();      // external package -> call count
    // reflective calls with a LITERAL method name in the same body (`getMethod("x")` … `invoke`):
    // the literal names the target, so a unique project match gets an EDGE alongside the honest
    // Unknown (the density review's JVM slice — recall without guessing).
    static final List<String[]> reflectPairs = new ArrayList<>();        // [callerId, literalName]
    static final Set<String> kappaClassified = new HashSet<>();         // packages with >=1 classification
    // Packages a CANDOR_DEPS sibling report covers: chained, not blind — even a call that joins
    // nothing (the dep fn is pure and omitted) is the report's honest purity claim.
    static final Set<String> depCoveredPkgs = new HashSet<>();

    /** A `deny <Effect…> [scope]` or `pure <scope>` rule. `effects` empty ⇒ a `pure` rule (ANY effect is
     *  forbidden). `scope` empty ⇒ the whole project. */
    static class DenyRule { TreeSet<String> effects = new TreeSet<>(); String scope = ""; String src; }
    /** An `allow <Effect> [in <scope>] <value…>` rule: a method in scope performing that effect may reach
     *  ONLY the listed values (Net hosts today). `scope` empty ⇒ whole project. */
    static class AllowRule { String effect; String scope = ""; TreeSet<String> values = new TreeSet<>(); String src; }
    /** A `forbid <A> -> <B>` rule: a method in scope A must not transitively reach into scope B. */
    static class ForbidRule { String from, to; }

    /** Reject an unrecognized leading-dash argument (spec §6.2): a typo'd flag must FAIL with exit 2,
     *  never be silently ignored nor read as a positional path — the same gateless-green class as an
     *  unreadable policy file. Shared by main() and Query.run so the binary has ONE posture. */
    static void rejectUnknownFlag(String arg, java.util.Set<String> known, String usage) {
        if (arg.startsWith("--") && !known.contains(arg)) {
            System.err.println("candor: unknown flag " + arg + " (usage: " + usage + ")");
            System.exit(2);
        }
    }

    /** Clear every mutable analysis accumulator so a scan starts from a clean slate. The engine's
     *  state lives in static collections (an analysis cache the binary fills once per run, not a
     *  singleton the process owns); without this a SECOND in-process scan would double-count edges
     *  and inherit the prior run's repo/entity/clinit/rule sets — fabricating effects from leftover
     *  state. Resetting here makes {@link #runScan} REENTRANT (the audit's highest structural risk).
     *  The immutable Set.of(...) markers (REPO_MARKERS, AMBIENT, KNOWN_EFFECTS, INJECTION,
     *  PATH_CTOR_OWNERS) are constants, not state, and are deliberately left untouched. */
    static void resetState() {
        direct.clear(); edges.clear(); loc.clear(); hashOf.clear(); viaCross.clear();
        crossDeps.clear(); fsDirect.clear(); unknownWhy.clear();
        entryPoints.clear(); projectClasses.clear(); repoTypes.clear();
        entityTables.clear(); repoTables.clear(); feignTypes.clear();
        ALL = List.of();
        byName.clear(); transSupersCache.clear(); subtypeIndex.clear(); annoMetaCache.clear();
        overloadDescs.clear(); classesWithClinit.clear();
        taintEnabled = false; tainted.clear();
        denyRules.clear(); allowRules.clear(); forbidRules.clear();
        hostsDirect.clear(); cmdsDirect.clear(); pathsDirect.clear(); tablesDirect.clear();
        kappaSeen.clear(); reflectPairs.clear(); kappaClassified.clear(); depCoveredPkgs.clear();
    }

    /** The analysis core, factored out of {@link #main} so it is REENTRANT (resets first) and free of
     *  System.exit (so it is unit-testable in-process): reset state, load the target, index overloads
     *  + CHA subtypes, compute Spring types, chain CANDOR_DEPS, run per-method analysis, resolve
     *  literal-reflection edges, then return the inferred per-method effect sets from the fixpoint. */
    static Map<String, TreeSet<String>> runScan(Path target) throws IOException {
        resetState();
        List<ClassNode> classes = load(target);
        ALL = classes;
        for (ClassNode cn : classes) {
            projectClasses.add(cn.name);
            byName.put(cn.name, cn);
            String dc = cn.name.replace('/', '.');
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("<clinit>")) classesWithClinit.add(cn.name);
                // Record this name's descriptor so overloaded names can be disambiguated (methodId).
                // EXCLUDE compiler-generated bridge/synthetic forwarders (a covariant-return or generic
                // bridge `call()Object` beside the real `call()Integer`): they aren't real overloads —
                // counting them would split a UNIQUE method (every Callable/Comparable impl) into a
                // disambiguated id and break the bare-`class.method` the report/entry-point rows use.
                // The bridge body just forwards to the real method, so leaving both bare (re-collapsed)
                // is correct — its effect IS the real method's.
                if ((mn.access & (Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC)) != 0) continue;
                overloadDescs.computeIfAbsent(dc + "." + mn.name, k -> new HashSet<>()).add(mn.desc);
            }
        }
        buildSubtypeIndex(classes);
        computeSpringTypes(classes);
        // Cross-jar inheritance (candor-spec §2): load dependency reports named by CANDOR_DEPS BEFORE
        // analyze, so a call into an already-analyzed dependency inherits its effects (vs assumed-pure).
        loadCrossDeps(System.getenv("CANDOR_DEPS"), provenance()[0]);
        taintEnabled = System.getenv("CANDOR_TAINT") != null; // read before analyze (the pass runs per method)
        // Per-class fail-soft: an exotic/malformed class that throws ANYWHERE in analyze (e.g. a malformed
        // method descriptor that ASM validates only lazily in Type.getArgumentTypes — the 0.5.6 crash class,
        // re-surfaced via an overloaded-name path the desc.startsWith("(") guard doesn't catch) must NOT
        // abort the WHOLE scan and silently zero EVERY other class's analysis (a DoS). Skip + disclose the
        // one bad class, mirroring collectClasses's tolerance.
        int analyzeSkipped = 0; String firstAnalyzeErr = null;
        for (ClassNode cn : classes) {
            try {
                analyze(cn);
            } catch (Throwable t) {
                analyzeSkipped++;
                if (firstAnalyzeErr == null) firstAnalyzeErr = cn.name + ": " + t;
            }
        }
        if (analyzeSkipped > 0)
            System.err.printf("candor-java: skipped %d unanalyzable class(es) (e.g. %s)%n",
                    analyzeSkipped, firstAnalyzeErr);

        // Resolve literal-getMethod reflection: edge to the named method OF THE RECEIVER CLASS only —
        // `Helper.class.getMethod("strip")` → `Helper.strip`. A receiver we can't pin to a project
        // class (a runtime `obj.getClass()`, or an EXTERNAL `String.class`) forms NO edge: the §4
        // Unknown stands. Matching by global leaf-name suffix (the old code) fabricated an edge to an
        // unrelated same-named project method — the exact "candor never fabricates an effect" breach
        // candor-scan's own comments record removing. Unknown stays either way (reflection is opaque).
        for (String[] pair : reflectPairs) {
            String caller = pair[0], lit = pair[1], recv = pair[2];
            if (recv.isEmpty() || !projectClasses.contains(recv)) continue;
            String callee = recv.replace('/', '.') + "." + lit;
            if (edges.containsKey(callee)) edges.get(caller).add(callee);
        }

        return fixpoint();
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>]");
            System.err.println(
                    "       candor <show|where|callers|map|diff|containment|reachable|path|impact|gains|whatif|rewire> <report.json> [arg]");
            System.err.println("       candor parsepolicy <policy-file>");
            System.err.println("       candor --version | --agents");
            System.exit(2);
        }
        // Read-only queries over a written report (no re-analysis) — the sibling of candor-query.
        if (Query.COMMANDS.contains(args[0])) {
            System.exit(Query.run(args));
        }
        // The agent contract for THE INSTALLED BUILD, baked into the jar as a resource — doc and
        // engine cannot drift (the §2.1 version-trust rule applied to documentation).
        if (args[0].equals("--agents")) {
            try (var in = Candor.class.getResourceAsStream("/AGENTS.md")) {
                if (in == null) {
                    System.err.println("candor: the AGENTS.md resource is missing from this build");
                    System.exit(2);
                }
                System.out.println("<!-- candor-java " + provenance()[0]
                        + " · the agent contract for this installed version -->");
                System.out.write(in.readAllBytes());
                System.out.flush();
            }
            System.exit(0);
        }
        // `--version` — the clean RELEASE semver (the GitHub-tag / jar-filename axis) + spec, then the
        // upgrade line. No network: candor analyzes for the `Net` effect and must not perform it, so it
        // never phones home. Staying current is the AGENT's job — it reads this, then (it has network)
        // compares against GitHub releases and upgrades.
        if (args[0].equals("--version")) {
            System.out.println("candor-java " + release() + " (spec " + SPEC_VERSION + ")");
            System.out.println("upgrade: jbang --fresh candor@tombaldwin/candor-java");
            System.exit(0);
        }
        // `parsepolicy <file>` — dump the parsed CANDOR_POLICY as canonical JSON. Not a user workflow;
        // it exists so the cross-impl conformance suite can diff this engine's policy parse against the
        // Rust reference and prove the SPEC §6.2 grammar means the same thing in both.
        if (args[0].equals("parsepolicy")) {
            if (args.length < 2) { System.err.println("usage: candor parsepolicy <policy-file>"); System.exit(2); }
            denyRules.clear(); allowRules.clear(); forbidRules.clear();
            if (!parsePolicy(args[1])) { System.err.println("candor: cannot read policy " + args[1]); System.exit(2); }
            System.out.println(Query.policyJson());
            System.exit(0);
        }
        // `selftest-reentrant <dirty-target> <real-target> --json <file>` — the REENTRANCY gate. Not a
        // user workflow: it scans <dirty-target> first to populate every static accumulator, then scans
        // <real-target> in the SAME process and writes <real-target>'s report. If resetState() missed an
        // accumulator, the first scan's edges/repo/entity/rule state leak into the second and the report
        // diverges from a fresh-process scan of <real-target> — which soundness/reentrancy.sh diffs.
        if (args[0].equals("selftest-reentrant")) {
            String rj = null;
            for (int i = 3; i < args.length; i++) if (args[i].equals("--json") && i + 1 < args.length) rj = args[++i];
            if (args.length < 3 || rj == null) {
                System.err.println("usage: candor selftest-reentrant <dirty-target> <real-target> --json <file>");
                System.exit(2);
            }
            runScan(Path.of(args[1]));                       // dirty the statics
            var inferred = runScan(Path.of(args[2]));        // real scan must be independent of the above
            writeJson(inferred, rj); writeCallgraph(rj);
            System.exit(0);
        }
        // The first arg is the scan target (a dir/jar) — a flag there is a typo or a newer-doc flag
        // an older jar doesn't know; fail loudly rather than scan a path named after it.
        var scanFlags = java.util.Set.of("--json"); // --agents handled above; the rest are unknown here
        rejectUnknownFlag(args[0], java.util.Set.of(), "candor <dir-or-jar> [--json <file>] | candor --agents");
        String jsonOut = null;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--json")) {
                if (i + 1 >= args.length) { // a trailing --json with no value must FAIL, not be
                    System.err.println("candor: --json requires a value"); // silently dropped (a
                    System.exit(2);                                        // CI gate then diffs a
                }                                                          // stale baseline ungated)
                jsonOut = args[++i];
            } else {
                rejectUnknownFlag(args[i], scanFlags, "candor <dir-or-jar> [--json <file>]");
            }
        }

        // CRASH-SAFETY: a nonexistent path, or a corrupt/truncated/empty/uppercase-ext "jar", must not
        // dump a stack trace and exit 1 — the archive layer throws raw NoSuchFileException / ZipException
        // / ProviderNotFoundException (a RuntimeException, not IOException). Match the unreadable-policy
        // posture: a clean one-line diagnostic and exit 2.
        Path scanTarget = Path.of(args[0]);
        if (!Files.exists(scanTarget)) {
            System.err.println("candor: no such path: " + args[0]);
            System.exit(2);
        }
        Map<String, TreeSet<String>> inferred;
        try {
            inferred = runScan(scanTarget);
        } catch (IOException | java.nio.file.ProviderNotFoundException e) {
            // Scoped to the file-read failures load() can raise: NoSuchFileException/ZipException
            // (IOException) + ProviderNotFoundException (a RuntimeException, for an unrecognized
            // archive). NOT a blanket `RuntimeException` catch — that would MASK a genuine analysis
            // bug (an NPE in analyze/fixpoint) as a file error, hiding an engine defect.
            System.err.println("candor: cannot read scan target " + args[0] + ": " + e.getMessage());
            System.exit(2);
            return; // unreachable — exit(2) above; satisfies the definite-assignment of `inferred`
        }

        // JSON output is orthogonal — write first so `--json` can snapshot a baseline.
        if (jsonOut != null) { writeJson(inferred, jsonOut); writeCallgraph(jsonOut); }

        // The κ-coverage disclosure (mirrors the Rust/TS receipts): external packages the bytecode
        // demonstrably calls where the classifier never fired — invisible, not Unknown. Per-scan
        // evidence instead of a doc footnote; never conclude "no effect" through a package named here.
        List<Map.Entry<String, Integer>> unlisted = kappaSeen.entrySet().stream()
                .filter(e -> !kappaClassified.contains(e.getKey()) && !depCoveredPkgs.contains(e.getKey()))
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .collect(Collectors.toList());
        if (!unlisted.isEmpty()) {
            String shown = unlisted.stream().limit(8)
                    .map(e -> e.getKey() + " (" + e.getValue() + " call" + (e.getValue() == 1 ? "" : "s") + ")")
                    .collect(Collectors.joining(", "));
            String more = unlisted.size() > 8 ? " + " + (unlisted.size() - 8) + " more" : "";
            System.err.printf("candor-java: κ doesn't know %d package%s this code calls into — effects through "
                    + "%s are INVISIBLE (not Unknown): %s%s%n",
                    unlisted.size(), unlisted.size() == 1 ? "" : "s",
                    unlisted.size() == 1 ? "it" : "them", shown, more);
        }

        // Modes: CANDOR_STRICT (conformance via DI), CANDOR_BASELINE (regression guard),
        // CANDOR_NO_AMBIENT (enforcement).
        String strict = System.getenv("CANDOR_STRICT");
        String baseline = System.getenv("CANDOR_BASELINE");
        String noAmbient = System.getenv("CANDOR_NO_AMBIENT");
        String policy = System.getenv("CANDOR_POLICY");
        boolean enforce = baseline != null || noAmbient != null || strict != null || policy != null
                || taintEnabled;

        if (!enforce) {
            System.out.println("candor-java — effect audit (Spring-aware; Unknown for reflection/dispatch)\n");
            inferred.entrySet().stream()
                    .filter(e -> !e.getValue().isEmpty())
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(e -> {
                        var d = direct.getOrDefault(e.getKey(), new TreeSet<>());
                        String set = e.getValue().stream()
                                .map(x -> d.contains(x) ? x : x + "*")
                                .collect(Collectors.joining(", "));
                        String tag = entryPoints.contains(e.getKey()) ? "  [entry]" : "";
                        System.out.printf("  %-52s { %s }%s%n", e.getKey(), set, tag);
                    });
            System.out.println("\n(* = via callee, [entry] = framework-invoked entry point)");
            return;
        }

        int violations = 0;
        if (strict != null) violations += checkConformance(inferred, strict);
        if (noAmbient != null) violations += checkNoAmbient(inferred, noAmbient);
        if (baseline != null) violations += checkBaseline(inferred, baseline);
        if (policy != null) violations += checkPolicy(inferred, policy);
        // AS-EFF-007 is a heuristic ADVISORY (spec §6): emit findings but never fail CI on its own.
        int advisories = taintEnabled ? checkTaint(inferred) : 0;
        if (violations == 0 && advisories == 0) System.out.println("candor-java: no violations");
        if (violations > 0) System.exit(1); // fail CI
    }

    /**
     * Conformance via dependency injection: a class's fields are the capabilities it holds, so its
     * effects must be covered by what those collaborators provide. An effect performed beyond them
     * means reaching for ambient authority instead of receiving it (AS-EFF-001). This is candor's
     * capability-token model in Java's idiom — "a bean's signature (its dependencies) tells you its
     * effect surface."
     */
    static int checkConformance(Map<String, TreeSet<String>> inferred, String scope) {
        // performed(class) = union of inferred over the class's own methods.
        Map<String, TreeSet<String>> performed = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> p = performed.computeIfAbsent(dc, k -> new TreeSet<>());
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                var inf = inferred.get(methodId(dc, mn.name, mn.desc));
                if (inf != null) p.addAll(inf);
            }
        }
        int v = 0;
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            if (!gateScopeCovers(scope, dc)) continue;
            TreeSet<String> declared = new TreeSet<>();
            if (cn.fields != null)
                for (FieldNode f : cn.fields) {
                    String t = fieldTypeInternal(f.desc);
                    if (t != null) declared.addAll(typeEffects(t, performed));
                }
            TreeSet<String> perf = performed.getOrDefault(dc, new TreeSet<>());
            boolean hasUnknown = perf.contains("Unknown");
            List<String> undeclared = perf.stream()
                    .filter(x -> !x.equals("Unknown") && !declared.contains(x)).sorted().collect(Collectors.toList());
            List<String> unused = declared.stream()
                    .filter(x -> !perf.contains(x)).sorted().collect(Collectors.toList());
            if (!undeclared.isEmpty()) {
                String have = declared.isEmpty() ? "no injected capability"
                        : "only { " + String.join(", ", declared) + " }";
                System.out.printf("[AS-EFF-001] class `%s` performs { %s } but holds %s; "
                        + "inject a collaborator that provides it (don't reach for ambient authority)%n",
                        dc, String.join(", ", undeclared), have);
                v++;
            }
            if (hasUnknown) {
                System.out.printf("[AS-EFF-003] class `%s` makes calls candor cannot resolve "
                        + "(reflection / unresolved dispatch); effect set not provably complete%n", dc);
                v++;
            }
            if (!unused.isEmpty()) {
                System.out.printf("[AS-EFF-002] class `%s` injects { %s } but never uses it%n",
                        dc, String.join(", ", unused));
                v++;
            }
        }
        return v;
    }

    /** Effects a field of type `internal` can supply (Spring repo/template, or a project collaborator). */
    static Set<String> typeEffects(String internal, Map<String, TreeSet<String>> performed) {
        if (repoTypes.contains(internal)) return Set.of("Db");
        if (feignTypes.contains(internal)) return Set.of("Net");
        String dotted = internal.replace('/', '.');
        Set<String> lib = classifyType(dotted);
        if (!lib.isEmpty()) return lib;
        if (byName.containsKey(internal)) return performed.getOrDefault(dotted, new TreeSet<>());
        return Set.of();
    }

    /** Type-level classification of a collaborator (mirrors the call-level classify, by owner type). */
    static Set<String> classifyType(String dotted) {
        if (dotted.equals("org.springframework.web.client.RestTemplate")
                || dotted.equals("org.springframework.web.client.RestClient")
                || dotted.startsWith("org.springframework.web.reactive.function.client.")
                || dotted.equals("org.springframework.jms.core.JmsTemplate")
                || dotted.equals("org.springframework.kafka.core.KafkaTemplate"))
            return Set.of("Net");
        if (dotted.equals("org.springframework.jdbc.core.JdbcTemplate")
                || dotted.equals("org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate")
                || dotted.equals("jakarta.persistence.EntityManager")
                || dotted.equals("javax.persistence.EntityManager"))
            return Set.of("Db");
        return Set.of();
    }

    /** Object type internal name from a field descriptor (`Lcom/x/Foo;` -> `com/x/Foo`); null if primitive. */
    static String fieldTypeInternal(String desc) {
        int l = desc.indexOf('L');
        if (l >= 0 && desc.endsWith(";")) return desc.substring(l + 1, desc.length() - 1);
        return null;
    }

    /** AS-EFF-004: flag direct use of ambient authority (route it through an injected collaborator). */
    static int checkNoAmbient(Map<String, TreeSet<String>> inferred, String scope) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            if (!gateScopeCovers(scope, e.getKey())) continue;
            List<String> ambient = direct.getOrDefault(e.getKey(), new TreeSet<>()).stream()
                    .filter(AMBIENT::contains).sorted().collect(Collectors.toList());
            if (!ambient.isEmpty()) {
                System.out.printf("[AS-EFF-004] `%s` uses ambient authority { %s } directly; "
                        + "route it through an injected collaborator / capability%n",
                        e.getKey(), String.join(", ", ambient));
                v++;
            }
        }
        return v;
    }

    /**
     * AS-EFF-007 (CANDOR_TAINT): a function performs an injection-class effect on a CALLER-DERIVED argument
     * (path traversal / command / SQL injection / SSRF). HEURISTIC + ADVISORY — an intraprocedural,
     * over-approximating dataflow (the `tainted` map is built in `analyze` by the taint `Analyzer`); it
     * misses cross-method flow and over-flags a parameter that is actually validated. Mirrors the Rust
     * impl's syntactic taint nudge. Emits findings but never fails CI (returns the count for messaging only).
     */
    static int checkTaint(Map<String, TreeSet<String>> inferred) {
        int v = 0;
        for (var e : new TreeMap<>(tainted).entrySet()) {
            if (e.getValue().isEmpty()) continue;
            System.out.printf("[AS-EFF-007] `%s` performs { %s } on caller-derived input (an injection "
                    + "surface — validate/sanitize it, or confirm the source is trusted); heuristic, may "
                    + "over- or under-flag%n", e.getKey(), String.join(", ", e.getValue()));
            v++;
        }
        return v;
    }

    /** The local-variable slots holding this method's declared parameters (excluding `this`); a load from
     *  one of these is the untrusted-input source for the taint pass. Long/double params occupy 2 slots. */
    static Set<Integer> paramSlots(MethodNode mn) {
        Set<Integer> s = new HashSet<>();
        int slot = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1; // instance methods carry `this` at slot 0
        for (Type t : Type.getArgumentTypes(mn.desc)) {
            s.add(slot);
            slot += t.getSize();
        }
        return s;
    }

    /** Is any ARGUMENT (not the receiver) of the call `min` tainted in the frame `f` before it executes? */
    static boolean argsTainted(Frame<TaintValue> f, MethodInsnNode min) {
        if (f == null) return false;
        int slots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) slots += a.getSize();
        int top = f.getStackSize();
        for (int i = 0; i < slots && i < top; i++) { // the args occupy the top `slots` stack entries
            TaintValue v = f.getStack(top - 1 - i);
            if (v != null && v.tainted) return true;
        }
        return false;
    }

    /** A dataflow value carrying ASM's type/size (`base`) plus a taint bit (derives from a parameter). */
    static final class TaintValue implements Value {
        final BasicValue base;
        final boolean tainted;
        TaintValue(BasicValue base, boolean tainted) { this.base = base; this.tainted = tainted; }
        public int getSize() { return base.getSize(); }
        public boolean equals(Object o) {
            return o instanceof TaintValue t && base.equals(t.base) && tainted == t.tainted;
        }
        public int hashCode() { return base.hashCode() * 2 + (tainted ? 1 : 0); }
    }

    /** Propagates taint over a method's dataflow: a load of a parameter slot is the source; taint flows
     *  through copies, casts, arithmetic, and method calls (StringBuilder/concat carry it). Type/size
     *  correctness is delegated to {@link BasicInterpreter} so the analyzer's frames merge soundly. */
    static final class TaintInterpreter extends Interpreter<TaintValue> {
        private final BasicInterpreter bi = new BasicInterpreter();
        private final Set<Integer> params;
        TaintInterpreter(Set<Integer> params) { super(Opcodes.ASM9); this.params = params; }
        private static TaintValue wrap(BasicValue b, boolean t) { return b == null ? null : new TaintValue(b, t); }

        public TaintValue newValue(Type type) { return wrap(bi.newValue(type), false); }
        public TaintValue newOperation(AbstractInsnNode insn) throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.newOperation(insn), false);
        }
        public TaintValue copyOperation(AbstractInsnNode insn, TaintValue value)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            int op = insn.getOpcode();
            // A load from a parameter slot IS the untrusted-input source; every other copy preserves taint.
            if (op >= Opcodes.ILOAD && op <= Opcodes.ALOAD && insn instanceof VarInsnNode vi
                    && params.contains(vi.var))
                return new TaintValue(value.base, true);
            return value;
        }
        public TaintValue unaryOperation(AbstractInsnNode insn, TaintValue value)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.unaryOperation(insn, value.base), value.tainted);
        }
        public TaintValue binaryOperation(AbstractInsnNode insn, TaintValue a, TaintValue b)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.binaryOperation(insn, a.base, b.base), a.tainted || b.tainted);
        }
        public TaintValue ternaryOperation(AbstractInsnNode insn, TaintValue a, TaintValue b, TaintValue c)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.ternaryOperation(insn, a.base, b.base, c.base), a.tainted || b.tainted || c.tainted);
        }
        public TaintValue naryOperation(AbstractInsnNode insn, List<? extends TaintValue> values)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            boolean t = false;
            List<BasicValue> bases = new ArrayList<>(values.size());
            for (TaintValue v : values) { bases.add(v.base); t |= v.tainted; }
            // The result of a call/concat/StringBuilder carries taint if any argument did.
            return wrap(bi.naryOperation(insn, bases), t);
        }
        public void returnOperation(AbstractInsnNode insn, TaintValue value, TaintValue expected) {}
        public TaintValue merge(TaintValue a, TaintValue b) {
            BasicValue mb = bi.merge(a.base, b.base);
            boolean mt = a.tainted || b.tainted; // at a control-flow join, tainted if tainted on either path
            if (mb.equals(a.base) && mt == a.tainted) return a;
            return new TaintValue(mb, mt);
        }
    }

    /** Receiver-provenance value (the soundness fix for monomorphic-dispatch fabrication). Carries ASM's
     *  type/size (`base`) plus, when this value is PROVABLY a single freshly-constructed `new T`, that
     *  type's internal name in `newType`; otherwise `newType` is null ("indeterminate" — a parameter, a
     *  field, a return value, a merge of different new-types, or anything else). A non-null `newType` is a
     *  guarantee, never a guess: it is set ONLY by `newOperation` on a NEW insn and survives only copies,
     *  loads/stores, and merges that agree on the exact same type. */
    static final class ProvValue implements Value {
        final BasicValue base;
        final String newType; // internal name of a provable `new T` receiver, or null = indeterminate
        final boolean fromIndy; // produced by an invokedynamic (a lambda/method-ref) — its body is edged at
                                // creation, so an executor hand-off of it needs no Unknown (vs a field/param)
        ProvValue(BasicValue base, String newType) { this(base, newType, false); }
        ProvValue(BasicValue base, String newType, boolean fromIndy) {
            this.base = base; this.newType = newType; this.fromIndy = fromIndy;
        }
        public int getSize() { return base.getSize(); }
        public boolean equals(Object o) {
            return o instanceof ProvValue p && base.equals(p.base)
                    && Objects.equals(newType, p.newType) && fromIndy == p.fromIndy;
        }
        public int hashCode() {
            return (base.hashCode() * 31 + (newType == null ? 0 : newType.hashCode())) * 31 + (fromIndy ? 1 : 0);
        }
    }

    /** Tracks, per stack/local value, whether it is PROVABLY a single `new T` — the receiver-provenance
     *  dataflow that lets an invokevirtual on a freshly-allocated, single-typed receiver resolve to the
     *  one method T dispatches, SKIPPING the CHA sibling fan-out (the monomorphic fabrication fix). Type/
     *  size correctness is delegated to {@link BasicInterpreter} so frames merge soundly. SOUND BY
     *  CONSTRUCTION: only `newOperation` on a NEW insn mints a `newType`; every other production (params
     *  via `newValue`, field/array/return values via the base interpreter, constants) is indeterminate;
     *  and `merge` of two DIFFERENT new-types (or a new with a non-new) collapses to indeterminate — so a
     *  genuinely polymorphic receiver (param/field/branch-merged) NEVER narrows, keeping the CHA. */
    static final class ProvInterpreter extends Interpreter<ProvValue> {
        private final BasicInterpreter bi = new BasicInterpreter();
        ProvInterpreter() { super(Opcodes.ASM9); }
        private static ProvValue wrap(BasicValue b, String t) { return b == null ? null : new ProvValue(b, t); }

        public ProvValue newValue(Type type) { return wrap(bi.newValue(type), null); }
        public ProvValue newOperation(AbstractInsnNode insn) throws org.objectweb.asm.tree.analysis.AnalyzerException {
            // The NEW opcode (and ONLY it among newOperation's insns) yields an UNINITIALIZED single-typed
            // reference; that type is the provable receiver type. LDC / GETSTATIC / constants / etc. carry
            // no allocation-site guarantee, so they stay indeterminate.
            String t = (insn.getOpcode() == Opcodes.NEW) ? ((TypeInsnNode) insn).desc : null;
            return wrap(bi.newOperation(insn), t);
        }
        public ProvValue copyOperation(AbstractInsnNode insn, ProvValue value) { return value; }
        public ProvValue unaryOperation(AbstractInsnNode insn, ProvValue value)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            // A unary op (cast, conversion, getfield, arraylength, …) never preserves the allocation-site
            // guarantee: even CHECKCAST of a `new T` keeps T, but a field read off it does not — and we
            // can't tell them apart cheaply, so conservatively drop to indeterminate. (The sound direction:
            // dropping a true `new T` only FORGOES a narrow and keeps the CHA over-approximation.)
            return wrap(bi.unaryOperation(insn, value.base), null);
        }
        public ProvValue binaryOperation(AbstractInsnNode insn, ProvValue a, ProvValue b)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.binaryOperation(insn, a.base, b.base), null);
        }
        public ProvValue ternaryOperation(AbstractInsnNode insn, ProvValue a, ProvValue b, ProvValue c)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.ternaryOperation(insn, a.base, b.base, c.base), null);
        }
        public ProvValue naryOperation(AbstractInsnNode insn, List<? extends ProvValue> values)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            List<BasicValue> bases = new ArrayList<>(values.size());
            for (ProvValue v : values) bases.add(v.base);
            // A call/multianewarray result is never a tracked allocation site (its return value's runtime
            // type is unknown to a syntactic pass) — indeterminate `newType`. But an INVOKEDYNAMIC result
            // IS a lambda/method-ref whose body candor edges at this creation site, so flag it: an executor
            // hand-off of a lambda needs no Unknown (the body is already captured), unlike an opaque
            // field/param task. (fromIndy is read ONLY at the hand-off site — monomorphicReceiver, which
            // reads newType, is unaffected.)
            BasicValue b = bi.naryOperation(insn, bases);
            boolean indy = insn.getOpcode() == Opcodes.INVOKEDYNAMIC;
            return b == null ? null : new ProvValue(b, null, indy);
        }
        public void returnOperation(AbstractInsnNode insn, ProvValue value, ProvValue expected) {}
        public ProvValue merge(ProvValue a, ProvValue b) {
            BasicValue mb = bi.merge(a.base, b.base);
            // CRITICAL for soundness: a control-flow join keeps the `new T` guarantee ONLY when BOTH paths
            // bring the SAME new-type; a new-vs-new(other), a new-vs-indeterminate, or any disagreement
            // collapses to indeterminate, so a branch-merged receiver (`if (c) new Base() else new Dirty()`)
            // is NOT monomorphic and the CHA fan-out is preserved.
            String mt = Objects.equals(a.newType, b.newType) ? a.newType : null;
            // a join is "definitely a lambda" only when BOTH paths are — else treat as opaque (a lambda-vs-
            // field merge must NOT be skipped at the hand-off site).
            boolean mi = a.fromIndy && b.fromIndy;
            if (mb.equals(a.base) && Objects.equals(mt, a.newType) && mi == a.fromIndy) return a;
            return new ProvValue(mb, mt, mi);
        }
    }

    /** The provable single `new T` receiver internal name of the call `min` in frame `f`, or null if the
     *  receiver is NOT provably a single freshly-constructed type (a param/field/return/merge — the
     *  genuinely polymorphic case that MUST keep the CHA). The receiver is the stack entry just below the
     *  call's arguments. */
    static String monomorphicReceiver(Frame<ProvValue> f, MethodInsnNode min) {
        if (f == null) return null;
        int argSlots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) argSlots += a.getSize();
        int top = f.getStackSize();
        int recvIdx = top - 1 - argSlots; // below the args sits the receiver
        if (recvIdx < 0) return null;
        ProvValue rv = f.getStack(recvIdx);
        return rv == null ? null : rv.newType;
    }

    /** AS-EFF-005: flag a function that gained an effect versus a saved baseline report. */
    static int checkBaseline(Map<String, TreeSet<String>> inferred, String path) {
        Map<String, Set<String>> base = loadBaseline(path);
        if (base == null) {
            System.err.println("candor-java: CANDOR_BASELINE set but " + path
                    + " could not be loaded — the regression guard is NOT active");
            return 0;
        }
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            Set<String> prior = base.get(e.getKey());
            if (prior == null) continue; // new function — reviewed as new code, not a regression
            List<String> gained = e.getValue().stream()
                    .filter(x -> !prior.contains(x)).sorted().collect(Collectors.toList());
            if (!gained.isEmpty()) {
                System.out.printf("[AS-EFF-005] `%s` gained effect { %s } not present in the baseline%n",
                        e.getKey(), String.join(", ", gained));
                v++;
            }
        }
        return v;
    }

    /** CANDOR_POLICY (candor-spec §5): architecture-as-code. Enforces all three boundary kinds, each
     *  TRANSITIVELY (so they catch what a local diff hides):
     *   - AS-EFF-006 `deny <Effect…> [scope]` / `pure <scope>` — WHAT a layer may do.
     *   - AS-EFF-008 `allow <Effect> in <scope> <value…>` — WHICH literals (Net hosts / Exec commands /
     *     Fs paths) it may reach, against the visible surface.
     *   - AS-EFF-009 `forbid <A> -> <B>` — WHO a layer may depend on (reachability over the call graph).
     *  A set-but-unreadable policy is LOUD (not silently passing). */
    static int checkPolicy(Map<String, TreeSet<String>> inferred, String path) {
        if (!parsePolicy(path)) {
            // A SET-but-unreadable policy FAILS the run (exit 2) — it must never gate-pass: a
            // typo'd CANDOR_POLICY path otherwise runs gateless and green (spec §6.2). Found by
            // the spec review: this engine printed loudly but returned clean; the siblings exit 2.
            System.err.println("candor-java: CANDOR_POLICY=" + path
                    + " could not be read — failing (exit 2), policy NOT evaluated");
            System.exit(2);
        }
        int v = 0;
        // AS-EFF-006: a method in scope must not perform (transitively) a denied effect.
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            for (DenyRule r : denyRules) {
                if (!scopeMatches(fn, r.scope)) continue;
                List<String> bad = r.effects.isEmpty()
                        ? e.getValue().stream().filter(x -> !x.equals("Unknown")).sorted().collect(Collectors.toList())
                        : e.getValue().stream().filter(r.effects::contains).sorted().collect(Collectors.toList());
                if (!bad.isEmpty()) {
                    System.out.printf("[AS-EFF-006] `%s` performs { %s }, forbidden by policy%s: `%s`%n",
                            fn, String.join(", ", bad),
                            r.scope.isEmpty() ? "" : " (scope `" + r.scope + "`)", r.src);
                    v++;
                }
            }
        }
        // AS-EFF-008: a method in an allow-listed scope may reach ONLY the listed literals — Net hosts
        // (matched by hostname), Exec commands (by basename), Fs paths (by path-prefix at a boundary).
        // Certifies the VISIBLE literal surface (propagated transitively); a method performing the effect
        // with no visible literal can't be certified and isn't flagged (the documented limit).
        v += checkAllowlist(inferred, "Net", literalFixpoint(hostsDirect),
                (allowed, reached) -> allowed.stream().anyMatch(a -> hostPart(a).equals(hostPart(reached))));
        v += checkAllowlist(inferred, "Exec", literalFixpoint(cmdsDirect),
                (allowed, reached) -> allowed.stream().anyMatch(a -> cmdBase(a).equals(cmdBase(reached))));
        v += checkAllowlist(inferred, "Fs", literalFixpoint(pathsDirect),
                (allowed, reached) -> allowed.stream().anyMatch(a -> pathCovered(a, reached)));
        v += checkAllowlist(inferred, "Db", literalFixpoint(tablesDirect),
                (allowed, reached) -> allowed.stream().anyMatch(a -> tableCovered(a, reached)));
        // AS-EFF-009: a method in scope A must not transitively reach into scope B (over the call graph).
        for (ForbidRule r : forbidRules) {
            for (String fn : new TreeSet<>(edges.keySet())) {
                if (!scopeMatches(fn, r.from)) continue;
                String hit = reachesScope(fn, r.to);
                if (hit != null) {
                    System.out.printf("[AS-EFF-009] `%s` reaches into a forbidden layer (via `%s`), "
                            + "violating policy: `forbid %s -> %s`%n", fn, hit, r.from, r.to);
                    v++;
                }
            }
        }
        return v;
    }

    /** AS-EFF-008 for one effect: for EACH `allow <effect> …` rule whose scope matches, the method
     *  performing `effect` must reach ONLY covered literals (per the effect's `covered` matcher).
     *  Per-rule, not unioned across rules — the SEMANTICS predicate quantifies over each rule `r`
     *  (and the Rust gate checks per rule), so two half-covering rules don't pass by union. A method
     *  whose reached surface is EMPTY is a violation too — "a literal it cannot see" can't be
     *  certified (lits_e(f) = ∅ in the predicate). No matching `allow` rule ⇒ unchecked. */
    static int checkAllowlist(Map<String, TreeSet<String>> inferred, String effect,
            Map<String, TreeSet<String>> reachedAcc,
            java.util.function.BiPredicate<Set<String>, String> covered) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            if (!e.getValue().contains(effect)) continue;
            for (AllowRule r : allowRules) {
                if (!effect.equals(r.effect) || !scopeMatches(fn, r.scope)) continue;
                TreeSet<String> reached = reachedAcc.getOrDefault(fn, new TreeSet<>());
                if (reached.isEmpty()) {
                    System.out.printf("[AS-EFF-008] `%s` performs %s with no visible literal — the "
                            + "surface cannot be certified: `allow %s%s %s`%n", fn, effect, effect,
                            r.scope.isEmpty() ? "" : " in " + r.scope,
                            String.join(" ", r.values));
                    v++;
                    continue;
                }
                List<String> bad = reached.stream()
                        .filter(x -> !covered.test(r.values, x)).sorted().collect(Collectors.toList());
                if (!bad.isEmpty()) {
                    System.out.printf("[AS-EFF-008] `%s` reaches { %s } outside the allowlist, forbidden by "
                            + "policy%s: `allow %s … %s`%n", fn, String.join(", ", bad),
                            r.scope.isEmpty() ? "" : " (scope `" + r.scope + "`)", effect,
                            String.join(" ", r.values));
                    v++;
                }
            }
        }
        return v;
    }

    /** Parse a CANDOR_POLICY file into deny/forbid rules. One rule per line; `#` comments + blanks
     *  ignored. Returns false if the file can't be read (so the caller can fail loud). */
    /** SPEC §6.2: a malformed/unknown policy line is "ignored with a WARNING" — never silently
     *  reinterpreted (a security gate must not). Mirrors the Rust parser's eprintln warnings. */
    static void warnPolicy(String line, String reason) {
        System.err.println("candor: ignoring policy rule (" + reason + "): " + line);
    }

    static boolean parsePolicy(String path) {
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of(path));
        } catch (IOException e) {
            return false;
        }
        for (String raw : lines) {
            // SPEC §6.2 lexical: `#` begins a comment to end-of-line (strip it, mirroring the Rust
            // parser's `raw_line.split('#').next()`); blank/comment-only lines are ignored. A bare
            // `startsWith("#")` check left an INLINE comment's tokens in the rule — `deny Exec # x`
            // neutered the deny (scope="#"), `allow Net … # x` widened the allowlist. (/code-review.)
            String line = raw.split("#", 2)[0].trim();
            if (line.isEmpty()) continue;
            String[] t = line.split("\\s+");
            switch (t[0]) {
                case "deny": {
                    // SPEC §6.2: read tokens left-to-right; each known effect (or `Unknown`) joins the
                    // forbidden set; the FIRST non-effect token is the scope and ENDS the rule. A `deny`
                    // naming no known effect is DROPPED — it is NOT a `pure` rule (that distinction is
                    // load-bearing: an empty-effect rule would forbid EVERYTHING). `Unknown` is denyable
                    // so `deny Unknown <scope>` can forbid the unverifiable case (AS-EFF-008's companion).
                    DenyRule r = new DenyRule();
                    r.src = line;
                    for (int i = 1; i < t.length; i++) {
                        if (KNOWN_EFFECTS.contains(t[i]) || "Unknown".equals(t[i])) r.effects.add(t[i]);
                        else { r.scope = t[i]; break; }
                    }
                    if (r.effects.isEmpty()) { warnPolicy(line, "names no known effect"); break; }
                    denyRules.add(r);
                    break;
                }
                case "pure": {
                    DenyRule r = new DenyRule(); // empty effects = ANY effect forbidden
                    r.src = line;
                    if (t.length > 1) r.scope = t[1];
                    denyRules.add(r);
                    break;
                }
                case "forbid": {
                    // SPEC §6.2: `forbid <A> -> <B>` — two scopes separated by a literal `->` TOKEN
                    // (so `forbid a->b` without surrounding spaces is malformed and dropped).
                    if (t.length >= 4 && t[2].equals("->")) {
                        ForbidRule r = new ForbidRule();
                        r.from = t[1];
                        r.to = t[3];
                        forbidRules.add(r);
                    } else {
                        warnPolicy(line, "want `forbid <scope> -> <scope>`");
                    }
                    break;
                }
                case "allow": {
                    // SPEC §6.2: `allow <Effect> [in <scope>] <value…>` — the effect MUST be one of the
                    // three that carry a literal surface; an `allow` for any other effect is dropped.
                    if (t.length < 3) { warnPolicy(line, "allow names no values"); break; }
                    if (!t[1].equals("Net") && !t[1].equals("Exec") && !t[1].equals("Fs") && !t[1].equals("Db")) {
                        warnPolicy(line, "allow supports only Net hosts / Exec commands / Fs paths / Db tables");
                        break;
                    }
                    AllowRule r = new AllowRule();
                    r.src = line;
                    r.effect = t[1];
                    // optional `in <scope>` prefix; `in` ENDS the keyword even with no scope/value after
                    // (`allow Net in` → no values → dropped), matching the Rust parser. A bare
                    // `t.length > 3` guard let a value-less `allow Net in` keep "in" as an allowed value.
                    int vi = 2;
                    if (t[2].equals("in")) { r.scope = t.length > 3 ? t[3] : ""; vi = 4; }
                    for (int i = vi; i < t.length; i++) r.values.add(t[i]);
                    if (r.values.isEmpty()) { warnPolicy(line, "allow names no values"); break; }
                    allowRules.add(r);
                    break;
                }
                default:
                    warnPolicy(line, "unknown rule kind `" + t[0] + "`");
                    break;
            }
        }
        return true;
    }

    /** A policy scope matches a method by dotted SEGMENT (so `domain` matches `app.domain.Svc.handle`
     *  and the `domain_logic` package, but not `subdomain`). Mirrors the Rust impl's `scope_matches`:
     *  a contiguous run of segments — intermediate segments exact, the LAST a prefix. Empty scope ⇒
     *  whole project (matches everything). */
    static boolean scopeMatches(String name, String scope) {
        if (scope.isEmpty()) return true;
        String[] segs = nameSegments(name);
        String[] parts = nameSegments(scope);
        if (parts.length == 0 || parts.length > segs.length) return false;
        String last = parts[parts.length - 1];
        for (int i = 0; i + parts.length <= segs.length; i++) {
            boolean ok = true;
            for (int j = 0; j < parts.length - 1; j++)
                if (!segs[i + j].equals(parts[j])) { ok = false; break; }
            if (ok && segs[i + parts.length - 1].startsWith(last)) return true;
        }
        return false;
    }

    /** Split a name OR a policy scope into segments on BOTH `.` and `::`, dropping empties. candor-java
     *  node ids are dotted (`com.foo.A.m`), but spec §6.2 + the conformance battery write scopes with `::`
     *  (`app::db`, `forbid app::web -> app::db`) and a Rust report names fns with `::` — so a `::`-written
     *  policy scope must still match a dotted name (it silently never did: the gate was a dead rule →
     *  a real violation passed). Mirrors the Rust impl's `name_segments` (splits on `.` and `:`). */
    static String[] nameSegments(String s) {
        List<String> out = new ArrayList<>();
        for (String seg : s.split("[.:]")) if (!seg.isEmpty()) out.add(seg);
        return out.toArray(new String[0]);
    }

    /** Forward reachability over the project call graph: the first method `start` transitively reaches
     *  whose name matches `scope` (seeded from `start`'s direct callees, so `start` itself isn't a hit),
     *  or null. Used for AS-EFF-009 layering. */
    static String reachesScope(String start, String scope) {
        Deque<String> stack = new ArrayDeque<>(edges.getOrDefault(start, Set.of()));
        Set<String> seen = new HashSet<>();
        while (!stack.isEmpty()) {
            String n = stack.pop();
            if (!seen.add(n)) continue;
            if (scopeMatches(n, scope)) return n;
            for (String c : edges.getOrDefault(n, Set.of())) if (!seen.contains(c)) stack.push(c);
        }
        return null;
    }

    /** The network endpoint a string literal names — `host[:port]`, scheme/path/userinfo stripped — or
     *  null if the string isn't UNAMBIGUOUSLY an endpoint. Real code is full of dotted strings that are
     *  NOT hosts — property keys (`os.name`), message keys (`terms.agency`), filenames (`page.html`),
     *  format strings (`"status":"`) — so a bare dotted name is rejected: it's indistinguishable from a
     *  property key without seeing the call it feeds. Accepted: a scheme URL (`https://…`), a
     *  `host:port` with a NUMERIC port, or a bare IPv4. The cost is UNDER-extraction (a bare-hostname
     *  `new Socket("api.example.com", 443)` isn't seen) — the sound direction for a visible-surface
     *  allowlist (a missed host can't certify, but never silently PASSES a forbidden one); modern HTTP
     *  clients use full URLs, which are caught. (Validated against a 2257-class Spring app, which had
     *  ~14 false dotted "hosts" under the old loose filter.) */
    static String netHostLiteral(String s) {
        if (s == null || s.isBlank()) return null;
        String h = s.trim();
        int scheme = h.indexOf("://");
        if (scheme >= 0) { // a URL: take the authority, drop path + userinfo
            h = h.substring(scheme + 3);
            int slash = h.indexOf('/'); if (slash >= 0) h = h.substring(0, slash);
            int at = h.lastIndexOf('@'); if (at >= 0) h = h.substring(at + 1);
            return (h.isBlank() || h.contains(" ")) ? null : h;
        }
        if (h.contains(" ") || h.contains("/")) return null;
        int colon = h.indexOf(':');
        if (colon > 0) { // host:port — accept only with a numeric port and a dotted/IP host
            String host = h.substring(0, colon), port = h.substring(colon + 1);
            boolean numericPort = !port.isEmpty() && port.chars().allMatch(Character::isDigit);
            return (numericPort && host.contains(".")) ? h : null;
        }
        return looksLikeIpv4(h) ? h : null; // a bare token: only a literal IPv4 is unambiguous
    }

    /** Whether `h` is a dotted-quad IPv4 literal (`1.2.3.4`) — the one bare (scheme-less, port-less)
     *  form that's unambiguously a network endpoint, not a property/message key. */
    static boolean looksLikeIpv4(String h) {
        String[] p = h.split("\\.", -1);
        if (p.length != 4) return false;
        for (String x : p) {
            if (x.isEmpty() || x.length() > 3 || !x.chars().allMatch(Character::isDigit)) return false;
            if (Integer.parseInt(x) > 255) return false;
        }
        return true;
    }

    /** The bare hostname of an endpoint (port + any residue stripped), so the allowlist matches
     *  port-insensitively: `api.stripe.com:443` is covered by `allow Net … api.stripe.com`. */
    static int countChar(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    static String hostPart(String h) {
        // Byte-for-byte the candor-rust `policy::host_part` (the GATE-side normalizer): strip ONLY a
        // `[ipv6]` bracket or a trailing `:port`. It does NOT strip scheme/path/userinfo — an earlier
        // java-only version did, which (a) diverged from rust (same policy → different verdict across
        // engines) and (b) silently WIDENED a policy author's allow literal: `allow Net build@github.com`
        // got cleaned to `github.com`, broadening the intended scope. The REACHED host stored in
        // hostsDirect is already a clean authority (netHostLiteral drops scheme/path/userinfo at
        // extraction), so the gate compares clean-vs-clean; the allow literal is taken verbatim, as rust
        // does. A bracketed `[ipv6]`/`[ipv6]:port` → the bracketed host; a BARE IPv6 (>1 colon, no
        // brackets) → returned whole (a naive first-colon split collapsed every `2001:db8::*` to `2001`,
        // so one allowed IPv6 accepted the whole block); host/IPv4 (≤1 colon) → split at the colon.
        if (h.startsWith("[")) {
            int close = h.indexOf(']');
            return close >= 0 ? h.substring(1, close) : h.substring(1);
        }
        if (countChar(h, ':') > 1) return h;   // bare IPv6 literal — no port suffix to strip
        int colon = h.indexOf(':');
        return colon >= 0 ? h.substring(0, colon) : h;
    }

    /** Propagate a literal-detail map (hosts / commands / paths) along the SAME call graph as effects, so
     *  a method that reaches the effect only through a callee still sees the callee's literals — the scale
     *  path for AS-EFF-008 (the literal often lives in a deep, even cross-layer, callee). */
    static Map<String, TreeSet<String>> literalFixpoint(Map<String, TreeSet<String>> direct) {
        Map<String, TreeSet<String>> acc = new HashMap<>();
        for (var e : direct.entrySet()) acc.put(e.getKey(), new TreeSet<>(e.getValue()));
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : edges.keySet()) {
                TreeSet<String> add = new TreeSet<>();
                for (String c : edges.get(caller)) {
                    var ce = acc.get(c);
                    if (ce != null) add.addAll(ce);
                }
                if (add.isEmpty()) continue;
                var set = acc.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                set.addAll(add);
                if (set.size() != before) changed = true;
            }
        }
        return acc;
    }

    /** The literal command/path a targeted call carries: the FIRST string constant pushed for its
     *  arguments (the program for `new ProcessBuilder("git","clone")` → `git`, element 0 of the varargs
     *  array; the path for `Path.of("/etc/app")`). Scans BACK from the call collecting `String` LDCs until
     *  a prior method call / jump bounds the argument block, then returns the EARLIEST — the first arg, not
     *  a trailing flag / the data of `Files.write(path, "content")`. Null if no literal. Never over-claims
     *  (SPEC §2): under-extracts a runtime-computed value rather than guessing. */
    static String firstLiteralArg(MethodNode mn, AbstractInsnNode call) {
        String found = null;
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            // Bound the back-scan at the START of THIS call's statement, so a literal from a PRIOR
            // statement is never grabbed. Without the NEW/store bounds, `new Socket(runtimeHost, 443)`
            // preceded by `String tag = "internal.metrics.svc"` captured `tag` as the host — fabricating a
            // host on a runtime-computed destination and DEFEATING the AS-EFF-008 allowlist (an attacker
            // host certified under the wrong literal). Boundaries: a prior call/branch (already), the
            // receiver's `new` (a constructor's allocation begins this statement; a real literal ARG sits
            // after the NEW/DUP so it's still captured), and a `*STORE`/PUTFIELD/PUTSTATIC ending the prior
            // statement.
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode
                    || (n instanceof TypeInsnNode && n.getOpcode() == Opcodes.NEW)
                    || (n instanceof VarInsnNode v && v.getOpcode() >= Opcodes.ISTORE
                            && v.getOpcode() <= Opcodes.ASTORE)
                    || (n instanceof FieldInsnNode fi
                            && (fi.getOpcode() == Opcodes.PUTFIELD || fi.getOpcode() == Opcodes.PUTSTATIC)))
                break;
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof String s) found = s; // keep the earliest
        }
        return found;
    }

    /** Every String literal pushed in `call`'s OWN argument window — bounded at the statement start
     *  exactly like {@link #firstLiteralArg} (a prior call/branch/NEW/`*STORE`/PUT* ends the window). Used
     *  to attribute a host/SQL literal to the SPECIFIC host/SQL-bearing call that consumes it. The old
     *  method-wide LDC sweep captured ANY host/SQL-shaped string in a host/SQL-bearing method, so a benign
     *  URL literal certified a runtime-computed host (an AS-EFF-008 gate EVASION) and a SQL-shaped log line
     *  poisoned the table allowlist. Keyed to the call's own window, a literal in another statement is
     *  never captured — mirroring candor-rust's per-classified-call `str_arg` attribution. */
    static List<String> literalArgsInWindow(AbstractInsnNode call, Map<Integer, String> constLocals) {
        List<String> out = new ArrayList<>();
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode
                    || (n instanceof TypeInsnNode && n.getOpcode() == Opcodes.NEW)
                    || (n instanceof VarInsnNode v && v.getOpcode() >= Opcodes.ISTORE
                            && v.getOpcode() <= Opcodes.ASTORE)
                    || (n instanceof FieldInsnNode fi
                            && (fi.getOpcode() == Opcodes.PUTFIELD || fi.getOpcode() == Opcodes.PUTSTATIC)))
                break;
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof String s) out.add(s);
            // Dataflow-lite: an arg that is a load of a PROVABLY-CONSTANT local (`String sql = "…"; q(sql)`)
            // resolves to its literal — the common "assign then use" shape the per-call window alone misses.
            // A load of a runtime/param local is NOT in constLocals, so the evasion stays killed (a benign
            // literal that never reaches the sink's arg slot is still never captured).
            else if (n instanceof VarInsnNode v && v.getOpcode() == Opcodes.ALOAD && constLocals.containsKey(v.var))
                out.add(constLocals.get(v.var));
        }
        return out;
    }

    /** Locals provably bound to a single String constant: an index whose EVERY `ASTORE` is fed directly by
     *  the SAME `LDC "…"`. An index ever stored a non-literal (a param, a method result, a concat) or two
     *  different literals is ambiguous and excluded — so resolving a load of one is sound (it is exactly that
     *  constant at every use). Used by {@link #literalArgsInWindow} to attribute a host/SQL literal that
     *  reaches the sink THROUGH a local, without re-introducing the method-wide over-capture. */
    static Map<Integer, String> constStringLocals(MethodNode mn) {
        Map<Integer, String> m = new HashMap<>();
        Set<Integer> ambiguous = new HashSet<>();
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof VarInsnNode v && v.getOpcode() == Opcodes.ASTORE) {
                AbstractInsnNode p = v.getPrevious();
                while (p != null && p.getOpcode() < 0) p = p.getPrevious(); // skip labels/frames/line-nos
                String s = (p instanceof LdcInsnNode ldc && ldc.cst instanceof String str) ? str : null;
                if (s == null || (m.containsKey(v.var) && !m.get(v.var).equals(s))) {
                    ambiguous.add(v.var);
                    m.remove(v.var);
                } else if (!ambiguous.contains(v.var)) {
                    m.put(v.var, s);
                }
            }
        }
        return m;
    }

    /** The literal int constant pushed closest before `call` — the port of a `(String host, int port)`
     *  Socket/InetSocketAddress ctor, for the SPEC §2 `host[:port]` surface. Null if the port is a runtime
     *  value (then no port is appended — the safe direction). Bounded to this call's arg window. */
    static String intLiteralBefore(AbstractInsnNode call) {
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            int op = n.getOpcode();
            if (op >= Opcodes.ICONST_0 && op <= Opcodes.ICONST_5) return String.valueOf(op - Opcodes.ICONST_0);
            if (n instanceof IntInsnNode iin && (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH)) return String.valueOf(iin.operand);
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof Integer i) return String.valueOf(i);
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode) break;
        }
        return null;
    }

    /** The literal PROGRAM head a subprocess call NAMES — argv[0] specifically, never a later argument.
     *  Unlike {@link #firstLiteralArg} (the earliest literal ANYWHERE in the arg window), this refuses
     *  to refine when argv[0] is a runtime value but a trailing arg happens to be a literal whose
     *  basename hits the head table: `new ProcessBuilder(tool, "curl")` / `exec(new String[]{prog,
     *  "psql"})` must NOT fabricate Net/Db — the §1 under-report rule (mirrors candor-rust gating the
     *  refinement on a program-NAMING position via `is_cmd_naming_method`). The argv[0] shape is read
     *  from the call descriptor: a leading `String` is the scalar program (`Runtime.exec("curl …")`);
     *  a leading `String[]` is a varargs/array whose ELEMENT 0 is the program (`ProcessBuilder("curl",
     *  …)`, `exec(new String[]{"curl", …})`). Returns null whenever argv[0] is not a static literal —
     *  the safe direction. Used ONLY for the effect refinement, never to widen it. */
    static String programHeadLiteral(MethodInsnNode call) {
        boolean arrayHead = call.desc.startsWith("([Ljava/lang/String;");
        boolean scalarHead = call.desc.startsWith("(Ljava/lang/String;");
        if (!arrayHead && !scalarHead) return null; // a List<String> ctor etc. names no static head
        // The call's argument-evaluation window, bounded by a prior call/branch, real insns only
        // (drop labels/line-numbers/frames so the array-store pattern below is contiguous).
        List<AbstractInsnNode> win = new ArrayList<>();
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode)
                break;
            if (n.getOpcode() >= 0) win.add(n); // skip pseudo-insns (opcode -1)
        }
        Collections.reverse(win); // evaluation order
        if (scalarHead) {
            // argv[0] is the FIRST value pushed (the instance receiver is a prior call/aload that the
            // window already excludes for the common `Runtime.getRuntime().exec(…)` form); it names a
            // program only if that first value is itself a String literal.
            if (win.isEmpty()) return null;
            AbstractInsnNode first = win.get(0);
            return (first instanceof LdcInsnNode ldc && ldc.cst instanceof String s) ? s : null;
        }
        // arrayHead: argv[0] is element 0 of the leading String[]. javac emits initializers in index
        // order, so the FIRST `ICONST_0, <elem>, AASTORE` in the window is that store — element 0 of
        // the command array (even in the two-array `exec(String[], String[] envp)` overload, where the
        // command array is built before envp). The head is static only if <elem> is a String literal.
        for (int i = 0; i + 2 < win.size(); i++) {
            if (win.get(i).getOpcode() == Opcodes.ICONST_0 && win.get(i + 2).getOpcode() == Opcodes.AASTORE) {
                AbstractInsnNode v = win.get(i + 1);
                return (v instanceof LdcInsnNode ldc && ldc.cst instanceof String s) ? s : null;
            }
        }
        return null;
    }

    /** The String literal CLOSEST to a call — its last-pushed String arg. For `getMethod("y")` the
     *  name is pushed immediately before the call, so the nearest String is unambiguously it; the
     *  loose firstLiteralArg (keep-earliest) would grab an unrelated prior constant (`String tag =
     *  "runIt"; … c.getMethod("strip")` returned "runIt" — a fabricated target). */
    static String nearestLiteralArg(MethodNode mn, AbstractInsnNode call) {
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode)
                return null;
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof String s) return s; // NEAREST
        }
        return null;
    }

    /** The receiver Class type of a reflective `X.class.getMethod("y")` — the nearest `LDC X.class`
     *  Type constant before the call (internal slash-form), bounded by a prior call/branch. Null when
     *  the receiver is a RUNTIME Class value (`obj.getClass()`, a field): then the reflection target
     *  is genuinely indeterminate and an edge MUST NOT be fabricated (the §4 Unknown stands). */
    static String reflectReceiver(MethodNode mn, AbstractInsnNode call) {
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode)
                return null; // a prior call (e.g. getClass()) or branch bounds the receiver evaluation
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof org.objectweb.asm.Type t
                    && t.getSort() == org.objectweb.asm.Type.OBJECT)
                return t.getInternalName();
        }
        return null;
    }

    /** Whether a path-constructor descriptor takes the path as a SINGLE leading String — `(String)` or
     *  `(String, String...)` (Path.of's varargs) — so the FIRST string literal is unambiguously the
     *  path. Excludes two-String overloads (`File(String,String)`, `RandomAccessFile(String,String)`)
     *  whose second String (child name / mode) could be the only literal when the path is computed. */
    static boolean pathArgIsSingleString(String desc) {
        String head = "(Ljava/lang/String;";
        return desc.startsWith(head)
                && desc.length() > head.length()
                && (desc.charAt(head.length()) == ')' || desc.charAt(head.length()) == '[');
    }

    /** The program a command literal names (`/usr/bin/git` → `git`), so `allow Exec … git` accepts an
     *  absolute path to it. Mirrors the Rust `cmd_base`, plus: `Runtime.exec(String)` passes a whole
     *  command LINE ("curl http://x"), so take the first whitespace token (the program) before the
     *  basename — `ProcessBuilder` literals are already a bare program. */
    static String cmdBase(String c) {
        String first = c.trim().split("\\s+", 2)[0];
        int i = Math.max(first.lastIndexOf('/'), first.lastIndexOf('\\'));
        return i >= 0 ? first.substring(i + 1) : first;
    }

    /** Refine the `Exec` cliff (spec §4 ⟨0.5⟩): the effects a literal, statically-known subprocess
     *  head implies, matched by basename. ADDED to a caller that already carries `Exec` (a subprocess
     *  is still spawned — `Exec` is never dropped); an unrecognised head returns {} and keeps the bare
     *  cliff (never guess). A **candor engine** reads Fs/Env only — spec §7 item 12 (the analyzer
     *  self-boundary) guarantees that, so that case is spec-supplied, not curation. The reference
     *  engines share this table verbatim so the `Exec` boundary refines identically. INVARIANT: every
     *  head is an external tool that does NOT run the analysed project's own code (so make/npm/cargo
     *  are deliberately absent — they keep the cliff). Mirrors candor-rust's `classify_command_head`. */
    static Set<String> commandHeadEffects(String cmd) {
        // Only UNAMBIGUOUS single-effect tools belong here. A multi-modal head (`git status` local vs
        // `git push` Net; `rsync` local vs remote) would FABRICATE the effect for its common case —
        // the under-report rule forbids it, so such heads keep the bare cliff.
        switch (cmdBase(cmd)) {
            case "curl": case "wget": case "http": case "ssh": case "scp":
            case "sftp": case "ftp": case "telnet":
                return Set.of("Net");
            case "psql": case "mysql": case "sqlite3": case "mongosh": case "mongo":
            case "redis-cli": case "cqlsh": case "influx":
                return Set.of("Db");
            case "candor": case "candor-run.sh": case "candor-scan": case "candor-query":
            case "candor-java": case "candor-classify": case "candor-report": case "cargo-candor":
                return Set.of("Env", "Fs"); // §7 item 12: analyzers do Fs/Env only
            default:
                return Set.of();
        }
    }

    /** Whether an allowed dir `a` covers the reached path `r` at a COMPONENT boundary (so `/etc/app`
     *  covers `/etc/app/cfg` but not `/etc/apppwned`); a `..` in the reached path is never covered.
     *  Mirrors the Rust `fs_path_covered`, including the absolute-vs-relative rootedness check. */
    static boolean pathCovered(String a, String r) {
        java.util.function.Function<String, List<String>> norm = s -> {
            List<String> out = new ArrayList<>();
            for (String c : s.split("[/\\\\]")) if (!c.isEmpty() && !c.equals(".")) out.add(c);
            return out;
        };
        if (norm.apply(r).contains("..")) return false;
        boolean aAbs = a.startsWith("/") || a.startsWith("\\");
        boolean rAbs = r.startsWith("/") || r.startsWith("\\");
        if (aAbs != rAbs) return false;
        List<String> ac = norm.apply(a), rc = norm.apply(r);
        if (ac.size() > rc.size()) return false;
        for (int i = 0; i < ac.size(); i++) if (!ac.get(i).equals(rc.get(i))) return false;
        return true;
    }

    /** Whether an allowed table entry `a` covers a reached table `r`: case-insensitive exact match
     *  on the (possibly schema-qualified) name, or a `schema.*` entry covering every table in that
     *  schema. Strict on qualification (an allowed `entries` does NOT cover `ledger.entries`).
     *  Mirrors the Rust `db_table_covered`. */
    static boolean tableCovered(String a, String r) {
        a = a.toLowerCase(); r = r.toLowerCase();
        if (a.endsWith(".*")) {
            String schema = a.substring(0, a.length() - 2);
            return r.startsWith(schema + ".");
        }
        return a.equals(r);
    }

    /** Table-position identifiers in a SQL string literal — the `Db` literal surface (SPEC §2
     *  `tables`). Conservative by construction (a wrong capture would FABRICATE): the string must
     *  open with a SQL statement keyword; only FROM/JOIN/INTO (anywhere), statement-leading
     *  UPDATE/TRUNCATE, and TABLE take the following identifier, skipping ONLY/IF NOT EXISTS;
     *  `FOR UPDATE SKIP LOCKED` yields nothing (mid-statement UPDATE ignored). Mirrors the Rust
     *  `tables_in_sql` token-for-token — SPEC §2 pins the algorithm and the cross-impl vector
     *  battery (candor-spec conformance/tables/vectors.json, run.sh Part 4b) enforces it. */
    static List<String> tablesInSql(String sql) {
        Set<String> stmt = Set.of("select", "insert", "update", "delete", "create", "drop", "alter",
                "truncate", "merge", "replace", "with");
        Set<String> skip = Set.of("only", "if", "not", "exists", "table");
        Set<String> stop = Set.of("select", "set", "where", "values", "on", "using", "group", "order",
                "by", "limit", "returning", "as", "inner", "outer", "left", "right", "cross", "lateral",
                "natural", "union", "all", "distinct", "case", "when", "null", "default", "skip",
                "nowait", "of", "from", "join", "into", "update", "delete", "insert");
        // `,` survives as its OWN token: it lets `FROM t1, t2` continue the table list without
        // fabricating from other comma-ridden positions (column lists, ON clauses).
        String cleaned = sql.toLowerCase().replaceAll("[();]", " ").replace(",", " , ");
        // "\\s+" (regex any-whitespace), NOT "\s+" — the latter is the Java 15 *space escape*, which
        // splits on literal spaces only and glues tokens across the newlines of formatted SQL.
        String[] toks = cleaned.trim().split("\\s+");
        List<String> out = new ArrayList<>();
        if (toks.length == 0 || !stmt.contains(toks[0])) return out;
        java.util.function.Function<String, String> ident = (raw) -> {
            String t = raw.replaceAll("^[\"'`]+|[\"'`]+$", "");
            if (t.isEmpty() || stop.contains(t)) return null;
            char c0 = t.charAt(0);
            if (!(Character.isLetter(c0) || c0 == '_')) return null;
            if (!t.matches("[a-z_][a-z0-9_.$\"`]*")) return null;
            return t.replaceAll("[\"`]", "");
        };
        for (int i = 0; i < toks.length; i++) {
            String tok = toks[i];
            boolean tablePos = tok.equals("from") || tok.equals("join") || tok.equals("into")
                    || tok.equals("table")
                    || ((tok.equals("update") || tok.equals("truncate")) && i == 0);
            if (!tablePos) continue;
            int j = i + 1;
            while (j < toks.length && skip.contains(toks[j])) j++;
            if (j >= toks.length) continue;
            String first = ident.apply(toks[j]);
            if (first == null) continue;
            if (!out.contains(first)) out.add(first);
            // Comma-ADJACENT continuation only: `FROM t1, t2, t3` takes all three, while an alias
            // breaks the chain (`FROM t1 a, t2` keeps just t1 — an under-report, never a guess:
            // skipping an alias to chase the comma would fabricate tables out of
            // `INSERT INTO t (a, b)`'s column list, whose parens are spaces by now).
            while (j + 2 < toks.length && toks[j + 1].equals(",")) {
                String more = ident.apply(toks[j + 2]);
                if (more == null) break;
                if (!out.contains(more)) out.add(more);
                j += 2;
            }
        }
        return out;
    }

    /** Load dependency reports named by CANDOR_DEPS (a path list — space/colon/comma-separated; a
     *  directory is scanned for *.json) into a `method-ref hash -> inferred effects` map, so a call
     *  into an already-analyzed dependency inherits its effects (candor-spec §2). Version-aware trust
     *  (§2.1): effects from a report produced by a DIFFERENT engine version are downgraded to Unknown
     *  rather than silently trusted. Unreadable/legacy-v0.1 (no hash) entries are skipped. */
    static void loadCrossDeps(String spec, String ownVersion) {
        if (spec == null || spec.isBlank()) return;
        for (String tok : spec.split("[\\s:,]+")) {
            if (tok.isBlank()) continue;
            Path p = Path.of(tok);
            List<Path> files = new ArrayList<>();
            try {
                if (Files.isDirectory(p)) {
                    try (var s = Files.walk(p)) {
                        s.filter(f -> f.toString().endsWith(".json")).forEach(files::add);
                    }
                } else if (Files.isRegularFile(p)) {
                    files.add(p);
                }
            } catch (IOException e) {
                continue;
            }
            for (Path f : files) {
                try {
                    JsonElement root = JsonParser.parseString(Files.readString(f));
                    JsonObject obj = root.isJsonObject() ? root.getAsJsonObject() : null;
                    // isJsonArray-gated reads (not getAsJsonArray, which THROWS on a non-array `functions`).
                    // A throw here was caught by the per-FILE catch below and abandoned the WHOLE report — so
                    // a single malformed field made every caller of the dep read PURE instead of the §2.1
                    // Unknown. Be resilient field-by-field and downgrade to Unknown, never silently drop.
                    JsonArray fns = obj != null && obj.has("functions") && obj.get("functions").isJsonArray()
                            ? obj.getAsJsonArray("functions")
                            : (root.isJsonArray() ? root.getAsJsonArray() : null);
                    if (fns == null) continue;
                    String depVer = null;
                    if (obj != null && obj.has("candor") && obj.get("candor").isJsonObject()) {
                        JsonElement v = obj.getAsJsonObject("candor").get("version");
                        if (v != null && v.isJsonPrimitive()) depVer = v.getAsString(); // JsonNull → null → stale
                    }
                    // A report whose version can't be VERIFIED is not trusted (§2.1) — a missing
                    // header is as untrustworthy as a mismatched one (the Rust engine's rule;
                    // /code-review found the engines split three ways on versionless reports).
                    boolean stale = depVer == null || !depVer.equals(ownVersion);
                    // File-level coverage: the producer's own package name(s) register the report's
                    // packages as COVERED even when `functions` is empty — an all-pure dep's empty
                    // report is its purity claim (SPEC §2 rule 3; the serde_json lesson). Accept BOTH
                    // the spec's singular `"package": "<name>"` (what candor-report and candor-ts
                    // emit) AND this engine's own plural `packages[]` — reading only the array meant an
                    // all-pure spec-form report was ignored and its package falsely named a blind spot.
                    if (obj != null) {
                        if (obj.has("package") && obj.get("package").isJsonPrimitive())
                            depCoveredPkgs.add(obj.get("package").getAsString());
                        if (obj.has("packages") && obj.get("packages").isJsonArray())
                            for (JsonElement x : obj.getAsJsonArray("packages"))
                                depCoveredPkgs.add(x.getAsString());
                    }
                    for (JsonElement el : fns) {
                        if (!el.isJsonObject()) continue;                 // a non-object entry → skip (not pure-able)
                        JsonObject m = el.getAsJsonObject();
                        if (!m.has("hash") || !m.get("hash").isJsonPrimitive()) continue; // v0.1 / no cross-jar id
                        String h = m.get("hash").getAsString();
                        if (h.isBlank()) continue;
                        DepFn de = new DepFn();
                        if (stale) {
                            de.effects.add("Unknown");
                        } else {
                            // `inferred` present but MALFORMED (JsonNull / a string / an object, or a
                            // non-string element) is an untrustworthy claim → Unknown, never silently dropped
                            // (the §2.1 contract: a corrupt same-version report ≠ pure). A clean array of
                            // strings reads its effects; a genuinely ABSENT inferred field stays pure.
                            if (m.has("inferred") && m.get("inferred").isJsonArray()) {
                                for (JsonElement x : m.getAsJsonArray("inferred"))
                                    if (x.isJsonPrimitive()) de.effects.add(x.getAsString());
                                    else de.effects.add("Unknown");
                            } else if (m.has("inferred") && !m.get("inferred").isJsonNull()) {
                                de.effects.add("Unknown");
                            } else if (m.has("inferred")) {
                                de.effects.add("Unknown"); // inferred: null → untrusted
                            }
                            for (var pair : List.of(Map.entry("hosts", de.hosts), Map.entry("cmds", de.cmds),
                                    Map.entry("paths", de.paths), Map.entry("tables", de.tables)))
                                if (m.has(pair.getKey()) && m.get(pair.getKey()).isJsonArray())
                                    for (JsonElement x : m.getAsJsonArray(pair.getKey()))
                                        pair.getValue().add(x.getAsString());
                        }
                        if (!de.effects.isEmpty()) crossDeps.put(h, de);
                        // Entry-level coverage fallback (reports with no package field): the hash's
                        // package prefix gives the EXACT package. The spec join key is `pkg#qual`
                        // (Rust/TS) — take what's before `#`; this engine's own hash is the
                        // slash-form `owner/Class.method(desc)`, so fall back to the last `/`.
                        int hashSep = h.indexOf('#');
                        if (hashSep > 0) {
                            depCoveredPkgs.add(h.substring(0, hashSep));
                        } else {
                            int slash = h.lastIndexOf('/');
                            if (slash > 0) depCoveredPkgs.add(h.substring(0, slash).replace('/', '.'));
                        }
                    }
                } catch (Exception ex) {
                    // skip unreadable / unparseable dependency reports (like the Rust impl)
                }
            }
        }
    }

    static class BaseEntry { String fn; List<String> inferred; }

    static Map<String, Set<String>> loadBaseline(String path) {
        try {
            String text = Files.readString(Path.of(path));
            // Accept BOTH the v0.2 self-describing envelope `{ candor, functions:[...] }` and the legacy
            // v0.1 bare array `[...]` — the migration contract (candor-spec §2: readers MUST accept both).
            JsonElement root = JsonParser.parseString(text);
            JsonArray arr = root.isJsonObject()
                    ? root.getAsJsonObject().getAsJsonArray("functions")
                    : (root.isJsonArray() ? root.getAsJsonArray() : null);
            if (arr == null) return null;
            List<BaseEntry> entries = new Gson().fromJson(arr, new TypeToken<List<BaseEntry>>() {}.getType());
            Map<String, Set<String>> m = new HashMap<>();
            for (BaseEntry e : entries) if (e.fn != null) m.put(e.fn, new HashSet<>(e.inferred == null ? List.of() : e.inferred));
            return m;
        } catch (Exception ex) {
            return null;
        }
    }

    /** Whether a CANDOR_* gate scope covers a dotted method/class name. The `1`/empty value is the
     *  whole-project flag; any other value is a real scope, matched through {@link #scopeMatches} so the
     *  gate scopes are SEGMENT- and `::`-aware exactly like the §6.2 policy gate. The old raw `startsWith`
     *  silently diverged — a `::`-written or non-prefix scope disabled the gate (a false PASS on a real
     *  ambient/strict violation) AND prefix-bled (`com.foo` matched `com.foobar`). */
    static boolean gateScopeCovers(String scope, String dottedName) {
        return scope.equals("1") || scope.isEmpty() || scopeMatches(dottedName, scope);
    }

    static List<ClassNode> load(Path root) throws IOException {
        List<ClassNode> out = new ArrayList<>();
        // A `.jar`/`.zip` is an ARCHIVE, not a directory: `Files.walk` over it yields only the archive
        // file itself (no `.class` entries), so the loader silently returned ZERO classes from a jar —
        // despite the usage advertising `<dir-or-jar-of-classes>`. Mount it as a zip filesystem and walk
        // its entries, so analysing a built jar / a dependency actually works.
        String name = root.toString().toLowerCase();
        if (Files.isRegularFile(root) && (name.endsWith(".jar") || name.endsWith(".zip"))) {
            try (FileSystem fs = FileSystems.newFileSystem(root)) {
                for (Path r : fs.getRootDirectories()) collectClasses(r, out);
            }
        } else {
            collectClasses(root, out);
        }
        return out;
    }

    static void collectClasses(Path root, List<ClassNode> out) throws IOException {
        int[] skipped = {0};
        String[] firstErr = {null};
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class"))::iterator) {
                // A MULTI-RELEASE jar ships version-specific overrides under META-INF/versions/<N>/; analyse
                // the BASE classes (the runtime picks the override; the base is the portable surface) and
                // skip the versioned copies — they are duplicates of the same class, and the newest ones may
                // be a bytecode version even a current ASM can't read.
                if (p.toString().replace('\\', '/').contains("/META-INF/versions/")) continue;
                // TOLERATE a class ASM can't parse (a future-major-version class, a corrupt entry): skip it
                // and DISCLOSE the count, never ABORT the whole scan on one bad class (the old behaviour —
                // one Java-25 entry in a multi-release jar threw IllegalArgumentException and killed the run).
                try {
                    ClassNode cn = new ClassNode();
                    new ClassReader(Files.readAllBytes(p)).accept(cn, 0);
                    out.add(cn);
                } catch (Exception | LinkageError e) {
                    skipped[0]++;
                    if (firstErr[0] == null) firstErr[0] = p.getFileName() + ": " + e.getMessage();
                }
            }
        }
        if (skipped[0] > 0) {
            System.err.println("candor-java: skipped " + skipped[0] + " unparseable class file(s) — their effects are"
                + " INVISIBLE, not analysed (e.g. " + firstErr[0] + "). A newer bytecode version may need an ASM bump.");
        }
    }

    /** Identify Spring Data repositories (effect: Db) and @FeignClient interfaces (Net). */
    static void computeSpringTypes(List<ClassNode> classes) {
        for (ClassNode cn : classes) if (annoPresent(cn.visibleAnnotations, FEIGN)) feignTypes.add(cn.name);
        // JPA entity tables: the literal @Table(name="…") (javax or jakarta persistence).
        for (ClassNode cn : classes) {
            if (cn.visibleAnnotations == null) continue;
            for (AnnotationNode a : cn.visibleAnnotations) {
                if (a.desc == null || !a.desc.contains("persistence/Table") || a.values == null) continue;
                for (int i = 0; i + 1 < a.values.size(); i += 2)
                    if ("name".equals(a.values.get(i)) && a.values.get(i + 1) instanceof String t && !t.isBlank())
                        entityTables.put(cn.name, t);
            }
        }
        boolean changed = true;
        while (changed) {
            changed = false;
            for (ClassNode cn : classes) {
                if (repoTypes.contains(cn.name) || cn.interfaces == null) continue;
                for (String itf : cn.interfaces) {
                    if (REPO_MARKERS.contains(itf) || repoTypes.contains(itf) || isSpringDataRepoBase(itf)) {
                        repoTypes.add(cn.name);
                        changed = true;
                        break;
                    }
                }
            }
        }
        // A repository's entity is its FIRST generic argument (`extends CrudRepository<User, Long>`):
        // read it from the interface's generic signature and join with the entity's declared table.
        for (ClassNode cn : classes) {
            if (!repoTypes.contains(cn.name) || cn.signature == null) continue;
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("<L([^;<]+);").matcher(cn.signature);
            if (m.find()) {
                String table = entityTables.get(m.group(1));
                if (table != null) repoTables.put(cn.name, table);
            }
        }
    }

    static void analyze(ClassNode cn) {
        String dottedClass = cn.name.replace('/', '.');
        boolean classTx = annoPresent(cn.visibleAnnotations, TX);
        // Runtime-invoked overrides this class is eligible for: the RUNTIME_OVERRIDES rows whose
        // supertype-substring appears in this class's supertype chain (computed once per class). A
        // matching method declared here is then an entry point — the runtime invokes it, not project code.
        Set<String> supers = transSupers(cn.name);
        List<String[]> runtimeRows = RUNTIME_OVERRIDES.stream()
                .filter(r -> supers.stream().anyMatch(s -> supertypeMatches(s, r[0])))
                .toList();
        // Ktor route handler: a Kotlin suspend-lambda (`extends SuspendLambda`) whose receiver is a Ktor
        // request context (`io.ktor.server.routing.RoutingContext` in 3.x, `io.ktor.util.pipeline.
        // PipelineContext` in 2.x) — i.e. a `get("/x") { … }` body. Ktor invokes it from its request
        // pipeline with NO project call site (the lambda is registered, then run later on another thread),
        // so it's orphaned from reachability — the Kotlin analog of Spring @*Mapping, but a lambda with no
        // annotation/supertype marker. The tell: a method whose descriptor carries a Ktor context PARAMETER
        // (the erased generic is concrete on the `invoke` bridge). Mark this class's body method.
        boolean ktorHandler = supers.contains("kotlin/coroutines/jvm/internal/SuspendLambda")
                && cn.methods.stream().anyMatch(m ->
                        m.desc.contains("io/ktor/server/routing/RoutingContext")
                                || m.desc.contains("io/ktor/util/pipeline/PipelineContext"));
        for (MethodNode mn : cn.methods) {
            // Constructors (`<init>`) AND static initializers (`<clinit>`) are both analyzed: a `new X()`
            // edges to `X.<init>`, and a class-load trigger (`new`, a static call, a static field access)
            // edges to `X.<clinit>` (see below), so an effectful constructor OR static initializer
            // propagates to its use site instead of being silently pure.
            String id = methodId(dottedClass, mn.name, mn.desc);
            var dir = direct.computeIfAbsent(id, k -> new TreeSet<>());
            edges.computeIfAbsent(id, k -> new HashSet<>());
            loc.putIfAbsent(id, cn.sourceFile + ":" + firstLine(mn));
            // Stable, descriptor-bearing cross-jar identity (candor-spec §2 `hash`): the exact ref a
            // call site in a dependent jar uses, so that jar can inherit this method's effects.
            hashOf.putIfAbsent(id, cn.name + "." + mn.name + mn.desc);

            // A `native` method has no bytecode body — its JNI implementation could perform ANY effect,
            // exactly the opacity reflection has. Honest `Unknown`, never silent-pure (SPEC §4); else a
            // call into a project-declared native binding would look like a no-op.
            if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
                dir.add("Unknown");
                unknownWhy.computeIfAbsent(id, k -> new TreeSet<>()).add("native:" + mn.name);
            }

            // Spring annotations on this method (the effect Spring's proxy/generated code performs).
            if (classTx || annoPresent(mn.visibleAnnotations, TX)) dir.add("Db");
            // META-ANNOTATION aware: a method carrying a COMPOSED annotation (Spring's stereotype idiom —
            // `@GetMapping` is itself `@RequestMapping`; a team's `@ApiEndpoint`/`@NightlyJob` wraps a known
            // marker) was NOT rooted by a direct-annotation-only check, orphaning a framework-invoked method
            // from every reachability root (silent-pure for a blast-radius / --agents walk). Resolve the
            // annotation type's own meta-annotations recursively.
            if (annoOrMetaMatches(mn.visibleAnnotations, ROOT_ANNOTATIONS))
                entryPoints.add(id);
            // CDI observer method: `void onX(@Observes Event e)` is invoked by the CDI container when the
            // event fires, with NO project call site (the @EventListener shape). Unlike the mappings the
            // marker is a PARAMETER annotation, so the method-annotation path above misses it — scan the
            // per-parameter annotation lists. Covers javax/ + jakarta/ enterprise.event.Observes(Async).
            if (anyParamAnnoMatches(mn, PARAM_ROOT_ANNOTATIONS))
                entryPoints.add(id);
            // gRPC service handler: a project class extends a generated `*ImplBase` and overrides an RPC
            // method whose signature carries an `io.grpc.stub.StreamObserver` — invoked by the gRPC server
            // runtime with no in-project call site. RUNTIME_OVERRIDES can't key on it (the RPC method names
            // are arbitrary) and the generated base isn't on candor's classpath (transSupers can't see
            // `BindableService`), so key on the `*ImplBase` direct super + the StreamObserver-param signature
            // — both gRPC-specific, so no fabrication.
            if (cn.superName != null && cn.superName.toLowerCase().contains("grpc")
                    && cn.superName.endsWith("ImplBase")
                    && mn.desc.contains("Lio/grpc/stub/StreamObserver;")
                    && (mn.access & (Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT)) == 0)
                entryPoints.add(id);
            // A `finalize()` override is run by the GC's finalizer thread — NOT by any bytecode call.
            // It's the JVM analog of Rust's implicit-Drop hole: an effect (a socket/file opened on
            // collection) that otherwise sits in finalize's own entry but is unreachable from any root,
            // so a "what does this program perform" walk from entry points silently misses it. Unlike
            // Rust we can't attribute it to a drop SITE (finalization is non-deterministic and runs on a
            // detached thread), so the honest model is the runtime-invoked entry point it actually is.
            if (mn.name.equals("finalize") && mn.desc.equals("()V") && (mn.access & Opcodes.ACC_STATIC) == 0)
                entryPoints.add(id);
            // Serialization callbacks (readObject/writeObject/readExternal/writeExternal/readResolve/
            // writeReplace/readObjectNoData) are invoked REFLECTIVELY by ObjectInput/OutputStream during
            // (de)serialization — no project call site, so an effect (custom read/write doing I/O, a
            // resource opened on resolve, decryption) is orphaned from every reachability root: the
            // finalize shape. Mark them as runtime-invoked entry points, GATED on the class being
            // Serializable/Externalizable so a same-named method on an unrelated class isn't fabricated.
            if ((mn.access & Opcodes.ACC_STATIC) == 0
                    && (supers.contains("java/io/Serializable") || supers.contains("java/io/Externalizable"))
                    && isSerializationCallback(mn.name, mn.desc))
                entryPoints.add(id);
            // The program entry `public static void main(String[])` — the JVM invokes it to start the app,
            // the root of a CLI tool's reachability (candor-spec §2, like the Rust impl's `fn main`).
            if (mn.name.equals("main") && mn.desc.equals("([Ljava/lang/String;)V")
                    && (mn.access & Opcodes.ACC_STATIC) != 0)
                entryPoints.add(id);
            // A runtime-invoked override (Runnable/Thread/Callable task body, Spring lifecycle hook,
            // servlet/filter/listener) — invoked by the runtime with NO project call site, so its I/O
            // would otherwise be orphaned from every reachability root (the finalize shape). A null
            // descriptor matches by method name alone (servlet methods carry javax/jakarta param types).
            for (String[] r : runtimeRows)
                if (mn.name.equals(r[1]) && (r[2] == null || mn.desc.equals(r[2]))) {
                    entryPoints.add(id);
                    break;
                }
            // The Ktor handler's BODY is `invokeSuspend` (the suspend-lambda's state machine); `invoke` is
            // the bridge that drives it. Mark the body so its effects become a reachability root.
            if (ktorHandler && (mn.name.equals("invokeSuspend") || mn.name.equals("invoke")))
                entryPoints.add(id);

            // AS-EFF-007 taint pass (CANDOR_TAINT): a per-method dataflow whose frames tell us, at each
            // effect call below, whether an argument is parameter-derived. Skipped without the mode, and on
            // bodiless or malformed methods — taint is advisory, so a failed analysis must never crash.
            Frame<TaintValue>[] taintFrames = null;
            if (taintEnabled && mn.instructions.size() > 0
                    && (mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) == 0) {
                try {
                    taintFrames = new Analyzer<>(new TaintInterpreter(paramSlots(mn))).analyze(cn.name, mn);
                } catch (Throwable t) { taintFrames = null; }
            }

            // Receiver-provenance pass (SOUNDNESS, always-on): tells us at each invokevirtual below whether
            // the receiver is PROVABLY a single `new T`. If so, the dispatch narrows to the one method T
            // resolves — no CHA sibling fan-out (the monomorphic-fabrication fix). Anything else (param,
            // field, return, branch-merged type → genuinely polymorphic) keeps the full CHA over-
            // approximation. Like the taint pass it is fail-soft: a bodiless/native/abstract method, or any
            // analyzer failure, leaves `provFrames` null and the dispatch keeps the CHA exactly as before.
            Frame<ProvValue>[] provFrames = null;
            if (mn.instructions.size() > 0
                    && (mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) == 0) {
                try {
                    provFrames = new Analyzer<>(new ProvInterpreter()).analyze(cn.name, mn);
                } catch (Throwable t) { provFrames = null; }
            }

            // Host/table literals are extracted PER host/SQL-bearing CALL (from each call's own argument
            // window — see literalArgsInWindow at the call sites below), not by a method-wide LDC sweep.
            // The per-call attribution mirrors candor-rust's `str_arg` and kills the AS-EFF-008 evasion
            // where a benign URL literal in a host-bearing method certified a runtime-computed host. The
            // const-local map lets the window resolve a literal that reaches the sink through a local.
            Map<Integer, String> constLocals = constStringLocals(mn);
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode min) {
                    String owner = min.owner.replace('/', '.');
                    String effect = classify(owner, min.name, min.desc);
                    if (effect != null) dir.add(effect);
                    // Executor hand-off: `es.submit(task)`/`execute`/`schedule*` and `new Thread(task)` invoke
                    // the task's run()/call() OUTSIDE project code. A fresh `new R()` (the NEW-site edge
                    // attributes R.run) or an inline lambda (edged at its indy) is already captured; an OPAQUE
                    // task — a field, a param, a factory return — has an unknown body, so the handing-off
                    // method must read Unknown (parallel to an unpinned `task.run()`), else it is silent-pure.
                    if (isExecutorHandoff(min.owner, min.name, min.desc) && provFrames != null) {
                        ProvValue task = handoffTaskArg(provFrames[mn.instructions.indexOf(min)], min);
                        if (task != null && !task.fromIndy && task.newType == null) {
                            dir.add("Unknown");
                            unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                                    .add("task-handoff:" + owner + "." + min.name);
                        }
                    }
                    if (owner.equals("java.lang.Class")
                            && (min.name.equals("getMethod") || min.name.equals("getDeclaredMethod"))) {
                        // Capture the literal method NAME (nearest String, not an unrelated earlier
                        // constant) AND the RECEIVER class (the `X.class` literal). The edge is only
                        // formed in resolution when the receiver is a project class — never a global
                        // leaf-name match that fabricates an edge to an unrelated same-named method.
                        String lit = nearestLiteralArg(mn, min);
                        String recv = reflectReceiver(mn, min);
                        if (lit != null) reflectPairs.add(new String[] { id, lit, recv == null ? "" : recv });
                    }
                    // κ ledger: key external owners by their EXACT package (the slash-form owner
                    // up to the class segment — no uppercase heuristic, which mangled lowercase/
                    // obfuscated classes); array owners ([Ljava/lang/String; — every enum's
                    // values() clone) are types, not packages, and stay out. A package with zero
                    // classifications anywhere in the scan is a named blind spot.
                    if (!projectClasses.contains(min.owner) && min.owner.charAt(0) != '[') {
                        int slash = min.owner.lastIndexOf('/');
                        String pkg = slash > 0 ? min.owner.substring(0, slash).replace('/', '.') : "";
                        if (!pkg.isEmpty() && !kappaCovers(pkg)) {
                            kappaSeen.merge(pkg, 1, Integer::sum);
                            if (effect != null) kappaClassified.add(pkg);
                        }
                    }
                    // An injection-class effect on a caller-derived argument is an injection surface.
                    if (taintFrames != null && effect != null && INJECTION.contains(effect)
                            && argsTainted(taintFrames[mn.instructions.indexOf(min)], min))
                        tainted.computeIfAbsent(id, k -> new TreeSet<>()).add(effect);
                    if ("Unknown".equals(effect)) // reflection / dynamic invoke (classify §)
                        unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                                .add("reflect:" + owner + "." + min.name);
                    if ("Fs".equals(effect)) { // non-breaking read/write refinement of Fs
                        List<String> k = fsKind(owner, min.name);
                        if (!k.isEmpty()) fsDirect.computeIfAbsent(id, x -> new TreeSet<>()).addAll(k);
                    }
                    // AS-EFF-008 literal surfaces (SPEC §2 `cmds`/`paths`): the subprocess program and the
                    // file path, read from the FIRST string-literal arg of the call that carries it — the
                    // ProcessBuilder/Runtime.exec command, the Path.of / File / file-stream ctor path.
                    if ((owner.equals("java.lang.ProcessBuilder") && min.name.equals("<init>"))
                            || (owner.equals("java.lang.Runtime") && min.name.equals("exec"))) {
                        // Only the program HEAD (argv[0]) names the command — a later argument is DATA
                        // (§4; mirrors candor-rust's is_cmd_naming_method). `programHeadLiteral` reads
                        // argv[0] specifically; the loose `firstLiteralArg` would grab a trailing literal
                        // (`new ProcessBuilder(toolVar, "curl")` → "curl"), fabricating a `cmds` head and
                        // letting `allow Exec curl` spuriously pass on a DYNAMIC head. Both the literal
                        // capture AND the cliff refinement (spec §4 ⟨0.5⟩: `curl`→Net, `candor`→Fs/Env)
                        // therefore key off argv[0]; a dynamic head keeps the bare Exec cliff with no
                        // `cmds`. Exec itself is emitted unconditionally below — only the literal tightens.
                        String head = programHeadLiteral(min);
                        if (head != null) {
                            cmdsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(head);
                            dir.addAll(commandHeadEffects(head));
                        }
                    }
                    // …only the overload whose path is a SINGLE leading String arg (descriptor
                    // `(Ljava/lang/String;)` or `(Ljava/lang/String;[…` for Path.of's varargs). A
                    // two-String ctor — `RandomAccessFile(String,String)`, `File(String,String)` — can
                    // have a NON-path literal as its only constant (a `"r"`/`"rw"` mode, a child name)
                    // when the path itself is runtime-computed, which firstLiteralArg would then grab.
                    if (((owner.equals("java.nio.file.Path") && min.name.equals("of"))
                            || (owner.equals("java.nio.file.Paths") && min.name.equals("get"))
                            || (PATH_CTOR_OWNERS.contains(owner) && min.name.equals("<init>")))
                            && pathArgIsSingleString(min.desc)) {
                        String p = firstLiteralArg(mn, min);
                        if (p != null) pathsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(p);
                    }
                    // A bare-hostname Net endpoint: `new Socket("api.stripe.com", 443)` /
                    // `new InetSocketAddress("api.stripe.com", 443)` names the host as a STRING argv[0]
                    // with a numeric port — but as a bare hostname (no scheme/`:port`) netHostLiteral
                    // rejects it (deliberately, to avoid the ~14 false dotted "hosts" a loose filter
                    // produced). Here the CALL SITE disambiguates: a `(String host, int port)` ctor's
                    // first String literal IS a host, so extract it without loosening netHostLiteral.
                    // Gated to the `(Ljava/lang/String;I…` shape, so the `(InetAddress,int)` and
                    // `(String,int,InetAddress,int)`-with-computed-host overloads add nothing.
                    if ((owner.equals("java.net.Socket") || owner.equals("java.net.InetSocketAddress"))
                            && min.name.equals("<init>") && min.desc.startsWith("(Ljava/lang/String;I")) {
                        String h = firstLiteralArg(mn, min);
                        // The host must look like a host (a dotted name / IPv4), not e.g. a "localhost"
                        // bareword that could equally be anything — reuse hostPart's shape via a dot test,
                        // matching netHostLiteral's "contains a dot" gate for bare host:port.
                        if (h != null && h.contains(".") && !h.contains("/") && !h.contains(" ")) {
                            // Append the literal int port for `host:port` (SPEC §2) — so a two-arg
                            // Socket("h", 443) matches the URL form's `h:port` and candor-scan, instead of
                            // dropping the statically-known port (adversarial coverage-gap review, GAP2).
                            String port = intLiteralBefore(min);
                            hostsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(port != null ? h + ":" + port : h);
                        }
                    }
                    // Host literal from THIS host-bearing call's OWN argument (a URL/URI string, a Spring/
                    // ktor request URL) — per-call attribution mirroring candor-rust's `str_arg`. Replaces
                    // the old method-wide LDC sweep, which captured any host-shaped string in a host-bearing
                    // method and so let a benign URL literal certify a runtime-computed host (AS-EFF-008
                    // evasion) / a never-contacted host poison the allowlist. netHostLiteral rejects
                    // non-hosts, so a benign non-URL arg adds nothing; the bare `Socket(host,port)` case is
                    // handled above (netHostLiteral rejects a scheme-less bare host by design).
                    if (isHostBearingOwner(min.owner) && min.desc.contains("Ljava/lang/String;"))
                        for (String lit : literalArgsInWindow(min, constLocals)) {
                            String hl = netHostLiteral(lit);
                            if (hl != null) hostsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(hl);
                        }
                    // Table literals from THIS SQL-bearing call's OWN argument (the executed/prepared SQL) —
                    // same per-call attribution. tablesInSql needs a leading SQL keyword so a non-SQL arg
                    // yields nothing; a SQL-shaped log line in another statement is no longer mis-attributed.
                    if (isSqlBearingOwner(min.owner) && min.desc.contains("Ljava/lang/String;"))
                        for (String lit : literalArgsInWindow(min, constLocals)) {
                            List<String> tl = tablesInSql(lit);
                            if (!tl.isEmpty()) tablesDirect.computeIfAbsent(id, x -> new TreeSet<>()).addAll(tl);
                        }
                    // Calls to a Spring Data repository / Feign client are I/O even though the
                    // callee has no body candor can see (Spring synthesizes the impl at runtime).
                    boolean springTyped = repoTypes.contains(min.owner) || feignTypes.contains(min.owner);
                    if (repoTypes.contains(min.owner)) {
                        dir.add("Db");
                        String tbl = repoTables.get(min.owner); // the declarative `tables` surface
                        if (tbl != null) tablesDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(tbl);
                    }
                    if (feignTypes.contains(min.owner)) dir.add("Net");

                    int op = min.getOpcode();
                    // A static call triggers the owner's class-load → its `<clinit>` runs.
                    if (op == Opcodes.INVOKESTATIC) clinitEdge(id, min.owner);
                    if (op == Opcodes.INVOKEVIRTUAL || op == Opcodes.INVOKEINTERFACE) {
                        // EXEMPT (SPEC §4): dispatch on the conventionally-pure java.lang.Object
                        // surface — toString/hashCode/equals (+ erased Comparable.compareTo) — is NOT
                        // CHA-fanned-out. Over `Object`, EVERY project class is a subtype, so one
                        // `x.toString()` would edge every override in the jar; Kotlin emits exactly
                        // that (`Any.toString` in string templates), which made kotlinx-coroutines
                        // attribute one ServiceLoader-touching toString to 2160 methods (87% of the
                        // jar). Same C2 trade as the Rust engine's dyn-Display/Error exemption — and
                        // the documented caveat: an override of these that performs real I/O (that
                        // kotlinx toString DOES reach a service load) is deliberately not attributed
                        // at the dispatch site.
                        // Class Hierarchy Analysis: dispatch reaches any project subtype's override.
                        // BOUNDED for a CHA-EXEMPT method (the conventionally-pure Object protocol +
                        // the function-interface / task-dispatch verbs every lambda/closure/Runnable
                        // implements): attribute when the receiver resolves to FEW impls (a concrete
                        // project type, an app's handful of Runnables — precise), but DROP the fan-out
                        // when it's broad (a library's hundreds of FunctionN/Closure impls — the
                        // kotlinx/scala/groovy smear that connected ~87% of a jar to one source). The
                        // runtime-invoked verbs' bodies stay reachable via RUNTIME_OVERRIDES entry
                        // points (incl. the function-interface rows) so a named implementor isn't
                        // orphaned. (The smear, plus the four soundness holes an UNCONDITIONAL skip
                        // opened — concrete-receiver toString, named-implementor orphaning, synchronous
                        // Runnable.run, all caller-attribution — were found by /code-review max.)
                        boolean dispatchExempt = isChaExemptMethod(min.owner, min.name, min.desc);
                        // SOUNDNESS — monomorphic-receiver narrowing: if the receiver is PROVABLY a single
                        // `new T` (the provenance pass above), this dispatch resolves to exactly the one
                        // method T invokes — NOT its CHA siblings. `b = new Base(); b.compute()` must read
                        // Base.compute alone, never the sibling Dirty.compute's Net. We narrow ONLY when the
                        // receiver is provably a single new-type AND that type resolves a concrete impl in
                        // its own chain; ANY other receiver (param/field/return/branch-merged → genuinely
                        // polymorphic) falls through to the unchanged CHA over-approximation below, so a real
                        // polymorphic effect is never lost. INVOKEINTERFACE is included: a provable `new T`
                        // under an interface call still dispatches to T's concrete impl.
                        String monoRecv = monomorphicReceiver(provFrames == null ? null
                                : provFrames[mn.instructions.indexOf(min)], min);
                        if (monoRecv != null && byName.containsKey(monoRecv)) {
                            // A provably-monomorphic PROJECT receiver (`new T`) has NO polymorphic siblings,
                            // so this resolves to exactly T's method — never its CHA subtypes. `b = new
                            // Base(); b.compute()` must read Base.compute alone, not the sibling Dirty's Net.
                            // No concrete impl in T's own chain (impl in an unloaded super) → an ordinary
                            // external call (no edge). Either way: resolved locally, so skip CHA, the Unknown
                            // branches, AND cross-dep (a project call traces locally, never inherits a dep).
                            String monoTarget = monomorphicTarget(monoRecv, min.name, min.desc);
                            if (monoTarget != null) edges.get(id).add(monoTarget);
                            continue;
                        }
                        // CHA runs ONLY for a genuinely POLYMORPHIC receiver (monoRecv == null). An EXTERNAL
                        // monoRecv (`new java.util.ArrayList<>()`) is PROVABLY that exact type, never a
                        // project subtype, so CHA fan-out would FABRICATE: once transSupers files a `class
                        // LoudList extends ArrayList { add(){…io…} }` under ArrayList, an unguarded fan-out
                        // smears LoudList's effect onto every plain `new ArrayList().add()`. Skip CHA for it
                        // — but DON'T `continue`: fall through to the cross-jar inheritance block below, since
                        // the call is into an external/dependency method that may carry recorded effects.
                        if (monoRecv == null) {
                        List<String> cha = chaTargets(min.owner, min.name, min.desc);
                        // BOUNDED CHA (SPEC §4): a dispatch over a local abstraction resolves to its
                        // implementors only when the fan-out is NARROW (≤ CHA_FANOUT_LIMIT); a broad
                        // fan-out is honest indeterminacy. Previously only EXEMPT methods (the pure
                        // Object protocol) were bounded, so a non-exempt collection method (`isEmpty`/
                        // `size`/`next`) over a deep hierarchy (scala-library: hundreds of impls) edged
                        // to EVERY override and connected ~everything to a few effect sources — a
                        // ThreadLocalRandom in one TrieMap.computeSize flooded 13k functions with Rand.
                        boolean broad = cha.size() > CHA_FANOUT_LIMIT;
                        // A NARROW java.util container-iteration dispatch (Iterator.next / Iterable etc.)
                        // DOES fan out: skipping it under-reported a custom Iterable's effect at the loop
                        // site (`for (x : customBag)` came back pure) — the §7.13 fuzzer's for-each form
                        // catches it. The jts Rand "smear" the skip avoided is sound over-approximation, not
                        // a reason to drop a real reachable effect; a broad fan-out still drops to Unknown.
                        List<String> targets = broad ? List.of() : cha;
                        edges.get(id).addAll(targets);
                        // A broad NON-exempt dispatch that DROPS project implementors → Unknown, not
                        // silent-pure (an effectful body could be among the many we just dropped; exempt
                        // methods are conventionally pure / runtime-entry, so they drop to nothing without
                        // Unknown). The discriminator is "are we dropping PROJECT impls whose effects we'd
                        // otherwise have propagated" — i.e. `cha` is non-empty — NOT "is the OWNER a project
                        // type". `chaTargets` only ever returns project-defined CONCRETE bodies (it scans
                        // byName, which holds project classes alone), so a non-empty `cha` IS that signal.
                        // The owner can be an EXTERNAL interface (java.util.function.Supplier, Runnable,
                        // Callable, java.util.List…) the project has ≥13 implementors of: bounded CHA drops
                        // the whole fan-out, and the old `isProjectIfaceOrAbstract(min.owner)` gate was
                        // FALSE for the external owner, so the caller went silently pure even though one of
                        // the dropped project bodies wrote a file (the cardinal soundness sin). We preserve
                        // the curated-κ posture for UBIQUITOUS stdlib dispatch (List.add / Iterator.next on
                        // stdlib-only impls): there `cha` is EMPTY (no project class declares the body), so
                        // no Unknown floods — they contribute nothing. (Found by /code-review max: 13+
                        // project Suppliers, one effectful, over a single dispatch site.)
                        // The exemption that suppresses this Unknown is ONLY the Object-protocol subset
                        // (toString/hashCode/equals/compareTo — §4 pure even when overridden). The
                        // function-object exemptions (Kotlin/Scala/Groovy invoke/apply/call) do NOT suppress
                        // it: when the broad fan-out DROPS NAMED project impls (`!cha.isEmpty()`), one of
                        // them can do real I/O, so honest Unknown — not silent-pure (the round-11 hole). This
                        // INCLUDES a broad fan-out over synthetic Kotlin/Scala/Groovy LAMBDA classes: their
                        // invoke()/apply() body is reachable ONLY through this dispatch edge (a `new Lam()`
                        // edges <init>, NOT invoke — unlike a Java indy lambda whose body is edged at the indy
                        // site), so suppressing the Unknown here AND dropping the edge made an effectful lambda
                        // SILENT-PURE (a round-12 chaImplsAllSynthetic regression — reverted). A >12-lambda
                        // higher-order site reporting Unknown is the SOUND over-approximation (the dispatcher
                        // invokes an unresolvable function), not a bug; the precise effects are still captured
                        // at each lambda's own rooted invoke() entry (the kotlin/Function RUNTIME_OVERRIDES row).
                        if (broad && !isObjectProtocolExempt(min.name, min.desc) && effect == null && !springTyped
                                && (isProjectIfaceOrAbstract(min.owner) || !cha.isEmpty())) {
                            dir.add("Unknown");
                            String why = isProjectIfaceOrAbstract(min.owner)
                                    ? "dispatch-broad:" + owner + "." + min.name
                                    : "dispatch-broad-ext:" + owner + "." + min.name;
                            unknownWhy.computeIfAbsent(id, k -> new TreeSet<>()).add(why);
                        }
                        // Genuine unresolved dispatch: a PROJECT interface/abstract type that DECLARES
                        // this method, with no visible concrete impl (DI-wired, external, or strategy)
                        // → honest Unknown (SPEC §4). The `projectDeclaresMethod` gate is essential:
                        // without it, a FRAMEWORK method merely INHERITED by a project abstract class
                        // (Struts `Action.getServletContext`/`saveMessages`/`isTokenValid`, called on a
                        // NEMsAction receiver) has no project override either, and would be mislabelled
                        // Unknown — when it actually resolves to a superclass candor never loaded, i.e.
                        // an ordinary external call (effect-free unless modelled, like every other lib
                        // call). Only a method the project ITSELF declares is a real missing-impl. An
                        // exempt method never raises Unknown (it's conventionally pure, or its body is a
                        // runtime-invoked entry point).
                        if (!broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                                && isProjectIfaceOrAbstract(min.owner)
                                && projectDeclaresMethod(min.owner, min.name, min.desc)) {
                            dir.add("Unknown");
                            unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                                    .add("dispatch:" + owner + "." + min.name);
                        }
                        // A JDK FUNCTIONAL-INTERFACE SAM (`Runnable.run`, `Callable.call`,
                        // `java.util.function.*`) invoked on an UNPINNED receiver with EMPTY CHA — the only
                        // implementors are lambdas/method-refs whose bodies aren't reachable from THIS call
                        // site (a field-stored handler `this.cb.run()`, a passed-in callback `h.run()`).
                        // Both gates above miss it: empty CHA is never "broad" (so the broad-ext gate skips),
                        // and the external functional-interface owner isn't a project iface (so the
                        // missing-impl gate skips) — leaving the caller SILENTLY PURE though the lambda can
                        // perform any effect (the 0.5.5 task_unpinned fuzzer used NAMED types, so it was
                        // blind to the lambda-only case). Honest Unknown. Stdlib non-functional dispatch
                        // (`list.size()`, `map.get()`) is unaffected — those owners aren't functional SAMs.
                        if (!broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                                && isJdkFunctionalSam(min.owner, min.name)) {
                            dir.add("Unknown");
                            unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                                    .add("dispatch-fn:" + owner + "." + min.name);
                        }
                        } // end CHA block (monoRecv == null)
                    } else if (projectClasses.contains(min.owner)) {
                        // static / special (super, private, ctor) — the exact target (descriptor known,
                        // so an overloaded callee resolves to the right overload's node).
                        edges.get(id).add(methodId(owner, min.name, min.desc));
                    }
                    // Cross-jar inheritance (candor-spec §2): a call into a DEPENDENCY analyzed
                    // separately — inherit its recorded effects via the stable method-ref hash. Only
                    // for external, non-built-in, non-Spring calls (project calls trace locally;
                    // reflection is already Unknown via classify).
                    if (effect == null && !springTyped && !projectClasses.contains(min.owner)) {
                        DepFn inh = crossDeps.get(min.owner + "." + min.name + min.desc);
                        // INTERFACE/SUPERTYPE-typed dep call: `Store s = new FileStore(); s.save()`
                        // compiles to INVOKEINTERFACE on `lib/Store`, but the dep report keys the body
                        // by its CONCRETE owner (`lib/FileStore.save`). The static call-site owner misses
                        // it, so the caller read SILENTLY PURE though the dep writes a file. When the
                        // receiver is provably a single `new T` (the monomorphic receiver) and T is NOT a
                        // project class (a dep type — a project T would have traced locally above), retry
                        // the join on the concrete impl's hash. Sound: it is the EXACT runtime type, so
                        // this is the one body the JVM dispatches to — never a CHA over-approximation.
                        int xop = min.getOpcode();
                        if (inh == null && (xop == Opcodes.INVOKEVIRTUAL || xop == Opcodes.INVOKEINTERFACE)) {
                            String cRecv = monomorphicReceiver(provFrames == null ? null
                                    : provFrames[mn.instructions.indexOf(min)], min);
                            if (cRecv != null && !byName.containsKey(cRecv) && !cRecv.equals(min.owner))
                                inh = crossDeps.get(cRecv + "." + min.name + min.desc);
                        }
                        if (inh != null) {
                            viaCross.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.effects);
                            if (!inh.hosts.isEmpty()) hostsDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.hosts);
                            if (!inh.cmds.isEmpty()) cmdsDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.cmds);
                            if (!inh.paths.isEmpty()) pathsDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.paths);
                            if (!inh.tables.isEmpty()) tablesDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.tables);
                        }
                    }
                } else if (insn instanceof TypeInsnNode tin && tin.getOpcode() == Opcodes.NEW) {
                    // `new C` triggers C's class-load → its `<clinit>` runs (the `<init>` edge is added
                    // separately by the INVOKESPECIAL above).
                    clinitEdge(id, tin.desc);
                    // ANONYMOUS/LOCAL class: it exists ONLY to be used via its supertype — typically
                    // handed to a runtime executor (`new Thread(new Runnable(){…}).start()`) that
                    // invokes run() OUTSIDE project code, so no in-project call site ever edges its
                    // body. Edge the INSTANTIATION to its declared methods, mirroring how a lambda's
                    // synthetic body is edged at its invokedynamic creation site (SEMANTICS §2's
                    // closure-attribution rule — the Rust engines attribute thread::spawn closures to
                    // the spawner; the scheduling method must inherit, not read pure). Gated on
                    // outerMethod != null (set exactly for anonymous + local classes), so named
                    // top-level/member classes are untouched. Found by the soundness fuzzer's
                    // `thread_anon` form.
                    ClassNode anonCn = byName.get(tin.desc);
                    if (anonCn != null && anonCn.outerMethod != null) {
                        for (MethodNode am : anonCn.methods)
                            // Edge to the framework-INVOKABLE surface only: a PRIVATE method can't be an
                            // override a runtime executor calls — it is reachable solely via an in-class
                            // call from a live method (a normal edge), so a DEAD private helper must not
                            // inherit at the instantiation site (it fabricated the helper's effect — e.g.
                            // a never-called private `exec(..)` → a phantom Exec + command literal on the
                            // spawner). A live private helper is still reached transitively via its caller.
                            if (!am.name.startsWith("<") && (am.access & Opcodes.ACC_PRIVATE) == 0)
                                edges.get(id).add(methodId(tin.desc.replace('/', '.'), am.name, am.desc));
                    } else if (anonCn != null && isTaskType(tin.desc)) {
                        // A NAMED class that is a TASK TYPE (implements Runnable/Callable or extends Thread)
                        // instantiated here is almost always handed to a runtime — `new Thread(new R()).start()`,
                        // `es.submit(new R())`, `new MyThread().start()` — which invokes its run()/call()
                        // OUTSIDE project code, so no in-project call site edges the body. Edge the
                        // instantiation to the task SAM only (run/call — not every method; a named task can
                        // have unrelated helpers), mirroring the anon case. The anon branch above is gated on
                        // outerMethod, which is null for named top-level/member classes — this is the named
                        // analog. RUNTIME_OVERRIDES also roots run/call; this attributes it to the spawner so
                        // a blast-radius walk from the scheduler isn't pure. (Found by an async/threading sweep.)
                        for (MethodNode am : anonCn.methods)
                            if ((am.name.equals("run") || am.name.equals("call") || am.name.equals("compute"))
                                    && (am.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) == 0)
                                edges.get(id).add(methodId(tin.desc.replace('/', '.'), am.name, am.desc));
                    }
                } else if (insn instanceof FieldInsnNode fin
                        && (fin.getOpcode() == Opcodes.GETSTATIC || fin.getOpcode() == Opcodes.PUTSTATIC)) {
                    // A static field access triggers the owner's class-load → its `<clinit>` runs.
                    clinitEdge(id, fin.owner);
                } else if (insn instanceof InvokeDynamicInsnNode idin) {
                    // Lambdas & method refs: the functional-interface factory's impl method (a project
                    // `lambda$…` synthetic, or a referenced method) carries the body's effects. Edge to
                    // it so they propagate here — else passing an effectful lambda looks pure.
                    for (Object a : idin.bsmArgs) {
                        // Only METHOD-kind handles (tags H_INVOKEVIRTUAL..H_INVOKEINTERFACE, i.e. >= 5)
                        // are call targets carrying effects. FIELD-kind handles (H_GETFIELD..H_PUTSTATIC,
                        // tags 1-4) also appear in bsmArgs — e.g. a `record`'s java.lang.runtime.ObjectMethods
                        // bootstrap for equals/hashCode/toString passes an H_GETFIELD handle per component.
                        // Their `desc` is a FIELD descriptor (no `()`), and a field read/write is pure, so
                        // skip them: passing one to methodId would feed a field descriptor to
                        // Type.getArgumentTypes and crash the whole scan.
                        if (a instanceof Handle h && h.getTag() >= Opcodes.H_INVOKEVIRTUAL) {
                            if (projectClasses.contains(h.getOwner()))
                                edges.get(id).add(methodId(h.getOwner().replace('/', '.'), h.getName(), h.getDesc()));
                            else {
                                // A method REFERENCE to a NON-project method (`File::delete`,
                                // `System::getenv`) handed to a stream stage / functional API IS invoked by
                                // that stage — but it has no project node to edge to, so classify the target
                                // the same way the direct-call path does, else its effect is lost. The direct
                                // call (`f.delete()`) classifies; the ref (`removeIf(File::delete)`) did not —
                                // a silent-pure hole found by a streams/method-ref sweep. A pure target →
                                // null → nothing added (no fabrication).
                                String eff = classify(h.getOwner().replace('/', '.'), h.getName(), h.getDesc());
                                if (eff != null) dir.add(eff);
                            }
                        }
                    }
                    // A bootstrap that is NOT one of the JVM's STRUCTURAL indy factories (lambda/method-ref
                    // creation, string concat, record ObjectMethods, pattern-switch, constant-dynamic) is a
                    // DYNAMIC-LANGUAGE dispatch bootstrap — Groovy's `IndyInterface.bootstrap`, JRuby, etc.
                    // Its bsmArgs carry only a call-NAME string (no resolvable target handle), so the
                    // dispatch is opaque exactly like reflection: it could reach any method and perform any
                    // effect. Without this, compiled dynamic Groovy (the default, non-@CompileStatic mode)
                    // dropped EVERY call — Fs/Exec/Net all silent-pure. Honest Unknown (SPEC §4), never
                    // silent-pure. (Found by a JVM-dialect sweep on compiled Groovy.)
                    if (idin.bsm != null && !STRUCTURAL_INDY_BSM.contains(idin.bsm.getOwner())) {
                        dir.add("Unknown");
                        unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                                .add("indy:" + idin.bsm.getOwner().replace('/', '.'));
                    }
                }
            }
        }
    }

    /** A class's `<clinit>` runs once, at first class-load — triggered by a `new C`, a static method
     *  call on C, or a static field access on C. Edge to `C.<clinit>` from each such trigger so an
     *  effectful static initializer (`static { … }` / `static final X = readFile()`) propagates to the
     *  use site instead of looking pure. Over-approximates — the class may already be loaded by the
     *  time we reach this site — which is the SOUND direction (the I/O genuinely runs on first trigger).
     *  Only project classes that actually have a `<clinit>` (so the edge isn't dangling). */
    static void clinitEdge(String callerId, String internalOwner) {
        if (classesWithClinit.contains(internalOwner))
            edges.get(callerId).add(internalOwner.replace('/', '.') + ".<clinit>");
        // JVMS §5.5: initializing a class FIRST initializes its superclasses — so touching `Sub` runs
        // `Base.<clinit>` too. Edge to every project SUPERCLASS's <clinit> as well, else an effect in a base
        // class's static initializer is silently dropped when only the subclass is touched (round-13 hole;
        // the 0.5.2/0.5.3 clinit work fixed direct-class transitivity, not the superclass chain). Sound
        // over-approximation (a super-INTERFACE without a default method isn't initialized by a subclass load,
        // but edging its <clinit> at worst over-reports). transSupers is cached, so this is cheap.
        for (String sup : transSupers(internalOwner))
            if (!sup.equals(internalOwner) && classesWithClinit.contains(sup))
                edges.get(callerId).add(sup.replace('/', '.') + ".<clinit>");
    }

    /** The JVM's STRUCTURAL invokedynamic bootstrap factories: lambda/method-ref creation, string
     *  concatenation, record ObjectMethods (equals/hashCode/toString), pattern-switch, and
     *  constant-dynamic. An indy whose bootstrap is NONE of these is dynamic-language dispatch
     *  (Groovy `IndyInterface`, JRuby, …) — opaque like reflection, so it raises Unknown rather than
     *  going silent-pure. */
    static final Set<String> STRUCTURAL_INDY_BSM = Set.of(
            "java/lang/invoke/LambdaMetafactory",
            "java/lang/invoke/StringConcatFactory",
            "java/lang/runtime/ObjectMethods",
            "java/lang/runtime/SwitchBootstraps",
            "java/lang/invoke/ConstantBootstraps");

    // entry-point annotation substrings (HTTP mappings + message listeners + container-invoked methods).
    // Each names a method the FRAMEWORK invokes with no in-project call site (Spring proxy, JAX-RS/Micronaut
    // container, AspectJ weaver, Kafka listener container, @Bean factory at startup) — so an effectful body
    // is orphaned from every reachability root without rooting it (the finalize shape). Rooting is sound,
    // never fabrication: each is genuinely framework-invoked. Substrings cover javax/ + jakarta/ variants.
    static final List<String> MAPPING_OR_LISTENER = List.of(
            "web/bind/annotation/RequestMapping", "web/bind/annotation/GetMapping",
            "web/bind/annotation/PostMapping", "web/bind/annotation/PutMapping",
            "web/bind/annotation/DeleteMapping", "web/bind/annotation/PatchMapping",
            "kafka/annotation/KafkaListener", "amqp/rabbit/annotation/RabbitListener",
            "jms/annotation/JmsListener", "context/event/EventListener",
            // Spring @Async (proxy invokes it on another thread, decoupled from the call site) + @Bean
            // factory methods (Spring calls them at context startup) + the multi-method @KafkaHandler form.
            "scheduling/annotation/Async", "context/annotation/Bean", "kafka/annotation/KafkaHandler",
            // JAX-RS / Jakarta REST resource methods (container-invoked) — covers javax.ws.rs + jakarta.ws.rs.
            "ws/rs/GET", "ws/rs/POST", "ws/rs/PUT", "ws/rs/DELETE", "ws/rs/PATCH", "ws/rs/HEAD", "ws/rs/Path",
            // Micronaut HTTP controller methods (container-invoked).
            "micronaut/http/annotation/Get", "micronaut/http/annotation/Post",
            "micronaut/http/annotation/Put", "micronaut/http/annotation/Delete",
            "micronaut/http/annotation/Patch",
            // AspectJ advice — the weaver invokes it at every matched join point; effectful advice (audit
            // logging, metrics push) has no in-project call site.
            "aspectj/lang/annotation/Around", "aspectj/lang/annotation/Before",
            "aspectj/lang/annotation/After", "aspectj/lang/annotation/AfterReturning",
            "aspectj/lang/annotation/AfterThrowing",
            // Event-bus subscribers — the bus invokes the @Subscribe method on event delivery with no
            // project call site (the @EventListener shape). Guava EventBus (`common/eventbus/Subscribe`)
            // + Greenrobot EventBus (`greenrobot/eventbus/Subscribe`, method-name `onEvent*` historically
            // but @Subscribe in v3). A handler that persists/pushes is otherwise orphaned.
            "common/eventbus/Subscribe", "greenrobot/eventbus/Subscribe",
            // Spring Integration @ServiceActivator (the EIP handler the messaging runtime invokes) + the
            // related endpoint annotations; Spring Shell @ShellMethod (the shell invokes it per command).
            "integration/annotation/ServiceActivator", "integration/annotation/Transformer",
            "integration/annotation/Filter", "integration/annotation/Router",
            "integration/annotation/Splitter", "shell/standard/ShellMethod");

    /** Container-invoked bean lifecycle callbacks (`@PostConstruct` init, `@PreDestroy` shutdown). Like
     *  the mappings/listeners they're called by the framework with no project call site — a `@PreDestroy`
     *  that flushes/closes does real I/O at shutdown. The substring matches both `javax/` and `jakarta/`. */
    static final List<String> LIFECYCLE = List.of(
            "annotation/PostConstruct", "annotation/PreDestroy",
            // JPA entity lifecycle callbacks — invoked by the persistence provider (Hibernate/…) on
            // persist/load/update/remove events, no project call site. An @PrePersist that stamps audit
            // fields or an @PostLoad that fetches does real I/O. Covers javax/ and jakarta/ persistence.
            "persistence/PrePersist", "persistence/PostPersist", "persistence/PreUpdate",
            "persistence/PostUpdate", "persistence/PreRemove", "persistence/PostRemove",
            "persistence/PostLoad");

    /** Runtime-invoked override methods: when a class's supertype chain contains `iface` and it declares
     *  `(name, desc)`, that method is an ENTRY POINT — the runtime (executor, thread scheduler, servlet
     *  container, Spring lifecycle) invokes it with NO project call site, so its I/O would otherwise be
     *  orphaned from every reachability root (the same shape as finalize). `iface` is a SUBSTRING of the
     *  internal supertype name, so a single entry covers `javax/` and `jakarta/` variants. */
    /** The canonical Java serialization callback signatures (the Serializable/Externalizable contract).
     *  Their stream-typed descriptors are the giveaway; the runtime invokes them reflectively with no
     *  in-project call site, so without this their I/O is orphaned from every reachability root. */
    static boolean isSerializationCallback(String name, String desc) {
        switch (name) {
            case "readObject":       return desc.equals("(Ljava/io/ObjectInputStream;)V");
            case "writeObject":      return desc.equals("(Ljava/io/ObjectOutputStream;)V");
            case "readExternal":     return desc.equals("(Ljava/io/ObjectInput;)V");
            case "writeExternal":    return desc.equals("(Ljava/io/ObjectOutput;)V");
            case "readObjectNoData": return desc.equals("()V");
            case "readResolve":      return desc.equals("()Ljava/lang/Object;");
            case "writeReplace":     return desc.equals("()Ljava/lang/Object;");
            default:                 return false;
        }
    }

    static final List<String[]> RUNTIME_OVERRIDES = List.of(
            // {supertype-substring, method, descriptor}
            new String[] {"java/lang/Runnable", "run", "()V"},
            new String[] {"java/lang/Thread", "run", "()V"},
            new String[] {"java/util/concurrent/Callable", "call", "()Ljava/lang/Object;"},
            // Spring bean lifecycle (interface form of @PostConstruct/@PreDestroy) + startup runners.
            new String[] {"springframework/beans/factory/InitializingBean", "afterPropertiesSet", "()V"},
            new String[] {"springframework/beans/factory/DisposableBean", "destroy", "()V"},
            new String[] {"springframework/boot/CommandLineRunner", "run", "([Ljava/lang/String;)V"},
            new String[] {"springframework/boot/ApplicationRunner", "run",
                    "(Lorg/springframework/boot/ApplicationArguments;)V"},
            // Servlet container lifecycle (raw servlets/filters/listeners — Spring MVC uses @*Mapping).
            new String[] {"servlet/http/HttpServlet", "doGet", null},
            new String[] {"servlet/http/HttpServlet", "doPost", null},
            new String[] {"servlet/http/HttpServlet", "doPut", null},
            new String[] {"servlet/http/HttpServlet", "doDelete", null},
            new String[] {"servlet/http/HttpServlet", "service", null},
            new String[] {"servlet/Filter", "doFilter", null},
            new String[] {"servlet/ServletContextListener", "contextInitialized", null},
            new String[] {"servlet/ServletContextListener", "contextDestroyed", null},
            // Function-interface bodies: a Kotlin/Scala/Groovy lambda or a NAMED class implementing
            // one is invoked by whatever higher-order function received it (often external) — a
            // runtime-invoked root, like a Runnable. Marking them entry points is what keeps a named
            // implementor's I/O from being orphaned when bounded CHA drops the broad fan-out (the
            // /code-review finding). `iface` matches as a substring, so "kotlin/jvm/functions/Function"
            // covers Function0..Function22 and "scala/Function" covers Function0..N.
            new String[] {"kotlin/jvm/functions/Function", "invoke", null},
            new String[] {"scala/Function", "apply", null},
            new String[] {"scala/PartialFunction", "apply", null},
            new String[] {"groovy/lang/Closure", "call", null},
            // JDK reflective/runtime invocation — the runtime calls these on a project IMPLEMENTOR with no
            // in-project call site, so an effectful body is orphaned from every root (the finalize/
            // serialization shape). `Comparator.compare`/`Comparable.compareTo` are invoked by the sort
            // machinery (Collections.sort, stream.sorted, TreeMap/TreeSet); `InvocationHandler.invoke` by
            // the JDK dynamic-proxy runtime. GATED on actually implementing the interface (the supertype
            // filter above), so a same-named method on an unrelated class is never fabricated as a root.
            // A null descriptor on compare/compareTo also roots the synthetic erased BRIDGE — sound, since
            // the bridge forwards to the typed body. (compareTo stays CHA-exempt for DISPATCH fan-out — a
            // separate concern from rooting its own effects.)
            new String[] {"java/util/Comparator", "compare", null},
            new String[] {"java/lang/Comparable", "compareTo", null},
            new String[] {"java/lang/reflect/InvocationHandler", "invoke",
                    "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;"},
            // Bean Validation: the validator runtime invokes isValid on a project ConstraintValidator with
            // no in-project call site (covers javax/ + jakarta/ via the substring).
            new String[] {"validation/ConstraintValidator", "isValid", null},
            // java.util.TimerTask is scheduled and run by a Timer thread. It implements Runnable, so the
            // Runnable row would cover it ONCE transSupers walks the external TimerTask supertype — but root
            // it explicitly too (cheap, and independent of external-supertype resolution being available).
            new String[] {"java/util/TimerTask", "run", "()V"},
            // Servlet async lifecycle callbacks — the container invokes them on a registered AsyncListener.
            new String[] {"servlet/AsyncListener", "onComplete", null},
            new String[] {"servlet/AsyncListener", "onTimeout", null},
            new String[] {"servlet/AsyncListener", "onError", null},
            new String[] {"servlet/AsyncListener", "onStartAsync", null},
            // Fork/join task bodies: a RecursiveTask/RecursiveAction's compute() is invoked by the
            // ForkJoinPool runtime (`pool.invoke(t)`, `t.fork()`, `ForkJoinTask.invokeAll(...)`) with no
            // in-project call site. ForkJoinTask implements Future/Serializable — NOT Runnable/Callable —
            // so the Runnable row never covered it (silent-pure). null desc matches compute()V (Action),
            // compute()Object (Task + its erased bridge).
            new String[] {"java/util/concurrent/ForkJoinTask", "compute", null},
            // (DE)SERIALIZATION-framework callbacks — the framework invokes a project implementor reflectively
            // with NO in-project call site (the finalize/serialization shape). Supertype-substring gated, so a
            // same-named method on an unrelated class is never fabricated. One substring per interface covers
            // its javax/jakarta + library-variant FQNs.
            new String[] {"JsonDeserializer", "deserialize", null},      // Jackson + Gson (both end JsonDeserializer)
            new String[] {"JsonSerializer", "serialize", null},          // Jackson + Gson
            new String[] {"databind/KeyDeserializer", "deserializeKey", null},
            new String[] {"databind/util/StdConverter", "convert", null},
            new String[] {"gson/TypeAdapter", "read", null},
            new String[] {"gson/TypeAdapter", "write", null},
            new String[] {"gson/InstanceCreator", "createInstance", null},
            new String[] {"kryo/Serializer", "read", null},
            new String[] {"kryo/Serializer", "write", null},
            new String[] {"kryo/KryoSerializable", "read", null},
            new String[] {"kryo/KryoSerializable", "write", null},
            new String[] {"adapters/XmlAdapter", "unmarshal", null},
            new String[] {"adapters/XmlAdapter", "marshal", null},
            new String[] {"ws/rs/ext/MessageBodyReader", "readFrom", null},
            new String[] {"ws/rs/ext/MessageBodyWriter", "writeTo", null},
            new String[] {"core/convert/converter/Converter", "convert", null},   // Spring conversion service
            new String[] {"springframework/format/Formatter", "parse", null},
            new String[] {"springframework/format/Formatter", "print", null},
            // RUNTIME-GENERATED PROXY interceptors — invoked by the CGLIB/ByteBuddy-generated subclass at
            // runtime, the same orphan shape as the JDK InvocationHandler (already rooted). cglib's substring
            // covers BOTH net.sf.cglib and the Spring-repackaged org.springframework.cglib; cglib has its OWN
            // InvocationHandler (a DIFFERENT FQN from java.lang.reflect's).
            new String[] {"cglib/proxy/MethodInterceptor", "intercept", null},
            new String[] {"cglib/proxy/InvocationHandler", "invoke", null},
            // LOGGING appender/handler callbacks — the logging framework invokes a project-defined appender
            // with no in-project call site; a network/file appender does real Net/Fs. (The Log EMIT is config;
            // the appender BODY is the effect that matters.) Covers logback Appender, jul Handler, log4j1/2.
            new String[] {"logback/core/Appender", "append", null},
            new String[] {"logback/core/Appender", "doAppend", null},
            new String[] {"java/util/logging/Handler", "publish", null},
            new String[] {"logging/log4j/core/Appender", "append", null},
            new String[] {"apache/log4j/Appender", "doAppend", null},
            // SCHEDULING / JOB / BATCH / WORKFLOW / serverless callbacks — invoked by the scheduler/engine/
            // runtime with no in-project call site (the finalize/Runnable shape). Supertype-substring gated
            // (one row per interface; covers javax/jakarta + impl variants), so a same-named non-implementor
            // is never fabricated as a root.
            new String[] {"org/quartz/Job", "execute", null},
            new String[] {"springframework/batch/core/step/tasklet/Tasklet", "execute", null},
            new String[] {"springframework/batch/item/ItemReader", "read", null},
            new String[] {"springframework/batch/item/ItemWriter", "write", null},
            new String[] {"springframework/batch/item/ItemProcessor", "process", null},
            new String[] {"springframework/batch/core/StepExecutionListener", "beforeStep", null},
            new String[] {"springframework/batch/core/StepExecutionListener", "afterStep", null},
            new String[] {"engine/delegate/JavaDelegate", "execute", null},   // Camunda + Activiti
            new String[] {"lambda/runtime/RequestHandler", "handleRequest", null},        // AWS Lambda
            new String[] {"lambda/runtime/RequestStreamHandler", "handleRequest", null},
            new String[] {"io/vertx/core/Verticle", "start", null},
            new String[] {"io/vertx/core/Handler", "handle", null},
            new String[] {"org/apache/camel/Processor", "process", null},
            new String[] {"kafka/streams/processor/Processor", "process", null},
            new String[] {"jobrunr/jobs/lambdas/JobRequestHandler", "run", null},
            // Android component lifecycle — the framework instantiates + invokes these with no project call
            // site (the servlet-doGet shape). The dominant Android entry points.
            new String[] {"android/app/Activity", "onCreate", null},
            new String[] {"android/app/Activity", "onStart", null},
            new String[] {"android/app/Activity", "onResume", null},
            new String[] {"android/app/Service", "onStartCommand", null},
            new String[] {"android/app/Service", "onBind", null},
            new String[] {"android/app/Service", "onCreate", null},
            new String[] {"android/app/IntentService", "onHandleIntent", null},
            new String[] {"android/content/BroadcastReceiver", "onReceive", null},
            new String[] {"android/app/Application", "onCreate", null},
            // Reactive-streams Subscriber callbacks (Reactor/RxJava/project publishers invoke them) + NIO
            // async-I/O CompletionHandler (invoked by the AsynchronousChannelGroup on completion) — both the
            // runtime-invoked-callback orphan shape, like ForkJoinTask.compute.
            new String[] {"reactivestreams/Subscriber", "onNext", null},
            new String[] {"reactivestreams/Subscriber", "onError", null},
            new String[] {"reactivestreams/Subscriber", "onComplete", null},
            new String[] {"java/nio/channels/CompletionHandler", "completed", null},
            new String[] {"java/nio/channels/CompletionHandler", "failed", null},
            // JPA AttributeConverter — the persistence provider invokes convert* on a project @Converter
            // during entity load/store with NO project call site (the orphan shape); an encrypting/
            // remote-resolving converter does real I/O. Covers javax/ + jakarta/ persistence.
            new String[] {"persistence/AttributeConverter", "convertToDatabaseColumn", null},
            new String[] {"persistence/AttributeConverter", "convertToEntityAttribute", null},
            // Netflix Hystrix command body + fallback — the Hystrix runtime invokes run()/getFallback() on
            // a worker thread when the command is executed/queued, no direct project call site.
            new String[] {"netflix/hystrix/HystrixCommand", "run", null},
            new String[] {"netflix/hystrix/HystrixCommand", "getFallback", null},
            new String[] {"netflix/hystrix/HystrixObservableCommand", "construct", null},
            // Spring Boot Actuator health check — the actuator endpoint invokes health() on a registered
            // HealthIndicator (often pinging a DB/remote) with no project call site.
            new String[] {"boot/actuate/health/HealthIndicator", "health", null},
            new String[] {"boot/actuate/info/InfoContributor", "contribute", null},
            // GUI event callbacks — the UI toolkit's event-dispatch thread invokes these on a registered
            // listener with no project call site (the servlet/Runnable shape). Swing/AWT ActionListener +
            // SwingWorker background work; JavaFX EventHandler + Application lifecycle; Android click/message
            // handlers. A handler that hits the network/disk/DB is otherwise orphaned from every root.
            new String[] {"java/awt/event/ActionListener", "actionPerformed", null},
            new String[] {"javax/swing/SwingWorker", "doInBackground", null},
            new String[] {"javax/swing/SwingWorker", "done", null},
            new String[] {"javafx/event/EventHandler", "handle", null},
            new String[] {"javafx/application/Application", "start", null},
            new String[] {"javafx/application/Application", "init", null},
            new String[] {"android/view/View$OnClickListener", "onClick", null},
            new String[] {"android/os/Handler", "handleMessage", null},
            // JDK runtime-invoked callbacks orphaned from every reachability root (the finalize/serialization
            // shape) — invoked by the JVM/executor/bean machinery with no project call site:
            // java.util.concurrent.Flow.Subscriber (JDK reactive — registered with SubmissionPublisher; the
            // direct analog of the already-rooted reactivestreams Subscriber, the inconsistency a sweep
            // flagged); Thread.UncaughtExceptionHandler (set as the default/per-thread handler, run by the
            // JVM on an uncaught throw — often remote crash reporting); the executor-config callbacks
            // RejectedExecutionHandler/ThreadFactory; the bean/Swing PropertyChangeListener; the custom
            // Spliterator/ResourceBundle.Control loaders. Supertype-substring gated → no fabrication on a
            // same-named non-implementor (verified by the entrypoint probe's decoy).
            new String[] {"java/util/concurrent/Flow$Subscriber", "onNext", null},
            new String[] {"java/util/concurrent/Flow$Subscriber", "onError", null},
            new String[] {"java/util/concurrent/Flow$Subscriber", "onComplete", null},
            new String[] {"java/util/concurrent/Flow$Subscriber", "onSubscribe", null},
            new String[] {"java/lang/Thread$UncaughtExceptionHandler", "uncaughtException", null},
            new String[] {"java/util/concurrent/RejectedExecutionHandler", "rejectedExecution", null},
            new String[] {"java/util/concurrent/ThreadFactory", "newThread", null},
            new String[] {"java/beans/PropertyChangeListener", "propertyChange", null},
            new String[] {"java/util/Spliterator", "tryAdvance", null},
            new String[] {"java/util/ResourceBundle$Control", "newBundle", null},
            // Framework runtime-invoked callbacks (INTERFACE forms — candor roots the ANNOTATION forms like
            // @EventListener/@JmsListener/@RabbitListener, but a raw interface implementor has no project
            // call site either). Spring: ApplicationListener (event), Smart/Lifecycle (bean start/stop),
            // HandlerInterceptor (per-request MVC), BeanPostProcessor (per-bean startup), FactoryBean
            // (bean materialization). Messaging: JMS/AMQP MessageListener, Kafka ConsumerRebalanceListener.
            // Servlet session/request listeners. All container-invoked, segment-gated (no over-root).
            new String[] {"springframework/context/ApplicationListener", "onApplicationEvent", null},
            new String[] {"springframework/context/Lifecycle", "start", null},
            new String[] {"springframework/context/Lifecycle", "stop", null},
            new String[] {"springframework/web/servlet/HandlerInterceptor", "preHandle", null},
            new String[] {"springframework/web/servlet/HandlerInterceptor", "postHandle", null},
            new String[] {"springframework/web/servlet/HandlerInterceptor", "afterCompletion", null},
            new String[] {"springframework/beans/factory/config/BeanPostProcessor", "postProcessBeforeInitialization", null},
            new String[] {"springframework/beans/factory/config/BeanPostProcessor", "postProcessAfterInitialization", null},
            new String[] {"springframework/beans/factory/FactoryBean", "getObject", null},
            new String[] {"jms/MessageListener", "onMessage", null},                 // javax/jakarta jms
            new String[] {"amqp/core/MessageListener", "onMessage", null},           // Spring AMQP
            new String[] {"amqp/rabbit/listener/api/ChannelAwareMessageListener", "onMessage", null},
            new String[] {"kafka/clients/consumer/ConsumerRebalanceListener", "onPartitionsAssigned", null},
            new String[] {"kafka/clients/consumer/ConsumerRebalanceListener", "onPartitionsRevoked", null},
            new String[] {"servlet/http/HttpSessionListener", "sessionCreated", null},
            new String[] {"servlet/http/HttpSessionListener", "sessionDestroyed", null},
            new String[] {"servlet/ServletRequestListener", "requestInitialized", null},
            new String[] {"servlet/ServletRequestListener", "requestDestroyed", null},
            // More container-invoked framework callbacks (round-13): Spring Security auth (loadUserByUsername
            // — a DB/LDAP lookup on every login), Spring *Aware injected setters + SmartInitializingSingleton,
            // JAX-RS container filters + ExceptionMapper, RxJava Observer (distinct from reactivestreams),
            // LMAX Disruptor EventHandler, jakarta.websocket Endpoint. All runtime-invoked, segment-gated.
            new String[] {"security/core/userdetails/UserDetailsService", "loadUserByUsername", null},
            new String[] {"context/ApplicationContextAware", "setApplicationContext", null},
            new String[] {"context/EnvironmentAware", "setEnvironment", null},
            new String[] {"beans/factory/BeanFactoryAware", "setBeanFactory", null},
            new String[] {"beans/factory/BeanNameAware", "setBeanName", null},
            new String[] {"context/ResourceLoaderAware", "setResourceLoader", null},
            new String[] {"context/ApplicationEventPublisherAware", "setApplicationEventPublisher", null},
            new String[] {"web/context/ServletContextAware", "setServletContext", null},
            new String[] {"beans/factory/SmartInitializingSingleton", "afterSingletonsInstantiated", null},
            new String[] {"ws/rs/container/ContainerRequestFilter", "filter", null},
            new String[] {"ws/rs/container/ContainerResponseFilter", "filter", null},
            new String[] {"ws/rs/ext/ExceptionMapper", "toResponse", null},
            new String[] {"io/reactivex/Observer", "onNext", null},               // RxJava 2
            new String[] {"io/reactivex/Observer", "onError", null},
            new String[] {"io/reactivex/Observer", "onComplete", null},
            new String[] {"io/reactivex/rxjava3/core/Observer", "onNext", null},   // RxJava 3
            new String[] {"io/reactivex/rxjava3/core/Observer", "onError", null},
            new String[] {"io/reactivex/rxjava3/core/Observer", "onComplete", null},
            new String[] {"lmax/disruptor/EventHandler", "onEvent", null},
            new String[] {"jakarta/websocket/Endpoint", "onOpen", null},
            new String[] {"javax/websocket/Endpoint", "onOpen", null},
            // Spring StateMachine action body — the state-machine runtime invokes execute() on a transition.
            new String[] {"springframework/statemachine/action/Action", "execute", null});

    /** The number of CHA targets above which a CHA-EXEMPT dispatch (Object protocol / function-interface
     *  / task verb) is treated as a broad smear and its fan-out dropped. An app's handful of Runnables /
     *  closures resolve precisely (attributed); a library's hundreds of FunctionN/Closure impls exceed
     *  this and are dropped (their bodies stay reachable via the RUNTIME_OVERRIDES entry points). */
    static final int CHA_FANOUT_LIMIT = 12;

    /** Whether a method's CHA dispatch is exempt from BROAD fan-out (SPEC §4 conventionally-pure +
     *  runtime-dispatched verbs). Declarative + unit-tested so a new dialect is a row, not another `||`
     *  buried in the bytecode loop. Narrow dispatch over these is still attributed precisely; only the
     *  library-scale smear is dropped (see CHA_FANOUT_LIMIT). */
    /** The single-ABSTRACT-method names of java.util.function.* (Function/BiFunction/operators → apply*;
     *  Consumer → accept; Predicate → test; Supplier → get*). Matched by NAME so the package's pure DEFAULT
     *  methods (andThen/compose/and/or/negate — known JDK plumbing that wraps the receiver into a new
     *  composed lambda, no effect at the call site) are NOT treated as the SAM. Without this, idiomatic
     *  function composition (`a.andThen(b)`) flooded Unknown — a precision regression. */
    static final Set<String> FUNCTION_PKG_SAM = Set.of(
            "apply", "applyAsInt", "applyAsLong", "applyAsDouble", "applyAsBoolean",
            "accept", "test", "get", "getAsInt", "getAsLong", "getAsDouble", "getAsBoolean");

    /** A JDK FUNCTIONAL-INTERFACE single-abstract-method invocation — its only implementors are lambdas/
     *  method-refs whose bodies don't resolve from the call site, so an unpinned dispatch with no project
     *  impl is honest Unknown (never silent-pure). Restricted to the actual SAM names (not the package's
     *  concrete default methods); Runnable.run and Callable.call are the two outside the package. NOT the
     *  Kotlin/Scala/Groovy FunctionN (those stay isChaExemptMethod — their lambda effect is captured). */
    static boolean isJdkFunctionalSam(String owner, String name) {
        if (owner.startsWith("java/util/function/")) return FUNCTION_PKG_SAM.contains(name);
        if (owner.equals("java/lang/Runnable") && name.equals("run")) return true;
        if (owner.equals("java/util/concurrent/Callable") && name.equals("call")) return true;
        return false;
    }

    /** The §4 conventionally-pure Object protocol (formatting / equality / hashing / ordering) — a SUBSET
     *  of isChaExemptMethod. These stay pure even under a broad fan-out: an effectful override is spec-§4
     *  pure by convention, so dropping it raises NO Unknown. The OTHER exemptions (Kotlin/Scala/Groovy
     *  function-objects) are NOT here: a NAMED class implementing FunctionN can do real I/O, so a broad
     *  fan-out that DROPS such named impls must raise Unknown, not stay silent (the round-11 hole — a
     *  >12-impl unpinned `Function0.invoke` with one effectful NAMED impl read silently pure). */
    static boolean isObjectProtocolExempt(String name, String desc) {
        return (name.equals("toString") && desc.equals("()Ljava/lang/String;"))
                || (name.equals("hashCode") && desc.equals("()I"))
                || (name.equals("equals") && desc.equals("(Ljava/lang/Object;)Z"))
                || (name.equals("compareTo") && desc.equals("(Ljava/lang/Object;)I"));
    }

    static boolean isChaExemptMethod(String owner, String name, String desc) {
        // Object protocol — conventionally pure (formatting / equality / hashing / ordering).
        if (isObjectProtocolExempt(name, desc)) return true;
        // Function-interface invocation: Kotlin FunctionN.invoke; Scala FunctionN/PartialFunction.apply
        // + the java8 JFunction SAM bridges; Groovy Closure.call/doCall.
        if (owner.startsWith("kotlin/jvm/functions/") && name.equals("invoke")) return true;
        if ((owner.startsWith("scala/Function") || owner.equals("scala/PartialFunction")
                || owner.startsWith("scala/runtime/java8/JFunction")) && name.equals("apply")) return true;
        if (owner.equals("groovy/lang/Closure") && (name.equals("call") || name.equals("doCall"))) return true;
        // NB: java.lang.Runnable.run / java.util.concurrent.Callable.call are NOT exempt. They can be
        // NAMED project classes (not just lambdas), and an unpinned `r.run()` over them was silently pure
        // (the §7.13 fuzzer's task_unpinned form caught it). They now go through normal bounded CHA —
        // narrow → fan out to the actual impls, broad → Unknown — like any other interface dispatch. A
        // lambda's own effect is still captured at its creation site (closure attribution), so this only
        // adds the sound over-approximation for genuinely-unresolvable task receivers. The Kotlin/Scala/
        // Groovy FUNCTION-object dispatch above stays exempt: there the impls are lambda classes whose
        // effect IS captured at creation, and fanning out smears (the documented FunctionN.invoke case).
        return false;
    }


    /** Whether an internal supertype name matches a RUNTIME_OVERRIDES row's substring at a SEGMENT boundary.
     *  The old raw `contains` over-rooted: a project `com/acme/JsonDeserializerMetrics` matched the
     *  `JsonDeserializer` row (infix), and a coincidental `com/co/batch/item/ItemReader` matched the Spring
     *  Batch row. Anchor it: exact, or a `/`-delimited suffix (the type name + optional package tail). The
     *  ONE exception is the FunctionN convention (kotlin `Function0..22`, scala `Function0..N`) where the row
     *  is a PREFIX of the leaf type — detected by the row ending in "Function". */
    /** The §4 conventionally-pure object protocol — never an effect, even on an effect-bearing owner.
     *  Used to subtract fabrications from whole-owner classify rules. */
    /** Owners whose string ARG is genuinely a network HOST/endpoint (so a host-literal extraction is
     *  meaningful). Excludes KV/messaging clients (Jedis/Kafka/Rabbit/Mqtt/…) whose string args are
     *  keys/topics/routing-keys, not hosts — gating the literal sweep on this prevents fabricating a host
     *  from a Redis key that happens to look like host:port. */
    static boolean isHostBearingOwner(String internalOwner) {
        return internalOwner.equals("java/net/Socket") || internalOwner.equals("java/net/ServerSocket")
                || internalOwner.equals("java/net/InetSocketAddress") || internalOwner.equals("java/net/InetAddress")
                || internalOwner.equals("java/net/URL") || internalOwner.equals("java/net/URI")
                || internalOwner.equals("java/net/URLConnection") || internalOwner.equals("java/net/HttpURLConnection")
                || internalOwner.equals("javax/net/ssl/HttpsURLConnection")
                || internalOwner.equals("java/net/DatagramSocket") || internalOwner.equals("java/net/MulticastSocket")
                || internalOwner.equals("javax/net/ssl/SSLSocket")
                || internalOwner.startsWith("java/net/http/")
                || internalOwner.startsWith("org/springframework/web/")
                || internalOwner.startsWith("io/ktor/") || internalOwner.startsWith("javax/naming/");
    }

    /** Owners whose string arg is genuinely SQL (so a table extraction is meaningful) — JDBC + JPA + the
     *  SQL templates. Excludes Android SQLite execSQL/rawQuery? No — those ARE SQL; but a non-SQL Db client
     *  (a KV store classified Db) is excluded. */
    static boolean isSqlBearingOwner(String internalOwner) {
        return internalOwner.startsWith("java/sql/") || internalOwner.startsWith("javax/persistence/")
                || internalOwner.startsWith("jakarta/persistence/") || internalOwner.startsWith("org/hibernate/")
                || internalOwner.startsWith("org/springframework/jdbc/")
                || internalOwner.equals("android/database/sqlite/SQLiteDatabase")
                // The raw-SQL DRIVERS classified Db (0.5.24/0.5.25): their SQL string args carry tables too.
                // Without them, a method mixing an allowed JDBC table with a forbidden jOOQ/jdbi table reported
                // only the allowed one → AS-EFF-008 certified a method hitting the forbidden table (round-13
                // gate EVASION). NB: Mongo is deliberately ABSENT — a collection name is not SQL and tablesInSql
                // (needs a leading SQL keyword) extracts nothing from it anyway.
                || internalOwner.startsWith("org/jooq/") || internalOwner.startsWith("org/jdbi/")
                || internalOwner.startsWith("org/apache/ibatis/") || internalOwner.startsWith("org/neo4j/driver/")
                || internalOwner.startsWith("com/datastax/oss/") || internalOwner.startsWith("io/r2dbc/")
                || internalOwner.equals("org/springframework/data/jdbc/core/JdbcAggregateTemplate");
    }

    /** The §4 conventionally-pure object protocol — never an effect, even on an effect-bearing owner.
     *  Used to subtract fabrications from whole-owner classify rules. */
    static boolean isConventionallyPure(String method) {
        return method.equals("toString") || method.equals("hashCode") || method.equals("equals")
                || method.equals("getClass");
    }

    /** AWS v1/v2 client config getters that match the `get*` Net verb but make no request — pure local
     *  accessors of already-resolved config. Without this carve-out the `*Client` Net rule fabricates Net
     *  on a provably-pure getter (cardinal sin). NB: getBucketRegionViaHeadRequest is deliberately absent
     *  (it issues a HEAD → genuinely Net). */
    static boolean isAwsPureClientGetter(String method) {
        switch (method) {
            case "getRegion": case "getRegionName": case "getRegionNameFromAuthorityOrSigner":
            case "getSignerRegion": case "getSignerRegionOverride": case "getResourceUrl":
            case "getUrl": case "getCachedResponseMetadata": case "getServiceName":
            case "getEndpointPrefix": case "getClientConfiguration": case "getServiceNameIntern":
            // The pure config getters INHERITED from com.amazonaws.AmazonWebServiceClient (the base of
            // every v1 `Amazon*Client`): they match the `get*` verb but read cached local config / build a
            // signer object — no request. Without them the `*Client` Net rule still FABRICATED Net on a
            // provably-pure accessor (the round-11 finding — same class as getRegion, carve-out was
            // incomplete). getBucketRegionViaHeadRequest is deliberately absent (it issues a HEAD → Net).
            case "getTimeOffset": case "getSignerOverride": case "getRequestMetricsCollector":
            case "getMonitoringListeners": case "getSignerByURI": case "getEndpoint":
                return true;
            default: return false;
        }
    }

    static boolean supertypeMatches(String internalSuper, String row) {
        if (internalSuper.equals(row) || internalSuper.endsWith("/" + row)) return true;
        return row.endsWith("Function") && internalSuper.startsWith(row);
    }

    static boolean annoPresent(List<AnnotationNode> anns, String descSubstring) {
        if (anns == null) return false;
        for (AnnotationNode a : anns) if (a.desc != null && a.desc.contains(descSubstring)) return true;
        return false;
    }

    static boolean annoPresentAny(List<AnnotationNode> anns, List<String> subs) {
        for (String s : subs) if (annoPresent(anns, s)) return true;
        return false;
    }

    /** All the entry-point-rooting annotation markers (HTTP mappings/listeners/lifecycle + @Scheduled +
     *  @JsonCreator), as one list for the meta-annotation-aware matcher. */
    static final List<String> ROOT_ANNOTATIONS;
    static {
        List<String> r = new ArrayList<>(MAPPING_OR_LISTENER);
        r.addAll(LIFECYCLE);
        r.add(SCHEDULED);
        r.add(JSON_CREATOR);
        // Jackson serialization callbacks invoked reflectively during (de)serialization, no project call
        // site: @JsonValue (custom serialize), @JsonAnySetter (deser overflow), @JsonAnyGetter (ser).
        r.add("annotation/JsonValue");
        r.add("annotation/JsonAnySetter");
        r.add("annotation/JsonAnyGetter");
        r.add("ejb/Schedule");   // EJB timer (jakarta/javax) — container-invoked on a schedule
        // Micronaut + Quarkus @Scheduled — the inconsistency with the already-rooted Spring @Scheduled (a
        // container-invoked timer on a top-tier framework).
        r.add("micronaut/scheduling/annotation/Scheduled");
        r.add("quarkus/scheduler/Scheduled");
        // jakarta/javax.websocket POJO @ServerEndpoint handlers — the container invokes the @OnMessage/
        // @OnOpen/@OnClose/@OnError methods with no project call site, and there's no interface form for the
        // annotated style (round-13). The substring covers javax/ + jakarta/ websocket.
        r.add("websocket/OnMessage"); r.add("websocket/OnOpen");
        r.add("websocket/OnClose"); r.add("websocket/OnError");
        ROOT_ANNOTATIONS = List.copyOf(r);
    }

    /** Marker annotations that appear on a PARAMETER (not the method) yet still mean the runtime invokes
     *  the method with no project call site. CDI's `@Observes`/`@ObservesAsync` are the canonical case:
     *  `void on(@Observes E e)` is a container-fired event observer. Covers javax/ + jakarta/ enterprise. */
    static final List<String> PARAM_ROOT_ANNOTATIONS = List.of(
            "enterprise/event/Observes", "enterprise/event/ObservesAsync");

    /** Whether any of the method's parameters carries one of the param-root markers (meta-annotation aware).
     *  ASM exposes per-parameter annotations as a {@code List<AnnotationNode>[]} (one slot per parameter). */
    static boolean anyParamAnnoMatches(MethodNode mn, List<String> markers) {
        return paramAnnoListHas(mn.visibleParameterAnnotations, markers)
                || paramAnnoListHas(mn.invisibleParameterAnnotations, markers);
    }

    static boolean paramAnnoListHas(List<AnnotationNode>[] params, List<String> markers) {
        if (params == null) return false;
        for (List<AnnotationNode> p : params)
            if (annoOrMetaMatches(p, markers)) return true;
        return false;
    }

    /** Whether any annotation in `anns` — DIRECTLY or via its META-annotation chain — matches a marker.
     *  Spring's stereotype model is composed annotations (`@GetMapping` is meta-annotated `@RequestMapping`;
     *  teams define `@ApiEndpoint = @GetMapping`), so a direct-only check orphans framework-invoked methods.
     *  Resolves each annotation TYPE's own annotations (project class via byName, else off candor's classpath
     *  via ASM), recursing with a visited-set + depth bound; JDK meta-annotations are skipped. The
     *  decoy-safe property holds: an UNRELATED `@com.myapp.GetMapping` whose meta-chain never reaches a real
     *  marker is not rooted (no fabrication). */
    static boolean annoOrMetaMatches(List<AnnotationNode> anns, List<String> markers) {
        if (anns == null) return false;
        Set<String> visited = new HashSet<>();
        for (AnnotationNode a : anns)
            if (a.desc != null && annoDescMatchesMeta(a.desc, markers, visited, 0)) return true;
        return false;
    }

    static boolean annoDescMatchesMeta(String desc, List<String> markers, Set<String> visited, int depth) {
        for (String m : markers) if (desc.contains(m)) return true;
        if (depth >= 5 || !desc.startsWith("L") || !desc.endsWith(";")) return false;
        String internal = desc.substring(1, desc.length() - 1);
        // a JDK meta-annotation (@Retention/@Target/@Documented/@Inherited) never reaches a framework marker
        if (internal.startsWith("java/") || !visited.add(internal)) return false;
        List<AnnotationNode> meta = annotationTypeAnnotations(internal);
        if (meta == null) return false;
        for (AnnotationNode a : meta)
            if (a.desc != null && annoDescMatchesMeta(a.desc, markers, visited, depth + 1)) return true;
        return false;
    }

    /** The visible annotations declared ON an annotation type (its meta-annotations), or null if
     *  unresolvable. A project annotation comes from byName; a framework one is read off candor's classpath
     *  via ASM (same posture as {@link #externalSupers}). Cached per type. */
    static final Map<String, List<AnnotationNode>> annoMetaCache = new HashMap<>();
    static List<AnnotationNode> annotationTypeAnnotations(String internal) {
        if (annoMetaCache.containsKey(internal)) return annoMetaCache.get(internal);
        List<AnnotationNode> out = null;
        ClassNode cn = byName.get(internal);
        if (cn != null) out = cn.visibleAnnotations;
        else {
            try {
                ClassNode an = new ClassNode();
                new ClassReader(internal).accept(an,
                        ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                out = an.visibleAnnotations;
            } catch (Throwable t) { /* not on candor's classpath → unresolvable, stays unrooted (sound) */ }
        }
        annoMetaCache.put(internal, out);
        return out;
    }

    static int firstLine(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) if (insn instanceof LineNumberNode ln) return ln.line;
        return 0;
    }

    /** Transitive supertypes (internal names) of a type. For a PROJECT class the supers come from its
     *  ClassNode; for an EXTERNAL ancestor they are read off candor's runtime classpath via ASM. The
     *  external walk matters because a project class can extend an external type (`class LoudList extends
     *  ArrayList`) and override a method DECLARED further up the EXTERNAL chain (`List.add`); without
     *  walking ArrayList's own supers, `LoudList` is never filed under `List`, so a base-typed dispatch on
     *  the grandparent interface (`l.add()` where `l: List`) finds no project subtype and goes silent-pure. */
    static Set<String> transSupers(String internal) {
        Set<String> cached = transSupersCache.get(internal);
        if (cached != null) return cached;
        Set<String> r = new HashSet<>();
        transSupersCache.put(internal, r); // seed first to break cycles
        List<String> sup = new ArrayList<>();
        ClassNode cn = byName.get(internal);
        if (cn != null) {
            if (cn.superName != null) sup.add(cn.superName);
            if (cn.interfaces != null) sup.addAll(cn.interfaces);
        } else {
            sup.addAll(externalSupers(internal));  // a JDK/library ancestor — read its own supers off the classpath
        }
        for (String s : sup) { r.add(s); r.addAll(transSupers(s)); }
        return r;
    }

    /** Whether `internal` is a RUNTIME-INVOKED task type — implements Runnable/Callable or extends Thread
     *  (transitively, including through external supertypes via {@link #transSupers}). Such a class's
     *  run()/call() is invoked by an executor/scheduler with no in-project call site. */
    static boolean isTaskType(String internal) {
        Set<String> s = transSupers(internal);
        return s.contains("java/lang/Runnable") || s.contains("java/util/concurrent/Callable")
                || s.contains("java/lang/Thread") || s.contains("java/util/concurrent/ForkJoinTask");
    }

    /** JDK executor owners whose submit/execute/schedule verbs invoke a Runnable/Callable TASK argument. */
    static final Set<String> EXECUTOR_OWNERS = Set.of(
            "java/util/concurrent/Executor", "java/util/concurrent/ExecutorService",
            "java/util/concurrent/ScheduledExecutorService", "java/util/concurrent/AbstractExecutorService",
            "java/util/concurrent/ThreadPoolExecutor", "java/util/concurrent/ScheduledThreadPoolExecutor",
            "java/util/concurrent/ForkJoinPool");

    /** A call that HANDS OFF a Runnable/Callable task to a runtime that invokes it — an executor
     *  submit/execute/schedule verb, or `new Thread(task)`. Gated on the FIRST parameter being the task
     *  (Runnable/Callable), which is always the deepest argument, so the owner+verb set stays small and a
     *  project method that merely happens to be named `submit` is excluded by the owner gate. */
    static boolean isExecutorHandoff(String owner, String name, String desc) {
        if (desc == null || !(desc.startsWith("(Ljava/lang/Runnable;")
                || desc.startsWith("(Ljava/util/concurrent/Callable;"))) return false;
        if (owner.equals("java/lang/Thread") && name.equals("<init>")) return true;
        return EXECUTOR_OWNERS.contains(owner)
                && (name.equals("submit") || name.equals("execute") || name.equals("schedule")
                    || name.equals("scheduleAtFixedRate") || name.equals("scheduleWithFixedDelay"));
    }

    /** The TASK argument (arg0 — the deepest) of an executor hand-off call, from the provenance frame. */
    static ProvValue handoffTaskArg(Frame<ProvValue> f, MethodInsnNode min) {
        if (f == null) return null;
        int argSlots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) argSlots += a.getSize();
        int idx = f.getStackSize() - argSlots; // arg0 sits at the bottom of the call's argument block
        return idx >= 0 && idx < f.getStackSize() ? f.getStack(idx) : null;
    }

    /** Direct supertypes (internal names) of an EXTERNAL class, read off candor's runtime classpath via
     *  ASM. JDK classes (java/util/ArrayList → AbstractList → List/Collection) resolve; the SCANNED
     *  project's own third-party deps are not on candor's classpath, so they fail to load and yield nothing
     *  — the same sound under-approximation as before (never fabrication). Never throws. Cached per name. */
    static final Map<String, List<String>> externalSupersCache = new HashMap<>();
    static List<String> externalSupers(String internal) {
        List<String> cached = externalSupersCache.get(internal);
        if (cached != null) return cached;
        List<String> out = new ArrayList<>();
        try {
            ClassReader cr = new ClassReader(internal);
            if (cr.getSuperName() != null) out.add(cr.getSuperName());
            for (String i : cr.getInterfaces()) out.add(i);
        } catch (Throwable t) { /* not on candor's classpath / unreadable → no supers (sound) */ }
        externalSupersCache.put(internal, out);
        return out;
    }

    /** Build the reverse-subtype index ONCE: owner -> loaded classes that are owner-or-a-subtype, in
     *  `ALL` order. For each loaded class `c` we record `c.name` against itself and against every
     *  transitive supertype of `c.name` — the exact inverse of chaTargets()'s old per-class predicate
     *  `c.name == owner || transSupers(c.name).contains(owner)`. Iterating `classes` (== `ALL`) in
     *  order makes every owner's candidate list identical, element-for-element AND in the same order,
     *  to the old ALL-scan that filtered by that predicate. Reuses the memoized transSupers. */
    static void buildSubtypeIndex(List<ClassNode> classes) {
        for (ClassNode c : classes) {
            // self: the `c.name == owner` arm. (No dedupe needed — a class appears once in `classes`,
            // and `c.name ∉ transSupers(c.name)` for a well-formed acyclic chain; transSupers seeds the
            // cache before recursing so a self-cycle can't add c.name to its own super set.)
            subtypeIndex.computeIfAbsent(c.name, k -> new ArrayList<>()).add(c.name);
            // every transitive supertype: the `transSupers(c.name).contains(owner)` arm.
            for (String sup : transSupers(c.name))
                subtypeIndex.computeIfAbsent(sup, k -> new ArrayList<>()).add(c.name);
        }
    }

    /** CHA: project subtypes-or-self of `owner` that provide a concrete (name,desc) impl. */
    static List<String> chaTargets(String owner, String name, String desc) {
        Set<String> out = new LinkedHashSet<>();
        // O(subtypes-of-owner) via the precomputed reverse index instead of scanning ALL classes. The
        // candidate set + its order are identical to the old `for (ClassNode c : ALL) if (c.name==owner
        // || transSupers(c.name).contains(owner))` filter (see buildSubtypeIndex), so `out` — and thus
        // cha.size(), the ≤CHA_FANOUT_LIMIT cap, the Unknown-on-overflow, and the edge set — are byte-
        // for-byte unchanged.
        for (String cName : subtypeIndex.getOrDefault(owner, List.of())) {
            ClassNode c = byName.get(cName);
            if (declaresConcrete(c, name, desc)) {
                out.add(methodId(c.name.replace('/', '.'), name, desc));
            } else {
                // c is owner-or-a-subtype that INHERITS the impl from its OWN superchain — a concrete
                // GRANDPARENT (the ubiquitous `Foo` / `Foo$AbstractBase` library pattern, where the impl
                // lives in a shared base like `FilterableList$AbstractBase`). The receiver-type-only and
                // owner-superchain checks both miss it, because the impl is reached by going DOWN from
                // owner to c then UP c's chain. Resolve it so the dispatch isn't a false Unknown. (Found
                // by the gradle-cache sweep: byte-buddy `MethodList.filter`/`getOnly` were 600+ false
                // Unknowns inside byte-buddy's own jar — pure methods, so precision, not soundness.)
                String impl = nearestConcreteSuper(c.name, name, desc);
                if (impl != null) out.add(impl);
            }
        }
        // owner itself inherits a concrete from a SUPER (a default on a super-interface) with no subtype
        // contributing — the original single-receiver inherited-concrete case.
        if (out.isEmpty()) {
            String impl = nearestConcreteSuper(owner, name, desc);
            if (impl != null) out.add(impl);
        }
        return new ArrayList<>(out);
    }

    /** The single method a dispatch on a PROVABLY-`new recv` receiver actually invokes: `recv` itself if it
     *  declares a concrete `(name,desc)`, else `recv`'s nearest concrete superclass that does — exactly how
     *  the JVM resolves virtual dispatch on a known concrete type. Used to NARROW an invokevirtual on a
     *  monomorphic receiver, replacing the CHA sibling fan-out with the one real target. Returns null only
     *  if no concrete impl is visible in `recv`'s own chain (then the caller keeps the CHA — sound). */
    static String monomorphicTarget(String recv, String name, String desc) {
        ClassNode c = byName.get(recv);
        if (c != null && declaresConcrete(c, name, desc))
            return methodId(recv.replace('/', '.'), name, desc);
        return nearestConcreteSuper(recv, name, desc);
    }

    /** The concrete `(name, desc)` declaration `internal` would invoke via inheritance: the first one
     *  found walking its supertype chain (excludes `internal` itself — the caller checks that). */
    static String nearestConcreteSuper(String internal, String name, String desc) {
        for (String sup : transSupers(internal)) {
            ClassNode c = byName.get(sup);
            if (c != null && declaresConcrete(c, name, desc)) return methodId(sup.replace('/', '.'), name, desc);
        }
        return null;
    }

    /** The node/edge id for a project method. UNIQUE name in its class → bare `class.method` (so every
     *  non-overloaded method, including every conformance fixture matched by leaf name, is unchanged).
     *  OVERLOADED name (>1 descriptor under `class.method`) → a stable per-overload suffix derived from
     *  the descriptor's param types (`HmacUtils.hmac(byte[])`), so a pure overload no longer unions an
     *  effectful sibling's effect. Keyed by the DECLARING class so the node-build site (the method's own
     *  class) and every edge site (call-site `owner`/CHA-resolved class) agree on the same id. A
     *  desc/owner candor can't see (a non-project owner, an unknown descriptor) falls back to the bare
     *  name — harmless, since those never key a project node. */
    static String methodId(String dottedClass, String name, String desc) {
        Set<String> descs = overloadDescs.get(dottedClass + "." + name);
        // Bare name unless this is a genuine overload with a parseable METHOD descriptor. The `(` guard is
        // defence-in-depth: a non-method descriptor (a field handle that slipped a caller's guard) must
        // never reach Type.getArgumentTypes, which overruns and crashes the scan on anything without `()`.
        if (descs == null || descs.size() <= 1 || desc == null || !desc.startsWith("("))
            return dottedClass + "." + name;
        String suffix = paramTypeList(desc);
        // Simple param names CAN collide across overloads whose param types share a SIMPLE name from
        // different packages (`f(a.User)` vs `f(b.User)` both → "User") — Java forbids same-ERASED-descriptor
        // overloads, not same-simple-name ones. Two overloads sharing a node id UNION their effects →
        // fabrication on the pure sibling (and every caller of it). When the readable suffix is ambiguous,
        // fall back to FULLY-QUALIFIED param names (unique per descriptor); the common non-colliding case
        // keeps the short, readable form.
        boolean ambiguous = descs.stream()
                .filter(d -> d != null && d.startsWith("(") && !d.equals(desc))
                .anyMatch(d -> paramTypeList(d).equals(suffix));
        return dottedClass + "." + name + "(" + (ambiguous ? paramTypeListFq(desc) : suffix) + ")";
    }

    /** Like {@link #paramTypeList} but with FULLY-QUALIFIED object names — the collision-free disambiguator
     *  used only when simple names clash across a class's overloads. */
    static String paramTypeListFq(String desc) {
        StringBuilder sb = new StringBuilder();
        try {
            for (Type t : Type.getArgumentTypes(desc)) {     // fail soft on a malformed descriptor (see paramTypeList)
                if (sb.length() > 0) sb.append(',');
                sb.append(fqTypeName(t));
            }
        } catch (Throwable t) { return ""; }
        return sb.toString();
    }

    static String fqTypeName(Type t) {
        if (t.getSort() == Type.ARRAY) return fqTypeName(t.getElementType()) + "[]".repeat(t.getDimensions());
        return t.getClassName(); // OBJECT → fully-qualified (a.User); primitive → int/long/...
    }

    /** A method descriptor's argument types as a readable, comma-separated list of source-form names
     *  (`(MessageDigest,byte[])` -> `MessageDigest,byte[]`) — the human-facing overload disambiguator.
     *  Stable per descriptor and collision-free across a class's overloads (Java forbids two overloads
     *  with the same erased parameter types). */
    static String paramTypeList(String desc) {
        StringBuilder sb = new StringBuilder();
        // Type.getArgumentTypes validates the descriptor lazily and THROWS on a malformed one (e.g. a
        // missing `;` — ASM stores the raw UTF8 and doesn't check at parse time). Fail soft: a bad
        // descriptor yields an empty suffix rather than aborting the scan (the per-class guard in runScan
        // also catches it, but keeping methodId total is cheaper and keeps the id stable-ish).
        try {
            for (Type t : Type.getArgumentTypes(desc)) {
                if (sb.length() > 0) sb.append(',');
                sb.append(shortTypeName(t));
            }
        } catch (Throwable t) { return ""; }
        return sb.toString();
    }

    /** A Type as its short source name: `byte[]`, `MessageDigest` (simple name for objects, so the
     *  suffix stays readable), `int`, etc. */
    static String shortTypeName(Type t) {
        if (t.getSort() == Type.ARRAY)
            return shortTypeName(t.getElementType()) + "[]".repeat(t.getDimensions());
        if (t.getSort() == Type.OBJECT) {
            String cn = t.getClassName();
            int dot = cn.lastIndexOf('.');
            return dot >= 0 ? cn.substring(dot + 1) : cn;
        }
        return t.getClassName(); // primitives: int, long, byte, ...
    }

    static boolean declaresConcrete(ClassNode c, String name, String desc) {
        for (MethodNode mn : c.methods)
            if (mn.name.equals(name) && mn.desc.equals(desc) && (mn.access & Opcodes.ACC_ABSTRACT) == 0)
                return true;
        return false;
    }

    static boolean isProjectIfaceOrAbstract(String internal) {
        ClassNode cn = byName.get(internal);
        return cn != null && (cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT)) != 0;
    }

    /** Does the PROJECT itself declare `(name, desc)` somewhere in `owner`'s own hierarchy (owner or a
     *  project supertype)? Distinguishes a genuine project abstraction whose impl is missing (→ honest
     *  Unknown) from a framework method merely INHERITED by a project type, which resolves to a
     *  superclass candor never loaded and is just an ordinary external call. byName holds only project
     *  classes, so a framework-only method (declared solely in an unloaded superclass) returns false. */
    static boolean projectDeclaresMethod(String owner, String name, String desc) {
        Set<String> types = new HashSet<>(transSupers(owner));
        types.add(owner);
        for (String t : types) {
            ClassNode c = byName.get(t);
            if (c == null) continue; // framework supertype — not a project declaration
            for (MethodNode mn : c.methods)
                if (mn.name.equals(name) && mn.desc.equals(desc)) return true;
        }
        return false;
    }

    /** Propagate the Fs read/write detail along the SAME call graph as effects, in a separate set. A
     *  function reaching the filesystem only across a jar boundary inherits `Fs` with NO recorded kind
     *  (FS_UNKNOWN), so the report presents an empty `fs` (no claim) rather than a misleading partial. */
    static Map<String, TreeSet<String>> fsFixpoint() {
        Map<String, TreeSet<String>> fs = new HashMap<>();
        for (var e : fsDirect.entrySet()) fs.put(e.getKey(), new TreeSet<>(e.getValue()));
        for (var e : viaCross.entrySet())
            if (e.getValue().contains("Fs")) fs.computeIfAbsent(e.getKey(), k -> new TreeSet<>()).add(FS_UNKNOWN);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : edges.keySet()) {
                TreeSet<String> add = new TreeSet<>();
                for (String c : edges.get(caller)) {
                    var ce = fs.get(c);
                    if (ce != null) add.addAll(ce);
                }
                if (add.isEmpty()) continue;
                var set = fs.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                set.addAll(add);
                if (set.size() != before) changed = true;
            }
        }
        return fs;
    }

    static Map<String, TreeSet<String>> fixpoint() {
        return computeFixpoint(direct, edges, viaCross);
    }

    /** The PURE least-fixpoint of effect propagation over the call graph — factored out of
     *  {@link #fixpoint()} with its three inputs passed explicitly (no static reads) so it is
     *  unit-testable with synthetic graphs. {@code direct} = each fn's own-body effects;
     *  {@code edges} = caller → callees; {@code viaCross} = effects inherited from a CANDOR_DEPS
     *  sibling report. Result: each fn's transitive (inferred) effect set. */
    static Map<String, TreeSet<String>> computeFixpoint(
            Map<String, TreeSet<String>> direct,
            Map<String, Set<String>> edges,
            Map<String, TreeSet<String>> viaCross) {
        Map<String, TreeSet<String>> eff = new HashMap<>();
        for (var k : direct.keySet()) eff.put(k, new TreeSet<>(direct.get(k)));
        // Seed in effects inherited via cross-jar calls (kept out of `direct` — they're not in this
        // method's own body; they appear in `inferred` and propagate transitively, like the Rust impl).
        for (var e : viaCross.entrySet()) eff.computeIfAbsent(e.getKey(), k -> new TreeSet<>()).addAll(e.getValue());
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : edges.keySet()) {
                var set = eff.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                for (String callee : edges.get(caller)) {
                    // A class-load TRIGGER edge propagates the `<clinit>`'s FULL transitive effects (spec §5:
                    // `inferred` is the transitive fixpoint over edges). Touching the class runs its static
                    // initializer, which can transitively reach whatever the static block calls or constructs,
                    // so the trigger site CAN reach those effects — sound over-approximation ("can reach"). A
                    // prior direct-only narrowing here under-reported (the §7.13 soundness fuzzer caught it on
                    // every clinit form: a real effect threaded through a static block came back pure). The
                    // guava-construction `Log` smear that narrowing avoided is sound-but-imprecise — the target
                    // of a separate precision effort, never a reason to drop a real reachable effect.
                    var ce = eff.get(callee);
                    if (ce != null) set.addAll(ce);
                }
                if (set.size() != before) changed = true;
            }
        }
        return eff;
    }

    /** Classify a resolved call by target class + method — match the I/O boundary, not the package. */
    /** For a call ALREADY classified `Fs`, the read/write direction its verb implies: ["read"],
     *  ["write"], ["read","write"] (e.g. Files.copy), or [] when the verb doesn't say (so we make no
     *  claim). Keyed off the java.io / java.nio.file vocabulary — a syntactic refinement of an effect
     *  candor already proved, NOT a soundness claim. */
    static List<String> fsKind(String owner, String method) {
        if (method.equals("<init>")) { // a stream constructor reveals direction by its type
            if (owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileReader")) return List.of("read");
            if (owner.equals("java.io.FileOutputStream") || owner.equals("java.io.FileWriter")) return List.of("write");
            return List.of(); // RandomAccessFile (mode-dependent), File (no I/O) — no claim
        }
        if (method.equals("copy")) return List.of("read", "write");
        switch (method) {
            case "write": case "writeString": case "newOutputStream": case "newBufferedWriter":
            case "createFile": case "createDirectory": case "createDirectories": case "createTempFile":
            case "createTempDirectory": case "delete": case "deleteIfExists": case "move":
            case "setAttribute": case "setLastModifiedTime": case "setPosixFilePermissions":
            case "setOwner": case "createLink": case "createSymbolicLink": case "mkdir": case "mkdirs":
            case "renameTo": case "createNewFile": case "setReadable": case "setWritable":
            case "setExecutable": case "setLastModified": case "deleteOnExit": case "truncate":
                return List.of("write");
            case "readAllBytes": case "readString": case "readAllLines": case "lines":
            case "newInputStream": case "newBufferedReader": case "exists": case "notExists":
            case "isDirectory": case "isRegularFile": case "isReadable": case "isWritable":
            case "isExecutable": case "size": case "length": case "getLastModifiedTime":
            case "readAttributes": case "getAttribute": case "list": case "listFiles": case "walk":
            case "find": case "newDirectoryStream": case "isSameFile": case "mismatch":
            case "probeContentType": case "canRead": case "canWrite": case "canExecute":
            case "lastModified": case "toRealPath": case "readSymbolicLink": case "isHidden":
            case "getFreeSpace": case "getTotalSpace": case "getUsableSpace":
                return List.of("read");
            default: break;
        }
        if (method.startsWith("write") || method.equals("append")) return List.of("write");
        if (method.startsWith("read")) return List.of("read");
        return List.of();
    }

    /** Packages OUTSIDE the ledger: the platform/runtime frontier (κ's builtin job — JDK, the
     *  language runtimes) and the verb-precise third-party packages κ already covers, where zero
     *  classifications can be legitimate (the app only touches their pure surface). Segment-exact
     *  prefixes so `javassist` is not mistaken for `java`. Hoisted to a static (the check runs in
     *  the per-instruction hot loop). */
    static final String[] KAPPA_COVERED_PREFIXES = { "java", "javax", "jakarta", "jdk", "sun", "com.sun",
            "kotlin", "kotlinx", "scala", "groovy", "org.codehaus.groovy", "org.jetbrains",
            "org.springframework", "io.ktor", "org.slf4j", "org.apache.logging", "ch.qos.logback" };

    static boolean kappaCovers(String pkg) {
        for (String p : KAPPA_COVERED_PREFIXES) {
            if (pkg.equals(p) || (pkg.length() > p.length() && pkg.charAt(p.length()) == '.' && pkg.startsWith(p))) return true;
        }
        return false;
    }

    /** Proven-PURE accessors/factories/inert ctors on owners whose effect is otherwise whole-owner
     *  (File→Fs, Socket→Net, Clock, Random→Rand, ZipFile/JarFile→Fs, Clipboard). The cardinal sin of
     *  an effect-checker is fabricating an effect on a PURE method, so we SUBTRACT only the methods we
     *  can prove do NO I/O / read NO entropy / read NO clock — and KEEP the whole-owner effect for
     *  everything else (the safe direction: when in doubt, KEEP it effectful). Mirrors the verb-gating
     *  already done for java.nio.file.Files, java.sql.Statement, kotlin.io.FilesKt, ktor, InetAddress,
     *  JNDI. Consulted by `classify` BEFORE the owner-match fires; returns true ⇒ classify returns null.
     *  CRITICAL: this may only ever REMOVE a fabrication, never introduce an under-report, so the
     *  effectful members of each type (delete/exists/getCanonicalPath; getInput/OutputStream; instant;
     *  nextInt/getSeed; entries; getContents) are deliberately ABSENT here and keep firing. */
    static boolean isPureHandleAccessor(String owner, String method) {
        switch (owner) {
            // java.io.File — a File is just an immutable PATHNAME object; these touch NO filesystem.
            // The inert ctor (`new File(...)`) does ZERO I/O (it stores the path string). The effectful
            // members — delete/exists/isDirectory/mkdir/listFiles/getCanonicalPath/getCanonicalFile
            // (resolve symlinks → touch the FS) — are NOT listed, so they keep returning Fs.
            case "java.io.File":
                return method.equals("<init>") || method.equals("getName") || method.equals("getParent")
                        || method.equals("getParentFile") || method.equals("getPath")
                        || method.equals("getAbsolutePath") || method.equals("getAbsoluteFile")
                        || method.equals("isAbsolute") || method.equals("toURI") || method.equals("toPath")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals")
                        || method.equals("compareTo");
            // java.net.Socket family — these read fields cached on the handle (the port/address bound at
            // construct/connect time, the closed/bound/connected flags); they do NO wire I/O. The I/O
            // boundary (getInputStream/getOutputStream/connect/bind/send/receive/close) is NOT listed.
            case "java.net.Socket":
            case "java.net.ServerSocket":
            case "java.net.DatagramSocket":
                return method.equals("getPort") || method.equals("getLocalPort")
                        || method.equals("getInetAddress") || method.equals("getLocalAddress")
                        || method.equals("getLocalSocketAddress") || method.equals("getRemoteSocketAddress")
                        || method.equals("isClosed") || method.equals("isBound") || method.equals("isConnected")
                        || method.equals("isInputShutdown") || method.equals("isOutputShutdown")
                        || method.equals("getReuseAddress") || method.equals("getSoTimeout")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            // java.time.Clock — the factories (systemUTC/system/fixed/offset/tick*) build a Clock object
            // and the accessors (getZone/withZone) read its zone; NONE read the wall clock. The actual
            // clock reads — instant()/millis() — are NOT listed, so they keep returning Clock.
            case "java.time.Clock":
                return method.equals("systemUTC") || method.equals("systemDefaultZone")
                        || method.equals("system") || method.equals("fixed") || method.equals("offset")
                        || method.equals("tick") || method.equals("tickMillis") || method.equals("tickSeconds")
                        || method.equals("tickMinutes") || method.equals("getZone") || method.equals("withZone")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            // java.util.Random / SecureRandom / ThreadLocalRandom / SplittableRandom — these read NO
            // entropy: getInstance/getInstanceStrong build a generator, getAlgorithm/getProvider read
            // its metadata. ThreadLocalRandom.current() is a pure thread-local FACTORY: it returns the
            // singleton `instance` and, on first call, seeds the thread's state from an atomic counter
            // (mixMurmur64 of a counter) — NOT from OS entropy/a CSPRNG (verified in the JDK source);
            // the actual draws come later. The draws (next*/ints/longs/doubles/getSeed/generateSeed/
            // setSeed) are NOT listed, so they keep returning Rand.
            case "java.util.Random":
            case "java.security.SecureRandom":
            case "java.util.concurrent.ThreadLocalRandom":
            case "java.util.SplittableRandom":
                return method.equals("getInstance") || method.equals("getInstanceStrong")
                        || method.equals("getAlgorithm") || method.equals("getProvider")
                        || method.equals("getParameters") || method.equals("current")
                        || method.equals("toString");
            // java.util.zip.ZipFile / java.util.jar.JarFile — getName returns the cached path, size()
            // returns the cached entry count (no re-read of the archive). The ctor (OPENS the archive),
            // entries()/getInputStream()/getEntry()/stream() (READ it) are NOT listed → keep Fs.
            case "java.util.zip.ZipFile":
            case "java.util.jar.JarFile":
                return method.equals("getName") || method.equals("size") || method.equals("toString");
            // java.awt.datatransfer.Clipboard — getName returns the clipboard's label; the actual
            // get/setContents (read/write the system clipboard) are NOT listed → keep Clipboard.
            case "java.awt.datatransfer.Clipboard":
                return method.equals("getName") || method.equals("toString");
            // java.nio.channels.FileChannel / AsynchronousFileChannel — isOpen() is `!closed`, a pure
            // field read inherited from AbstractInterruptibleChannel (verified in the JDK source). The
            // real file I/O — read/write/map/force/truncate/transferTo/transferFrom/lock/size — is NOT
            // listed → keeps Fs. DELIBERATELY ABSENT: position() (the no-arg getter). Despite looking
            // like a cached accessor, FileChannelImpl.position() issues an lseek syscall (nd.seek(fd,-1))
            // to read the current OS file-pointer, so it is genuine Fs I/O — the SAFETY RULE (keep the
            // effect when not PROVABLY pure) forbids subtracting it.
            case "java.nio.channels.FileChannel":
            case "java.nio.channels.AsynchronousFileChannel":
                return method.equals("isOpen")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            // java.nio.channels socket channels — the accessors read fields cached on the handle (open
            // flag, connect state, blocking mode, the addresses bound/connected at setup time) and
            // socket() lazily wraps the channel in an adaptor object; NONE touch the wire (verified in
            // SocketChannelImpl/ServerSocketChannelImpl/DatagramChannelImpl). The network boundary —
            // connect/finishConnect/read/write/send/receive/bind/accept — is NOT listed → keeps Net.
            case "java.nio.channels.SocketChannel":
            case "java.nio.channels.ServerSocketChannel":
            case "java.nio.channels.DatagramChannel":
                return method.equals("isOpen") || method.equals("isConnected")
                        || method.equals("isConnectionPending") || method.equals("isBlocking")
                        || method.equals("getLocalAddress") || method.equals("getRemoteAddress")
                        || method.equals("socket")
                        // config/registration verbs touch NO wire — a whole-owner Net rule fabricated Net on
                        // them (cardinal sin, found by a NIO sweep). setOption sets a socket option,
                        // configureBlocking sets a flag, register registers interest with a selector,
                        // supportedOptions returns a static Set, bind selects a local endpoint.
                        || method.equals("setOption") || method.equals("getOption")
                        || method.equals("supportedOptions") || method.equals("configureBlocking")
                        || method.equals("register") || method.equals("validOps")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            default:
                return false;
        }
    }

    // The `Log` effect means PRODUCING a log record. The genuine emit surface across slf4j / jul /
    // log4j2 / logback is a NARROW, NAMED set of verbs on the Logger (and the fluent builder's terminal
    // `log()`, the backend Appender/Handler append). Everything else in those packages — Markers, Levels,
    // ThreadContext maps, Message data types, formatters, config/registry lookups, util helpers — emits
    // NOTHING. The classify() gate therefore fires Log ONLY on these verbs (VERB-PRECISE), letting every
    // other logging-package method fall through to its real, transitively-analysed effect (a util that
    // reads env is Env, a config loader that reads a file is Fs) — never a fabricated Log.
    //
    // This replaces an earlier whole-package gate + a growing per-type pure-accessor allowlist: a real
    // log4j-api scan showed the whole-package rule fabricated Log on ~100 non-Logger classes (and MASKED
    // their genuine Env/Fs). Verb-precise is the same narrowing the Rust classifier applies to
    // effect-bearing crates. SAFETY (no lost Log): every public emit entry point is named here, and
    // loggers reach the backend through these verbs, so Log still propagates through the call graph.
    static boolean isLogEmitVerb(String method) {
        switch (method) {
            // slf4j / log4j2 / logback shared level verbs + the generic log()
            case "trace": case "debug": case "info": case "warn": case "error":
            case "fatal": case "log":
            // jul level verbs + structured/localised emit
            case "severe": case "warning": case "config": case "fine": case "finer": case "finest":
            case "logp": case "logrb": case "entering": case "exiting":
            // throwable-logging emit (all four frameworks)
            case "catching": case "throwing":
            // log4j2 internal emit pipeline (public verbs delegate through these; named so Log propagates
            // even when the terminal append is out-of-jar) + fluent/structured entry points
            case "logIfEnabled": case "logMessage": case "printf": case "doLog": case "forcedLog":
            case "logEvent": case "traceEntry": case "traceExit":
            // backend append / publish (log4j-core Appender, jul Handler, logback Appender)
            case "doAppend": case "append": case "callAppenders": case "publish":
                return true;
            default:
                return false;
        }
    }

    static String classify(String owner, String method, String desc) {
        // A proven-pure accessor/factory/inert-ctor on an otherwise-effectful handle type is PURE — the
        // whole-owner rules below would fabricate the type's effect on it (the cardinal sin). Subtract
        // these explicitly; everything else on the type keeps its effect. (See isPureHandleAccessor.)
        if (isPureHandleAccessor(owner, method)) return null;
        // Reflection / dynamic invocation — could call ANYTHING; honestly `Unknown`, never assumed
        // pure (SPEC §4 trust contract). This is the JVM's defining opacity, and the foundation of
        // the framework magic (Spring proxies, DI) candor can't otherwise see through.
        if (owner.equals("java.lang.reflect.Method") && method.equals("invoke")) return "Unknown";
        if (owner.equals("java.lang.reflect.Constructor") && method.equals("newInstance")) return "Unknown";
        if (owner.equals("java.lang.Class") && (method.equals("newInstance") || method.equals("forName")))
            return "Unknown";
        if (owner.equals("java.lang.reflect.Proxy") && method.equals("newProxyInstance")) return "Unknown";
        // Groovy dynamic dispatch IS reflection: MetaClass/GroovyObject.invokeMethod resolves the target
        // at runtime through the metaclass registry and can call anything (the engine's own provenance
        // trace ran through ExpandoMetaClass.invokeMethod into ProcessGroovyMethods.execute). Honest
        // Unknown for consumers, exactly like Method.invoke.
        if ((owner.startsWith("groovy.lang.MetaClass") || owner.equals("groovy.lang.GroovyObject")
                || owner.equals("groovy.lang.MetaObjectProtocol") || owner.equals("groovy.lang.GroovyShell")
                || owner.equals("groovy.lang.Script"))
                && (method.startsWith("invoke") || method.equals("run") || method.equals("evaluate")))
            return "Unknown";
        if (owner.equals("java.lang.invoke.MethodHandle") && method.startsWith("invoke")) return "Unknown";

        // ── ARBITRARY-CODE-EXECUTION / OPAQUE sinks → Unknown (could perform ANY effect; same posture as
        // reflection/Method.invoke and candor-ts's `eval()`). These run a code/expression string, deserialize
        // untrusted data (gadget-chain RCE), parse XXE-able XML, or call native code — all security sinks
        // that read SILENT-PURE (no classify row; their JDK packages are even κ-"covered" so undisclosed).
        // Scripting / expression-language eval:
        if ((owner.equals("javax.script.ScriptEngine") || owner.equals("javax.script.CompiledScript")
                || owner.equals("javax.script.Invocable") || owner.equals("javax.script.Compilable"))
                && (method.equals("eval") || method.startsWith("invoke") || method.equals("compile")))
            return "Unknown";
        if (owner.equals("org.springframework.expression.Expression") && method.startsWith("getValue")) return "Unknown";
        if (owner.equals("ognl.Ognl") && (method.equals("getValue") || method.equals("setValue"))) return "Unknown";
        if (owner.equals("org.mvel2.MVEL") && (method.equals("eval") || method.startsWith("execute"))) return "Unknown";
        if (owner.equals("org.apache.commons.jexl3.JexlExpression") && method.equals("evaluate")) return "Unknown";
        if (owner.startsWith("jakarta.el.") && method.equals("getValue")) return "Unknown";
        if (owner.startsWith("javax.el.") && method.equals("getValue")) return "Unknown";
        if (owner.equals("groovy.util.Eval") || owner.equals("groovy.lang.GroovyClassLoader")) return "Unknown";
        if (owner.equals("bsh.Interpreter") && method.equals("eval")) return "Unknown";
        if (owner.equals("org.jruby.embed.ScriptingContainer") && method.startsWith("runScriptlet")) return "Unknown";
        if (owner.equals("org.python.util.PythonInterpreter") && (method.equals("exec") || method.equals("eval"))) return "Unknown";
        if (owner.equals("clojure.lang.Compiler") && method.equals("eval")) return "Unknown";
        if (owner.equals("javax.tools.JavaCompiler") && method.equals("run")) return "Unknown";
        // Untrusted deserialization (gadget-chain RCE) + XXE-able XML parsing → Unknown (the realized effect
        // depends on the payload/config a static pass can't see). ObjectInputStream.readObject is THE classic
        // Java RCE sink; candor roots a project class's readObject CALLBACK but the readObject CALL is the sink.
        if (owner.equals("java.io.ObjectInputStream") && (method.equals("readObject") || method.equals("readUnshared")))
            return "Unknown";
        if (owner.equals("java.beans.XMLDecoder") && method.equals("readObject")) return "Unknown";
        if ((owner.equals("javax.xml.parsers.DocumentBuilder") || owner.equals("javax.xml.parsers.SAXParser")
                || owner.equals("org.xml.sax.XMLReader")) && method.equals("parse"))
            return "Unknown";
        if (owner.equals("javax.xml.transform.Transformer") && method.equals("transform")) return "Unknown";
        // FFI / native execution: a native call runs arbitrary machine code (opaque like a `native` body,
        // already Unknown). JNA Function.invoke* / Library-interface dispatch / Unsafe raw memory / Panama
        // symbol+upcall / Instrumentation rewrite → Unknown; load-a-native-lib / attach-to-another-JVM → Exec.
        if (owner.equals("com.sun.jna.Function") && method.startsWith("invoke")) return "Unknown";
        if ((owner.equals("sun.misc.Unsafe") || owner.equals("jdk.internal.misc.Unsafe"))
                && (method.endsWith("Memory") || method.startsWith("put") || method.startsWith("get")
                    || method.equals("defineClass") || method.equals("defineAnonymousClass")
                    || method.equals("allocateInstance")))
            return "Unknown";
        if ((owner.equals("java.lang.foreign.SymbolLookup") && method.equals("find"))
                || (owner.equals("java.lang.foreign.Linker") && method.equals("upcallStub")))
            return "Unknown";
        if (owner.equals("java.lang.instrument.Instrumentation")
                && (method.equals("redefineClasses") || method.equals("retransformClasses"))) return "Unknown";
        if (owner.equals("com.sun.jna.Native") && method.equals("load")) return "Exec";  // loads + runs native lib init
        if (owner.equals("com.sun.tools.attach.VirtualMachine")
                && (method.equals("attach") || method.equals("loadAgent") || method.startsWith("loadAgent")))
            return "Exec";  // attaches to + injects code into another process

        // Filesystem — classic java.io streams + NIO file channels (the channel's identity IS file I/O).
        if (owner.equals("java.nio.file.Files")
                || owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileOutputStream")
                || owner.equals("java.io.FileReader") || owner.equals("java.io.FileWriter")
                || owner.equals("java.io.RandomAccessFile") || owner.equals("java.io.File")
                || owner.equals("java.nio.channels.FileChannel")
                || owner.equals("java.nio.channels.AsynchronousFileChannel")
                // Archive readers open and read a file from disk (the ctor opens it, entries/getInputStream
                // read it); ZipEntry/JarEntry data types stay pure. (Found by a controlled JDK probe.)
                || owner.equals("java.util.zip.ZipFile") || owner.equals("java.util.jar.JarFile"))
            return "Fs";
        // MappedByteBuffer is file-backed (returned only by FileChannel.map), so its get*/put*/force/load
        // touch the mapped file → Fs. VERB-GATED (was whole-owner): the inherited Buffer queries
        // capacity()/position()/limit()/remaining()/order()/hasArray()/isDirect()/duplicate()/slice() are
        // PURE in-memory ops — a whole-owner rule fabricated Fs on them (cardinal sin, found by a
        // fabrication sweep). get*/put* don't collide with any pure Buffer method name. isLoaded() does a
        // mincore syscall → Fs.
        if (owner.equals("java.nio.MappedByteBuffer")
                && (method.startsWith("get") || method.startsWith("put")
                    || method.equals("force") || method.equals("load") || method.equals("isLoaded")))
            return "Fs";
        // FileStore disk-space/metadata stats (getTotalSpace/getUsableSpace/type/…) hit the filesystem;
        // FileDescriptor.sync is an fsync syscall. (Files.getFileStore — the open — is already Fs above.)
        if (owner.equals("java.nio.file.FileStore")
                && (method.startsWith("get") || method.equals("type") || method.equals("isReadOnly")
                    || method.equals("supportsFileAttributeView")))
            return "Fs";
        if (owner.equals("java.io.FileDescriptor") && method.equals("sync")) return "Fs";
        // javax.imageio.ImageIO — the dominant image read/write API (analog of FileReader/Files). Gate to the
        // FILE-descriptor overloads: read(File)/write(…,File) do Fs; read(URL) does Net; the stream overloads
        // (read(InputStream)/write(…,OutputStream)) wrap a caller-supplied stream and stay pure (the Fs is on
        // the underlying FileInputStream, caught at its construction).
        if (owner.equals("javax.imageio.ImageIO")) {
            if (method.equals("read") && desc.startsWith("(Ljava/io/File;")) return "Fs";
            if (method.equals("read") && desc.startsWith("(Ljava/net/URL;")) return "Net";
            if (method.equals("write") && desc.contains("Ljava/io/File;")) return "Fs";
        }
        // commons-io FileUtils/IOUtils + guava Files/MoreFiles — the ubiquitous file-convenience libs (the
        // analog of the modeled java.nio.file.Files/FileInputStream/FileWriter). Verb-gated to the file
        // read/write/copy/move/delete operators; the pure helpers (closeQuietly, lineIterator builders) and
        // the in-memory stream overloads of IOUtils (toString(InputStream) is on a stream, not a file —
        // but commons-io's IOUtils is dominantly used for file streams; gate to the unambiguous file verbs).
        if ((owner.equals("org.apache.commons.io.FileUtils"))
                && (method.startsWith("read") || method.startsWith("write") || method.startsWith("copy")
                    || method.startsWith("move") || method.startsWith("delete") || method.startsWith("force")
                    || method.startsWith("touch") || method.startsWith("cleanDirectory")
                    || method.startsWith("listFiles") || method.startsWith("openInputStream")
                    || method.startsWith("openOutputStream") || method.startsWith("iterateFiles")))
            return "Fs";
        if ((owner.equals("com.google.common.io.Files") || owner.equals("com.google.common.io.MoreFiles"))
                // NB: asByteSource/asCharSource/asByteSink/asCharSink are LAZY FACTORIES — they return a
                // Source/Sink VIEW and touch no file until a terminal read/write, so classifying them Fs
                // FABRICATED on a provably-pure builder (round-13 cardinal sin). Only the eager verbs below
                // do I/O.
                && (method.startsWith("toByteArray") || method.startsWith("write") || method.startsWith("copy")
                    || method.startsWith("move") || method.startsWith("readLines")
                    || method.startsWith("createParentDirs") || method.startsWith("touch")
                    || method.startsWith("deleteRecursively") || method.startsWith("deleteDirectoryContents")))
            return "Fs";
        // Classpath RESOURCE reads (a file/jar entry off disk) — the ubiquitous config/i18n-loading idioms:
        // Class/ClassLoader.getResource*, ResourceBundle.getBundle, ServiceLoader (reads META-INF/services),
        // FileSystems.newFileSystem (mounts a jar/zip), LogManager/Preferences (OS prefs store). All Fs.
        if ((owner.equals("java.lang.Class") || owner.equals("java.lang.ClassLoader")
                || owner.equals("java.lang.Module"))
                && (method.equals("getResourceAsStream") || method.equals("getResource")
                    || method.equals("getResources") || method.equals("getSystemResourceAsStream")
                    || method.equals("getSystemResource") || method.equals("getSystemResources"))) return "Fs";
        if (owner.equals("java.util.ResourceBundle") && method.equals("getBundle")) return "Fs";
        if (owner.equals("java.util.ServiceLoader") && method.equals("load")) return "Fs";
        if (owner.equals("java.nio.file.FileSystems") && method.equals("newFileSystem")) return "Fs";
        if (owner.equals("java.util.prefs.Preferences")
                && (method.startsWith("get") || method.startsWith("put") || method.equals("remove")
                    || method.equals("flush") || method.equals("sync"))) return "Fs";
        if (owner.equals("java.util.logging.LogManager") && method.equals("readConfiguration")) return "Fs";
        // java.util.Scanner(File)/(Path) opens and reads a file. CTOR-DESCRIPTOR-GATED: Scanner(String) is
        // pure (a string source) and Scanner(InputStream/Readable) defers to its source's owner — so gate to
        // the File/Path ctor descriptors only (no fabrication on the pure ctors). (JDK Fs-deep probe.)
        if (owner.equals("java.util.Scanner") && method.equals("<init>") && desc != null
                && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")))
            return "Fs";
        // PrintStream/PrintWriter/Formatter open a file directly in their (String fileName)/(File) ctors (no
        // wrapped FileOutputStream to catch elsewhere) → Fs. CTOR-DESCRIPTOR-GATED to the file-opening forms:
        // the (OutputStream)/(Writer)/(Appendable) overloads defer to the wrapped sink and stay pure (so an
        // in-memory PrintWriter(StringWriter)/PrintStream(ByteArrayOutputStream) never fabricates).
        if ((owner.equals("java.io.PrintStream") || owner.equals("java.io.PrintWriter")
                || owner.equals("java.util.Formatter"))
                && method.equals("<init>") && desc != null
                && (desc.startsWith("(Ljava/lang/String;") || desc.startsWith("(Ljava/io/File;")))
            return "Fs";
        // WatchService.take()/poll() block on filesystem change events. java.nio.file.Path is otherwise
        // pure path manipulation (resolve/getParent/normalize), so VERB-gate it: toRealPath resolves
        // symlinks against the live FS and register walks/stats the watched dir. (JDK Fs-deep probe.)
        if (owner.equals("java.nio.file.WatchService") && (method.equals("take") || method.equals("poll")))
            return "Fs";
        if (owner.equals("java.nio.file.Path") && (method.equals("toRealPath") || method.equals("register")))
            return "Fs";
        // Kotlin stdlib file API (kotlin.io FilesKt extensions on java.io.File; kotlin.io.path PathsKt
        // on java.nio.file.Path) — Kotlin's IDIOMATIC filesystem surface, compiled to static calls on
        // these owners. VERB-level, not owner-level: both classes also hold pure path manipulation
        // (relativeTo/normalize/resolve/name accessors), which must stay pure. The stat family
        // (exists/isDirectory/fileSize) is Fs, mirroring the Rust engine's std::path::Path rule. (Found
        // by a Kotlin-idiom probe: `f.readText()` was silent-pure — masked at first by the java.io.File
        // owner-match catching the File CTOR in the same fn.) `$default` wrappers share the base name.
        if (owner.equals("kotlin.io.FilesKt") || owner.equals("kotlin.io.TextStreamsKt")
                || owner.equals("kotlin.io.path.PathsKt")) {
            // A URL-receiver read (`URL.readText()/readBytes()` — TextStreamsKt) is NETWORK egress, not
            // filesystem: the verb-prefix below would mislabel it Fs (a wrong effect, worse than an
            // under-report). The descriptor's first parameter is the receiver. (Found by /code-review max.)
            if (desc != null && desc.startsWith("(Ljava/net/URL;")) return "Net";
            String base = method.endsWith("$default") ? method.substring(0, method.length() - 8) : method;
            if (base.startsWith("read") || base.startsWith("write") || base.startsWith("append")
                    || base.startsWith("copy") || base.startsWith("delete") || base.startsWith("create")
                    || base.startsWith("walk") || base.startsWith("forEach") || base.startsWith("use")
                    || base.startsWith("list") || base.equals("exists") || base.equals("notExists")
                    || base.equals("isDirectory") || base.equals("isRegularFile")
                    || base.equals("isSymbolicLink") || base.equals("fileSize") || base.equals("moveTo")
                    || base.equals("inputStream") || base.equals("outputStream")
                    || base.equals("reader") || base.equals("writer")
                    || base.equals("bufferedReader") || base.equals("bufferedWriter")
                    || base.equals("printWriter") || base.equals("getLastModifiedTime")
                    || base.equals("setLastModifiedTime"))
                return "Fs";
            return null; // Path()/div/name/relativeTo/normalize — pure path manipulation
        }
        // Kotlin stdlib entropy (kotlin.random.Random / Random.Default / top-level RandomKt) — Kotlin's
        // idiomatic randomness; whole-owner, mirroring the java.util.Random handling.
        if (owner.equals("kotlin.random.Random") || owner.equals("kotlin.random.Random$Default")
                || owner.equals("kotlin.random.RandomKt"))
            return "Rand";
        // Kotlin stdlib collection/range/array entropy verbs — `list.random()` / `(1..6).random()` /
        // `arr.random()` / `list.shuffled()` draw entropy inside the stdlib body (candor doesn't descend
        // into kotlin-stdlib), so the VERB must be classified, like kotlin.random.Random above. Verb-gated
        // (these owners have hundreds of pure methods → NOT whole-owner).
        if ((owner.equals("kotlin.collections.CollectionsKt") || owner.equals("kotlin.ranges.RangesKt")
                || owner.equals("kotlin.collections.ArraysKt"))
                && (method.equals("random") || method.equals("randomOrNull") || method.equals("shuffled")
                    || method.equals("shuffle")))
            return "Rand";
        // Groovy GDK — the language's OWN stdlib I/O, which @CompileStatic compiles to direct static calls
        // (as fundamental to Groovy as java.io is to Java). ResourceGroovyMethods holds the File/URL
        // read/write extension methods (`f.text`/`f.bytes`/`f << s` → getText/getBytes/leftShift);
        // ProcessGroovyMethods.execute spawns. Was silent-pure (no classify row + the package is
        // κ-"covered", so not even disclosed). Found by a JVM-dialect sweep. Verb-gated so the pure GDK
        // surface (path/string helpers) stays pure.
        if (owner.equals("org.codehaus.groovy.runtime.ResourceGroovyMethods")) {
            if (desc != null && desc.startsWith("(Ljava/net/URL;")) return "Net"; // URL receiver = network egress
            if (method.startsWith("get") || method.startsWith("read") || method.startsWith("set")
                    || method.startsWith("write") || method.startsWith("append") || method.equals("leftShift")
                    || method.startsWith("eachLine") || method.startsWith("eachByte")
                    || method.startsWith("newReader") || method.startsWith("newWriter")
                    || method.startsWith("newInputStream") || method.startsWith("newOutputStream")
                    || method.startsWith("withReader") || method.startsWith("withWriter")
                    || method.startsWith("withInputStream") || method.startsWith("withOutputStream")
                    || method.startsWith("filterLine") || method.startsWith("splitEachLine"))
                return "Fs";
            return null;
        }
        if (owner.equals("org.codehaus.groovy.runtime.ProcessGroovyMethods") && method.startsWith("execute"))
            return "Exec";
        // Scala stdlib I/O — the language's own stdlib. scala.io.Source file/URL reads; scala.sys.process
        // subprocess spawn (`cmd.!` / `.run` compile to $bang / run on the process owners).
        if (owner.equals("scala.io.Source$") || owner.equals("scala.io.Source")) {
            if (method.equals("fromFile") || method.equals("fromPath") || method.equals("fromResource")) return "Fs";
            if (method.equals("fromURL") || method.equals("fromURI")) return "Net";
            return null;
        }
        if (owner.startsWith("scala.sys.process")
                && (method.equals("run") || method.startsWith("$bang") || method.startsWith("lazyLines")
                    || method.startsWith("lineStream")))
            return "Exec";
        // Network — raw sockets, NIO socket channels (the channel type IS the network boundary; the
        // generic ReadableByteChannel/WritableByteChannel interfaces are NOT classified, they may wrap a
        // file or an in-memory buffer), java.net.http, and Spring's outbound HTTP clients. Without the NIO
        // channels, every NIO-based stack (Netty, async/reactive frameworks, modern high-perf I/O) was a
        // silent under-report — found by the gradle-cache soundness sweep (httpcore5 uses SocketChannel).
        // Selector.select* is the readiness-wait of every NIO reactor (Netty/Vert.x event loop) — a blocking
        // network-I/O wait; verb-gated (open/keys/selectedKeys/wakeup/close stay pure). MulticastChannel.join
        // is IGMP group join (network egress, the NIO twin of MulticastSocket.joinGroup).
        if (owner.equals("java.nio.channels.Selector")
                && (method.equals("select") || method.equals("selectNow"))) return "Net";
        if (owner.equals("java.nio.channels.MulticastChannel") && method.equals("join")) return "Net";
        // HTTP / cloud-storage clients — the CONCRETE-class ubiquitous ones (parallel to the already-modeled
        // RestTemplate/WebClient/Jedis; a pinned concrete receiver resolved to pure → silent-pure). Verb-gated
        // so request/URL BUILDERS stay pure (no fabrication).
        if ((owner.equals("okhttp3.Call") || owner.equals("okhttp3.RealCall"))
                && (method.equals("execute") || method.equals("enqueue"))) return "Net";
        if ((owner.equals("org.apache.http.client.HttpClient")
                || owner.equals("org.apache.http.impl.client.CloseableHttpClient")
                || owner.equals("org.apache.hc.client5.http.classic.HttpClient")
                || owner.equals("org.apache.hc.client5.http.impl.classic.CloseableHttpClient"))
                && method.equals("execute")) return "Net";
        if (owner.equals("retrofit2.Call") && (method.equals("execute") || method.equals("enqueue"))) return "Net";
        if (owner.equals("com.google.api.client.http.HttpRequest") && method.equals("execute")) return "Net";
        // Apache HttpAsyncClient — the ASYNC sibling of the already-modeled classic HttpClient.execute (hc4
        // nio + hc5 async). execute kicks off the request.
        if ((owner.equals("org.apache.http.nio.client.HttpAsyncClient")
                || owner.equals("org.apache.http.impl.nio.client.CloseableHttpAsyncClient")
                || owner.equals("org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient")
                || owner.equals("org.apache.hc.client5.http.async.HttpAsyncClient"))
                && method.equals("execute")) return "Net";
        // okhttp WebSocket — the wire verbs (Call.execute/enqueue above is the HTTP path; the WS path is
        // distinct and was silent-pure). send/close transmit; the factory opens the connection.
        if (owner.equals("okhttp3.WebSocket") && (method.equals("send") || method.equals("close"))) return "Net";
        // gRPC CLIENT calls — candor roots the gRPC SERVER `*ImplBase` (StreamObserver) but the client path
        // was unmodeled. The blocking/async/future stub verbs funnel through io.grpc.stub.ClientCalls (the
        // generated stub's method calls these, so a typed-stub call propagates). Channel.newCall is NOT here
        // — it only CREATES a ClientCall object (no wire I/O until start/sendMessage), so it stays pure.
        if (owner.equals("io.grpc.stub.ClientCalls")
                && (method.startsWith("blocking") || method.startsWith("async") || method.startsWith("futureUnary")))
            return "Net";
        // Micronaut HTTP client — exchange/retrieve EXECUTE the request (toBlocking() only adapts, stays pure).
        if ((owner.equals("io.micronaut.http.client.HttpClient")
                || owner.equals("io.micronaut.http.client.BlockingHttpClient")
                || owner.startsWith("io.micronaut.http.client.Reactive"))
                && (method.equals("exchange") || method.equals("retrieve"))) return "Net";
        // Vert.x — get/post on WebClient build an HttpRequest (pure); the TERMINAL `send*` transmits. For the
        // core client the terminal is HttpClientRequest.send/end. Gate to the terminals so builders stay pure.
        if (owner.equals("io.vertx.ext.web.client.HttpRequest") && method.startsWith("send")) return "Net";
        if (owner.equals("io.vertx.core.http.HttpClientRequest")
                && (method.equals("send") || method.equals("end"))) return "Net";
        // Reactor-Netty — get/post/put configure the client (immutable builder, pure); the `response*`
        // terminals execute and consume the wire.
        if (owner.equals("reactor.netty.http.client.HttpClient")
                && (method.equals("response") || method.equals("responseContent") || method.equals("responseSingle")
                    || method.equals("responseConnection"))) return "Net";
        if ((owner.startsWith("software.amazon.awssdk.services.") || owner.startsWith("com.amazonaws.services."))
                && owner.endsWith("Client")   // the CLIENT classes only — not the model/request getters (v1 uses get*)
                && (method.startsWith("get") || method.startsWith("put") || method.startsWith("list")
                    || method.startsWith("create") || method.startsWith("delete") || method.startsWith("send")
                    || method.startsWith("query") || method.startsWith("scan") || method.startsWith("update")
                    || method.startsWith("describe") || method.startsWith("invoke") || method.startsWith("upload")
                    || method.startsWith("download") || method.startsWith("receive") || method.startsWith("publish"))
                && !isConventionallyPure(method)
                // AWS v1 CLIENT classes themselves carry pure config getters that match `get*` but make
                // no request: getRegion/getRegionName/getSignerRegion/getResourceUrl/getUrl/
                // getCachedResponseMetadata, etc. The 0.5.21 `owner.endsWith("Client")` gate stopped the
                // v1 *model* getters fabricating, but the client's OWN config getters still matched get* →
                // FABRICATED Net on a provably-pure accessor (cardinal sin, regression). Carve them out by
                // exact name. getBucketRegionViaHeadRequest is NOT here → stays Net (it does a HEAD).
                && !isAwsPureClientGetter(method)) return "Net";
        if (owner.equals("java.net.Socket") || owner.equals("java.net.ServerSocket")
                || owner.equals("java.net.DatagramSocket")
                // MulticastSocket extends DatagramSocket; a receiver TYPED as MulticastSocket emits
                // invokevirtual owner=java/net/MulticastSocket for the inherited send/receive, which the
                // exact-owner match above misses — a silent Net under-report (multicast send/receive IS
                // network I/O). joinGroup/leaveGroup likewise.
                || owner.equals("java.net.MulticastSocket")
                || owner.equals("java.nio.channels.SocketChannel")
                || owner.equals("java.nio.channels.ServerSocketChannel")
                || owner.equals("java.nio.channels.DatagramChannel")
                || owner.equals("java.nio.channels.AsynchronousSocketChannel")
                || owner.equals("java.nio.channels.AsynchronousServerSocketChannel")
                // java.net.http: ONLY HttpClient.send/sendAsync touch the wire. The old blanket
                // `java.net.http.` prefix FABRICATED Net on the entire pure builder/factory surface —
                // `HttpRequest.newBuilder()…build()`, `HttpClient.newBuilder()`, BodyHandlers/BodyPublishers —
                // none of which transmit (the cardinal sin: Net on a provably-pure request builder; found by
                // a Net-deep sweep). Mirror the ktor verb-precision below: the send verbs are the one
                // dispatch boundary that performs I/O; everything else in the package is request
                // construction and stays pure.
                || (owner.equals("java.net.http.HttpClient")
                    && (method.equals("send") || method.equals("sendAsync")))
                // java.net.http.WebSocket: the wire verbs (sendText/sendBinary/sendPing/sendPong/sendClose/
                // request) transmit, and Builder.buildAsync OPENS the connection. The 0.5.15 narrowing of
                // the blanket `java.net.http.` prefix to HttpClient.send fixed a builder FABRICATION but
                // REGRESSED the whole WebSocket API to silent-pure — restore it verb-precisely. The pure
                // `HttpClient.newWebSocketBuilder()` factory stays pure (no `build` verb here).
                || (owner.equals("java.net.http.WebSocket") && method.startsWith("send"))
                || (owner.equals("java.net.http.WebSocket") && method.equals("request"))
                || (owner.equals("java.net.http.WebSocket$Builder") && method.equals("buildAsync"))
                // TLS sockets: SSLSocket extends java.net.Socket, so a receiver typed SSLSocket emits
                // owner=javax/net/ssl/SSLSocket for the inherited getInputStream/getOutputStream and for
                // startHandshake — missed by the exact java.net.Socket match (same shape as MulticastSocket,
                // silent TLS I/O). The factories open the connection.
                || owner.equals("javax.net.ssl.SSLSocket")
                || (owner.equals("javax.net.ssl.SSLSocketFactory") && method.equals("createSocket"))
                || (owner.equals("javax.net.SocketFactory") && method.equals("createSocket"))
                || owner.equals("org.springframework.web.client.RestTemplate")
                || owner.equals("org.springframework.web.client.RestClient")
                || owner.startsWith("org.springframework.web.reactive.function.client.")
                // ktor client (Kotlin's dominant HTTP client): the request verbs (get/post/request —
                // INLINE suspend extensions) all funnel through `HttpStatement.execute`, the one
                // dispatch boundary the compiler actually emits (ktor's reqwest-send analog); `body`
                // on the statement also executes. The response readers (`bodyAsText`/`bodyAsChannel`
                // on HttpResponseKt, `body` on HttpClientCallKt) consume the wire. Builders
                // (HttpRequestBuilder/url/setMethod) and HttpClient() construction stay pure. (Found
                // by a ktor-consumer probe: fetch/post/request all silent-pure.)
                || (owner.equals("io.ktor.client.statement.HttpStatement")
                    && (method.startsWith("execute") || method.startsWith("body")))
                || (owner.equals("io.ktor.client.statement.HttpResponseKt")
                    && (method.startsWith("body") || method.startsWith("read")))
                || (owner.equals("io.ktor.client.call.HttpClientCallKt") && method.startsWith("body"))
                // DNS resolution — getByName/getAllByName/getLocalHost/getCanonicalHostName send a query
                // to the resolver (UDP/TCP) = network egress. getByAddress(byte[]) builds from bytes with
                // NO lookup, so it's excluded. (Found by a controlled JDK-effect probe: all three lookup
                // forms read Net 0 — a silent under-report on an extremely common API.)
                || (owner.equals("java.net.InetAddress")
                    && (method.equals("getByName") || method.equals("getAllByName")
                        || method.equals("getLocalHost") || method.equals("getCanonicalHostName")))
                || (owner.equals("java.net.URL")
                    && (method.equals("openStream") || method.equals("openConnection") || method.equals("getContent")))
                // URLConnection / HttpURLConnection wire verbs: `URL.openConnection()` returns a LAZY
                // connection that performs NO I/O until a wire verb runs — and that verb is very commonly in
                // a DIFFERENT method than the openConnection() call (open in a helper, read the body in
                // another), so classifying only openConnection left the actual transmission silent-pure
                // (found by a Net-deep sweep). connect()/getInputStream()/getOutputStream()/getContent()/
                // getResponseCode()/getResponseMessage() each trigger the request; the pure getters
                // (getURL/getRequestMethod/setRequestProperty) stay unclassified — no fabrication.
                || ((owner.equals("java.net.URLConnection") || owner.equals("java.net.HttpURLConnection")
                        || owner.equals("javax.net.ssl.HttpsURLConnection"))
                    && (method.equals("connect") || method.equals("getInputStream")
                        || method.equals("getOutputStream") || method.equals("getContent")
                        || method.equals("getResponseCode") || method.equals("getResponseMessage")))
                // JNDI — a naming/directory lookup contacts a remote naming service (LDAP/RMI/DNS/CORBA);
                // `InitialContext.lookup("ldap://…")` is exactly the hidden network egress an effect checker
                // exists to surface (the Log4Shell vector). The lookup/bind/search family is the boundary;
                // Name/NameParser data types stay pure. (Found by a controlled JDK probe — was Net 0.)
                || (owner.startsWith("javax.naming.")
                    && (method.equals("lookup") || method.equals("lookupLink") || method.equals("doLookup")
                        || method.equals("bind") || method.equals("rebind") || method.equals("rename")
                        || method.equals("list") || method.equals("listBindings") || method.equals("search")
                        || method.equals("createSubcontext") || method.equals("destroySubcontext")
                        || method.equals("getAttributes") || method.equals("modifyAttributes")))
                // RMI — the registry/Naming facade resolves and invokes remote objects over the network.
                || owner.equals("java.rmi.Naming")
                || owner.equals("java.rmi.registry.Registry")
                || owner.equals("java.rmi.registry.LocateRegistry")
                // The JDK's built-in HTTP server binds a listening socket (create/bind) and serves it.
                || (owner.equals("com.sun.net.httpserver.HttpServer")
                    && (method.equals("create") || method.equals("bind") || method.equals("start")))
                // JMX remote — JMXConnectorFactory.connect opens a remote management channel (RMI/JMXMP);
                // JMXConnector.getMBeanServerConnection materializes it. Same remote-channel shape as RMI/JNDI.
                || (owner.equals("javax.management.remote.JMXConnectorFactory") && method.equals("connect"))
                || (owner.equals("javax.management.remote.JMXConnector")
                    && (method.equals("connect") || method.equals("getMBeanServerConnection"))))
            return "Net";
        // Messaging (Net-family) — Spring templates + the RAW broker/mail clients (as ubiquitous as the
        // templates that were already modeled; each was silent-pure, not even Unknown, because a pinned
        // concrete receiver resolved to an unmodeled owner). Message BUILDERS (MimeMessage.setText,
        // ProducerRecord ctor, TextMessage.setText) stay pure — only the send/connect/fetch verbs are Net.
        if (owner.equals("org.springframework.jms.core.JmsTemplate")
                || owner.equals("org.springframework.kafka.core.KafkaTemplate")
                || owner.equals("org.springframework.amqp.rabbit.core.RabbitTemplate")
                // JavaMail / Jakarta Mail — SMTP send + IMAP/POP connect & fetch
                || ((owner.equals("javax.mail.Transport") || owner.equals("jakarta.mail.Transport"))
                    && (method.equals("send") || method.equals("sendMessage") || method.equals("connect")))
                || ((owner.equals("javax.mail.Store") || owner.equals("jakarta.mail.Store")
                        || owner.equals("javax.mail.Folder") || owner.equals("jakarta.mail.Folder"))
                    && (method.equals("connect") || method.equals("open") || method.startsWith("getMessage")
                        || method.equals("fetch")))
                // raw Kafka producer/consumer
                || (owner.equals("org.apache.kafka.clients.producer.KafkaProducer")
                    && (method.equals("send") || method.equals("flush")))
                || (owner.equals("org.apache.kafka.clients.consumer.KafkaConsumer")
                    && (method.equals("poll") || method.startsWith("commit")))
                // raw JMS producer/consumer
                || ((owner.equals("javax.jms.MessageProducer") || owner.equals("jakarta.jms.MessageProducer"))
                    && method.equals("send"))
                || ((owner.equals("javax.jms.MessageConsumer") || owner.equals("jakarta.jms.MessageConsumer"))
                    && (method.equals("receive") || method.startsWith("receive")))
                // RabbitMQ AMQP wire
                || (owner.equals("com.rabbitmq.client.Channel")
                    && (method.equals("basicPublish") || method.equals("basicGet") || method.equals("basicConsume")))
                || (owner.equals("com.rabbitmq.client.ConnectionFactory") && method.equals("newConnection"))
                // MQTT / NATS / Pulsar / ZeroMQ
                || (owner.equals("org.eclipse.paho.client.mqttv3.MqttClient")
                    && (method.equals("publish") || method.equals("connect") || method.equals("subscribe")))
                || (owner.equals("io.nats.client.Connection") && method.equals("publish"))
                || (owner.equals("org.apache.pulsar.client.api.Producer") && method.equals("send"))
                // Spring WebSocket send (java.net.http.WebSocket.send* is already Net — parity)
                || (owner.equals("org.springframework.web.socket.WebSocketSession") && method.equals("sendMessage")))
            return "Net";
        // Distributed caches / KV stores — RAW concrete clients (interface-typed Lettuce/Hazelcast/Ignite/
        // Ehcache/JCache correctly fall to the Unknown dispatch-floor; in-process Caffeine/Guava stay pure —
        // so this is ONLY the concrete remote clients that silently resolved to pure). Net (remote round-trip).
        if ((owner.equals("redis.clients.jedis.Jedis") || owner.equals("redis.clients.jedis.JedisCluster")
                || owner.equals("net.spy.memcached.MemcachedClient")
                || owner.equals("org.apache.zookeeper.ZooKeeper"))
                // EXEMPT the conventionally-pure surface from the whole-owner Net rule (else a fabrication on
                // toString/hashCode/equals and the cached field-reads getDB/getSessionId/getState/
                // getSessionTimeout — found by a fabrication sweep). The remaining methods are commands.
                && !isConventionallyPure(method)
                && !(method.equals("getDB") || method.equals("getSessionId") || method.equals("getState")
                     || method.equals("getSessionTimeout")))
            return "Net";
        // PKI revocation — CertPathValidator (OCSP/CRL fetch) + a network CertStore (LDAP/HTTP) make a remote
        // lookup hidden inside the JDK, the same shape as JNDI.lookup (already Net).
        if (owner.equals("java.security.cert.CertPathValidator") && method.equals("validate")) return "Net";
        if (owner.equals("java.security.cert.CertStore")
                && (method.equals("getCertificates") || method.equals("getCRLs"))) return "Net";
        // ── Android SDK (candor scans the pre-dex JVM bytecode) — the android.* effect surface was entirely
        // unmodeled (silent-pure, often not even Unknown for concrete owners). The high-frequency mappings:
        if (owner.equals("android.database.sqlite.SQLiteDatabase")    // local SQLite DB ops
                && (method.equals("query") || method.equals("rawQuery") || method.equals("insert")
                    || method.equals("update") || method.equals("delete") || method.startsWith("execSQL")
                    || method.startsWith("insertOrThrow") || method.equals("replace")))
            return "Db";
        if (owner.equals("android.database.sqlite.SQLiteOpenHelper")
                && (method.equals("getWritableDatabase") || method.equals("getReadableDatabase"))) return "Db";
        // ContentResolver is a Binder RPC to another app's ContentProvider → Ipc (cross-app data access).
        if (owner.equals("android.content.ContentResolver")
                && (method.equals("query") || method.equals("insert") || method.equals("update")
                    || method.equals("delete") || method.startsWith("openInputStream")
                    || method.startsWith("openOutputStream") || method.startsWith("openFileDescriptor")
                    || method.equals("call") || method.startsWith("bulkInsert")))
            return "Ipc";
        if (owner.equals("android.webkit.WebView")
                && (method.equals("loadUrl") || method.equals("postUrl") || method.startsWith("loadData"))) return "Net";
        // Settings.{System,Secure,Global}.getString/putString — ambient system settings / device-id reads.
        // EXACT owner + EXACT method (was startsWith, which fabricated Env on the NameValueCache inner
        // class's getStringHelper/getIntForCache — found by a fabrication sweep).
        if ((owner.equals("android.provider.Settings$System") || owner.equals("android.provider.Settings$Secure")
                || owner.equals("android.provider.Settings$Global"))
                && (method.equals("getString") || method.equals("putString") || method.equals("getInt")
                    || method.equals("putInt") || method.equals("getLong") || method.equals("putLong")
                    || method.equals("getFloat") || method.equals("putFloat"))) return "Env";
        if ((owner.equals("android.content.ClipboardManager") || owner.equals("android.text.ClipboardManager"))
                && !isConventionallyPure(method))
            return "Clipboard";
        // SharedPreferences.Editor.commit/apply writes the prefs XML file; Context.openFile* opens app-private files.
        if (owner.equals("android.content.SharedPreferences$Editor")
                && (method.equals("commit") || method.equals("apply"))) return "Fs";
        if (owner.equals("android.content.Context")
                && (method.equals("openFileInput") || method.equals("openFileOutput")
                    || method.equals("getFilesDir") || method.equals("getCacheDir")
                    || method.equals("deleteFile"))) return "Fs";
        // Context component-launch is Binder IPC to other app components.
        if (owner.equals("android.content.Context")
                && (method.equals("startActivity") || method.equals("startService")
                    || method.equals("startForegroundService") || method.equals("sendBroadcast")
                    || method.equals("bindService"))) return "Ipc";
        // Database — JDBC, Spring JdbcTemplate, JPA EntityManager (Spring Data repos handled in analyze)
        if ((owner.equals("java.sql.Statement") || owner.equals("java.sql.PreparedStatement")
                || owner.equals("java.sql.CallableStatement") || owner.equals("java.sql.Connection")
                || owner.equals("java.sql.DriverManager")
                // javax.sql.DataSource.getConnection — the POOLED-connection acquisition every HikariCP/
                // Tomcat-JDBC/Spring DataSource app uses (interface dispatch lands on this owner); missed
                // by the java.sql-only list, so the standard connection entry point read silent-pure.
                || owner.equals("javax.sql.DataSource") || owner.equals("javax.sql.CommonDataSource")
                // Concrete connection-pool DataSources: a receiver typed as the concrete pool emits its OWN
                // owner for getConnection (interface dispatch on javax.sql.DataSource is only seen when the
                // receiver is typed as the interface). The dominant pools — without these a `HikariDataSource
                // ds; ds.getConnection()` read silent-pure.
                || owner.equals("com.zaxxer.hikari.HikariDataSource")
                || owner.equals("org.apache.tomcat.jdbc.pool.DataSource")
                || owner.equals("org.apache.commons.dbcp2.BasicDataSource")
                || owner.equals("org.apache.commons.dbcp.BasicDataSource")
                || owner.equals("com.mchange.v2.c3p0.ComboPooledDataSource")
                || owner.equals("com.alibaba.druid.pool.DruidDataSource")
                || owner.equals("oracle.jdbc.pool.OracleDataSource")
                || owner.equals("oracle.ucp.jdbc.PoolDataSource")
                || owner.equals("org.postgresql.ds.PGSimpleDataSource")
                || owner.equals("org.h2.jdbcx.JdbcDataSource")
                || owner.equals("org.springframework.jdbc.datasource.DriverManagerDataSource"))
                && (method.startsWith("execute") || method.equals("getConnection")
                    || method.equals("prepareStatement") || method.equals("prepareCall")
                    // Connection.isValid pings the server (a real round-trip the execute*-only gate missed).
                    || method.equals("isValid")
                    // commit/rollback finalize the transaction at the server (a real round-trip);
                    // setAutoCommit(false) begins one — all DB I/O the execute*-only gate missed.
                    || method.equals("commit") || method.equals("rollback") || method.equals("setAutoCommit")))
            return "Db";
        // java.sql.Driver.connect opens the physical connection (the layer under DriverManager) — silent-pure
        // for code that bypasses DriverManager and calls a Driver directly (pool internals, custom routing).
        if (owner.equals("java.sql.Driver") && method.equals("connect")) return "Db";
        // ResultSet is a LIVE DB CURSOR: cursor-movement verbs fetch rows from the server (a round-trip in
        // streaming/forward-only mode), updatable-set writes flush to the DB, and refreshRow re-reads. The
        // scalar getXxx reads of the CURRENT row are in-memory, so they stay pure (no fabrication — Db on a
        // cursor-advance is sound). Covers java.sql.ResultSet + RowSet (javax.sql).
        if ((owner.equals("java.sql.ResultSet") || owner.startsWith("javax.sql.") && owner.endsWith("RowSet"))
                && (method.equals("next") || method.equals("previous") || method.equals("first")
                    || method.equals("last") || method.equals("absolute") || method.equals("relative")
                    || method.equals("refreshRow") || method.equals("insertRow") || method.equals("updateRow")
                    || method.equals("deleteRow")))
            return "Db";
        // DatabaseMetaData catalog queries round-trip to the server (getTables/getColumns/getPrimaryKeys/…
        // run a system-catalog SELECT). The whole-owner would FABRICATE on its many pure capability getters
        // (supportsX/getMaxX/getDatabaseProductName), so gate to the catalog-FETCH verbs only.
        if (owner.equals("java.sql.DatabaseMetaData")
                && (method.equals("getTables") || method.equals("getColumns") || method.equals("getPrimaryKeys")
                    || method.equals("getImportedKeys") || method.equals("getExportedKeys")
                    || method.equals("getIndexInfo") || method.equals("getSchemas") || method.equals("getCatalogs")
                    || method.equals("getProcedures") || method.equals("getFunctions")
                    || method.equals("getColumnPrivileges") || method.equals("getTablePrivileges")
                    || method.equals("getBestRowIdentifier") || method.equals("getVersionColumns")
                    || method.equals("getCrossReference") || method.equals("getTypeInfo")
                    || method.equals("getUDTs") || method.equals("getSuperTypes") || method.equals("getSuperTables")
                    || method.equals("getAttributes") || method.equals("getProcedureColumns")
                    || method.equals("getFunctionColumns") || method.equals("getPseudoColumns")
                    || method.equals("getClientInfoProperties") || method.equals("getTableTypes")))
            return "Db";
        if (owner.equals("org.springframework.jdbc.core.JdbcTemplate")
                || owner.equals("org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate")
                // Reactive SQL (R2DBC) + the NoSQL store templates — the reactive/store analog of
                // JdbcTemplate, all whole-owner Db. A method returning Mono/Flux off these still does the DB
                // round-trip; missing them left reactive data layers silent-pure.
                || owner.equals("org.springframework.r2dbc.core.DatabaseClient")
                || owner.equals("org.springframework.data.r2dbc.core.R2dbcEntityTemplate")
                || owner.equals("org.springframework.data.mongodb.core.MongoTemplate")
                || owner.equals("org.springframework.data.mongodb.core.ReactiveMongoTemplate")
                || owner.equals("org.springframework.data.cassandra.core.CassandraTemplate")
                || owner.equals("org.springframework.data.redis.core.RedisTemplate"))
            return "Db";
        // JPA EntityManager — the whole-owner rule FABRICATED Db on its pure surface: `createQuery`/
        // `createNamedQuery`/`createNativeQuery` BUILD a Query (no execution), and `clear`/`detach`/
        // `getCriteriaBuilder`/`contains` are in-memory persistence-context ops touching no DB (cardinal
        // sin; found by a Db-deep sweep). Gate to the methods that actually round-trip: find/getReference
        // (SELECT), persist/merge/remove/refresh (the unit-of-work DB ops), flush (forces the SQL), lock.
        if ((owner.equals("jakarta.persistence.EntityManager") || owner.equals("javax.persistence.EntityManager"))
                && (method.equals("find") || method.equals("getReference") || method.equals("persist")
                    || method.equals("merge") || method.equals("remove") || method.equals("refresh")
                    || method.equals("flush") || method.equals("lock")))
            return "Db";
        // JPA query EXECUTION verbs — `em.createQuery(hql)` is a pure BUILDER (above), but the round-trip is
        // on the returned Query/TypedQuery/StoredProcedureQuery. Without classifying these, the whole JPA
        // query path (createQuery + getResultList in one method) read pure (Unknown if unpinned, fully
        // silent-pure if the Query receiver was monomorphically pinned). getResultStream also executes.
        if ((owner.equals("jakarta.persistence.Query") || owner.equals("javax.persistence.Query")
                || owner.equals("jakarta.persistence.TypedQuery") || owner.equals("javax.persistence.TypedQuery")
                || owner.equals("jakarta.persistence.StoredProcedureQuery")
                || owner.equals("javax.persistence.StoredProcedureQuery"))
                && (method.equals("getResultList") || method.equals("getSingleResult")
                    || method.equals("getResultStream") || method.equals("executeUpdate")
                    || method.equals("execute")))
            return "Db";
        // Hibernate Session — get/load fetch by id, the query factories execute via list/uniqueResult on the
        // returned org.hibernate.query.Query, persist/save/update/delete/saveOrUpdate are the unit-of-work DB
        // ops. createQuery/createNativeQuery stay pure builders (their execution is list/uniqueResult, below).
        if (owner.equals("org.hibernate.Session")
                && (method.equals("get") || method.equals("load") || method.equals("save")
                    || method.equals("update") || method.equals("delete") || method.equals("persist")
                    || method.equals("saveOrUpdate") || method.equals("merge") || method.equals("refresh")
                    || method.equals("flush") || method.equals("byId")))
            return "Db";
        if ((owner.equals("org.hibernate.query.Query") || owner.equals("org.hibernate.Query"))
                && (method.equals("list") || method.equals("uniqueResult") || method.equals("getResultList")
                    || method.equals("getSingleResult") || method.equals("executeUpdate")
                    || method.equals("scroll") || method.equals("stream")))
            return "Db";
        // ── Raw data-store DRIVERS (the layer UNDER the Spring templates already modeled above). A non-Spring
        // app — or Spring code typed to the driver — calls these directly; they were silent-pure though their
        // Spring-template analog (MongoTemplate/CassandraTemplate/RedisTemplate/R2dbc) IS modeled, an
        // inconsistency a completeness sweep keeps re-finding. Verb-gated so the BUILDERS/getters of each
        // driver stay pure (no fabrication on a query builder / cached-metadata getter).
        // MongoDB driver (sync + reactivestreams). MongoCollection carries the CRUD round-trips; the
        // database/client handles only the getCollection/getDatabase navigation (also a round-trip on first
        // use, but the I/O that matters is the collection op). Gate to the operation verbs.
        if ((owner.equals("com.mongodb.client.MongoCollection")
                || owner.equals("com.mongodb.reactivestreams.client.MongoCollection"))
                && (method.startsWith("find") || method.startsWith("insert") || method.startsWith("update")
                    || method.startsWith("replace") || method.startsWith("delete") || method.equals("aggregate")
                    || method.equals("countDocuments") || method.equals("estimatedDocumentCount")
                    || method.equals("distinct") || method.startsWith("bulkWrite") || method.startsWith("watch")
                    || method.startsWith("createIndex") || method.startsWith("drop")
                    || method.startsWith("findOneAndUpdate") || method.startsWith("findOneAndReplace")
                    || method.startsWith("findOneAndDelete") || method.startsWith("mapReduce")))
            return "Db";
        // Datastax Cassandra driver (the dominant CqlSession).
        if (owner.equals("com.datastax.oss.driver.api.core.CqlSession")
                && (method.startsWith("execute") || method.startsWith("prepare"))) return "Db";
        // R2DBC reactive-SQL SPI — the reactive analog of JDBC. Connection.createStatement BUILDS (pure);
        // Statement.execute / Batch.execute / ConnectionFactory.create round-trip.
        if ((owner.equals("io.r2dbc.spi.Statement") || owner.equals("io.r2dbc.spi.Batch"))
                && method.equals("execute")) return "Db";
        if (owner.equals("io.r2dbc.spi.ConnectionFactory") && method.equals("create")) return "Db";
        // jOOQ — ONLY the TERMINAL operators run the SQL. fetch*/execute on DSLContext (`dsl.fetch(sql)`)
        // and on Query/ResultQuery execute; the builder chain (selectFrom/insertInto/query/resultQuery —
        // all return query BUILDERS) stays pure (classifying them would FABRICATE Db on a pure builder).
        if (owner.equals("org.jooq.DSLContext")
                && (method.startsWith("fetch") || method.equals("execute")
                    // batch(Query…/String…/Collection) are pure BUILDERS that return an org.jooq.Batch (no
                    // I/O until Batch.execute) — the SQL analog of selectFrom. Only the batchStore/batchInsert/
                    // batchUpdate/batchDelete/batchMerge variants execute. The bare `startsWith("batch")`
                    // FABRICATED Db on the builder (round-12 cardinal sin); gate to the executing variants.
                    || method.equals("batchStore") || method.equals("batchInsert") || method.equals("batchUpdate")
                    || method.equals("batchDelete") || method.equals("batchMerge")
                    || method.startsWith("transactionResult"))) return "Db";
        if ((owner.equals("org.jooq.Query") || owner.equals("org.jooq.ResultQuery"))
                && (method.equals("execute") || method.startsWith("fetch"))) return "Db";
        // MyBatis SqlSession.
        if (owner.equals("org.apache.ibatis.session.SqlSession")
                && (method.startsWith("select") || method.startsWith("insert") || method.startsWith("update")
                    || method.startsWith("delete") || method.equals("commit") || method.equals("rollback")
                    || method.equals("flushStatements"))) return "Db";
        // Neo4j official driver — Session.run / Transaction.run execute the Cypher; session() is a factory.
        if ((owner.equals("org.neo4j.driver.Session") || owner.equals("org.neo4j.driver.Transaction")
                || owner.equals("org.neo4j.driver.reactive.RxSession")
                || owner.equals("org.neo4j.driver.async.AsyncSession"))
                && (method.equals("run") || method.startsWith("execute") || method.startsWith("read")
                    || method.startsWith("write"))) return "Db";
        // jdbi3 — Handle/Jdbi terminal verbs run the SQL (createQuery/createUpdate return builders, stay pure).
        if ((owner.equals("org.jdbi.v3.core.Handle") || owner.equals("org.jdbi.v3.core.Jdbi"))
                && (method.equals("execute") || method.startsWith("select") || method.equals("inTransaction")
                    || method.equals("useTransaction") || method.equals("withHandle") || method.equals("useHandle")))
            return "Db";
        // Spring Data JDBC aggregate template — the template sibling of the modeled JdbcTemplate/MongoTemplate
        // (the CrudRepository INTERFACE path is covered by repoTypes; this is the imperative template).
        if (owner.equals("org.springframework.data.jdbc.core.JdbcAggregateTemplate")
                && (method.equals("save") || method.startsWith("insert") || method.equals("update")
                    || method.startsWith("delete") || method.startsWith("findBy") || method.startsWith("findAll")
                    || method.equals("findById") || method.equals("count") || method.equals("existsById")))
            return "Db";
        // Subprocess
        // ProcessBuilder.start() spawns one process; the static startPipeline(List) spawns a whole pipeline
        // of them (Java 9+) — same Exec, a distinct method name the `start`-only match missed (found by an
        // Exec-deep sweep).
        if (owner.equals("java.lang.ProcessBuilder")
                && (method.equals("start") || method.equals("startPipeline"))) return "Exec";
        if (owner.equals("java.lang.Runtime") && method.equals("exec")) return "Exec";
        // Subprocess convenience libs (the analog of the modeled ProcessBuilder.start/Runtime.exec):
        // Apache commons-exec DefaultExecutor.execute, zt-exec ProcessExecutor.execute. The setX config
        // setters stay pure (verb-gated).
        if (owner.equals("org.apache.commons.exec.DefaultExecutor") && method.equals("execute")) return "Exec";
        if (owner.equals("org.zeroturnaround.exec.ProcessExecutor")
                && (method.equals("execute") || method.equals("executeNoTimeout") || method.equals("start")))
            return "Exec";
        // Driving an already-spawned subprocess is Exec too — getInputStream/getErrorStream read its
        // output, getOutputStream feeds its stdin (an unmonitored data channel), waitFor blocks on it.
        // Splitting spawn (start(), in one method) from drive (these, in another) lost the effect on the
        // driver. java.lang.Process getters typed as I/O verbs; toHandle/exitValue/isAlive stay pure.
        if (owner.equals("java.lang.Process")
                && (method.equals("getInputStream") || method.equals("getOutputStream")
                    || method.equals("getErrorStream") || method.equals("waitFor")
                    // destroy/destroyForcibly send SIGTERM/SIGKILL — subprocess CONTROL (spec §1 Exec =
                    // "spawning / controlling a subprocess"); were silent-pure.
                    || method.equals("destroy") || method.equals("destroyForcibly"))) return "Exec";
        if (owner.equals("java.lang.ProcessHandle")
                && (method.equals("destroy") || method.equals("destroyForcibly"))) return "Exec";
        // System.load/loadLibrary (and the Runtime twins) load a native image and RUN its JNI init
        // (JNI_OnLoad) — arbitrary native-code execution (candor already treats a `native` body as
        // Unknown; the call that loads+triggers it must not be invisible). The gateway to every native
        // effect → Exec.
        if ((owner.equals("java.lang.System") || owner.equals("java.lang.Runtime"))
                && (method.equals("load") || method.equals("loadLibrary"))) return "Exec";
        // Environment. `Env` is the OS process ENVIRONMENT (spec §1: "environment variables"),
        // i.e. System.getenv — NOT System.getProperty/setProperty, which read/write JVM system
        // PROPERTIES (os.name, line.separator, -D flags): JVM config, not the OS environment, and
        // read pervasively at class-init (lumping them flooded a scala-library scan with a spurious
        // 14k Env — and `getProperty("os.name")` is not an env read in any case). Properties are
        // low-signal config, left unclassified like console writes (§1).
        if (owner.equals("java.lang.System") && method.equals("getenv")) return "Env";
        // ProcessBuilder.environment() returns the live child-process env map — reading it surfaces the
        // same OS environment as getenv (an Env disclosure), writing it sets a subprocess env var.
        if (owner.equals("java.lang.ProcessBuilder") && method.equals("environment")) return "Env";
        // Spring's Environment.getProperty reads a MERGED source that includes the OS environment, so
        // it genuinely may surface an env var — a sound over-approximation, kept as Env.
        if (owner.equals("org.springframework.core.env.Environment") && method.equals("getProperty")) return "Env";
        // commons-lang3 SystemUtils.getEnvironmentVariable — reads an OS env var (the analog of System.getenv).
        if (owner.equals("org.apache.commons.lang3.SystemUtils") && method.equals("getEnvironmentVariable"))
            return "Env";
        // Clock
        if (owner.equals("java.lang.System") && (method.equals("currentTimeMillis") || method.equals("nanoTime")))
            return "Clock";
        if (owner.equals("java.time.Clock")) return "Clock";
        if (method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")
                    || owner.equals("java.time.LocalDate") || owner.equals("java.time.ZonedDateTime")
                    // the rest of the java.time `.now()` surface — OffsetDateTime is very common; the
                    // partials (LocalTime/Year/YearMonth/MonthDay/OffsetTime) likewise read the clock.
                    || owner.equals("java.time.OffsetDateTime") || owner.equals("java.time.OffsetTime")
                    || owner.equals("java.time.LocalTime") || owner.equals("java.time.Year")
                    || owner.equals("java.time.YearMonth") || owner.equals("java.time.MonthDay")))
            return "Clock";
        // Legacy date/time: the NO-ARG `new java.util.Date()` reads System.currentTimeMillis, and
        // `Calendar.getInstance()` / no-arg `new GregorianCalendar()` initialize to "now". ARITY-PRECISE:
        // `new Date(long)` / `new GregorianCalendar(y,m,d)` take a value and are pure (no clock read), so
        // gate the ctors to the no-arg descriptor to avoid fabricating Clock on the valued forms.
        if (method.equals("<init>") && "()V".equals(desc)
                && (owner.equals("java.util.Date") || owner.equals("java.util.GregorianCalendar")))
            return "Clock";
        if (owner.equals("java.util.Calendar") && method.equals("getInstance")) return "Clock";
        // Randomness — the concrete PRNG/CSPRNG classes (mirrors `new Random()` / `Math.random()`).
        // ThreadLocalRandom and SplittableRandom are the java.util(.concurrent) generators a probe found
        // unclassified despite Random being flagged — same effect category, added for consistency.
        if (owner.equals("java.util.Random") || owner.equals("java.security.SecureRandom")
                || owner.equals("java.util.concurrent.ThreadLocalRandom")
                || owner.equals("java.util.SplittableRandom")
                // java.util.random.RandomGenerator is the Java 17+ root interface for all PRNGs; code typed
                // to it (or to RandomGeneratorFactory.create() results) bypasses the concrete-class matches
                // above. The sub-interfaces (Jumpable/Splittable/StreamableGenerator) extend it.
                || owner.equals("java.util.random.RandomGenerator")
                || (owner.equals("java.lang.Math") && method.equals("random")))
            return "Rand";
        // UUID.randomUUID() draws a v4 UUID from a SecureRandom (genuine entropy) — Rand. METHOD-precise:
        // UUID's other members (fromString/nameUUIDFromBytes/getMostSignificantBits/toString/compareTo)
        // are pure value ops, so classifying the whole owner would fabricate Rand onto them.
        if (owner.equals("java.util.UUID") && method.equals("randomUUID")) return "Rand";
        // Logging — PRODUCING a log record. VERB-PRECISE within the slf4j / jul / log4j2 / logback
        // packages: only the genuine emit verbs are Log; every other method (Markers, Levels, Message
        // data types, ThreadContext maps, formatters, config/registry, util) falls through to its real
        // transitively-analysed effect, never a fabricated Log. (See isLogEmitVerb.)
        if (owner.startsWith("org.slf4j.") || owner.startsWith("java.util.logging.")
                || owner.startsWith("org.apache.logging.log4j.") || owner.startsWith("ch.qos.logback.")) {
            // RESOURCE-OPENING handlers/appenders are NOT just Log — they open a file/socket/DB connection
            // (the ctor) and transmit (publish/append) to it. A network log handler is a real exfil channel;
            // a file handler does Fs; a DB appender does Db. The package gate below would `return null`
            // (silent-pure) for these. Verb-gated (ctor + the transmit/lifecycle verbs) so the inherited
            // config getters (getLevel/getFormatter/…) stay pure — no fabrication. (Found by a fresh
            // classify-gate review; the soundness fuzzer's Log form only exercises Logger.info.)
            boolean opensResource = method.equals("<init>") || method.equals("publish") || method.equals("append")
                    || method.equals("doAppend") || method.equals("start") || method.equals("flush")
                    || method.equals("close") || method.equals("openFile") || method.equals("setFile");
            if (opensResource) {
                if (owner.equals("java.util.logging.SocketHandler")
                        || owner.endsWith(".SocketAppender") || owner.endsWith(".SSLSocketAppender")
                        || owner.endsWith(".SyslogAppender") || owner.endsWith(".KafkaAppender")
                        || owner.endsWith(".SmtpAppender") || owner.endsWith(".HttpAppender"))
                    return "Net";
                if (owner.equals("java.util.logging.FileHandler")
                        || owner.endsWith(".FileAppender") || owner.endsWith(".RollingFileAppender")
                        || owner.endsWith(".RollingRandomAccessFileAppender") || owner.endsWith(".RandomAccessFileAppender"))
                    return "Fs";
                if (owner.endsWith(".DBAppender") || owner.endsWith(".JDBCAppender")
                        || owner.endsWith(".JPAAppender") || owner.endsWith(".CassandraAppender"))
                    return "Db";
            }
            if (isLogEmitVerb(method)) return "Log";
            return null;
        }
        // Clipboard — system clipboard access (spec §1). Toolkit hands out the system clipboard/selection
        // handle; the `Clipboard` get/setContents are the read/write. Restores cross-impl vocabulary parity
        // — Clipboard was the one spec effect candor-java never emitted (the Rust impl classifies arboard).
        if ((owner.equals("java.awt.Toolkit")
                && (method.equals("getSystemClipboard") || method.equals("getSystemSelection")))
                || owner.equals("java.awt.datatransfer.Clipboard"))
            return "Clipboard";
        // JavaFX clipboard (the AWT successor) — getSystemClipboard hands out the handle; setContent/
        // getString/getContent/hasString read/write it. Verb-gated so the pure quartet stays pure.
        if (owner.equals("javafx.scene.input.Clipboard")
                && !isConventionallyPure(method)
                && (method.equals("getSystemClipboard") || method.startsWith("get") || method.startsWith("set")
                    || method.startsWith("has") || method.equals("clear")))
            return "Clipboard";
        return null;
    }

    static void writeJson(Map<String, TreeSet<String>> inferred, String out) throws IOException {
        // Per-class conformance (same model as checkConformance, SPEC §5): declared = effects
        // the class's injected dependency types can supply; performed = union over its methods.
        // We attach declared/undeclared/overdeclared to each method entry so an agent can
        // consume conformance from the JSON, not just the AS-EFF diagnostics. The unit of
        // declaration in the DI idiom is the class, projected onto each of its methods.
        Map<String, TreeSet<String>> performed = new HashMap<>();
        Map<String, String> fnToClass = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> p = performed.computeIfAbsent(dc, k -> new TreeSet<>());
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                String fn = methodId(dc, mn.name, mn.desc);
                fnToClass.put(fn, dc);
                var inf = inferred.get(fn);
                if (inf != null) p.addAll(inf);
            }
        }
        Map<String, TreeSet<String>> declaredByClass = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> declared = new TreeSet<>();
            if (cn.fields != null)
                for (FieldNode f : cn.fields) {
                    String t = fieldTypeInternal(f.desc);
                    if (t != null) declared.addAll(typeEffects(t, performed));
                }
            declaredByClass.put(dc, declared);
        }

        Map<String, TreeSet<String>> fsAcc = fsFixpoint();
        Map<String, TreeSet<String>> hostsAcc = literalFixpoint(hostsDirect);
        Map<String, TreeSet<String>> cmdsAcc = literalFixpoint(cmdsDirect);
        Map<String, TreeSet<String>> pathsAcc = literalFixpoint(pathsDirect);
        Map<String, TreeSet<String>> tablesAcc = literalFixpoint(tablesDirect);
        List<Map<String, Object>> entries = new ArrayList<>();
        inferred.entrySet().stream()
                // Keep a method if it has effects, is an entry point, OR its class declares a
                // capability — so a class that injects-but-never-uses one (overdeclared /
                // AS-EFF-002) is still visible in the JSON even when all its methods are pure.
                .filter(e -> {
                    if (!e.getValue().isEmpty() || entryPoints.contains(e.getKey())) return true;
                    String dc = fnToClass.get(e.getKey());
                    return dc != null && !declaredByClass.getOrDefault(dc, new TreeSet<>()).isEmpty();
                })
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> {
                    String fn = e.getKey();
                    TreeSet<String> inf = e.getValue();
                    String dc = fnToClass.get(fn);
                    TreeSet<String> declared = dc == null ? new TreeSet<>()
                            : declaredByClass.getOrDefault(dc, new TreeSet<>());
                    TreeSet<String> perf = dc == null ? new TreeSet<>()
                            : performed.getOrDefault(dc, new TreeSet<>());
                    // undeclared = inferred − declared (the AS-EFF-001 surface; Unknown excluded,
                    // it's handled by AS-EFF-003). overdeclared = class declares but never performs.
                    List<String> undeclared = inf.stream()
                            .filter(x -> !x.equals("Unknown") && !declared.contains(x))
                            .sorted().collect(Collectors.toList());
                    List<String> overdeclared = declared.stream()
                            .filter(x -> !perf.contains(x)).sorted().collect(Collectors.toList());
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("fn", fn);
                    m.put("loc", loc.getOrDefault(fn, "?"));
                    m.put("inferred", new ArrayList<>(inf));
                    m.put("direct", new ArrayList<>(direct.getOrDefault(fn, new TreeSet<>())));
                    m.put("declared", new ArrayList<>(declared));
                    m.put("undeclared", undeclared);
                    m.put("overdeclared", overdeclared);
                    m.put("entryPoint", entryPoints.contains(fn));
                    m.put("unresolved", inf.contains("Unknown")); // trust contract (SPEC §4)
                    // spec ⟨0.5⟩ unitKind: a static initializer is a UNIT, not a method anyone
                    // calls — name it so consumers render it sensibly. Absent = ordinary function.
                    if (fn.endsWith(".<clinit>")) m.put("unitKind", "initializer");
                    // Why Unknown was emitted HERE (not inherited): native:/reflect:/dispatch: tags,
                    // so a reader can see which opacity is improvable (a missing-impl dispatch) vs
                    // irreducible (reflection, native). Omitted when this fn introduces no Unknown.
                    TreeSet<String> uw = unknownWhy.get(fn);
                    if (uw != null && !uw.isEmpty()) m.put("unknownWhy", new ArrayList<>(uw));
                    m.put("hash", hashOf.getOrDefault(fn, "")); // cross-jar join key (SPEC §2)
                    // Effect-relevant local call graph (SPEC §2 `calls`): the EFFECTFUL local callees,
                    // so a consumer can answer "who calls X?" from the report without re-analysis.
                    // Omitted when empty.
                    List<String> calls = edges.getOrDefault(fn, Set.of()).stream()
                            .filter(c -> {
                                TreeSet<String> ce = inferred.get(c);
                                return ce != null && !ce.isEmpty();
                            })
                            .sorted().collect(Collectors.toList());
                    if (!calls.isEmpty()) m.put("calls", calls);
                    // Fs read/write detail (SPEC §2 `fs`): the access kind, when known AND complete.
                    // Empty when unknown, when the fn performs no Fs, or when reached cross-jar
                    // (FS_UNKNOWN) — never a misleading partial. Omitted when empty.
                    TreeSet<String> fk = fsAcc.get(fn);
                    if (inf.contains("Fs") && fk != null && !fk.contains(FS_UNKNOWN)) {
                        List<String> kinds = fk.stream().filter(x -> !x.equals(FS_UNKNOWN)).sorted()
                                .collect(Collectors.toList());
                        if (!kinds.isEmpty()) m.put("fs", kinds);
                    }
                    // Literal Net/Exec/Fs surfaces statically visible from this method (SPEC §2
                    // `hosts`/`cmds`/`paths`): the decidable subset of who it talks to / what it runs /
                    // what it touches, feeding the AS-EFF-008 allowlist. Omitted when none are visible (a
                    // runtime-computed value, or the effect absent) — never a completeness claim.
                    TreeSet<String> hk = hostsAcc.get(fn);
                    if (inf.contains("Net") && hk != null && !hk.isEmpty())
                        m.put("hosts", new ArrayList<>(hk));
                    TreeSet<String> ck = cmdsAcc.get(fn);
                    if (inf.contains("Exec") && ck != null && !ck.isEmpty())
                        m.put("cmds", new ArrayList<>(ck));
                    TreeSet<String> pk = pathsAcc.get(fn);
                    if (inf.contains("Fs") && pk != null && !pk.isEmpty())
                        m.put("paths", new ArrayList<>(pk));
                    TreeSet<String> tk = tablesAcc.get(fn);
                    if (inf.contains("Db") && tk != null && !tk.isEmpty())
                        m.put("tables", new ArrayList<>(tk));
                    entries.add(m);
                });
        // v0.2 self-describing envelope (candor-spec §2): a provenance header + the function entries.
        // Readers still accept the legacy v0.1 bare array (see loadBaseline) during migration.
        String[] prov = provenance();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("version", prov[0]);
        header.put("toolchain", prov[1]);
        header.put("spec", SPEC_VERSION); // candor-spec contract version (§2.1), distinct from the build id
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("candor", header);
        // The packages this report COVERS — exact, from the analyzed class names. Lets a consumer
        // chaining this report register coverage even when `functions` is empty (an all-pure
        // dep's report is its purity claim, SPEC §2 rule 3 — the empty-report coverage fix).
        TreeSet<String> pkgs = new TreeSet<>();
        for (ClassNode cn : ALL) {
            int slash = cn.name.lastIndexOf('/');
            if (slash > 0) pkgs.add(cn.name.substring(0, slash).replace('/', '.'));
        }
        envelope.put("packages", pkgs);
        envelope.put("functions", entries);
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(envelope);
        writeAtomic(Path.of(out), json);
        System.err.println("candor-java: wrote " + entries.size() + " entries (@" + prov[0] + ") to " + out);
        reportUnknownSources();
    }

    /** The FULL call graph (every project method -> its callees, including pure ones), written beside the
     *  report as `<out-minus-.json>.callgraph.json`. The report omits pure functions, so without this a
     *  `callers` query can't answer the PRE-EDIT blast-radius question ("who would be affected if I add an
     *  effect to this pure function?") — the most natural thing an agent asks. Mirrors candor-scan's
     *  callgraph sidecar so both engines answer it identically (candor-spec §2). */
    static void writeCallgraph(String out) throws IOException {
        String cgOut = out.endsWith(".json") ? out.substring(0, out.length() - 5) + ".callgraph.json"
                                             : out + ".callgraph.json";
        Map<String, List<String>> cg = new TreeMap<>();
        // SPEC §2.2: EVERY analyzed method is a key — a LEAF with no project callees gets an empty
        // list (was skipped, which made an uncalled leaf invisible to whatif/callers and conflated
        // "no callers" with "no such function"; mirrors the same fix in candor-scan + the lint).
        for (var e : edges.entrySet()) {
            cg.put(e.getKey(), new ArrayList<>(new TreeSet<>(e.getValue())));
        }
        writeAtomic(Path.of(cgOut), new GsonBuilder().setPrettyPrinting().create().toJson(cg));
    }

    /** Write a report file ATOMICALLY: serialize to a sibling temp file, then move it into place. A
     *  concurrent reader (a cross-engine candor-query merging this report) must never observe a
     *  half-written file — the same write invariant the Rust and TS backends hold. Tries an atomic
     *  move first; falls back to a plain replacing move on a filesystem that can't do ATOMIC_MOVE
     *  (e.g. across a tmp boundary), which still beats an in-place truncate+write. On ANY failure
     *  (disk full mid-write, both moves rejected) the temp is removed so a failed run never leaves an
     *  accumulating `<name>.json<rnd>.tmp` residue beside the report. */
    static void writeAtomic(Path path, String contents) throws IOException {
        Path dir = path.toAbsolutePath().getParent();
        Path tmp = Files.createTempFile(dir, path.getFileName().toString(), ".tmp");
        boolean moved = false;
        try {
            Files.writeString(tmp, contents);
            try {
                Files.move(tmp, path, java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
        } finally {
            if (!moved) Files.deleteIfExists(tmp);
        }
    }

    /** Human-readable breakdown of WHERE direct Unknowns come from, bucketed into the irreducible
     *  (reflection, native) vs the improvable (unresolved dispatch — a project iface/abstract whose
     *  impl wasn't on the analyzed classpath). Printed to stderr so a maintainer can see which
     *  opacity is worth chasing (widen the classpath) vs accept (honest Unknown, SPEC §4). */
    static void reportUnknownSources() {
        if (unknownWhy.isEmpty()) return;
        var byCategory = new java.util.TreeMap<String, Integer>();   // native|reflect|dispatch -> count
        var byTarget = new java.util.TreeMap<String, Integer>();     // specific owner/method -> count
        for (TreeSet<String> reasons : unknownWhy.values())
            for (String r : reasons) {
                String cat = r.substring(0, r.indexOf(':'));
                byCategory.merge(cat, 1, Integer::sum);
                byTarget.merge(r, 1, Integer::sum);
            }
        System.err.println("\ncandor-java: Unknown sources (direct) — " + unknownWhy.size() + " methods");
        byCategory.forEach((c, n) -> System.err.println(String.format("  %-9s %4d", c, n)));
        System.err.println("  top targets (dispatch: = improvable by widening the analyzed classpath):");
        byTarget.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(12)
                .forEach(e -> System.err.println(String.format("    %4d  %s", e.getValue(), e.getKey())));
    }

    /** Engine provenance for the v0.2 envelope (candor-spec §2.1): the build id + toolchain baked into
     *  a resource at build time, so the report reflects the BINARY that ran rather than the source
     *  tree. Falls back to "unknown" / the running JDK when the resource is absent. */
    static String[] provenance() {
        String version = "unknown";
        String toolchain = "jvm-" + System.getProperty("java.version", "?");
        try (var in = Candor.class.getResourceAsStream("/candor/build-info.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                version = p.getProperty("version", version);
                toolchain = p.getProperty("toolchain", toolchain);
            }
        } catch (IOException ignored) {
        }
        return new String[] {version, toolchain};
    }

    /** The clean RELEASE semver (e.g. "0.5.0") — the crate-semver axis that GitHub releases tag and the
     *  `-all.jar` filename carry, distinct from {@link #provenance()}'s git-hash build id. Baked into
     *  build-info.properties as `release` by the Gradle build; falls back to "unknown" if absent. */
    static String release() {
        try (var in = Candor.class.getResourceAsStream("/candor/build-info.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                return p.getProperty("release", "unknown");
            }
        } catch (IOException ignored) {
        }
        return "unknown";
    }
}
