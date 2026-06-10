package candor;

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
    static final String SPEC_VERSION = "0.3";

    static final Map<String, TreeSet<String>> direct = new HashMap<>();
    static final Map<String, Set<String>> edges = new HashMap<>();
    static final Map<String, String> loc = new HashMap<>();
    static final Map<String, String> hashOf = new HashMap<>();           // fn -> stable method-ref hash (owner.name+desc)
    static final Map<String, TreeSet<String>> viaCross = new HashMap<>();// fn -> effects inherited from a dependency report
    static final Map<String, List<String>> crossDeps = new HashMap<>();  // method-ref hash -> effects (from CANDOR_DEPS)
    static final Map<String, TreeSet<String>> fsDirect = new HashMap<>();// fn -> Fs read/write kind performed directly
    static final Map<String, TreeSet<String>> unknownWhy = new HashMap<>();// fn -> why Unknown was emitted directly (native:/reflect:/dispatch:)
    static final String FS_UNKNOWN = "?";   // Fs reached with no recorded kind (cross-jar) -> make no read/write claim
    static final Set<String> entryPoints = new HashSet<>(); // framework-invoked methods
    static final Set<String> projectClasses = new HashSet<>();
    static final Set<String> repoTypes = new HashSet<>();    // Spring Data repository interfaces (internal names)
    static final Set<String> feignTypes = new HashSet<>();   // @FeignClient interfaces (internal names)
    static List<ClassNode> ALL = List.of();                  // all loaded classes (for CHA)
    static final Map<String, ClassNode> byName = new HashMap<>();      // internal name -> node
    static final Map<String, Set<String>> transSupersCache = new HashMap<>();
    static final Set<String> classesWithClinit = new HashSet<>(); // project classes with a `<clinit>`

    // --- Spring markers (internal names / annotation-desc substrings) ---
    static final Set<String> REPO_MARKERS = Set.of(
            "org/springframework/data/repository/Repository",
            "org/springframework/data/repository/CrudRepository",
            "org/springframework/data/repository/ListCrudRepository",
            "org/springframework/data/repository/PagingAndSortingRepository",
            "org/springframework/data/jpa/repository/JpaRepository");
    static final String TX = "springframework/transaction/annotation/Transactional";
    static final String SCHEDULED = "springframework/scheduling/annotation/Scheduled";
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

    /** A `deny <Effect…> [scope]` or `pure <scope>` rule. `effects` empty ⇒ a `pure` rule (ANY effect is
     *  forbidden). `scope` empty ⇒ the whole project. */
    static class DenyRule { TreeSet<String> effects = new TreeSet<>(); String scope = ""; String src; }
    /** An `allow <Effect> [in <scope>] <value…>` rule: a method in scope performing that effect may reach
     *  ONLY the listed values (Net hosts today). `scope` empty ⇒ whole project. */
    static class AllowRule { String effect; String scope = ""; TreeSet<String> values = new TreeSet<>(); String src; }
    /** A `forbid <A> -> <B>` rule: a method in scope A must not transitively reach into scope B. */
    static class ForbidRule { String from, to; }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>]");
            System.err.println(
                    "       candor <show|where|callers|map|diff|containment|reachable|path|impact> <report.json> [arg]");
            System.exit(2);
        }
        // Read-only queries over a written report (no re-analysis) — the sibling of candor-query.
        if (Query.COMMANDS.contains(args[0])) {
            System.exit(Query.run(args));
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
        String jsonOut = null;
        for (int i = 1; i + 1 < args.length; i++) if (args[i].equals("--json")) jsonOut = args[i + 1];

        List<ClassNode> classes = load(Path.of(args[0]));
        ALL = classes;
        for (ClassNode cn : classes) {
            projectClasses.add(cn.name);
            byName.put(cn.name, cn);
            for (MethodNode mn : cn.methods) if (mn.name.equals("<clinit>")) classesWithClinit.add(cn.name);
        }
        computeSpringTypes(classes);
        // Cross-jar inheritance (candor-spec §2): load dependency reports named by CANDOR_DEPS BEFORE
        // analyze, so a call into an already-analyzed dependency inherits its effects (vs assumed-pure).
        loadCrossDeps(System.getenv("CANDOR_DEPS"), provenance()[0]);
        taintEnabled = System.getenv("CANDOR_TAINT") != null; // read before analyze (the pass runs per method)
        for (ClassNode cn : classes) analyze(cn);

        Map<String, TreeSet<String>> inferred = fixpoint();

        // JSON output is orthogonal — write first so `--json` can snapshot a baseline.
        if (jsonOut != null) { writeJson(inferred, jsonOut); writeCallgraph(jsonOut); }

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
                var inf = inferred.get(dc + "." + mn.name);
                if (inf != null) p.addAll(inf);
            }
        }
        int v = 0;
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            if (!inScope(scope, dc)) continue;
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
            if (!inScope(scope, e.getKey())) continue;
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
            System.err.println("candor-java: CANDOR_POLICY=" + path
                    + " could not be read; policy NOT enforced");
            return 0;
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

    /** AS-EFF-008 for one effect: each method performing `effect` in a scope with an `allow <effect> …`
     *  rule must reach ONLY covered literals (per the effect's `covered` matcher). Allowed values are
     *  UNIONed across matching rules. A method with no `allow` rule for its scope is unchecked. */
    static int checkAllowlist(Map<String, TreeSet<String>> inferred, String effect,
            Map<String, TreeSet<String>> reachedAcc,
            java.util.function.BiPredicate<Set<String>, String> covered) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            if (!e.getValue().contains(effect)) continue;
            Set<String> allowed = null; // null ⇒ no `allow <effect>` rule covers this method → not checked
            String scope = "";
            for (AllowRule r : allowRules) {
                if (!effect.equals(r.effect) || !scopeMatches(fn, r.scope)) continue;
                if (allowed == null) { allowed = new HashSet<>(); scope = r.scope; }
                allowed.addAll(r.values);
            }
            if (allowed == null) continue;
            Set<String> fa = allowed;
            List<String> bad = reachedAcc.getOrDefault(fn, new TreeSet<>()).stream()
                    .filter(reached -> !covered.test(fa, reached)).sorted().collect(Collectors.toList());
            if (!bad.isEmpty()) {
                System.out.printf("[AS-EFF-008] `%s` reaches { %s } outside the allowlist, forbidden by "
                        + "policy%s: `allow %s … %s`%n", fn, String.join(", ", bad),
                        scope.isEmpty() ? "" : " (scope `" + scope + "`)", effect,
                        String.join(" ", new TreeSet<>(allowed)));
                v++;
            }
        }
        return v;
    }

    /** Parse a CANDOR_POLICY file into deny/forbid rules. One rule per line; `#` comments + blanks
     *  ignored. Returns false if the file can't be read (so the caller can fail loud). */
    static boolean parsePolicy(String path) {
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of(path));
        } catch (IOException e) {
            return false;
        }
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
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
                    if (r.effects.isEmpty()) break; // names no effect -> drop (do NOT invert into pure)
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
                    }
                    break;
                }
                case "allow": {
                    // SPEC §6.2: `allow <Effect> [in <scope>] <value…>` — the effect MUST be one of the
                    // three that carry a literal surface; an `allow` for any other effect is dropped.
                    if (t.length < 3) break;
                    if (!t[1].equals("Net") && !t[1].equals("Exec") && !t[1].equals("Fs")) break;
                    AllowRule r = new AllowRule();
                    r.src = line;
                    r.effect = t[1];
                    int vi = 2;
                    if (t.length > 3 && t[2].equals("in")) { r.scope = t[3]; vi = 4; }
                    for (int i = vi; i < t.length; i++) r.values.add(t[i]);
                    if (!r.values.isEmpty()) allowRules.add(r);
                    break;
                }
                default:
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
        String[] segs = name.split("\\.");
        String[] parts = scope.split("\\.");
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
    static String hostPart(String h) {
        String x = h;
        int scheme = x.indexOf("://"); if (scheme >= 0) x = x.substring(scheme + 3);
        int slash = x.indexOf('/');    if (slash >= 0)  x = x.substring(0, slash);
        int at = x.lastIndexOf('@');   if (at >= 0)     x = x.substring(at + 1);
        int colon = x.indexOf(':');    if (colon >= 0)  x = x.substring(0, colon);
        return x;
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
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode)
                break; // a prior call / branch bounds this call's argument evaluation
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof String s) found = s; // keep the earliest
        }
        return found;
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
                    JsonArray fns = obj != null ? obj.getAsJsonArray("functions")
                            : (root.isJsonArray() ? root.getAsJsonArray() : null);
                    if (fns == null) continue;
                    String depVer = obj != null && obj.has("candor") && obj.getAsJsonObject("candor").has("version")
                            ? obj.getAsJsonObject("candor").get("version").getAsString() : null;
                    boolean stale = depVer != null && ownVersion != null && !depVer.equals(ownVersion);
                    for (JsonElement el : fns) {
                        JsonObject m = el.getAsJsonObject();
                        if (!m.has("hash") || m.get("hash").isJsonNull()) continue; // v0.1 / no cross-jar id
                        String h = m.get("hash").getAsString();
                        if (h.isBlank()) continue;
                        List<String> effs = new ArrayList<>();
                        if (stale) {
                            effs.add("Unknown");
                        } else if (m.has("inferred")) {
                            for (JsonElement x : m.getAsJsonArray("inferred")) effs.add(x.getAsString());
                        }
                        if (!effs.isEmpty()) crossDeps.put(h, effs);
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

    static boolean inScope(String var, String name) {
        return var.equals("1") || var.isEmpty() || name.startsWith(var);
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
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class"))::iterator) {
                ClassNode cn = new ClassNode();
                new ClassReader(Files.readAllBytes(p)).accept(cn, 0);
                out.add(cn);
            }
        }
    }

    /** Identify Spring Data repositories (effect: Db) and @FeignClient interfaces (Net). */
    static void computeSpringTypes(List<ClassNode> classes) {
        for (ClassNode cn : classes) if (annoPresent(cn.visibleAnnotations, FEIGN)) feignTypes.add(cn.name);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (ClassNode cn : classes) {
                if (repoTypes.contains(cn.name) || cn.interfaces == null) continue;
                for (String itf : cn.interfaces) {
                    if (REPO_MARKERS.contains(itf) || repoTypes.contains(itf)) {
                        repoTypes.add(cn.name);
                        changed = true;
                        break;
                    }
                }
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
                .filter(r -> supers.stream().anyMatch(s -> s.contains(r[0])))
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
            String id = dottedClass + "." + mn.name;
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
            if (annoPresent(mn.visibleAnnotations, SCHEDULED)
                    || annoPresentAny(mn.visibleAnnotations, MAPPING_OR_LISTENER)
                    || annoPresentAny(mn.visibleAnnotations, LIFECYCLE))
                entryPoints.add(id);
            // A `finalize()` override is run by the GC's finalizer thread — NOT by any bytecode call.
            // It's the JVM analog of Rust's implicit-Drop hole: an effect (a socket/file opened on
            // collection) that otherwise sits in finalize's own entry but is unreachable from any root,
            // so a "what does this program perform" walk from entry points silently misses it. Unlike
            // Rust we can't attribute it to a drop SITE (finalization is non-deterministic and runs on a
            // detached thread), so the honest model is the runtime-invoked entry point it actually is.
            if (mn.name.equals("finalize") && mn.desc.equals("()V") && (mn.access & Opcodes.ACC_STATIC) == 0)
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

            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode min) {
                    String owner = min.owner.replace('/', '.');
                    String effect = classify(owner, min.name, min.desc);
                    if (effect != null) dir.add(effect);
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
                        String cmd = firstLiteralArg(mn, min);
                        if (cmd != null) cmdsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(cmd);
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
                    // Calls to a Spring Data repository / Feign client are I/O even though the
                    // callee has no body candor can see (Spring synthesizes the impl at runtime).
                    boolean springTyped = repoTypes.contains(min.owner) || feignTypes.contains(min.owner);
                    if (repoTypes.contains(min.owner)) dir.add("Db");
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
                        List<String> cha = chaTargets(min.owner, min.name, min.desc);
                        boolean broadSmear = dispatchExempt && cha.size() > CHA_FANOUT_LIMIT;
                        List<String> targets = broadSmear ? List.of() : cha;
                        edges.get(id).addAll(targets);
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
                        if (targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                                && isProjectIfaceOrAbstract(min.owner)
                                && projectDeclaresMethod(min.owner, min.name, min.desc)) {
                            dir.add("Unknown");
                            unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                                    .add("dispatch:" + owner + "." + min.name);
                        }
                    } else if (projectClasses.contains(min.owner)) {
                        // static / special (super, private, ctor) — the exact target.
                        edges.get(id).add(owner + "." + min.name);
                    }
                    // Cross-jar inheritance (candor-spec §2): a call into a DEPENDENCY analyzed
                    // separately — inherit its recorded effects via the stable method-ref hash. Only
                    // for external, non-built-in, non-Spring calls (project calls trace locally;
                    // reflection is already Unknown via classify).
                    if (effect == null && !springTyped && !projectClasses.contains(min.owner)) {
                        List<String> inh = crossDeps.get(min.owner + "." + min.name + min.desc);
                        if (inh != null) viaCross.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh);
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
                            if (!am.name.startsWith("<"))
                                edges.get(id).add(tin.desc.replace('/', '.') + "." + am.name);
                    }
                } else if (insn instanceof FieldInsnNode fin
                        && (fin.getOpcode() == Opcodes.GETSTATIC || fin.getOpcode() == Opcodes.PUTSTATIC)) {
                    // A static field access triggers the owner's class-load → its `<clinit>` runs.
                    clinitEdge(id, fin.owner);
                } else if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    // A literal Net endpoint visible in this method (`new Socket("h",p)`, `new
                    // URL("https://api.stripe.com/…")`) — the decidable subset of "who it talks to",
                    // feeding the AS-EFF-008 host allowlist. Non-host strings are rejected by
                    // netHostLiteral, so this never fabricates an endpoint. Method-level (the unit the
                    // allowlist certifies); a runtime-computed host stays honestly invisible.
                    String host = netHostLiteral(s);
                    if (host != null) hostsDirect.computeIfAbsent(id, k -> new TreeSet<>()).add(host);
                } else if (insn instanceof InvokeDynamicInsnNode idin) {
                    // Lambdas & method refs: the functional-interface factory's impl method (a project
                    // `lambda$…` synthetic, or a referenced method) carries the body's effects. Edge to
                    // it so they propagate here — else passing an effectful lambda looks pure.
                    for (Object a : idin.bsmArgs) {
                        if (a instanceof Handle h && projectClasses.contains(h.getOwner()))
                            edges.get(id).add(h.getOwner().replace('/', '.') + "." + h.getName());
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
    }

    // entry-point annotation substrings (HTTP mappings + message listeners)
    static final List<String> MAPPING_OR_LISTENER = List.of(
            "web/bind/annotation/RequestMapping", "web/bind/annotation/GetMapping",
            "web/bind/annotation/PostMapping", "web/bind/annotation/PutMapping",
            "web/bind/annotation/DeleteMapping", "web/bind/annotation/PatchMapping",
            "kafka/annotation/KafkaListener", "amqp/rabbit/annotation/RabbitListener",
            "jms/annotation/JmsListener", "context/event/EventListener");

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
            new String[] {"groovy/lang/Closure", "call", null});

    /** The number of CHA targets above which a CHA-EXEMPT dispatch (Object protocol / function-interface
     *  / task verb) is treated as a broad smear and its fan-out dropped. An app's handful of Runnables /
     *  closures resolve precisely (attributed); a library's hundreds of FunctionN/Closure impls exceed
     *  this and are dropped (their bodies stay reachable via the RUNTIME_OVERRIDES entry points). */
    static final int CHA_FANOUT_LIMIT = 12;

    /** Whether a method's CHA dispatch is exempt from BROAD fan-out (SPEC §4 conventionally-pure +
     *  runtime-dispatched verbs). Declarative + unit-tested so a new dialect is a row, not another `||`
     *  buried in the bytecode loop. Narrow dispatch over these is still attributed precisely; only the
     *  library-scale smear is dropped (see CHA_FANOUT_LIMIT). */
    static boolean isChaExemptMethod(String owner, String name, String desc) {
        // Object protocol — conventionally pure (formatting / equality / hashing / ordering).
        if ((name.equals("toString") && desc.equals("()Ljava/lang/String;"))
                || (name.equals("hashCode") && desc.equals("()I"))
                || (name.equals("equals") && desc.equals("(Ljava/lang/Object;)Z"))
                || (name.equals("compareTo") && desc.equals("(Ljava/lang/Object;)I")))
            return true;
        // Function-interface invocation: Kotlin FunctionN.invoke; Scala FunctionN/PartialFunction.apply
        // + the java8 JFunction SAM bridges; Groovy Closure.call/doCall.
        if (owner.startsWith("kotlin/jvm/functions/") && name.equals("invoke")) return true;
        if ((owner.startsWith("scala/Function") || owner.equals("scala/PartialFunction")
                || owner.startsWith("scala/runtime/java8/JFunction")) && name.equals("apply")) return true;
        if (owner.equals("groovy/lang/Closure") && (name.equals("call") || name.equals("doCall"))) return true;
        // Task-dispatch verbs on the external interface.
        if (owner.equals("java/lang/Runnable") && name.equals("run")) return true;
        if (owner.equals("java/util/concurrent/Callable") && name.equals("call")) return true;
        return false;
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

    static int firstLine(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) if (insn instanceof LineNumberNode ln) return ln.line;
        return 0;
    }

    /** Transitive supertypes (internal names) of a project type; stops at non-project ancestors. */
    static Set<String> transSupers(String internal) {
        Set<String> cached = transSupersCache.get(internal);
        if (cached != null) return cached;
        Set<String> r = new HashSet<>();
        transSupersCache.put(internal, r); // seed first to break cycles
        ClassNode cn = byName.get(internal);
        if (cn != null) {
            List<String> sup = new ArrayList<>();
            if (cn.superName != null) sup.add(cn.superName);
            if (cn.interfaces != null) sup.addAll(cn.interfaces);
            for (String s : sup) { r.add(s); r.addAll(transSupers(s)); }
        }
        return r;
    }

    /** CHA: project subtypes-or-self of `owner` that provide a concrete (name,desc) impl. */
    static List<String> chaTargets(String owner, String name, String desc) {
        Set<String> out = new LinkedHashSet<>();
        for (ClassNode c : ALL) {
            if (!(c.name.equals(owner) || transSupers(c.name).contains(owner))) continue;
            if (declaresConcrete(c, name, desc)) {
                out.add(c.name.replace('/', '.') + "." + name);
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

    /** The concrete `(name, desc)` declaration `internal` would invoke via inheritance: the first one
     *  found walking its supertype chain (excludes `internal` itself — the caller checks that). */
    static String nearestConcreteSuper(String internal, String name, String desc) {
        for (String sup : transSupers(internal)) {
            ClassNode c = byName.get(sup);
            if (c != null && declaresConcrete(c, name, desc)) return sup.replace('/', '.') + "." + name;
        }
        return null;
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

    static String classify(String owner, String method, String desc) {
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
        // Network — raw sockets, NIO socket channels (the channel type IS the network boundary; the
        // generic ReadableByteChannel/WritableByteChannel interfaces are NOT classified, they may wrap a
        // file or an in-memory buffer), java.net.http, and Spring's outbound HTTP clients. Without the NIO
        // channels, every NIO-based stack (Netty, async/reactive frameworks, modern high-perf I/O) was a
        // silent under-report — found by the gradle-cache soundness sweep (httpcore5 uses SocketChannel).
        if (owner.equals("java.net.Socket") || owner.equals("java.net.ServerSocket")
                || owner.equals("java.net.DatagramSocket")
                || owner.equals("java.nio.channels.SocketChannel")
                || owner.equals("java.nio.channels.ServerSocketChannel")
                || owner.equals("java.nio.channels.DatagramChannel")
                || owner.equals("java.nio.channels.AsynchronousSocketChannel")
                || owner.equals("java.nio.channels.AsynchronousServerSocketChannel")
                || owner.startsWith("java.net.http.")
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
                    && (method.equals("create") || method.equals("bind") || method.equals("start"))))
            return "Net";
        // Messaging (Net-family)
        if (owner.equals("org.springframework.jms.core.JmsTemplate")
                || owner.equals("org.springframework.kafka.core.KafkaTemplate"))
            return "Net";
        // Database — JDBC, Spring JdbcTemplate, JPA EntityManager (Spring Data repos handled in analyze)
        if ((owner.equals("java.sql.Statement") || owner.equals("java.sql.PreparedStatement")
                || owner.equals("java.sql.CallableStatement") || owner.equals("java.sql.Connection")
                || owner.equals("java.sql.DriverManager"))
                && (method.startsWith("execute") || method.equals("getConnection")
                    || method.equals("prepareStatement") || method.equals("prepareCall")))
            return "Db";
        if (owner.equals("org.springframework.jdbc.core.JdbcTemplate")
                || owner.equals("org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate")
                || owner.equals("jakarta.persistence.EntityManager") || owner.equals("javax.persistence.EntityManager"))
            return "Db";
        // Subprocess
        if (owner.equals("java.lang.ProcessBuilder") && method.equals("start")) return "Exec";
        if (owner.equals("java.lang.Runtime") && method.equals("exec")) return "Exec";
        // Environment / config
        if (owner.equals("java.lang.System")
                && (method.equals("getenv") || method.equals("getProperty") || method.equals("setProperty")))
            return "Env";
        if (owner.equals("org.springframework.core.env.Environment") && method.equals("getProperty")) return "Env";
        // Clock
        if (owner.equals("java.lang.System") && (method.equals("currentTimeMillis") || method.equals("nanoTime")))
            return "Clock";
        if (owner.equals("java.time.Clock")) return "Clock";
        if (method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")
                    || owner.equals("java.time.LocalDate") || owner.equals("java.time.ZonedDateTime")))
            return "Clock";
        // Randomness — the concrete PRNG/CSPRNG classes (mirrors `new Random()` / `Math.random()`).
        // ThreadLocalRandom and SplittableRandom are the java.util(.concurrent) generators a probe found
        // unclassified despite Random being flagged — same effect category, added for consistency.
        if (owner.equals("java.util.Random") || owner.equals("java.security.SecureRandom")
                || owner.equals("java.util.concurrent.ThreadLocalRandom")
                || owner.equals("java.util.SplittableRandom")
                || (owner.equals("java.lang.Math") && method.equals("random")))
            return "Rand";
        // Logging
        if (owner.startsWith("org.slf4j.") || owner.startsWith("java.util.logging.")
                || owner.startsWith("org.apache.logging.log4j.") || owner.startsWith("ch.qos.logback."))
            return "Log";
        // Clipboard — system clipboard access (spec §1). Toolkit hands out the system clipboard/selection
        // handle; the `Clipboard` get/setContents are the read/write. Restores cross-impl vocabulary parity
        // — Clipboard was the one spec effect candor-java never emitted (the Rust impl classifies arboard).
        if ((owner.equals("java.awt.Toolkit")
                && (method.equals("getSystemClipboard") || method.equals("getSystemSelection")))
                || owner.equals("java.awt.datatransfer.Clipboard"))
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
                String fn = dc + "." + mn.name;
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
        envelope.put("functions", entries);
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(envelope);
        Files.writeString(Path.of(out), json);
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
        Files.writeString(Path.of(cgOut), new GsonBuilder().setPrettyPrinting().create().toJson(cg));
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
}
