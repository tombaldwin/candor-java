package candor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

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
 * TRUST CONTRACT (SPEC §4): reflection / dynamic invocation is reported as `Unknown`, never assumed
 * pure. NOT YET (deferred honestly — PRINCIPLES #7): `Unknown` for the broader unresolvable-dispatch
 * cases (interface dispatch to an unknown impl, lambdas/callbacks, custom AOP) needs CHA to first
 * resolve what it *can* — otherwise it floods; that's the next rung. Also: conformance mode.
 */
public class Candor {
    static final Map<String, TreeSet<String>> direct = new HashMap<>();
    static final Map<String, Set<String>> edges = new HashMap<>();
    static final Map<String, String> loc = new HashMap<>();
    static final Set<String> entryPoints = new HashSet<>(); // framework-invoked methods
    static final Set<String> projectClasses = new HashSet<>();
    static final Set<String> repoTypes = new HashSet<>();    // Spring Data repository interfaces (internal names)
    static final Set<String> feignTypes = new HashSet<>();   // @FeignClient interfaces (internal names)
    static List<ClassNode> ALL = List.of();                  // all loaded classes (for CHA)
    static final Map<String, ClassNode> byName = new HashMap<>();      // internal name -> node
    static final Map<String, Set<String>> transSupersCache = new HashMap<>();

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
    // Ambient authorities (for CANDOR_NO_AMBIENT). Log/Unknown are not authorities.
    static final Set<String> AMBIENT = Set.of("Net", "Fs", "Db", "Exec", "Env", "Clock", "Rand");

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>]");
            System.exit(2);
        }
        String jsonOut = null;
        for (int i = 1; i + 1 < args.length; i++) if (args[i].equals("--json")) jsonOut = args[i + 1];

        List<ClassNode> classes = load(Path.of(args[0]));
        ALL = classes;
        for (ClassNode cn : classes) { projectClasses.add(cn.name); byName.put(cn.name, cn); }
        computeSpringTypes(classes);
        for (ClassNode cn : classes) analyze(cn);

        Map<String, TreeSet<String>> inferred = fixpoint();

        // JSON output is orthogonal — write first so `--json` can snapshot a baseline.
        if (jsonOut != null) writeJson(inferred, jsonOut);

        // Modes: CANDOR_STRICT (conformance via DI), CANDOR_BASELINE (regression guard),
        // CANDOR_NO_AMBIENT (enforcement).
        String strict = System.getenv("CANDOR_STRICT");
        String baseline = System.getenv("CANDOR_BASELINE");
        String noAmbient = System.getenv("CANDOR_NO_AMBIENT");
        boolean enforce = baseline != null || noAmbient != null || strict != null;

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
        if (violations == 0) System.out.println("candor-java: no violations");
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
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class"))::iterator) {
                ClassNode cn = new ClassNode();
                new ClassReader(Files.readAllBytes(p)).accept(cn, 0);
                out.add(cn);
            }
        }
        return out;
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
        for (MethodNode mn : cn.methods) {
            if (mn.name.startsWith("<")) continue;
            String id = dottedClass + "." + mn.name;
            var dir = direct.computeIfAbsent(id, k -> new TreeSet<>());
            edges.computeIfAbsent(id, k -> new HashSet<>());
            loc.putIfAbsent(id, cn.sourceFile + ":" + firstLine(mn));

            // Spring annotations on this method (the effect Spring's proxy/generated code performs).
            if (classTx || annoPresent(mn.visibleAnnotations, TX)) dir.add("Db");
            if (annoPresent(mn.visibleAnnotations, SCHEDULED)
                    || annoPresentAny(mn.visibleAnnotations, MAPPING_OR_LISTENER))
                entryPoints.add(id);

            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode min) {
                    String owner = min.owner.replace('/', '.');
                    String effect = classify(owner, min.name);
                    if (effect != null) dir.add(effect);
                    // Calls to a Spring Data repository / Feign client are I/O even though the
                    // callee has no body candor can see (Spring synthesizes the impl at runtime).
                    boolean springTyped = repoTypes.contains(min.owner) || feignTypes.contains(min.owner);
                    if (repoTypes.contains(min.owner)) dir.add("Db");
                    if (feignTypes.contains(min.owner)) dir.add("Net");

                    int op = min.getOpcode();
                    if (op == Opcodes.INVOKEVIRTUAL || op == Opcodes.INVOKEINTERFACE) {
                        // Class Hierarchy Analysis: dispatch could reach any project subtype's
                        // override — add edges to all of them so their effects propagate.
                        List<String> targets = chaTargets(min.owner, min.name, min.desc);
                        edges.get(id).addAll(targets);
                        // Genuine unresolved dispatch: a PROJECT interface/abstract type with no
                        // visible impl (DI-wired, external, or strategy) → honest Unknown (SPEC §4).
                        if (targets.isEmpty() && effect == null && !springTyped
                                && isProjectIfaceOrAbstract(min.owner))
                            dir.add("Unknown");
                    } else if (projectClasses.contains(min.owner)) {
                        // static / special (super, private, ctor) — the exact target.
                        edges.get(id).add(owner + "." + min.name);
                    }
                }
            }
        }
    }

    // entry-point annotation substrings (HTTP mappings + message listeners)
    static final List<String> MAPPING_OR_LISTENER = List.of(
            "web/bind/annotation/RequestMapping", "web/bind/annotation/GetMapping",
            "web/bind/annotation/PostMapping", "web/bind/annotation/PutMapping",
            "web/bind/annotation/DeleteMapping", "web/bind/annotation/PatchMapping",
            "kafka/annotation/KafkaListener", "amqp/rabbit/annotation/RabbitListener",
            "jms/annotation/JmsListener", "context/event/EventListener");

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
        List<String> out = new ArrayList<>();
        for (ClassNode c : ALL) {
            if (c.name.equals(owner) || transSupers(c.name).contains(owner)) {
                if (declaresConcrete(c, name, desc)) out.add(c.name.replace('/', '.') + "." + name);
            }
        }
        return out;
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

    static Map<String, TreeSet<String>> fixpoint() {
        Map<String, TreeSet<String>> eff = new HashMap<>();
        for (var k : direct.keySet()) eff.put(k, new TreeSet<>(direct.get(k)));
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
    static String classify(String owner, String method) {
        // Reflection / dynamic invocation — could call ANYTHING; honestly `Unknown`, never assumed
        // pure (SPEC §4 trust contract). This is the JVM's defining opacity, and the foundation of
        // the framework magic (Spring proxies, DI) candor can't otherwise see through.
        if (owner.equals("java.lang.reflect.Method") && method.equals("invoke")) return "Unknown";
        if (owner.equals("java.lang.reflect.Constructor") && method.equals("newInstance")) return "Unknown";
        if (owner.equals("java.lang.Class") && (method.equals("newInstance") || method.equals("forName")))
            return "Unknown";
        if (owner.equals("java.lang.reflect.Proxy") && method.equals("newProxyInstance")) return "Unknown";
        if (owner.equals("java.lang.invoke.MethodHandle") && method.startsWith("invoke")) return "Unknown";
        // Filesystem
        if (owner.equals("java.nio.file.Files")
                || owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileOutputStream")
                || owner.equals("java.io.FileReader") || owner.equals("java.io.FileWriter")
                || owner.equals("java.io.RandomAccessFile") || owner.equals("java.io.File"))
            return "Fs";
        // Network — raw sockets, java.net.http, and Spring's outbound HTTP clients
        if (owner.equals("java.net.Socket") || owner.equals("java.net.ServerSocket")
                || owner.equals("java.net.DatagramSocket") || owner.startsWith("java.net.http.")
                || owner.equals("org.springframework.web.client.RestTemplate")
                || owner.equals("org.springframework.web.client.RestClient")
                || owner.startsWith("org.springframework.web.reactive.function.client.")
                || (owner.equals("java.net.URL")
                    && (method.equals("openStream") || method.equals("openConnection") || method.equals("getContent"))))
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
        // Randomness
        if (owner.equals("java.util.Random") || owner.equals("java.security.SecureRandom")
                || (owner.equals("java.lang.Math") && method.equals("random")))
            return "Rand";
        // Logging
        if (owner.startsWith("org.slf4j.") || owner.startsWith("java.util.logging.")
                || owner.startsWith("org.apache.logging.log4j.") || owner.startsWith("ch.qos.logback."))
            return "Log";
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
                    entries.add(m);
                });
        // v0.2 self-describing envelope (candor-spec §2): a provenance header + the function entries.
        // Readers still accept the legacy v0.1 bare array (see loadBaseline) during migration.
        String[] prov = provenance();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("version", prov[0]);
        header.put("toolchain", prov[1]);
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("candor", header);
        envelope.put("functions", entries);
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(envelope);
        Files.writeString(Path.of(out), json);
        System.err.println("candor-java: wrote " + entries.size() + " entries (@" + prov[0] + ") to " + out);
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
