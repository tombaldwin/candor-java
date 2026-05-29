package candor;

import com.google.gson.GsonBuilder;
import org.objectweb.asm.ClassReader;
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

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>]");
            System.exit(2);
        }
        String jsonOut = null;
        for (int i = 1; i + 1 < args.length; i++) if (args[i].equals("--json")) jsonOut = args[i + 1];

        List<ClassNode> classes = load(Path.of(args[0]));
        for (ClassNode cn : classes) projectClasses.add(cn.name);
        computeSpringTypes(classes);
        for (ClassNode cn : classes) analyze(cn);

        Map<String, TreeSet<String>> inferred = fixpoint();

        System.out.println("candor-java — effect audit (Spring-aware; Unknown for reflection)\n");
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

        if (jsonOut != null) writeJson(inferred, jsonOut);
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
                    if (repoTypes.contains(min.owner)) dir.add("Db");
                    if (feignTypes.contains(min.owner)) dir.add("Net");
                    if (projectClasses.contains(min.owner)) edges.get(id).add(owner + "." + min.name);
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
        List<Map<String, Object>> entries = new ArrayList<>();
        inferred.entrySet().stream()
                .filter(e -> !e.getValue().isEmpty() || entryPoints.contains(e.getKey()))
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("fn", e.getKey());
                    m.put("loc", loc.getOrDefault(e.getKey(), "?"));
                    m.put("inferred", new ArrayList<>(e.getValue()));
                    m.put("direct", new ArrayList<>(direct.getOrDefault(e.getKey(), new TreeSet<>())));
                    m.put("entryPoint", entryPoints.contains(e.getKey()));
                    m.put("unresolved", e.getValue().contains("Unknown")); // trust contract (SPEC §4)
                    entries.add(m);
                });
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(entries);
        Files.writeString(Path.of(out), json);
        System.err.println("candor-java: wrote " + entries.size() + " entries to " + out);
    }
}
