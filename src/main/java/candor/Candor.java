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
 * Mirrors the Rust reference impl's first version: resolve each call to its concrete target,
 * classify it against the effect table, record per-method DIRECT effects + call edges, then
 * propagate to a transitive fixpoint. See https://github.com/tombaldwin/candor-spec.
 *
 * NOT YET (deferred, honestly — per PRINCIPLES #7): the trust contract's `Unknown` for
 * unresolvable dispatch (virtual/interface dispatch to unknown impls, lambdas/invokedynamic,
 * reflection). v0 reports resolved effects only; dispatch resolution (CHA) is the next rung.
 */
public class Candor {
    static final Map<String, TreeSet<String>> direct = new HashMap<>();
    static final Map<String, Set<String>> edges = new HashMap<>();
    static final Map<String, String> loc = new HashMap<>();
    static final Set<String> projectClasses = new HashSet<>(); // internal names (slashes)

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>]");
            System.exit(2);
        }
        String jsonOut = null;
        for (int i = 1; i + 1 < args.length; i++) if (args[i].equals("--json")) jsonOut = args[i + 1];

        List<ClassNode> classes = load(Path.of(args[0]));
        for (ClassNode cn : classes) projectClasses.add(cn.name);
        for (ClassNode cn : classes) analyze(cn);

        Map<String, TreeSet<String>> inferred = fixpoint();

        System.out.println("candor-java — effect audit (resolved; v0, no Unknown yet)\n");
        inferred.entrySet().stream()
                .filter(e -> !e.getValue().isEmpty())
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> {
                    var d = direct.getOrDefault(e.getKey(), new TreeSet<>());
                    String set = e.getValue().stream()
                            .map(x -> d.contains(x) ? x : x + "*")
                            .collect(Collectors.joining(", "));
                    System.out.printf("  %-45s { %s }%n", e.getKey(), set);
                });
        System.out.println("\n(* = via callee)");

        if (jsonOut != null) writeJson(inferred, jsonOut);
    }

    static List<ClassNode> load(Path root) throws IOException {
        List<ClassNode> out = new ArrayList<>();
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class"))::iterator) {
                ClassNode cn = new ClassNode();
                new ClassReader(Files.readAllBytes(p)).accept(cn, 0); // keep line numbers
                out.add(cn);
            }
        }
        return out;
    }

    static void analyze(ClassNode cn) {
        String dottedClass = cn.name.replace('/', '.');
        for (MethodNode mn : cn.methods) {
            if (mn.name.startsWith("<")) continue; // skip <init>/<clinit> for v0 readability
            String id = dottedClass + "." + mn.name;
            direct.computeIfAbsent(id, k -> new TreeSet<>());
            edges.computeIfAbsent(id, k -> new HashSet<>());
            loc.putIfAbsent(id, cn.sourceFile + ":" + firstLine(mn));
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode min) {
                    String owner = min.owner.replace('/', '.');
                    String effect = classify(owner, min.name);
                    if (effect != null) direct.get(id).add(effect);
                    if (projectClasses.contains(min.owner)) edges.get(id).add(owner + "." + min.name);
                }
            }
        }
    }

    static int firstLine(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) if (insn instanceof LineNumberNode ln) return ln.line;
        return 0;
    }

    /** effects[f] = direct[f] ∪ ⋃ effects[callee], to a fixpoint. */
    static Map<String, TreeSet<String>> fixpoint() {
        Map<String, TreeSet<String>> eff = new HashMap<>();
        for (var k : direct.keySet()) eff.put(k, new TreeSet<>(direct.get(k)));
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : edges.keySet()) {
                TreeSet<String> set = eff.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                for (String callee : edges.get(caller)) {
                    TreeSet<String> ce = eff.get(callee);
                    if (ce != null) set.addAll(ce);
                }
                if (set.size() != before) changed = true;
            }
        }
        return eff;
    }

    /** The effect classifier — match the I/O boundary, not the package (candor-spec CLASSIFIER §2). */
    static String classify(String owner, String method) {
        // Filesystem
        if (owner.equals("java.nio.file.Files")
                || owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileOutputStream")
                || owner.equals("java.io.FileReader") || owner.equals("java.io.FileWriter")
                || owner.equals("java.io.RandomAccessFile") || owner.equals("java.io.File"))
            return "Fs";
        // Network (I/O types + http; not pure data like URL/InetAddress construction)
        if (owner.equals("java.net.Socket") || owner.equals("java.net.ServerSocket")
                || owner.equals("java.net.DatagramSocket") || owner.startsWith("java.net.http.")
                || (owner.equals("java.net.URL")
                    && (method.equals("openStream") || method.equals("openConnection") || method.equals("getContent"))))
            return "Net";
        // Subprocess
        if (owner.equals("java.lang.ProcessBuilder") && method.equals("start")) return "Exec";
        if (owner.equals("java.lang.Runtime") && method.equals("exec")) return "Exec";
        // Environment / system properties
        if (owner.equals("java.lang.System")
                && (method.equals("getenv") || method.equals("getProperty") || method.equals("setProperty")))
            return "Env";
        // Clock
        if (owner.equals("java.lang.System") && (method.equals("currentTimeMillis") || method.equals("nanoTime")))
            return "Clock";
        if (owner.equals("java.time.Clock")) return "Clock";
        if (method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")
                    || owner.equals("java.time.LocalDate") || owner.equals("java.time.ZonedDateTime")))
            return "Clock";
        // Database (JDBC) — execution verbs, not construction
        if ((owner.equals("java.sql.Statement") || owner.equals("java.sql.PreparedStatement")
                || owner.equals("java.sql.CallableStatement") || owner.equals("java.sql.Connection")
                || owner.equals("java.sql.DriverManager"))
                && (method.startsWith("execute") || method.equals("getConnection")
                    || method.equals("prepareStatement") || method.equals("prepareCall")))
            return "Db";
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
                .filter(e -> !e.getValue().isEmpty())
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("fn", e.getKey());
                    m.put("loc", loc.getOrDefault(e.getKey(), "?"));
                    m.put("inferred", new ArrayList<>(e.getValue()));
                    m.put("direct", new ArrayList<>(direct.getOrDefault(e.getKey(), new TreeSet<>())));
                    m.put("unresolved", false); // v0: no Unknown yet
                    entries.add(m);
                });
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(entries);
        Files.writeString(Path.of(out), json);
        System.err.println("candor-java: wrote " + entries.size() + " entries to " + out);
    }
}
