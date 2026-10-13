package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1166 — A GENERIC METHOD RUNS ITS CALLER'S OVERRIDE, AND THE CALLER READ SILENT.
 *
 * <p>Erasure compiles {@code <T> boolean same(T a, T b) { return a.equals(b); }} to {@code invokevirtual
 * Object.equals}, and {@code <T> int count(Iterable<T> it)} to {@code invokeinterface Iterable.iterator}. The
 * body that runs belongs to the CALLER's argument. EXECUTED on v0.40.9 (fixture
 * {@code javaagent-r1166/fx}): each of six overrides — {@code equals}, {@code hashCode}, {@code toString},
 * {@code compareTo}, {@code Iterable.iterator}, {@code Iterator.next} — wrote its file, and
 * <ul>
 *   <li>CHAINED (the generic in a library whose report the app chains): all six callers ABSENT;</li>
 *   <li>ONE TREE with more than twelve overrides of the member (any real project): the four Object-protocol
 *       callers ABSENT (the §4 exemption drops a broad fan-out with no disclosure); the iterator two
 *       disclosed {@code Unknown}.</li>
 * </ul>
 *
 * <p>The fix is a RESOLUTION, the one the JDK sinks already use ({@code String.valueOf(w)} is charged
 * {@code w.toString()}'s effect over the ARGUMENT's type): a method that dispatches such a member on its own
 * PARAMETER is, to its caller, a re-entry sink for that parameter, and the caller is charged the override of
 * the type it actually passes. Pure overrides contribute nothing, so the controls below must stay absent.
 */
class ArgContractR1166Test {

    static final String SINK = "package app;\nfinal class Sink { static void w() { try { java.nio.file.Files"
            + ".writeString(java.nio.file.Path.of(\"/nonexistent-r1166/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String LIB = "package glib;\npublic class G {\n"
            + "  public static <T> boolean same(T a, T b) { return a.equals(b); }\n"
            + "  public static <T> int hash(T a) { return a.hashCode(); }\n"
            + "  public static <T> String str(T a) { return a.toString(); }\n"
            + "  public static <T extends Comparable<T>> int cmp(T a, T b) { return a.compareTo(b); }\n"
            + "  public static <T> int count(Iterable<T> it) { int n = 0; for (T t : it) n++; return n; }\n"
            + "  public static <T> T first(java.util.Iterator<T> it) { return it.next(); }\n"
            + "  public static <T> boolean wrap(T x) { return same(x, x); }\n"
            + "  public static boolean rec(Object x, Object y, int n) { return n == 0 ? y.equals(y) && y.hashCode() == 1 : rec(y, x, n - 1); }\n"
            + "  public static <T> String viaSink(T x) { return String.valueOf(x); }\n"
            + "  static Object held = new Object();\n"
            + "  public static boolean notParam(Object x) { return held.equals(\"k\"); }\n"
            + "}\n";

    static final String IMPLS = "package app;\nimport java.util.*;\n"
            + "class Weq { public boolean equals(Object o) { Sink.w(); return true; } public int hashCode() { return 1; } }\n"
            + "class Whash { public int hashCode() { Sink.w(); return 1; } }\n"
            + "class Wstr { public String toString() { Sink.w(); return \"w\"; } }\n"
            + "class Wcmp implements Comparable<Wcmp> { public int compareTo(Wcmp o) { Sink.w(); return 0; } }\n"
            + "class Witer implements Iterable<String> { public Iterator<String> iterator() { Sink.w(); return List.of(\"a\").iterator(); } }\n"
            + "class Wnext implements Iterator<String> { public boolean hasNext() { return true; } public String next() { Sink.w(); return \"n\"; } }\n"
            + "class Peq { public boolean equals(Object o) { return o == this; } public int hashCode() { return 2; } }\n"
            + "class Phash { public int hashCode() { return 3; } }\n"
            + "class Pstr { public String toString() { return \"p\"; } }\n"
            + "class Pcmp implements Comparable<Pcmp> { public int compareTo(Pcmp o) { return 0; } }\n"
            + "class Piter implements Iterable<String> { public Iterator<String> iterator() { return List.of(\"a\").iterator(); } }\n"
            + "class LoudList extends ArrayList<String> { public boolean add(String x) { Sink.w(); return true; } public String toString() { Sink.w(); return \"l\"; } }\n"
            + "abstract class Shape { }\n"
            + "class LoudShape extends Shape { public String toString() { Sink.w(); return \"s\"; } }\n"
            + "class QuietShape extends Shape { public String toString() { return \"q\"; } }\n"
            + "class Pnext implements Iterator<String> { public boolean hasNext() { return true; } public String next() { return \"n\"; } }\n";

    /** Function names are chosen so none is a prefix of another (§3.3 prefix matching). */
    static final String MAIN = "package app;\nimport glib.G;\npublic class Main {\n"
            + "  public static boolean eqW() { return G.same(new Weq(), new Weq()); }\n"
            + "  public static int hashW() { return G.hash(new Whash()); }\n"
            + "  public static String strW() { return G.str(new Wstr()); }\n"
            + "  public static int cmpW() { return G.cmp(new Wcmp(), new Wcmp()); }\n"
            + "  public static int iterW() { return G.count(new Witer()); }\n"
            + "  public static String nextW() { return G.first(new Wnext()); }\n"
            + "  public static boolean wrapW() { return G.wrap(new Weq()); }\n"
            + "  public static boolean recurW() { return G.rec(new Weq(), \"s\", 3); }\n"
            + "  public static String sinkW() { return G.viaSink(new Wstr()); }\n"
            + "  public static boolean eqP() { return G.same(new Peq(), new Peq()); }\n"
            + "  public static int hashP() { return G.hash(new Phash()); }\n"
            + "  public static String strP() { return G.str(new Pstr()); }\n"
            + "  public static int cmpP() { return G.cmp(new Pcmp(), new Pcmp()); }\n"
            + "  public static int iterP() { return G.count(new Piter()); }\n"
            + "  public static String nextP() { return G.first(new Pnext()); }\n"
            + "  public static boolean jdkArg() { return G.same(\"a\", \"b\"); }\n"
            + "  public static boolean heldW() { return G.notParam(new Weq()); }\n"
            + "  public static boolean asymW() { return G.same(\"s\", new Weq()); }\n"
            + "  static Shape pick(int i) { return i > 0 ? new QuietShape() : new LoudShape(); }\n"
            + "  public static String wideDecl() { return G.str(pick(1)); }\n"
            + "  public static String exactJdk() { return G.str(new java.util.ArrayList<String>()); }\n"
            + "}\n";

    /** Thirteen PURE overrides of every member — past the shared bound of twelve, the shape of any real
     *  project, where the in-scan fan-out is dropped. */
    static String filler() {
        StringBuilder b = new StringBuilder("package app;\nimport java.util.*;\n");
        for (int i = 1; i <= 13; i++)
            b.append("class F").append(i).append(" implements Comparable<F").append(i)
             .append(">, Iterable<String>, Iterator<String> { public boolean equals(Object o){return o==this;}")
             .append(" public int hashCode(){return ").append(i).append(";} public String toString(){return \"f\";}")
             .append(" public int compareTo(F").append(i).append(" o){return 0;} public Iterator<String> iterator(){return this;}")
             .append(" public boolean hasNext(){return false;} public String next(){return \"f\";} }\n");
        return b.toString();
    }

    static final List<String> EFFECTFUL = List.of("eqW", "hashW", "strW", "cmpW", "iterW", "nextW", "wrapW", "sinkW", "recurW");
    static final List<String> PURE_OBJECT = List.of("eqP", "hashP", "strP", "cmpP", "jdkArg");

    static Map<String, String> app(boolean withFiller) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Sink.java", SINK);
        m.put("app/Impls.java", IMPLS);
        m.put("app/Main.java", MAIN);
        if (withFiller) m.put("app/Fill.java", filler());
        return m;
    }

    @SuppressWarnings("unchecked")
    static List<String> inferred(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get("app.Main." + fn);
        return row == null ? null : (List<String>) row.get("inferred");
    }

    /** Pure = absent, or present only as a ⟨0.39⟩ walk HOP: a row naming no effect. A hop is a row the
     *  consumer's dispatch walk passes through; `pure`, `deny` and `allow` read `inferred`, which is empty. */
    static void assertPure(Map<String, Map<String, Object>> r, String fn, String why) {
        Map<String, Object> row = r.get("app.Main." + fn);
        assertTrue(row == null || ((List<?>) row.get("inferred")).isEmpty(), fn + ": " + why + "; got " + row);
    }

    // ---- the over-charge controls, written first -------------------------------------------------------

    @Test
    void pureOverridesAndJdkArgumentsStayAbsentInOneTree() throws Exception {
        Tree t = Tree.of(Map.of("glib/G.java", LIB), app(true));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll("glib", "app"));
            for (String fn : PURE_OBJECT) assertPure(r, fn, "a PURE override (or a JDK argument) must add nothing");
            assertPure(r, "heldW", "the library dispatches on a FIELD, not on the parameter the caller supplied,"
                    + " so the caller's type is not the receiver");
            assertPure(r, "wideDecl", "a DECLARED type naming two bodies is the open dispatch §4 leaves"
                    + " unresolved; resolving it to the CHA union is the measured smear (9,551 census rows)");
            assertPure(r, "exactJdk", "a provable `new ArrayList` is not its effectful project subclass LoudList");
            assertPure(r, "asymW", "`\"s\".equals(weq)` runs String.equals — the effectful type is the ARGUMENT,"
                    + " not the receiver");
            for (String fn : List.of("iterP", "nextP")) {
                List<String> inf = inferred(r, fn);
                assertTrue(inf == null || !inf.contains("Fs"), fn + ": a pure iterator gains no Fs; got " + inf);
            }
        } finally {
            t.close();
        }
    }

    @Test
    void pureOverridesStayAbsentChained() throws Exception {
        Tree t = Tree.of(Map.of("glib/G.java", LIB), app(false));
        try {
            String lib = t.scan("glib");
            Map<String, Map<String, Object>> r = byFn(t.scanChained("app", lib));
            for (String fn : List.of("eqP", "hashP", "strP", "cmpP", "iterP", "nextP", "jdkArg", "heldW"))
                assertPure(r, fn, "must stay pure chained");
        } finally {
            t.close();
        }
    }

    // ---- the row ---------------------------------------------------------------------------------------

    @Test
    void effectfulOverridesAreChargedInOneTreePastTheBound() throws Exception {
        Tree t = Tree.of(Map.of("glib/G.java", LIB), app(true));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll("glib", "app"));
            for (String fn : EFFECTFUL) {
                List<String> inf = inferred(r, fn);
                assertTrue(inf != null && inf.contains("Fs"), fn + " runs an override that writes a file; got " + inf);
            }
        } finally {
            t.close();
        }
    }

    @Test
    void effectfulOverridesAreChargedChained() throws Exception {
        Tree t = Tree.of(Map.of("glib/G.java", LIB), app(false));
        try {
            String lib = t.scan("glib");
            Map<String, Map<String, Object>> r = byFn(t.scanChained("app", lib));
            for (String fn : EFFECTFUL) {
                List<String> inf = inferred(r, fn);
                assertTrue(inf != null && inf.contains("Fs"), fn + " chained; got " + inf);
            }
        } finally {
            t.close();
        }
    }

    @Test
    void theLibraryNamesTheMemberOnlyWhereItsParameterIsTheReceiver() throws Exception {
        Tree t = Tree.of(Map.of("glib/G.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scan("glib"));
            assertEquals(List.of("java/lang/Object.equals(Ljava/lang/Object;)Z"), r.get("glib.G.same").get("dispatchesOn"));
            assertEquals(List.of("java/lang/Object.toString()Ljava/lang/String;"), r.get("glib.G.viaSink").get("dispatchesOn"));
            assertTrue(r.get("glib.G.count") != null
                    && ((List<?>) r.get("glib.G.count").get("dispatchesOn")).contains("java/lang/Iterable.iterator()Ljava/util/Iterator;"),
                    "got " + r.get("glib.G.count"));
            assertNull(r.get("glib.G.notParam"), "a dispatch on a FIELD names nothing; got " + r.get("glib.G.notParam"));
            assertEquals(List.of(), r.get("glib.G.same").get("inferred"), "a name, never a charge");
        } finally {
            t.close();
        }
    }

    // ---- harness (ChainedDispatchUnionTest's, with a two-package one-tree arm) -------------------------

    private static final class Tree implements AutoCloseable {
        final Path base;
        private final Config saved = Candor.config;

        private Tree(Path base) { this.base = base; }

        @SafeVarargs
        static Tree of(Map<String, String>... pkgs) throws Exception {
            Map<String, String> all = new LinkedHashMap<>();
            for (Map<String, String> p : pkgs) all.putAll(p);
            Path cls = TestCompiler.compile(all);
            Path base = cls.getParent();
            try (var s = Files.list(cls)) {
                for (Path top : s.toList()) {
                    if (!Files.isDirectory(top)) continue;
                    Path dir = base.resolve("d_" + top.getFileName());
                    Files.createDirectories(dir);
                    copyTree(top, dir.resolve(top.getFileName()));
                    copyTree(top, base.resolve("d_all").resolve(top.getFileName()));
                }
            }
            return new Tree(base);
        }

        String scan(String pkg) throws Exception { return scanChained(pkg); }

        String scanAll(String... unused) throws Exception {
            Files.deleteIfExists(base.resolve(".candor/config"));
            Candor.config = Config.empty();
            Path out = base.resolve("all.json");
            Files.deleteIfExists(out);
            ReportWriter.writeJson(Candor.runScan(base.resolve("d_all")), out.toString());
            return out.toString();
        }

        String scanChained(String pkg, String... deps) throws Exception {
            Path dir = base.resolve("d_" + pkg);
            Path out = base.resolve(pkg + "-" + Math.abs(String.join(",", deps).hashCode()) + ".json");
            Files.deleteIfExists(out);
            Files.createDirectories(base.resolve(".candor"));
            if (deps.length == 0) {
                Files.deleteIfExists(base.resolve(".candor/config"));
                Candor.config = Config.empty();
            } else {
                Files.writeString(base.resolve(".candor/config"), "deps " + String.join(" ", deps) + "\n");
                Candor.config = Config.forTarget(dir);
            }
            ReportWriter.writeJson(Candor.runScan(dir), out.toString());
            return out.toString();
        }

        @Override
        public void close() {
            Candor.config = saved;
            rm(base);
        }
    }

    private static void copyTree(Path from, Path to) throws Exception {
        Files.createDirectories(to);
        try (var s = Files.list(from)) {
            for (Path p : s.toList()) {
                if (Files.isDirectory(p)) copyTree(p, to.resolve(p.getFileName()));
                else Files.copy(p, to.resolve(p.getFileName()), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> byFn(String reportPath) throws Exception {
        Map<String, Object> doc = new Gson().fromJson(Files.readString(Path.of(reportPath)), Map.class);
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Object o : (List<Object>) doc.getOrDefault("functions", new ArrayList<>())) {
            Map<String, Object> e = (Map<String, Object>) o;
            out.put((String) e.get("fn"), e);
        }
        return out;
    }
}
