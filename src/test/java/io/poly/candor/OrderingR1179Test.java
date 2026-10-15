package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
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
 * SOUNDNESS R1179 — AN ORDERING OVER AN ERASED CONTAINER RUNS ITS ELEMENTS' {@code compareTo}, AND READ ABSENT.
 * SOUNDNESS R1174 — A COLLECTION OF PROJECT VALUES HANDED TO A CHAINED DEPENDENCY, STORED AND COMPARED LATER,
 * READ ABSENT.
 *
 * <p>Every member below was EXECUTED on JDK 21 against v0.40.10 (fixture {@code javaagent-v059/fx}): each
 * {@code q*} wrote its file through {@code Eff.compareTo} (or {@code Hq.equals/hashCode} chained) and each was
 * absent under {@code deny Fs Unknown <fn>}; each {@code k*} wrote nothing. The one-tree half is a RESOLUTION
 * (an edge to the element's override); the chained half is a DISCLOSURE ({@code Unknown[dispatch:..]}), the
 * shape {@link ArgContract#chainWitness} already takes for a value handed over directly.
 */
class OrderingR1179Test {

    static final String SINK = "package app;\nfinal class Sink { static void w() { try { java.nio.file.Files"
            + ".writeString(java.nio.file.Path.of(\"/nonexistent-r1179/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String TYPES = "package app;\nimport java.util.*;\n"
            + "final class Eff implements Comparable<Eff> { final int v; Eff(int v) { this.v = v; } public int compareTo(Eff o) { Sink.w(); return v - o.v; } }\n"
            + "final class Pure implements Comparable<Pure> { final int v; Pure(int v) { this.v = v; } public int compareTo(Pure o) { return v - o.v; } }\n"
            + "final class Hq { public boolean equals(Object o) { Sink.w(); return o == this; } public int hashCode() { Sink.w(); return 1; } }\n"
            + "final class Box<T> { final List<T> items; Box(Collection<? extends T> c) { items = new ArrayList<>(c); } void order() { Collections.sort((List) items); } }\n"
            + "final class Holder { final Set<Eff> s; Holder(Set<Eff> s) { this.s = s; } void put(Eff e) { s.add(e); } }\n"
            + "final class HolderH { final Set<Eff> s; HolderH(Set<Eff> s) { this.s = s; } void put(Eff e) { s.add(e); } }\n"
            + "final class LoudSet extends HashSet<String> { public boolean equals(Object o) { Sink.w(); return super.equals(o); } public int hashCode() { Sink.w(); return 1; } }\n"
            + "enum Color { RED }\n"
            + "final class EnumHolder { final Set<?> delegate; private EnumHolder(Set<?> d) { delegate = d; } static EnumHolder of(Set<?> s) { return new EnumHolder(s); } int hc() { return new HashSet<Object>(delegate).size(); } }\n"
            + "final class Funnel { @SuppressWarnings({\"unchecked\", \"rawtypes\"}) static EnumHolder copy(Collection<?> c) { return c instanceof EnumSet ? EnumHolder.of(EnumSet.copyOf((EnumSet) c)) : null; } }\n"
            + "final class View { final Map<Eff, String> m; View() { Map<Eff, String> h = new LinkedHashMap<>(); m = Collections.unmodifiableMap(h); } String at(Eff e) { return m.get(e); } }\n"
            + "final class G {\n"
            + "  static <T> void ins(Set<T> s, T a) { s.add(a); }\n"
            + "  static <T extends Comparable<? super T>> void srt(List<T> l) { Collections.sort(l); }\n"
            + "  static <T> int cnt(List<T> l) { return l.size(); }\n"
            + "  static <T> void ins2(Set<T> s, T a) { ins(s, a); }\n"
            + "  static int hashAll(Collection<?> c) { return new HashSet<>(c).size(); }\n"
            + "  static <T> List<T> dup(Collection<T> c) { return new ArrayList<>(c); }\n"
            + "}\n";

    /** No name is a prefix of another (§3.3). */
    static final String MAIN = "package app;\nimport java.util.*;\npublic class Main {\n"
            + "  static List<Eff> effs() { List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); return l; }\n"
            + "  static List<Pure> pures() { List<Pure> l = new ArrayList<>(); l.add(new Pure(2)); l.add(new Pure(1)); return l; }\n"
            + "  static final TreeSet<Eff> NATF = new TreeSet<>();\n"
            + "  static final TreeSet<Eff> CMPF = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v));\n"
            + "  public static void qColSort() { Collections.sort(effs()); }\n"
            + "  public static void qListSortNull() { effs().sort(null); }\n"
            + "  public static void qArrSort() { Eff[] a = { new Eff(2), new Eff(1) }; Arrays.sort(a); }\n"
            + "  public static void qTreeSetCopy() { new TreeSet<>(effs()); }\n"
            + "  public static void qTreeSetAddAll() { TreeSet<Eff> t = new TreeSet<>(); t.addAll(effs()); }\n"
            + "  public static void qSetErased() { G.ins(new TreeSet<Eff>(), new Eff(1)); }\n"
            + "  public static void qSetDeclAdd() { Set<Eff> s = new TreeSet<>(); s.add(new Eff(2)); s.add(new Eff(1)); }\n"
            + "  public static void qTreeMapCopy() { Map<Eff, String> h = new HashMap<>(); h.put(new Eff(2), \"a\"); h.put(new Eff(1), \"b\"); new TreeMap<>(h); }\n"
            + "  public static void qGenSort() { G.srt(effs()); }\n"
            + "  public static void qBoxOrder() { new Box<Eff>(effs()).order(); }\n"
            + "  public static void qPq() { PriorityQueue<Eff> q = new PriorityQueue<>(); q.add(new Eff(2)); q.add(new Eff(1)); }\n"
            + "  public static void qMax() { Collections.max(effs()); }\n"
            + "  public static void qStreamSorted() { effs().stream().sorted().count(); }\n"
            + "  public static void qNatField() { NATF.addAll(effs()); }\n"
            + "  public static void qFactoryEff() { List<Eff> d = G.dup(effs()); Collections.sort(d); }\n"
            + "  public static void qCtorTree() { Holder h = new Holder(new TreeSet<>()); h.put(new Eff(1)); }\n"
            + "  public static void kSetParamHash() { G.ins(new HashSet<Eff>(), new Eff(1)); }\n"
            + "  public static void kUnmodMap() { new View().at(new Eff(1)); }\n"
            + "  public static void kCtorHash() { HolderH h = new HolderH(new HashSet<>()); h.put(new Eff(1)); }\n"
            + "  public static void qInsChain() { G.ins2(new TreeSet<Eff>(), new Eff(1)); }\n"
            + "  public static void kOwnSetEq() { LoudSet l = new LoudSet(); l.add(\"a\"); G.hashAll(l); }\n"
            + "  public static void kFunnel() { List<Hq> l = new ArrayList<>(); l.add(new Hq()); Funnel.copy(l); EnumHolder.of(EnumSet.of(Color.RED)).hc(); }\n"
            + "  public static void kSortCmp() { Collections.sort(effs(), (x, y) -> x.v - y.v); }\n"
            + "  public static void kTreeSetCmp() { TreeSet<Eff> t = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v)); t.addAll(effs()); }\n"
            + "  public static void kPureSort() { Collections.sort(pures()); }\n"
            + "  public static void kPureArr() { Pure[] a = { new Pure(2), new Pure(1) }; Arrays.sort(a); }\n"
            + "  public static void kHashCopy() { new HashSet<>(effs()); }\n"
            + "  public static void kSetDeclHash() { Set<Eff> s = new HashSet<>(); s.add(new Eff(2)); s.add(new Eff(1)); }\n"
            + "  public static void kMapDeclHash() { Map<Eff, String> m = new HashMap<>(); m.put(new Eff(2), \"a\"); }\n"
            + "  public static void kGenPure() { G.srt(pures()); }\n"
            + "  public static void kGenCount() { G.cnt(effs()); }\n"
            + "  public static void kCmpField() { CMPF.addAll(effs()); }\n"
            + "  public static void kSortedDeclCmpAdd() { SortedSet<Eff> t = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v)); t.add(new Eff(1)); }\n"
            + "  public static void kFactoryPure() { List<Pure> d = G.dup(pures()); Collections.sort(d); }\n"
            + "  public static void kFactoryNoSort() { G.dup(effs()).size(); }\n"
            + "}\n";

    static final List<String> REAL = List.of("qColSort", "qListSortNull", "qArrSort", "qTreeSetCopy", "qTreeSetAddAll",
            "qSetErased", "qSetDeclAdd", "qTreeMapCopy", "qGenSort", "qBoxOrder", "qPq", "qMax", "qStreamSorted",
            "qNatField", "qFactoryEff", "qCtorTree", "qInsChain");
    static final List<String> CONTROLS = List.of("kSortCmp", "kTreeSetCmp", "kPureSort", "kPureArr", "kHashCopy",
            "kSetDeclHash", "kMapDeclHash", "kGenPure", "kGenCount", "kCmpField", "kSortedDeclCmpAdd", "kFactoryPure",
            "kFactoryNoSort", "kSetParamHash", "kUnmodMap", "kCtorHash", "kOwnSetEq", "kFunnel");

    /** Controls hashing an {@code Eff} key into a HashMap-backed structure (R1184's tree-bin disclosure). */
    static final List<String> TREE_BIN = List.of("kHashCopy", "kSetDeclHash", "kMapDeclHash", "kSetParamHash", "kUnmodMap", "kCtorHash");

    static final String LIB = "package zlib;\nimport java.util.*;\n"
            + "public final class Store { private final List<Object> items;\n"
            + "  public Store(Collection<?> c) { items = new ArrayList<>(c); }\n"
            + "  public int hc() { return items.hashCode(); }\n"
            + "  public static <T extends Comparable<? super T>> void sortIt(List<T> l) { Collections.sort(l); }\n"
            + "}\n";
    static final String CONSUMER = "package app;\nimport java.util.*;\npublic class Use {\n"
            + "  static List<Hq> hqs() { List<Hq> l = new ArrayList<>(); l.add(new Hq()); l.add(new Hq()); return l; }\n"
            + "  static List<Eff> effs() { List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); return l; }\n"
            + "  static List<String> strs() { List<String> l = new ArrayList<>(); l.add(\"b\"); l.add(\"a\"); return l; }\n"
            + "  public static void cStoreHash() { new zlib.Store(hqs()).hc(); }\n"
            + "  public static void cSorter() { zlib.Store.sortIt(effs()); }\n"
            + "  static <T extends Comparable<? super T>> void via(List<T> l) { zlib.Store.sortIt(l); }\n"
            + "  public static void cThroughParam() { via(effs()); }\n"
            + "  public static void kStrings() { zlib.Store.sortIt(strs()); }\n"
            + "}\n";

    static Map<String, String> app() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Sink.java", SINK);
        m.put("app/Types.java", TYPES);
        m.put("app/Main.java", MAIN);
        m.put("app/Use.java", CONSUMER);
        return m;
    }

    @SuppressWarnings("unchecked")
    static List<String> inferred(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get(fn);
        return row == null ? List.of() : (List<String>) row.get("inferred");
    }

    // ---- the over-charge controls, written first -------------------------------------------------------

    @Test
    void comparatorOrderedPureAndUnsortedContainersAddNothing() throws Exception {
        Tree t = Tree.of(app(), Map.of("zlib/Store.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : CONTROLS) {
                // R1184: a HashMap-backed structure keyed by a self-Comparable Eff MAY run Eff.compareTo in a tree bin
                // (11+ colliding keys; executed). These run two keys, so nothing — and the engine, which cannot see
                // the hash distribution, DISCLOSES it and never charges it.
                if (TREE_BIN.contains(fn)) {
                    List<String> inf = inferred(r, "app.Main." + fn);
                    @SuppressWarnings("unchecked")
                    List<String> why = (List<String>) r.get("app.Main." + fn).get("unknownWhy");
                    assertTrue(inf.equals(List.of("Unknown")) && why.equals(List.of("dispatch:java.lang.Comparable.compareTo")),
                            fn + " is at most the tree-bin disclosure; got " + r.get("app.Main." + fn));
                    continue;
                }
                assertTrue(inferred(r, "app.Main." + fn).isEmpty(), fn + " runs no effectful compareTo (executed); got "
                        + r.get("app.Main." + fn));
            }
            // the generic callee keeps only what its own signature names: its CALLERS are charged
            assertTrue(!inferred(r, "app.G.srt").contains("Fs"), "got " + r.get("app.G.srt"));
            assertTrue(!inferred(r, "app.G.dup").contains("Fs"), "got " + r.get("app.G.dup"));
        } finally {
            t.close();
        }
    }

    @Test
    void chainedPureElementsDiscloseNothing() throws Exception {
        Tree t = Tree.of(app(), Map.of("zlib/Store.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanChained("app", t.scan("zlib")));
            assertTrue(inferred(r, "app.Use.kStrings").isEmpty(), "a JDK element type adds nothing; got " + r.get("app.Use.kStrings"));
        } finally {
            t.close();
        }
    }

    // ---- the rows ---------------------------------------------------------------------------------------

    @Test
    void orderingOverAnErasedContainerIsChargedInOneTree() throws Exception {
        Tree t = Tree.of(app(), Map.of("zlib/Store.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : REAL)
                assertTrue(inferred(r, "app.Main." + fn).contains("Fs"), fn + " runs Eff.compareTo (executed); got "
                        + r.get("app.Main." + fn));
        } finally {
            t.close();
        }
    }

    @Test
    void aCollectionHandedToAChainedDependencyIsDisclosed() throws Exception {
        Tree t = Tree.of(app(), Map.of("zlib/Store.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanChained("app", t.scan("zlib")));
            for (String fn : List.of("cStoreHash", "cSorter", "cThroughParam")) {
                List<String> inf = inferred(r, "app.Use." + fn);
                assertTrue(inf.contains("Unknown") && !inf.contains("Fs"), fn + " chained: disclosed, not charged; got "
                        + r.get("app.Use." + fn));
                @SuppressWarnings("unchecked")
                List<String> why = (List<String>) r.get("app.Use." + fn).get("unknownWhy");
                assertTrue(why.stream().anyMatch(w -> w.startsWith("dispatch:java.")), fn + " why " + why);
            }
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
