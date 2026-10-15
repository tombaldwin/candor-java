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
 * SOUNDNESS R1195 — THE ORDERING RESIDUALS OF R1179/R1184/R1188/R1189: a stream with no collection behind it
 * ({@code Stream.iterate/generate/concat}, a builder, {@code StreamSupport}), a {@code flatMap} stage, a scalar stored
 * into a callee's FIELD container and sorted later, and a comparator that reaches a sorted container through a
 * return, a field or a dependency.
 *
 * <p>Every {@code q*} member was EXECUTED on JDK 21 (fixture {@code javaagent-v065/fx}, {@code /cfx}): each wrote its
 * file through {@code Eff.compareTo} and was absent under {@code deny Fs Unknown <fn>} on v0.40.11 and on main
 * {@code ceaae07}. Each {@code k*} wrote nothing. The field case once smeared stanford-corenlp (R1184: a field cell merges
 * every instance), so its controls are the point: two instances of one class, two owners, a generic counter.
 */
class OrderingR1195Test {

    static final String SINK = "package app;\nfinal class Sink { static void w() { try { java.nio.file.Files"
            + ".writeString(java.nio.file.Path.of(\"/nonexistent-r1195/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String TYPES = "package app;\nimport java.util.*;\n"
            + "final class Eff implements Comparable<Eff> { final int v; Eff(int v) { this.v = v; } public int compareTo(Eff o) { Sink.w(); return v - o.v; } }\n"
            + "final class Pure implements Comparable<Pure> { final int v; Pure(int v) { this.v = v; } public int compareTo(Pure o) { return v - o.v; } }\n"
            + "final class Hold { final int n; Hold(int n) { this.n = n; }\n"
            + "  List<Eff> effList() { List<Eff> l = new ArrayList<>(); l.add(new Eff(n)); l.add(new Eff(n + 1)); return l; }\n"
            + "  List<Pure> pureList() { List<Pure> l = new ArrayList<>(); l.add(new Pure(n)); l.add(new Pure(n + 1)); return l; } }\n"
            + "class Bag { final List<Object> items = new ArrayList<>(); void put(Object o) { items.add(o); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) void order() { Collections.sort((List) items); } int size() { return items.size(); } }\n"
            + "final class TBag<T extends Comparable<T>> { final List<T> items = new ArrayList<>(); void put(T o) { items.add(o); } void order() { Collections.sort(items); } }\n"
            + "final class Reg { static final List<Object> ALL = new ArrayList<>(); static void add(Object o) { ALL.add(o); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) static void sortAll() { Collections.sort((List) ALL); } }\n"
            + "final class Owner { final Bag bag = new Bag(); }\n"
            + "final class Owner2 { final Bag bag = new Bag(); }\n"
            + "final class LCounter<E> { final List<E> keys = new ArrayList<>(); void inc(E e) { keys.add(e); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) List<E> sorted() { List<E> l = new ArrayList<>(keys); Collections.sort((List) l); return l; }\n"
            + "  int size() { return keys.size(); } static <E> LCounter<E> make() { return new LCounter<>(); } }\n"
            + "final class U { static void addEff(List<Object> l) { l.add(new Eff(1)); l.add(new Eff(2)); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) static void sortIt(List<Object> l) { Collections.sort((List) l); }\n"
            + "  static void fillBag(Bag b) { b.put(new Eff(1)); b.put(new Eff(2)); } static void sortBag(Bag b) { b.order(); }\n"
            + "  static <T extends Comparable<? super T>> Comparator<T> nat() { return Comparator.naturalOrder(); }\n"
            + "  static void addDecl(List<Comparable> l) { } }\n";

    /** No name is a prefix of another (§3.3). */
    static final String MAIN = "package app;\nimport java.util.*;\nimport java.util.stream.*;\npublic class Main {\n"
            + "  static List<Eff> effs() { List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); return l; }\n"
            + "  static List<Hold> holds() { List<Hold> l = new ArrayList<>(); l.add(new Hold(2)); l.add(new Hold(1)); return l; }\n"
            + "  static List<List<Eff>> nested() { List<List<Eff>> l = new ArrayList<>(); l.add(effs()); l.add(effs()); return l; }\n"
            + "  static final Comparator<Eff> NATF = Comparator.naturalOrder();\n"
            // a non-collection stream source
            + "  public static void qIterate() { Stream.iterate(new Eff(3), x -> x.v > 0, x -> new Eff(x.v - 1)).sorted().collect(Collectors.toList()); }\n"
            + "  public static void qGenerate() { Stream.generate(() -> new Eff(1)).limit(3).sorted().collect(Collectors.toList()); }\n"
            + "  public static void qConcat() { Stream.concat(effs().stream(), Stream.of(new Eff(0))).sorted().collect(Collectors.toList()); }\n"
            + "  public static void qBuilder() { Stream.<Eff>builder().add(new Eff(2)).add(new Eff(1)).build().sorted().collect(Collectors.toList()); }\n"
            + "  public static void qSupport() { StreamSupport.stream(effs().spliterator(), false).sorted().collect(Collectors.toList()); }\n"
            // flatMap
            + "  public static void qFlatRef() { nested().stream().flatMap(List::stream).sorted().collect(Collectors.toList()); }\n"
            + "  public static void qFlatLam() { holds().stream().flatMap(h -> h.effList().stream()).sorted().collect(Collectors.toList()); }\n"
            + "  public static void qFlatParam() { nested().stream().flatMap(l -> l.stream()).collect(Collectors.toCollection(TreeSet::new)); }\n"
            // a scalar into a callee's field
            + "  public static void qBag() { Bag b = new Bag(); b.put(new Eff(2)); b.put(new Eff(1)); b.order(); }\n"
            + "  public static void qTBag() { TBag<Eff> b = new TBag<>(); b.put(new Eff(2)); b.put(new Eff(1)); b.order(); }\n"
            + "  public static void qRegistry() { Reg.add(new Eff(2)); Reg.add(new Eff(1)); Reg.sortAll(); }\n"
            + "  public static void qBagFilled() { Bag e = new Bag(); U.fillBag(e); U.sortBag(e); }\n"
            + "  public static void qBagOuter() { Bag b = new Bag(); b.put(new Eff(2)); b.put(new Eff(1)); Collections.sort((List) b.items); }\n"
            + "  public static void qOwner() { Owner a = new Owner(); a.bag.put(new Eff(1)); a.bag.put(new Eff(2)); a.bag.order(); }\n"
            + "  public static void qBackList() { List<Object> a = new ArrayList<>(); U.addEff(a); U.sortIt(a); }\n"
            // a natural comparator through a return or a field
            + "  public static void qRetNatPq() { PriorityQueue<Eff> q = new PriorityQueue<>(U.<Eff>nat()); q.add(new Eff(2)); q.add(new Eff(1)); }\n"
            + "  public static void qFieldNatAll() { new TreeSet<>(NATF).addAll(effs()); }\n"
            + "  public static void qNullsSkip() { java.util.concurrent.ConcurrentSkipListSet<Eff> s = new java.util.concurrent.ConcurrentSkipListSet<>(Comparator.nullsFirst(U.<Eff>nat())); s.add(new Eff(2)); s.add(new Eff(1)); }\n"
            // controls
            + "  public static void kIterPure() { Stream.iterate(new Pure(3), x -> x.v > 0, x -> new Pure(x.v - 1)).sorted().collect(Collectors.toList()); }\n"
            + "  public static void kIterNoSort() { Stream.iterate(new Eff(3), x -> x.v > 0, x -> new Eff(x.v - 1)).collect(Collectors.toList()); }\n"
            + "  public static void kFlatPure() { holds().stream().flatMap(h -> h.pureList().stream()).sorted().collect(Collectors.toList()); }\n"
            + "  public static void kFlatNoSort() { nested().stream().flatMap(List::stream).collect(Collectors.toList()); }\n"
            + "  public static void kBagSize() { Bag b = new Bag(); b.put(new Eff(2)); b.put(new Eff(1)); b.size(); }\n"
            + "  public static void kBagTwo() { Bag a = new Bag(); a.put(new Eff(1)); a.put(new Eff(2)); a.size(); Bag b = new Bag(); b.put(new Pure(1)); b.put(new Pure(2)); b.order(); }\n"
            + "  public static void kCounterTwo() { LCounter<Eff> a = LCounter.make(); a.inc(new Eff(1)); a.inc(new Eff(2)); a.size(); LCounter<Pure> b = LCounter.make(); b.inc(new Pure(1)); b.inc(new Pure(2)); b.sorted(); }\n"
            + "  public static void kBackOther() { List<Object> a = new ArrayList<>(); U.addEff(a); a.size(); List<Object> b = new ArrayList<>(); b.add(new Pure(1)); b.add(new Pure(2)); U.sortIt(b); }\n"
            + "  public static void kSortBagPure() { Bag e = new Bag(); U.fillBag(e); e.size(); Bag p = new Bag(); p.put(new Pure(1)); p.put(new Pure(2)); U.sortBag(p); }\n"
            + "  public static void kOwners() { Owner a = new Owner(); a.bag.put(new Eff(1)); a.bag.put(new Eff(2)); Owner2 b = new Owner2(); b.bag.put(new Pure(1)); b.bag.put(new Pure(2)); b.bag.order(); }\n"
            + "  public static void kDeclParam() { List<Comparable> l = new ArrayList<>(); U.addDecl(l); l.add(new Pure(1)); l.add(new Pure(2)); Collections.sort(l); }\n"
            + "  public static void kNatPure() { PriorityQueue<Pure> q = new PriorityQueue<>(U.<Pure>nat()); q.add(new Pure(2)); q.add(new Pure(1)); }\n"
            + "  public static void kNatUnused() { U.<Eff>nat(); new PriorityQueue<Eff>().size(); }\n"
            + "}\n";

    static final List<String> REAL = List.of("qIterate", "qGenerate", "qConcat", "qBuilder", "qSupport", "qFlatRef",
            "qFlatLam", "qFlatParam", "qBag", "qTBag", "qRegistry", "qBagFilled", "qBagOuter", "qOwner", "qBackList",
            "qRetNatPq", "qFieldNatAll", "qNullsSkip");
    static final List<String> CONTROLS = List.of("kIterPure", "kIterNoSort", "kFlatPure", "kFlatNoSort", "kBagSize",
            "kBagTwo", "kCounterTwo", "kBackOther", "kSortBagPure", "kOwners", "kDeclParam", "kNatPure", "kNatUnused");

    /** A dependency's comparator: its value is out of sight of the consumer's scan. */
    static final String LIB = "package zlib;\nimport java.util.*;\n"
            + "public final class Cmps { private Cmps() {}\n"
            + "  public static <T extends Comparable<? super T>> Comparator<T> natural() { return Comparator.naturalOrder(); }\n"
            + "  public static <T> Comparator<T> same() { return (a, b) -> 0; } }\n";
    static final String CONSUMER = "package app;\nimport java.util.*;\npublic class Use {\n"
            + "  static List<Eff> effs() { List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); return l; }\n"
            + "  public static void cDepPq() { PriorityQueue<Eff> q = new PriorityQueue<>(zlib.Cmps.<Eff>natural()); q.add(new Eff(2)); q.add(new Eff(1)); }\n"
            + "  public static void cDepAll() { new TreeSet<>(zlib.Cmps.<Eff>natural()).addAll(effs()); }\n"
            + "  public static void cDepPure() { PriorityQueue<Pure> q = new PriorityQueue<>(zlib.Cmps.<Pure>same()); q.size(); }\n"
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
    void controlsChargeNothingAndTheFieldModelDoesNotMergeInstances() throws Exception {
        Tree t = Tree.of(app(), Map.of("zlib/Cmps.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : CONTROLS)
                assertTrue(inferred(r, "app.Main." + fn).isEmpty(), fn + " runs no effectful compareTo (executed); got "
                        + r.get("app.Main." + fn));
            // the generic class's own sort keeps only what its signature names: its CALLERS are charged
            assertTrue(!inferred(r, "app.LCounter.sorted").contains("Fs"), "got " + r.get("app.LCounter.sorted"));
            assertTrue(!inferred(r, "app.Bag.order").contains("Fs"), "got " + r.get("app.Bag.order"));
        } finally {
            t.close();
        }
    }

    // ---- the row ----------------------------------------------------------------------------------------

    @Test
    void theOrderingResidualsAreChargedInOneTree() throws Exception {
        Tree t = Tree.of(app(), Map.of("zlib/Cmps.java", LIB));
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
    void aDependencysComparatorIsDisclosedWhereTheContainerRunsIt() throws Exception {
        Tree t = Tree.of(app(), Map.of("zlib/Cmps.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanChained("app", t.scan("zlib")));
            for (String fn : List.of("cDepPq", "cDepAll")) {
                assertTrue(inferred(r, "app.Use." + fn).contains("Unknown"), fn + " chained: disclosed; got " + r.get("app.Use." + fn));
                @SuppressWarnings("unchecked")
                List<String> why = (List<String>) r.get("app.Use." + fn).get("unknownWhy");
                assertTrue(why.contains("callback:java.util.Comparator.compare") || why.contains("dispatch:java.lang.Comparable.compareTo"),
                        fn + " why " + why);
            }
            // a container built with a dependency's comparator and never keyed runs nothing
            assertTrue(inferred(r, "app.Use.cDepPure").isEmpty(), "got " + r.get("app.Use.cDepPure"));
        } finally {
            t.close();
        }
    }

    // ---- harness (OrderingR1179Test's) -------------------------------------------------------------------

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

        String scanAll() throws Exception {
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
