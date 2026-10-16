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
 * SOUNDNESS R1199 — THE RESIDUALS OF R1198: an element declared as a JDK interface ({@code Comparable}) or as
 * {@code Object}, aliasing through a callee's RETURN or an instance field's global cell, and a container filled and
 * sorted by different methods with no traced common receiver (stanford-corenlp {@code SceneGraph.nodeListSorted}).
 *
 * <p>Every positive was EXECUTED on JDK 21 (fixture {@code javaagent-v069/f9}, package {@code vy}; {@code s01/s02/p01}
 * driven by {@code vd9.D}, which is not scanned): each wrote its file through {@code Eff.compareTo} or
 * {@code KxEff.compareTo}. Every {@code k*} wrote nothing. On 0.40.12 every positive here except the carried
 * {@code j03/r02/r03/r07/s01Sort/s03} controls-of-the-model was absent under {@code deny Fs Unknown <fn>}.
 *
 * <p>THE MODEL CHANGE. A sort whose element set does not BOUND what it orders — nothing traced, or a value known only as
 * {@code Object}/{@code Comparable} — is a {@code Comparable.compareTo} dispatch, DISCLOSED by the body that sorts
 * where some implementor carries a concrete effect it does not already report ({@code dispatch:java.lang.Comparable
 * .compareTo}); callers inherit it along the call edge. Two RESOLUTIONS ride beside it: a callee that returns its
 * argument container is one object with it at that site (elements flow back, {@code r04/r09}), and a generic project
 * method's container return is instantiated by its receiver's static type ({@code Set<V>} on a {@code Graph2<Eff>},
 * {@code s02}).
 */
class OrderingR1199Test {

    static final String SINK = "package app;\nfinal class Sink { static void w() { try { java.nio.file.Files"
            + ".writeString(java.nio.file.Path.of(\"/nonexistent-r1199/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String TYPES = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "final class Eff implements Comparable<Eff> { final int v; Eff(int v) { this.v = v; }\n"
            + "  public int compareTo(Eff o) { Sink.w(); return Integer.compare(v, o.v); } }\n"
            + "final class Pure implements Comparable<Pure> { final int v; Pure(int v) { this.v = v; }\n"
            + "  public int compareTo(Pure o) { return Integer.compare(v, o.v); } }\n"
            + "final class Mk { @SuppressWarnings(\"rawtypes\") static Comparable any(int v) { return new Eff(v); }\n"
            + "  @SuppressWarnings(\"rawtypes\") static Comparable anyPure(int v) { return new Pure(v); }\n"
            + "  static Object obj(int v) { return new Eff(v); }\n"
            + "  static Outer outer() { return new Outer(); }\n"
            + "  static Outer id(Outer o) { return o; }\n"
            + "  static List<Object> idList(List<Object> l) { return l; } }\n"
            + "class Bag { final List<Object> items = new ArrayList<>(); void put(Object o) { items.add(o); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) void order() { Collections.sort((List) items); } int size() { return items.size(); } }\n"
            + "final class Outer { final Bag bag = new Bag(); void add(Object o) { bag.put(o); } void sort() { bag.order(); } int size() { return bag.size(); } }\n"
            + "final class Box { Outer o; }\n"
            + "final class Graph2<V> { final Map<V, Integer> out = new HashMap<>(); void addV(V v) { out.put(v, 1); } Set<V> all() { return out.keySet(); } }\n"
            + "abstract class Kb implements Comparable<Kb> { final int v; Kb(int v) { this.v = v; } abstract int key();\n"
            + "  public int compareTo(Kb o) { return Integer.compare(key(), o.v); } }\n"
            + "final class KEff extends Kb { KEff(int v) { super(v); } int key() { Sink.w(); return v; } }\n"
            + "final class KPure extends Kb { KPure(int v) { super(v); } int key() { return v; } }\n"
            + "final class EqEff { final int v; EqEff(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { Sink.w(); return o instanceof EqEff e && e.v == v; }\n"
            + "  @Override public int hashCode() { Sink.w(); return v; } }\n"
            + "final class HBag { final List<Object> items = new ArrayList<>(); void put(Object o) { items.add(o); } int hash() { return items.hashCode(); } }\n"
            + "final class Mk2 { static HBag id(HBag b) { return b; } static Object eq(int v) { return new EqEff(v); } }\n"
            + "interface Kx extends Comparable<Kx> { int v(); }\n"
            + "final class KxEff implements Kx { final int v; KxEff(int v) { this.v = v; } public int v() { return v; }\n"
            + "  public int compareTo(Kx o) { Sink.w(); return Integer.compare(v, o.v()); } }\n"
            + "final class KxPure implements Kx { final int v; KxPure(int v) { this.v = v; } public int v() { return v; }\n"
            + "  public int compareTo(Kx o) { return Integer.compare(v, o.v()); } }\n"
            + "public final class Reg { final List<Object> items = new ArrayList<>();\n"
            + "  void fill() { items.add(new Eff(1)); items.add(new Eff(2)); }\n"
            + "  public void fillPure() { items.add(new Pure(1)); items.add(new Pure(2)); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) List<Object> sorted() { List l = new ArrayList(items); Collections.sort(l); return l; } }\n"
            + "public final class Scene { final Graph2<Eff> g = new Graph2<>(); void add(int v) { g.addV(new Eff(v)); }\n"
            + "  List<Eff> nodesSorted() { List<Eff> l = new ArrayList<>(g.all()); Collections.sort(l); return l; } }\n"
            + "public final class ScenePure { final Graph2<Pure> g = new Graph2<>(); void add(int v) { g.addV(new Pure(v)); }\n"
            + "  List<Pure> nodesSorted() { List<Pure> l = new ArrayList<>(g.all()); Collections.sort(l); return l; } }\n"
            + "/** A container whose own inserts are traced (exact KxPure) and whose public add takes a Comparable from outside. */\n"
            + "@SuppressWarnings({\"unchecked\", \"rawtypes\"})\n"
            + "public final class PReg { final List<Comparable> items = new ArrayList<>(); public PReg() { items.add(new KxPure(9)); }\n"
            + "  public void add(Comparable c) { items.add(c); } void sort() { Collections.sort(items); } }\n";

    static final String MAIN = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "@SuppressWarnings({\"unchecked\", \"rawtypes\"})\n"
            + "public class N {\n"
            + "  // ---- part 1: element declared as a JDK interface / Object\n"
            + "  public static void j01Any() { List<Object> a = new ArrayList<>(); addAny(a); Collections.sort((List) a); }\n"
            + "  static void addAny(List<Object> l) { l.add(Mk.any(1)); l.add(Mk.any(2)); }\n"
            + "  public static void j02Fwd() { List<Object> a = new ArrayList<>(); a.add(Mk.any(1)); a.add(Mk.any(2)); Collections.sort((List) a); }\n"
            + "  public static void j03Direct() { Comparable x = Mk.any(1), y = Mk.any(2); x.compareTo(y); }\n"
            + "  public static void j04Obj() { List<Object> a = new ArrayList<>(); a.add(Mk.obj(1)); a.add(Mk.obj(2)); Collections.sort((List) a); }\n"
            + "  public static void j05Typed() { List<Comparable> a = new ArrayList<>(); a.add(Mk.any(1)); a.add(Mk.any(2)); Collections.sort(a); }\n"
            + "  public static void j06Tree() { List<Comparable> a = new ArrayList<>(); a.add(Mk.any(1)); a.add(Mk.any(2)); new TreeSet<>(a); }\n"
            + "  public static void j07Stream() { List<Comparable> a = new ArrayList<>(); a.add(Mk.any(1)); a.add(Mk.any(2)); a.stream().sorted().count(); a.stream().sorted().toList(); }\n"
            + "  public static void j08Arr() { Object[] a = { Mk.obj(1), Mk.obj(2) }; Arrays.sort(a); }\n"
            + "  public static void j09Max() { List<Comparable> a = new ArrayList<>(); a.add(Mk.any(1)); a.add(Mk.any(2)); Collections.max(a); }\n"
            + "  // ---- part 2: alias through a callee's RETURN cell / an instance field's global cell\n"
            + "  public static void r01Id() { Outer o = new Outer(); Outer p = Mk.id(o); p.add(new Eff(1)); p.add(new Eff(2)); o.sort(); }\n"
            + "  public static void r02Make() { Outer o = Mk.outer(); o.add(new Eff(1)); o.add(new Eff(2)); o.sort(); }\n"
            + "  public static void r03Field() { Box h = new Box(); h.o = new Outer(); h.o.add(new Eff(1)); h.o.add(new Eff(2)); h.o.sort(); }\n"
            + "  public static void r04ListId() { List<Object> l = new ArrayList<>(); List<Object> m = Mk.idList(l); m.add(new Eff(1)); m.add(new Eff(2)); Collections.sort((List) l); }\n"
            + "  public static void r05IdBack() { Outer o = new Outer(); o.add(new Eff(1)); o.add(new Eff(2)); Mk.id(o).sort(); }\n"
            + "  public static void r06FieldLocal() { Box h = new Box(); Outer o = new Outer(); h.o = o; o.add(new Eff(1)); o.add(new Eff(2)); h.o.sort(); }\n"
            + "  // ---- part 3: filled by one method, sorted by another; no common receiver in any one body\n"
            + "  public static void s01Fill(Reg r) { r.fill(); }\n"
            + "  public static void s01Sort(Reg r) { r.sorted(); }\n"
            + "  public static void s02Scene(Scene s) { s.nodesSorted(); }\n"
            + "  public static void s03Make() { Reg r = new Reg(); r.fill(); r.sorted(); }\n"
            + "  // ---- residual probes: a PARTIAL element set (an informative type traced, the alias's insert not), and the equals/hashCode twins\n"
            + "  public static void r07Mixed() { Outer o = new Outer(); o.add(new KPure(5)); Mk.id(o).add(new KEff(1)); o.sort(); }\n"
            + "  public static void r08Mixed() { Outer o = new Outer(); o.add(new KxPure(5)); Mk.id(o).add(new KxEff(1)); o.sort(); }\n"
            + "  public static void r09MixedList() { List<Object> l = new ArrayList<>(); l.add(new KxPure(5)); Mk.idList(l).add(new KxEff(1)); Collections.sort((List) l); }\n"
            + "  public static void p01Sort(PReg r) { r.sort(); }\n"
            + "  public static void h01IdHash() { HBag b = new HBag(); Mk2.id(b).put(new EqEff(1)); b.hash(); }\n"
            + "  public static void h02ObjHash() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); l.hashCode(); }\n"
            + "  public static void h03SetObj() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); l.add(Mk2.eq(2)); new HashSet<>(l); }\n"
            + "  // ---- controls (real = 0)\n"
            + "  public static void kj01AnyPure() { List<Comparable> a = new ArrayList<>(); a.add(Mk.anyPure(1)); a.add(Mk.anyPure(2)); Collections.sort(a); }\n"
            + "  public static void kj02DirectPure() { Comparable x = Mk.anyPure(1), y = Mk.anyPure(2); x.compareTo(y); }\n"
            + "  public static void kr01IdPure() { Outer o = new Outer(); Outer p = Mk.id(o); p.add(new Pure(1)); p.add(new Pure(2)); o.sort(); Outer q = new Outer(); q.add(new Eff(1)); q.add(new Eff(2)); q.size(); }\n"
            + "  public static void kr02MakeTwo() { Outer a = Mk.outer(); a.add(new Eff(1)); a.add(new Eff(2)); a.size(); Outer b = Mk.outer(); b.add(new Pure(1)); b.add(new Pure(2)); b.sort(); }\n"
            + "  public static void kr03FieldTwo() { Box h = new Box(); h.o = new Outer(); h.o.add(new Eff(1)); h.o.add(new Eff(2)); h.o.size(); Box k = new Box(); k.o = new Outer(); k.o.add(new Pure(1)); k.o.add(new Pure(2)); k.o.sort(); }\n"
            + "  public static void ks01SortPure(Reg r) { r.sorted(); }\n"
            + "  public static void ks02ScenePure(ScenePure s) { s.nodesSorted(); }\n"
            + "  public static void ks03MakePure() { Reg r = new Reg(); r.fillPure(); r.sorted(); }\n"
            + "  public static void kp01Sort(PReg r) { r.sort(); }\n"
            + "  @SuppressWarnings(\"rawtypes\") public static Comparable kxEff(int v) { return new KxEff(v); }\n"
            + "  @SuppressWarnings(\"rawtypes\") public static Comparable kxPure(int v) { return new KxPure(v); }\n"
            + "  public static Reg reg() { return new Reg(); }\n"
            + "  public static Scene scene() { Scene s = new Scene(); s.add(2); s.add(1); return s; }\n"
            + "  public static ScenePure scenePure() { ScenePure s = new ScenePure(); s.add(2); s.add(1); return s; }\n"
            + "}\n";

    /** Resolved: a concrete charge. */
    static final List<String> CHARGED = List.of("r04ListId", "r09MixedList", "s02Scene");
    /** Disclosed with the true reason (here, or inherited from the callee that sorts). */
    static final List<String> DISCLOSED = List.of("j01Any", "j02Fwd", "j04Obj", "j05Typed", "j06Tree", "j07Stream", "j08Arr",
            "j09Max", "r01Id", "r05IdBack", "r06FieldLocal", "r08Mixed", "p01Sort");
    /** Pure (executed): never a concrete charge from this change. */
    static final List<String> CONTROLS = List.of("kj01AnyPure", "kr01IdPure", "kr02MakeTwo", "kr03FieldTwo", "ks02ScenePure", "kp01Sort");

    static Map<String, String> app() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Sink.java", SINK);
        m.put("app/T.java", TYPES.replace("public final class", "final class"));
        m.put("app/N.java", MAIN);
        return m;
    }

    @SuppressWarnings("unchecked")
    static List<String> inferred(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get(fn);
        return row == null ? List.of() : (List<String>) row.get("inferred");
    }

    /** SOUNDNESS R1199 — a pure control's row is empty, or carries ONLY an {@code Unknown} inherited from a callee whose
     *  own disclosure is the untraced-ordering one ({@code dispatch:java.lang.Comparable.compareTo}). Used by the older
     *  ordering suites' controls: a generic sorter now discloses what an outside caller could hand it. */
    @SuppressWarnings("unchecked")
    static boolean emptyOrInheritsTheOrderingDisclosure(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get(fn);
        if (row == null) return true;
        List<String> inf = (List<String>) row.get("inferred");
        if (inf.isEmpty()) return true;
        if (!inf.equals(List.of("Unknown"))) return false;
        List<String> own = (List<String>) row.getOrDefault("unknownWhy", List.of());
        if (own.equals(List.of("dispatch:java.lang.Comparable.compareTo"))) return true;
        if (!own.isEmpty()) return false;
        for (String callee : (List<String>) row.getOrDefault("calls", List.of())) {
            Map<String, Object> cr = r.get(callee);
            if (cr == null) continue;
            if (((List<String>) cr.getOrDefault("unknownWhy", List.of())).contains("dispatch:java.lang.Comparable.compareTo")) return true;
            if (emptyOrInheritsTheOrderingDisclosure(r, callee) && !((List<String>) cr.get("inferred")).isEmpty()) return true;
        }
        return false;
    }

    @Test
    void controlsGainNoConcreteEffect() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : CONTROLS)
                assertTrue(emptyOrInheritsTheOrderingDisclosure(r, "app.N." + fn), fn + " runs no effectful compareTo (executed); got "
                        + r.get("app.N." + fn));
            // a typed generic container sorted over Pure resolves to Pure: nothing at all
            assertTrue(inferred(r, "app.N.ks02ScenePure").isEmpty(), "ks02ScenePure got " + r.get("app.N.ks02ScenePure"));
        } finally {
            t.close();
        }
    }

    @Test
    void anIdentityReturnAndAGenericReceiverAreResolved() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : CHARGED)
                assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " runs Eff/KxEff.compareTo (executed); got " + r.get("app.N." + fn));
        } finally {
            t.close();
        }
    }

    @Test
    void anUntracedOrderingIsDisclosedNeverSilent() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : DISCLOSED) {
                List<String> inf = inferred(r, "app.N." + fn);
                assertTrue(inf.contains("Fs") || inf.contains("Unknown"), fn + " runs Eff/KxEff.compareTo (executed); got " + r.get("app.N." + fn));
            }
            // the reason is the true one, on the body that sorts
            for (String fn : List.of("app.N.j01Any", "app.N.j08Arr", "app.Bag.order", "app.PReg.sort"))
                assertTrue(String.valueOf(r.get(fn).get("unknownWhy")).contains("dispatch:java.lang.Comparable.compareTo"), fn + " got " + r.get(fn));
        } finally {
            t.close();
        }
    }

    /** STATED RESIDUAL, not closed: the equals/hashCode twin (a hashed element known only as Object, or a container
     *  aliased through a callee's return and then hashed). Executed: h01-h03 each run EqEff.hashCode. */
    @Test
    void theEqualsHashCodeTwinStaysTheStatedResidual() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : List.of("h01IdHash", "h02ObjHash", "h03SetObj"))
                assertTrue(inferred(r, "app.N." + fn).isEmpty(), "if this now reports, close the residual in its row: " + r.get("app.N." + fn));
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
