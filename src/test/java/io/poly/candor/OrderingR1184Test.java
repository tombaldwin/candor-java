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
 * SOUNDNESS R1184 — THE ONE-TREE ORDERING RESIDUALS OF R1179, and R1183 — A COMPARATOR-BUILT TreeSet/TreeMap CHARGED
 * ITS ELEMENTS' {@code compareTo}.
 *
 * <p>Every member was EXECUTED on JDK 21 (fixture {@code javaagent-v062/fx}): each {@code q*} wrote its file through
 * an effectful {@code compareTo}, each {@code k*} wrote nothing. Against v0.40.11 every {@code q*} below except the
 * natural-tree ones read absent under {@code deny Fs Unknown}, and {@code kCmpSetOps}/{@code kCmpMapOps}/
 * {@code kCmpFieldAdd} were charged. Two directions:
 * <ul>
 *   <li>RESOLUTIONS (an edge to the element's override): map VALUES, erased {@code T[]} arrays, a stream past a
 *       {@code map} stage, {@code Collectors.toCollection(TreeSet::new)}/{@code toMap(.., TreeMap::new)}, a scalar
 *       parameter added to the caller's list, natural-ordering comparators, a dependency's {@code SortedSet};</li>
 *   <li>DISCLOSURES ({@code Unknown[dispatch:java.lang.Comparable.compareTo]}, never a charge): a dependency's
 *       {@code Set}/{@code Map}/{@code Collection} return (its allocation is out of sight), and a HashMap tree bin
 *       (a self-{@code Comparable} key; whether keys collide is the program's data — {@code kBinFew} is the price).</li>
 * </ul>
 */
class OrderingR1184Test {

    static final String DEP = """
package zd;
import java.util.*;
/** A dependency: its allocations are OUT OF SIGHT of a scan of package sy. */
public final class Dep {
  public static <T> Set<T> tree() { return new TreeSet<>(); }
  public static <T> Set<T> hash() { return new HashSet<>(); }
  public static <T> HashSet<T> hashDecl() { return new HashSet<>(); }
  public static <T> SortedSet<T> sorted() { return new TreeSet<>(); }
  public static <K, V> Map<K, V> treeMap() { return new TreeMap<>(); }
  public static <K, V> Map<K, V> hashMap() { return new HashMap<>(); }
  public static <T> TreeSet<T> cmpTree(Comparator<T> c) { return new TreeSet<>(c); }
  public static <T> TreeSet<T> natTree() { return new TreeSet<>(); }
  public static <T> Collection<T> treeColl() { return new TreeSet<>(); }
  private Dep() {}
}
""";

    static final String APP = """
package app;
import java.util.*;
import java.util.stream.*;
final class Sink { static void w(String n) { try { java.nio.file.Files.writeString(java.nio.file.Path.of("/nonexistent-r1184", n), "x"); } catch (Exception e) { throw new RuntimeException(e); } } }
final class Eff implements Comparable<Eff> { final int v; Eff(int v) { this.v = v; }
  public int compareTo(Eff o) { Sink.w("Eff.compareTo." + N.cur); return Integer.compare(v, o.v); } }
final class Pure implements Comparable<Pure> { final int v; Pure(int v) { this.v = v; }
  public int compareTo(Pure o) { return Integer.compare(v, o.v); } }
final class Hq { final int v; Hq(int v) { this.v = v; } }
/** HashMap tree bins: self-Comparable, every key collides. */
final class HEff implements Comparable<HEff> { final int v; HEff(int v) { this.v = v; }
  @Override public int hashCode() { return 7; } @Override public boolean equals(Object o) { return o instanceof HEff h && h.v == v; }
  public int compareTo(HEff o) { Sink.w("HEff.compareTo." + N.cur); return Integer.compare(v, o.v); } }
final class HPure implements Comparable<HPure> { final int v; HPure(int v) { this.v = v; }
  @Override public int hashCode() { return 7; } @Override public boolean equals(Object o) { return o instanceof HPure h && h.v == v; }
  public int compareTo(HPure o) { return Integer.compare(v, o.v); } }
class HBase implements Comparable<HBase> { final int v; HBase(int v) { this.v = v; }
  @Override public int hashCode() { return 7; } @Override public boolean equals(Object o) { return o instanceof HBase h && h.v == v && o.getClass() == getClass(); }
  public int compareTo(HBase o) { Sink.w("HBase.compareTo." + N.cur); return Integer.compare(v, o.v); } }
final class HSub extends HBase { HSub(int v) { super(v); } }
final class Bag { final List<Object> items = new ArrayList<>(); void put(Object o) { items.add(o); }
  @SuppressWarnings({"unchecked", "rawtypes"}) void order() { Collections.sort((List) items); } int size() { return items.size(); } }
final class G2 {
  static <T> void push(List<T> l, T e) { l.add(e); }
  static <T> void push2(List<T> l, T e) { push(l, e); }
  static <T> List<T> two(T a, T b) { List<T> l = new ArrayList<>(); l.add(a); l.add(b); return l; }
  static <T extends Comparable<? super T>> void sa(T[] a) { Arrays.sort(a); }
  static <T> void sc(T[] a, Comparator<? super T> c) { Arrays.sort(a, c); }
  static <T> int ln(T[] a) { return a.length; }
  @SafeVarargs static <T extends Comparable<? super T>> T mx(T... a) { Arrays.sort(a); return a[a.length - 1]; }
  static void tadd(TreeSet<Eff> t, Eff e) { t.add(e); }
}
public class N {
  static String cur = "";
  static List<Eff> effs() { List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); return l; }
  static List<Pure> pures() { List<Pure> l = new ArrayList<>(); l.add(new Pure(2)); l.add(new Pure(1)); return l; }
  static Map<String, Eff> vals() { Map<String, Eff> m = new HashMap<>(); m.put("a", new Eff(2)); m.put("b", new Eff(1)); return m; }
  // ===== out-of-sight allocation (a dependency's return)
  public static void qDepTreeAdd() { Set<Eff> s = zd.Dep.tree(); s.add(new Eff(2)); s.add(new Eff(1)); }
  public static void qDepSortedAdd() { Set<Eff> s = zd.Dep.sorted(); s.add(new Eff(2)); s.add(new Eff(1)); }
  public static void qDepMapPut() { Map<Eff, String> m = zd.Dep.treeMap(); m.put(new Eff(2), "a"); m.put(new Eff(1), "b"); }
  public static void qDepAddAll() { Collection<Eff> s = zd.Dep.treeColl(); s.addAll(effs()); }
  public static void qDepNatTree() { TreeSet<Eff> t = zd.Dep.natTree(); t.add(new Eff(1)); }
  public static void kDepHashDecl() { Set<Eff> s = zd.Dep.hashDecl(); s.add(new Eff(2)); s.add(new Eff(1)); }
  public static void kDepPureAdd() { Set<Pure> s = zd.Dep.tree(); s.add(new Pure(2)); s.add(new Pure(1)); }
  public static void kDepPlainAdd() { Set<Hq> s = zd.Dep.hash(); s.add(new Hq(2)); s.add(new Hq(1)); }
  public static void kDepHashSet() { Set<Eff> s = zd.Dep.hash(); s.add(new Eff(2)); s.add(new Eff(1)); }
  public static void kDepHashMap() { Map<Eff, String> m = zd.Dep.hashMap(); m.put(new Eff(2), "a"); m.put(new Eff(1), "b"); }
  public static void kDepCmpTree() { TreeSet<Eff> t = zd.Dep.cmpTree(Comparator.comparingInt((Eff x) -> x.v)); t.add(new Eff(1)); t.add(new Eff(2)); }
  // ===== map VALUES
  public static void qValSort() { List<Eff> l = new ArrayList<>(vals().values()); Collections.sort(l); }
  public static void qValTree() { new TreeSet<>(vals().values()); }
  public static void qValMax() { Collections.max(vals().values()); }
  public static void qValStream() { vals().values().stream().sorted().collect(Collectors.toList()); }
  public static void qValLocal() { Map<String, Eff> m = new HashMap<>(); m.put("a", new Eff(2)); m.put("b", new Eff(1)); List<Eff> l = new ArrayList<>(m.values()); Collections.sort(l); }
  public static void kValKeysPure() { Map<Pure, Eff> m = new HashMap<>(); m.put(new Pure(1), new Eff(2)); m.put(new Pure(2), new Eff(1)); List<Pure> l = new ArrayList<>(m.keySet()); Collections.sort(l); }
  public static void kValNoSort() { new ArrayList<>(vals().values()).size(); }
  public static void kValPure() { Map<String, Pure> m = new HashMap<>(); m.put("a", new Pure(2)); m.put("b", new Pure(1)); Collections.sort(new ArrayList<>(m.values())); }
  public static void kValCmp() { List<Eff> l = new ArrayList<>(vals().values()); l.sort(Comparator.comparingInt(x -> x.v)); }
  // ===== erased T[] arrays
  public static void qArrGen() { G2.sa(new Eff[] { new Eff(2), new Eff(1) }); }
  public static void qArrObj() { Object[] a = effs().toArray(); Arrays.sort(a); }
  public static void qArrVar() { G2.mx(new Eff(2), new Eff(1)); }
  public static void kArrGenPure() { G2.sa(new Pure[] { new Pure(2), new Pure(1) }); }
  public static void kArrGenCmp() { G2.sc(new Eff[] { new Eff(2), new Eff(1) }, Comparator.comparingInt((Eff x) -> x.v)); }
  public static void kArrGenLen() { G2.ln(new Eff[] { new Eff(2), new Eff(1) }); }
  public static void kArrObjPure() { Object[] a = pures().toArray(); Arrays.sort(a); }
  // ===== a stream past a map stage
  public static void qMapSorted() { Stream.of(2, 1).map(Eff::new).sorted().collect(Collectors.toList()); }
  public static void qMapLambda() { effs().stream().map(e -> new Eff(e.v + 1)).sorted().collect(Collectors.toList()); }
  public static void kMapPure() { effs().stream().map(e -> new Pure(e.v)).sorted().collect(Collectors.toList()); }
  public static void kMapNoSort() { Stream.of(2, 1).map(Eff::new).collect(Collectors.toList()); }
  public static void kMapCmp() { Stream.of(2, 1).map(Eff::new).sorted(Comparator.comparingInt((Eff x) -> x.v)).collect(Collectors.toList()); }
  // ===== Collectors building a sorted container
  public static void qCollTree() { effs().stream().collect(Collectors.toCollection(TreeSet::new)); }
  public static void qCollLam() { effs().stream().collect(Collectors.toCollection(() -> new TreeSet<>())); }
  public static void qCollPq() { effs().stream().collect(Collectors.toCollection(PriorityQueue::new)); }
  public static void qCollMap() { effs().stream().collect(Collectors.toMap(x -> x, x -> 1, (a, b) -> a, TreeMap::new)); }
  public static void kCollHash() { effs().stream().collect(Collectors.toCollection(HashSet::new)); }
  public static void kCollCmp() { effs().stream().collect(Collectors.toCollection(() -> new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v)))); }
  public static void kCollPure() { pures().stream().collect(Collectors.toCollection(TreeSet::new)); }
  public static void kCollList() { effs().stream().collect(Collectors.toCollection(ArrayList::new)); }
  // ===== a scalar parameter added to a list the caller sorts
  public static void qPushSort() { List<Eff> l = new ArrayList<>(); G2.push(l, new Eff(2)); G2.push(l, new Eff(1)); Collections.sort(l); }
  public static void qPushTwo() { List<Eff> l = new ArrayList<>(); G2.push2(l, new Eff(2)); G2.push2(l, new Eff(1)); Collections.sort(l); }
  public static void qTwoSort() { Collections.sort(G2.two(new Eff(2), new Eff(1))); }
  public static void qBagOrder() { Bag b = new Bag(); b.put(new Eff(2)); b.put(new Eff(1)); b.order(); }
  public static void kPushNoSort() { List<Eff> l = new ArrayList<>(); G2.push(l, new Eff(2)); G2.push(l, new Eff(1)); l.size(); }
  public static void kPushPure() { List<Pure> l = new ArrayList<>(); G2.push(l, new Pure(2)); G2.push(l, new Pure(1)); Collections.sort(l); }
  public static void kPushCmp() { List<Eff> l = new ArrayList<>(); G2.push(l, new Eff(2)); G2.push(l, new Eff(1)); l.sort(Comparator.comparingInt(x -> x.v)); }
  public static void kBagSize() { Bag b = new Bag(); b.put(new Eff(2)); b.put(new Eff(1)); b.size(); }
  // ===== HashMap tree bins (12 colliding self-Comparable keys)
  public static void qBinPut() { Map<HEff, Integer> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new HEff(i), i); }
  public static void qBinSetAdd() { Set<HEff> s = new HashSet<>(); for (int i = 0; i < 12; i++) s.add(new HEff(i)); }
  public static void qBinCopy() { List<HEff> l = new ArrayList<>(); for (int i = 0; i < 12; i++) l.add(new HEff(i)); new HashSet<>(l); }
  public static void qBinBase() { Map<HBase, Integer> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new HBase(i), i); }
  public static void kBinSub() { Map<HBase, Integer> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new HSub(i), i); }
  public static void kBinTable() { Map<HEff, Integer> m = new Hashtable<>(); for (int i = 0; i < 12; i++) m.put(new HEff(i), i); }
  public static void kBinPure() { Map<HPure, Integer> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new HPure(i), i); }
  public static void kBinFew() { Map<HEff, Integer> m = new HashMap<>(); m.put(new HEff(1), 1); m.put(new HEff(2), 2); }
  // ===== R1183: a comparator-built TreeSet/TreeMap
  public static void kCmpSetOps() { TreeSet<Eff> t = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v)); t.add(new Eff(1)); t.add(new Eff(2)); t.contains(new Eff(3)); }
  public static void kCmpMapOps() { TreeMap<Eff, String> t = new TreeMap<>(Comparator.comparingInt((Eff x) -> x.v)); t.put(new Eff(1), "a"); t.put(new Eff(2), "b"); t.get(new Eff(1)); t.containsKey(new Eff(4)); }
  static final TreeSet<Eff> CMPT = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v));
  public static void kCmpFieldAdd() { CMPT.add(new Eff(1)); CMPT.add(new Eff(2)); }
  public static void kCmpTadd() { TreeSet<Eff> t = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v)); G2.tadd(t, new Eff(1)); G2.tadd(t, new Eff(2)); }
  public static void qNatSetAdd() { TreeSet<Eff> t = new TreeSet<>(); t.add(new Eff(1)); }
  public static void qNatMapPut() { TreeMap<Eff, String> t = new TreeMap<>(); t.put(new Eff(1), "a"); }
  static final TreeSet<Eff> NATT = new TreeSet<>();
  public static void qNatFieldAdd() { NATT.add(new Eff(1)); }
  public static void qNatTadd() { TreeSet<Eff> t = new TreeSet<>(); G2.tadd(t, new Eff(1)); }
  public static void qSortedCopyAdd() { TreeSet<Eff> s = new TreeSet<>(); s.add(new Eff(3)); TreeSet<Eff> t = new TreeSet<>((SortedSet<Eff>) s); t.add(new Eff(1)); }
  // ===== natural-ordering COMPARATORS (each runs compareTo)
  public static void qRevTreeAdd() { TreeSet<Eff> t = new TreeSet<>(Collections.reverseOrder()); t.add(new Eff(1)); t.add(new Eff(2)); }
  public static void qNatOrdSort() { effs().sort(Comparator.naturalOrder()); }
  public static void qRevColSort() { Collections.sort(effs(), Collections.reverseOrder()); }
  public static void qRefCmpTree() { TreeSet<Eff> t = new TreeSet<>(Eff::compareTo); t.add(new Eff(1)); t.add(new Eff(2)); }
  public static void qStreamMaxNat() { effs().stream().max(Comparator.naturalOrder()); }
  public static void qNullsFirstSort() { effs().sort(Comparator.nullsFirst(Comparator.naturalOrder())); }
  public static void qNullCmpParam() { tc(null); }
  static void tc(Comparator<Eff> c) { TreeSet<Eff> t = new TreeSet<>(c); t.add(new Eff(1)); t.add(new Eff(2)); }
  static int flip = 1;
  private static TreeSet<Eff> MIX = flip > 0 ? new TreeSet<>() : new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v));
  public static void qMixFieldAdd() { MIX.add(new Eff(1)); MIX.add(new Eff(2)); }
  public static TreeSet<Eff> PUBT = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v));
  public static void kPubCmpField() { PUBT.add(new Eff(1)); PUBT.add(new Eff(2)); }
  public static void kRevOfCmp() { TreeSet<Eff> t = new TreeSet<>(Collections.reverseOrder(Comparator.comparingInt((Eff x) -> x.v))); t.add(new Eff(1)); t.add(new Eff(2)); }
  public static void kSortedCount() { effs().stream().sorted().count(); }
  static TreeSet<Eff> natMake() { return new TreeSet<>(); }
  public static void qLocalMixAdd() { TreeSet<Eff> t = flip > 0 ? natMake() : new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v)); t.add(new Eff(1)); t.add(new Eff(2)); }
  private static TreeSet<Eff> pfield = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v));
  static void setPfield(TreeSet<Eff> t) { pfield = t; }
  public static void qFieldFromParam() { setPfield(new TreeSet<>()); pfield.add(new Eff(1)); pfield.add(new Eff(2)); }
  private static TreeSet<Eff> afield = new TreeSet<>(Comparator.comparingInt((Eff x) -> x.v));
  @SuppressWarnings("unchecked") static void setAfield(Object[] a) { afield = (TreeSet<Eff>) a[0]; }
  public static void qFieldFromArr() { setAfield(new Object[] { new TreeSet<Eff>() }); afield.add(new Eff(1)); afield.add(new Eff(2)); }
}
""";

    static final List<String> RESOLVED = List.of("qDepSortedAdd", "qDepNatTree", "qValSort", "qValTree", "qValMax", "qValStream", "qValLocal", "qArrGen", "qArrObj", "qArrVar", "qMapSorted", "qMapLambda", "qCollTree", "qCollLam", "qCollPq", "qCollMap", "qPushSort", "qPushTwo", "qTwoSort", "qBagOrder", "qNatSetAdd", "qNatMapPut", "qNatFieldAdd", "qNatTadd", "qSortedCopyAdd", "qRevTreeAdd", "qNatOrdSort", "qRevColSort", "qRefCmpTree", "qStreamMaxNat", "qNullsFirstSort", "qNullCmpParam", "qMixFieldAdd", "qLocalMixAdd", "qFieldFromParam", "qFieldFromArr");
    static final List<String> DISCLOSED = List.of("qDepTreeAdd", "qDepMapPut", "qDepAddAll", "qBinPut", "qBinSetAdd", "qBinCopy", "qBinBase");
    static final List<String> NOTHING = List.of("kDepPureAdd", "kDepPlainAdd", "kValKeysPure", "kValNoSort", "kValPure", "kArrGenPure", "kArrGenLen", "kArrObjPure", "kMapPure", "kMapNoSort", "kCollHash", "kCollCmp", "kCollPure", "kCollList", "kPushNoSort", "kPushPure", "kBagSize", "kBinSub", "kBinTable", "kBinPure", "kCmpSetOps", "kCmpMapOps", "kCmpFieldAdd");
    static final List<String> NEVER_CHARGED = List.of("kDepHashDecl", "kDepHashSet", "kDepHashMap", "kBinFew");

    // ---- the over-charge controls, written first -------------------------------------------------------

    @Test
    void controlsCarryNothing() throws Exception {
        Map<String, Map<String, Object>> r = scan();
        for (String fn : NOTHING)
            assertTrue(inferred(r, "app.N." + fn).isEmpty(), fn + " runs no effectful compareTo (executed); got " + r.get("app.N." + fn));
        for (String fn : NEVER_CHARGED)
            assertTrue(!inferred(r, "app.N." + fn).contains("Fs"), fn + " is at most disclosed; got " + r.get("app.N." + fn));
    }

    // ---- the rows ---------------------------------------------------------------------------------------

    @Test
    void residualsAreResolved() throws Exception {
        Map<String, Map<String, Object>> r = scan();
        for (String fn : RESOLVED)
            assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " runs Eff.compareTo (executed); got " + r.get("app.N." + fn));
    }

    @Test
    @SuppressWarnings("unchecked")
    void outOfSightAndTreeBinsAreDisclosed() throws Exception {
        Map<String, Map<String, Object>> r = scan();
        for (String fn : DISCLOSED) {
            List<String> inf = inferred(r, "app.N." + fn);
            assertTrue(inf.contains("Unknown") && !inf.contains("Fs"), fn + ": disclosed, not charged; got " + r.get("app.N." + fn));
            List<String> why = (List<String>) r.get("app.N." + fn).get("unknownWhy");
            assertTrue(why.contains("dispatch:java.lang.Comparable.compareTo"), fn + " why " + why);
        }
    }

    // ---- harness: the app package scanned ALONE, so zd is a dependency out of sight ----------------------

    private static Map<String, Map<String, Object>> scan() throws Exception {
        Map<String, String> src = new LinkedHashMap<>();
        src.put("zd/Dep.java", DEP);
        src.put("app/N.java", APP);
        Path cls = TestCompiler.compile(src);
        Config saved = Candor.config;
        Path out = cls.getParent().resolve("r1184.json");
        try {
            Path only = cls.getParent().resolve("d_app");
            copyTree(cls.resolve("app"), only.resolve("app"));
            Candor.config = Config.empty();
            ReportWriter.writeJson(Candor.runScan(only), out.toString());
            return byFn(out.toString());
        } finally {
            Candor.config = saved;
            rm(cls.getParent());
        }
    }

    @SuppressWarnings("unchecked")
    static List<String> inferred(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get(fn);
        return row == null ? List.of() : (List<String>) row.get("inferred");
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
