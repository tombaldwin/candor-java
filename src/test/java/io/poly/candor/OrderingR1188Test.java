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
 * SOUNDNESS R1188 — {@code Comparator.comparing(f)} RUNS THE KEY'S {@code compareTo}; R1189 — A COMPARATOR OBJECT'S
 * {@code compare} AT THE ORDERING SITES OF THE CONTAINER IT ORDERS; R1191 — A HASHMAP TREE BIN OVER A CHAINED
 * DEPENDENCY'S KEY TYPE; R1190 — {@code sorted().count()}.
 *
 * <p>Every member was EXECUTED on JDK 21 (fixtures {@code javaagent-v064/fx} and {@code /cfx}): each {@code a*}/{@code b*}
 * and {@code d*} wrote its file through an effectful {@code compareTo}/{@code compare}, each {@code k*}/{@code e*} wrote
 * nothing. Against 0.40.11 / 441dd0e: the {@code a*} sort-site members were DISCLOSED only
 * ({@code Unknown[callback:java.util.Comparator.compare]}, an opaque comparator handed to a sort), and every member
 * whose comparator reaches a CONTAINER ({@code a03TreeAdd}, {@code a11PqCmp}, {@code b01..b18} but the four R1183 covered)
 * and every {@code d01..d05} tree bin read ABSENT under {@code deny Fs Unknown}. All are RESOLVED here (an edge to the
 * key's compareTo / the comparator's compare) except the tree bins, which are DISCLOSED as R1184's are.
 */
class OrderingR1188Test {

    static final String TYPES = """
package app;
import java.util.*;
final class Out { static String cur = "";
  static void w(String what) { try { java.nio.file.Files.writeString(java.nio.file.Path.of("/nonexistent-r1188", what + "." + cur), "x"); } catch (Exception e) { throw new RuntimeException(e); } } }
final class Eff implements Comparable<Eff> { final int v; Eff(int v) { this.v = v; }
  public int compareTo(Eff o) { Out.w("Eff.compareTo"); return Integer.compare(v, o.v); } }
final class Pure implements Comparable<Pure> { final int v; Pure(int v) { this.v = v; }
  public int compareTo(Pure o) { return Integer.compare(v, o.v); } }
final class Hold { final Eff k; final String name; final int n; Hold(int v) { k = new Eff(v); name = "same"; n = v; }
  Eff key() { return k; } String name() { return name; } int n() { return n; } Pure pk() { return new Pure(n); } }
/** runs Eff.compareTo (unboundid's ReverseComparator shape) */
final class RevCmp implements Comparator<Eff> { public int compare(Eff a, Eff b) { return b.compareTo(a); } }
/** its own effect, over pure elements */
final class LogCmp implements Comparator<Pure> { public int compare(Pure a, Pure b) { Out.w("LogCmp.compare"); return Integer.compare(a.v, b.v); } }
final class PureCmp implements Comparator<Pure> { public int compare(Pure a, Pure b) { return Integer.compare(a.v, b.v); } }
final class Keeper { final Comparator<Pure> c; Keeper(Comparator<Pure> c) { this.c = c; } TreeSet<Pure> set() { return new TreeSet<>(c); } }
""";

    static final String APP = """
package app;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;
public class N {
  static List<Hold> holds() { List<Hold> l = new ArrayList<>(); l.add(new Hold(2)); l.add(new Hold(1)); l.add(new Hold(3)); return l; }
  static List<Eff> effs() { List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); return l; }
  static List<Pure> pures() { List<Pure> l = new ArrayList<>(); l.add(new Pure(2)); l.add(new Pure(1)); return l; }
  static final Comparator<Hold> BYKEY = Comparator.comparing(Hold::key);
  static final Comparator<Eff> REVF = new RevCmp();
  static final TreeSet<Pure> LOGT = new TreeSet<>(new LogCmp());
  static Comparator<Hold> byKey() { return Comparator.comparing(Hold::key); }
  static void sortBy(List<Hold> l, Comparator<Hold> c) { l.sort(c); }
  static void fillP(Comparator<Eff> c) { TreeSet<Eff> t = new TreeSet<>(c); t.add(new Eff(1)); t.add(new Eff(2)); }
  static void fillQ(Comparator<Pure> c) { TreeSet<Pure> t = new TreeSet<>(c); t.add(new Pure(1)); t.add(new Pure(2)); }
  // ---- R1188: Comparator.comparing(f) runs the KEY's compareTo
  public static void a01SortRef() { holds().sort(Comparator.comparing(Hold::key)); }
  public static void a02SortLam() { Collections.sort(holds(), Comparator.comparing(h -> h.k)); }
  public static void a03TreeAdd() { TreeSet<Hold> t = new TreeSet<>(Comparator.comparing(Hold::key)); t.add(new Hold(1)); t.add(new Hold(2)); }
  public static void a04Reversed() { holds().sort(Comparator.comparing(Hold::key).reversed()); }
  public static void a05ThenFn() { holds().sort(Comparator.comparing(Hold::name).thenComparing(Hold::key)); }
  public static void a06NatCmp() { holds().sort(Comparator.comparing(Hold::key, Comparator.naturalOrder())); }
  public static void a07StreamCmp() { holds().stream().sorted(Comparator.comparing(Hold::key)).collect(Collectors.toList()); }
  public static void a08MaxCmp() { Collections.max(holds(), Comparator.comparing(Hold::key)); }
  public static void a09ArrCmp() { Hold[] a = { new Hold(2), new Hold(1) }; Arrays.sort(a, Comparator.comparing(Hold::key)); }
  public static void a10FieldCmp() { holds().sort(BYKEY); }
  public static void a11PqCmp() { PriorityQueue<Hold> q = new PriorityQueue<>(Comparator.comparing(Hold::key)); q.add(new Hold(2)); q.add(new Hold(1)); }
  public static void a12EntryKey() { Map<Eff, String> m = new HashMap<>(); m.put(new Eff(2), "a"); m.put(new Eff(1), "b"); List<Map.Entry<Eff, String>> e = new ArrayList<>(m.entrySet()); e.sort(Map.Entry.comparingByKey()); }
  public static void a13ThenCmp() { holds().sort(Comparator.comparing(Hold::name).thenComparing(Comparator.comparing(Hold::key))); }
  public static void a14LocalCmp() { Comparator<Hold> c = Comparator.comparing(Hold::key); holds().sort(c); }
  public static void a15PassCmp() { sortBy(holds(), Comparator.comparing(Hold::key)); }
  public static void a16Factory() { holds().sort(byKey()); }
  public static void a17ThenRev() { holds().sort(Comparator.comparing(Hold::name).thenComparing(Hold::key, Comparator.reverseOrder())); }
  public static void a18NullsCmp() { holds().sort(Comparator.nullsFirst(Comparator.comparing(Hold::key))); }
  public static void a19CmpObj() { holds().sort(Comparator.comparing(Hold::key, new RevCmp())); }
  public static void a20EntryVal() { Map<String, Eff> m = new HashMap<>(); m.put("a", new Eff(2)); m.put("b", new Eff(1)); List<Map.Entry<String, Eff>> e = new ArrayList<>(m.entrySet()); e.sort(Map.Entry.comparingByValue()); }
  // ---- R1189: a comparator OBJECT's compare, at the ordering sites of the container it orders
  public static void b01NewCmpAll() { new TreeSet<>(new RevCmp()).addAll(effs()); }
  public static void b02NewCmpAdd() { TreeSet<Eff> t = new TreeSet<>(new RevCmp()); t.add(new Eff(1)); t.add(new Eff(2)); }
  public static void b03NewCmpPut() { TreeMap<Eff, String> t = new TreeMap<>(new RevCmp()); t.put(new Eff(1), "a"); t.put(new Eff(2), "b"); }
  public static void b04NewCmpPq() { PriorityQueue<Eff> q = new PriorityQueue<>(new RevCmp()); q.add(new Eff(1)); q.add(new Eff(2)); }
  public static void b05FieldObj() { TreeSet<Eff> t = new TreeSet<>(REVF); t.add(new Eff(1)); t.add(new Eff(2)); }
  public static void b06ParamObj() { fillP(new RevCmp()); }
  public static void b07LogTree() { TreeSet<Pure> t = new TreeSet<>(new LogCmp()); t.add(new Pure(1)); t.add(new Pure(2)); }
  public static void b08LogField() { LOGT.add(new Pure(1)); LOGT.add(new Pure(2)); }
  public static void b09SkipList() { java.util.concurrent.ConcurrentSkipListSet<Pure> s = new java.util.concurrent.ConcurrentSkipListSet<>(new LogCmp()); s.add(new Pure(1)); s.add(new Pure(2)); }
  public static void b10SortObj() { Collections.sort(pures(), new LogCmp()); }
  public static void b11LogParam() { fillQ(new LogCmp()); }
  public static void b12Keeper() { TreeSet<Pure> t = new Keeper(new LogCmp()).set(); t.add(new Pure(1)); t.add(new Pure(2)); }
  public static void b13NullsObj() { TreeSet<Pure> t = new TreeSet<>(Comparator.nullsFirst(new LogCmp())); t.add(new Pure(1)); t.add(new Pure(2)); }
  public static void b14LogMapCopy() { TreeMap<Pure, String> t = new TreeMap<>(new LogCmp()); Map<Pure, String> h = new HashMap<>(); h.put(new Pure(1), "a"); h.put(new Pure(2), "b"); t.putAll(h); }
  public static void b15OneAdd() { TreeSet<Pure> t = new TreeSet<>(new LogCmp()); t.add(new Pure(1)); }
  static void put2(TreeSet<Pure> t) { t.add(new Pure(1)); t.add(new Pure(2)); }
  static int keep(Comparator<Pure> c) { return c == null ? 0 : 1; }
  public static void b16CtrParam() { put2(new TreeSet<>(new LogCmp())); }
  public static void b17CmpLocalTree() { Comparator<Pure> c = new LogCmp(); TreeSet<Pure> t = new TreeSet<>(c); t.add(new Pure(1)); t.add(new Pure(2)); }
  public static void b18RetTree() { TreeSet<Pure> t = mkLog(); t.add(new Pure(1)); t.add(new Pure(2)); }
  static TreeSet<Pure> mkLog() { return new TreeSet<>(new LogCmp()); }
  // ---- R1190: sorted() on a SIZED stream ending in count()
  public static void c01CountSized() { effs().stream().sorted().count(); }
  public static void c02CountFilter() { effs().stream().filter(x -> true).sorted().count(); }
  public static void c03CountMap() { effs().stream().map(x -> x).sorted().count(); }
  public static void c04CountLimit() { effs().stream().sorted().limit(5).count(); }
  public static void c05CountSkip() { effs().stream().skip(0).sorted().count(); }
  public static void c06SortedList() { effs().stream().sorted().collect(Collectors.toList()); }
  public static void c07CountOf() { Stream.of(new Eff(2), new Eff(1)).sorted().count(); }
  public static void c08CountPeek() { effs().stream().sorted().peek(x -> {}).count(); }
  public static void c09CountDistinct() { effs().stream().distinct().sorted().count(); }
  public static void c10CountCmp() { holds().stream().sorted(Comparator.comparing(Hold::key)).count(); }
  public static void c11CountCq() { new java.util.concurrent.ConcurrentLinkedQueue<>(effs()).stream().sorted().count(); }
  public static void c12CountArr() { Arrays.stream(new Eff[] { new Eff(2), new Eff(1) }).sorted().count(); }
  public static void c13CountLocal() { Stream<Eff> s = effs().stream().sorted(); s.count(); }
  public static void c14CountPar() { effs().parallelStream().sorted().count(); }
  public static void c15CountUnsized() { Stream.iterate(new Eff(2), x -> x.v > 0, x -> new Eff(x.v - 1)).sorted().count(); }
  // ---- controls
  public static void k01PureKey() { holds().sort(Comparator.comparing(Hold::name)); }
  public static void k02OwnCmp() { holds().sort(Comparator.comparing(Hold::key, (x, y) -> 0)); }
  public static void k03CmpInt() { holds().sort(Comparator.comparingInt(Hold::n)); }
  public static void k04Unused() { Comparator.comparing(Hold::key); }
  public static void k05PureKeyT() { holds().sort(Comparator.comparing(Hold::pk)); }
  public static void k06PureCmpObj() { TreeSet<Pure> t = new TreeSet<>(new PureCmp()); t.add(new Pure(1)); t.add(new Pure(2)); }
  public static void k07NoUse() { new TreeSet<>(new LogCmp()); }
  public static void k08OneHold() { List<Hold> l = new ArrayList<>(); l.add(new Hold(1)); l.sort(Comparator.comparing(Hold::key)); }
  public static void k09ThenFirst() { List<Hold> l = new ArrayList<>(); l.add(new Hold(1)); l.add(new Hold(2)); l.sort(Comparator.comparing(Hold::n).thenComparing(Hold::key)); }
  public static void k10Size() { new TreeSet<>(new LogCmp()).size(); }
  public static void k11NatParam() { put2(new TreeSet<>()); }
  public static void k12IntViaParam() { sortBy(holds(), Comparator.comparingInt(Hold::n)); }
  public static void k13KeepOnly() { keep(new LogCmp()); }
  public static void k14PureViaFill() { fillQ(new PureCmp()); }
}
""";

    static final String LIB = """
package zk;
import java.util.*;
public final class Lib { public static String cur = "";
  public static void w(String what) { try { java.nio.file.Files.writeString(java.nio.file.Path.of("/nonexistent-r1191", what + "." + cur), "x"); } catch (Exception e) { throw new RuntimeException(e); } }
  private Lib() {} }
""";
    static final String L_LKey = """
package zk;
public class LKey implements Comparable<LKey> { public final int v; public LKey(int v) { this.v = v; }
  @Override public int hashCode() { return 7; }
  @Override public boolean equals(Object o) { return o instanceof LKey k && k.v == v; }
  public int compareTo(LKey o) { Lib.w("LKey.compareTo"); return Integer.compare(v, o.v); } }
""";
    static final String L_LSub = """
package zk;
public final class LSub extends LKey { public LSub(int v) { super(v); } }
""";
    static final String L_LOther = """
package zk;
public final class LOther implements Comparable<LKey> { public final int v; public LOther(int v) { this.v = v; }
  @Override public int hashCode() { return 7; }
  @Override public boolean equals(Object o) { return o instanceof LOther k && k.v == v; }
  public int compareTo(LKey o) { Lib.w("LOther.compareTo"); return 0; } }
""";
    static final String L_LRev = """
package zk;
public final class LRev implements java.util.Comparator<LKey> { public int compare(LKey a, LKey b) { Lib.w("LRev.compare"); return Integer.compare(b.v, a.v); } }
""";
    static final String L_LHold = """
package zk;
public final class LHold { final LKey k; public LHold(int v) { k = new LKey(v); } public LKey key() { return k; } public String name() { return "same"; } }
""";

    static final String CONSUMER = """
package app2;
import java.util.*;
import zk.*;
public class B {
  static List<LHold> lholds() { List<LHold> l = new ArrayList<>(); l.add(new LHold(2)); l.add(new LHold(1)); return l; }
  static List<LKey> lkeys() { List<LKey> l = new ArrayList<>(); for (int i = 0; i < 12; i++) l.add(new LKey(i)); return l; }
  // ---- R1191: HashMap tree bins over a chained dependency's self-Comparable key
  public static void d01BinPut() { HashMap<LKey, String> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new LKey(i), "x"); }
  public static void d02BinSet() { HashSet<LKey> s = new HashSet<>(); for (int i = 0; i < 12; i++) s.add(new LKey(i)); }
  public static void d03BinDecl() { Map<LKey, String> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new LKey(i), "x"); }
  public static void d04BinCopy() { new HashSet<>(lkeys()); }
  public static void d05BinGet() { Map<LKey, String> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new LKey(i), "x"); m.get(new LKey(99)); }
  // ---- R1188 / R1189 across the boundary
  public static void d06CmpLib() { lholds().sort(Comparator.comparing(LHold::key)); }
  public static void d07CmpTreeLib() { TreeSet<LHold> t = new TreeSet<>(Comparator.comparing(LHold::key)); t.add(new LHold(1)); t.add(new LHold(2)); }
  public static void d08DepCmpObj() { TreeSet<LKey> t = new TreeSet<>(new LRev()); t.add(new LKey(1)); t.add(new LKey(2)); }
  // ---- controls
  public static void e01BinSub() { HashMap<LSub, String> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new LSub(i), "x"); }
  public static void e02BinTable() { Hashtable<LKey, String> m = new Hashtable<>(); for (int i = 0; i < 12; i++) m.put(new LKey(i), "x"); }
  public static void e03BinFew() { HashMap<LKey, String> m = new HashMap<>(); m.put(new LKey(1), "x"); m.put(new LKey(2), "y"); }
  public static void e04OtherCmp() { HashMap<LOther, String> m = new HashMap<>(); for (int i = 0; i < 12; i++) m.put(new LOther(i), "x"); }
  public static void e05PureKey() { lholds().sort(Comparator.comparing(LHold::name)); }
}
""";

    /** Comparator facts RESOLVED at the site that runs them (each executed). */
    static final List<String> RESOLVED = List.of("a01SortRef", "a02SortLam", "a03TreeAdd", "a04Reversed", "a05ThenFn",
            "a06NatCmp", "a07StreamCmp", "a08MaxCmp", "a09ArrCmp", "a10FieldCmp", "a11PqCmp", "a13ThenCmp", "a14LocalCmp",
            "a15PassCmp", "a16Factory", "a17ThenRev", "a18NullsCmp", "a19CmpObj", "b01NewCmpAll", "b04NewCmpPq",
            "b07LogTree", "b08LogField", "b09SkipList", "b11LogParam", "b12Keeper", "b13NullsObj", "b14LogMapCopy",
            "b15OneAdd", "b16CtrParam", "b17CmpLocalTree", "b18RetTree",
            // covered before this row (R1183's element charge, Candor#namedFunctionalToHof): kept
            "b02NewCmpAdd", "b03NewCmpPut", "b05FieldObj", "b06ParamObj", "b10SortObj");
    /** {@code Map.Entry.comparingByKey/Value()}: the key is the ENTRY's, not on the stack — still disclosed only. */
    static final List<String> DISCLOSED_ONLY = List.of("a12EntryKey", "a20EntryVal");
    /** Nothing runs (executed). The comparing-family controls keep the opaque-comparator disclosure they had. */
    static final List<String> NO_FS = List.of("k01PureKey", "k02OwnCmp", "k03CmpInt", "k04Unused", "k05PureKeyT",
            "k06PureCmpObj", "k07NoUse", "k10Size", "k11NatParam", "k12IntViaParam", "k13KeepOnly", "k14PureViaFill");
    /** Stated over-charges, executed real=0: a one-element sort, a first comparator that decides. The engine cannot
     *  see the data; the natural-ordering charges R1179 makes already carry the same price. */
    static final List<String> STATED = List.of("k08OneHold", "k09ThenFirst");

    static final List<String> BIN_DISCLOSED = List.of("d01BinPut", "d02BinSet", "d03BinDecl", "d04BinCopy", "d05BinGet");
    static final List<String> CHAIN_RESOLVED = List.of("d06CmpLib", "d07CmpTreeLib", "d08DepCmpObj");

    // ---- the over-charge controls, written first -------------------------------------------------------

    @Test
    void controlsGainNoEffect() throws Exception {
        Map<String, Map<String, Object>> r = scanOne();
        for (String fn : NO_FS)
            assertTrue(!inferred(r, "app.N." + fn).contains("Fs"), fn + " runs nothing effectful (executed); got " + r.get("app.N." + fn));
        // a comparator PARAMETER is summarised per call, never merged: the callee is not charged a caller's comparator
        assertTrue(!inferred(r, "app.N.sortBy").contains("Fs"), "got " + r.get("app.N.sortBy"));
        assertTrue(!inferred(r, "app.N.fillQ").contains("Fs"), "got " + r.get("app.N.fillQ"));
        assertTrue(!inferred(r, "app.N.put2").contains("Fs"), "got " + r.get("app.N.put2"));
    }

    @Test
    void chainedControlsAreAtMostDisclosed() throws Exception {
        Map<String, Map<String, Object>> r = scanChained();
        // a subclass never treeifies by compareTo, nor does a Hashtable (executed): nothing
        for (String fn : List.of("e01BinSub", "e02BinTable", "e05PureKey"))
            assertTrue(!inferred(r, "app2.B." + fn).contains("Fs"), fn + "; got " + r.get("app2.B." + fn));
        assertTrue(inferred(r, "app2.B.e01BinSub").isEmpty() && inferred(r, "app2.B.e02BinTable").isEmpty(),
                "got " + r.get("app2.B.e01BinSub") + " / " + r.get("app2.B.e02BinTable"));
        // two keys never collide into a tree bin, and Comparable<LKey> on LOther never compares: the price of a
        // disclosure that cannot see the hash distribution or the type argument (the sidecar has none)
        for (String fn : List.of("e03BinFew", "e04OtherCmp"))
            assertTrue(inferred(r, "app2.B." + fn).equals(List.of("Unknown")), fn + "; got " + r.get("app2.B." + fn));
    }

    // ---- the rows ---------------------------------------------------------------------------------------

    @Test
    void aComparatorRunsWhereItRuns() throws Exception {
        Map<String, Map<String, Object>> r = scanOne();
        for (String fn : RESOLVED)
            assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " runs an effectful compareTo/compare (executed); got " + r.get("app.N." + fn));
        for (String fn : STATED)
            assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " (stated over-charge); got " + r.get("app.N." + fn));
        for (String fn : DISCLOSED_ONLY)
            assertTrue(inferred(r, "app.N." + fn).contains("Unknown"), fn + "; got " + r.get("app.N." + fn));
    }

    /** SOUNDNESS R1190 — {@code sorted()} on a SIZED sequential stream ending in {@code count()} compares NOTHING on
     *  JDK 9+ ({@code count()} short-circuits: executed on 11, 17, 21, 25), and NOT with a {@code limit}/{@code skip} stage
     *  on 17+ — but it DOES on JDK 8 (executed, eclipse-temurin:8: every member compared), and on JDK 11 with
     *  {@code sorted().limit(n).count()}. The charge is therefore real on a supported runtime and is KEPT; this pins
     *  it so a later "precision" change has to say which JDK it is giving up. Corpus reach of the shape: 0 sites. */
    @Test
    void sortedCountIsKeptForJdk8() throws Exception {
        Map<String, Map<String, Object>> r = scanOne();
        for (String fn : List.of("c01CountSized", "c03CountMap", "c04CountLimit", "c05CountSkip", "c07CountOf",
                "c08CountPeek", "c12CountArr", "c13CountLocal"))
            assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " compares on JDK 8 (executed); got " + r.get("app.N." + fn));
        // the ones that compare on every JDK
        for (String fn : List.of("c02CountFilter", "c06SortedList", "c09CountDistinct", "c11CountCq", "c14CountPar"))
            assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " compares on JDK 21 (executed); got " + r.get("app.N." + fn));
    }

    @Test
    void aChainedKeyIsResolvedAndItsTreeBinDisclosed() throws Exception {
        Map<String, Map<String, Object>> r = scanChained();
        for (String fn : CHAIN_RESOLVED)
            assertTrue(inferred(r, "app2.B." + fn).contains("Fs"), fn + " (executed); got " + r.get("app2.B." + fn));
        for (String fn : BIN_DISCLOSED) {
            List<String> inf = inferred(r, "app2.B." + fn);
            assertTrue(inf.contains("Unknown") && !inf.contains("Fs"), fn + ": disclosed, not charged; got " + r.get("app2.B." + fn));
            @SuppressWarnings("unchecked")
            List<String> why = (List<String>) r.get("app2.B." + fn).get("unknownWhy");
            assertTrue(why.contains("dispatch:java.lang.Comparable.compareTo"), fn + " why " + why);
        }
    }

    // ---- harness ------------------------------------------------------------------------------------------

    private static Map<String, Map<String, Object>> scanOne() throws Exception {
        Map<String, String> src = new LinkedHashMap<>();
        src.put("app/T.java", TYPES);
        src.put("app/N.java", APP);
        Path cls = TestCompiler.compile(src);
        Config saved = Candor.config;
        Path out = cls.getParent().resolve("r1188.json");
        try {
            Candor.config = Config.empty();
            ReportWriter.writeJson(Candor.runScan(cls), out.toString());
            return byFn(out.toString());
        } finally {
            Candor.config = saved;
            rm(cls.getParent());
        }
    }

    /** zk scanned first; app2 scanned ALONE, chained on zk's report (and its hierarchy sidecar). */
    private static Map<String, Map<String, Object>> scanChained() throws Exception {
        Map<String, String> src = new LinkedHashMap<>();
        src.put("zk/Lib.java", LIB);
        src.put("zk/LKey.java", L_LKey);
        src.put("zk/LSub.java", L_LSub);
        src.put("zk/LOther.java", L_LOther);
        src.put("zk/LRev.java", L_LRev);
        src.put("zk/LHold.java", L_LHold);
        src.put("app2/B.java", CONSUMER);
        Path cls = TestCompiler.compile(src);
        Path base = cls.getParent();
        Config saved = Candor.config;
        try {
            copyTree(cls.resolve("zk"), base.resolve("d_zk").resolve("zk"));
            copyTree(cls.resolve("app2"), base.resolve("d_app2").resolve("app2"));
            Candor.config = Config.empty();
            Path lib = base.resolve("zk.json");
            ReportWriter.writeReport(Candor.runScan(base.resolve("d_zk")), lib.toString(), null);   // + the hierarchy sidecar
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + lib + "\n");
            Candor.config = Config.forTarget(base.resolve("d_app2"));
            Path out = base.resolve("app2.json");
            ReportWriter.writeJson(Candor.runScan(base.resolve("d_app2")), out.toString());
            return byFn(out.toString());
        } finally {
            Candor.config = saved;
            rm(base);
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
