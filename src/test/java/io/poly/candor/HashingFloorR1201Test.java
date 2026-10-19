package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1201 — THE OBJECT FLOOR for {@code equals}/{@code hashCode}: a value known only as {@code Object} (an
 * erased read, a factory declared {@code Object}, an {@code Object} field), hashed or compared by the JDK, or a direct
 * {@code equals}/{@code hashCode} past the CHA fan-out bound. EXECUTED on JDK 21 (fixtures {@code javaagent-v071/f10}
 * package {@code vz} and {@code f12} package {@code vw}): every positive ran {@code EqEff.equals/hashCode} and wrote
 * the file; every control wrote nothing. On 0.40.12 every positive here was absent under {@code deny Fs Unknown <fn>}.
 * Now each is DISCLOSED ({@code dispatch:java.lang.Object.hashCode|equals}, on the body that hashes or inherited along the
 * call edge) where some override in the scan carries an effect the caller lacks. An {@code Object} whose real type is
 * pure ({@code kh01ObjPure}, {@code kh02Str}, {@code kh06MapStr}, {@code kd01DirectStr}, {@code kd03HelperPure})
 * is disclosed too: nothing here can tell it from an effectful one. It is never CHARGED.
 */
class HashingFloorR1201Test {

    static final String SINK = "package app;\nfinal class Sink { static void w() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1201/x\"), \"x\"); } catch (Exception e) {} } }\n";
    static final String TYPES = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "final class EqEff { final int v; EqEff(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { Sink.w(); return o instanceof EqEff e && e.v == v; }\n"
            + "  @Override public int hashCode() { Sink.w(); return v; } }\n"
            + "final class EqPure { final int v; EqPure(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { return o instanceof EqPure e && e.v == v; }\n"
            + "  @Override public int hashCode() { return v; } }\n"
            + "interface Keyed { int v(); }\n"
            + "final class KeyEff implements Keyed { final int v; KeyEff(int v) { this.v = v; } public int v() { return v; }\n"
            + "  @Override public boolean equals(Object o) { Sink.w(); return o instanceof KeyEff e && e.v == v; }\n"
            + "  @Override public int hashCode() { Sink.w(); return v; } }\n"
            + "final class HBag { final List<Object> items = new ArrayList<>(); void put(Object o) { items.add(o); } int hash() { return items.hashCode(); } }\n"
            + "final class Mk2 { static HBag id(HBag b) { return b; } static Object eq(int v) { return new EqEff(v); } static Object pure(int v) { return new EqPure(v); }\n"
            + "  static Keyed key(int v) { return new KeyEff(v); } static List<Object> idList(List<Object> l) { return l; }\n"
            + "  static Object str() { return \"s\"; } }\n"
            + "final class Holder { Object o; }\n"
            + "final class G { static <T> int hashAll(List<T> l) { return new HashSet<>(l).size(); }\n"
            + "  static <T> boolean has(Collection<T> c, T x) { return c.contains(x); } }\n";
    static final String MAIN = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "@SuppressWarnings({\"unchecked\", \"rawtypes\"})\n"
            + "public class N {\n"
            + "  // ---- the three filed shapes\n"
            + "  public static void h01IdHash() { HBag b = new HBag(); Mk2.id(b).put(new EqEff(1)); b.hash(); }\n"
            + "  public static void h02ObjHash() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); l.hashCode(); }\n"
            + "  public static void h03SetObj() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); l.add(Mk2.eq(2)); new HashSet<>(l); }\n"
            + "  // ---- the population: JDK sites that run an element's / argument's hashCode or equals, element known only as Object\n"
            + "  public static void h04MapPut() { Map<Object, Integer> m = new HashMap<>(); m.put(Mk2.eq(1), 1); }\n"
            + "  public static void h05SetAdd() { Set<Object> s = new HashSet<>(); s.add(Mk2.eq(1)); }\n"
            + "  public static void h06ObjectsHash() { Objects.hash(Mk2.eq(1)); }\n"
            + "  public static void h07ObjectsEquals() { Objects.equals(Mk2.eq(1), Mk2.eq(2)); }\n"
            + "  public static void h08Contains() { List<Object> l = new ArrayList<>(); l.add(Mk2.pure(1)); l.contains(Mk2.eq(1)); }\n"
            + "  public static void h09IndexOf() { List<Object> l = new ArrayList<>(); l.add(Mk2.pure(1)); l.indexOf(Mk2.eq(1)); }\n"
            + "  public static void h10Direct() { Object o = Mk2.eq(1); o.hashCode(); }\n"
            + "  public static void h11MapGet() { Map<Object, Integer> m = new HashMap<>(); m.put(\"a\", 1); m.get(Mk2.eq(1)); }\n"
            + "  public static void h12ArraysHash() { Object[] a = { Mk2.eq(1) }; Arrays.hashCode(a); }\n"
            + "  public static void h13ListEquals() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); List<Object> k = new ArrayList<>(); k.add(Mk2.eq(1)); l.equals(k); }\n"
            + "  public static void h14Iface() { List<Keyed> l = new ArrayList<>(); l.add(Mk2.key(1)); l.hashCode(); }\n"
            + "  public static void h15IdList() { List<Object> l = new ArrayList<>(); Mk2.idList(l).add(new EqEff(1)); l.hashCode(); }\n"
            + "  public static void h16Field() { Holder h = new Holder(); h.o = new EqEff(1); Set<Object> s = new HashSet<>(); s.add(h.o); }\n"
            + "  public static void h17Generic() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); G.hashAll(l); }\n"
            + "  public static void h18GenericExact() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); G.hashAll(l); }\n"
            + "  public static void h19Remove() { List<Object> l = new ArrayList<>(); l.add(Mk2.pure(1)); l.remove(Mk2.eq(1)); }\n"
            + "  public static void h20DirectEq() { Object o = Mk2.eq(1); o.equals(\"x\"); }\n"
            + "  public static void h21SetOfObj() { Set.of(Mk2.eq(1), Mk2.eq(2)); }\n"
            + "  public static void h22Distinct() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); l.add(Mk2.eq(2)); l.stream().distinct().count(); }\n"
            + "  // ---- controls (real = 0)\n"
            + "  public static void kh01ObjPure() { List<Object> l = new ArrayList<>(); l.add(Mk2.pure(1)); l.hashCode(); }\n"
            + "  public static void kh02Str() { List<Object> l = new ArrayList<>(); l.add(Mk2.str()); l.hashCode(); }\n"
            + "  public static void kh03StrList() { List<String> l = new ArrayList<>(); l.add(\"a\"); new HashSet<>(l); }\n"
            + "  public static void kh04ExactPure() { Set<Object> s = new HashSet<>(); s.add(new EqPure(1)); }\n"
            + "  public static void kh05NoHash() { List<Object> l = new ArrayList<>(); l.add(Mk2.eq(1)); l.size(); }\n"
            + "  public static void kh06MapStr() { Map<Object, Integer> m = new HashMap<>(); m.put(Mk2.str(), 1); }\n"
            + "  public static void kh07DirectPure() { Object o = Mk2.pure(1); o.hashCode(); }\n"
            + "}\n";
    static final String WSINK = "package wide;\nfinal class Sink { static void w() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1201/x\"), \"x\"); } catch (Exception e) {} } }\n";
    static final String WTYPES = ""
            + "package wide;\n"
            + "import java.util.*;\n"
            + "final class EqEff { final int v; EqEff(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { Sink.w(); return o instanceof EqEff e && e.v == v; }\n"
            + "  @Override public int hashCode() { Sink.w(); return v; } }\n"
            + "final class P0 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 0; } }\n"
            + "final class P1 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 1; } }\n"
            + "final class P2 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 2; } }\n"
            + "final class P3 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 3; } }\n"
            + "final class P4 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 4; } }\n"
            + "final class P5 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 5; } }\n"
            + "final class P6 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 6; } }\n"
            + "final class P7 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 7; } }\n"
            + "final class P8 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 8; } }\n"
            + "final class P9 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 9; } }\n"
            + "final class P10 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 10; } }\n"
            + "final class P11 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 11; } }\n"
            + "final class P12 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 12; } }\n"
            + "final class P13 { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 13; } }\n"
            + "final class Mk { static Object eq(int v) { return new EqEff(v); } static Object str() { return \"s\"; } static Object p() { return new P0(); } }\n"
            + "final class G { static void put(Set<Object> s, Object o) { s.add(o); } static int hk(Object o) { return o.hashCode(); } }\n";
    static final String WMAIN = ""
            + "package wide;\n"
            + "import java.util.*;\n"
            + "/** Fifteen equals/hashCode overrides in the tree: past the CHA fan-out bound (12). */\n"
            + "public class N {\n"
            + "  public static void d01Direct() { Object o = Mk.eq(1); o.hashCode(); }\n"
            + "  public static void d02DirectEq() { Object o = Mk.eq(1); o.equals(\"x\"); }\n"
            + "  public static void d03Helper() { Set<Object> s = new HashSet<>(); G.put(s, Mk.eq(1)); }\n"
            + "  public static void d04HelperExact() { Set<Object> s = new HashSet<>(); G.put(s, new EqEff(1)); }\n"
            + "  public static void d05HkObj() { G.hk(Mk.eq(1)); }\n"
            + "  public static void kd01DirectStr() { Object o = Mk.str(); o.hashCode(); }\n"
            + "  public static void kd02Str() { String s = \"a\"; s.hashCode(); }\n"
            + "  public static void kd03HelperPure() { Set<Object> s = new HashSet<>(); G.put(s, Mk.p()); }\n"
            + "}\n";

    static final List<String> POSITIVES = List.of("h01IdHash", "h02ObjHash", "h03SetObj", "h04MapPut", "h05SetAdd", "h06ObjectsHash", "h07ObjectsEquals", "h08Contains", "h09IndexOf", "h11MapGet", "h12ArraysHash", "h13ListEquals", "h16Field", "h17Generic", "h19Remove", "h21SetOfObj", "h22Distinct");
    /** RESOLVED since R1205 (ExactTypes): the {@code Object} a factory returns IS an {@code EqEff}, so the helper's
     *  hashing (d03, d05) and the direct dispatch (d01, d02) are CHARGED, past the bound as well as in it. Executed: each
     *  writes the file. */
    static final List<String> WIDE_RESOLVED = List.of("d01Direct", "d02DirectEq", "d03Helper", "d05HkObj");
    /** …and the same producers name a PURE class: a String, a {@code P0}. Executed clean; nothing is charged or hedged. */
    static final List<String> WIDE_PURE = List.of("kd01DirectStr", "kd03HelperPure");
    /** Executed clean, and bounded: a String constant, an exact pure element, a list never hashed, a String receiver. */
    static final List<String> CLEAN = List.of("kh03StrList", "kh04ExactPure", "kh05NoHash");
    /** Executed clean, but the value is known only as Object: disclosed, never charged. */
    static final List<String> OVER = List.of("kh01ObjPure", "kh02Str", "kh06MapStr");

    @Test
    void anObjectHashedIsDisclosedNeverSilent() throws Exception {
        Map<String, Map<String, Object>> r = scan("app", SINK, TYPES, MAIN);
        for (String fn : POSITIVES) {
            List<String> inf = HashingR1203Test.inferred(r, "app.N." + fn);
            assertTrue(inf.contains("Fs") || inf.contains("Unknown"), fn + " runs EqEff (executed); got " + r.get("app.N." + fn));
        }
        for (String fn : CLEAN) assertTrue(HashingR1203Test.inferred(r, "app.N." + fn).isEmpty(), fn + " got " + r.get("app.N." + fn));
        for (String fn : OVER) assertTrue(HashingR1203Test.inferred(r, "app.N." + fn).equals(List.of("Unknown")), fn + " got " + r.get("app.N." + fn));
        // the reason is the true one, on the body that hashes
        assertTrue(String.valueOf(r.get("app.N.h04MapPut").get("unknownWhy")).contains("dispatch:java.lang.Object.hashCode"), "got " + r.get("app.N.h04MapPut"));
        assertTrue(String.valueOf(r.get("app.HBag.hash").get("unknownWhy")).contains("dispatch:java.lang.Object.hashCode"), "got " + r.get("app.HBag.hash"));
    }

    @Test
    void anObjectHandedToAHashingHelperIsDisclosed() throws Exception {
        Map<String, Map<String, Object>> r = scan("wide", WSINK, WTYPES, WMAIN);
        for (String fn : WIDE_RESOLVED) {
            List<String> inf = HashingR1203Test.inferred(r, "wide.N." + fn);
            assertTrue(inf.contains("Fs"), fn + " runs EqEff (executed), and its producer says so; got " + r.get("wide.N." + fn));
        }
        assertTrue(HashingR1203Test.inferred(r, "wide.N.d04HelperExact").contains("Fs"), "got " + r.get("wide.N.d04HelperExact"));
        assertTrue(HashingR1203Test.inferred(r, "wide.N.kd02Str").isEmpty(), "got " + r.get("wide.N.kd02Str"));
        for (String fn : WIDE_PURE)
            assertTrue(HashingR1203Test.inferred(r, "wide.N." + fn).isEmpty(), fn + ": its producer is a pure class; got " + r.get("wide.N." + fn));
    }

    static Map<String, Map<String, Object>> scan(String pkg, String sink, String types, String main) throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        m.put(pkg + "/Sink.java", sink);
        m.put(pkg + "/T.java", types);
        m.put(pkg + "/N.java", main);
        return HashingR1203Test.scanSources(m);
    }
}
