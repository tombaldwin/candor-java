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
            // a DECLARED type naming two bodies is not resolved (the CHA union was the measured smear, 9,551 census
            // rows) — but one of them writes a file, so the caller DISCLOSES rather than staying silent
            List<String> wd = inferred(r, "wideDecl");
            assertTrue(wd != null && !wd.contains("Fs") && wd.contains("Unknown"), "wideDecl; got " + wd);
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
            // a project value whose overrides are all PURE discloses nothing; one with an effectful override
            // (heldW hands a Weq to a method that never calls its equals) is DISCLOSED, never charged
            for (String fn : List.of("eqP", "hashP", "strP", "cmpP", "iterP", "nextP", "jdkArg"))
                assertPure(r, fn, "must stay pure chained");
            List<String> held = inferred(r, "heldW");
            assertTrue(held != null && !held.contains("Fs") && held.contains("Unknown"), "got " + held);
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
            // DISCLOSED, not charged: the dependency's report has no spelling for a JDK-owned member (SPEC §4,
            // the deferred stdlib-requirement rung), so `deny Fs Unknown` is the gate that moves (0 -> 1).
            for (String fn : EFFECTFUL) {
                List<String> inf = inferred(r, fn);
                assertTrue(inf != null && inf.contains("Unknown") && !inf.contains("Fs"), fn + " chained; got " + inf);
                @SuppressWarnings("unchecked")
                List<String> why = (List<String>) r.get("app.Main." + fn).get("unknownWhy");
                assertTrue(why != null && why.stream().anyMatch(w -> w.startsWith("dispatch:java.")), fn + " why " + why);
            }
        } finally {
            t.close();
        }
    }

    @Test
    void theLibraryPublishesNoJdkOwnedKey() throws Exception {
        Tree t = Tree.of(Map.of("glib/G.java", LIB));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scan("glib"));
            for (var row : r.values()) {
                Object d = row.get("dispatchesOn");
                assertTrue(d == null || ((List<?>) d).stream().noneMatch(k -> k.toString().startsWith("java/")),
                        "no java.*-owned dispatchesOn key on the wire (SPEC §4 forbids the invented spelling); got " + row);
            }
        } finally {
            t.close();
        }
    }

    // ---- the audit's four properties (independent javap checker, auditagent-r1166) ----------------------

    static final String PSINK = "package px;\nfinal class Sink { static void w() { try { java.nio.file.Files"
            + ".writeString(java.nio.file.Path.of(\"/nonexistent-r1166/p\"), \"x\"); } catch (Exception e) {} } }\n";
    static final String PSRC = "package px;\nimport java.util.*;\n"
            + "class Weq { public boolean equals(Object o) { Sink.w(); return true; } public int hashCode() { return 1; } }\n"
            + "class Whash { public int hashCode() { Sink.w(); return 1; } public boolean equals(Object o) { return o == this; } }\n"
            + "class Wstr { public String toString() { Sink.w(); return \"w\"; } }\n"
            + "class Base { }\nclass Sub extends Base { public boolean equals(Object o) { Sink.w(); return true; } }\n"
            + "class Cfg { Object last; void config(Object o) { last = o; } }\n"
            + "final class MyNum extends Number { public int intValue() { return 0; } public long longValue() { return 0; }"
            + " public float floatValue() { return 0; } public double doubleValue() { return 0; }"
            + " public String toString() { Sink.w(); return \"n\"; } }\n"
            + "final class MyList extends AbstractList<String> { public String get(int i) { return \"a\"; } public int size() { return 1; }"
            + " public Iterator<String> iterator() { Sink.w(); return List.of(\"a\").iterator(); } }\n"
            + "class Bse { public boolean equals(Object o) { step(); return true; } void step() { } }\n"
            + "class S1 extends Bse { void step() { Sink.w(); } }\nclass S2 extends Bse { }\n"
            + "class Sup { public boolean equals(Object o) { return super.equals(o); } }\n"
            + "abstract class Am { public boolean equals(Object o) { return G.str(this).isEmpty(); }"
            + " public String toString() { return step(); } String step() { return \"\"; } }\n"
            + "class Am1 extends Am { String step() { Sink.w(); return \"1\"; } }\nclass Am2 extends Am { }\n"
            + "class Bp { public boolean equals(Object o) { H.go(this); return true; } void step() { } }\n"
            + "class Bp1 extends Bp { void step() { Sink.w(); } }\nclass Bp2 extends Bp { }\n"
            + "final class H { static void go(Bp b) { b.step(); } }\n"
            + "class Br { public boolean equals(Object o) { Runnable r = this::step; r.run(); return true; } void step() { } }\n"
            + "class Br1 extends Br { void step() { Sink.w(); } }\nclass Br2 extends Br { }\n"
            + "final class G {\n"
            + "  static <T> boolean same(T a, T b) { return a.equals(b); }\n"
            + "  static <T> String str(T a) { return a.toString(); }\n"
            + "  static <T> int count(Iterable<T> it) { int n = 0; for (T t : it) n++; return n; }\n"
            + "  static void keepL(List<Object> l, Object o) { l.add(o); }\n"
            + "  static boolean hasL(List<Object> l, Object o) { return l.contains(o); }\n"
            + "  static void reg(Cfg c, Object o) { c.config(o); }\n"
            + "  static Base mk(boolean s) { return s ? new Sub() : new Base(); }\n"
            + "  static boolean oeq(Object a, Object b) { return Objects.equals(a, b); }\n}\n"
            + "public class P {\n  static Object sink;\n"
            + "  static Number num() { return Integer.valueOf(3); }\n"
            + "  public static void listAdd() { G.keepL(new ArrayList<>(), new Weq()); }\n"
            + "  public static void listAddHash() { G.keepL(new ArrayList<>(), new Whash()); }\n"
            + "  public static void listContainsHash() { sink = G.hasL(new ArrayList<>(List.of(\"z\")), new Whash()); }\n"
            + "  public static void directListAdd() { new ArrayList<Object>().add(new Weq()); }\n"
            + "  public static void lostRealHash() { List<Object> l = new ArrayList<>(); l.add(new Whash()); sink = l.hashCode(); }\n"
            + "  public static void lostRealEq() { List<Object> l = new ArrayList<>(); l.add(new Weq()); sink = l.equals(List.of(1)); }\n"
            + "  public static void lostRealSet() { List<Object> l = new ArrayList<>(); l.add(new Whash()); sink = new HashSet<>(l); }\n"
            + "  public static void lostFalse() { List<Object> l = new ArrayList<>(); l.add(new Whash()); sink = l.size(); }\n"
            + "  static List<Object> kept = new ArrayList<>();\n"
            + "  public static void lostEscape() { kept.add(new Whash()); }\n"
            + "  private static final List<Object> kept2 = new ArrayList<>();\n"
            + "  public static void addKept2() { kept2.add(new Whash()); }\n"
            + "  public static void useKept2() { sink = kept2.hashCode(); }\n"
            + "  static List<Object> build() { List<Object> l = new ArrayList<>(); l.add(new Whash()); return l; }\n"
            + "  public static void useBuilt() { sink = Collections.unmodifiableList(build()).hashCode(); }\n"
            + "  public static void dropBuilt() { sink = build().size(); }\n"
            + "  static List<Object> opts() { List<Object> l = new ArrayList<>(); l.add(new Weq()); return Collections.unmodifiableList(l); }\n"
            + "  public static void lostRemoveAll() { List<Object> r = new ArrayList<>(List.of(new Weq())); r.removeAll(opts()); }\n"
            + "  public static void cfgReg() { G.reg(new Cfg(), new Wstr()); }\n"
            + "  public static void boxedNumber() { sink = G.str(num()); }\n"
            + "  public static void asListIt() { sink = G.count(Arrays.asList(\"a\", \"b\")); }\n"
            + "  public static void declBaseF() { Base b = G.mk(false); sink = G.same(b, b); }\n"
            + "  public static void ctxSmear() { sink = G.same(new S2(), \"x\"); }\n"
            + "  public static void ctxReal() { sink = G.same(new S1(), \"x\"); }\n"
            + "  public static void passSmear() { sink = G.same(new Bp2(), \"x\"); }\n"
            + "  public static void passReal() { sink = G.same(new Bp1(), \"x\"); }\n"
            + "  public static void refSmear() { sink = G.same(new Br2(), \"x\"); }\n"
            + "  public static void refReal() { sink = G.same(new Br1(), \"x\"); }\n"
            + "  public static void ownSmear() { sink = G.same(new Am2(), \"x\"); }\n"
            + "  public static void ownReal() { sink = G.same(new Am1(), \"x\"); }\n"
            + "  public static void superEq() { sink = G.same(new Sup(), \"x\"); }\n"
            + "  public static void objEqW() { sink = G.oeq(new Weq(), \"x\"); }\n"
            + "  public static void realMyList() { sink = G.count(new MyList()); }\n}\n";

    static Map<String, String> pkgP() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("px/Sink.java", PSINK);
        m.put("px/P.java", PSRC);
        StringBuilder b = new StringBuilder("package px;\n");   // past the bound, as any real project is
        for (int i = 1; i <= 13; i++)
            b.append("class F").append(i).append(" implements Iterable<String> { public boolean equals(Object o){return o==this;}")
             .append(" public int hashCode(){return ").append(i).append(";} public String toString(){return \"f\";}")
             .append(" public java.util.Iterator<String> iterator(){ return java.util.Collections.emptyIterator(); } }\n");
        m.put("px/Fill.java", b.toString());
        return m;
    }

    @SuppressWarnings("unchecked")
    static List<String> inf(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get(fn);
        return row == null ? List.of() : (List<String>) row.get("inferred");
    }

    /** Property 1 (JDK semantics), 2 (one body over every runtime type), 4 (the receiver the resolution
     *  established) — each EXECUTED by the audit: no file was written on any of the pure arms. */
    @Test
    void auditPropertiesHoldInOneTree() throws Exception {
        Tree t = Tree.of(pkgP());
        try {
            Map<String, Map<String, Object>> r = byFnAll(t.scanAll());
            for (String fn : List.of("listAdd", "listAddHash", "listContainsHash", "directListAdd", "cfgReg",
                    "lostFalse", "lostEscape", "dropBuilt",
                    "boxedNumber", "asListIt", "declBaseF", "ctxSmear", "superEq", "passSmear", "refSmear", "ownSmear"))
                assertTrue(!inf(r, "px.P." + fn).contains("Fs"), fn + " never performs Fs (executed); got " + r.get("px.P." + fn));
            // a list runs its ELEMENTS' contracts later (`l.hashCode()`, `l.equals(..)`, `new HashSet<>(l)`,
            // `r.removeAll(c)`), across a field and a helper's return too — all executed by an independent removal
            // audit, each writing a file. ElementFlow models that path; `add` itself charges nothing.
            for (String fn : List.of("ctxReal", "objEqW", "realMyList", "passReal", "refReal", "ownReal",
                    "lostRealHash", "lostRealEq", "lostRealSet", "useKept2", "useBuilt", "lostRemoveAll"))
                assertTrue(inf(r, "px.P." + fn).contains("Fs"), fn + " performs Fs (executed); got " + r.get("px.P." + fn));
        } finally {
            t.close();
        }
    }

    static final String XL = "package xl;\npublic final class L {\n"
            + "  public static void f(Object a, Object b) { a.hashCode(); }\n"
            + "  public static void keep(java.util.List<Object> l, Object o) { l.add(o); }\n}\n";
    static final String XA = "package xa;\n"
            + "final class Sink { static void w() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1166/q\"), \"x\"); } catch (Exception e) {} } }\n"
            + "class Whash { public int hashCode() { Sink.w(); return 1; } }\nclass Phash { public int hashCode() { return 3; } }\n"
            + "class Weq { public boolean equals(Object o) { Sink.w(); return true; } public int hashCode() { return 1; } }\n"
            + "public class M {\n"
            + "  public static void crossArg() { xl.L.f(new Phash(), new Whash()); }\n"
            + "  public static void crossArgRight() { xl.L.f(new Whash(), new Phash()); }\n"
            + "  public static void chainKeep() { xl.L.keep(new java.util.ArrayList<>(), new Weq()); }\n}\n";

    /** Property 3: the chained join resolves only the argument that reaches the dispatch — and where the wire
     *  cannot say which, it DISCLOSES (both arms) rather than charging the wrong one. */
    @Test
    void aChainedJoinChargesOnlyTheReceiverAndDisclosesWhenItCannotTell() throws Exception {
        Tree t = Tree.of(Map.of("xl/L.java", XL), Map.of("xa/M.java", XA));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanChained("xa", t.scan("xl")));
            assertTrue(!inf(r, "xa.M.crossArg").contains("Fs"), "Whash is the SECOND argument; a.hashCode() runs"
                    + " Phash's: never charge it; got " + r.get("xa.M.crossArg"));
            assertTrue(inf(r, "xa.M.crossArgRight").contains("Unknown"), "the wire does not name the parameter,"
                    + " so a real Whash.hashCode is disclosed, never silent; got " + r.get("xa.M.crossArgRight"));
            assertTrue(!inf(r, "xa.M.chainKeep").contains("Fs"), "List.add calls neither equals nor hashCode; got "
                    + r.get("xa.M.chainKeep"));
        } finally {
            t.close();
        }
    }

    /** The JVM resolves the whole superclass chain before an interface default: `Ctx2 extends LinkedHashMap
     *  implements CView` runs LinkedHashMap.forEach, never CView's default (executed: no file). */
    @Test
    void aJdkSuperclassBodyBeatsAProjectInterfaceDefault() throws Exception {
        StringBuilder b = new StringBuilder("package pj;\nimport java.util.*; import java.util.function.*;\n"
                + "final class Sink { static void w() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1166/j\"), \"x\"); } catch (Exception e) {} } }\n"
                + "interface CView { default void forEach(BiConsumer<? super String, ? super String> a) { Sink.w(); } }\n"
                + "final class Ctx2 extends LinkedHashMap<String, String> implements CView { }\n"
                + "final class G { static <K, V> void each(Map<K, V> m) { m.forEach((k, v) -> { }); } }\n"
                + "public class M { public static void jdkWins() { G.each(new Ctx2()); } }\n");
        for (int i = 0; i < 14; i++)   // past the bound, so the callee's own Map.forEach CHA is dropped
            b.append("final class F").append(i).append(" extends HashMap<String,String> { public void forEach(BiConsumer<? super String, ? super String> a) { } }\n");
        Tree t = Tree.of(Map.of("pj/M.java", b.toString()));
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            assertTrue(!inf(r, "pj.M.jdkWins").contains("Fs"), "got " + r.get("pj.M.jdkWins"));
        } finally {
            t.close();
        }
    }

    private static Map<String, Map<String, Object>> byFnAll(String p) throws Exception { return byFn(p); }

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
