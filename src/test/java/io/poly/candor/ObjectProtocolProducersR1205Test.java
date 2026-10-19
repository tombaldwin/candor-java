package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * SOUNDNESS R1205 / R1217 / R1204 — AN OBJECT-PROTOCOL DISPATCH IS DECIDED BY WHAT PRODUCED THE RECEIVER.
 *
 * <p>EXECUTED on JDK 21 (fixture {@code javaagent-v074/f74}, package {@code vz}, drivers {@code vz.D}/{@code vz.D2}, the
 * same sources in a 4-override tree and, with thirteen pure filler classes, a 17-override one): every {@code e*},
 * {@code c*} and {@code x*} below wrote the file, every {@code k*} wrote nothing. On 0.40.12 and on 2713406:
 * <ul>
 *   <li>IN BOUND the {@code k*} direct dispatches read {@code deny Fs} exit 1 (every override edged whatever the
 *       receiver could be — a fabrication), and the {@code c*} JDK string sinks and {@code x*} entries read 0
 *       (silent);</li>
 *   <li>PAST THE BOUND every {@code e*}, {@code c*} and {@code x*} read {@code deny Fs Unknown} exit 0 (silent).</li>
 * </ul>
 * The receivers' producers name their exact classes (a factory, a field with a closed write set, a final type, an
 * entry's key), so each is now RESOLVED: the effectful ones charged {@code Fs} and the pure ones absent, in both trees.
 * {@code e15}/{@code e16} pin two producers the def-use frames do NOT record — a caught exception, and a parameter the
 * body also reassigns — which an independent javap audit of the corpus removals found the first cut reading as "no
 * receiver" (e15 went {@code deny Fs} 1 -> 0 in bound); they must stay charged.
 */
class ObjectProtocolProducersR1205Test {

    static final String SINK = "package op;\nfinal class Sink { static void w() { try { java.nio.file.Files.writeString("
            + "java.nio.file.Path.of(\"/nonexistent-r1205/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String TYPES = ""
            + "package op;\n"
            + "import java.util.*;\n"
            + "final class EqEff implements Comparable<EqEff> { final int v; EqEff(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { Sink.w(); return o instanceof EqEff e && e.v == v; }\n"
            + "  @Override public int hashCode() { Sink.w(); return v; }\n"
            + "  @Override public String toString() { Sink.w(); return \"e\"; }\n"
            + "  @Override public int compareTo(EqEff o) { Sink.w(); return 0; } }\n"
            + "final class P0 implements Comparable<P0> { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 0; } @Override public String toString() { return \"p\"; } @Override public int compareTo(P0 o) { return 0; } }\n"
            + "final class P1 implements Comparable<P1> { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 1; } @Override public String toString() { return \"p\"; } @Override public int compareTo(P1 o) { return 0; } }\n"
            + "final class P2 implements Comparable<P2> { @Override public boolean equals(Object o) { return o == this; } @Override public int hashCode() { return 2; } @Override public String toString() { return \"p\"; } @Override public int compareTo(P2 o) { return 0; } }\n"
            + "enum Color { RED; @Override public String toString() { Sink.w(); return \"r\"; } }\n"
            + "final class MyList extends ArrayList<Object> { }\n"
            + "final class Mk { static Object eq(int v) { return new EqEff(v); } @SuppressWarnings(\"rawtypes\") static Comparable cmp() { return new EqEff(1); }\n"
            + "  static Object p() { return new P0(); } @SuppressWarnings(\"rawtypes\") static Comparable cmpPure() { return new P1(); } static Object str() { return \"s\"; } }\n"
            + "class Fac { Object make() { return new EqEff(3); } }\n"
            + "final class Holder { final Object f; Holder(Object f) { this.f = f; } }\n"
            + "final class Own { private final Object f = Mk.eq(4); int h() { return f.hashCode(); } }\n"
            + "final class BoomEx extends RuntimeException { @Override public String toString() { Sink.w(); return \"b\"; } }\n";

    static final String MAIN = ""
            + "package op;\n"
            + "import java.util.*;\n"
            + "public class N {\n"
            + "  static Object HO = new Object();\n"
            + "  static Object HE = Mk.eq(7);\n"
            + "  static Object HS = \"k\";\n"
            + "  private static Object PF = new EqEff(1);\n"
            + "  public static Object PUB = new Object();\n"
            + "  public static boolean e01HeldObj() { return HO.equals(\"k\"); }\n"
            + "  public static boolean e02HeldEff() { return HE.equals(\"k\"); }\n"
            + "  public static String e03ToStr() { Object o = Mk.eq(1); return o.toString(); }\n"
            + "  @SuppressWarnings({\"rawtypes\", \"unchecked\"}) public static int e05Cmp() { Comparable c = Mk.cmp(); return c.compareTo(c); }\n"
            + "  public static int e06Hash() { Object o = Mk.eq(1); return o.hashCode(); }\n"
            + "  public static int ke01HeldStr() { return HS.hashCode(); }\n"
            + "  public static String ke02ToStrPure() { Object o = Mk.p(); return o.toString(); }\n"
            + "  @SuppressWarnings({\"rawtypes\", \"unchecked\"}) public static int kj02CmpPure() { Comparable x = Mk.cmpPure(), y = Mk.cmpPure(); return x.compareTo(y); }\n"
            + "  public static boolean e07PrivField() { return PF.equals(\"k\"); }\n"
            + "  public static boolean kpPubField() { return PUB.equals(\"k\"); }\n"
            + "  public static int e08FinalInst() { return new Holder(Mk.eq(2)).f.hashCode(); }\n"
            + "  public static int e09OwnPrivate() { return new Own().h(); }\n"
            + "  public static String e10Merge() { Object o = System.getProperty(\"flip\") == null ? Mk.eq(1) : new P0(); return o.toString(); }\n"
            + "  public static int e11Array() { Object[] a = { Mk.eq(1) }; return a[0].hashCode(); }\n"
            + "  public static String e12Virtual() { return new Fac().make().toString(); }\n"
            + "  public static String e13Enum() { Object e = Color.RED; return e.toString(); }\n"
            + "  public static String kl01Lambda() { Object r = (Runnable) () -> { }; return r.toString(); }\n"
            + "  public static String kl02JdkSub() { Object l = new MyList(); return l.toString(); }\n"
            + "  static int hp(Object o) { return o.hashCode(); }\n"
            + "  public static int e14Param() { return hp(Mk.eq(1)); }\n"
            + "  public static String c01Concat() { Object o = Mk.eq(1); return \"\" + o; }\n"
            + "  public static String c02ValueOf() { Object o = Mk.eq(1); return String.valueOf(o); }\n"
            + "  public static String c03Append() { Object o = Mk.eq(1); return new StringBuilder().append(o).toString(); }\n"
            + "  public static String c04ObjToStr() { Object o = Mk.eq(1); return Objects.toString(o); }\n"
            + "  public static String c05Format() { Object o = Mk.eq(1); return String.format(\"%s\", o); }\n"
            + "  public static String kc06ConcatPure() { Object o = Mk.p(); return \"\" + o; }\n"
            + "  static String cat(Object x) { return \"<\" + x; }\n"
            + "  public static String c07ConcatParam() { return cat(Mk.eq(1)); }\n"
            + "  public static String kc08ConcatStr() { Object o = Mk.str(); return \"\" + o; }\n"
            + "  public static String c12SinkArray() { Object[] a = { Mk.eq(1) }; return String.valueOf(a[0]); }\n"
            + "  public static String c13ParamTop() { Object[] a = { Mk.eq(1) }; return cat(a[0]); }\n"
            + "  public static String kc14SinkArrayPure() { Object[] a = { Mk.p() }; return String.valueOf(a[0]); }\n"
            + "  static void boom() { throw new BoomEx(); }\n"
            + "  public static String e15CatchToStr() { try { boom(); return \"-\"; } catch (RuntimeException e) { return e.toString(); } }\n"
            + "  static String pov(Object x) { if (System.getProperty(\"flip\") != null) x = new P0(); return x.toString(); }\n"
            + "  public static String e16ParamOverwrite() { return pov(Mk.eq(1)); }\n"
            + "  public static int x27MapEntryHash() { return Map.entry(new EqEff(1), 1).hashCode(); }\n"
            + "  public static String x28EntryToStr() { return Map.entry(Mk.eq(1), 1).toString(); }\n"
            + "  public static boolean x29SimpleEq() { return new AbstractMap.SimpleEntry<Object, Integer>(new EqEff(1), 1).equals(Map.entry(\"a\", 1)); }\n"
            + "  public static int kx30EntryPure() { return Map.entry(\"a\", 1).hashCode(); }\n"
            + "}\n";

    /** Thirteen pure overrides of all four members: past the bound of twelve. */
    static String filler() {
        StringBuilder b = new StringBuilder("package op;\n");
        for (int i = 1; i <= 13; i++)
            b.append("final class F").append(i).append(" implements Comparable<F").append(i).append("> { public boolean equals(Object o){return o==this;}")
             .append(" public int hashCode(){return ").append(i).append(";} public String toString(){return \"f\";} public int compareTo(F")
             .append(i).append(" o){return 0;} }\n");
        return b.toString();
    }

    /** Wrote the file; the producer names the effectful class. */
    static final List<String> RESOLVED_EFFECTFUL = List.of("e02HeldEff", "e03ToStr", "e05Cmp", "e06Hash", "e07PrivField",
            "e09OwnPrivate", "e10Merge", "e13Enum", "e14Param", "c01Concat", "c02ValueOf", "c03Append", "c04ObjToStr",
            "c05Format", "c07ConcatParam", "e15CatchToStr", "e16ParamOverwrite", "x27MapEntryHash", "x28EntryToStr", "x29SimpleEq", "Indy.c09IndyConcat",
            "Indy.c11IndyParam");
    /** Wrote nothing; the producer names a pure class. */
    static final List<String> RESOLVED_PURE = List.of("e01HeldObj", "ke01HeldStr", "ke02ToStrPure", "kj02CmpPure",
            "kl01Lambda", "kl02JdkSub", "kc06ConcatPure", "kc08ConcatStr", "kx30EntryPure", "Indy.kc10IndyPure");
    /** Wrote the file, but a producer is out of sight (a constructor parameter, an array element, an overridable factory,
     *  a public field): in bound the explicit dispatch keeps its CHA edges; past it, never charged. */
    static final List<String> TOP_DIRECT = List.of("e08FinalInst", "e11Array", "e12Virtual");

    static Map<String, String> sources(boolean wide) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("op/Sink.java", SINK);
        m.put("op/T.java", TYPES);
        m.put("op/N.java", MAIN);
        if (wide) m.put("op/Fill.java", filler());
        return m;
    }

    static String fn(String f) { return f.contains(".") ? "op." + f : "op.N." + f; }

    @Test
    void eachSiteResolvesByItsProducerInBoundAndPastIt() throws Exception {
        for (boolean wide : new boolean[] {false, true}) {
            Map<String, Map<String, Object>> r = scan(sources(wide), Map.of());
            String tree = wide ? "WIDE (17 overrides)" : "NARROW (5 overrides)";
            for (String f : RESOLVED_EFFECTFUL) {
                List<String> inf = HashingR1203Test.inferred(r, fn(f));
                assertTrue(inf.contains("Fs"), tree + " " + f + " runs EqEff (executed); got " + r.get(fn(f)));
            }
            for (String f : RESOLVED_PURE)
                assertTrue(HashingR1203Test.inferred(r, fn(f)).isEmpty(), tree + " " + f + " runs no effect (executed); got " + r.get(fn(f)));
            for (String f : TOP_DIRECT) {
                List<String> inf = HashingR1203Test.inferred(r, fn(f));
                assertEquals(!wide, inf.contains("Fs"), tree + " " + f + ": the CHA edges are the in-bound answer only; got " + r.get(fn(f)));
            }
            // a field any package can reassign is not followed: in bound it keeps the CHA over-approximation
            assertEquals(!wide, HashingR1203Test.inferred(r, fn("kpPubField")).contains("Fs"), tree + " got " + r.get(fn("kpPubField")));
        }
    }

    @Test
    void theFloorDisclosesWhatTheProducersCannotName() throws Exception {
        Map<String, Map<String, Object>> r = scan(sources(true), Map.of("S4", true, "S5", true));
        for (String f : List.of("e08FinalInst", "e11Array", "e12Virtual", "c12SinkArray", "c13ParamTop")) {
            List<String> inf = HashingR1203Test.inferred(r, fn(f));
            assertTrue(inf.contains("Unknown") && !inf.contains("Fs"), f + ": disclosed, never charged; got " + r.get(fn(f)));
        }
        // and nothing resolved is disturbed by it
        for (String f : RESOLVED_PURE)
            assertTrue(HashingR1203Test.inferred(r, fn(f)).isEmpty(), f + " got " + r.get(fn(f)));
        assertTrue(String.valueOf(r.get(fn("e11Array")).get("unknownWhy")).contains("dispatch:java.lang.Object.hashCode"), "got " + r.get(fn("e11Array")));
        assertTrue(String.valueOf(r.get(fn("c12SinkArray")).get("unknownWhy")).contains("dispatch:java.lang.Object.toString"), "got " + r.get(fn("c12SinkArray")));
    }

    /** R1166's control {@code heldW} — {@code static Object held = new Object(); held.equals("k")} — is pure because its
     *  one store is {@code new Object()}, with or without the thirteen filler overrides that used to decide it. */
    @Test
    void heldWIsPureForTheRightReasonWithAndWithoutFiller() throws Exception {
        for (boolean filler : new boolean[] {false, true}) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("glib/G.java", ArgContractR1166Test.LIB);
            m.putAll(ArgContractR1166Test.app(filler));
            Map<String, Map<String, Object>> r = scan(m, Map.of());
            Map<String, Object> row = r.get("app.Main.heldW");
            assertTrue(row == null || ((List<?>) row.get("inferred")).isEmpty(), "filler=" + filler + ": " + row);
            // …and not because nothing is edged: the effectful sibling through the same library still charges
            assertTrue(HashingR1203Test.inferred(r, "app.Main.eqW").contains("Fs"), "filler=" + filler + ": " + r.get("app.Main.eqW"));
        }
    }

    /** The answer reads OTHER classes' bodies (the factory), so it is decided after the analyze loop every run: a warm
     *  refresh after the factory alone changed must equal a cold scan (the R163 shape, executed). */
    @Test
    void aFactoryChangeReachesAWarmRefresh() throws Exception {
        Map<String, String> m = sources(true);
        Path cls = TestCompiler.compile(m);
        Path base = cls.getParent();
        Config saved = Candor.config;
        try {
            Path cache = base.resolve("cache");
            Files.createDirectories(cache);
            String before = scanCached(cls, cache)[0];
            assertTrue(before.contains("\"op.N.e06Hash\""), "the fixture must charge e06Hash first");
            // only Mk changes: eq() now returns a pure P0
            Map<String, String> m2 = new LinkedHashMap<>(m);
            m2.put("op/T.java", TYPES.replace("static Object eq(int v) { return new EqEff(v); }", "static Object eq(int v) { return new P0(); }"));
            Path cls2 = TestCompiler.compile(m2);
            try {
                copyOver(cls2, cls);
                String[] w = scanCached(cls, cache);
                String warm = w[0];
                assertTrue(Integer.parseInt(w[1]) > 0, "the warm run reused no class, so it is not a refresh: " + w[1]);
                String cold = scanCached(cls, null)[0];
                assertEquals(cold, warm, "a warm refresh must reproduce the cold scan after a factory-only change");
                assertTrue(!cold.contains("\"op.N.e06Hash\""), "…and the cold scan sees the pure factory");
            } finally {
                rm(cls2.getParent());
            }
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    // ---- helpers -------------------------------------------------------------------------------------

    static Map<String, Map<String, Object>> scan(Map<String, String> m, Map<String, Boolean> floors) throws Exception {
        Path cls = TestCompiler.compile(m, "-g");
        if (m.containsKey("op/N.java")) writeIndy(cls);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Path out = cls.getParent().resolve("r.json");
            if (floors.isEmpty()) ReportWriter.writeJson(Candor.runScan(cls), out.toString());
            else withFloors(floors, () -> ReportWriter.writeJson(Candor.runScan(cls), out.toString()));
            return HashingR1203Test.byFn(out);
        } finally {
            Candor.config = saved;
            rm(cls.getParent());
        }
    }

    interface Body { void run() throws Exception; }

    /** {@code CANDOR_R1201_FLOOR} is read once into a static set; a test cannot set the environment, so it widens that set. */
    static void withFloors(Map<String, Boolean> floors, Body b) throws Exception {
        java.util.Set<String> cur = ArgContract.FLOOR;
        java.util.Set<String> wider = new java.util.HashSet<>(cur);
        for (var e : floors.entrySet()) if (e.getValue()) wider.add(e.getKey()); else wider.remove(e.getKey());
        ArgContract.FLOOR = java.util.Set.copyOf(wider);
        try { b.run(); } finally { ArgContract.FLOOR = cur; }
    }

    /** The javac 9-18 / Kotlin shape of {@code "" + o}: makeConcatWithConstants over an {@code Object} operand. JDK 21's
     *  javac calls {@code String.valueOf} first, so this class is written with ASM (fixture f74 {@code gen/Gen.java},
     *  executed: c09/c11 wrote the file, kc10 did not). */
    static void writeIndy(Path cls) throws Exception {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
            @Override protected String getCommonSuperClass(String a, String b) { return "java/lang/Object"; }
        };
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "op/Indy", null, "java/lang/Object", null);
        Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/StringConcatFactory", "makeConcatWithConstants",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;", false);
        for (String[] m : new String[][] {{"c09IndyConcat", "eq"}, {"kc10IndyPure", "p"}}) {
            MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, m[0], "()Ljava/lang/String;", null, null);
            mv.visitCode();
            if (m[1].equals("eq")) { mv.visitInsn(Opcodes.ICONST_1); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "op/Mk", "eq", "(I)Ljava/lang/Object;", false); }
            else mv.visitMethodInsn(Opcodes.INVOKESTATIC, "op/Mk", "p", "()Ljava/lang/Object;", false);
            mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(Ljava/lang/Object;)Ljava/lang/String;", bsm, "<\u0001");
            mv.visitInsn(Opcodes.ARETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
        }
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_STATIC, "cat2", "(Ljava/lang/Object;)Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(Ljava/lang/Object;)Ljava/lang/String;", bsm, "<\u0001");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "c11IndyParam", "()Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "op/Mk", "eq", "(I)Ljava/lang/Object;", false);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "op/Indy", "cat2", "(Ljava/lang/Object;)Ljava/lang/String;", false);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        Files.write(cls.resolve("op/Indy.class"), cw.toByteArray());
    }

    private static void copyOver(Path from, Path to) throws Exception {
        try (var s = Files.walk(from)) {
            for (Path p : s.toList()) {
                if (!Files.isRegularFile(p)) continue;
                Path d = to.resolve(from.relativize(p).toString());
                Files.createDirectories(d.getParent());
                Files.copy(p, d, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    /** {report, classes reused}. */
    private static String[] scanCached(Path dir, Path cache) throws Exception {
        Config cfg = Config.empty();
        if (cache != null) {
            java.lang.reflect.Field f = Config.class.getDeclaredField("values");
            f.setAccessible(true);
            @SuppressWarnings("unchecked") Map<String, String> v = (Map<String, String>) f.get(cfg);
            v.put("refresh", cache.toString());
        }
        Candor.config = cfg;
        Path out = Files.createTempFile(dir.getParent(), "report", ".json");
        PrintStream savedErr = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(buf, true, StandardCharsets.UTF_8));
            ReportWriter.writeJson(Candor.runScan(dir), out.toString());
        } finally {
            System.setErr(savedErr);
        }
        var mm = java.util.regex.Pattern.compile("reused (\\d+) of").matcher(buf.toString(StandardCharsets.UTF_8));
        return new String[] {Files.readString(out), mm.find() ? mm.group(1) : "0"};
    }
}
