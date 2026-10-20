package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1235 — A JDK BODY THAT DISPATCHES BACK INTO USER CODE. Every {@code c*} method below wrote a file when
 * run on JDK 21 (fixture {@code javaagent-r1232/bat}, {@code bat2}: each driver records which override ran) and every
 * one read ABSENT on c6ad21c, {@code deny Fs} exit 0:
 * <ul>
 *   <li>{@code Object.toString()} runs {@code this.hashCode()} — through a direct call, a concat, {@code String.valueOf},
 *       {@code append(Object)}, {@code Objects.toString}, and an inherited project {@code hashCode};</li>
 *   <li>{@code Throwable.toString()} runs {@code this.getLocalizedMessage()}, which runs {@code this.getMessage()};</li>
 *   <li>{@code Objects.hashCode(p)}/{@code Objects.equals(p, q)} over a PARAMETER charged only the callers;</li>
 *   <li>a JDK container's toString (explicit, by concat, by {@code String.valueOf}) runs each element's — and a map's
 *       values' — toString.</li>
 * </ul>
 * The {@code k*} methods are the CONTROLS, and each wrote nothing when run: a class whose own toString is pure (its
 * effectful hashCode never runs), its subclass, an exception whose toString is pure over an effectful getMessage, an
 * ARRAY stringified (Object's identity string — its elements are not visited), and a list of the pure-toString class.
 */
class JdkReentryR1235Test {

    static final String SRC_W = "package rq;\npublic final class W { public static void w() { try { java.nio.file.Files.writeString("
            + "java.nio.file.Path.of(\"/nonexistent-r1235/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String SRC_T = ""
            + "package rq;\n"
            + "class HashOnly { @Override public int hashCode() { W.w(); return 7; } }\n"
            + "class SubHash extends HashOnly { }\n"
            + "class EqOnly { @Override public boolean equals(Object o) { W.w(); return false; } @Override public int hashCode() { return 1; } }\n"
            + "class StrOnly { @Override public String toString() { W.w(); return \"s\"; } }\n"
            + "class MyEx extends RuntimeException { @Override public String getMessage() { W.w(); return \"m\"; } }\n"
            + "class LocMsg extends java.io.IOException { @Override public String getLocalizedMessage() { W.w(); return \"l\"; } }\n"
            + "class Both { @Override public int hashCode() { W.w(); return 7; } @Override public String toString() { return \"pure\"; } }\n"
            + "class SubOfBoth extends Both { }\n"
            + "class MsgPure extends RuntimeException { @Override public String getMessage() { W.w(); return \"m\"; } @Override public String toString() { return \"pure\"; } }\n";

    static final String SRC_U = ""
            + "package rq;\n"
            + "import java.util.*;\n"
            + "public class U {\n"
            + "  public static String cDirect(HashOnly h) { return h.toString(); }\n"
            + "  public static String cConcat(HashOnly h) { return \"v=\" + h; }\n"
            + "  public static String cValueOf(HashOnly h) { return String.valueOf(h); }\n"
            + "  public static String cAppend(HashOnly h) { return new StringBuilder().append(h).toString(); }\n"
            + "  public static String cObjectsToString(HashOnly h) { return Objects.toString(h); }\n"
            + "  public static String cInherited(SubHash h) { return \"\" + h; }\n"
            + "  public static String cNew() { return new HashOnly().toString(); }\n"
            + "  public static String cExToString(MyEx e) { return e.toString(); }\n"
            + "  public static String cExConcat(MyEx e) { return \"e=\" + e; }\n"
            + "  public static String cLocMsg(LocMsg e) { return e.toString(); }\n"
            + "  public static int cObjectsHashCode(HashOnly h) { return Objects.hashCode(h); }\n"
            + "  public static boolean cObjectsEquals(EqOnly a, EqOnly b) { return Objects.equals(a, b); }\n"
            + "  public static String cListToString(StrOnly s) { List<StrOnly> l = new ArrayList<>(); l.add(s); return l.toString(); }\n"
            + "  public static String cListConcat(StrOnly s) { List<StrOnly> l = new ArrayList<>(); l.add(s); return \"l=\" + l; }\n"
            + "  public static String cListValueOf(StrOnly s) { List<StrOnly> l = new ArrayList<>(); l.add(s); return String.valueOf(l); }\n"
            + "  public static String cMapValues(StrOnly s) { Map<String, StrOnly> m = new HashMap<>(); m.put(\"k\", s); return m.toString(); }\n"
            + "  public static String cListOfHashOnly(HashOnly h) { List<HashOnly> l = new ArrayList<>(); l.add(h); return l.toString(); }\n"
            + "  public static String kBoth(Both b) { return \"\" + b; }\n"
            + "  public static String kSubOfBoth(SubOfBoth b) { return String.valueOf(b); }\n"
            + "  public static String kNewBoth() { return new Both().toString(); }\n"
            + "  public static String kMsgPure(MsgPure e) { return \"\" + e; }\n"
            + "  public static String kArray(StrOnly s) { StrOnly[] a = {s}; return \"a=\" + a + String.valueOf((Object) a); }\n"
            + "  public static String kListBoth(Both b) { List<Both> l = new ArrayList<>(); l.add(b); return l.toString() + l; }\n"
            + "}\n";

    static final List<String> CHARGED = List.of("cDirect", "cConcat", "cValueOf", "cAppend", "cObjectsToString", "cInherited",
            "cNew", "cExToString", "cExConcat", "cLocMsg", "cObjectsHashCode", "cObjectsEquals", "cListToString", "cListConcat",
            "cListValueOf", "cMapValues", "cListOfHashOnly");
    static final List<String> PURE = List.of("kBoth", "kSubOfBoth", "kNewBoth", "kMsgPure", "kArray", "kListBoth");

    @BeforeEach
    void fresh() { Candor.resetState(); }

    @AfterEach
    void clear() { Candor.resetState(); }

    @Test
    void aJdkBodyThatDispatchesBackChargesTheBodyItRuns() throws Exception {
        Path cls = TestCompiler.compile(Map.of("rq/W.java", SRC_W, "rq/T.java", SRC_T, "rq/U.java", SRC_U));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String m : CHARGED) {
                EffectSet e = inf.getOrDefault("rq.U." + m, EffectSet.empty());
                assertTrue(e.contains(Effect.FS), "R1235: rq.U." + m + " runs an effectful override through a JDK body — got " + e);
            }
            for (String m : PURE) {
                EffectSet e = inf.getOrDefault("rq.U." + m, EffectSet.empty());
                assertFalse(e.contains(Effect.FS), "control: rq.U." + m + " runs no effectful body (executed) — got " + e);
            }
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    // ---- SOUNDNESS R1299: the receiver's declared type, not `java/lang/Object`, bounds the dispatch ----------------

    static final String SRC_R1299 = ""
            + "package rz;\n"
            + "interface Cv { Object convert(Object o); }\n"
            + "class H implements Cv { public Object convert(Object o) { return o; } @Override public int hashCode() { rq.W.w(); return 1; } }\n"
            + "class K implements Cv { public Object convert(Object o) { return o; } @Override public String toString() { return \"K\" + System.currentTimeMillis(); } }\n"
            + "class Un { @Override public int hashCode() { return String.valueOf(System.getenv(\"HOME\")).length(); } }\n"
            + "abstract class MO { @Override public int hashCode() { return String.valueOf(System.getenv(\"HOME\")).length(); } }\n"
            + "class R1 extends MO { @Override public String toString() { return \"R1\"; } }\n"
            + "class R2 extends MO { @Override public String toString() { return \"R2\"; } }\n"
            + "abstract class MA { @Override public int hashCode() { rq.W.w(); return 2; } }\n"
            + "class MB extends MA { }\n"
            + "public class Z {\n"
            + "  Cv f;\n"
            + "  public String viaObjectOwner() { return ((Object) f).toString(); }\n"   // invokevirtual Object.toString, GETFIELD Cv
            + "  public static String anyObject(Object o) { return o.toString(); }\n"
            + "  public static String mo(MO m) { return m.toString(); }\n"                // javac: invokevirtual Object.toString
            + "  public static String ma(MA m) { return m.toString(); }\n"
            + "}\n";

    /** Executed (javaagent-b r1299/fx, JDK 21): {@code viaObjectOwner} over an {@code H} wrote the file, over a {@code K}
     *  read the clock; {@code ma(new MB())} wrote the file; {@code mo(new R1())}/{@code mo(new R2())} ran the pure
     *  overrides. On 2c5647d {@code viaObjectOwner} and {@code mo} were charged {@code Env} from {@code Un}/{@code MO} —
     *  types the receiver can never hold (commons-beanutils {@code ConverterFacade.toString}, spring
     *  {@code MethodOverrideCallbackFilter.accept}). The must-still-charge rows are asserted first. */
    @Test
    void anObjectOwnedDispatchIsBoundedByTheReceiversDeclaredType() throws Exception {
        Path cls = TestCompiler.compile(Map.of("rq/W.java", SRC_W, "rz/Z.java", SRC_R1299));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            EffectSet via = inf.getOrDefault("rz.Z.viaObjectOwner", EffectSet.empty());
            assertTrue(via.contains(Effect.FS) && via.contains(Effect.CLOCK), "both Cv bodies still charge — got " + via);
            assertTrue(inf.getOrDefault("rz.Z.ma", EffectSet.empty()).contains(Effect.FS),
                    "an abstract class's hashCode still runs through its concrete subclass MB");
            EffectSet any = inf.getOrDefault("rz.Z.anyObject", EffectSet.empty());
            assertTrue(any.contains(Effect.ENV) && any.contains(Effect.FS), "an Object-typed receiver may be anything — got " + any);
            assertFalse(via.contains(Effect.ENV), "R1299: Un and MO are not Cv — got " + via);
            EffectSet mo = inf.getOrDefault("rz.Z.mo", EffectSet.empty());
            assertFalse(mo.contains(Effect.ENV) || mo.contains(Effect.CLOCK) || mo.contains(Effect.UNKNOWN),
                    "R1299: every concrete MO declares a pure toString; abstract MO never runs Object.toString — got " + mo);
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }
}
