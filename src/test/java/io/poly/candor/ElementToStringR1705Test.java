package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1705 — A JDK BODY THAT STRINGIFIES THE ELEMENTS OF AN ARRAY ARGUMENT, AND A LOGGER'S VARARGS. Every {@code w*}
 * method read a file on JDK 21 through {@code Bad}'s {@code toString}/{@code hashCode} (executed:
 * {@code javaagent-r1705/fx} q.Arr, and {@code logv} with slf4j 2.0.13 and a provider that formats) and read ABSENT on
 * 75ebbf7 and on published 0.41.3: the operand travels in a varargs pack, and only {@code String.format} had a route.
 * {@code ext.Logger} is deleted before the scan so it is an EXTERNAL logger owner, as slf4j's is. The {@code k*} controls
 * must stay clean: pure elements, and a formatter whose {@code %s} never runs the {@code hashCode} its {@code %h} would.
 */
class ElementToStringR1705Test {

    static final String BAD = ""
            + "package q;\n"
            + "public class Bad {\n"
            + "  static void hit() { try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of(\"/etc/hosts\")); } catch (Exception e) {} }\n"
            + "  @Override public String toString() { hit(); return \"b\"; }\n"
            + "  @Override public int hashCode() { hit(); return 1; }\n"
            + "}\n";
    static final String HASHY = ""
            + "package q;\n"
            + "public class Hashy {\n"
            + "  @Override public String toString() { return \"h\"; }\n"
            + "  @Override public int hashCode() { Bad.hit(); return 1; }\n"
            + "}\n";
    static final String LOGGER = "package ext;\npublic interface Logger { void info(String f, Object... a); }\n";
    static final String USE = ""
            + "package q;\n"
            + "import java.util.*;\n"
            + "public class Use {\n"
            + "  static final java.io.PrintStream NUL = new java.io.PrintStream(java.io.OutputStream.nullOutputStream());\n"
            + "  static final Bad[] FIELD = { new Bad() };\n"
            + "  static ext.Logger LOG;\n"
            + "  public static String wFormatted() { return \"%s\".formatted(new Bad()); }\n"
            + "  public static String wMsgFmt() { return java.text.MessageFormat.format(\"{0}\", new Bad()); }\n"
            + "  public static void wPrintf() { NUL.printf(\"%s\", new Bad()); }\n"
            + "  public static void wFormatter() { new Formatter().format(\"%s\", new Bad()); }\n"
            + "  public static String wArrStr() { return Arrays.toString(new Object[]{new Bad()}); }\n"
            + "  public static String wDeepStr() { return Arrays.deepToString(new Object[]{new Bad()}); }\n"
            + "  public static String wArrStrField() { return Arrays.toString(FIELD); }\n"
            + "  public static String wFormattedField() { return \"%s\".formatted((Object[]) FIELD); }\n"
            + "  static String pArrStr(Object o) { return Arrays.toString(new Object[]{o}); }\n"
            + "  static String pFormatted(Object o) { return \"%s\".formatted(o); }\n"
            + "  static int pObjHash(Object o) { return Objects.hash(o); }\n"
            + "  static int pArrHash(Object o) { return Arrays.hashCode(new Object[]{o}); }\n"
            + "  static String qArrStr(Object[] a) { return Arrays.toString(a); }\n"
            + "  public static String wParamArrStr() { return pArrStr(new Bad()); }\n"
            + "  public static String wParamFormatted() { return pFormatted(new Bad()); }\n"
            + "  public static int wParamObjHash() { return pObjHash(new Bad()); }\n"
            + "  public static int wParamArrHash() { return pArrHash(new Bad()); }\n"
            + "  public static String wArrayParam() { return qArrStr(new Object[]{new Bad()}); }\n"
            + "  public static void wLogThree() { LOG.info(\"{} {} {}\", new Bad(), 1, 2); }\n"
            + "  public static String uFormattedOpaque() { List<Object> l = new ArrayList<>(); l.add(new Bad()); return \"%s\".formatted(l.get(0)); }\n"
            + "  public static String kFormattedPure() { return \"%s\".formatted(\"s\"); }\n"
            + "  public static String kArrStrPure() { return Arrays.toString(new Object[]{\"s\", 1}); }\n"
            + "  public static String kMsgFmtPure() { return java.text.MessageFormat.format(\"{0}\", 3); }\n"
            + "  public static String kFormatNoHash() { return pFormatted(new Hashy()); }\n"
            + "}\n";

    @Test
    void anArrayElementsStringificationIsCharged() throws Exception {
        Path cls = TestCompiler.compile(Map.of("q/Bad.java", BAD, "q/Hashy.java", HASHY, "ext/Logger.java", LOGGER, "q/Use.java", USE));
        try {
            Files.delete(cls.resolve("ext/Logger.class"));   // an EXTERNAL logger owner, as slf4j's
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String w : List.of("wFormatted", "wMsgFmt", "wPrintf", "wFormatter", "wArrStr", "wDeepStr", "wArrStrField",
                    "wFormattedField", "wParamArrStr", "wParamFormatted", "wParamObjHash", "wParamArrHash", "wArrayParam", "wLogThree"))
                assertTrue(inf.getOrDefault("q.Use." + w, EffectSet.empty()).contains(Effect.FS), "R1705: " + w + " — got " + inf.get("q.Use." + w));
            // an element known only as Object, from a producer that names no class: disclosed, as String.format's is (R1217 S5)
            assertTrue(inf.getOrDefault("q.Use.uFormattedOpaque", EffectSet.empty()).contains(Effect.UNKNOWN),
                    "R1705: uFormattedOpaque — got " + inf.get("q.Use.uFormattedOpaque"));
            for (String k : List.of("kFormattedPure", "kArrStrPure", "kMsgFmtPure", "kFormatNoHash")) {
                EffectSet e = inf.getOrDefault("q.Use." + k, EffectSet.empty());
                assertFalse(e.contains(Effect.FS) || e.contains(Effect.UNKNOWN), "control " + k + " — got " + e);
            }
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }
}
