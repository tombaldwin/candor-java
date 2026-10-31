package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Call-target round 2 — a call on a JDK stream DECORATOR whose delegate the caller does not name runs that delegate's
 * read/write, and the delegate may be a project stream ({@link JdkSites#decoratorDelegate}, the S6 floor). Found on the
 * corpus A/B as removals: commons-compress {@code ArjArchiveInputStream.read8(dis)} reads the InputStream its
 * constructor was handed through a DataInputStream; tomcat {@code PEMFile} reads a caller's InputStream through a
 * BufferedReader over an InputStreamReader. Published 0.40.17 read the decorator call pure too, and charged some of the
 * callers only through R32's by-name edges to the caller's own stream class, which never ran there.
 *
 * <p>Executed on JDK 21 (soundness/calltarget/checker/decor-fixture): {@code dis}, {@code held} and {@code lines} over a
 * {@code new In()} each wrote the file; {@code known} did not. {@code sys} reads System.in and is not run.
 */
class StreamDecoratorDelegateTest {

    static final String W = "static void hit() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-ct2/x\"), \"x\"); } catch (Exception e) { } }";

    static Map<String, String> src() {
        Map<String, String> m = new HashMap<>();
        m.put("dd/S.java", "package dd;\nclass S { " + W + " }\n");
        m.put("dd/In.java", "package dd;\nclass In extends java.io.InputStream { public int read() { S.hit(); return 'x'; } }\n");
        m.put("dd/Held.java", "package dd;\nclass Held {\n"
                + "  private final java.io.DataInputStream dis;\n"
                + "  Held(java.io.InputStream in) { dis = new java.io.DataInputStream(in); }\n"
                + "  int read8() throws java.io.IOException { return dis.readUnsignedByte(); }\n"
                + "}\n");
        m.put("dd/Use.java", "package dd;\npublic class Use {\n"
                + "  public static int dis(java.io.InputStream in) throws Exception { return new java.io.DataInputStream(in).readUnsignedByte(); }\n"
                + "  public static int held(Held h) throws Exception { return h.read8(); }\n"
                + "  public static String lines(java.io.InputStream in) throws Exception {\n"
                + "    java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(in)); return r.readLine(); }\n"
                + "  public static int known() throws Exception { return new java.io.DataInputStream(new java.io.ByteArrayInputStream(new byte[] {1})).readUnsignedByte(); }\n"
                + "  public static boolean sys() throws Exception { return new java.io.BufferedReader(new java.io.InputStreamReader(System.in)).ready(); }\n"
                + "}\n");
        return m;
    }

    @Test
    void aDecoratorOverAnUnnamedDelegateIsDisclosedAndANamedOneIsNot() throws Exception {
        Path cls = TestCompiler.compile(new HashMap<>(src()));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String w : new String[] {"dis", "lines"})
                assertTrue(inf.getOrDefault("dd.Use." + w, EffectSet.empty()).contains(Effect.UNKNOWN),
                        "a decorator over a caller's stream runs that stream (In.read writes the file): dd.Use." + w + " — got " + inf.get("dd.Use." + w));
            assertTrue(inf.getOrDefault("dd.Held.read8", EffectSet.empty()).contains(Effect.UNKNOWN),
                    "a field-held decorator over the constructor's stream: dd.Held.read8 — got " + inf.get("dd.Held.read8"));
            assertTrue(inf.getOrDefault("dd.Use.held", EffectSet.empty()).contains(Effect.UNKNOWN),
                    "…and its caller: dd.Use.held — got " + inf.get("dd.Use.held"));
            for (String w : new String[] {"known", "sys"})
                assertFalse(inf.getOrDefault("dd.Use." + w, EffectSet.empty()).contains(Effect.UNKNOWN),
                        "the delegate is named here (a JDK stream built in place / System.in): dd.Use." + w + " — got " + inf.get("dd.Use." + w));
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    @Test
    void theTableNamesTheDecorators() {
        assertTrue(JdkSites.delegateBases("java/io/DataInputStream").contains("java/io/InputStream"));
        assertTrue(JdkSites.delegateBases("java/io/InputStreamReader").contains("java/io/InputStream"));
        assertTrue(JdkSites.delegateBases("java/io/BufferedReader").contains("java/io/Reader"));
        assertTrue(JdkSites.delegateBases("java/io/FileReader").isEmpty() || !JdkSites.delegateBases("java/io/FileReader").contains("java/io/InputStream"),
                "FileReader opens a file; it wraps no caller stream");
        assertTrue(JdkSites.delegateBases("java/io/ByteArrayInputStream").isEmpty());
    }
}
