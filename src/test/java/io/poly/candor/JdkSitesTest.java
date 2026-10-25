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
 * Call-target round 2 — the derived JDK site table ({@link JdkSites}), pinned on the shapes the hand tables missed or
 * got wrong. Each positive wrote a file when run on JDK 21 (the call-target matrix executes every one:
 * soundness/calltarget h_skel_*, h_thread, h_serial, x_skel_copyctor, x_skip_inherited, x_write_inherited) and each
 * control did not (nl_skip_overridden, nl_skip_own, c_skel_isempty — R1441 and R1242's own caution).
 */
class JdkSitesTest {

    static final String W = "static void hit() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-ct2/x\"), \"x\"); } catch (Exception e) { } }";

    static Map<String, String> src() {
        Map<String, String> m = new HashMap<>();
        m.put("st/S.java", "package st;\nclass S { " + W + " }\n");
        m.put("st/L.java", "package st;\nabstract class L extends java.util.AbstractList<Object> { public int size() { return 1; } }\n");
        m.put("st/LW.java", "package st;\nclass LW extends L { public Object get(int i) { S.hit(); return \"w\"; } }\n");
        m.put("st/Th.java", "package st;\nclass Th extends Thread { public void run() { S.hit(); } }\n");
        m.put("st/Ser.java", "package st;\nclass Ser implements java.io.Serializable { private void writeObject(java.io.ObjectOutputStream o) throws java.io.IOException { S.hit(); o.defaultWriteObject(); } }\n");
        m.put("st/C.java", "package st;\nabstract class C extends java.util.AbstractCollection<Object> { public int size() { return 0; } }\n");
        m.put("st/CW.java", "package st;\nclass CW extends C { public java.util.Iterator<Object> iterator() { S.hit(); return java.util.Collections.emptyIterator(); } }\n");
        m.put("st/In.java", "package st;\nclass In extends java.io.InputStream { public int read() { S.hit(); return -1; } }\n");
        m.put("st/InSkip.java", "package st;\nclass InSkip extends java.io.InputStream { public int read() { S.hit(); return -1; } public long skip(long n) { return n; } }\n");
        m.put("st/Use.java", "package st;\npublic class Use {\n"
                + "  public static boolean contains(L l) { return l.contains(\"z\"); }\n"
                + "  public static boolean isEmpty(L l) { return l.isEmpty(); }\n"
                + "  public static void start(Th t) { t.start(); }\n"
                + "  public static void ser(Ser s) throws Exception { new java.io.ObjectOutputStream(java.io.OutputStream.nullOutputStream()).writeObject(s); }\n"
                + "  public static Object copy(C c) { return new java.util.ArrayList<>(c); }\n"
                + "  public static long skip(In i) throws Exception { return i.skip(3); }\n"
                + "  public static long skipOverridden(InSkip i) { return i.skip(3); }\n"
                + "}\n");
        return m;
    }

    @Test
    void theDerivedSitesChargeWhatRunsAndNotWhatDoesNot() throws Exception {
        Path cls = TestCompiler.compile(new HashMap<>(src()));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String w : new String[] {"contains", "start", "ser", "copy", "skip"})
                assertTrue(inf.getOrDefault("st.Use." + w, EffectSet.empty()).contains(Effect.FS),
                        "the JDK body re-enters an effectful override: st.Use." + w + " — got " + inf.get("st.Use." + w));
            for (String w : new String[] {"isEmpty", "skipOverridden"})
                assertFalse(inf.getOrDefault("st.Use." + w, EffectSet.empty()).contains(Effect.FS),
                        "the JDK body never runs the effectful member (R1441 / R1242's caution): st.Use." + w + " — got " + inf.get("st.Use." + w));
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    @Test
    void theTableIsLoadedAndNamesTheHandTablesItReplaced() {
        assertTrue(JdkSites.size() > 10000, "jdk-sites.idx.gz is missing or truncated: " + JdkSites.size());
        assertTrue(JdkSites.at("java/lang/Object", "toString", "()Ljava/lang/String;") != null, "R1235: Object.toString -> hashCode");
        assertTrue(JdkSites.argsHooking("java/lang/RuntimeException", "<init>", "(Ljava/lang/Throwable;)V", "toString()Ljava/lang/String;").length == 1,
                "R1305: RuntimeException(Throwable) stringifies its cause");
        assertTrue(JdkSites.at("java/io/InputStream", "skip", "(J)J") != null, "R32: InputStream.skip re-enters read");
        assertTrue(JdkSites.at("java/lang/Thread", "start", "()V") != null, "the residual: Thread.start -> run");
    }
}
