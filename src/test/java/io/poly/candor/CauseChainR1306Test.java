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
 * SOUNDNESS R1306 — {@code printStackTrace} prints the CAUSE (and suppressed) chain, running each throwable's toString,
 * and a re-entry body {@code chaTargets} HELD BACK at the bound was dropped silently. Each {@code w*} wrote a file on
 * JDK 21 (javaagent-c fx/r1305, fx/r1306): {@code wCause} prints a JDK exception whose cause's getMessage writes;
 * {@code wPst}/{@code wConcat} reach fifteen project exceptions that inherit {@code Throwable.toString}, one of whose
 * getMessage writes — past the bound, so the answer must be a disclosure. The controls are the same shapes over a
 * hierarchy whose every getMessage is a constant.
 */
class CauseChainR1306Test {

    static Map<String, String> sources(String pkg, boolean effectful) {
        Map<String, String> m = new HashMap<>();
        m.put(pkg + "/W.java", "package " + pkg + ";\nclass W { static void hit() { try { java.nio.file.Files.writeString("
                + "java.nio.file.Path.of(\"/nonexistent-r1306/x\"), \"x\"); } catch (Exception e) {} } }\n");
        for (int i = 1; i <= 14; i++)
            m.put(pkg + "/P" + i + ".java", "package " + pkg + ";\nclass P" + i + " extends RuntimeException { @Override public String getMessage() { return \"p\"; } }\n");
        m.put(pkg + "/M.java", "package " + pkg + ";\nclass M extends RuntimeException { @Override public String getMessage() { "
                + (effectful ? "W.hit(); " : "") + "return \"m\"; } }\n");
        m.put(pkg + "/Use.java", "package " + pkg + ";\npublic class Use {\n"
                + "  public static void wPst(Throwable t) { t.printStackTrace(new java.io.PrintStream(java.io.OutputStream.nullOutputStream())); }\n"
                + "  public static String wConcat(Throwable t) { return \"x\" + t; }\n"
                + "  public static void wCause(M c) { new RuntimeException(\"outer\", c).printStackTrace(new java.io.PrintStream(java.io.OutputStream.nullOutputStream())); }\n"
                + "}\n");
        return m;
    }

    @Test
    void theCauseChainAndHeldReentriesAreNotSilent() throws Exception {
        Map<String, String> src = new HashMap<>(sources("ra", true));
        Path cls = TestCompiler.compile(src);
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String w : new String[] {"wPst", "wConcat", "wCause"}) {
                EffectSet e = inf.getOrDefault("ra.Use." + w, EffectSet.empty());
                assertTrue(e.contains(Effect.FS) || e.contains(Effect.UNKNOWN), "R1306: " + w + " — got " + e);
            }
        } finally {
            TestCompiler.rm(cls.getParent());
        }
        Path ctl = TestCompiler.compile(new HashMap<>(sources("rb", false)));
        try {
            Map<String, EffectSet> inf = Candor.runScan(ctl);
            for (String w : new String[] {"wPst", "wConcat", "wCause"}) {
                EffectSet e = inf.getOrDefault("rb.Use." + w, EffectSet.empty());
                assertFalse(e.contains(Effect.FS) || e.contains(Effect.UNKNOWN), "control " + w + " — got " + e);
            }
        } finally {
            TestCompiler.rm(ctl.getParent());
        }
    }
}
