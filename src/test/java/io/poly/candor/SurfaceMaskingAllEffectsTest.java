package io.poly.candor;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Sweep 2026-06-17 teeth: the AS-EFF-008 masking guard, generalized from Net to ALL FOUR allowlisted
 * effects ([0]). A program-NAMING Exec call / path-establishing Fs call / SQL-establishing Db call with a
 * RUNTIME (non-literal) locator marks the effect's surface INCOMPLETE, so a benign sibling literal can no
 * longer mask the invisible forbidden endpoint. (The fabrication carve-outs [21]/[22] are teethed at the
 * classify boundary in HelpersTest; the prefix narrowing [2] by the κ-ledger soundness probes.)
 *
 * <p>Originally review round 18 (Round18FixesTest).
 */
class SurfaceMaskingAllEffectsTest {

    /** A program-naming Exec call / path-establishing Fs call with a RUNTIME locator marks the surface
     *  incomplete (so a benign literal can't mask it); a benign-only sibling does NOT. */
    @Test
    void maskingGeneralizesToExecAndFs() throws Exception {
        Path cls = compile(Map.of("app/M.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "public class M {",
            "  void maskExec(String c) throws Exception {",
            "    Runtime.getRuntime().exec(\"git\");",          // benign literal head (captured)
            "    Runtime.getRuntime().exec(c); }",              // runtime command — INVISIBLE
            "  void cleanExec() throws Exception { Runtime.getRuntime().exec(\"git\"); }",
            "  void maskFs(String p) throws Exception {",
            "    new FileInputStream(\"/var/app/ok\").close();", // benign literal path (captured)
            "    new FileInputStream(p).close(); }",            // runtime path — INVISIBLE
            "  void cleanFs() throws Exception { new FileInputStream(\"/var/app/ok\").close(); }",
            "}")));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.M.maskExec", new TreeSet<>()).contains("Exec"),
                    "runtime Exec command must mark the surface incomplete");
            assertFalse(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.M.cleanExec", new TreeSet<>()).contains("Exec"),
                    "a benign literal command must NOT be incomplete");
            assertTrue(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.M.maskFs", new TreeSet<>()).contains("Fs"),
                    "runtime Fs path must mark the surface incomplete");
            assertFalse(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.M.cleanFs", new TreeSet<>()).contains("Fs"),
                    "a benign literal path must NOT be incomplete");
        } finally { rm(cls.getParent()); }
    }
}
