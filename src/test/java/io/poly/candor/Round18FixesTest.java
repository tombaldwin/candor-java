package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Sweep 2026-06-17 teeth: the AS-EFF-008 masking guard, generalized from Net to ALL FOUR allowlisted
 * effects ([0]). A program-NAMING Exec call / path-establishing Fs call / SQL-establishing Db call with a
 * RUNTIME (non-literal) locator marks the effect's surface INCOMPLETE, so a benign sibling literal can no
 * longer mask the invisible forbidden endpoint. (The fabrication carve-outs [21]/[22] are teethed at the
 * classify boundary in HelpersTest; the prefix narrowing [2] by the κ-ledger soundness probes.)
 */
class Round18FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-r18");
        List<String> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path p = dir.resolve(e.getKey());
            Files.createDirectories(p.getParent());
            Files.writeString(p, e.getValue());
            files.add(p.toString());
        }
        Path out = dir.resolve("cls");
        Files.createDirectories(out);
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        args.addAll(files);
        org.junit.jupiter.api.Assertions.assertEquals(
                0, jc.run(null, null, null, args.toArray(new String[0])), "fixture must compile");
        return out;
    }

    private static void rm(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

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
            assertTrue(AnalysisState.surfaceIncomplete.getOrDefault("app.M.maskExec", new TreeSet<>()).contains("Exec"),
                    "runtime Exec command must mark the surface incomplete");
            assertFalse(AnalysisState.surfaceIncomplete.getOrDefault("app.M.cleanExec", new TreeSet<>()).contains("Exec"),
                    "a benign literal command must NOT be incomplete");
            assertTrue(AnalysisState.surfaceIncomplete.getOrDefault("app.M.maskFs", new TreeSet<>()).contains("Fs"),
                    "runtime Fs path must mark the surface incomplete");
            assertFalse(AnalysisState.surfaceIncomplete.getOrDefault("app.M.cleanFs", new TreeSet<>()).contains("Fs"),
                    "a benign literal path must NOT be incomplete");
        } finally { rm(cls.getParent()); }
    }
}
