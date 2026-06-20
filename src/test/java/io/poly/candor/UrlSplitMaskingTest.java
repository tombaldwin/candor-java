package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * AS-EFF-008 URL split construct-then-use gate EVASION (sweep follow-up to [0]/Round18). The Net effect of
 * `URL.openStream()`/`openConnection()`/`getContent()` fires on the TERMINAL, but the host is fixed at a
 * SEPARATE `new URL(String)` CONSTRUCTION (no Net effect, no String arg on the terminal). So
 * `new URL(getenv).openStream()` reaches a fully runtime-controlled host while a benign sibling
 * `new URL("good").openStream()` populated the host surface and MASKED it. The fix fails CLOSED — marks Net
 * incomplete — when no host literal is cheaply attributable to the terminal's receiver, while still
 * certifying the common inline-literal-URL form (and the const-URL-local split).
 */
class UrlSplitMaskingTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-url");
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
        assertEquals(0, jc.run(null, null, null, args.toArray(new String[0])), "fixture must compile");
        return out;
    }

    private static void rm(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Test
    void urlSplitConstructUseFailsClosed() throws Exception {
        Path cls = compile(Map.of("app/Clean.java", String.join("\n",
            "package app;",
            "import java.net.*;",
            "public class Clean {",
            // EVASION: a benign visible literal URL alongside an attacker-controlled runtime host.
            "  void evil() throws Exception {",
            "    new URL(\"https://good.com\").openStream();",
            "    new URL(System.getenv(\"TARGET\")).openStream(); }",
            // COMMON CASE: a single inline-literal URL — must NOT be over-flagged.
            "  void inline() throws Exception {",
            "    new URL(\"https://good.com/api\").openStream(); }",
            // SPLIT-but-literal: `URL u = new URL(\"lit\"); u.openStream();` — host still attributable.
            "  void splitLiteral() throws Exception {",
            "    URL u = new URL(\"https://good.com/api\");",
            "    u.openStream(); }",
            // SPLIT-runtime via local: a runtime-built URL through a local — must fail closed.
            "  void splitRuntime() throws Exception {",
            "    URL u = new URL(System.getenv(\"TARGET\"));",
            "    u.openStream(); }",
            // TRANSITIVE: op() calls both the benign and the evil leaf; op must inherit incompleteness.
            "  void op() throws Exception { good(); attacker(); }",
            "  void good() throws Exception { new URL(\"https://good.com\").openStream(); }",
            "  void attacker() throws Exception { new URL(System.getenv(\"TARGET\")).openStream(); }",
            "}")));
        try {
            Candor.runScan(cls);
            Map<String, TreeSet<String>> inc = Literals.literalFixpoint(Candor.surfaceIncomplete);

            // The mixed evasion method is incomplete (the runtime host masks behind the benign literal).
            assertTrue(inc.getOrDefault("app.Clean.evil", new TreeSet<>()).contains("Net"),
                    "runtime URL host alongside a benign literal must mark Net incomplete (fail-closed)");

            // The COMMON inline-literal-URL case is NOT over-flagged — it still certifies.
            assertFalse(inc.getOrDefault("app.Clean.inline", new TreeSet<>()).contains("Net"),
                    "an inline literal URL must NOT be incomplete (must still certify)");
            assertTrue(Candor.hostsDirect.getOrDefault("app.Clean.inline", new TreeSet<>()).contains("good.com"),
                    "an inline literal URL host must be captured");

            // A split-but-literal URL through a const local still attributes its host.
            assertFalse(inc.getOrDefault("app.Clean.splitLiteral", new TreeSet<>()).contains("Net"),
                    "a const-URL-local split with a literal host must NOT be incomplete");
            assertTrue(Candor.hostsDirect.getOrDefault("app.Clean.splitLiteral", new TreeSet<>()).contains("good.com"),
                    "a const-URL-local split must capture its literal host");

            // A runtime URL through a local fails closed.
            assertTrue(inc.getOrDefault("app.Clean.splitRuntime", new TreeSet<>()).contains("Net"),
                    "a runtime URL through a local must mark Net incomplete");

            // The transitive caller inherits incompleteness from the attacker leaf.
            assertTrue(inc.getOrDefault("app.Clean.op", new TreeSet<>()).contains("Net"),
                    "a caller reaching the runtime-URL leaf must inherit Net incompleteness");
        } finally { rm(cls.getParent()); }
    }
}
