package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Teeth for the per-method BLIND-SPOT honesty disclosure: a `pure`-looking method that reaches an external
 * package candor cannot analyse must carry that package in `invisible`, so `inferred` is never an unqualified
 * completeness claim. The blind lib is compiled to a SEPARATE dir (off the scan path) so it's genuinely
 * external; a method with no blind reach carries no `invisible`.
 */
class Round17FixesTest {

    private static void rm(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    void pureMethodDisclosesUnanalysablePackages() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-blind");
        // (1) the external "blind" library — compiled to libcls, NEVER on the scan path
        Path libSrc = dir.resolve("Widget.java");
        Files.writeString(libSrc, "package com.obscure.lib; public class Widget { public void doStuff(){} }");
        Path libCls = dir.resolve("libcls");
        Files.createDirectories(libCls);
        assertEquals(0, jc.run(null, null, null, "-d", libCls.toString(), libSrc.toString()), "lib compiles");
        // (2) the app — uses the blind lib (on classpath) but is scanned alone
        Path appSrc = dir.resolve("A.java");
        Files.writeString(appSrc, String.join("\n",
            "package app;",
            "public class A {",
            "  public void looksPure(com.obscure.lib.Widget w){ w.doStuff(); }",  // blind reach → invisible
            "  public void caller(com.obscure.lib.Widget w){ looksPure(w); }",    // transitive
            "  public void trulyPure(int x){ int y = x + 1; }",                   // no blind reach
            "}"));
        Path appCls = dir.resolve("appcls");
        Files.createDirectories(appCls);
        assertEquals(0, jc.run(null, null, null, "-cp", libCls.toString(), "-d", appCls.toString(), appSrc.toString()),
                "app compiles");
        Path out = dir.resolve("r.json");
        try {
            Map<String, java.util.TreeSet<String>> inf = Candor.runScan(appCls);
            Report.writeJson(inf, out.toString());
            Map<String, Object> report = new Gson().fromJson(Files.readString(out), Map.class);
            List<Map<String, Object>> fns = (List<Map<String, Object>>) report.get("functions");
            Map<String, List<String>> invisibleByFn = new java.util.HashMap<>();
            Map<String, List<String>> inferredByFn = new java.util.HashMap<>();
            for (Map<String, Object> e : fns) {
                invisibleByFn.put((String) e.get("fn"), (List<String>) e.getOrDefault("invisible", List.of()));
                inferredByFn.put((String) e.get("fn"), (List<String>) e.getOrDefault("inferred", List.of()));
            }
            // looksPure: pure effect set BUT discloses the unanalysable package (honesty)
            assertTrue(inferredByFn.getOrDefault("app.A.looksPure", List.of()).isEmpty(),
                    "looksPure has no inferred effect");
            assertTrue(invisibleByFn.getOrDefault("app.A.looksPure", List.of()).contains("com.obscure.lib"),
                    "a pure method reaching an unanalysable package must disclose it in `invisible`, got "
                            + invisibleByFn.get("app.A.looksPure"));
            // caller: inherits the blind spot transitively
            assertTrue(invisibleByFn.getOrDefault("app.A.caller", List.of()).contains("com.obscure.lib"),
                    "the blind spot propagates to the transitive caller");
            // trulyPure: no blind reach → no invisible (and may be omitted entirely)
            assertFalse(invisibleByFn.getOrDefault("app.A.trulyPure", List.of()).contains("com.obscure.lib"),
                    "a method with no blind reach must NOT disclose one");
        } finally { rm(dir); }
    }
}
