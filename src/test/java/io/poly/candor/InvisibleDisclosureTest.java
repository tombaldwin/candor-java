package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Teeth for the per-method BLIND-SPOT honesty disclosure: a `pure`-looking method that reaches an external
 * package candor cannot analyse must carry that package in `invisible`, so `inferred` is never an unqualified
 * completeness claim. The blind lib is compiled to a SEPARATE dir (off the scan path) so it's genuinely
 * external; a method with no blind reach carries no `invisible`.
 *
 * <p>Originally review round 17 (Round17FixesTest).
 */
class InvisibleDisclosureTest {

    @SuppressWarnings("unchecked")
    @Test
    void pureMethodDisclosesUnanalysablePackages() throws Exception {
        // the external "blind" library goes on the classpath but NEVER on the scan path; the app —
        // which uses it — is scanned alone (the two-phase harness).
        Path appCls = compileApp(
            Map.of("Widget.java", "package com.obscure.lib; public class Widget { public void doStuff(){} }"),
            Map.of("A.java", String.join("\n",
                "package app;",
                "public class A {",
                "  public void looksPure(com.obscure.lib.Widget w){ w.doStuff(); }",  // blind reach → invisible
                "  public void caller(com.obscure.lib.Widget w){ looksPure(w); }",    // transitive
                "  public void trulyPure(int x){ int y = x + 1; }",                   // no blind reach
                "}")));
        Path dir = appCls.getParent();
        Path out = dir.resolve("r.json");
        try {
            Map<String, EffectSet> inf = Candor.runScan(appCls);
            ReportWriter.writeJson(inf, out.toString());
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
