package io.poly.candor;

import com.google.gson.Gson;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import io.poly.candor.model.EffectSet;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * AN Unknown ON THE WIRE MUST CARRY THE MARKER THAT SAYS WHY — INCLUDING WHEN IT WAS INHERITED.
 *
 * <p>{@code unknownWhy} is DIRECT by contract ("why Unknown was emitted HERE, not inherited"), because
 * its other consumers — {@code candor blindspots}, the `Unknown sources (direct)` summary — want SOURCES.
 * So a dependency unit whose Unknown came from a callee publishes {@code inferred: ['Unknown']} with no
 * {@code unknownWhy} at all, and ⟨0.19⟩'s boundary fix ({@code 6ab26e4}), which carries the dep's own
 * tags across, has nothing to carry. One hop past where that fix looked, the reason class dies and the
 * reason-scoped gate fails OPEN:
 *
 * <pre>
 *   lib.Deep.go      ['Unknown']  unknownWhy ['reflect:java.lang.Class.forName', …]
 *   lib.Shallow.call ['Unknown']  unknownWhy ABSENT           calls ['lib.Deep.go']
 *
 *   deny Net Unknown[reflect] app    one scan over both trees     1 violation
 *                                    app chaining lib's report    0            <- fail-OPEN
 * </pre>
 *
 * <p>The dependency's report already held the answer: {@code calls} (SPEC §2) is its effect-relevant local
 * call graph, which is exactly the edge set an Unknown propagates along. No format change — the consumer
 * simply never looked.
 *
 * <p>Every test here asserts BOTH directions. A "fix" that made every reason-scoped rule bite everything
 * would pass the reflect arm and is caught by the native arm beside it.
 */
class TransitiveUnknownReasonTest {

    /** {@code Deep.go} reflects (a `reflect:` Unknown); {@code Shallow.call} only calls it, so its own
     *  Unknown is INHERITED and its report entry carries no reason. */
    private static final Map<String, String> LIB = Map.of(
        "lib/Deep.java", "package lib;\npublic class Deep {\n"
            + "  public void go() throws Exception { Class.forName(\"x.Y\").getMethod(\"m\").invoke(null); }\n}\n",
        "lib/Shallow.java", "package lib;\npublic class Shallow {\n"
            + "  public void call() throws Exception { new Deep().go(); }\n}\n");

    /** TWO hops from the reason: `A.run` -> `Shallow.call` -> `Deep.go`. */
    private static final Map<String, String> APP_TWO_HOP = Map.of(
        "app/A.java", "package app;\npublic class A {\n"
            + "  public void run() throws Exception { new lib.Shallow().call(); }\n}\n");

    /** ONE hop — `6ab26e4`'s shape, which already worked. The control that proves the two-hop failure is
     *  about the extra hop and not about chaining in general. */
    private static final Map<String, String> APP_ONE_HOP = Map.of(
        "app/B.java", "package app;\npublic class B {\n"
            + "  public void run() throws Exception { new lib.Deep().go(); }\n}\n");

    private record Chained(Map<String, EffectSet> inferred, Path base) {}

    /** Scan `app` alone with `lib`'s own report chained. Leaves the context populated so the caller can run
     *  the gate against it; the caller must {@code rm(base)}. */
    private static Chained scanChained(Map<String, String> app) throws Exception {
        Path appDir = compileApp(LIB, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path depReport = base.resolve("dep.json");
            Files.deleteIfExists(depReport);        // standing-bar item 7: never read a stale arm
            Candor.config = Config.empty();
            // Produced by THIS build, so §2.1 trusts it — a stale report forces Unknown WITHOUT reading any
            // surface array, which would mask exactly what this test measures.
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            return new Chained(Candor.runScan(appDir), base);
        } finally {
            Candor.config = saved;
        }
    }

    /** Run ONE rule against an already-scanned context. {@code parsePolicy} APPENDS, so without the clear
     *  a second call evaluates both rules and every count is the running total — which is how this helper
     *  first "found" a defect that was entirely its own (standing-bar item 7d). */
    private static int violations(Map<String, EffectSet> inferred, Path dir, String rule) throws Exception {
        AnalysisState.ctx().denyRules.clear();
        AnalysisState.ctx().allowRules.clear();
        AnalysisState.ctx().forbidRules.clear();
        Path p = dir.resolve(rule.replaceAll("[^a-zA-Z]", "") + ".policy");
        Files.writeString(p, rule + "\n");
        return Policy.checkPolicy(inferred, p.toString());
    }

    /** The single-tree control: everything in one scan, where the reason class travels the project call
     *  graph and the gate fires. This is the answer the chained arrangement has to reproduce. */
    @Test
    void singleTreeControlFiresOnReflectAndToleratesNative() throws Exception {
        Map<String, String> both = new java.util.HashMap<>(LIB);
        both.putAll(APP_TWO_HOP);
        Path dir = compile(both);
        try {
            Map<String, EffectSet> inferred = Candor.runScan(dir);
            assertTrue(inferred.get("app.A.run").toNames().contains("Unknown"), "two hops still reach Unknown");
            assertEquals(1, violations(inferred, dir, "deny Net Unknown[reflect] app"),
                    "control: a reflection-caused Unknown two hops down fires a reflect-scoped deny");
            assertEquals(0, violations(inferred, dir, "deny Net Unknown[native] app"),
                    "control: and a native-scoped deny still tolerates it");
        } finally { rm(dir.getParent()); }
    }

    /** THE DEFECT, and the reason it was invisible: bare {@code deny Net Unknown} fired the whole time —
     *  the Unknown WAS there, only its class was missing, so only a reason-SCOPED rule could see it. */
    @Test
    void aTwoHopChainedUnknownCarriesItsReasonClass() throws Exception {
        Chained c = scanChained(APP_TWO_HOP);
        try {
            assertTrue(c.inferred().get("app.A.run").toNames().contains("Unknown"),
                    "the Unknown crosses the boundary (it always did)");
            assertEquals(1, violations(c.inferred(), c.base(), "deny Net Unknown app"),
                    "bare deny Unknown fires — which is why the missing CLASS was invisible");
            assertEquals(1, violations(c.inferred(), c.base(), "deny Net Unknown[reflect] app"),
                    "an Unknown the dependency INHERITED must still arrive with its reason class, or a "
                    + "reason-scoped gate silently degrades to `some Unknown, cause unknown` exactly at "
                    + "the boundary");
            assertEquals(0, violations(c.inferred(), c.base(), "deny Net Unknown[native] app"),
                    "and the scoping must keep discriminating — a fix that made every reason-scoped rule "
                    + "bite everything would pass the assertion above and fail this one");
        } finally { rm(c.base()); }
    }

    /** The ONE-hop control (`6ab26e4`'s shape). It passed before this change and must still pass: the
     *  two-hop failure was about the extra hop, not about chaining. */
    @Test
    void aOneHopChainedUnknownStillCarriesItsReasonClass() throws Exception {
        Chained c = scanChained(APP_ONE_HOP);
        try {
            assertEquals(1, violations(c.inferred(), c.base(), "deny Net Unknown[reflect] app"),
                    "the direct-reason boundary case must be untouched");
            assertEquals(0, violations(c.inferred(), c.base(), "deny Net Unknown[native] app"));
        } finally { rm(c.base()); }
    }

    /** The dependency's report is what makes this possible, and it is worth asserting rather than assuming:
     *  the inherited-Unknown entry publishes NO {@code unknownWhy} (the field is direct-by-contract, and
     *  that stays true — {@code candor blindspots} reads it as a source list) but DOES publish the
     *  {@code calls} edge that names where the reason lives. If either half of this ever changes, the
     *  consumer-side walk is reading something that is no longer there. */
    @SuppressWarnings("unchecked")
    @Test
    void theDependencyReportCarriesTheChainButNotTheInheritedReason() throws Exception {
        Path libDir = compile(LIB);
        try {
            Path out = libDir.resolveSibling("dep.json");
            Files.deleteIfExists(out);                     // standing-bar item 7
            Config saved = Candor.config;
            try {
                Candor.config = Config.empty();
                ReportWriter.writeJson(Candor.runScan(libDir), out.toString());
            } finally { Candor.config = saved; }
            Map<String, Object> root = new Gson().fromJson(Files.readString(out), Map.class);
            Map<String, Object> deep = null, shallow = null;
            for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions")) {
                if ("lib.Deep.go".equals(e.get("fn"))) deep = e;
                if ("lib.Shallow.call".equals(e.get("fn"))) shallow = e;
            }
            assertNotNull(deep); assertNotNull(shallow);
            assertTrue(((List<String>) deep.get("unknownWhy")).stream().anyMatch(w -> w.startsWith("reflect:")),
                    "the SOURCE unit publishes its reason");
            assertEquals(null, shallow.get("unknownWhy"),
                    "the INHERITING unit publishes none — `unknownWhy` is direct by contract, and that is "
                    + "the property this whole test class exists because of");
            assertEquals(List.of("lib.Deep.go"), shallow.get("calls"),
                    "…but §2 `calls` names where the reason lives, so no format rung is needed");
            assertEquals(true, shallow.get("unresolved"),
                    "the tier-1 trust marker itself does NOT fail open — it is the reason CLASS that did");
        } finally { rm(libDir.getParent()); }
    }
}
