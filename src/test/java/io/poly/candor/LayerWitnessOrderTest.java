package io.poly.candor;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * AS-EFF-009's WITNESS is a fact about the call graph, not about string hashing.
 *
 * <p>{@code Policy.reachesScope} answers two things at once: WHETHER a scope is reachable — which decides
 * the violation, the count and the exit code — and WHICH node it was reached through, which is printed in
 * the diagnostic and travels in {@code --gate-json}'s machine-readable {@code detail}. The first is a set
 * property and was never in doubt. The second was decided by a depth-first walk over a stack seeded from a
 * {@code HashSet}, so the node named was whichever bucket the set handed over first — the same "walk an
 * unordered set, return the first hit" shape {@code 9f8e71c} removed from four supertype walks.
 *
 * <p>The fixture below makes the arbitrariness visible rather than arguing it: {@code app.A.run} has two
 * routes into {@code repo}, one crossing at 2 hops and one at 6, and the old walk named the 6-hop node.
 */
class LayerWitnessOrderTest {

    /** Two routes out of `run`: `direct` crosses immediately, `far0` crosses five hops later. */
    private static final Map<String, String> SRC = Map.of(
        "repo/R.java", "package repo;\npublic class R { public void hit() { System.getenv(\"X\"); } }\n",
        "app/A.java", "package app;\npublic class A {\n"
            + "  public void run() { direct(); far0(); }\n"
            + "  void direct() { new repo.R().hit(); }\n"
            + "  void far0() { far1(); }\n  void far1() { far2(); }\n"
            + "  void far2() { far3(); }\n  void far3() { new repo.R().hit(); }\n}\n");

    /** TWO crossings at the SAME depth, so nearest-first cannot separate them and only the tie-break can.
     *  The names are not arbitrary: {@code repo.R.aa} sorts BEFORE {@code repo.R.ac}, and a 16-bucket
     *  {@code HashSet} puts {@code ac} (bucket 8) before {@code aa} (bucket 10) — so the unsorted walk
     *  answers {@code ac} and the sorted one answers {@code aa}. Without this, dropping the sort passes
     *  every test in the file, and a guard that has never failed is not evidence. */
    private static final Map<String, String> TIE = Map.of(
        "repo/R.java", "package repo;\npublic class R {\n"
            + "  public static void aa() { System.getenv(\"X\"); }\n"
            + "  public static void ac() { System.getenv(\"X\"); }\n}\n",
        "app/A.java", "package app;\npublic class A {\n"
            + "  public void run() { repo.R.ac(); repo.R.aa(); }\n}\n");

    @BeforeEach void capture() { Candor.gateCapture = true; Candor.gateViolations.clear(); }
    @AfterEach void release() { Candor.gateCapture = false; Candor.gateViolations.clear(); }

    @Test
    void theLayerWitnessIsTheNEARESTCrossingAndTheVerdictIsUnchanged() throws Exception {
        Path dir = compile(SRC);
        try {
            Candor.runScan(dir);
            Path pol = dir.resolve("layer.policy");
            Files.writeString(pol, "forbid app -> repo\n");
            int v = Policy.checkPolicy(Map.of(), pol.toString());

            // The VERDICT half: every app method that reaches repo is still named, exactly as before —
            // reachability is a set property and no traversal order can change it.
            assertEquals(6, v, "run + direct + far0..far3 all reach repo");
            List<String> hit = Candor.gateViolations.stream()
                    .filter(e -> "AS-EFF-009".equals(e.get("rule")))
                    .map(e -> (String) e.get("fn")).sorted().toList();
            assertEquals(List.of("app.A.direct", "app.A.far0", "app.A.far1", "app.A.far2",
                    "app.A.far3", "app.A.run"), hit);

            // The WITNESS half. `run`'s nearest crossing is two hops away, through `direct`; the six-hop
            // route through far0..far3 arrives at the same class. A depth-first walk named the far one.
            String detail = (String) Candor.gateViolations.stream()
                    .filter(e -> "app.A.run".equals(e.get("fn"))).findFirst().orElseThrow().get("detail");
            assertTrue(detail.contains("via `repo.R.<init>`"),
                    "the witness must be the NEAREST crossing, tie-broken by name — an arbitrary one reads "
                    + "exactly like a chosen one, and it is what --gate-json publishes; got: " + detail);

            // …and it is the SAME node for every violator here, because every one of them crosses into the
            // same class. Under the old walk `run` and `direct` disagreed about which member they crossed
            // at, though the code is identical.
            for (var e : Candor.gateViolations)
                assertTrue(((String) e.get("detail")).contains("via `repo.R.<init>`"),
                        "structurally identical crossings must name the same witness; got " + e.get("detail"));
        } finally { rm(dir.getParent()); }
    }

    /** The tie-break, exercised. Both crossings are one hop away, so nearest-first says nothing and the
     *  witness is decided entirely by the order the callee set is walked in — which, unsorted, is the
     *  order a 16-bucket {@code HashSet} happens to produce, and it is the reverse of the source order,
     *  the declaration order AND the lexicographic order. */
    @Test
    void twoCrossingsAtTheSameDepthAreTieBrokenByNameNotByHash() throws Exception {
        Path dir = compile(TIE);
        try {
            Candor.runScan(dir);
            Path pol = dir.resolve("layer.policy");
            Files.writeString(pol, "forbid app -> repo\n");
            assertEquals(1, Policy.checkPolicy(Map.of(), pol.toString()));
            String detail = (String) Candor.gateViolations.stream()
                    .filter(e -> "app.A.run".equals(e.get("fn"))).findFirst().orElseThrow().get("detail");
            assertTrue(detail.contains("via `repo.R.aa`"),
                    "equidistant crossings tie-break by NAME; `repo.R.ac` is what a HashSet hands over "
                    + "first (bucket 8 vs 10) and it is what the unsorted walk answers. Got: " + detail);
        } finally { rm(dir.getParent()); }
    }
}
