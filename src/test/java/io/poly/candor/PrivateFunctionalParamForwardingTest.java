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
 * Teeth for PRIVATE FUNCTIONAL-PARAM FORWARDING ({@link Candor#isForwardableFunctionalSink} +
 * {@code fwdSink*}). A {@code private} method that invokes its sole functional-interface parameter is a
 * CLOSED sink — its call sites are all nestmates, so the set of lambdas reaching the param is fully
 * enumerable. When every call site passes a fresh PROJECT lambda, the param's SAM resolves to those
 * bodies instead of a {@code callback:} Unknown that would otherwise smear across the sink's callers
 * (the jsoup {@code Tag.setupTags(String[], Consumer)} pattern: pure lambdas whose Unknown reached every
 * function touching {@code Tag} via the {@code <clinit>} trigger).
 *
 * <p>Bail directions (each keeps the honest Unknown — never silently pure): a non-private sink (external
 * callers unknown); a call site passing an opaque (field/param) handler; a class field of the functional
 * type (the SAM might be on the field, not the param).
 */
class PrivateFunctionalParamForwardingTest {

    private static Map<String, TreeSet<String>> compileAndScan(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-fwd");
        try {
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
            return Candor.runScan(out);
        } finally {
            try (Stream<Path> s = Files.walk(dir)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static TreeSet<String> eff(Map<String, TreeSet<String>> r, String fn) {
        return r.getOrDefault(fn, new TreeSet<>());
    }

    /** The win + no-fabrication anchor: a private Consumer-sink invoked only with PURE inline lambdas is
     *  pure (no callback Unknown), and so are its callers — the smear is gone, nothing fabricated. */
    @Test
    void pureLambdasThroughPrivateSinkStayPure() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("A.java", String.join("\n",
            "import java.util.function.Consumer;",
            "public class A {",
            "  private static void each(String[] xs, Consumer<String> c){ for (String x : xs) c.accept(x); }",
            "  static int n;",
            "  void use(){ each(new String[]{\"a\"}, s -> { n++; }); }",  // pure lambda (field write on a static int is not an effect)
            "}")));
        assertFalse(eff(r, "A.each").contains("Unknown"),
                "a private Consumer-sink called only with project lambdas must NOT read callback Unknown, got " + r.get("A.each"));
        assertTrue(eff(r, "A.each").isEmpty(), "pure lambdas → the sink is pure, got " + r.get("A.each"));
        assertTrue(eff(r, "A.use").isEmpty(), "the caller stays pure, got " + r.get("A.use"));
    }

    /** Soundness: a private Consumer-sink invoked with an EFFECTFUL project lambda surfaces that effect on
     *  the sink (Net), not Unknown — the lambda body is resolved through the closed call site. */
    @Test
    void effectfulLambdaThroughPrivateSinkSurfaces() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("B.java", String.join("\n",
            "import java.util.function.Consumer;",
            "public class B {",
            "  private static void each(String[] xs, Consumer<String> c){ for (String x : xs) c.accept(x); }",
            "  void use(){ each(new String[]{\"h\"}, s -> { try { new java.net.Socket(s,80); } catch(Exception e){} }); }",
            "}")));
        assertTrue(eff(r, "B.each").contains("Net"),
                "the effectful lambda's Net must surface on the resolved sink, got " + r.get("B.each"));
        assertFalse(eff(r, "B.each").contains("Unknown"), "the sink is resolved — no Unknown, got " + r.get("B.each"));
        assertTrue(eff(r, "B.use").contains("Net"), "the caller performs the lambda's Net, got " + r.get("B.use"));
    }

    /** Bail #1 — an OPAQUE call site: the same private sink is also called with a field-stored handler whose
     *  body candor cannot see, so the param could be anything → the sink keeps its honest callback Unknown. */
    @Test
    void opaqueCallSiteKeepsUnknown() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("C.java", String.join("\n",
            "import java.util.function.Consumer;",
            "public class C {",
            "  Consumer<String> handler;",   // NOTE: a field of the functional type alone also bails (#3)
            "  private static void each(String[] xs, Consumer<String> c){ for (String x : xs) c.accept(x); }",
            "  void lambdaUse(){ each(new String[]{\"a\"}, s -> {}); }",
            "  void opaqueUse(){ each(new String[]{\"a\"}, handler); }",  // opaque arg — unresolvable
            "}")));
        assertTrue(eff(r, "C.each").contains("Unknown"),
                "a sink with an opaque call site must keep callback Unknown (no silent pure), got " + r.get("C.each"));
    }

    /** Bail #2 — a NON-private sink: a public method's call sites are not enumerable (an external caller may
     *  pass any handler), so it must keep the honest Unknown even when every visible call site is a lambda. */
    @Test
    void publicSinkKeepsUnknown() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("D.java", String.join("\n",
            "import java.util.function.Consumer;",
            "public class D {",
            "  public static void each(String[] xs, Consumer<String> c){ for (String x : xs) c.accept(x); }",
            "  void use(){ each(new String[]{\"a\"}, s -> {}); }",
            "}")));
        assertTrue(eff(r, "D.each").contains("Unknown"),
                "a public functional-param sink must keep Unknown (external callers unknown), got " + r.get("D.each"));
    }
}
