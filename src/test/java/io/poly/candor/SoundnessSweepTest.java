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
 * A curated CARDINAL-SIN regression guard distilled from an adversarial soundness sweep (~63 fixtures,
 * each performing a real effect through an effect-hiding construct). Every case here exercises a DISTINCT
 * engine path where a real effect could read silently pure. The bar: a function that performs an effect
 * must NOT report it as absent — surfacing the precise effect, or at minimum a disclosed {@code Unknown},
 * is acceptable; a silent-pure (empty) result is the cardinal sin. (Effect-hiding patterns specific to the
 * lambda-forwarding and closed-enum features have their own dedicated tests.)
 */
class SoundnessSweepTest {

    private static Map<String, TreeSet<String>> scan(String src) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-sweep");
        try {
            Path f = dir.resolve("A.java");
            Files.writeString(f, src);
            Path out = dir.resolve("cls");
            Files.createDirectories(out);
            assertEquals(0, jc.run(null, null, null, "-d", out.toString(), f.toString()), "fixture must compile");
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

    /** Asserts {@code fn} surfaces {@code want} (the precise effect) — a silent-pure here is the cardinal sin. */
    private static void mustHave(Map<String, TreeSet<String>> r, String fn, String want) {
        assertTrue(eff(r, fn).contains(want), fn + " must surface " + want + " (cardinal sin if pure), got " + eff(r, fn));
    }

    /** Asserts {@code fn} is at least DISCLOSED (the precise effect or {@code Unknown}) — never silent-pure. */
    private static void mustNotBePure(Map<String, TreeSet<String>> r, String fn, String want) {
        TreeSet<String> got = eff(r, fn);
        assertTrue(got.contains(want) || got.contains("Unknown"),
                fn + " must surface " + want + " or Unknown (never silent pure), got " + got);
    }

    private static final String NET = "try{new java.net.Socket(\"h\",80);}catch(Exception ex){}";
    private static final String FS = "try{new java.io.FileOutputStream(\"f\").write(1);}catch(Exception ex){}";

    /** Monomorphic-receiver narrowing must NOT narrow away a real target: a branch-merged receiver whose
     *  one arm has an effectful override keeps the CHA over-approximation (the round-where-this-could-break). */
    @Test
    void monomorphicNarrowingKeepsBranchMergedEffect() throws Exception {
        var r = scan("class Base { void foo(){} }\n"
                + "class Dirty extends Base { void foo(){ " + NET + " } }\n"
                + "public class A { public void use(boolean c){ Base b = c ? new Base() : new Dirty(); b.foo(); } }");
        mustHave(r, "A.use", "Net");
    }

    /** A receiver reassigned across a branch must keep the effectful candidate (no false monomorphic narrow). */
    @Test
    void reassignedReceiverKeepsEffect() throws Exception {
        var r = scan("class Base { void foo(){} }\n"
                + "class Dirty extends Base { void foo(){ " + FS + " } }\n"
                + "public class A { public void use(boolean c){ Base b = new Base(); if(c) b = new Dirty(); b.foo(); } }");
        mustHave(r, "A.use", "Fs");
    }

    /** A polymorphic param receiver with an effectful subtype override must not read pure. */
    @Test
    void polymorphicParamReceiverNotPure() throws Exception {
        var r = scan("class Base { void foo(){} }\n"
                + "class Dirty extends Base { void foo(){ " + FS + " } }\n"
                + "public class A { public void use(Base b){ b.foo(); } }");
        mustNotBePure(r, "A.use", "Fs");
    }

    /** Effect in an instance-initializer block (runs in every constructor) must reach the {@code new} site. */
    @Test
    void instanceInitializerEffect() throws Exception {
        var r = scan("public class A { { " + FS + " } public void use(){ new A(); } }");
        mustHave(r, "A.use", "Fs");
    }

    /** Effect in a superclass constructor reached via implicit {@code super()}. */
    @Test
    void superConstructorEffect() throws Exception {
        var r = scan("class Base { Base(){ " + NET + " } }\n"
                + "public class A extends Base { public void use(){ new A(); } }");
        mustHave(r, "A.use", "Net");
    }

    /** Effect in a {@code finally} block. */
    @Test
    void finallyBlockEffect() throws Exception {
        var r = scan("public class A { public void use(){ try { int x=1; } finally { " + FS + " } } }");
        mustHave(r, "A.use", "Fs");
    }

    /** Effect in an {@code AutoCloseable.close()} reached via try-with-resources. */
    @Test
    void tryWithResourcesCloseEffect() throws Exception {
        var r = scan("class Res implements AutoCloseable { public void close(){ " + NET + " } }\n"
                + "public class A { public void use(){ try (Res r = new Res()){ int x=1; } catch(Exception e){} } }");
        mustHave(r, "A.use", "Net");
    }

    /** Effect in a custom {@code Iterator.next()} driven by a for-each loop. */
    @Test
    void customIteratorEffect() throws Exception {
        var r = scan("import java.util.*;\n"
                + "class Bag implements Iterable<String> {\n"
                + "  public Iterator<String> iterator(){ return new Iterator<String>(){\n"
                + "    public boolean hasNext(){ return false; }\n"
                + "    public String next(){ " + NET + " return null; } }; } }\n"
                + "public class A { public void use(Bag b){ for (String s : b){} } }");
        mustHave(r, "A.use", "Net");
    }

    /** Effect in a stream pipeline stage ({@code peek}). */
    @Test
    void streamStageEffect() throws Exception {
        var r = scan("import java.util.*; import java.util.stream.*;\n"
                + "public class A { public void use(List<String> l){ l.stream().peek(s -> { " + FS + " }).count(); } }");
        mustHave(r, "A.use", "Fs");
    }

    /** Effect in an effectful {@code toString()} reached implicitly via string concatenation. */
    @Test
    void stringConcatToStringReentryEffect() throws Exception {
        var r = scan("class T { public String toString(){ " + NET + " return \"x\"; } }\n"
                + "public class A { public String use(T t){ return \"v=\" + t; } }");
        mustHave(r, "A.use", "Net");
    }

    /** Reflection must read Unknown, never silently pure. */
    @Test
    void reflectionIsUnknownNotPure() throws Exception {
        var r = scan("import java.lang.reflect.*;\n"
                + "public class A { public void use(Method m, Object o) throws Exception { m.invoke(o); } }");
        assertTrue(eff(r, "A.use").contains("Unknown"), "reflection must read Unknown, got " + eff(r, "A.use"));
    }

    /** Deferred-execution containers (ThreadLocal.withInitial, Kotlin {@code by lazy}) stow a lambda that
     *  runs at the FORCE site, not at creation. The lambda's effect must NOT be edged to the creation site
     *  (&lt;clinit&gt;/&lt;init&gt;) — else, since any static touch of the class triggers its init, the effect smears
     *  onto every such method (a fabrication found by the Kotlin sweep: a {@code by lazy { net }} flooded an
     *  unrelated fs-only method with Net). The force site must still attribute it (no under-report). */
    @Test
    void deferredContainerEffectDoesNotSmearViaClinit() throws Exception {
        var r = scan("public class A {\n"
                + "  static final ThreadLocal<String> TL = ThreadLocal.withInitial(() -> { net(); return \"x\"; });\n"
                + "  static void net(){ " + NET + " }\n"
                + "  static void fs(){ " + FS + " }\n"
                + "  public static void touchesClass(){ fs(); }\n"
                + "  public static String force(){ return TL.get(); }\n"
                + "}");
        assertFalse(eff(r, "A.touchesClass").contains("Net"),
                "deferred-lambda effect must not smear via <clinit> onto an unrelated method, got " + eff(r, "A.touchesClass"));
        assertTrue(eff(r, "A.touchesClass").contains("Fs"), "its own Fs must remain, got " + eff(r, "A.touchesClass"));
        assertTrue(eff(r, "A.force").contains("Net"),
                "the force site must still attribute the deferred lambda's Net, got " + eff(r, "A.force"));
    }

    /** The broader form of the deferred-lambda smear: a plain static/instance field holding a lambda
     *  (created in &lt;clinit&gt;/&lt;init&gt;, invoked later via a field-SAM) must not attribute its effect to the
     *  initializer — else class-init triggering smears it onto unrelated methods. The field-SAM invocation
     *  discloses Unknown instead (honest), and the initializer/neighbours stay clean. */
    @Test
    void fieldStoredLambdaDoesNotSmearViaClinit() throws Exception {
        var r = scan("public class A {\n"
                + "  static Runnable R = () -> { net(); };\n"
                + "  static void net(){ " + NET + " }\n"
                + "  static void fs(){ " + FS + " }\n"
                + "  public static void clean(){ fs(); }\n"
                + "  public static void runIt(){ R.run(); }\n"
                + "}");
        assertFalse(eff(r, "A.clean").contains("Net"),
                "a field-stored lambda's effect must not smear via <clinit> onto a neighbour, got " + eff(r, "A.clean"));
        assertTrue(eff(r, "A.clean").contains("Fs"), "its own Fs must remain, got " + eff(r, "A.clean"));
        assertFalse(eff(r, "A.runIt").isEmpty(),
                "the field-SAM invocation must disclose (Unknown), never silent-pure, got " + eff(r, "A.runIt"));
    }

    /** A lambda stored into a COLLECTION/MAP in an initializer (a registry: {@code M.put("k", () -> eff)})
     *  is stored, not invoked there — its effect must not smear via {@code <clinit>}. But an INVOKING
     *  container HOF ({@code computeIfAbsent}) must still attribute it (it runs the lambda) — the storing
     *  vs invoking distinction must be preserved. */
    @Test
    void collectionStoredLambdaDoesNotSmearButInvokingHofDoes() throws Exception {
        var r = scan("import java.util.*;\n"
                + "public class A {\n"
                + "  static Map<String,Runnable> M = new HashMap<>();\n"
                + "  static { M.put(\"k\", () -> { net(); }); }\n"
                + "  static void net(){ " + NET + " }\n"
                + "  static void fs(){ " + FS + " }\n"
                + "  public static void clean(){ fs(); }\n"
                + "  public static String invoke(Map<String,String> m, String k){ return m.computeIfAbsent(k, x -> { net(); return x; }); }\n"
                + "}");
        assertFalse(eff(r, "A.clean").contains("Net"),
                "a map-stored lambda must not smear via <clinit>, got " + eff(r, "A.clean"));
        assertTrue(eff(r, "A.invoke").contains("Net"),
                "an INVOKING container HOF (computeIfAbsent) must still attribute the lambda's effect, got " + eff(r, "A.invoke"));
    }

    /** A factory method that RETURNS an effectful lambda must not be attributed the effect — it constructs
     *  the closure, it does not run it; the eventual invocation on the returned value discloses Unknown.
     *  Else the effect smears to the factory's callers, and (when called from an initializer) across the
     *  class via &lt;clinit&gt;. */
    @Test
    void factoryReturnedLambdaIsNotAttributed() throws Exception {
        var r = scan("public class A {\n"
                + "  static Runnable HANDLER = makeHandler();\n"
                + "  static Runnable makeHandler(){ return () -> { net(); }; }\n"
                + "  static void net(){ " + NET + " }\n"
                + "  static void fs(){ " + FS + " }\n"
                + "  public static void clean(){ fs(); }\n"
                + "}");
        assertFalse(eff(r, "A.makeHandler").contains("Net"),
                "a factory that returns (does not run) a lambda must not be attributed its effect, got " + eff(r, "A.makeHandler"));
        assertFalse(eff(r, "A.clean").contains("Net"),
                "the returned-lambda effect must not smear via <clinit>, got " + eff(r, "A.clean"));
    }

    /** No-over-suppression control: a lambda PASSED TO A CALL that runs it (a stream stage) must STILL be
     *  attributed — the escape detection must only fire for store/return, never for an invoking consumer. */
    @Test
    void lambdaPassedToInvokerIsStillAttributed() throws Exception {
        var r = scan("import java.util.*; import java.util.stream.*;\n"
                + "public class A { public void use(List<String> l){ l.forEach(s -> { " + NET + " }); } }");
        assertTrue(eff(r, "A.use").contains("Net"),
                "a lambda passed to an invoking consumer (forEach) must still attribute its effect, got " + eff(r, "A.use"));
    }

    /** No-fabrication control: a genuinely pure version of the trickiest shape stays pure. */
    @Test
    void pureControlStaysPure() throws Exception {
        var r = scan("class Base { void foo(){} }\n"
                + "class Clean extends Base { void foo(){ int x = 1; } }\n"
                + "public class A { public void use(){ Base b = new Clean(); b.foo(); } }");
        assertFalse(eff(r, "A.use").contains("Net"), "must not fabricate Net, got " + eff(r, "A.use"));
        assertFalse(eff(r, "A.use").contains("Fs"), "must not fabricate Fs, got " + eff(r, "A.use"));
    }

    /** A NAMED class implementing a JDK functional interface, handed to an EXTERNAL HOF that invokes its
     *  SAM outside project code (`Stream.forEach`), must surface the SAM's effect. A lambda/method-ref in
     *  the SAME position is sound (edged at its indy), so a silent-pure here was an INTERNAL asymmetry —
     *  the named-instance-into-library-HOF cardinal sin (found by the novel-constructs sweep). */
    @Test
    void namedFunctionalInstanceIntoLibraryHofNotPure() throws Exception {
        var r = scan("import java.util.stream.*; import java.util.function.*;\n"
                + "public class A {\n"
                + "  static class Eff implements Consumer<String> { public void accept(String s){ " + FS + " } }\n"
                + "  public void use(){ Stream.of(\"x\").forEach(new Eff()); }\n"
                + "}");
        mustHave(r, "A.use", "Fs");
    }

    /** The anti-fabrication anchor for the fix above: a named functional instance only STORED in a
     *  container (never invoked) must stay PURE — the storing-container gate must keep the fix from
     *  over-reporting, exactly as a stored lambda stays pure. */
    @Test
    void namedFunctionalInstanceStoredStaysPure() throws Exception {
        var r = scan("import java.util.*; import java.util.function.*;\n"
                + "public class A {\n"
                + "  static class Eff implements Consumer<String> { public void accept(String s){ " + FS + " } }\n"
                + "  public void use(){ List<Consumer<String>> b = new ArrayList<>(); b.add(new Eff()); }\n"
                + "}");
        assertFalse(eff(r, "A.use").contains("Fs"),
                "stored-not-invoked must not fabricate Fs, got " + eff(r, "A.use"));
    }

    /** A named `java.util.Comparator` with an effectful `compare`, handed to a library sort API
     *  (`List.sort`/`Collections.sort`/`Stream.sorted`/`new TreeMap`), must surface the effect. Comparator
     *  is a SAM the JDK invokes outside project code but is NOT in `java.util.function.*` — the
     *  named-instance fix had to recognise it explicitly (the sort/TreeMap idiom is ubiquitous). */
    @Test
    void namedComparatorIntoSortNotPure() throws Exception {
        var r = scan("import java.util.*;\n"
                + "public class A {\n"
                + "  static class Cmp implements Comparator<String> { public int compare(String a,String b){ " + FS + " return 0; } }\n"
                + "  public void use(List<String> xs){ xs.sort(new Cmp()); }\n"
                + "}");
        mustHave(r, "A.use", "Fs");
    }

    /** `java.lang.System.Logger` (the JDK 9+ platform logging facade) must classify its `log` emit as Log,
     *  consistently with java.util.logging/slf4j/log4j. It was absent from the Log owner gate → silent-pure
     *  (found by the κ-coverage audit). Verb-precise: isLoggable/getName stay pure (no Log fabrication). */
    @Test
    void systemLoggerEmitsLog() throws Exception {
        var r = scan("public class A { public void use(System.Logger l){ l.log(System.Logger.Level.INFO, \"x\"); } }");
        mustHave(r, "A.use", "Log");
    }
}
