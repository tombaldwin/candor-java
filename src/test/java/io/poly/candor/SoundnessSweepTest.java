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

    /** No-fabrication control: a genuinely pure version of the trickiest shape stays pure. */
    @Test
    void pureControlStaysPure() throws Exception {
        var r = scan("class Base { void foo(){} }\n"
                + "class Clean extends Base { void foo(){ int x = 1; } }\n"
                + "public class A { public void use(){ Base b = new Clean(); b.foo(); } }");
        assertFalse(eff(r, "A.use").contains("Net"), "must not fabricate Net, got " + eff(r, "A.use"));
        assertFalse(eff(r, "A.use").contains("Fs"), "must not fabricate Fs, got " + eff(r, "A.use"));
    }
}
