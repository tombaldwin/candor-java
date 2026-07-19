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
import java.util.stream.Stream;
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

    private static Map<String, EffectSet> scan(String src) throws Exception {
        Path out = TestCompiler.compile(Map.of("A.java", src));
        try {
            return Candor.runScan(out);
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    /** Compile {@code src}, DELETE {@code deleteClass}.class (simulate an off-classpath type), then scan —
     *  for the sealed-unseen-permit gate (a permit named in `permits` but absent from the analysis classpath). */
    private static Map<String, EffectSet> scanDeleting(String src, String deleteClass) throws Exception {
        Path out = TestCompiler.compile(Map.of("A.java", src));
        try {
            Files.deleteIfExists(out.resolve(deleteClass + ".class"));
            return Candor.runScan(out);
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** Asserts {@code fn} surfaces {@code want} (the precise effect) — a silent-pure here is the cardinal sin. */
    private static void mustHave(Map<String, EffectSet> r, String fn, String want) {
        assertTrue(eff(r, fn).toNames().contains(want), fn + " must surface " + want + " (cardinal sin if pure), got " + eff(r, fn));
    }

    /** Asserts {@code fn} is at least DISCLOSED (the precise effect or {@code Unknown}) — never silent-pure. */
    private static void mustNotBePure(Map<String, EffectSet> r, String fn, String want) {
        EffectSet got = eff(r, fn);
        assertTrue(got.toNames().contains(want) || got.toNames().contains("Unknown"),
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
        assertTrue(eff(r, "A.use").toNames().contains("Unknown"), "reflection must read Unknown, got " + eff(r, "A.use"));
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
        assertFalse(eff(r, "A.touchesClass").toNames().contains("Net"),
                "deferred-lambda effect must not smear via <clinit> onto an unrelated method, got " + eff(r, "A.touchesClass"));
        assertTrue(eff(r, "A.touchesClass").toNames().contains("Fs"), "its own Fs must remain, got " + eff(r, "A.touchesClass"));
        assertTrue(eff(r, "A.force").toNames().contains("Net"),
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
        assertFalse(eff(r, "A.clean").toNames().contains("Net"),
                "a field-stored lambda's effect must not smear via <clinit> onto a neighbour, got " + eff(r, "A.clean"));
        assertTrue(eff(r, "A.clean").toNames().contains("Fs"), "its own Fs must remain, got " + eff(r, "A.clean"));
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
        assertFalse(eff(r, "A.clean").toNames().contains("Net"),
                "a map-stored lambda must not smear via <clinit>, got " + eff(r, "A.clean"));
        assertTrue(eff(r, "A.invoke").toNames().contains("Net"),
                "an INVOKING container HOF (computeIfAbsent) must still attribute the lambda's effect, got " + eff(r, "A.invoke"));
    }

    /** AccessController.doPrivileged(action) runs action.run() SYNCHRONOUSLY — a genuine invoking HOF.
     *  A named PrivilegedAction/PrivilegedExceptionAction impl whose run() performs an effect must
     *  propagate to the doPrivileged caller. Found silent-pure on commons-vfs2's PrivilegedFileReplicator
     *  (init/replicateFile → Net/Fs through a doPrivileged'd wrapped-replicator call). */
    @Test
    void doPrivilegedActionRunsSynchronouslyAndPropagates() throws Exception {
        var r = scan("import java.security.*;\n"
                + "public class A {\n"
                + "  final class NetAction implements PrivilegedAction<Object> {\n"
                + "    public Object run(){ net(); return null; }\n"
                + "  }\n"
                + "  final class FsAction implements PrivilegedExceptionAction<Object> {\n"
                + "    public Object run() throws Exception { fs(); return null; }\n"
                + "  }\n"
                + "  static void net(){ " + NET + " }\n"
                + "  static void fs(){ " + FS + " }\n"
                + "  void doNet(){ AccessController.doPrivileged(new NetAction()); }\n"
                + "  void doFs() throws Exception { AccessController.doPrivileged(new FsAction()); }\n"
                + "}");
        assertTrue(eff(r, "A.doNet").toNames().contains("Net"),
                "doPrivileged(PrivilegedAction) must propagate run()'s Net, got " + eff(r, "A.doNet"));
        assertTrue(eff(r, "A.doFs").toNames().contains("Fs"),
                "doPrivileged(PrivilegedExceptionAction) must propagate run()'s Fs, got " + eff(r, "A.doFs"));
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
        assertFalse(eff(r, "A.makeHandler").toNames().contains("Net"),
                "a factory that returns (does not run) a lambda must not be attributed its effect, got " + eff(r, "A.makeHandler"));
        assertFalse(eff(r, "A.clean").toNames().contains("Net"),
                "the returned-lambda effect must not smear via <clinit>, got " + eff(r, "A.clean"));
    }

    /** No-over-suppression control: a lambda PASSED TO A CALL that runs it (a stream stage) must STILL be
     *  attributed — the escape detection must only fire for store/return, never for an invoking consumer. */
    @Test
    void lambdaPassedToInvokerIsStillAttributed() throws Exception {
        var r = scan("import java.util.*; import java.util.stream.*;\n"
                + "public class A { public void use(List<String> l){ l.forEach(s -> { " + NET + " }); } }");
        assertTrue(eff(r, "A.use").toNames().contains("Net"),
                "a lambda passed to an invoking consumer (forEach) must still attribute its effect, got " + eff(r, "A.use"));
    }

    /** No-fabrication control: a genuinely pure version of the trickiest shape stays pure. */
    @Test
    void pureControlStaysPure() throws Exception {
        var r = scan("class Base { void foo(){} }\n"
                + "class Clean extends Base { void foo(){ int x = 1; } }\n"
                + "public class A { public void use(){ Base b = new Clean(); b.foo(); } }");
        assertFalse(eff(r, "A.use").toNames().contains("Net"), "must not fabricate Net, got " + eff(r, "A.use"));
        assertFalse(eff(r, "A.use").toNames().contains("Fs"), "must not fabricate Fs, got " + eff(r, "A.use"));
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
        assertFalse(eff(r, "A.use").toNames().contains("Fs"),
                "stored-not-invoked must not fabricate Fs, got " + eff(r, "A.use"));
    }

    /** ANTI-FABRICATION (regression for a code-review finding): a named functional instance passed to an
     *  external method that merely RECEIVES it — null-check, Optional-wrap, Comparator stored in a TreeMap
     *  ctor — must stay PURE. The first cut gated on `!isStoringContainerCall` (any external non-store),
     *  which fabricated the SAM's effect on these non-invoking sinks; the allowlist (isInvokingHof) fixes it. */
    @Test
    void namedFunctionalInstanceToNonInvokingSinkStaysPure() throws Exception {
        var r = scan("import java.util.*; import java.util.function.*;\n"
                + "public class A {\n"
                + "  static class Eff implements Consumer<String> { public void accept(String s){ " + FS + " } }\n"
                + "  static class Cmp implements Comparator<String> { public int compare(String a,String b){ " + FS + " return 0; } }\n"
                + "  public void nullCheck(){ Objects.requireNonNull(new Eff()); }\n"
                + "  public void wrap(){ Optional.ofNullable(new Eff()); }\n"
                + "  public void treeCtor(){ Map<String,Integer> m = new TreeMap<>(new Cmp()); }\n"
                + "}");
        assertFalse(eff(r, "A.nullCheck").toNames().contains("Fs"), "requireNonNull must not fabricate, got " + eff(r, "A.nullCheck"));
        assertFalse(eff(r, "A.wrap").toNames().contains("Fs"), "Optional.ofNullable must not fabricate, got " + eff(r, "A.wrap"));
        assertFalse(eff(r, "A.treeCtor").toNames().contains("Fs"), "TreeMap ctor must not fabricate, got " + eff(r, "A.treeCtor"));
    }

    /** SEALED closed-hierarchy carve-out: a sealed type with >CHA_FANOUT_LIMIT(12) FINAL permits, one
     *  effectful, resolves to the effect (the permits list is the complete target set — sound+exact past the
     *  bound, like an enum). Was `dispatch:` Unknown before the carve-out. */
    @Test
    void sealedClosedHierarchyResolvesPastBound() throws Exception {
        StringBuilder sb = new StringBuilder("sealed interface Sh permits ");
        for (int i = 1; i <= 13; i++) sb.append("X").append(i).append(i < 13 ? "," : "");
        sb.append(" { void op(); }\n");
        for (int i = 1; i <= 13; i++)
            sb.append("final class X").append(i).append(" implements Sh { public void op(){ ")
              .append(i == 6 ? FS : "").append(" } }\n");
        sb.append("public class A { public void use(Sh s){ s.op(); } }");
        var r = scan(sb.toString());
        mustHave(r, "A.use", "Fs");
    }

    /** PROVABLE-INCOMPLETENESS gate (cardinal-sin fix): a sealed type with an OFF-CLASSPATH effectful permit
     *  must disclose Unknown even on the NARROW path — candor knows (from `permits`) a subtype it can't see
     *  exists, so resolving only the visible subset would silent-pure the unseen one. */
    @Test
    void sealedUnseenPermitDisclosesUnknown() throws Exception {
        // 5 permits (≤12 → narrow); the effectful Ghost is compiled then deleted (off-classpath).
        String src = "sealed interface Sb permits Ghost,V1,V2,V3,V4 { void op(); }\n"
                + "final class Ghost implements Sb { public void op(){ " + FS + " } }\n"
                + "final class V1 implements Sb { public void op(){} }\n"
                + "final class V2 implements Sb { public void op(){} }\n"
                + "final class V3 implements Sb { public void op(){} }\n"
                + "final class V4 implements Sb { public void op(){} }\n"
                + "public class A { public void use(Sb s){ s.op(); } }";
        var r = scanDeleting(src, "Ghost");
        assertTrue(eff(r, "A.use").toNames().contains("Unknown"),
                "sealed type with an unseen effectful permit must disclose Unknown (not silent-pure), got " + eff(r, "A.use"));
    }

    /** Anti-over-disclosure for the gate above: a FULLY-VISIBLE sealed hierarchy must resolve precisely (no
     *  spurious Unknown from the provable-incompleteness check). */
    @Test
    void sealedFullyVisibleNotOverDisclosed() throws Exception {
        var r = scan("sealed interface Sv permits U1,U2,U3 { void op(); }\n"
                + "final class U1 implements Sv { public void op(){} }\n"
                + "final class U2 implements Sv { public void op(){ " + FS + " } }\n"
                + "final class U3 implements Sv { public void op(){} }\n"
                + "public class A { public void use(Sv s){ s.op(); } }");
        assertTrue(eff(r, "A.use").toNames().contains("Fs"), "must resolve, got " + eff(r, "A.use"));
        assertFalse(eff(r, "A.use").toNames().contains("Unknown"),
                "fully-visible sealed must NOT be over-disclosed Unknown, got " + eff(r, "A.use"));
    }

    /** Regression: an OPEN (non-sealed) hierarchy over the bound must STILL drop to disclosed Unknown — the
     *  bound exists to prevent open-hierarchy smear; the carve-out must not swallow it. */
    @Test
    void openHierarchyOverLimitStaysUnknown() throws Exception {
        StringBuilder sb = new StringBuilder("interface O { void op(); }\n");
        for (int i = 1; i <= 13; i++)
            sb.append("class Y").append(i).append(" implements O { public void op(){ ")
              .append(i == 6 ? FS : "").append(" } }\n");
        sb.append("public class A { public void use(O o){ o.op(); } }");
        var r = scan(sb.toString());
        assertTrue(eff(r, "A.use").toNames().contains("Unknown"),
                "open >12 hierarchy must stay disclosed-Unknown (not resolved, not silent), got " + eff(r, "A.use"));
    }

    /** A pure sealed hierarchy past the bound stays PURE (not Unknown, not a fabricated effect) — the
     *  carve-out resolves to the exact set, which is empty-effect here. */
    @Test
    void pureSealedHierarchyStaysPure() throws Exception {
        StringBuilder sb = new StringBuilder("sealed interface Sp permits ");
        for (int i = 1; i <= 13; i++) sb.append("Z").append(i).append(i < 13 ? "," : "");
        sb.append(" { void op(); }\n");
        for (int i = 1; i <= 13; i++)
            sb.append("final class Z").append(i).append(" implements Sp { public void op(){ int x=1; } }\n");
        sb.append("public class A { public void use(Sp s){ s.op(); } }");
        var r = scan(sb.toString());
        assertFalse(eff(r, "A.use").toNames().contains("Fs"), "pure sealed must not fabricate, got " + eff(r, "A.use"));
        assertFalse(eff(r, "A.use").toNames().contains("Unknown"), "pure sealed must resolve (not Unknown), got " + eff(r, "A.use"));
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
