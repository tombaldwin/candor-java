package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * TRUE-FORWARDING for deferred-execution containers. A deferred lambda stored in a FIELD and FORCED at a
 * getter/reader otherwise reads silent-pure (a cardinal under-report): the effect is charged only to the
 * constructor (the lambda-construction over-approximation) and the lambda body, NOT the forcing site that
 * actually RUNS it. We bind, PER FIELD, the lambda stored into a recognised container ({@code
 * ThreadLocal.withInitial} here — the kotlin {@code by lazy} lane is teethed by the KotlinProbe soundness
 * run, which needs kotlinc) and edge the forcing call ({@code ThreadLocal.get}) to it, even across classes.
 *
 * FIELD-SCOPED, not class-scoped: a forcing site edges ONLY to lambdas stored in the SPECIFIC field being
 * forced, so a pure-init container's reader stays pure (no flooding). The three tests cover repro B
 * (cross-class force), the no-fabrication control (pure init → pure reader), and the multi-field control
 * (a pure field's reader must not inherit a sibling effectful field's effect).
 */
class DeferredForwardingTest {

    /** Repro B: an INSTANCE-field ThreadLocal whose initial-value Supplier writes a file, forced by a
     *  reader IN ANOTHER CLASS ({@code t.tl.get()}). The reader must carry Fs (not silent-pure). The
     *  lambda body and the constructor carry Fs too; the FORCING method gaining Fs is the new behaviour. */
    @Test
    void threadLocalForceForwardsAcrossClasses() throws Exception {
        Path cls = compile(Map.of("app/Ti.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "class Ti {",
            "  final ThreadLocal<Integer> tl = ThreadLocal.withInitial(() -> {",
            "    try { new FileOutputStream(\"/tmp/t\").write(1); } catch (Exception e) {}",
            "    return 42; });",
            "}",
            "class TiReader { int read(Ti t) { return t.tl.get(); } }")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.TiReader.read", EffectSet.empty()).toNames().contains("Fs"),
                    "cross-class ThreadLocal.get force site must carry the stored Supplier's Fs — got "
                            + r.get("app.TiReader.read"));
        } finally { rm(cls.getParent()); }
    }

    /** No-fabrication control: a PURE-init ThreadLocal's reader must STAY pure — the stored lambda has no
     *  effect, so field-scoped forwarding adds nothing. (Forwarding that flooded would tag this Fs.) */
    @Test
    void pureInitContainerReaderStaysPure() throws Exception {
        Path cls = compile(Map.of("app/P.java", String.join("\n",
            "package app;",
            "class P { final ThreadLocal<Integer> tl = ThreadLocal.withInitial(() -> 1 + 1); }",
            "class R { int read(P p) { return p.tl.get(); } }")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.R.read", EffectSet.empty()).isEmpty(),
                    "a pure-init container's reader must stay pure (no fabrication) — got " + r.get("app.R.read"));
        } finally { rm(cls.getParent()); }
    }

    /** Multi-field control: a class with TWO ThreadLocal fields — one pure-init, one effectful-init. The
     *  reader of the PURE field must NOT inherit the effectful field's effect — proving the forwarding is
     *  FIELD-SCOPED, not class-scoped (the property that prevents flooding). */
    @Test
    void forwardingIsFieldScopedNotClassScoped() throws Exception {
        Path cls = compile(Map.of("app/M.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "class M {",
            "  final ThreadLocal<Integer> pure = ThreadLocal.withInitial(() -> 7);",
            "  final ThreadLocal<Integer> eff  = ThreadLocal.withInitial(() -> {",
            "    try { new FileOutputStream(\"/tmp/m\").write(1); } catch (Exception e) {}",
            "    return 9; });",
            "  int readPure() { return pure.get(); }",
            "  int readEff()  { return eff.get(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.M.readEff", EffectSet.empty()).toNames().contains("Fs"),
                    "the effectful field's reader must carry Fs — got " + r.get("app.M.readEff"));
            assertFalse(r.getOrDefault("app.M.readPure", EffectSet.empty()).toNames().contains("Fs"),
                    "the pure field's reader must NOT inherit the sibling effectful field's Fs (field-scoping) — got "
                            + r.get("app.M.readPure"));
        } finally { rm(cls.getParent()); }
    }
}
