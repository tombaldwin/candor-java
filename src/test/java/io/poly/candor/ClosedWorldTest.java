package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * CANDOR_CLOSED_WORLD — a broad (>CHA_FANOUT_LIMIT) dispatch over a PROJECT-DEFINED type resolves to the
 * exact union of its impls instead of dropping to Unknown. DEFAULT (no flag) keeps the sound conservative
 * Unknown; the flag is the user's explicit "the scanned classes are the complete world" assertion. Gated to
 * project types, so an external/library broad hierarchy still bounds (it stays Unknown even under the flag).
 */
class ClosedWorldTest {

    @Test
    void closedWorldResolvesBroadProjectDispatch_defaultStaysUnknown() throws Exception {
        // a project interface with 13 impls (> the fan-out limit of 12), ALL pure; and a 14-impl interface
        // where exactly one impl does Fs — so a sound resolution is pure / {Fs} respectively (not Unknown).
        StringBuilder id = new StringBuilder("package app;\ninterface Id { String getId(); }\n");
        for (int i = 1; i <= 13; i++) id.append("class P").append(i).append(" implements Id { public String getId(){ return \"p").append(i).append("\"; } }\n");
        StringBuilder op = new StringBuilder("package app;\ninterface Op { void run() throws Exception; }\n");
        op.append("class O0 implements Op { public void run() throws Exception { new java.io.FileInputStream(\"x\").read(); } }\n");
        for (int i = 1; i <= 13; i++) op.append("class O").append(i).append(" implements Op { public void run(){} }\n");
        Path cls = compile(Map.of(
            "app/Id.java", id.toString(),
            "app/Op.java", op.toString(),
            "app/Use.java", String.join("\n",
                "package app;",
                "public class Use {",
                "  public static String pureDispatch(Id x){ return x.getId(); }",            // 13 pure impls > 12
                "  public static void mixedDispatch(Op o) throws Exception { o.run(); } }"))); // 14 impls, one Fs
        try {
            // DEFAULT: a broad dispatch is honest Unknown.
            Map<String, EffectSet> def = Candor.runScan(cls);
            assertTrue(eff(def, "app.Use.pureDispatch").contains(Effect.UNKNOWN),
                "default: a broad >12 dispatch must stay Unknown, got " + def.get("app.Use.pureDispatch"));
            assertTrue(eff(def, "app.Use.mixedDispatch").contains(Effect.UNKNOWN),
                "default: a broad >12 dispatch must stay Unknown, got " + def.get("app.Use.mixedDispatch"));

            // CLOSED-WORLD: resolves to the EXACT union of the (complete) project impl set.
            Candor.forceClosedWorld = true;
            Map<String, EffectSet> cw = Candor.runScan(cls);
            assertTrue(eff(cw, "app.Use.pureDispatch").isEmpty(),
                "closed-world: all-pure impls → pure (no Unknown), got " + cw.get("app.Use.pureDispatch"));
            EffectSet mixed = eff(cw, "app.Use.mixedDispatch");
            assertTrue(mixed.contains(Effect.FS), "closed-world: the heterogeneous union must carry Fs, got " + mixed);
            assertFalse(mixed.contains(Effect.UNKNOWN), "closed-world: a resolved dispatch must not also be Unknown, got " + mixed);
        } finally {
            Candor.forceClosedWorld = false;
            rm(cls.getParent());
        }
    }

    // ── harness ─────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

}
