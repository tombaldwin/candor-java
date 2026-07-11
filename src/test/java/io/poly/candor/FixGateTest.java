package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.Effector;
import io.poly.candor.model.EffectorKind;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * fix / fix-gate (integrations/FIX-SPEC.md) — the boundary FIX, the remedial inverse of whatif and the port
 * of candor-query's `fix`. When a function performs an effect its layer forbids, candor computes where the
 * effect belongs (hoist to the nearest allowed-layer caller) and which functions become pure. The orderflow
 * ground truth: {@code api.getQuote → domain.quoteBulk → domain.priceQuote → infra.fetchRate}, all carrying
 * Net, the leaf performing it directly; {@code deny Net domain} makes the two domain functions a violation
 * whose site is the infra leaf and whose hoist target is the api caller.
 */
class FixGateTest {

    @BeforeEach void fresh() { Candor.resetState(); }

    /** Write the orderflow report's callgraph sidecar beside {@code <dir>/r.json} and return that report
     *  path (the file itself need not exist — fix/fix-gate take the effector list directly). */
    private static String orderflowGraph(Path dir) throws Exception {
        String cg = "{"
                + "\"of.api.Api.getQuote\":[\"of.domain.Pricing.quoteBulk\"],"
                + "\"of.domain.Pricing.quoteBulk\":[\"of.domain.Pricing.priceQuote\"],"
                + "\"of.domain.Pricing.priceQuote\":[\"of.infra.Rates.fetchRate\"],"
                + "\"of.infra.Rates.fetchRate\":[]}";
        Files.writeString(dir.resolve("r.callgraph.json"), cg);
        return dir.resolve("r.json").toString();
    }

    private static List<Effector> orderflowFns() {
        return List.of(
                eff("of.api.Api.getQuote", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.domain.Pricing.quoteBulk")),
                eff("of.domain.Pricing.quoteBulk", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.domain.Pricing.priceQuote")),
                eff("of.domain.Pricing.priceQuote", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.infra.Rates.fetchRate")),
                eff("of.infra.Rates.fetchRate", EffectSet.of(Effect.NET), EffectSet.of(Effect.NET), List.of()));
    }

    @Test void fixGateCollapsesInheritorsToOneRemedy(@TempDir Path dir) throws Exception {
        // The two domain functions both carry Net — ONE root cause. The dedup must collapse them to a single
        // plan (same site, same hoist), the shape the edit-time loop folds into its block message.
        String report = orderflowGraph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net domain\n");

        String out = capture(() -> Query.fixGate(orderflowFns(), report, pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertFalse(o.get("ok").getAsBoolean(), "a crossing exists → not ok");
        JsonArray rem = o.getAsJsonArray("remedies");
        assertEquals(1, rem.size(), "the two domain inheritors collapse to one remedy");
        JsonObject r0 = rem.get(0).getAsJsonObject();
        assertEquals("domain", r0.get("layer").getAsString());
        assertTrue(r0.get("cleanHoist").getAsBoolean(), "a clean hoist exists");
        assertEquals("of.infra.Rates.fetchRate", r0.getAsJsonArray("site").get(0).getAsString());
        assertEquals("of.api.Api.getQuote", r0.getAsJsonArray("hoistTo").get(0).getAsString());
        assertEquals(2, r0.getAsJsonArray("deniedSpan").size(), "the pure span is the two domain functions");
        assertEquals("allow Net domain", r0.get("policyAlternative").getAsString());
    }

    @Test void fixHoistsNetToApi(@TempDir Path dir) throws Exception {
        // Single-function `fix`: the same cut, addressed at the violating function by name.
        String report = orderflowGraph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net domain\n");

        String out = capture(() -> Query.fix(orderflowFns(), report, "priceQuote", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals("of.domain.Pricing.priceQuote", o.get("fn").getAsString());
        assertEquals("of.infra.Rates.fetchRate", o.getAsJsonArray("site").get(0).getAsString());
        assertEquals("of.api.Api.getQuote", o.getAsJsonArray("hoistTo").get(0).getAsString());
    }

    @Test void fixSurfacesHigherHoistTradeoff(@TempDir Path dir) throws Exception {
        // With an allowed-layer entry point ABOVE the minimal frontier, candor surfaces the trade-off: the
        // minimal hoist is still api.getQuote, but Main.run (which calls it, also allowed) is a higher option.
        String cg = "{"
                + "\"Main.run\":[\"of.api.Api.getQuote\"],"
                + "\"of.api.Api.getQuote\":[\"of.domain.Pricing.quoteBulk\"],"
                + "\"of.domain.Pricing.quoteBulk\":[\"of.domain.Pricing.priceQuote\"],"
                + "\"of.domain.Pricing.priceQuote\":[\"of.infra.Rates.fetchRate\"],"
                + "\"of.infra.Rates.fetchRate\":[]}";
        Files.writeString(dir.resolve("r.callgraph.json"), cg);
        String report = dir.resolve("r.json").toString();
        List<Effector> fns = List.of(
                eff("Main.run", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.api.Api.getQuote")),
                eff("of.api.Api.getQuote", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.domain.Pricing.quoteBulk")),
                eff("of.domain.Pricing.quoteBulk", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.domain.Pricing.priceQuote")),
                eff("of.domain.Pricing.priceQuote", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.infra.Rates.fetchRate")),
                eff("of.infra.Rates.fetchRate", EffectSet.of(Effect.NET), EffectSet.of(Effect.NET), List.of()));
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net domain\n");

        String out = capture(() -> Query.fix(fns, report, "priceQuote", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals("of.api.Api.getQuote", o.getAsJsonArray("hoistTo").get(0).getAsString(), "minimal frontier unchanged");
        assertEquals("Main.run", o.getAsJsonArray("hoistHigher").get(0).getAsString(), "Main.run is the higher option");
    }

    @Test void fixGateCleanReportIsOk(@TempDir Path dir) throws Exception {
        // A scope pattern that matches no function → ok:true, empty remedies.
        String report = orderflowGraph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net nonexistentlayer\n");

        String out = capture(() -> Query.fixGate(orderflowFns(), report, pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertTrue(o.get("ok").getAsBoolean(), "no crossing → ok");
        assertEquals(0, o.getAsJsonArray("remedies").size());
    }

    @Test void fixUnreadablePolicyExits2(@TempDir Path dir) throws Exception {
        // Same fail-loud contract as whatif: a specified-but-unreadable policy must exit 2, never emit a plan.
        String report = orderflowGraph(dir);
        String bogus = dir.resolve("does-not-exist.policy").toString();
        int rc = Query.fix(orderflowFns(), report, "priceQuote", "Net", bogus, true);
        assertEquals(2, rc, "an unreadable policy must exit 2");
    }

    @Test void fixNoPolicyExits2(@TempDir Path dir) throws Exception {
        // No policy (and no CANDOR_POLICY) → a fix has no boundary to restore; exit 2, not an empty plan.
        String report = orderflowGraph(dir);
        int rc = Query.fix(orderflowFns(), report, "priceQuote", "Net", null, true);
        // Only assert when the environment doesn't supply a fallback policy (CI sets none).
        if (System.getenv("CANDOR_POLICY") == null) assertEquals(2, rc, "no policy must exit 2");
    }

    private static Effector eff(String fn, EffectSet inferred, EffectSet direct, List<String> calls) {
        return new Effector(fn, "", inferred, List.of(), direct, EffectSet.empty(),
                EffectSet.empty(), EffectSet.empty(), false, inferred.hasUnknown(), EffectorKind.FUNCTION,
                List.of(), "", calls, List.of(), List.of(), List.of(), List.of(), List.of());
    }

    private static String capture(Runnable r) {
        PrintStream orig = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buf));
        try {
            r.run();
        } finally {
            System.setOut(orig);
        }
        return buf.toString();
    }
}
