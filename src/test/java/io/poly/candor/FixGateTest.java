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

        String out = capture(() -> Query.fixGate(orderflowFns(), report, report, pol.toString(), true, false));
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

        String out = capture(() -> Query.fix(orderflowFns(), report, report, "priceQuote", "Net", pol.toString(), true));
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

        String out = capture(() -> Query.fix(fns, report, report, "priceQuote", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals("of.api.Api.getQuote", o.getAsJsonArray("hoistTo").get(0).getAsString(), "minimal frontier unchanged");
        assertEquals("Main.run", o.getAsJsonArray("hoistHigher").get(0).getAsString(), "Main.run is the higher option");
    }

    @Test void fixPrefersTheEffectPerformingMatch(@TempDir Path dir) throws Exception {
        // A bare leaf `save` matches BOTH a pure `Cache.save` and the effectful, denied `Repo.save`.
        // Resolution must prefer the effect-performing match — else `fix save Net` gives a false all-clear.
        Files.writeString(dir.resolve("r.callgraph.json"), "{\"Cache.save\":[],\"Repo.save\":[]}");
        String report = dir.resolve("r.json").toString();
        List<Effector> fns = List.of(
                eff("Cache.save", EffectSet.empty(), EffectSet.empty(), List.of()),
                eff("Repo.save", EffectSet.of(Effect.NET), EffectSet.of(Effect.NET), List.of()));
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net Repo\n");
        String out = capture(() -> Query.fix(fns, report, report, "save", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals("Repo.save", o.get("fn").getAsString(), "must resolve to the effectful, denied match");
    }

    @Test void fixSandwichedLayerIsNotACleanHoist(@TempDir Path dir) throws Exception {
        // domain.top → api.mid → domain.inner → infra.fetch, `deny Net domain`. api.mid is the nearest allowed
        // frontier, but domain.top CALLS it → hoisting Net there leaves top violating → NOT a clean hoist.
        String cg = "{\"domain.Dom.top\":[\"api.Api.mid\"],\"api.Api.mid\":[\"domain.Dom.inner\"],"
                + "\"domain.Dom.inner\":[\"infra.Infra.fetch\"],\"infra.Infra.fetch\":[]}";
        Files.writeString(dir.resolve("r.callgraph.json"), cg);
        String report = dir.resolve("r.json").toString();
        List<Effector> fns = List.of(
                eff("domain.Dom.top", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("api.Api.mid")),
                eff("api.Api.mid", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("domain.Dom.inner")),
                eff("domain.Dom.inner", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("infra.Infra.fetch")),
                eff("infra.Infra.fetch", EffectSet.of(Effect.NET), EffectSet.of(Effect.NET), List.of()));
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net domain\n");
        String out = capture(() -> Query.fix(fns, report, report, "inner", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(false, o.get("cleanHoist").getAsBoolean(), "a sandwiched frontier is NOT a clean hoist");
    }

    @Test void fixGateCleanReportIsOk(@TempDir Path dir) throws Exception {
        // A scope pattern that matches no function → ok:true, empty remedies.
        String report = orderflowGraph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net nonexistentlayer\n");

        String out = capture(() -> Query.fixGate(orderflowFns(), report, report, pol.toString(), true, false));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertTrue(o.get("ok").getAsBoolean(), "no crossing → ok");
        assertEquals(0, o.getAsJsonArray("remedies").size());
    }

    @Test void fixUnreadablePolicyExits2(@TempDir Path dir) throws Exception {
        // Same fail-loud contract as whatif: a specified-but-unreadable policy must exit 2, never emit a plan.
        String report = orderflowGraph(dir);
        String bogus = dir.resolve("does-not-exist.policy").toString();
        int rc = Query.fix(orderflowFns(), report, report, "priceQuote", "Net", bogus, true);
        assertEquals(2, rc, "an unreadable policy must exit 2");
    }

    @Test void fixNoPolicyExits2(@TempDir Path dir) throws Exception {
        // No policy (and no CANDOR_POLICY) → a fix has no boundary to restore; exit 2, not an empty plan.
        String report = orderflowGraph(dir);
        int rc = Query.fix(orderflowFns(), report, report, "priceQuote", "Net", null, true);
        // Only assert when the environment doesn't supply a fallback policy (CI sets none).
        if (System.getenv("CANDOR_POLICY") == null) assertEquals(2, rc, "no policy must exit 2");
    }

    @Test void unverifiedFlagsAnUnknownInScope(@TempDir Path dir) throws Exception {
        // domain.price is Unknown (a fn-value call) → `pure domain` PASSES it, but its purity is unverified.
        // `unverified` flags it + names the `deny Unknown domain` upgrade; the provably-pure domain.calc isn't.
        List<Effector> fns = List.of(
                eff("domain.price", EffectSet.of(Effect.UNKNOWN), EffectSet.empty(), List.of()),
                eff("domain.calc", EffectSet.empty(), EffectSet.empty(), List.of()));
        Path pol = dir.resolve("p.policy");
        Files.writeString(pol, "pure domain\n");
        String out = capture(() -> Query.unverified(fns, null, null, pol.toString(), true, false, null));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertFalse(o.get("ok").getAsBoolean());
        JsonArray items = o.getAsJsonArray("unverified");
        assertEquals(1, items.size(), "only the Unknown fn is flagged");
        assertEquals("domain.price", items.get(0).getAsJsonObject().get("fn").getAsString());
        assertEquals("deny Unknown domain", items.get(0).getAsJsonObject().get("upgrade").getAsString());
        // --strict → exit 1
        assertEquals(1, Query.unverified(fns, null, null, pol.toString(), false, true, null));
    }

    /**
     * THE REFUSAL IS RIGHT; THE NOUN WAS BORROWED. {@code fix}, {@code fix-gate} and {@code unverified}
     * share one policy loader, and over an unhonourable policy (⟨0.24⟩ an unrecognised class token) it
     * refused with "— no fix computed" for all three. {@code unverified} computes no fix: it reports which
     * functions PASS their policy without being provably clean, so what an unhonourable policy costs it is
     * the CHECK. A diagnostic naming the wrong consequence sends the reader looking for a remedy that was
     * never the subject. Exit 2 either way — this is about what the sentence says, not what it does.
     */
    @Test void anUnhonourablePolicyNamesTheCallingVerbsConsequence(@TempDir Path dir) throws Exception {
        List<Effector> fns = List.of(eff("domain.price", EffectSet.of(Effect.UNKNOWN), EffectSet.empty(), List.of()));
        Path pol = dir.resolve("p.policy");
        Files.writeString(pol, "deny Unknown[dispatch,nativ] domain\n");   // `nativ` — a typo among valid tokens

        String unv = captureErr(() -> Query.unverified(fns, null, null, pol.toString(), false, false, null));
        assertTrue(unv.contains("nothing was checked"),
                "`unverified` must name ITS consequence — it computes no fix, so an unhonourable policy "
                + "costs it the CHECK: " + unv);
        assertFalse(unv.contains("no fix computed"),
                "…and must not borrow the sibling verb's noun: " + unv);
        assertTrue(unv.startsWith("candor unverified:"),
                "…under the verb's own name, as the missing-policy branch of the same loader already does: " + unv);
        Candor.resetState();
        assertEquals(2, exitOf(() -> Query.unverified(fns, null, null, pol.toString(), false, false, null)),
                "the POSTURE is unchanged — an unhonourable policy still refuses (exit 2)");

        Candor.resetState();
        String fx = captureErr(() -> Query.fixGate(fns, dir.resolve("r.json").toString(), dir.resolve("r.json").toString(), pol.toString(), false, false));
        assertTrue(fx.contains("no fix computed"),
                "CONTROL: the verb that DOES compute a fix keeps the noun — the repair is per-verb wording, "
                + "not the deletion of a sentence: " + fx);
    }

    /** stderr, where every refusal diagnostic in the shared policy loader goes. */
    private static String captureErr(Runnable r) {
        PrintStream orig = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setErr(new PrintStream(buf));
        try { r.run(); } finally { System.setErr(orig); }
        return buf.toString().trim();
    }

    private static Effector eff(String fn, EffectSet inferred, EffectSet direct, List<String> calls) {
        return new Effector(fn, "", inferred, List.of(), direct, EffectSet.empty(),
                EffectSet.empty(), EffectSet.empty(), false, inferred.hasUnknown(), EffectorKind.FUNCTION,
                List.of(), "", calls, List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
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

    /** Run an exit-code-returning call with stdout+stderr muted, returning the int. */
    private static int exitOf(java.util.function.IntSupplier r) {
        PrintStream o = System.out, e = System.err;
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        System.setOut(new PrintStream(sink));
        System.setErr(new PrintStream(sink));
        try { return r.getAsInt(); }
        finally { System.setOut(o); System.setErr(e); }
    }

    @Test void fixGateStrictExitsOneOnCrossingAdvisoryOtherwise(@TempDir Path dir) throws Exception {
        // #3 exit-code contract: fix-gate is ADVISORY (exit 0) by default so the agent fix-loop reads the
        // remedy and edits; `--strict` makes an outstanding crossing a CI failure (exit 1), matching
        // `unverified --strict`. Same crossing, two exit codes by flag.
        String report = orderflowGraph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net domain\n");
        assertEquals(0, exitOf(() -> Query.fixGate(orderflowFns(), report, report, pol.toString(), false, false)),
                "advisory default exits 0");
        assertEquals(1, exitOf(() -> Query.fixGate(orderflowFns(), report, report, pol.toString(), false, true)),
                "--strict with an outstanding crossing exits 1");
        assertEquals(1, exitOf(() -> Query.fixGate(orderflowFns(), report, report, pol.toString(), true, true)),
                "--strict --json with a crossing exits 1");
        // clean policy → exit 0 even with --strict (no crossing to fail on)
        Files.writeString(pol, "deny Net nonexistentlayer\n");
        assertEquals(0, exitOf(() -> Query.fixGate(orderflowFns(), report, report, pol.toString(), false, true)),
                "--strict over a clean report exits 0");
    }

    @Test void gainsStrictExitsOneAndRejectsSwallowedPolicy(@TempDir Path dir) throws Exception {
        // #3: gains is a diff view (exit 0 by default). `--strict` fails on ANY gained effect; an unknown
        // `--policy` a user reaches for expecting a gate is REJECTED loud (exit 2), never swallowed.
        Path base = dir.resolve("b.lib.deep.json");
        Path cur = dir.resolve("c.lib.deep.json");
        Files.writeString(base, "{\"candor\":{\"version\":\"t\",\"spec\":\"0.19\"},\"package\":\"lib\",\"functions\":[{\"fn\":\"lib.f\",\"loc\":\"s:1\",\"inferred\":[\"Fs\"],\"hash\":\"h\"}]}");
        Files.writeString(cur, "{\"candor\":{\"version\":\"t\",\"spec\":\"0.19\"},\"package\":\"lib\",\"functions\":[{\"fn\":\"lib.f\",\"loc\":\"s:1\",\"inferred\":[\"Fs\",\"Net\"],\"hash\":\"h\"}]}");
        String c = dir.resolve("c").toString(), b = dir.resolve("b").toString();
        assertEquals(0, exitOf(() -> Query.gains2(c, b, false, false, null)), "advisory default exits 0");
        assertEquals(1, exitOf(() -> Query.gains2(c, b, false, true, null)), "--strict with a gain exits 1");
        assertEquals(2, exitOf(() -> Query.gains2(c, b, false, false, "/x")), "a swallowed --policy is rejected (exit 2)");
    }
}
