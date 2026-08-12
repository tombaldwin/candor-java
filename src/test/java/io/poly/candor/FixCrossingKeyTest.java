package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
 * ⟨0.28⟩ SPEC §6.1 — {@code crossing} is PINNED: a boolean, present exactly when the {@code fix} verb
 * ANSWERED, absent when it refused, with {@code reason} on the {@code false} arm.
 *
 * <p>MEASURED on the jar built before this change (spec 413451d's own measurement, reproduced here):
 * <pre>
 *   fix A.writeFile Fs --json   (policy denies nothing relevant)
 *     → stdout: "candor fix: `A.writeFile` performs Fs, but no policy forbids it there — …"   exit 0
 * </pre>
 * — a determined negative as PROSE on a {@code --json} stdout, which §3.3.1 independently forbids
 * ("stdout MUST then be pure JSON"). candor-ts and candor-swift answer the same arm as
 * {@code {fn, effect, crossing: false, reason}} and the MCP {@code candor_fix} tool contract reads that
 * shape, so the key is a shipped consumer contract, not a mint.
 */
class FixCrossingKeyTest {

    @BeforeEach void fresh() { Candor.resetState(); }

    private static String graph(Path dir) throws Exception {
        String cg = "{"
                + "\"of.api.Api.getQuote\":[\"of.domain.Pricing.priceQuote\"],"
                + "\"of.domain.Pricing.priceQuote\":[\"of.infra.Rates.fetchRate\"],"
                + "\"of.infra.Rates.fetchRate\":[]}";
        Files.writeString(dir.resolve("r.callgraph.json"), cg);
        return dir.resolve("r.json").toString();
    }

    private static List<Effector> fns() {
        return List.of(
                eff("of.api.Api.getQuote", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.domain.Pricing.priceQuote")),
                eff("of.domain.Pricing.priceQuote", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("of.infra.Rates.fetchRate")),
                eff("of.infra.Rates.fetchRate", EffectSet.of(Effect.NET), EffectSet.of(Effect.NET), List.of()),
                eff("of.domain.Pricing.describe", EffectSet.empty(), EffectSet.empty(), List.of()));
    }

    @Test void answeredWithAPlanCarriesCrossingTrue(@TempDir Path dir) throws Exception {
        String report = graph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net domain\n");
        String out = capture(() -> Query.fix(fns(), report, report, "priceQuote", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertTrue(o.has("crossing"), "the answered arm carries the pinned boolean: " + out);
        assertTrue(o.get("crossing").getAsBoolean(), "a plan means the boundary IS crossed");
        assertFalse(o.has("reason"), "`reason` belongs to the false arm only");
        assertEquals("of.domain.Pricing.priceQuote", o.get("fn").getAsString(),
                "the remedy fields still ride the same document");
    }

    @Test void notForbiddenIsCrossingFalseInTheDocumentNotProse(@TempDir Path dir) throws Exception {
        String report = graph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Db domain\n"); // denies nothing the fn performs
        String out = capture(() -> Query.fix(fns(), report, report, "priceQuote", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out.trim()).getAsJsonObject(); // MUST parse: §3.3.1 purity
        assertFalse(o.get("crossing").getAsBoolean(), "determined negative → crossing: false");
        assertEquals("not-forbidden", o.get("reason").getAsString(),
                "the family reason token candor-ts/swift already publish");
        assertEquals("of.domain.Pricing.priceQuote", o.get("fn").getAsString());
        assertEquals("Net", o.get("effect").getAsString());
        assertFalse(out.contains("no policy forbids it there"),
                "the prose stays on the HUMAN channel — stdout under --json is pure JSON");
    }

    @Test void doesNotPerformIsCrossingFalseWithItsOwnReason(@TempDir Path dir) throws Exception {
        String report = graph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net domain\n");
        String out = capture(() -> Query.fix(fns(), report, report, "of.domain.Pricing.describe", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out.trim()).getAsJsonObject();
        assertFalse(o.get("crossing").getAsBoolean());
        assertEquals("does-not-perform", o.get("reason").getAsString());
    }

    @Test void refusedArmStaysCrossingFree(@TempDir Path dir) throws Exception {
        // The withheld-rule refusal: `deny Net[known-partner] domain` over a report whose entry carries no
        // `netClass` — the gate cannot adjudicate, so the verb refuses and the document carries NO
        // `crossing` key (absent, not false): the arm the MCP contract's check-`refused`-first order needs.
        String report = graph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Net[known-partner] domain\n");
        String out = capture(() -> Query.fix(fns(), report, report, "priceQuote", "Net", pol.toString(), true));
        JsonObject o = JsonParser.parseString(out.trim()).getAsJsonObject();
        assertFalse(o.has("crossing"), "refused → the key is ABSENT, present-iff-answered: " + out);
        assertTrue(o.has("unevaluated"), "the refusal names what could not be evaluated");
    }

    @Test void theHumanChannelKeepsItsProse(@TempDir Path dir) throws Exception {
        // Control: without --json the sentence is the answer and must survive byte-for-byte.
        String report = graph(dir);
        Path pol = dir.resolve("arch.policy");
        Files.writeString(pol, "deny Db domain\n");
        String out = capture(() -> Query.fix(fns(), report, report, "priceQuote", "Net", pol.toString(), false));
        assertTrue(out.contains("no policy forbids it there"), "the human arm is unchanged: " + out);
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
        try { r.run(); } finally { System.setOut(orig); }
        return buf.toString();
    }
}
