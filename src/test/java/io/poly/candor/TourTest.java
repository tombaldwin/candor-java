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
 * tour [<N>] (SURFACE-BEST-FIND-DESIGN.md, P2) — the on-demand, top-N version of the scan-time surprise
 * note, the port of candor-query's {@code tour}. Mirrors the Rust reference's fixture: a benign
 * {@code settings.Settings.load} inherits Net three hops down via {@code netLayer.doSend}, and an
 * effecty {@code api.fetch} that must NOT win. The verb reads the report entries + the callgraph sidecar
 * (no re-scan) and ranks via the SHARED {@link Surface#bestFinds}, so its ranking can't drift from the
 * scan note.
 */
class TourTest {

    @BeforeEach void fresh() { Candor.resetState(); }

    /** The benign-deep fixture: settings.Settings.load -> core.refresh -> core.syncState -> netLayer.doSend
     *  (direct Net, at src/net.java:9); plus api.fetch (effecty leaf) that must be excluded. Writes the
     *  callgraph sidecar beside {@code <dir>/r.json} and returns that report path. */
    private static String benignDeepGraph(Path dir) throws Exception {
        String cg = "{"
                + "\"core.syncState\":[\"netLayer.doSend\"],"
                + "\"core.refresh\":[\"core.syncState\"],"
                + "\"settings.Settings.load\":[\"core.refresh\"],"
                + "\"api.fetch\":[\"netLayer.doSend\"]}";
        Files.writeString(dir.resolve("r.callgraph.json"), cg);
        return dir.resolve("r.json").toString();
    }

    private static List<Effector> benignDeepFns() {
        return List.of(
                eff("netLayer.doSend", EffectSet.of(Effect.NET), EffectSet.of(Effect.NET), List.of(), "src/net.java:9"),
                eff("core.syncState", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("netLayer.doSend"), ""),
                eff("core.refresh", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("core.syncState"), ""),
                eff("settings.Settings.load", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("core.refresh"), "src/Settings.java:5"),
                eff("api.fetch", EffectSet.of(Effect.NET), EffectSet.empty(), List.of("netLayer.doSend"), ""));
    }

    @Test void tourNamesTheBenignDeepReach(@TempDir Path dir) throws Exception {
        String report = benignDeepGraph(dir);
        String out = capture(() -> Query.tour(benignDeepFns(), report, null, true, Query.ReportRef.NONE));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        JsonArray reaches = o.getAsJsonArray("reaches");
        assertFalse(reaches.isEmpty(), "the benign-deep reach should surface");
        JsonObject top = reaches.get(0).getAsJsonObject();
        assertEquals("settings.Settings.load", top.get("fn").getAsString());
        assertEquals("Net", top.get("effect").getAsString());
        assertEquals(3, top.get("hops").getAsInt());
        assertEquals("netLayer.doSend", top.get("source").getAsString());
        assertEquals("src/net.java:9", top.get("loc").getAsString());
        // api.fetch (effecty) is excluded — it never appears in the tour.
        for (int i = 0; i < reaches.size(); i++)
            assertFalse(reaches.get(i).getAsJsonObject().get("fn").getAsString().equals("api.fetch"),
                    "the effecty api.fetch must be excluded");
    }

    @Test void tourHumanOutputMatchesFormat(@TempDir Path dir) throws Exception {
        String report = benignDeepGraph(dir);
        String out = capture(() -> Query.tour(benignDeepFns(), report, null, false, Query.ReportRef.NONE));
        // Header: "the 2 most surprising reaches in r.json:" — settings.Settings.load AND the plain-named
        // core.refresh both clear the bar (crate = report basename; plural "reaches" for >= 2).
        assertTrue(out.contains("candor tour — the 2 most surprising reaches in r.json:"),
                "unexpected header:\n" + out);
        // The top reach line with the source loc + the suggested `candor path`.
        assertTrue(out.contains(
                "  1. `settings.Settings.load` performs Net, 3 hops away via `netLayer.doSend` (src/net.java:9)"),
                "unexpected reach line:\n" + out);
        assertTrue(out.contains("     →  candor path settings.Settings.load Net"),
                "missing suggested path command:\n" + out);
    }

    @Test void tourNThatCapsToOne(@TempDir Path dir) throws Exception {
        // N == 1 caps the list to one distinct function — byte-identical to the scan-note winner.
        String report = benignDeepGraph(dir);
        String out = capture(() -> Query.tour(benignDeepFns(), report, "1", true, Query.ReportRef.NONE));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(1, o.getAsJsonArray("reaches").size(), "N=1 caps the list");
    }

    @Test void tourNonIntegerNIsUsageError(@TempDir Path dir) throws Exception {
        String report = benignDeepGraph(dir);
        int rc = Query.tour(benignDeepFns(), report, "notanint", false, Query.ReportRef.NONE);
        assertEquals(2, rc, "a non-integer N is a usage error (exit 2)");
    }

    @Test void tourEmitsHonestFallbackWhenNothingSurprises(@TempDir Path dir) throws Exception {
        // A lone effecty, direct source — nothing clears the bar, but the crate IS effectful → the fallback.
        Files.writeString(dir.resolve("r.callgraph.json"), "{\"net.client.send\":[]}");
        String report = dir.resolve("r.json").toString();
        List<Effector> fns = List.of(
                eff("net.client.send", EffectSet.of(Effect.NET), EffectSet.of(Effect.NET), List.of(), ""));
        String out = capture(() -> Query.tour(fns, report, null, false, Query.ReportRef.NONE));
        assertTrue(out.contains("candor: nothing hidden — every effect sits where its name says it should."),
                "expected the honest fallback:\n" + out);
    }

    private static Effector eff(String fn, EffectSet inferred, EffectSet direct, List<String> calls, String loc) {
        return new Effector(fn, loc, inferred, List.of(), direct, EffectSet.empty(),
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
}
