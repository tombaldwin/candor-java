package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * {@code callers --include-unknown} ⟨0.7⟩ — the unresolved-dispatch frontier. The confirmed transitive
 * callers never include a function that reaches the target only through a dispatch candor declined to
 * resolve (an unresolved dispatch, `dispatch:`, disclosed as Unknown). The flag discloses
 * those "MAY also reach" functions — a function F carrying {@code dispatch:OWNER.M} is listed iff a
 * confirmed reacher is an override of OWNER.M (same method name AND a subtype of OWNER per the hierarchy).
 * The subtype check makes it precise; with no hierarchy it falls back to a simple-name match (over-lists).
 * Default output (no flag) stays byte-for-byte unchanged.
 */
class QueryIncludeUnknownTest {

    // app.Impl.run -> app.Sink.touch is the only resolved edge; app.Frontier.go's real (broad) call was
    // dropped to Unknown. app.Impl is a subtype of app.Base.
    private static Map<String, List<String>> graph() {
        Map<String, List<String>> cg = new TreeMap<>();
        cg.put("app.Impl.run", List.of("app.Sink.touch"));
        cg.put("app.Sink.touch", List.of());
        cg.put("app.Frontier.go", List.of());
        return cg;
    }

    private static Map<String, List<String>> hierarchy() {
        return Map.of("app.Impl", List.of("app.Base")); // Impl <: Base
    }

    @Test void disclosesFrontierWhenDispatchOwnerMatches() {
        // Frontier.go broad-dispatches app.Base.run; the confirmed reacher app.Impl.run IS an override
        // of Base.run (Impl <: Base) -> go MAY reach the target.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("app.Base.run"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, hierarchy()));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertTrue(o.getAsJsonArray("transitive").toString().contains("app.Impl.run"));
        var poss = o.getAsJsonArray("possibleViaUnknownDispatch");
        assertEquals(1, poss.size(), "the broad-dispatch frontier function is disclosed");
        assertEquals("app.Frontier.go", poss.get(0).getAsJsonObject().get("fn").getAsString());
        assertEquals("run", poss.get(0).getAsJsonObject().get("viaDispatchOn").getAsString());
    }

    @Test void precisionDropsUnrelatedSameNamedDispatch() {
        // Frontier.go broad-dispatches app.Unrelated.run. The only confirmed reacher with method `run`
        // is app.Impl.run, and Impl is NOT a subtype of Unrelated -> the dispatch cannot land on it ->
        // NOT disclosed. (A bare simple-name match would wrongly list it; the hierarchy check prevents that.)
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("app.Unrelated.run"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, hierarchy()));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(0, o.getAsJsonArray("possibleViaUnknownDispatch").size(),
                "an unrelated same-named dispatch is not disclosed when the hierarchy rules it out");
    }

    @Test void fallsBackToSimpleNameWithoutHierarchy() {
        // Same unrelated dispatch, but no hierarchy sidecar (hier == null) -> simple-name match -> the
        // documented over-list (safe direction). Confirms graceful degradation.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("app.Unrelated.run"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, null));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(1, o.getAsJsonArray("possibleViaUnknownDispatch").size(),
                "no hierarchy -> simple-name match over-lists (lower-bound disclosure, safe direction)");
    }

    @Test void confirmedCallerIsNotRelistedAsPossible() {
        Map<String, Set<String>> broad = Map.of("app.Impl.run", Set.of("app.Sink.touch"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, hierarchy()));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(0, o.getAsJsonArray("possibleViaUnknownDispatch").size(),
                "a confirmed caller is not re-listed as a possible reacher");
    }

    @Test void defaultOutputUnchangedWithoutFlag() {
        String out = capture(() -> Query.callersViaCallgraph(graph(), "app.Sink.touch", true, null, null));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertFalse(o.has("possibleViaUnknownDispatch"),
                "no flag -> no possibleViaUnknownDispatch key (cross-engine parity preserved)");
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
