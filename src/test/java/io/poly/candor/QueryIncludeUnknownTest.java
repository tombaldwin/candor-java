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
 * {@code callers --include-unknown} — the unresolved-dispatch frontier. The confirmed transitive callers
 * never include a function that reaches the target only through a dispatch candor declined to resolve
 * (a {@code dispatch-broad} over the CHA fan-out limit, disclosed as Unknown). The flag discloses those
 * "MAY also reach" functions — matched by the dispatch method's simple name against a confirmed reacher —
 * without ever asserting them. Default output (no flag) stays byte-for-byte unchanged.
 */
class QueryIncludeUnknownTest {

    // app.Frontier.go broad-dispatches `run`; the confirmed reacher app.Impl.run is an override of it,
    // so go MAY reach the target. app.Impl.run -> app.Sink.touch is the only resolved edge.
    private static Map<String, List<String>> graph() {
        Map<String, List<String>> cg = new TreeMap<>();
        cg.put("app.Impl.run", List.of("app.Sink.touch"));
        cg.put("app.Sink.touch", List.of());
        cg.put("app.Frontier.go", List.of()); // its real (broad) call was dropped to Unknown
        return cg;
    }

    @Test void disclosesFrontierUnderFlag() {
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("run"));
        String out = capture(() -> Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();

        assertTrue(o.getAsJsonArray("transitive").toString().contains("app.Impl.run"),
                "the confirmed reacher is in transitive");
        var poss = o.getAsJsonArray("possibleViaUnknownDispatch");
        assertEquals(1, poss.size(), "the broad-dispatch frontier function is disclosed");
        JsonObject p = poss.get(0).getAsJsonObject();
        assertEquals("app.Frontier.go", p.get("fn").getAsString());
        assertEquals("run", p.get("viaDispatchOn").getAsString());
    }

    @Test void confirmedCallerIsNotRelistedAsPossible() {
        // If the frontier function is ALSO a confirmed caller (reaches via a resolved edge too), it must
        // not appear in the possible set — it's already counted.
        Map<String, List<String>> cg = graph();
        cg.put("app.Impl.run", List.of("app.Sink.touch")); // app.Impl.run is confirmed
        Map<String, Set<String>> broad = Map.of("app.Impl.run", Set.of("touch"));
        String out = capture(() -> Query.callersViaCallgraph(cg, "app.Sink.touch", true, broad));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(0, o.getAsJsonArray("possibleViaUnknownDispatch").size(),
                "a confirmed caller is not re-listed as a possible reacher");
    }

    @Test void defaultOutputUnchangedWithoutFlag() {
        String out = capture(() -> Query.callersViaCallgraph(graph(), "app.Sink.touch", true, null));
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
