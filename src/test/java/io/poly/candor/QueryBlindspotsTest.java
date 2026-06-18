package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * blindspots (SPEC §3.1 ⟨0.6⟩) — the Unknown SOURCES (units whose own body has an unresolvable call, so
 * they carry {@code unknownWhy}), each ranked by its Unknown blast radius. A transitive-only Unknown (no
 * {@code unknownWhy}) is NOT a source and is excluded — turning a widely-propagated Unknown into a short,
 * ranked worklist of real blind spots.
 */
class QueryBlindspotsTest {

    @Test void rankedSourcesAndTotal() {
        Query.Fn src = new Query.Fn();
        src.fn = "app.Svc.dispatch";
        src.inferred = List.of("Unknown");
        src.unknownWhy = List.of("dispatch-broad:app.I.run"); // a real SOURCE
        Query.Fn caller = new Query.Fn();
        caller.fn = "app.Ctrl.handle";
        caller.inferred = List.of("Unknown"); // Unknown ONLY because it calls the source (no own why)
        caller.calls = List.of("app.Svc.dispatch");
        Query.Fn clean = new Query.Fn();
        clean.fn = "app.Util.pure";
        clean.inferred = List.of();

        String out = capture(() -> Query.blindspots(List.of(src, caller, clean), true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();

        assertEquals(2, o.get("totalUnknown").getAsInt(), "two Unknown fns: the source + its transitive caller");
        var sources = o.getAsJsonArray("sources");
        assertEquals(1, sources.size(), "only the source (carrying unknownWhy) is listed, not the transitive caller");
        JsonObject s = sources.get(0).getAsJsonObject();
        assertEquals("app.Svc.dispatch", s.get("fn").getAsString(), "the source is named");
        assertEquals(1, s.get("reaches").getAsInt(), "the source reaches its 1 transitive caller (the blast radius)");
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
