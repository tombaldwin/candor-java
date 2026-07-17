package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.Effector;
import io.poly.candor.model.EffectorKind;
import io.poly.candor.model.UnknownReason;
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
        Effector src = eff("app.Svc.dispatch", EffectSet.of(Effect.UNKNOWN), List.of(),
                List.of(UnknownReason.of(UnknownReason.Kind.DISPATCH, "app.I.run"))); // a real SOURCE
        // Unknown ONLY because it calls the source (no own why)
        Effector caller = eff("app.Ctrl.handle", EffectSet.of(Effect.UNKNOWN),
                List.of("app.Svc.dispatch"), List.of());
        Effector clean = eff("app.Util.pure", EffectSet.empty(), List.of(), List.of());

        String out = capture(() -> Query.blindspots(List.of(src, caller, clean), true, false));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();

        assertEquals(2, o.get("totalUnknown").getAsInt(), "two Unknown fns: the source + its transitive caller");
        var sources = o.getAsJsonArray("sources");
        assertEquals(1, sources.size(), "only the source (carrying unknownWhy) is listed, not the transitive caller");
        JsonObject s = sources.get(0).getAsJsonObject();
        assertEquals("app.Svc.dispatch", s.get("fn").getAsString(), "the source is named");
        assertEquals(1, s.get("reaches").getAsInt(), "the source reaches its 1 transitive caller (the blast radius)");
    }

    @Test void statsReasonClassDistribution() {
        // ⟨0.20⟩ `--stats`: the reason-class distribution over the Unknown SOURCES. One reflect source, one
        // native source, plus a transitive-only caller (no own why → not a source).
        Effector refl = eff("app.R.refl", EffectSet.of(Effect.UNKNOWN), List.of(),
                List.of(UnknownReason.of(UnknownReason.Kind.REFLECT, "eval")));
        Effector nat = eff("app.N.nat", EffectSet.of(Effect.UNKNOWN), List.of(),
                List.of(UnknownReason.of(UnknownReason.Kind.NATIVE, "jni")));
        Effector caller = eff("app.C.use", EffectSet.of(Effect.UNKNOWN), List.of("app.R.refl"), List.of());

        String out = capture(() -> Query.blindspots(List.of(refl, nat, caller), true, true));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        JsonObject byClass = o.getAsJsonObject("byClass");
        for (String c : new String[]{"reflect", "dispatch", "indirect", "native", "unresolved", "setup"})
            assertEquals(true, byClass.has(c), "byClass must carry every class: " + c);
        assertEquals(1, byClass.get("reflect").getAsInt());
        assertEquals(1, byClass.get("native").getAsInt());
        assertEquals(0, byClass.get("dispatch").getAsInt());
        assertEquals(2, o.get("sources").getAsInt(), "refl + nat carry a direct reason; the caller is transitive-only");
        assertEquals(3, o.get("totalUnknown").getAsInt());
    }

    private static Effector eff(String fn, EffectSet inferred, List<String> calls, List<UnknownReason> why) {
        return new Effector(fn, "", inferred, List.of(), EffectSet.empty(), EffectSet.empty(),
                EffectSet.empty(), EffectSet.empty(), false, inferred.hasUnknown(), EffectorKind.FUNCTION,
                why, "", calls, List.of(), List.of(), List.of(), List.of(), List.of());
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
