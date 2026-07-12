package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

/**
 * Native unit tests (JUnit 5) for {@link Surface} — the cold-repo "most surprising reach" hook. Mirrors
 * the Rust reference's {@code surface.rs} tests (dotted node ids in place of {@code ::}), so both engines
 * pin the SAME behaviour: a benign function inheriting a scary effect a few hops down beats a shallow /
 * effecty one, and the honest fallback fires when nothing clears the bar.
 */
class SurfaceTest {

    private static EffectSet set(Effect... es) {
        return EffectSet.of(es);
    }

    private static Set<String> sset(String... items) {
        return new HashSet<>(List.of(items));
    }

    @Test
    void tokenizeSplitsAllBoundaries() {
        assertEquals(List.of("settings", "settings", "needs", "update"),
                Surface.tokenize("settings.Settings.needsUpdate"));
        assertEquals(List.of("api", "client", "latest", "version"),
                Surface.tokenize("api_client.latestVersion"));
    }

    @Test
    void benignDeepInheritedBeatsShallowEffecty() {
        // Graph (dotted analogue of the Rust fixture):
        //   settings.Settings.load  (benign leaf "load")  -inherits-> Net, 3 hops
        //     -> core.refresh -> core.syncState -> netLayer.doSend (direct Net)
        //   api.fetch  (effecty leaf "fetch") -inherits-> Net, 1 hop  (EXCLUDED — effecty)
        //     -> netLayer.doSend
        Map<String, EffectSet> direct = new HashMap<>();
        Map<String, EffectSet> inferred = new HashMap<>();
        Map<String, Set<String>> calls = new HashMap<>();

        direct.put("netLayer.doSend", set(Effect.NET));
        inferred.put("netLayer.doSend", set(Effect.NET));

        inferred.put("core.syncState", set(Effect.NET));
        calls.put("core.syncState", sset("netLayer.doSend"));

        inferred.put("core.refresh", set(Effect.NET));
        calls.put("core.refresh", sset("core.syncState"));

        // benign candidate: settings.Settings.load, 3 hops to source.
        inferred.put("settings.Settings.load", set(Effect.NET));
        calls.put("settings.Settings.load", sset("core.refresh"));

        // effecty candidate: api.fetch, 1 hop — must be excluded by the EFFECTY leaf/module.
        inferred.put("api.fetch", set(Effect.NET));
        calls.put("api.fetch", sset("netLayer.doSend"));

        Surface.Result r = Surface.bestFind(inferred, direct, calls);
        assertEquals(Surface.Result.State.WINNER, r.state, "expected a winner");
        Surface.Find got = r.find;
        assertEquals("settings.Settings.load", got.func);
        assertEquals("Net", got.effect);
        assertEquals(3, got.hops);
        assertEquals("netLayer.doSend", got.source);
        assertEquals("load", got.benignToken);
    }

    @Test
    void fallbackWhenNothingQualifies() {
        // One effectful function, but it is a DIRECT source (not inherited) AND effecty-named — no
        // candidate qualifies → FALLBACK, the honest note.
        Map<String, EffectSet> direct = new HashMap<>();
        Map<String, EffectSet> inferred = new HashMap<>();
        Map<String, Set<String>> calls = new HashMap<>();
        direct.put("net.client.send", set(Effect.NET));
        inferred.put("net.client.send", set(Effect.NET));

        Surface.Result r = Surface.bestFind(inferred, direct, calls);
        assertEquals(Surface.Result.State.FALLBACK, r.state, "expected the honest fallback");
    }

    @Test
    void nothingWhenNoEffects() {
        // No non-Unknown effect anywhere → NONE (caller emits nothing at all).
        Map<String, EffectSet> direct = new HashMap<>();
        Map<String, EffectSet> inferred = new HashMap<>();
        Map<String, Set<String>> calls = new HashMap<>();
        inferred.put("util.parse", set(Effect.UNKNOWN));

        Surface.Result r = Surface.bestFind(inferred, direct, calls);
        assertEquals(Surface.Result.State.NONE, r.state);
    }
}
