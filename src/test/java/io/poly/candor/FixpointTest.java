package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Native unit tests for the effect-propagation least-fixpoint, extracted from {@code fixpoint()} into
 * the pure {@code computeFixpoint(direct, edges, viaCross)} so its inputs are synthetic graphs rather
 * than a whole scan's static state. Pins the propagation heart directly — including the clinit
 * direct-only rule and the cross-jar seed, both of which were fabrication fixes in the campaign.
 */
class FixpointTest {

    private static EffectSet set(String... xs) {
        return EffectSet.ofNames(List.of(xs));
    }

    private static EffectSet inferred(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    @Test
    void effectsPropagateTransitivelyAlongEdges() {
        var direct = Map.of("c", set("Fs"));
        var edges = Map.of("a", Set.of("b"), "b", Set.of("c"));
        var r = Candor.computeFixpoint(direct, edges, Map.of());
        assertEquals(set("Fs"), inferred(r, "a")); // a -> b -> c, c is Fs
        assertEquals(set("Fs"), inferred(r, "b"));
        assertEquals(set("Fs"), inferred(r, "c"));
    }

    @Test
    void effectsUnionFromMultipleCallees() {
        var direct = Map.of("x", set("Net"), "y", set("Db"));
        var edges = Map.of("caller", Set.of("x", "y"));
        var r = Candor.computeFixpoint(direct, edges, Map.of());
        assertEquals(set("Db", "Net"), inferred(r, "caller"));
    }

    @Test
    void clinitTriggerPropagatesTransitiveEffectsToConsumers() {
        // The class-load trigger edge propagates the clinit's FULL transitive effects (spec §5): touching
        // `X` runs `X.<clinit>`, which transitively reaches whatever it calls — so a consumer CAN reach
        // those effects (sound "can reach"). The §7.13 soundness fuzzer caught the prior direct-only
        // narrowing dropping exactly this (a real effect threaded through a static block came back pure).
        var direct = Map.of("X.<clinit>", set("Log"), "deep", set("Net"));
        var edges = Map.of(
                "user", Set.of("X.<clinit>"),
                "X.<clinit>", Set.of("deep")); // the clinit body itself reaches a Net fn
        var r = Candor.computeFixpoint(direct, edges, Map.of());
        // the clinit keeps its own full transitive set...
        assertEquals(set("Log", "Net"), inferred(r, "X.<clinit>"));
        // ...and its consumer reaches it transitively too (Log from the static block + Net through the body).
        assertEquals(set("Log", "Net"), inferred(r, "user"));
    }

    @Test
    void crossJarEffectsSeedAndPropagate() {
        // viaCross effects (from a CANDOR_DEPS sibling report) are not in `direct` but seed `inferred`
        // and propagate to callers transitively.
        var edges = Map.of("local", Set.of("dep"));
        var viaCross = Map.of("dep", set("Net"));
        var r = Candor.computeFixpoint(Map.of(), edges, viaCross);
        assertEquals(set("Net"), inferred(r, "dep"));
        assertEquals(set("Net"), inferred(r, "local"));
    }

    @Test
    void cyclesTerminateAtTheLeastFixpoint() {
        var direct = Map.of("a", set("Fs"));
        var edges = Map.of("a", Set.of("b"), "b", Set.of("a")); // a <-> b
        var r = Candor.computeFixpoint(direct, edges, Map.of());
        assertEquals(set("Fs"), inferred(r, "a"));
        assertEquals(set("Fs"), inferred(r, "b")); // the cycle does not loop forever
    }

    @Test
    void aPureLeafStaysEmpty() {
        var edges = Map.of("a", Set.of("b"));
        var r = Candor.computeFixpoint(Map.of(), edges, Map.of());
        assertEquals(EffectSet.empty(), inferred(r, "a")); // nothing reachable carries an effect
    }
}
