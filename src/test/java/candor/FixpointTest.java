package candor;

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

    private static TreeSet<String> set(String... xs) {
        return new TreeSet<>(List.of(xs));
    }

    private static TreeSet<String> inferred(Map<String, TreeSet<String>> r, String fn) {
        return r.getOrDefault(fn, new TreeSet<>());
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
    void clinitContributesOnlyItsDirectEffectsToConsumers() {
        // The class-load trigger edge: a caller of `X.<clinit>` inherits the clinit's DIRECT effects
        // (its static-block first-touch I/O) but NOT the clinit's TRANSITIVE effects (the deep effects
        // of structures it builds — the guava-construction-reaches-a-logger fabrication this rule fixed).
        var direct = Map.of("X.<clinit>", set("Log"), "deep", set("Net"));
        var edges = Map.of(
                "user", Set.of("X.<clinit>"),
                "X.<clinit>", Set.of("deep")); // the clinit body itself reaches a Net fn
        var r = Candor.computeFixpoint(direct, edges, Map.of());
        // the clinit keeps its OWN full transitive set...
        assertEquals(set("Log", "Net"), inferred(r, "X.<clinit>"));
        // ...but its consumer sees only the clinit's DIRECT effects, never the transitive Net.
        assertEquals(set("Log"), inferred(r, "user"));
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
        assertEquals(new TreeSet<>(), inferred(r, "a")); // nothing reachable carries an effect
    }
}
