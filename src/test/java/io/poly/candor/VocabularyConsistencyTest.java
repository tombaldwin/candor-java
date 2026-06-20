package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.poly.candor.model.Effect;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Ties the engine's string-keyed vocabulary lists back to the {@link Effect} enum, so adding an effect
 * in ONE place (the enum) can't silently leave a gate/containment list stale. The lists keep their own
 * (spec §6.1 display) ORDER; this only pins their MEMBERSHIP to the enum predicates.
 */
class VocabularyConsistencyTest {

    private static Set<String> names(java.util.function.Predicate<Effect> p) {
        return Arrays.stream(Effect.values()).filter(p).map(Effect::specName).collect(Collectors.toSet());
    }

    @Test
    void knownEffectsMatchTheEnum() {
        assertEquals(names(e -> e != Effect.UNKNOWN), Candor.KNOWN_EFFECTS);
    }

    @Test
    void containmentListsMatchTheEnumPartition() {
        assertEquals(names(Effect::isBoundary), Set.copyOf(Query.CONTAINED),
                "Query.CONTAINED must be exactly the boundary effects (order aside)");
        assertEquals(names(Effect::isCrossCutting), Set.copyOf(Query.AMBIENT),
                "Query.AMBIENT must be exactly the cross-cutting effects (order aside)");
    }
}
