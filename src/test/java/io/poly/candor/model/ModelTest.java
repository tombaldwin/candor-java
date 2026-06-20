package io.poly.candor.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/** Unit tests for the candor-java domain model — pins the byte-identity-critical invariants
 *  (effect-set wire ordering, Unknown-reason round-trip) and the spec-vocabulary facts. */
class ModelTest {

    @Test
    void effectSpecNamesAndLookup() {
        assertEquals("Net", Effect.NET.specName());
        assertEquals("Unknown", Effect.UNKNOWN.specName());
        assertEquals(Effect.DB, Effect.fromSpecName("Db"));
        assertNull(Effect.fromSpecName("Bogus"));
        assertTrue(Effect.UNKNOWN.isTrustMarker());
        assertFalse(Effect.NET.isTrustMarker());
        assertTrue(Effect.DB.isBoundary());
        assertFalse(Effect.LOG.isBoundary());
        assertTrue(Effect.LOG.isCrossCutting());
    }

    @Test
    void effectVocabularySets() {
        assertEquals(10, Effect.KNOWN.size());
        assertFalse(Effect.KNOWN.contains(Effect.UNKNOWN));
        // AS-EFF-004 ambient authority = 𝔼 \ {Log}
        assertEquals(9, Effect.AMBIENT_AUTHORITY.size());
        assertFalse(Effect.AMBIENT_AUTHORITY.contains(Effect.LOG));
        assertFalse(Effect.AMBIENT_AUTHORITY.contains(Effect.UNKNOWN));
        assertTrue(Effect.AMBIENT_AUTHORITY.contains(Effect.NET));
        assertEquals(6, Effect.INJECTION.size());
        assertFalse(Effect.INJECTION.contains(Effect.CLOCK));
    }

    /** THE load-bearing byte-identity invariant: EffectSet serializes in the SAME order as the
     *  historical TreeSet<String> — alphabetical by spec name, regardless of insertion order. */
    @Test
    void effectSetWireOrderMatchesTreeSetOfStrings() {
        EffectSet s = EffectSet.of(Effect.NET, Effect.DB, Effect.UNKNOWN, Effect.CLOCK, Effect.FS);
        TreeSet<String> reference = new TreeSet<>(List.of("Net", "Db", "Unknown", "Clock", "Fs"));
        assertEquals(List.copyOf(reference), s.toNames());
        // explicit expected order
        assertEquals(List.of("Clock", "Db", "Fs", "Net", "Unknown"), s.toNames());
    }

    @Test
    void effectSetOps() {
        EffectSet a = EffectSet.of(Effect.NET);
        EffectSet b = EffectSet.of(Effect.DB, Effect.UNKNOWN);
        EffectSet j = a.join(b);
        assertTrue(j.contains(Effect.NET));
        assertTrue(j.contains(Effect.DB));
        assertTrue(j.hasUnknown());
        assertFalse(a.hasUnknown());
        assertEquals(1, a.size()); // join is non-mutating
        assertTrue(EffectSet.empty().isEmpty());
    }

    @Test
    void unknownReasonRoundTripsAllSixKinds() {
        String[] tags = {
            "reflect:Foo.bar", "native:doNative", "dispatch:com.x.Y.m",
            "callback:p.q.R.run", "task-handoff:e.Executor.submit", "indy:groovy.Bsm"
        };
        for (String tag : tags) {
            UnknownReason r = UnknownReason.parse(tag);
            assertEquals(tag, r.format(), "round-trip: " + tag);
        }
        assertEquals(UnknownReason.Kind.DISPATCH, UnknownReason.parse("dispatch:A.b").kind());
        // detail keeps everything after the FIRST colon (task-handoff prefix has no inner colon issue)
        assertEquals("e.Executor.submit", UnknownReason.parse("task-handoff:e.Executor.submit").detail());
        // foreign / malformed → null (tolerant on read)
        assertNull(UnknownReason.parse("bogus:x"));
        assertNull(UnknownReason.parse("nocolon"));
    }

    @Test
    void unknownReasonOrderingMatchesWireStringOrder() {
        UnknownReason a = new UnknownReason(UnknownReason.Kind.DISPATCH, "A.a");
        UnknownReason b = new UnknownReason(UnknownReason.Kind.NATIVE, "z");
        // "dispatch:A.a" < "native:z" lexicographically — the TreeSet<String> order
        assertTrue(a.compareTo(b) < 0);
    }

    @Test
    void effectorKindWire() {
        assertNull(EffectorKind.FUNCTION.wireName());
        assertEquals("initializer", EffectorKind.INITIALIZER.wireName());
        assertEquals(EffectorKind.INITIALIZER, EffectorKind.fromWire("initializer"));
        assertEquals(EffectorKind.FUNCTION, EffectorKind.fromWire(null));
        assertEquals(EffectorKind.FUNCTION, EffectorKind.fromWire("somethingNew")); // tolerant
    }

    @Test
    void diagnosticCodeStrings() {
        assertEquals("AS-EFF-006", DiagnosticCode.AS_EFF_006.code());
        assertEquals("[AS-EFF-006]", DiagnosticCode.AS_EFF_006.bracket());
        assertEquals(
                "[AS-EFF-004] 'foo' uses ambient authority { Net } directly",
                new Diagnostic(DiagnosticCode.AS_EFF_004, "'foo' uses ambient authority { Net } directly")
                        .render());
    }
}
