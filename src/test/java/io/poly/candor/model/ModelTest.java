package io.poly.candor.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
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
        // a foreign prefix is PRESERVED verbatim (round-trips), with kind() == null
        UnknownReason foreign = UnknownReason.parse("bogus:x");
        assertEquals("bogus:x", foreign.format());
        assertNull(foreign.kind());
        // no colon → not a tag
        assertNull(UnknownReason.parse("nocolon"));
        // of(kind, detail) builds the same as parse
        assertEquals("dispatch:A.b", UnknownReason.of(UnknownReason.Kind.DISPATCH, "A.b").format());
    }

    @Test
    void unknownReasonOrderingMatchesWireStringOrder() {
        UnknownReason a = UnknownReason.of(UnknownReason.Kind.DISPATCH, "A.a");
        UnknownReason b = UnknownReason.of(UnknownReason.Kind.NATIVE, "z");
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
    void boundaryCrossCuttingPartition() {
        Set<Effect> boundary = Arrays.stream(Effect.values()).filter(Effect::isBoundary).collect(Collectors.toSet());
        Set<Effect> cross = Arrays.stream(Effect.values()).filter(Effect::isCrossCutting).collect(Collectors.toSet());
        assertEquals(Set.of(Effect.DB, Effect.NET, Effect.EXEC, Effect.FS, Effect.IPC, Effect.CLIPBOARD), boundary);
        assertEquals(Set.of(Effect.LOG, Effect.CLOCK, Effect.RAND, Effect.ENV), cross);
        assertTrue(Collections.disjoint(boundary, cross), "boundary and cross-cutting are disjoint");
        // Clipboard is a §6.1 boundary effect (external-resource I/O), so it is contained/scored, not ambient.
        assertTrue(Effect.CLIPBOARD.isBoundary());
        assertFalse(Effect.CLIPBOARD.isCrossCutting());
    }

    @Test
    void effectSetAlgebra() {
        EffectSet a = EffectSet.of(Effect.NET, Effect.DB, Effect.UNKNOWN);
        EffectSet b = EffectSet.of(Effect.DB, Effect.FS);
        assertEquals(EffectSet.of(Effect.NET, Effect.UNKNOWN), a.minus(b));
        assertEquals(EffectSet.of(Effect.DB), a.intersect(b));
        assertEquals(EffectSet.of(Effect.NET, Effect.DB), a.without(Effect.UNKNOWN));
        assertTrue(a.contains(Effect.NET) && a.size() == 3); // non-mutating: a unchanged
    }

    @Test
    void effectorIsADefensiveValue() {
        EffectSet live = EffectSet.of(Effect.NET);
        java.util.List<String> liveCalls = new java.util.ArrayList<>(List.of("a.b"));
        Effector e = new Effector("x.y", "", live, List.of(), EffectSet.empty(), EffectSet.empty(),
                EffectSet.empty(), EffectSet.empty(), false, false, EffectorKind.FUNCTION, List.of(), "",
                liveCalls, List.of(), List.of(), List.of(), List.of(), List.of());
        // mutating the sources after construction must NOT change the Effector (defensive copy)
        live.add(Effect.DB);
        liveCalls.add("c.d");
        assertEquals(List.of("Net"), e.inferred().toNames());
        assertEquals(List.of("a.b"), e.calls());
        // an accessor-returned list is immutable
        try {
            e.calls().add("z");
            org.junit.jupiter.api.Assertions.fail("Effector.calls() must be unmodifiable");
        } catch (UnsupportedOperationException expected) {
        }
    }

    @Test
    void unknownReasonCompareToConsistentWithEquals() {
        UnknownReason a = UnknownReason.of(UnknownReason.Kind.DISPATCH, "A.a");
        UnknownReason a2 = UnknownReason.of(UnknownReason.Kind.DISPATCH, "A.a");
        UnknownReason b = UnknownReason.of(UnknownReason.Kind.DISPATCH, "A.b");
        assertEquals(0, a.compareTo(a2));
        assertEquals(a, a2);
        assertTrue(a.compareTo(b) < 0);
        // sign of compareTo agrees with (in)equality
        assertTrue((a.compareTo(b) == 0) == a.equals(b));
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
