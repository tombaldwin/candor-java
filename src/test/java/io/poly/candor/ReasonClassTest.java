package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.poly.candor.model.ReasonClass;
import org.junit.jupiter.api.Test;

/**
 * The normative raw-{@code unknownWhy}→class map (REASON-SCOPED-UNKNOWN-DESIGN.md §1). Cases are the REAL
 * reasons the four engines emit (2026-07-16 audit), so this is the java half of the four-way contract:
 * `deny E Unknown[reflect]` must mean the same thing everywhere, which requires the same classification here.
 */
class ReasonClassTest {

    private static void maps(String raw, ReasonClass expected) {
        assertEquals(expected, ReasonClass.classify(raw), "raw reason `" + raw + "` must classify as " + expected.token());
    }

    @Test void auditedVocabularyClassifiesToTheRightClass() {
        // reflect (ts + swift emit these; rust/java to follow — finding 2)
        maps("reflect:eval", ReasonClass.REFLECT);
        maps("reflect:vm", ReasonClass.REFLECT);
        maps("reflect:require", ReasonClass.REFLECT);
        maps("reflect:accessor:x", ReasonClass.REFLECT);
        maps("reflect_apply", ReasonClass.REFLECT);
        maps("reflect-metadata", ReasonClass.REFLECT);
        maps("reflecting", ReasonClass.REFLECT);            // swift
        maps("dynamicMemberLookup", ReasonClass.REFLECT);   // swift
        // dispatch (rust/ts/java) + rust same-name ambiguity
        maps("dispatch:foo.Bar", ReasonClass.DISPATCH);
        maps("dispatch", ReasonClass.DISPATCH);
        maps("ambiguous:same-name local defs", ReasonClass.DISPATCH);
        // indirect (all engines) + ts closure
        maps("callback:unresolved call", ReasonClass.INDIRECT);
        maps("callback:opaque-iterable:param", ReasonClass.INDIRECT);
        maps("callback:computed", ReasonClass.INDIRECT);    // swift
        maps("closure", ReasonClass.INDIRECT);
        // native (rust)
        maps("native:extern fn", ReasonClass.NATIVE);
        // unresolved (ts/java/swift) + the conservative catch-all
        maps("unresolved", ReasonClass.UNRESOLVED);
        maps("some-future-reason-no-engine-emits-yet", ReasonClass.UNRESOLVED);
        maps(null, ReasonClass.UNRESOLVED);
        // setup (pinned for when engines emit it — finding 1)
        maps("missing-config", ReasonClass.SETUP);
        maps("no-tsconfig", ReasonClass.SETUP);
    }

    @Test void tokensRoundTrip() {
        for (ReasonClass c : ReasonClass.values()) {
            assertEquals(c, ReasonClass.fromToken(c.token()), "token round-trip for " + c);
        }
        assertEquals(null, ReasonClass.fromToken("not-a-class"));
    }

    /** The gate classifies via the STRING path {@code classify(ur.format())} (four-way parity with rust/ts/
     *  swift); the report still uses the structured {@code of(ur)} (Kind) path. Pin that the two AGREE for
     *  every {@code Kind} candor-java emits, so the two java code paths can never silently drift (review). */
    @Test void structuredAndStringPathsAgreeForEveryKind() {
        for (io.poly.candor.model.UnknownReason.Kind k : io.poly.candor.model.UnknownReason.Kind.values()) {
            var ur = io.poly.candor.model.UnknownReason.of(k, "detail.Sym");
            assertEquals(ReasonClass.of(ur), ReasonClass.classify(ur.format()),
                    "of(Kind) must match classify(format()) for " + k + " (" + ur.format() + ")");
        }
    }

    /** A FOREIGN engine's token in the normative {@code kind:detail} form must classify by its KIND.
     *  candor-swift emits {@code dynamicMemberLookup:<root>.<prop>} and never the bare token, so the
     *  equality test this replaced could not match a real one — the token fell through to UNRESOLVED, and
     *  because both classes sit in the `dynamic` set a bare {@code deny Unknown} still fired while the
     *  class-targeted {@code deny Unknown[reflect]} silently did not. That is the form in which the reason
     *  ratchet is actually adopted, so the weakening is exactly where it matters least visibly.
     *
     *  <p>The BARE row stays: it is what the equality test covered, and dropping it while widening would
     *  be a narrowing dressed as a fix. Both must classify REFLECT. */
    @Test void aForeignReasonTokenClassifiesByKindNotByExactString() {
        assertEquals(ReasonClass.REFLECT, ReasonClass.classify("dynamicMemberLookup:Config.host"),
                "swift's real emitted form must be REFLECT, not UNRESOLVED");
        assertEquals(ReasonClass.REFLECT, ReasonClass.classify("dynamicMemberLookup"),
                "the bare token the old equality test covered must still be REFLECT");
    }
}
