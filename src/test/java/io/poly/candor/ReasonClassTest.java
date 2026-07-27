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
        // dispatch (rust/ts/java) + ⟨0.24⟩ the canonical `ambiguous:` kind (rust's same-name ambiguity)
        maps("dispatch:foo.Bar", ReasonClass.DISPATCH);
        maps("dispatch", ReasonClass.DISPATCH);
        maps("ambiguous:same-name local defs", ReasonClass.DISPATCH);
        // ⟨0.24⟩ REGISTERED dependency-boundary kinds (SPEC §4/§6.2) — pinned, not left to the catch-all
        maps("dep:9f2a3c", ReasonClass.UNRESOLVED);
        maps("dep-stale:com.example", ReasonClass.UNRESOLVED);
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

    /**
     * ⟨0.24⟩ SPEC §4's canonical kind set is FIVE, and {@code ambiguous:} is the fifth: the analyser's own
     * NAME RESOLUTION was ambiguous (two same-named local definitions), so no owner could be formed at all.
     * It must be a RECOGNIZED {@link UnknownReason.Kind}, not merely a string {@link ReasonClass#classify}
     * happens to prefix-match — because §6.2 has ALWAYS projected {@code ambiguous:*} to class
     * {@code dispatch}, a CONSUMER classified it correctly while the vocabulary it was drawn from did not
     * contain it. That asymmetry survives precisely because a consumer never complains about a token it can
     * classify. {@code dep:}/{@code dep-stale:} are registered the same way (§4 ⟨0.24⟩, class
     * {@code unresolved}).
     *
     * <p>None of these are MIGRATION kinds. This engine's migration kinds are its own {@code task-handoff:}
     * and {@code indy:}, which are to be reconciled onto the canonical five; {@code ambiguous:} /
     * {@code dep:} / {@code dep-stale:} are permanent members of the spec vocabulary and must never be
     * filed under "tolerated during migration".
     */
    @Test void theFiveCanonicalKindsAndTheTwoRegisteredOnesAreRecognized() {
        for (String p : new String[] {"reflect", "native", "dispatch", "callback", "ambiguous",
                                      "dep", "dep-stale"}) {
            assertEquals(p, java.util.Objects.requireNonNull(
                    io.poly.candor.model.UnknownReason.Kind.fromPrefix(p),
                    "SPEC §4 kind `" + p + ":` must be a recognized Kind, not a foreign prefix").prefix());
        }
        // and the classes those kinds carry, via BOTH paths
        assertEquals(ReasonClass.DISPATCH,
                ReasonClass.of(io.poly.candor.model.UnknownReason.parse("ambiguous:same-name local defs")),
                "the structured path must project the fifth kind to `dispatch` too — it is the path that "
                        + "used to read it as a foreign prefix and hand back `unresolved`");
        assertEquals(ReasonClass.UNRESOLVED,
                ReasonClass.of(io.poly.candor.model.UnknownReason.parse("dep-stale:com.example")));
    }

    /**
     * THE CONTROL. Recognizing a fifth kind must not degrade into recognizing everything: a genuinely
     * off-vocabulary kind is still foreign — no {@code Kind}, and the conservative {@code unresolved}
     * catch-all under §2 forward compatibility (it therefore stays in scope of {@code Unknown[*]} /
     * {@code Unknown[dynamic]} and is never silently tolerated). Without this, "added a fifth kind" is
     * indistinguishable from "stopped checking".
     */
    @Test void anOffVocabularyKindIsStillForeign() {
        assertEquals(null, io.poly.candor.model.UnknownReason.Kind.fromPrefix("banana"));
        assertEquals(null, io.poly.candor.model.UnknownReason.parse("banana:whatever").kind());
        assertEquals(ReasonClass.UNRESOLVED, ReasonClass.classify("banana:whatever"));
        assertEquals(ReasonClass.UNRESOLVED,
                ReasonClass.of(io.poly.candor.model.UnknownReason.parse("banana:whatever")));
        // specifically NOT the class the newly-canonical kind projects to
        org.junit.jupiter.api.Assertions.assertNotEquals(ReasonClass.DISPATCH,
                ReasonClass.classify("banana:whatever"));
    }

    /** The gate classifies via the STRING path {@code classify(ur.format())} (four-way parity with rust/ts/
     *  swift). {@code of(ur)} is the typed sibling on the model; the gate does not use it, so it is exactly
     *  the kind of second implementation that drifts unnoticed. Pin that the two AGREE for every
     *  {@code Kind} this build RECOGNIZES — which, since {@code Kind} now carries the canonical five plus
     *  the registered two, is what makes the ⟨0.24⟩ vocabulary a property of the code (review). */
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
