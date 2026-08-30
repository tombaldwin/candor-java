package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * {@code Policy.scopeIsExact} (private, exercised through {@link Policy#scopeMatches}) — the trailing
 * `::` / `.` EXACT-SEGMENT marker, and before this test, exercised by NOTHING in this suite: a grep of
 * every test file for a scope literal ending in `::` or `.` (as opposed to `::` used mid-string as a
 * plain segment separator, which several tests do use) found zero hits, and deleting the whole method
 * body (replacing it with `return false`) left the ENTIRE unit suite, the smoke suite, and
 * `ci/self-gate.sh` fully green (confirmed in a throwaway worktree, not theorised).
 *
 * <p>THE FIELD BUG THIS GUARDS, verbatim from the method's own doc comment: `forbid aws -> app` fired 14
 * times on honest AWS SDK calls because bare `app` prefix-matches `application`; writing `app::` to fix
 * it did nothing, because {@link Policy#nameSegments} used to drop the trailing separator's meaning along
 * with the empty segment it produces. The reporter's workaround was to delete the rule entirely — the
 * real cost, since nothing in the policy file then records that a boundary stopped being checked. This
 * pins the fix so a future change to {@code nameSegments} or {@code scopeMatches} cannot silently
 * reopen it.
 */
class ScopeExactSuffixTest {

    @Test
    void trailingDoubleColonRequiresAnExactSegment_bareFormKeepsThePrefixBehaviour() {
        // `app::` must NOT prefix-match "application" — the exact bug report.
        assertFalse(Policy.scopeMatches("application.Foo.bar", "app::"),
                "app:: must be an EXACT segment match, not a prefix — application must not match");
        // `app::` MUST still match the segment "app" itself.
        assertTrue(Policy.scopeMatches("app.Foo.bar", "app::"),
                "app:: must match the exact segment app");
        // The bare form is UNCHANGED (additive fix) — application still matches plain `app`.
        assertTrue(Policy.scopeMatches("application.Foo.bar", "app"),
                "bare 'app' must keep its documented prefix behaviour (no verdict moves for existing rules)");
    }

    @Test
    void trailingDotAlsoRequiresAnExactSegment() {
        assertFalse(Policy.scopeMatches("application.Foo.bar", "app."),
                "a trailing '.' must ALSO mean an exact-segment match, not a prefix");
        assertTrue(Policy.scopeMatches("app.Foo.bar", "app."),
                "app. must match the exact segment app");
    }

    @Test
    void exactSegmentMatchingAppliesAtAnyPosition_notOnlyTheLast() {
        // The exact marker binds the LAST segment of the scope, wherever that scope matches inside a
        // longer dotted name — not only when the scope happens to be the tail of the whole name.
        assertFalse(Policy.scopeMatches("app.application.Foo", "app::app::"),
                "an exact multi-segment scope must not prefix-match a longer inner segment either");
        assertTrue(Policy.scopeMatches("app.app.Foo", "app::app::"),
                "an exact multi-segment scope must match when every segment is exact");
    }
}
