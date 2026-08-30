package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * GUARD-DELETION SWEEP: {@code ReportCompleteness#absorb}'s ⟨0.34⟩ {@code unaskedRulesPredates033} merge
 * — "NAMES THE CAUSE, NEVER MOVES THE VERDICT" — had zero coverage of its own contribution. Its own javadoc
 * warns against exactly the bug a plain {@code &&} introduces: "a side that contributed NOTHING
 * ({@code unaskedRules} empty, flag {@code false} by construction) must not move the merged answer
 * either" — but replacing the four-way conditional with a naive
 * {@code unaskedRulesPredates033 && other.unaskedRulesPredates033} left the full unit suite AND
 * {@code smoke.sh} green, because no test ever called {@code absorb} on two sides where exactly ONE had
 * {@code unaskedRules} entries.
 *
 * <p>{@code absorb} merges two locators' completeness ({@code containment <baseline>}, which reads both
 * the current and baseline report sets). The naive AND is wrong precisely when one side contributed
 * NOTHING to {@code unaskedRules}: its default {@code false} then vetoes the other side's real answer,
 * turning "fully explained by pre-⟨0.33⟩ producers" into a false "not explained" — mislabelling the
 * disclosed CAUSE (never the exit code, which this flag by design never touches).
 */
class ReportCompletenessAbsorbTest {

    private static Query.ReportCompleteness with(List<String> unaskedRules, boolean predates033) {
        return new Query.ReportCompleteness(List.of(), List.of(), List.of(), List.of(), List.of(),
                List.of(), unaskedRules, predates033);
    }

    @Test
    void aSideWithNoUnaskedRulesDoesNotVetoTheOtherSidesExplainedAnswer() {
        // self: unaskedRules non-empty, fully explained by pre-0.33 producers (predates033=true).
        // other: unaskedRules EMPTY — contributed nothing, so its default-false flag must not count.
        Query.ReportCompleteness self = with(List.of("deny Net -> app"), true);
        Query.ReportCompleteness other = with(List.of(), false);
        assertTrue(self.absorb(other).unaskedRulesPredates033(),
                "a side that named NO unasked rules must not veto the other side's genuinely-explained "
                        + "answer — the merge must read the contributing side alone");
    }

    @Test
    void aSideWithNoUnaskedRulesDoesNotVetoTheOtherSidesUnexplainedAnswer() {
        // Symmetric control: other's genuine "not explained" (predates033=false) must survive the merge
        // when self contributed nothing, not merely happen to agree with a naive AND.
        Query.ReportCompleteness self = with(List.of(), false);
        Query.ReportCompleteness other = with(List.of("deny Db -> app"), false);
        assertFalse(self.absorb(other).unaskedRulesPredates033(),
                "the contributing side's real (unexplained) answer must survive the merge");
    }

    @Test
    void neitherSideHavingUnaskedRulesMergesToNotPredating() {
        Query.ReportCompleteness self = with(List.of(), false);
        Query.ReportCompleteness other = with(List.of(), false);
        assertFalse(self.absorb(other).unaskedRulesPredates033(),
                "nothing to explain on either side must not fabricate a predates-0.33 claim");
    }

    @Test
    void bothSidesContributingRequiresBothToPredate() {
        Query.ReportCompleteness bothOld = with(List.of("deny Net -> app"), true)
                .absorb(with(List.of("deny Db -> app"), true));
        assertTrue(bothOld.unaskedRulesPredates033(), "both sides fully explained by legacy producers");

        Query.ReportCompleteness oneModern = with(List.of("deny Net -> app"), true)
                .absorb(with(List.of("deny Db -> app"), false));
        assertFalse(oneModern.unaskedRulesPredates033(),
                "one genuinely modern gap (predates033=false) on either contributing side must not be "
                        + "papered over by the other's legacy explanation");
    }
}
