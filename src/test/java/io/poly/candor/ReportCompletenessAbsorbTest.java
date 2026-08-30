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
 *
 * <p><b>ROUND 2, 2026-08-30 — WHAT THIS CLASS'S FIRST VERSION COULD AND COULD NOT SEE.</b> Each of the
 * four-way's arms was deleted in turn and this class re-run. Two arms had teeth and two did not:
 *
 * <pre>
 *   branch 1  both sides empty        deleted -> 888/888 GREEN   (no test could see it)
 *   branch 2  self contributed only   deleted -> RED
 *   branch 3  other contributed only  deleted -> 888/888 GREEN   (no test could see it)
 *   branch 4  both contributed        replaced by a naive OR -> RED
 * </pre>
 *
 * The cause was the same for both blind arms and is worth stating as a rule: <b>every case posed here set
 * {@code other.predates033 = false}, and the correct answer and the naive AND agree on every input where
 * that flag is false.</b> A control has to differ from the wrong implementation in the VALUE of the field
 * under test, not merely exercise the code path — an arm reached by an input both implementations agree
 * on is an arm nothing is checking. The tests below now set that flag {@code true} on the non-self side
 * for exactly the two arms that needed it, and each was watched go red with its arm removed.
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

    /**
     * THE ARM THAT ACTUALLY DISCRIMINATES BRANCH 3 (self contributed nothing, other did). MEASURED
     * 2026-08-30: deleting that branch outright — so the merge falls through to the naive
     * {@code unaskedRulesPredates033 && other.unaskedRulesPredates033} — left ALL 888 tests green,
     * this class's own included. The reason is that every case posed here set
     * {@code other.predates033 = false}, and {@code false && false} is {@code false}: the naive AND
     * agrees with the correct answer on exactly those inputs, so the branch could not move an assertion.
     *
     * <p>The discriminating input is {@code other.predates033 = TRUE} while self is empty. Correct
     * (branch 3): the contributing side's {@code true} survives. Naive AND: {@code false && true} is
     * {@code false} — a side that named no unasked rules vetoes the other's genuine "fully explained by
     * pre-⟨0.33⟩ producers", which is the exact mislabelled-cause bug this branch exists to prevent.
     */
    @Test
    void anEmptySELFSideDoesNotVetoTheOtherSidesExplainedAnswer() {
        Query.ReportCompleteness self = with(List.of(), false);          // contributed nothing
        Query.ReportCompleteness other = with(List.of("deny Db -> app"), true);
        assertTrue(self.absorb(other).unaskedRulesPredates033(),
                "a side that named NO unasked rules must not veto the other side's genuinely-explained "
                        + "answer. This is the MIRROR of the self-side test above, and the only shape in "
                        + "this class whose expected value differs from a naive AND's — measured: with "
                        + "branch 3 deleted every other case here stays green.");
    }

    @Test
    void aSideWithNoUnaskedRulesDoesNotVetoTheOtherSidesUnexplainedAnswer() {
        // A CONSISTENCY CASE, NOT A DISCRIMINATOR — and it says so, because the comment that used to sit
        // here claimed the opposite ("not merely happen to agree with a naive AND"). It does happen to
        // agree: other.predates033=false makes the correct answer and the naive AND both false, so this
        // assertion cannot tell branch 3 from its absence. Kept because the merge must not FABRICATE a
        // true here either; the teeth against branch 3 are in the test above.
        Query.ReportCompleteness self = with(List.of(), false);
        Query.ReportCompleteness other = with(List.of("deny Db -> app"), false);
        assertFalse(self.absorb(other).unaskedRulesPredates033(),
                "the contributing side's real (unexplained) answer must survive the merge");
    }

    @Test
    void neitherSideHavingUnaskedRulesMergesToNotPredating() {
        // Same shape as the case above and, for the same reason, NOT a discriminator of branch 1:
        // with both flags false, deleting the both-empty arm still lands on false.
        Query.ReportCompleteness self = with(List.of(), false);
        Query.ReportCompleteness other = with(List.of(), false);
        assertFalse(self.absorb(other).unaskedRulesPredates033(),
                "nothing to explain on either side must not fabricate a predates-0.33 claim");
    }

    /**
     * BRANCH 1's teeth — the sibling hole, found by mutating every arm of the four-way rather than only
     * the one the review named (the audit-boundary rule: a boundary drawn around its own trigger misses
     * the next instance). MEASURED: deleting the both-empty arm ALSO left 888/888 green, for the same
     * reason branch 3's deletion did — every both-empty case posed here had both flags {@code false}.
     *
     * <p>The discriminating input sets {@code other.predates033 = true} on a side with NO unasked rules.
     * The class's javadoc says such a flag is "{@code false} by construction", and that is precisely why
     * this needs pinning: branch 1 is what makes the merged answer independent of a flag no
     * {@code unaskedRules} entry ever justified. With branch 1 deleted the merge falls to branch 3 and
     * returns that unjustified {@code true} — a fabricated "fully explained by pre-⟨0.33⟩ producers" over
     * two reports where nothing was left unasked at all.
     */
    @Test
    void anEmptySidesFlagCannotFabricateAPredatesClaim() {
        Query.ReportCompleteness self = with(List.of(), false);
        Query.ReportCompleteness other = with(List.of(), true);   // flag set with nothing to justify it
        assertFalse(self.absorb(other).unaskedRulesPredates033(),
                "with no unasked rules on EITHER side there is nothing for a predates-⟨0.33⟩ claim to be "
                        + "about, whatever the flags say — the merged list is empty, so the merged flag "
                        + "must be false");
        assertFalse(with(List.of(), true).absorb(with(List.of(), false)).unaskedRulesPredates033(),
                "and symmetrically, with the unjustified flag on the self side");
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
