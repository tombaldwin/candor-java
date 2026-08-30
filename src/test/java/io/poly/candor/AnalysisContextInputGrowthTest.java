package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * {@link AnalysisContext#assertNoInputGrowth} — the refresh-cache split's own correctness check
 * (CANDOR_REFRESH_VERIFY), and, before this test, exercised by NOTHING: no test in this suite calls it,
 * and it only ever runs inside a real scan when that env var is set, over real overlay input sizes that
 * never happen to grow under the current field set. So the guard has never actually been proven to fire.
 *
 * <p>THE HAZARD IT GUARDS AGAINST, per its own doc comment: an accumulator wrongly classified as a
 * shared INPUT (non-final in {@link AnalysisContext}) writes straight into the master during {@code
 * analyze}, so its per-class delta is always empty — "the one error the cold byte-equality arm cannot
 * see, precisely because the priming run gets the right answer." A silent under-report on every refresh
 * after the first. This test proves the detector actually detects it, directly, without needing to first
 * misclassify a real field (which would mean corrupting production code to test the corruption-detector).
 */
class AnalysisContextInputGrowthTest {

    /**
     * THE PINNED SET, spelled out — {@link AnalysisContext#inputNames()} in declaration order, which is
     * also the order {@link AnalysisContext#inputSizes()} reports sizes in, so the ORDER is load-bearing
     * and this is a LIST equality, not a set one.
     *
     * <p>WHY IT IS WRITTEN OUT RATHER THAN DERIVED FROM THE CODE UNDER TEST. The previous version of this
     * test asked only {@code names.size() > 5} and then iterated whatever it was handed — a property of
     * the list, not the list. MEASURED 2026-08-30 by truncating {@code inputNames()}:
     *
     * <pre>
     *   46 -> 45 fields   GREEN      46 -> 10 fields   GREEN      46 -> 3 fields   red (the size floor)
     * </pre>
     *
     * So the growth check could go 78% blind and this test would still pass. That matters because a field
     * leaving the set is exactly how the guard loses its teeth: adding a name to {@code MEMOS}, or making
     * a field {@code final}, silently removes it from the check — and the check is what stops an
     * accumulator on the wrong side of the refresh split from silently under-reporting on every refresh
     * after the first.
     *
     * <p>THIS LIST IS EXPECTED TO NEED EDITING, and its red is the prompt to think. A new shared input
     * makes it red: decide which side of the split the field belongs on, then add the name. A field
     * DISAPPEARING is the direction that matters more — confirm it became {@code final} (correct: it is
     * an output) rather than joining {@code MEMOS}, which exempts it from the growth check entirely.
     */
    private static final List<String> EXPECTED_INPUTS = List.of(
            "crossDeps", "depFnsByOwner", "depFnsByOwnerName", "depOwnersBySigBuilt",
            "suppressibleStreamFields", "unknownAliases", "vocabularySource", "netPartners",
            "netPartnersSource", "unanalyzed", "excluded", "archives", "sourceFiles", "classpathRoots",
            "scanRoot", "outOfScope", "scannedUnder", "peekedClasses", "projectClasses", "repoTypes",
            "entityTables", "repoTables", "feignTypes", "httpClientTypes", "ALL", "byName",
            "subtypeIndex", "overloadDescs", "classesWithClinit", "taintEnabled", "unknownRatchet",
            "closedWorld", "peekVersioned", "depCoveredPkgs", "depChainedPkgs", "depReportsRead",
            "depCallsByFn", "depWhyByFn", "depSupers", "depSplitKnown", "depSuperclass", "classHash",
            "denyRules", "allowRules", "forbidRules", "onlyRules");

    @Test
    void theInputSetIsExactlyTheOnePinnedHere() {
        assertEquals(EXPECTED_INPUTS, AnalysisContext.inputNames(),
                "the shared-INPUT set — or its declaration ORDER — changed. inputNames() and inputSizes() "
                + "are index-aligned, so a reorder makes assertNoInputGrowth blame the wrong field, and a "
                + "field leaving the list drops out of the growth check altogether. Work out which side "
                + "of the refresh split the change puts the field on, then update EXPECTED_INPUTS — do "
                + "not just make this line pass.");
    }

    @Test
    void growingAnyOneInputThrowsNamingThatField() {
        // EVERY slot in turn, not one of them. The previous version grew names.size() / 2 and checked the
        // message named it — true of a correct implementation AND of one that is only right in the
        // middle. Walking all 46 also pins that inputNames() and inputSizes() stay index-aligned right to
        // the ends of the list, which a single middle probe cannot see.
        List<String> names = AnalysisContext.inputNames();
        assertEquals(EXPECTED_INPUTS, names, "this test's own precondition — pinned above");

        for (int grown = 0; grown < names.size(); grown++) {
            List<Integer> before = new java.util.ArrayList<>();
            for (int i = 0; i < names.size(); i++) before.add(0);
            List<Integer> after = new java.util.ArrayList<>(before);
            after.set(grown, 1);

            final int slot = grown;
            AnalysisContext.UnmergeableDelta ex = assertThrows(AnalysisContext.UnmergeableDelta.class,
                    () -> AnalysisContext.assertNoInputGrowth(before, after),
                    "growth in slot " + slot + " ('" + names.get(slot) + "') was not detected at all");
            assertTrue(ex.getMessage().contains(names.get(grown)),
                    "the thrown message must NAME the misclassified field ('" + names.get(grown)
                            + "', slot " + grown + "), so the fix lands on the right accumulator instead "
                            + "of a slot number: " + ex.getMessage());
        }
    }

    @Test
    void unchangedInputSizesDoNotThrow() {
        List<String> names = AnalysisContext.inputNames();
        List<Integer> sizes = new java.util.ArrayList<>();
        for (int i = 0; i < names.size(); i++) sizes.add(i);   // any fixed, stable sizes
        assertDoesNotThrow(() -> AnalysisContext.assertNoInputGrowth(sizes, new java.util.ArrayList<>(sizes)),
                "identical before/after input sizes must never be read as growth — the CONTROL for the "
                        + "test above, so its RED is proven to come from the growth, not from calling the "
                        + "method at all");
    }
}
