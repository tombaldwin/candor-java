package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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

    @Test
    void growingAnInputThrowsNamingTheField() {
        // AnalysisContext.inputNames() enumerates every non-static, non-final, non-MEMO field, in
        // declaration order — the same order inputSizes() reports sizes in. Grow the size for exactly one
        // slot and the thrown message must name that field, not just fire generically.
        List<String> names = AnalysisContext.inputNames();
        assertTrue(names.size() > 5, "too few input fields to be a meaningful measurement: " + names.size());

        List<Integer> before = new java.util.ArrayList<>();
        for (int i = 0; i < names.size(); i++) before.add(0);
        List<Integer> after = new java.util.ArrayList<>(before);
        int grown = names.size() / 2;
        after.set(grown, 1);

        AnalysisContext.UnmergeableDelta ex = assertThrows(AnalysisContext.UnmergeableDelta.class,
                () -> AnalysisContext.assertNoInputGrowth(before, after));
        assertTrue(ex.getMessage().contains(names.get(grown)),
                "the thrown message must NAME the misclassified field ('" + names.get(grown)
                        + "'), so the fix lands on the right accumulator instead of a slot number: "
                        + ex.getMessage());
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
