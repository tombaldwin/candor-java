package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * A RAW NUL BYTE IN A SOURCE FILE MAKES THAT FILE INVISIBLE TO `grep`.
 *
 * <p>{@code Policy.unanswerableKey} joined a rule's source line to a function name with a literal NUL
 * written between the quotes rather than the {@code \0} escape. The two are the same string to the
 * compiler and nothing about the engine's behaviour differed — but {@code grep} classifies a file holding
 * a NUL as BINARY and, with no {@code -a}, reports NO MATCHES and exits 1 for it. That silently removed
 * 1,105 lines of the policy parser from every search anyone (or any agent) ran over this tree, and the
 * failure mode is the one that hides itself: a search over the file that contains the answer comes back
 * empty and reads as "not here".
 *
 * <p>Not hypothetical and not local to this engine: candor-ts introduced the identical defect from a
 * template-literal separator in the same session and removed it. The idiom — an unlikely character as a
 * key separator — recurs, so the guard is over the whole main source tree rather than the one line.
 */
class SourceHygieneTest {

    @Test
    void noMainSourceFileHoldsARawNulByte() throws IOException {
        Path root = Path.of("src/main/java");
        assertTrue(Files.isDirectory(root), "the main source tree must be findable from the test's working "
                + "directory, or this guard silently passes over zero files: " + root.toAbsolutePath());
        List<String> offenders = new ArrayList<>();
        int scanned = 0;
        try (Stream<Path> files = Files.walk(root)) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                scanned++;
                byte[] b = Files.readAllBytes(p);
                for (byte x : b)
                    if (x == 0) { offenders.add(p.toString()); break; }
            }
        }
        // The control: a guard that walked an empty tree would report success just as loudly.
        assertTrue(scanned > 0, "scanned no .java files at all — the guard proved nothing");
        assertTrue(offenders.isEmpty(), "these source files hold a raw NUL byte, so `grep` treats them as "
                + "BINARY and reports no matches for anything in them — write the `\\0` ESCAPE instead, "
                + "which compiles to the identical string: " + offenders);
    }

    /** Read the whole main tree as one string — the census tests below ask "how many places do X?", and
     *  a per-file view would answer "one" for each of two files. */
    private static String mainSource() throws IOException {
        Path root = Path.of("src/main/java");
        assertTrue(Files.isDirectory(root), "the main source tree must be findable from the test's working "
                + "directory, or every census below silently passes over zero files: " + root.toAbsolutePath());
        StringBuilder sb = new StringBuilder();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path f : files.filter(x -> x.toString().endsWith(".java")).sorted().toList())
                sb.append(Files.readString(f)).append('\n');
        }
        assertTrue(sb.length() > 10_000, "read almost no source — the census would prove nothing");
        return sb.toString();
    }

    private static int count(String hay, String needle) {
        int n = 0, i = 0;
        while ((i = hay.indexOf(needle, i)) >= 0) { n++; i += needle.length(); }
        return n;
    }

    /**
     * ONE WRITER FOR {@code crossDeps} — the chained-dependency entry index.
     *
     * <p>Its merge rule is the family-wide entry UNION (candor-spec/ENTRY-COLLISION-DECISION.md): two
     * entries under one key are unioned, never picked between. What that replaced was
     * {@code if (!de.effects.isEmpty()) crossDeps.put(h, de)} — last-non-empty-wins — under which a stale
     * report's §2.1 {@code {Unknown}} downgrade overwrote a trusted report's concrete {@code Fs} and
     * {@code deny Fs} went exit 1 to exit 0.
     *
     * <p>A SECOND WRITE SITE WOULD REINTRODUCE EXACTLY THAT and nothing would say so: the union lives at
     * the one site, so any other {@code put} into this map is last-writer-wins by construction. Counting
     * is the only way to notice, because the defect is the ABSENCE of a call to {@code unionWith}, and
     * absence is what no behavioural test can enumerate.
     */
    @Test
    void crossDepsHasExactlyOneWriter() throws IOException {
        String src = mainSource();
        assertEquals(1, count(src, "crossDeps.put("),
                "`crossDeps.put(` must appear EXACTLY once — the entry-collision union lives at that one "
                + "site, so a second raw put is last-writer-wins and silently undoes it for the keys it "
                + "touches (ENTRY-COLLISION-DECISION.md: a stale {Unknown} erasing a trusted Fs, `deny Fs` "
                + "exit 1 -> 0)");
        assertEquals(1, count(src, "prev.unionWith(de)"),
                "…and that one site must MERGE rather than overwrite");
        // VACUITY FLOOR: a rename makes both patterns unfindable and both assertions above vacuous.
        assertTrue(src.contains("void unionWith(DepFn other)"),
                "located no `unionWith` at all — this census is asserting about source it can no longer "
                + "find, and would go green through the very defect it exists to catch");
    }

    /**
     * ONE LIST OF SPEC §2.2's RESERVED SIDECAR SEGMENTS, and every locator asks it.
     *
     * <p>{@code Loader.isSidecarName} says so in its own doc — *"The ONE rule, for every locator glob in
     * this engine … because two lists that can drift apart is exactly how this started"* — and a doc
     * comment is an assertion that will be believed. This makes it fail instead.
     *
     * <p>The history is why it is worth counting: §2.2 exists because candor-rust discriminated sidecars
     * by SEGMENT COUNT and claimed one as a report; java's own earlier two-suffix list left it picking a
     * {@code gate} sidecar over the real report and refusing every query about a file the user never
     * named. And the conformance harness for PART 29 reproduced the same mistake a third time, in Python,
     * by excluding two of the six segments — so this is a rule that gets re-derived wrongly whenever it is
     * re-derived at all.
     */
    @Test
    void theReservedSidecarSegmentsAreListedExactlyOnce() throws IOException {
        String src = mainSource();
        assertEquals(1, count(src, "\"calibrated\""),
                "SPEC §2.2's reserved segments must be enumerated in ONE place (Loader's "
                + "RESERVED_SIDECAR_SEGMENTS). A second list is a list that can drift, which is how this "
                + "started — and the two lists disagreeing is unobservable until a locator picks a sidecar "
                + "as a report");
        assertEquals(1, count(src, "\"layerreach\""), "the same, for the segment least likely to be copied");
        assertTrue(count(src, "isSidecarName(") >= 3,
                "the single rule must actually be ASKED by the locators — fewer than three references "
                + "means a glob has stopped consulting it and is discriminating some other way");
        // VACUITY FLOOR.
        assertTrue(src.contains("RESERVED_SIDECAR_SEGMENTS"),
                "located no reserved-segment set — this census is asserting about source it can no longer "
                + "find");
    }
}
