package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R421 — THE STRING-LOCATOR TAIL REACHED NO MASKING GUARD AT ALL.
 *
 * <p>Two guards stood either side of this and neither covered it. {@code pathArgIsSingleString} requires
 * the path to be the ONLY String — deliberately, because a two-String ctor's second literal can be a mode
 * or a child name, and capturing it would fabricate a destination. {@code FS_LOCATOR_TYPES} excludes
 * {@code Ljava/lang/String;} — deliberately, because a String argument to an Fs call is as often DATA as
 * a path. Between them sat every path ctor that takes the path as a LEADING String and something else
 * after it:
 *
 * <pre>
 *   new FileOutputStream(userPath, true)     new RandomAccessFile(userPath, "rw")
 *   new FileReader(userPath, UTF_8)          new FileWriter(userPath, true)
 * </pre>
 *
 * <p>MEASURED on the shipped jar: a method doing {@code Files.write(Paths.get("/tmp/benign"), …)} and then
 * {@code new FileOutputStream(argv[0], true).write(42)} reported {@code paths: ["/tmp/benign"]} with NO
 * incompleteness, and {@code allow Fs /tmp/benign} EXITED 0 over an append to a caller-chosen file.
 * Identical on the 0.36.1 jar, so pre-existing rather than introduced by ⟨0.37⟩.
 *
 * <p><b>The boundary WAS written down</b> — in {@code FS_LOCATOR_TYPES}'s javadoc, as leaving the tail
 * "exactly where it was before this rule — no worse, and named here so the boundary is stated rather than
 * implied". It was named and it was still live. A limitation written as a comment reads as CONSIDERED,
 * which is what stops it being measured.
 *
 * <p><b>THE SPLIT IS ON HOW MANY STRINGS THE CTOR TAKES, and the first draft got it wrong.</b> That draft
 * stayed silent whenever every String operand was a compile-time constant, reasoning that a destination
 * visible in the source is not a masked one. It is, when nobody RECORDS it — {@code
 * new RandomAccessFile("/etc/passwd", "rw")} beside a benign literal measured EXIT 0, a fully determined
 * destination certified by a sibling because it never reached {@code paths}. Visible-to-a-reader is not
 * visible-to-the-gate, and {@link #aDeterminedTwoStringPathIsNotCertifiedByASibling()} is that case.
 *
 * <p>PRICED against 119 real jars (515,029 rows): 71 changed, 3 added, <b>0 removed</b> — every change in
 * the disclosure direction, and only ELEVEN of them a direct call site. Each of those eleven was read by
 * name and is a genuine runtime-path open (a log file, a metrics writer, {@code RandomAccessFile(path,
 * mode)}), which is exactly the surface {@code PATH_CTOR_OWNERS}'s own comment says must not be maskable.
 */
class StringLocatorTailMaskingTest {

    private static Path fixture() throws Exception {
        return compile(Map.of("app/Tail.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "import java.nio.file.*;",
            "import java.nio.charset.StandardCharsets;",
            "public class Tail {",
            // THE EVASIONS: a benign visible literal beside a caller-chosen path, in each spelling that
            // fell between the two guards.
            "  void append(String[] argv) throws Exception {",
            "    Files.write(Paths.get(\"/tmp/benign\"), new byte[]{1});",
            "    new FileOutputStream(argv[0], true).write(42); }",
            "  void randomAccess(String[] argv) throws Exception {",
            "    Files.write(Paths.get(\"/tmp/benign\"), new byte[]{1});",
            "    new RandomAccessFile(argv[0], \"rw\").write(42); }",
            "  void reader(String[] argv) throws Exception {",
            "    Files.write(Paths.get(\"/tmp/benign\"), new byte[]{1});",
            "    new FileReader(argv[0], StandardCharsets.UTF_8).read(); }",
            // DETERMINED but AMBIGUOUS: both Strings are literals, yet neither can be named as THE path,
            // so the destination never reaches `paths` and a sibling would certify it.
            "  void determinedTwoString() throws Exception {",
            "    Files.write(Paths.get(\"/tmp/benign\"), new byte[]{1});",
            "    new RandomAccessFile(\"/etc/passwd\", \"rw\").write(42); }",
            // THE OVER-MASK CONTROL: one String, and it is a literal. Unambiguous, so it must be
            // CAPTURED and must still certify.
            "  void determinedOneString() throws Exception {",
            "    new FileOutputStream(\"/tmp/benign\", true).write(42); }",
            "}")));
    }

    @Test
    void theStringLocatorTailFailsClosedInEverySpelling() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> inc = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        for (String m : new String[] {"append", "randomAccess", "reader"}) {
            assertTrue(inc.getOrDefault("app.Tail." + m, new TreeSet<>()).contains("Fs"),
                    m + ": a caller-chosen path beside a benign literal must mark Fs incomplete — this is "
                    + "the case that exited 0 on the shipped jar");
        }
    }

    /**
     * The one the first draft of the fix got WRONG. Both Strings are compile-time constants, so a rule
     * keyed on "is everything determined" stays silent — and a write to /etc/passwd is then certified by
     * a benign sibling, because being visible in the SOURCE is not the same as being in {@code paths}.
     */
    @Test
    void aDeterminedTwoStringPathIsNotCertifiedByASibling() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> inc = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        assertTrue(inc.getOrDefault("app.Tail.determinedTwoString", new TreeSet<>()).contains("Fs"),
                "two Strings means we cannot say WHICH is the locator; guessing fabricates a destination, "
                + "so the honest answer is to disclose — not to stay silent because both happen to be literals");
    }

    /**
     * THE CONTROL, and it must assert the CAPTURE and not merely the exit: one String operand is
     * unambiguously arg 0, so the ambiguity that keeps {@code pathArgIsSingleString} narrow does not
     * exist. Before this change {@code new FileOutputStream("/tmp/log", true)} was uncertifiable — a
     * determined path nobody recorded — so this arm is a fix, not just a guard against one.
     */
    @Test
    void anUnambiguousSingleStringPathIsCapturedAndStillCertifies() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> inc = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        assertFalse(inc.getOrDefault("app.Tail.determinedOneString", new TreeSet<>()).contains("Fs"),
                "one String operand is unambiguously the path — a literal there must not be disclosed as invisible");
        assertTrue(AnalysisState.ctx().pathsDirect
                        .getOrDefault("app.Tail.determinedOneString", new TreeSet<>()).contains("/tmp/benign"),
                "and it must be CAPTURED: a path left out of `paths` cannot be certified by any allowlist");
    }
}
