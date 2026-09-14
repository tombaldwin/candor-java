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

    /** SOUNDNESS R433/R434 — the tail was closed for `PATH_CTOR_OWNERS` and OPEN for every other Fs
     *  owner whose locator is a leading String. `new PrintWriter(argv[0])` was charged `Fs` with
     *  `incomplete` ABSENT, so `allow Fs <benign>` printed "no violations" over a caller-chosen file —
     *  and R421's own new capture made that newly exploitable (PRE exit 1, POST exit 0).
     *
     *  <p>The boundary is now DERIVED from the classification (`effect == Effect.FS` plus a leading
     *  String) rather than from a second owner list, and from the CALL SHAPE rather than a list of
     *  handle types: a ctor or a static call has no pre-existing receiver, so its leading String is its
     *  own; an instance call may be a use-verb whose locator was fixed earlier.
     *
     *  <p><b>CAPTURE AND DISCLOSURE ARE SPLIT, and the corpus decided it.</b> Capturing across the
     *  widened set published 2,910 new "paths" over 119 real jars whose distinct values were `top`,
     *  `messages`, `com.sun.faces.resources.Messages`, `jakarta.faces.Messages`, `Operation Cancelled`
     *  and `warmup` — seven values, not one a filesystem path. So the widened set discloses and does not
     *  capture; only an owner that NAMES a path contributes one. Re-measured: 0 paths moved. */
    @Test
    void anFsCallWithAnUndeterminedLeadingStringDisclosesWhoeverTheOwnerIs() throws Exception {
        Path cls = compile(Map.of("app/Wide.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "public class Wide {",
            "  void pw(String p) throws Exception { new PrintWriter(p).close(); }",
            "  void zf(String p) throws Exception { new java.util.zip.ZipFile(p).close(); }",
            // CONTROL: a use-verb on an OPEN handle. Its leading String is DATA and the locator was
            // fixed at the ctor — marking it would be R393's content-vs-path confusion from the other
            // side, and the first cut of this fix did exactly that.
            "  void handle(String data) throws Exception {",
            "    FileWriter w = new FileWriter(\"/tmp/benign/out.txt\"); w.write(data); w.close(); }",
            "}")));
        Candor.runScan(cls);
        Map<String, TreeSet<String>> inc = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        for (String m : new String[] {"pw", "zf"}) {
            assertTrue(inc.getOrDefault("app.Wide." + m, new TreeSet<>()).contains("Fs"),
                    m + ": an Fs call with a caller-chosen leading String must disclose, whoever owns it");
        }
        assertFalse(inc.getOrDefault("app.Wide.handle", new TreeSet<>()).contains("Fs"),
                "a use-verb on an open handle takes DATA, not a locator — marking it is an over-mask");
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
