package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R464 — THE Exec MASKING GUARD WAS THE LAST OWNER-LIST ONE IN THIS ENGINE.
 *
 * <p>R409 measured Fs as the one allowlist-shaped effect and recorded that "Net, Exec and Db are all
 * CAUGHT". That verdict for Exec was taken on {@code ProcessBuilder} and {@code Runtime.exec} — the two
 * owners named inside the guard — which is an audit boundary drawn around its own trigger. The guard
 * fires on those two owners and nothing else, while {@code Classifier.classify} charges {@code Exec} on
 * {@code System.load}/{@code loadLibrary} and their {@code Runtime} twins, on {@code Desktop.browse}/
 * {@code open}, and on a dozen third-party launchers.
 *
 * <p>MEASURED on the pre-fix engine, one variable — the presence of the benign sibling:
 *
 * <pre>
 *   new ProcessBuilder("git","status").start();   // benign, captures cmds:["git"]
 *   System.load(argv[0]);                          // a caller-chosen NATIVE LIBRARY
 *   → cmds:["git"], `incomplete` ABSENT, `allow Exec git` EXIT 0, "candor-java: no violations"
 * </pre>
 *
 * <p>Six spellings measured exit 0 that way: {@code System.load}, {@code System.loadLibrary},
 * {@code Runtime.load}, {@code Runtime.loadLibrary}, {@code Desktop.open(File)}, {@code
 * Desktop.browse(URI)}. Calibration on each of the same fixtures: {@code deny Exec} exits 1, so the gate
 * could fail. Controls: {@code Runtime.exec(argv[0])} and {@code new ProcessBuilder(argv[0])} — the two
 * owners the old branch names — exited 1 before and after.
 *
 * <p>PRICED with {@code bin/corpus-ab.py} over 324 real jars / 1,181,397 rows: <b>1,995 rows changed,
 * 0 added, 0 REMOVED</b>; the only field that moved on any of them was {@code incomplete}, every one
 * GAINED it and none lost one, and {@code inferred} changed on 0 rows. REACH 273 markings across 40
 * entries, so the branch demonstrably ran. The whole over-mask risk is the {@code java.io.File} operand
 * position ({@code pb.directory(File)}, {@code pb.redirectOutput(File)}), because {@code
 * Desktop.open(File)} launches the handler FOR its File and the descriptor cannot tell the two apart —
 * 18 functions reach it, 11 have no other new marking, and only <b>3</b> changed a row. All three were
 * read by name and all three are correct: {@code MongoCryptHelper.startProcess(ProcessBuilder)},
 * {@code ProcessCreation.$anonfun$apply$1(ProcessBuilder,File)} and {@code ProcessExecutor.directory}
 * each take the builder (or its configuration) as a PARAMETER, so the command really is caller-supplied.
 */
class ExecMaskingGuardTest {

    /** The benign sibling every arm carries: a fully visible program head that populates {@code cmds}
     *  and would certify under {@code allow Exec git}. Without it these functions would fail closed on
     *  the empty-{@code cmds} branch and the test could not discriminate. */
    private static final String BENIGN =
            "    try { new ProcessBuilder(\"git\",\"status\").start(); } catch (Exception e) {}";

    private static Path fixture() throws Exception {
        return compile(Map.of("app/Ex.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "public class Ex {",
            // ── THE BYPASSES. Each loads or launches something the caller chooses, beside `git`.
            "  void sysLoad(String[] argv) { ", BENIGN, "    System.load(argv[0]); }",
            "  void sysLoadLibrary(String[] argv) { ", BENIGN, "    System.loadLibrary(argv[0]); }",
            "  void rtLoad(String[] argv) { ", BENIGN, "    Runtime.getRuntime().load(argv[0]); }",
            "  void rtLoadLibrary(String[] argv) { ", BENIGN, "    Runtime.getRuntime().loadLibrary(argv[0]); }",
            "  void desktopOpen(String[] argv) throws Exception { ", BENIGN,
            "    java.awt.Desktop.getDesktop().open(new File(argv[0])); }",
            "  void desktopBrowse(String[] argv) throws Exception { ", BENIGN,
            "    java.awt.Desktop.getDesktop().browse(new java.net.URI(argv[0])); }",
            // ── R466's masking half: `command(...)` REPLACES the ctor's program, so `git` never runs.
            //    EXECUTED proof, not read from the javadoc: a fixture doing exactly this printed
            //    "MOVED-AND-RAN" from /bin/echo. The report still NAMES `git` (a fabricated `cmds`
            //    entry — see R466), but the verdict must at least fail closed.
            "  void commandMoved(String[] argv) throws Exception {",
            "    ProcessBuilder pb = new ProcessBuilder(\"git\",\"status\");",
            "    pb.command(argv[0]); pb.start(); }",
            // ── THE CONTROLS. Each launches only `git`, fully visible, and must STAY certifiable.
            //    A rule keyed on "carries arguments" alone marks all four of these — that is why the
            //    carve-out is by operand TYPE and not by argument count.
            "  void ctlWaitFor() throws Exception {",
            "    Process p = new ProcessBuilder(\"git\",\"status\").start(); p.waitFor(); }",
            "  void ctlWaitForTimed() throws Exception {",
            "    Process p = new ProcessBuilder(\"git\",\"status\").start();",
            "    p.waitFor(1, java.util.concurrent.TimeUnit.SECONDS); }",
            "  void ctlRedirectErrorStream() throws Exception {",
            "    new ProcessBuilder(\"git\",\"status\").redirectErrorStream(true).start(); }",
            "  void ctlRedirect() throws Exception {",
            "    new ProcessBuilder(\"git\",\"status\").redirectOutput(ProcessBuilder.Redirect.INHERIT).start(); }",
            "}")));
    }

    private static TreeSet<String> inc(Map<String, TreeSet<String>> m, String fn) {
        return m.getOrDefault("app.Ex." + fn, new TreeSet<>());
    }

    /** The defect arms. Each is an {@code Exec} reach whose program is caller-chosen, standing beside a
     *  literal one — the shape that certified on the pre-fix engine. */
    @Test
    void anExecCallThatNamesNoVisibleCommandDisclosesWhoeverTheOwnerIs() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> m = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        for (String fn : new String[] {"sysLoad", "sysLoadLibrary", "rtLoad", "rtLoadLibrary",
                                       "desktopOpen", "desktopBrowse", "commandMoved"}) {
            assertTrue(inc(m, fn).contains("Exec"),
                    fn + ": a caller-chosen program beside a benign literal must mark Exec incomplete — "
                    + "this is the case that exited 0 with `allow Exec git`");
        }
    }

    /** THE OVER-CHARGE CONTROL, and it is the arm that decided the rule's shape. An {@code Exec} call
     *  that cannot carry a program — every operand a primitive, a {@code TimeUnit} or a {@code Redirect}
     *  — is evidence in NEITHER direction, exactly as the Net rule says of a zero-argument call. Marking
     *  these would make {@code allow Exec <head>} unusable on the commonest subprocess idiom there is. */
    @Test
    void anExecCallThatCannotCarryAProgramIsNotEvidenceOfIncompleteness() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> m = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        for (String fn : new String[] {"ctlWaitFor", "ctlWaitForTimed",
                                       "ctlRedirectErrorStream", "ctlRedirect"}) {
            assertFalse(inc(m, fn).contains("Exec"),
                    fn + ": every operand here is a primitive, a TimeUnit or a Redirect — none can be a "
                    + "program, so this call is not evidence that the command surface is incomplete");
        }
        assertTrue(AnalysisState.ctx().cmdsDirect
                        .getOrDefault("app.Ex.ctlWaitFor", new TreeSet<>()).contains("git"),
                "and the visible head must still be captured: a command left out of `cmds` cannot be "
                + "certified by any allowlist");
    }
}
