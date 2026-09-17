package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R477 — R464 READ THE PROGRAM OUT OF THE ARGUMENTS AND NEVER LOOKED AT THE RECEIVER.
 *
 * <p>{@code Candor#execCallCouldNameAProgram} answers {@code false} for an argument-less call, on the
 * stated ground that such a call "cannot name a command". That is true of {@code p.waitFor()} and false
 * of {@code b.start()}: a {@code ProcessBuilder} IS the program, so a spawn whose builder arrives from
 * anywhere but this function launches something the gate never saw, and R464's branch — keyed on the
 * ARGUMENT list — has nothing to mark.
 *
 * <p>MEASURED on {@code fd4199c} (R464's own commit), one variable, the benign sibling literal:
 *
 * <pre>
 *   public static void f(ProcessBuilder b) throws Exception {
 *     new ProcessBuilder("git").start();   // benign, captures cmds:["git"]
 *     b.start();                           // the caller's program
 *   }
 *   → cmds:["git"], `incomplete` ABSENT, `allow Exec git` EXIT 0, "candor-java: no violations"
 * </pre>
 *
 * <p>Delete the benign line and the same function exits 1; {@code deny Exec} exits 1 on both, so the gate
 * could fail and the exit 0 is the sibling literal and nothing else. This is R464's class at the other
 * operand position, exactly as R414 was R409's — and the rust twin (R460) had already closed the receiver
 * form, so the family shipped one engine right and one wrong until conformance PART 91's {@code e2recv}
 * arm said so on its first execution.
 *
 * <p>THE RULE IS DERIVED, NOT A SECOND OWNER LIST — re-introducing one is what R464 removed. An
 * {@code Exec} call's RECEIVER could be carrying the program unless it is a handle to a process that is
 * ALREADY RUNNING ({@code Candor#EXEC_LAUNCHED_HANDLE_TYPES}: {@code Process}, {@code ProcessHandle}),
 * whose program was named wherever that handle was produced. So a third-party spawner nobody listed —
 * testcontainers' {@code GenericContainer.start()}, scala's {@code AbstractBuilder.run(Z)}, whose only
 * argument is a boolean and which therefore reads as argument-less to R464's rule — DISCLOSES instead of
 * going silent. Census over 242 real jars: 882 {@code Exec} call sites, 380 of them argument-less
 * instance calls, splitting 367 already-running handle verbs (carved out) against 13 program-carrying
 * receivers that launch.
 *
 * <p>THE CONTROLS ARE THE POINT OF THE FILE. Widening a masking guard is where this family turns a
 * silence into an unusable gate (R416), and R464's own over-charge control caught the first cut of this
 * fix: reading {@code newType} (the NEW instruction alone) reddened {@code ctlRedirectErrorStream}, a
 * fully determined {@code new ProcessBuilder("git","status").redirectErrorStream(true).start()}, on the
 * first {@code ./gradlew test} and before any corpus run. {@code Interp.ProvValue#allocChain} —
 * "built by THIS method", surviving a store/load and a self-returning builder step — is what keeps the
 * determined spellings certifiable.
 */
class ExecReceiverLocatorTest {

    /** The benign sibling every arm carries: a fully visible program head that populates {@code cmds} and
     *  would certify under {@code allow Exec git}. Without it these functions fail closed on the
     *  empty-{@code cmds} branch and the test could not discriminate. */
    private static final String BENIGN =
            "    try { new ProcessBuilder(\"git\",\"status\").start(); } catch (Exception e) {}";

    private static Path fixture() throws Exception {
        return compile(Map.of("app/Rx.java", String.join("\n",
            "package app;",
            "import java.util.List;",
            "public class Rx {",
            "  static ProcessBuilder FIELD;",
            "  static ProcessBuilder make() { return new ProcessBuilder(\"sh\"); }",
            // ── THE BYPASSES. In each, the builder that actually runs was configured somewhere else,
            //    so the program is invisible here and the benign `git` beside it must not certify it.
            "  static void recvParam(ProcessBuilder b) throws Exception { ", BENIGN,
            "    b.start(); }",
            "  static void recvField() throws Exception { ", BENIGN,
            "    FIELD.start(); }",
            "  static void recvReturn() throws Exception { ", BENIGN,
            "    make().start(); }",
            "  static void recvListElement(List<ProcessBuilder> bs) throws Exception { ", BENIGN,
            "    bs.get(0).start(); }",
            "  static void recvBranchMerged(boolean c, ProcessBuilder other) throws Exception { ", BENIGN,
            "    ProcessBuilder pb = c ? new ProcessBuilder(\"git\") : other; pb.start(); }",
            // A builder built here whose program is then REPLACED from a caller-supplied value: the chain
            // must not launder it. R464's rule marks at `command(...)`; this pins that the R477 chain
            // peel did not undo that.
            "  static void recvChainCommandMoved(String[] argv) throws Exception {",
            "    new ProcessBuilder(\"git\").command(argv[0]).start(); }",
            // ── THE CONTROLS. Each runs only the fully visible `git` and must STAY certifiable.
            "  static void ctlInline() throws Exception { new ProcessBuilder(\"git\",\"status\").start(); }",
            "  static void ctlLocal() throws Exception {",
            "    ProcessBuilder pb = new ProcessBuilder(\"git\",\"status\"); pb.start(); }",
            "  static void ctlChainInheritIo() throws Exception {",
            "    new ProcessBuilder(\"git\",\"status\").inheritIO().start(); }",
            "  static void ctlChainRedirectErrorStream() throws Exception {",
            "    new ProcessBuilder(\"git\",\"status\").redirectErrorStream(true).start(); }",
            // The handle carve-out, in both the shapes that matter: a Process the caller hands us, and a
            // Process this method spawned. Neither call launches anything — the program was named where
            // the handle was produced — so neither is evidence the command surface is incomplete.
            "  static void ctlHandleParam(Process p) throws Exception { ", BENIGN,
            "    p.waitFor(); p.destroy(); p.getInputStream().close(); }",
            "  static void ctlHandleLocal() throws Exception {",
            "    Process p = new ProcessBuilder(\"git\",\"status\").start();",
            "    p.waitFor(); p.getInputStream().close(); }",
            "}")));
    }

    private static TreeSet<String> inc(Map<String, TreeSet<String>> m, String fn) {
        return m.getOrDefault("app.Rx." + fn, new TreeSet<>());
    }

    /** THE DEFECT ARMS. Each is a spawn whose program arrives through the RECEIVER from outside this
     *  function, standing beside a literal one — the shape that exited 0 on the pre-fix engine. */
    @Test
    void aSpawnWhoseBuilderWasNotBuiltHereDisclosesHoweverTheBuilderArrived() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> m = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        for (String fn : new String[] {"recvParam", "recvField", "recvReturn", "recvListElement",
                                       "recvBranchMerged", "recvChainCommandMoved"}) {
            assertTrue(inc(m, fn).contains("Exec"),
                    fn + ": the program this spawn runs was chosen outside this function, so a benign "
                    + "sibling literal must not certify it — this is the case that exited 0 under "
                    + "`allow Exec git` on fd4199c");
        }
    }

    /** THE OVER-CHARGE CONTROL, and the arm that decided the rule's shape. A builder BUILT HERE has
     *  already had its program captured (or its absence marked) at the constructor, and every later
     *  program-naming verb is marked at its own site by R464 — so marking the spawn too is the over-mask
     *  that makes {@code allow Exec <head>} unusable on ordinary subprocess code (R416's shape). The
     *  chained arms are here because the first cut of the fix failed exactly them. */
    @Test
    void aBuilderBuiltHereStillCertifiesInlineThroughALocalAndThroughABuilderChain() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> m = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        for (String fn : new String[] {"ctlInline", "ctlLocal", "ctlChainInheritIo",
                                       "ctlChainRedirectErrorStream"}) {
            assertFalse(inc(m, fn).contains("Exec"),
                    fn + ": this builder was built in this function with a visible program head, so the "
                    + "command surface is complete and marking it would refuse ordinary code");
        }
        assertTrue(AnalysisState.ctx().cmdsDirect
                        .getOrDefault("app.Rx.ctlInline", new TreeSet<>()).contains("git"),
                "and the visible head must still be captured: a command left out of `cmds` cannot be "
                + "certified by any policy");
    }

    /** THE HANDLE CARVE-OUT. A {@code Process} / {@code ProcessHandle} receiver denotes a process that is
     *  already running, so {@code waitFor}/{@code destroy}/{@code getInputStream} launch nothing and name
     *  no program — the Exec counterpart of the {@code FileOutputStream} carve-out {@code
     *  Candor#FS_LOCATOR_TYPES} describes for {@code Fs}. 367 of the 380 argument-less {@code Exec}
     *  instance calls in a 242-jar census are these verbs; marking them is the difference between this
     *  fix and one nobody can adopt. */
    @Test
    void aHandleToAnAlreadyRunningProcessNamesNoProgramAndIsNotEvidenceOfIncompleteness() throws Exception {
        Candor.runScan(fixture());
        Map<String, TreeSet<String>> m = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        for (String fn : new String[] {"ctlHandleParam", "ctlHandleLocal"}) {
            assertFalse(inc(m, fn).contains("Exec"),
                    fn + ": a Process handle was produced by whoever spawned it; these verbs launch "
                    + "nothing, so they are evidence in neither direction");
        }
    }
}
