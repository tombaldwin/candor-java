package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * SOUNDNESS R497 — <b>a one-function query verb must never answer ABOUT A FUNCTION NOBODY ASKED FOR.</b>
 *
 * <p>MEASURED on the jar built from the commit before this one, over a scan of
 * {@code soundness/lib/auth-2.25.60.jar}:
 *
 * <pre>
 *   candor path ProfileCredentialsProvider.resolveCredentials Exec --report auth.json
 *   -> software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider.resolveCredentials
 *      does not perform Exec  (inferred: [])                                            exit 0
 * </pre>
 *
 * <p>Two stacked defects, and the fix needs both halves:
 * <ol>
 *   <li>the match was {@code equals(q) else FIRST contains(q)} — not segment-anchored — so
 *       {@code ProfileCredentialsProvider} matched INSIDE {@code InstanceProfileCredentialsProvider};</li>
 *   <li>with several candidates it PICKED instead of refusing.</li>
 * </ol>
 *
 * <p>The sharp part: the function actually asked about is in the same report, is the only dot-anchored
 * match, and DOES perform {@code Exec} ({@code inferred: [Clock, Env, Exec, Fs, Net, Unknown]}). So the
 * verdict was a FALSE NEGATIVE on the real question, not merely a wrong subject. {@code impact} carried
 * the identical code and answered <i>"0 effectful functions transitively call it"</i> about the same
 * substituted name; post-fix the function asked about has FOUR.
 *
 * <p><b>Each half is pinned separately, because either one alone leaves a live defect.</b>
 * {@link #anchoringAloneWouldNotHaveBeenEnough} is the control for that: it uses a query with MANY
 * dot-anchored candidates, which an anchor-only fix still answers silently.
 */
class AmbiguousSelectorTest {

    @TempDir Path tmp;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private PrintStream priorOut;
    private PrintStream priorErr;

    @BeforeEach void capture() {
        priorOut = System.out;
        priorErr = System.err;
        System.setOut(new PrintStream(out, true));
        System.setErr(new PrintStream(err, true));
    }

    @AfterEach void restore() {
        System.setOut(priorOut);
        System.setErr(priorErr);
        Candor.resetState();
    }

    private static Map<String, Object> entry(String fn, List<String> inferred, List<String> calls) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", fn);
        m.put("loc", "X.java:1");
        m.put("inferred", inferred);
        m.put("direct", inferred);
        m.put("calls", calls);
        m.put("declared", List.of());
        m.put("undeclared", List.of());
        m.put("overdeclared", List.of());
        m.put("entryPoint", false);
        m.put("unresolved", false);
        m.put("hash", "");
        return m;
    }

    private Path report(String name, List<Map<String, Object>> entries) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("p"));
        env.put("analyzed", Map.of("count", entries.size(), "digest", "0"));
        env.put("functions", entries);
        Path f = tmp.resolve(name);
        Files.writeString(f, io.poly.candor.model.ReportJson.pretty(env));
        return f;
    }

    /** The real shape, minimised: one bare-suffix cousin with NO effect and the dot-anchored function
     *  actually asked about, which HAS the effect. Named after the jar it was measured on. */
    private Path awsShaped() throws Exception {
        return report("aws.json", List.of(
                entry("p.c.InstanceProfileCredentialsProvider.resolveCredentials", List.of(), List.of()),
                entry("p.c.ProfileCredentialsProvider.resolveCredentials", List.of("Exec"), List.of())));
    }

    private String[] run(Path report, String... verb) {
        out.reset();
        err.reset();
        List<String> a = new ArrayList<>(List.of(verb));
        a.addAll(List.of("--report", report.toString()));
        int rc = Query.run(a.toArray(new String[0]));
        return new String[]{out.toString(), err.toString(), String.valueOf(rc)};
    }

    // ── half 1: the match is segment-anchored ─────────────────────────────────────────────────────────

    @Test
    void pathAnswersAboutTheDotAnchoredFunctionNotTheLongerCousin() throws Exception {
        String[] r = run(awsShaped(), "path", "ProfileCredentialsProvider.resolveCredentials", "Exec");
        assertEquals("0", r[2]);
        assertTrue(r[0].contains("p.c.ProfileCredentialsProvider.resolveCredentials"),
                "must answer about the function asked for; got: " + r[0] + r[1]);
        // The heart of it: the pre-fix answer was a NEGATIVE about the cousin. A test that only asserted
        // "names the right fn" would pass on an implementation that still said `does not perform`.
        assertFalse((r[0] + r[1]).contains("does not perform"),
                "the function asked about DOES perform Exec — a negative here is the R497 defect");
        assertFalse(r[0].contains("InstanceProfileCredentialsProvider"),
                "the substituted subject must not appear at all");
    }

    @Test
    void impactAnswersAboutTheDotAnchoredFunctionNotTheLongerCousin() throws Exception {
        Path rep = report("imp.json", List.of(
                entry("p.c.InstanceProfileCredentialsProvider.resolveCredentials", List.of(), List.of()),
                entry("p.c.ProfileCredentialsProvider.resolveCredentials", List.of("Exec"), List.of()),
                entry("p.app.Caller.go", List.of("Exec"),
                        List.of("p.c.ProfileCredentialsProvider.resolveCredentials"))));
        String[] r = run(rep, "impact", "ProfileCredentialsProvider.resolveCredentials");
        assertEquals("0", r[2]);
        assertTrue(r[0].contains("p.c.ProfileCredentialsProvider.resolveCredentials"), r[0]);
        // `affectedCount: 0` is this verb's strongest claim. Pre-fix it made that claim about the cousin,
        // which really has no callers — so the assertion that discriminates is the COUNT, not the name.
        assertTrue(r[0].contains("1 effectful function"),
                "the caller of the function asked about must be counted; got: " + r[0]);
    }

    // ── half 2: MANY equally-good candidates is a refusal, not a pick ─────────────────────────────────

    /** THE CONTROL FOR HALF 1 BEING INSUFFICIENT. Every candidate here is dot-anchored, so an
     *  anchoring-only fix still has to choose one — and pre-fix `path` answered a confident
     *  "does not perform Exec" about the alphabetically-first of fourteen such candidates on the real
     *  jar, while three of the fourteen performed it. */
    @Test
    void anchoringAloneWouldNotHaveBeenEnough() throws Exception {
        Path rep = report("many.json", List.of(
                entry("p.c.AnonymousCredentialsProvider.resolveCredentials", List.of(), List.of()),
                entry("p.c.ProcessCredentialsProvider.resolveCredentials", List.of("Exec"), List.of()),
                entry("p.c.ProfileCredentialsProvider.resolveCredentials", List.of("Exec"), List.of())));
        String[] r = run(rep, "path", "resolveCredentials", "Exec");
        assertEquals("2", r[2], "many equally-good candidates must REFUSE, not pick");
        assertTrue(r[1].contains("AMBIGUOUS"), r[1]);
        // Naming the candidates is the remedy — a refusal a user cannot act on is a dead end.
        assertTrue(r[1].contains("p.c.AnonymousCredentialsProvider.resolveCredentials"), r[1]);
        assertTrue(r[1].contains("p.c.ProcessCredentialsProvider.resolveCredentials"), r[1]);
        assertTrue(r[1].contains("p.c.ProfileCredentialsProvider.resolveCredentials"), r[1]);
        assertTrue(r[0].isEmpty(), "nothing may reach stdout: a refusal is not an answer; got: " + r[0]);
    }

    @Test
    void impactRefusesOnManyToo() throws Exception {
        Path rep = report("manyi.json", List.of(
                entry("p.c.A.resolveCredentials", List.of(), List.of()),
                entry("p.c.B.resolveCredentials", List.of("Exec"), List.of())));
        String[] r = run(rep, "impact", "resolveCredentials");
        assertEquals("2", r[2]);
        assertTrue(r[1].contains("AMBIGUOUS"), r[1]);
    }

    // ── the two directions the refusal must NOT have broken ──────────────────────────────────────────

    /** The asymmetry that let R497 survive: ZERO matches already refused at exit 2. Still does. */
    @Test
    void zeroMatchesStillRefuses() throws Exception {
        String[] r = run(awsShaped(), "path", "zzz_no_such_fn", "Exec");
        assertEquals("2", r[2]);
        assertTrue(r[1].contains("no function matching"), r[1]);
        assertEquals("2", run(awsShaped(), "impact", "zzz_no_such_fn")[2]);
    }

    /** THE OVER-REFUSAL CONTROL. A refusal rung's failure mode is refusing questions that have one right
     *  answer, and that would be invisible to every assertion above. A fully-qualified name, and a
     *  segment-suffix with exactly one dot-anchored candidate, must both still answer. */
    @Test
    void anUnambiguousQuestionStillGetsItsAnswer() throws Exception {
        Path rep = awsShaped();
        String[] full = run(rep, "path", "p.c.InstanceProfileCredentialsProvider.resolveCredentials", "Exec");
        assertEquals("0", full[2]);
        assertTrue(full[0].contains("does not perform Exec"),
                "a determined negative about the function actually named is the correct answer: " + full[0]);
        String[] one = run(report("one.json", List.of(
                entry("p.c.OnlyOne.doIt", List.of("Exec"), List.of()))), "path", "OnlyOne.doIt", "Exec");
        assertEquals("0", one[2]);
        assertTrue(one[0].contains("p.c.OnlyOne.doIt"), one[0]);
    }

    /** Ambiguity is over DISTINCT NAMES, not rows. `--report` unions a report SET, so the same qual can
     *  arrive twice; counting rows would refuse a question with exactly one answer. */
    @Test
    void duplicateRowsForOneNameAreNotAmbiguity() throws Exception {
        Path rep = report("dup.json", List.of(
                entry("p.c.OnlyOne.doIt", List.of("Exec"), List.of()),
                entry("p.c.OnlyOne.doIt", List.of("Exec"), List.of())));
        String[] r = run(rep, "path", "OnlyOne.doIt", "Exec");
        assertEquals("0", r[2], "one name, two rows, one answer: " + r[1]);
    }
}
