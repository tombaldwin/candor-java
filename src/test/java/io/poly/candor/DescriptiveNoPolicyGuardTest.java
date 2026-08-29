package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.34⟩ 37c9b10 — BACKLOG "candor-java: {@code --policy} is ACCEPTED and silently ignored on every
 * descriptive verb". {@code show}/{@code where}/{@code callers}/{@code map}/{@code diff}/
 * {@code containment}/{@code reachable}/{@code path}/{@code impact}/{@code blindspots}/{@code tour}/
 * {@code rewire} parsed {@code --policy} into {@code policyFlag} and never read it again — MEASURED
 * pre-fix, byte-identical output with and without the flag, no diagnostic. None of these verbs' SPEC §3.1
 * pinned JSON shapes carries a policy-derived field, so a user who passes {@code --policy} expecting it to
 * change the answer gets one computed without it, silently — the ⟨0.18⟩ rule's own inversion ("a
 * not-applicable flag is an exit-2 error, never a silent swallow").
 *
 * <p>Fixed with one shared check, {@link Query#DESCRIPTIVE_NO_POLICY}, applied inside {@link Query#run}
 * immediately after argument parsing and BEFORE {@code reportFlag} is ever resolved into a file read —
 * asserted here directly, by pointing {@code --report} at a path that does not exist and confirming the
 * failure is still the policy refusal, not a "file not found".
 *
 * <p>Two verbs stand in for the twelve — the fix is ONE {@code if} shared by all of them, not twelve
 * separate call sites, so one full assertion plus a membership spot-check on the rest is proportionate.
 * The positive control ({@link #aPolicyVerbIsUntouched}) proves the fix did not become a blanket
 * {@code --policy} rejection that would also break {@code whatif}/{@code fix}/{@code fix-gate}/
 * {@code unverified}/{@code gate}.
 */
class DescriptiveNoPolicyGuardTest {

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

    private int rc(String... args) {
        out.reset();
        err.reset();
        return Query.run(args);
    }

    /** {@code show} — a report locator that does not exist on disk, so a green result here can only mean
     *  the check ran BEFORE report resolution, not that some later failure happened to also exit 2. */
    @Test void showRejectsAnUnusablePolicyFlag() {
        String missingReport = tmp.resolve("does-not-exist.app.jvm.json").toString();
        String policy = tmp.resolve("some.policy").toString();
        int code = rc("show", "app.repo.read", "--report", missingReport, "--policy", policy);
        assertEquals(2, code, "`show --policy` must be a usage error (exit 2), not a silent swallow: " + err);
        assertTrue(err.toString().contains("unknown flag `--policy`"),
            "must name the flag as the cause, not a report-loading failure: " + err);
        assertTrue(err.toString().contains("no policy-relative verdict"),
            "must say WHY show has nothing for --policy to do: " + err);
        assertTrue(err.toString().contains("gate --report"),
            "must name the remedy (candor gate --report <locator> --policy <file>): " + err);
    }

    /** {@code map} — no positional query arg at all, the shortest possible invocation of this shape. */
    @Test void mapRejectsAnUnusablePolicyFlag() {
        String missingReport = tmp.resolve("also-missing.app.jvm.json").toString();
        String policy = tmp.resolve("other.policy").toString();
        int code = rc("map", "--report", missingReport, "--policy", policy);
        assertEquals(2, code, "`map --policy` must be a usage error (exit 2), not a silent swallow: " + err);
        assertTrue(err.toString().contains("unknown flag `--policy`"), err.toString());
    }

    /** THE POSITIVE CONTROL. A verb that legitimately threads {@code --policy} (SPEC §3.3.1's
     *  {@code POLICY_VERBS}) must not be caught by the same net — an over-broad fix that rejected
     *  {@code --policy} everywhere would pass the two tests above and break every real user of the flag.
     *  {@code whatif} against a missing report/policy fails for an ORDINARY reason (an unreadable file),
     *  never with "unknown flag `--policy`" — that is the discriminator this test checks. */
    @Test void aPolicyVerbIsUntouched() {
        String missingReport = tmp.resolve("wi-missing.app.jvm.json").toString();
        String policy = tmp.resolve("wi.policy").toString();
        int code = rc("whatif", "app.repo.read", "Net", "--report", missingReport, "--policy", policy);
        assertEquals(2, code, "whatif over a missing report/policy still exits 2 — but for a different reason");
        assertTrue(!err.toString().contains("unknown flag `--policy`"),
            "whatif is a POLICY_VERB and must never be told --policy is unknown: " + err);
    }

    /** THE MEMBERSHIP SWEEP for the other ten verbs this fix also covers, so the two full tests above are
     *  not standing in for a set the fix actually left half-covered. Reflects the BACKLOG's own verb list
     *  rather than re-typing it, so a future addition/removal from {@link Query#DESCRIPTIVE_NO_POLICY}
     *  fails this test until the list here is re-justified alongside it. */
    @Test void theRemainingTenDescriptiveVerbsAreCoveredByTheSameCheck() {
        assertEquals(java.util.Set.of("show", "where", "callers", "map", "diff", "containment",
                "reachable", "path", "impact", "blindspots", "tour", "rewire"),
            Query.DESCRIPTIVE_NO_POLICY,
            "the twelve-verb set the fix's own commit message names must match exactly — a silent "
            + "narrowing here would leave a verb accept-and-drop --policy again with nothing to notice");
    }
}
