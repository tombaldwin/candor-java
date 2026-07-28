package io.poly.candor;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * ⟨0.24⟩ SPEC §3.1 — <b>PRECEDENCE BINDS THE VERDICT, NOT THE POLICY GATE</b>, and the vocabulary anchor
 * is the RESOLVED policy path however it was supplied.
 *
 * <p>Both defects here are things the CLI does, not things a library call does, so every case runs the real
 * binary as a subprocess and reads the {@code --gate-json} DOCUMENT — which is the whole point: the
 * measured harm in each was a finding that survived on stderr and vanished from the machine channel.
 */
class VerdictPrecedenceTest {

    private record Run(int exit, String stdout, String stderr) {}

    private Path scratch;

    @BeforeEach
    void mkScratch() throws Exception {
        scratch = Files.createTempDirectory("candor-precedence");
    }

    @AfterEach
    void rmScratch() throws Exception {
        if (scratch == null || !Files.exists(scratch)) return;
        try (Stream<Path> s = Files.walk(scratch)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    /** Run the real CLI as a subprocess (main() calls System.exit), with an env overlay. */
    private static Run runCli(Map<String, String> env, String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().putAll(env);
        Process p = pb.start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    private Path compile(String dir, String src) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path srcDir = scratch.resolve("src-" + dir);   // public class Svc ⇒ the file MUST be named Svc.java
        Files.createDirectories(srcDir);
        Path file = srcDir.resolve("Svc.java");
        Files.writeString(file, src);
        Path out = scratch.resolve(dir);
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), file.toString()), "fixture must compile");
        return out;
    }

    /** The SAME class, pure — the frozen baseline's world. */
    private Path pureFixture() throws Exception {
        return compile("before", """
            package app;
            public class Svc {
                public int compute(int x) { return x * 2; }
            }
            """);
    }

    /** …and after it gains an `Fs` call: the AS-EFF-005 regression. */
    private Path regressedFixture() throws Exception {
        return compile("after", """
            package app;
            import java.nio.file.Files;
            import java.nio.file.Path;
            public class Svc {
                public int compute(int x) throws Exception {
                    Files.readString(Path.of("/tmp/x"));
                    return x * 2;
                }
            }
            """);
    }

    private static JsonObject doc(Path p) throws Exception {
        return JsonParser.parseString(Files.readString(p)).getAsJsonObject();
    }

    private static List<String> ruleIds(JsonObject verdict) {
        List<String> ids = new ArrayList<>();
        if (!verdict.has("violations")) return ids;
        for (JsonElement e : verdict.getAsJsonArray("violations"))
            ids.add(e.getAsJsonObject().get("rule").getAsString());
        return ids;
    }

    // ── ITEM 1: a certain BASELINE regression is not deleted by an unrelated policy refusal ───────────

    /**
     * SPEC §3.1 ⟨0.24⟩: the AS-EFF-005 baseline ratchet is a violation PRODUCER that runs BEFORE the policy
     * gate and records into the same verdict. A policy the engine cannot honour must not delete what it
     * established. Measured before the fix: exit 2 with NO `violations` key — the regression survived only
     * on stderr, so the human kept it and CI lost it.
     */
    @Test
    void aBaselineRegressionSurvivesAnUnrelatedPolicyRefusal() throws Exception {
        Path before = pureFixture(), after = regressedFixture();
        Path baseline = scratch.resolve("baseline.json");
        assertEquals(0, runCli(Map.of(), before.toString(), "--json", baseline.toString()).exit(),
                "the baseline scan must succeed");

        // CONTROL — no policy at all: the ratchet fires and the document names it.
        Path control = scratch.resolve("control.json");
        Run c = runCli(Map.of("CANDOR_BASELINE", baseline.toString()),
                after.toString(), "--gate-json", control.toString());
        assertEquals(1, c.exit(), "control: a gained effect vs the baseline is exit 1\nSTDERR:\n" + c.stderr());
        assertEquals(List.of("AS-EFF-005"), ruleIds(doc(control)), "control: the regression is in the document");

        // …and now the same run with a policy carrying a bad class token.
        Path pol = scratch.resolve("bad.policy");
        Files.writeString(pol, "deny Unknown[corp] app\ndeny Net app\n");
        Path verdict = scratch.resolve("verdict.json");
        Run r = runCli(Map.of("CANDOR_BASELINE", baseline.toString()),
                after.toString(), "--policy", pol.toString(), "--gate-json", verdict.toString());

        JsonObject v = doc(verdict);
        // THE ASSERTION THIS TEST EXISTS FOR: the violation is IN THE DOCUMENT.
        assertTrue(v.has("violations"),
                "the certain baseline violation MUST be in the verdict document, not only on stderr\nDOC:\n" + v);
        assertEquals(List.of("AS-EFF-005"), ruleIds(v),
                "…and it is the same finding the control produced\nDOC:\n" + v);
        assertEquals(1, r.exit(),
                "a violation established on carried evidence dominates a refusal (violation 1 > refusal 2)"
                + "\nSTDERR:\n" + r.stderr());
        assertFalse(v.get("ok").getAsBoolean(), "ok is false either way");

        // THE MIRROR: exit 1 must NOT read as "the policy ran and this is all it found". The document says
        // the policy was refused, why, and which of its rules therefore went unevaluated — ALL of them.
        assertTrue(v.has("refused") && v.get("refused").getAsBoolean(),
                "the refusal is still disclosed beside the violation\nDOC:\n" + v);
        assertTrue(v.has("reason") && v.get("reason").getAsString().contains("corp"),
                "`reason` names the cause\nDOC:\n" + v);
        JsonArray un = v.getAsJsonArray("unevaluated");
        List<String> rules = new ArrayList<>();
        for (JsonElement e : un) rules.add(e.getAsJsonObject().get("rule").getAsString());
        assertEquals(List.of("deny Unknown[corp] app", "deny Net app"), rules,
                "one entry per RULE, the raw line verbatim — including the rules that carry no typo, because "
                + "a refused policy is evaluated as a whole or not at all\nDOC:\n" + v);
        for (JsonElement e : un)
            assertTrue(e.getAsJsonObject().has("why"), "each unevaluated row carries a `why`");
    }

    /**
     * THE MIRROR OF THE FIX ABOVE, and the reason its arm is keyed on "evaluated nothing" rather than
     * "ended refused": with NO earlier producer to establish anything, a refused policy must still be a
     * REFUSAL — exit 2, `refused: true`, and NO `violations` key (§3.1: an empty array there is precisely
     * the claim the gate cannot make).
     */
    @Test
    void aSoleRefusalIsStillARefusalWithNoViolationsKey() throws Exception {
        Path after = regressedFixture();
        Path pol = scratch.resolve("bad.policy");
        Files.writeString(pol, "deny Unknown[corp] app\n");
        Path verdict = scratch.resolve("verdict.json");
        Run r = runCli(Map.of(), after.toString(), "--policy", pol.toString(), "--gate-json", verdict.toString());
        assertEquals(2, r.exit(), "a sole refusal still exits 2\nSTDERR:\n" + r.stderr());
        JsonObject v = doc(verdict);
        assertFalse(v.has("violations"),
                "a refusal makes NO claim about violations — an empty array is the claim it cannot make\nDOC:\n" + v);
        assertTrue(v.get("refused").getAsBoolean(), "refused: true");
        assertFalse(v.get("ok").getAsBoolean(), "ok: false");
        assertEquals(1, v.getAsJsonArray("unevaluated").size(), "the refused rule is named\nDOC:\n" + v);
    }

    /**
     * ⟨0.24⟩ <b>THE STALE-DOCUMENT RULE OVER ITS CONDITION, NOT ITS EXIT SITES — SPEC §3.1.</b>
     * {@code 1503368} made a refusal write its document and {@code 901f14d} generalised that over machine
     * output PATHS; both were implemented at the exit sites that had been measured. Found while checking
     * the mirror of the fix above, on a {@code --gate-json} path a clean run had left {@code ok: true}:
     * <pre>
     *   CANDOR_BASELINE=&lt;no provenance header&gt;  -> exit 2, the path STILL READS ok: true
     *   an unreadable scan target                -> exit 2, the path STILL READS ok: true
     * </pre>
     * Two unrelated causes, one stale green, and a CI wrapper reading that path unconditionally passes.
     * The repair arms the path fail-closed when the FLAG IS PARSED, so it covers every exit site including
     * the ones nobody enumerated — a crash, an OOM, a kill.
     */
    @Test
    void anIncompleteRunNeverLeavesThePreviousVerdictOnTheGateJsonPath() throws Exception {
        Path pure = pureFixture();
        Path pol = scratch.resolve("ok.policy");
        Files.writeString(pol, "deny Net app\n");
        Path verdict = scratch.resolve("verdict.json");

        // Establish the stale green the hazard needs: a real, clean, ok:true document on that exact path.
        assertEquals(0, runCli(Map.of(), pure.toString(), "--policy", pol.toString(),
                "--gate-json", verdict.toString()).exit(), "the clean run must pass");
        assertTrue(doc(verdict).get("ok").getAsBoolean(), "…and leave ok:true behind");

        // CAUSE 1 — a baseline with no provenance header. Nothing about the policy or the code is wrong.
        Path legacy = scratch.resolve("legacy.json");
        Files.writeString(legacy, "[]");
        Run a = runCli(Map.of("CANDOR_BASELINE", legacy.toString()),
                pure.toString(), "--policy", pol.toString(), "--gate-json", verdict.toString());
        assertEquals(2, a.exit(), "an unusable baseline is exit 2\nSTDERR:\n" + a.stderr());
        JsonObject va = doc(verdict);
        assertFalse(va.get("ok").getAsBoolean(),
                "a run that could not decide must not leave the PREVIOUS run's green on the path CI "
                + "reads — the naive read of what is there has to be FAIL\nDOC:\n" + va);
        assertTrue(va.get("refused").getAsBoolean(), "…and say so under `refused`\nDOC:\n" + va);

        // CAUSE 2 — a different subsystem entirely, which is why the repair is at the flag and not at the
        // exit: an unreadable scan target. Re-establish the green first, or this proves nothing.
        assertEquals(0, runCli(Map.of(), pure.toString(), "--policy", pol.toString(),
                "--gate-json", verdict.toString()).exit());
        assertTrue(doc(verdict).get("ok").getAsBoolean(), "the green is back on the path");
        Run b = runCli(Map.of(), scratch.resolve("no-such-tree").toString(),
                "--policy", pol.toString(), "--gate-json", verdict.toString());
        assertEquals(2, b.exit(), "an unreadable scan target is exit 2\nSTDERR:\n" + b.stderr());
        assertFalse(doc(verdict).get("ok").getAsBoolean(),
                "…and the same rule binds it, because the rule is about the PATH, not about which "
                + "subsystem failed\nDOC:\n" + doc(verdict));
    }

    /** THE MIRROR of the arming above: `-` means stdout, which carries exactly ONE document. A placeholder
     *  there would put two in a consumer's pipe and break every `--gate-json - | jq` in existence. */
    @Test
    void armingNeverWritesASecondDocumentToStdout() throws Exception {
        Path pure = pureFixture();
        Path pol = scratch.resolve("ok.policy");
        Files.writeString(pol, "deny Net app\n");
        Run r = runCli(Map.of(), pure.toString(), "--policy", pol.toString(), "--gate-json", "-");
        assertEquals(0, r.exit(), "a clean gate is exit 0\nSTDERR:\n" + r.stderr());
        JsonObject v = JsonParser.parseString(r.stdout()).getAsJsonObject();   // throws on two documents
        assertTrue(v.get("ok").getAsBoolean(), "…and stdout is exactly the one verdict\nSTDOUT:\n" + r.stdout());
        assertFalse(v.has("refused"), "no placeholder leaked into it\nSTDOUT:\n" + r.stdout());
    }

    /** …and a clean gate is untouched: no `refused`, no `reason`, no `unevaluated`. */
    @Test
    void aCleanGateVerdictCarriesNoneOfTheRefusalKeys() throws Exception {
        Path pure = pureFixture();
        Path pol = scratch.resolve("ok.policy");
        Files.writeString(pol, "deny Net app\n");
        Path verdict = scratch.resolve("verdict.json");
        Run r = runCli(Map.of(), pure.toString(), "--policy", pol.toString(), "--gate-json", verdict.toString());
        assertEquals(0, r.exit(), "a clean gate is exit 0\nSTDERR:\n" + r.stderr());
        JsonObject v = doc(verdict);
        assertTrue(v.get("ok").getAsBoolean());
        assertFalse(v.has("refused"), "byte-identical to a pre-⟨0.24⟩ verdict\nDOC:\n" + v);
        assertFalse(v.has("reason"), "byte-identical to a pre-⟨0.24⟩ verdict\nDOC:\n" + v);
        assertFalse(v.has("unevaluated"), "byte-identical to a pre-⟨0.24⟩ verdict\nDOC:\n" + v);
    }
}
