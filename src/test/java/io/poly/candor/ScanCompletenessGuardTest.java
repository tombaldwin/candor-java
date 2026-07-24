package io.poly.candor;

import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The two SCAN-COMPLETENESS advisories. Both were found by running candor on a real 18.7k-function DI
 * webapp and mis-reading the result; each is stderr-only and must never move a verdict.
 *
 * <ul>
 *   <li>the <b>closed-world hazard warning</b> — `closed-world` asserts the scanned classes ARE the whole
 *       world, licensing a would-be-broad dispatch to resolve to the visible impls instead of disclosing
 *       Unknown. It fires on the owners where the flag ACTUALLY CHANGED THE ANSWER. That trigger matters:
 *       an earlier version keyed off the uncovered-package ledger and was therefore SILENT on the
 *       load-bearing case — a self-contained app whose own broad interface is silently resolved, with
 *       nothing uncovered to report — while also misnaming the mechanism (an owner inside an uncovered
 *       package is never closed-world-resolved, since resolution requires the owner in `byName`).
 *       Measured: app classes ONLY under closed-world reported 618 gate hits where the same app scanned
 *       WITH its 222 dependency jars honestly reports ~6.7k;</li>
 *   <li>the <b>scan-completeness nudge</b> — high CALL VOLUME into unscanned packages is the signature of
 *       pointing candor at `build/classes` instead of at the deployed artifact, leaving the dependencies'
 *       effects invisible. Supplying the jars makes them DETERMINED: on that app, provable Net reaches went
 *       465 → 5,865. Volume, not package count: candor's own `build/classes` makes 519 such calls into just
 *       4 packages, which a count threshold misses entirely. It promises VISIBILITY, not dispatch
 *       resolution — 23 of that app's 26 unresolved dispatches were over its OWN broad hierarchies.</li>
 * </ul>
 *
 * <p>The two are INDEPENDENT signals (different triggers, different remedies) and may both fire on one
 * scan. Run in a subprocess (main() calls System.exit) with a CANDOR_*-stripped environment so a developer
 * who exports those vars cannot flip a result.
 */
class ScanCompletenessGuardTest {

    @TempDir
    Path tmp;

    private record Run(int exit, String stdout, String stderr) {}

    /** Subprocess CLI. The inherited environment is stripped of every CANDOR_* key first: the guards read
     *  config that a developer may well have exported (CANDOR_CLOSED_WORLD, CANDOR_POLICY), so without
     *  this the suite is non-hermetic and fails on their machine only. */
    private static Run runCli(Map<String, String> env, String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().keySet().removeIf(k -> k.startsWith("CANDOR_"));
        pb.environment().putAll(env);
        Process p = pb.start();
        // Drain concurrently: either stream alone can outgrow the pipe buffer and deadlock a sequential read.
        java.util.concurrent.CompletableFuture<String> out =
                java.util.concurrent.CompletableFuture.supplyAsync(() -> drain(p.getInputStream()));
        String err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out.join(), err);
    }

    private static String drain(InputStream in) {
        try (in) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            in.transferTo(bos);
            return bos.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** An app making {@code calls} calls into {@code pkgs} distinct library packages compiled OFF the scan
     *  path — so the scan sees the calls but never the callees, and the κ ledger names exactly {@code pkgs}
     *  packages carrying {@code calls} calls between them. */
    private Path appWithUncoveredCalls(int pkgs, int calls) throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        for (int i = 1; i <= pkgs; i++)
            lib.put("W" + i + ".java",
                "package com.unc.p" + i + "; public class W" + i + " { public static void go(){} }");
        StringBuilder body = new StringBuilder("package app;\npublic class A {\n  public void f(){\n");
        for (int c = 0; c < calls; c++)
            body.append("    com.unc.p").append((c % pkgs) + 1).append(".W").append((c % pkgs) + 1).append(".go();\n");
        body.append("  }\n}\n");
        return compileApp(lib, Map.of("A.java", body.toString()));
    }

    /** An app whose OWN interface has a broad (> CHA_FANOUT_LIMIT) implementor set and makes no external
     *  calls at all: under closed-world that dispatch is resolved instead of disclosed — the exact hazard —
     *  while the κ ledger stays EMPTY. The fixture an uncovered-keyed guard was blind to. */
    private Path appWithBroadOwnInterface() throws Exception {
        Map<String, String> src = new LinkedHashMap<>();
        src.put("I.java", "package app; public interface I { void go(); }");
        for (int i = 1; i <= Rules.CHA_FANOUT_LIMIT + 2; i++)
            src.put("Im" + i + ".java", "package app; class Im" + i + " implements I { public void go(){} }");
        src.put("Caller.java", "package app; public class Caller { public void run(I i){ i.go(); } }");
        // A lib entry is required (javac errors on zero sources) but is NEVER CALLED, so it cannot enter
        // the κ ledger — the fixture's "nothing uncovered" precondition holds.
        return compileApp(Map.of("Unused.java", "package com.unused; public class Unused {}"), src);
    }

    // ── 1. the closed-world hazard warning ────────────────────────────────────────────────────────

    /** THE REGRESSION THIS GUARD EXISTS FOR: nothing uncovered, so the old ledger-keyed trigger was silent,
     *  yet closed-world silently resolved a broad project dispatch that is Unknown by default. */
    @Test
    void closedWorldWarnsWhenItActuallyResolvedABroadDispatch() throws Exception {
        Path app = appWithBroadOwnInterface();
        Run r = runCli(Map.of("CANDOR_CLOSED_WORLD", "1"), app.toString());
        assertEquals(0, r.exit(), "advisory only — the exit code is untouched: " + r.stderr());
        assertFalse(r.stderr().contains("classifier doesn't cover"),
            "fixture precondition: nothing is uncovered, so only the flag can explain the warning: " + r.stderr());
        assertTrue(r.stderr().contains("closed-world resolved"),
            "the hazard fires on the owner whose answer the flag changed: " + r.stderr());
        assertTrue(r.stderr().contains("app.I"), "it names the owner: " + r.stderr());
        assertTrue(r.stderr().contains("false all-clear"),
            "it names the risk in candor's own vocabulary: " + r.stderr());
    }

    @Test
    void closedWorldStaysSilentWhenItChangedNothing() throws Exception {
        // one uncovered package, but no broad project hierarchy — the flag is INERT here, so no hazard.
        Path app = appWithUncoveredCalls(1, 1);
        Run r = runCli(Map.of("CANDOR_CLOSED_WORLD", "1"), app.toString());
        assertEquals(0, r.exit(), r.stderr());
        assertTrue(r.stderr().contains("classifier doesn't cover"), "precondition: the ledger IS non-empty");
        assertFalse(r.stderr().contains("closed-world resolved"),
            "an uncovered package alone is NOT the hazard — the flag changed no answer: " + r.stderr());
    }

    @Test
    void withoutTheFlagTheHazardNeverFires() throws Exception {
        Path app = appWithBroadOwnInterface();
        Run r = runCli(Map.of(), app.toString());
        assertEquals(0, r.exit(), r.stderr());
        assertFalse(r.stderr().contains("closed-world resolved"),
            "default keeps the sound Unknown, so there is no hazard to report: " + r.stderr());
    }

    // ── 2. the scan-completeness nudge ────────────────────────────────────────────────────────────

    @Test
    void heavyCallVolumeIntoUnscannedCodeNudgesTowardTheFullArtifact() throws Exception {
        Path app = appWithUncoveredCalls(2, Rules.UNCOVERED_CALLS_NUDGE_MIN);
        Run r = runCli(Map.of(), app.toString());
        assertEquals(0, r.exit(), "advisory only: " + r.stderr());
        assertTrue(r.stderr().contains("are not scanned, so their effects are invisible here"),
            "the nudge names what is lost — visibility: " + r.stderr());
        assertTrue(r.stderr().contains("dependency jars"), "it carries the remedy: " + r.stderr());
        assertTrue(r.stderr().contains("DETERMINED"),
            "it promises visibility (determined effects), NOT dispatch resolution: " + r.stderr());
    }

    /** Pins the THRESHOLD ITSELF at its literal boundary — deriving both fixtures from the constant would
     *  keep passing if the constant drifted to 6 or 600. */
    @Test
    void theNudgeThresholdIsPinnedAtItsBoundary() throws Exception {
        assertEquals(50, Rules.UNCOVERED_CALLS_NUDGE_MIN, "threshold drift: update this test deliberately");
        Run below = runCli(Map.of(), appWithUncoveredCalls(2, 49).toString());
        assertFalse(below.stderr().contains("are not scanned, so their effects are invisible here"),
            "49 calls is below the bar — silent: " + below.stderr());
        Run at = runCli(Map.of(), appWithUncoveredCalls(2, 50).toString());
        assertTrue(at.stderr().contains("are not scanned, so their effects are invisible here"),
            "50 calls is the bar — fires: " + at.stderr());
    }

    // ── 3. the safety contract both advisories must honour ────────────────────────────────────────

    /** The load-bearing property: an advisory rides on stderr and CANNOT corrupt a machine consumer.
     *  Both `--json -` and `--gate-json -` promise pure JSON on stdout. */
    @Test
    void advisoriesNeverContaminateJsonStdoutOrTheExitCode() throws Exception {
        Path app = appWithUncoveredCalls(2, Rules.UNCOVERED_CALLS_NUDGE_MIN);
        Run report = runCli(Map.of("CANDOR_CLOSED_WORLD", "1"), app.toString(), "--json");
        assertEquals(0, report.exit(), report.stderr());
        assertTrue(report.stderr().contains("invisible here"), "precondition: an advisory did fire");
        assertDoesNotThrow(() -> JsonParser.parseString(report.stdout()),
            "bare --json streams the report to stdout — it must stay pure JSON while stderr carries the advisory");

        Run gate = runCli(Map.of("CANDOR_CLOSED_WORLD", "1"), app.toString(), "--gate-json", "-");
        assertEquals(0, gate.exit(), gate.stderr());
        assertDoesNotThrow(() -> JsonParser.parseString(gate.stdout()),
            "--gate-json - must stay pure JSON while an advisory prints to stderr");
    }

    /** The advisories are INDEPENDENT signals — a scan that is both dependency-poor and closed-world gets
     *  both, because they name different problems with different remedies. */
    @Test
    void bothAdvisoriesCanFireOnOneScan() throws Exception {
        Map<String, String> lib = Map.of("W1.java",
            "package com.unc.p1; public class W1 { public static void go(){} }");
        Map<String, String> app = new LinkedHashMap<>();
        app.put("I.java", "package app; public interface I { void go(); }");
        for (int i = 1; i <= Rules.CHA_FANOUT_LIMIT + 2; i++)
            app.put("Im" + i + ".java", "package app; class Im" + i + " implements I { public void go(){} }");
        StringBuilder c = new StringBuilder("package app;\npublic class Caller {\n  public void run(I i){ i.go(); }\n  public void ext(){\n");
        for (int k = 0; k < Rules.UNCOVERED_CALLS_NUDGE_MIN; k++) c.append("    com.unc.p1.W1.go();\n");
        c.append("  }\n}\n");
        app.put("Caller.java", c.toString());
        Path cls = compileApp(lib, app);
        Run r = runCli(Map.of("CANDOR_CLOSED_WORLD", "1"), cls.toString());
        assertEquals(0, r.exit(), r.stderr());
        assertTrue(r.stderr().contains("closed-world resolved"), "the hazard fires: " + r.stderr());
        assertTrue(r.stderr().contains("invisible here"), "and so does the nudge: " + r.stderr());
    }

    /** A COMPLETE scan — every callee present, no flag — is silent on both. The false-positive guard. */
    @Test
    void aCompleteScanGetsNoAdvisories() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path src = tmp.resolve("B.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "public class B {",
            "  public void reads(){ try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of(\"/tmp/x\")); } catch (Exception e) {} }",
            "}"));
        Path out = tmp.resolve("cls-covered");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "fixture must compile");
        Run r = runCli(Map.of(), out.toString());
        assertEquals(0, r.exit(), r.stderr());
        assertFalse(r.stderr().contains("invisible here"), "no nudge on a complete scan: " + r.stderr());
        assertFalse(r.stderr().contains("closed-world resolved"), "no hazard without the flag: " + r.stderr());
    }
}
