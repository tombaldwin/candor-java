package io.poly.candor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.15 staged⟩ The `coverage` surface (COVERAGE-DESIGN.md): the κ-coverage ledger travels WITH the
 * artifacts instead of evaporating on stderr. Three consumers, one ledger:
 *
 * <ul>
 *   <li>the report envelope's `coverage` field — same names/counts as the stderr line, OMITTED entirely
 *       when nothing is uncovered (a fully-covered report is byte-identical to a pre-⟨0.15⟩ one);</li>
 *   <li>the `--gate-json` advisory — VERDICT-PRESERVING (ok/violations/exit untouched, the ⟨0.9⟩
 *       provable-purity auto-disclosure precedent), omitted when fully covered;</li>
 *   <li>gains' re-disclosure — the CURRENT envelope's block verbatim, plus `coverageDelta` when the
 *       baseline's uncovered name set differs; the human TSV is a pinned surface and stays byte-stable.</li>
 * </ul>
 *
 * <p>Scan/gate cases run the CLI in a subprocess (main() calls System.exit) — the SchemaShapeTest harness.
 */
class CoverageEnvelopeTest {

    @TempDir
    Path tmp;

    private record Run(int exit, String stdout, String stderr) {}

    private static Run runCli(String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    /** Two-phase fixture: the lib is compiled OFF the scan path (genuinely uncovered), the app calls it
     *  once and also does a real (covered) Fs effect so a `deny Fs` gate has something to bite on. */
    private Path uncoveredApp() throws Exception {
        return compileApp(
            Map.of("Widget.java", "package com.obscure.lib; public class Widget { public void doThing(){} }"),
            Map.of("A.java", String.join("\n",
                "package app;",
                "public class A {",
                "  public void f(com.obscure.lib.Widget w){ w.doThing(); }",
                "  public void reads(){ try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of(\"/tmp/x\")); } catch (Exception e) {} }",
                "}")));
    }

    /** JDK-only fixture — every called package is classifier-covered, so the ledger is empty. */
    private Path coveredApp() throws Exception {
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
        return out;
    }

    // ── 1. the report envelope ────────────────────────────────────────────────────────────────────

    @Test
    void uncoveredScanEmitsTheCoverageEnvelopeMatchingStderrAndInvisible() throws Exception {
        Path app = uncoveredApp();
        Path report = tmp.resolve("r.json");
        try {
            Run r = runCli(app.toString(), "--json", report.toString());
            assertEquals(0, r.exit(), r.stderr());
            // the stderr ledger is UNCHANGED and names the package with its count
            assertTrue(r.stderr().contains("classifier doesn't cover 1 package"),
                "stderr ledger names the uncovered count: " + r.stderr());
            assertTrue(r.stderr().contains("com.obscure.lib (1 call)"),
                "stderr ledger names the package + calls: " + r.stderr());
            JsonObject root = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
            assertTrue(root.has("coverage"), "the envelope carries the ledger as data");
            JsonArray unc = root.getAsJsonObject("coverage").getAsJsonArray("uncovered");
            assertEquals(1, unc.size(), "same list as stderr: exactly the one uncovered package");
            JsonObject e0 = unc.get(0).getAsJsonObject();
            assertEquals("com.obscure.lib", e0.get("name").getAsString(), "same name as the stderr line");
            assertEquals(1, e0.get("calls").getAsInt(), "same count as the stderr line");
            assertEquals(Set.of("name", "calls"), new TreeSet<>(e0.keySet()), "entry shape: exactly name/calls");
            // the per-function attribution (`invisible`) is unchanged and consistent with the envelope
            boolean sawInvisible = false;
            for (var fe : root.getAsJsonArray("functions")) {
                JsonObject f = fe.getAsJsonObject();
                if (f.get("fn").getAsString().equals("app.A.f")) {
                    assertTrue(f.has("invisible") && f.getAsJsonArray("invisible").toString().contains("com.obscure.lib"),
                        "the calling fn carries invisible:[\"com.obscure.lib\"], got " + f);
                    sawInvisible = true;
                }
            }
            assertTrue(sawInvisible, "app.A.f is in the report (blind-reach entries survive)");
        } finally { rm(app.getParent()); }
    }

    @Test
    void fullyCoveredReportOmitsTheCoverageKeyEntirely() throws Exception {
        Path app = coveredApp();
        Path report = tmp.resolve("rc.json");
        Run r = runCli(app.toString(), "--json", report.toString());
        assertEquals(0, r.exit(), r.stderr());
        assertFalse(r.stderr().contains("classifier doesn't cover"), "no stderr ledger when fully covered");
        JsonObject root = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
        assertEquals(Set.of("candor", "packages", "functions"), new TreeSet<>(root.keySet()),
            "a fully-covered report is byte-identical to a pre-⟨0.15⟩ one: NO coverage key");
    }

    // ── 2. the --gate-json advisory ───────────────────────────────────────────────────────────────

    @Test
    void gateAdvisoryDisclosesCoverageVerdictPreserving() throws Exception {
        Path app = uncoveredApp();
        try {
            Path pol = tmp.resolve("arch.policy");
            Files.writeString(pol, "deny Fs app\n");
            Path gate = tmp.resolve("gate.json");
            Run r = runCli(app.toString(), "--policy", pol.toString(), "--gate-json", gate.toString());
            assertEquals(1, r.exit(), "the deny still bites — exit code UNCHANGED by the advisory\n" + r.stderr());
            JsonObject v = JsonParser.parseString(Files.readString(gate)).getAsJsonObject();
            assertEquals(Set.of("spec", "ok", "violations", "coverage"), new TreeSet<>(v.keySet()),
                "verdict fields spec/ok/violations undisturbed; coverage is the one added advisory");
            assertFalse(v.get("ok").getAsBoolean(), "ok still mirrors the violations, not the coverage");
            assertTrue(v.getAsJsonArray("violations").size() >= 1, "the real violation is still listed");
            JsonObject cov = v.getAsJsonObject("coverage");
            assertEquals(1, cov.get("uncovered").getAsInt());
            assertEquals("[\"com.obscure.lib\"]", cov.get("packages").toString(), "the advisory names the ledger's packages");

            // the SAME scan with a policy that does not bite: still exit 0 / ok:true — the advisory is
            // disclosure, never a gate (nearly every real scan has uncovered deps; failing would kill them).
            Files.writeString(pol, "deny Db app\n");
            Run clean = runCli(app.toString(), "--policy", pol.toString(), "--gate-json", gate.toString());
            assertEquals(0, clean.exit(), "uncovered packages alone NEVER fail the gate\n" + clean.stderr());
            JsonObject cv = JsonParser.parseString(Files.readString(gate)).getAsJsonObject();
            assertTrue(cv.get("ok").getAsBoolean());
            assertEquals(0, cv.getAsJsonArray("violations").size());
            assertEquals(1, cv.getAsJsonObject("coverage").get("uncovered").getAsInt(),
                "the advisory rides a clean verdict too — the caveat travels either way");
        } finally { rm(app.getParent()); }
    }

    @Test
    void fullyCoveredGateVerdictOmitsCoverage() throws Exception {
        Path app = coveredApp();
        Path pol = tmp.resolve("clean.policy");
        Files.writeString(pol, "deny Db app\n");
        Path gate = tmp.resolve("gatec.json");
        Run r = runCli(app.toString(), "--policy", pol.toString(), "--gate-json", gate.toString());
        assertEquals(0, r.exit(), r.stderr());
        JsonObject v = JsonParser.parseString(Files.readString(gate)).getAsJsonObject();
        assertEquals(Set.of("spec", "ok", "violations"), new TreeSet<>(v.keySet()),
            "a fully-covered verdict is byte-identical to a pre-⟨0.15⟩ one: NO coverage key");
    }

    // ── 3. gains re-disclosure ────────────────────────────────────────────────────────────────────

    private Path reportFile(String name, String coverageJson) throws Exception {
        return reportFile(name, coverageJson, "Net");
    }

    private Path reportFile(String name, String coverageJson, String effect) throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, "{\"candor\":{\"version\":\"t1\",\"toolchain\":\"jvm\",\"spec\":\"test\"},"
                + "\"packages\":[\"app\"],"
                + (coverageJson == null ? "" : "\"coverage\":" + coverageJson + ",")
                + "\"functions\":[{\"fn\":\"app.A.f\",\"loc\":\"?\",\"inferred\":[\"" + effect + "\"],"
                + "\"direct\":[\"" + effect + "\"],"
                + "\"declared\":[],\"undeclared\":[],\"overdeclared\":[],\"entryPoint\":false,"
                + "\"unresolved\":false,\"hash\":\"h\"}]}");
        return p;
    }

    private static String capture(Runnable r) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream orig = System.out;
        System.setOut(new PrintStream(buf));
        try { r.run(); } finally { System.setOut(orig); }
        return buf.toString();
    }

    @Test
    void gainsJsonCarriesCurrentCoverageAndDeltaWhenBaselineDiffers() throws Exception {
        Path cur = reportFile("gcur.json", "{\"uncovered\":[{\"name\":\"okio\",\"calls\":3}]}");
        Path base = reportFile("gbase.json", null);
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        String out = capture(() ->
            Query.gains(curFns, cur.toString(), base.toString(), List.of(), true, false));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        // the CURRENT envelope's block, verbatim
        assertTrue(o.has("coverage"), "gains re-discloses the current report's coverage: " + out);
        JsonObject c0 = o.getAsJsonObject("coverage").getAsJsonArray("uncovered").get(0).getAsJsonObject();
        assertEquals("okio", c0.get("name").getAsString());
        assertEquals(3, c0.get("calls").getAsInt());
        // baseline had NO uncovered packages → okio became uncovered between scans (itself a signal)
        assertTrue(o.has("coverageDelta"));
        assertEquals("[\"okio\"]", o.getAsJsonObject("coverageDelta").get("nowUncovered").toString());
        assertEquals("[]", o.getAsJsonObject("coverageDelta").get("noLongerUncovered").toString());
        // existing verdict fields undisturbed
        assertTrue(o.has("gained") && o.has("byFunction") && o.has("baseline_version") && o.has("engine_version"));
    }

    @Test
    void gainsOmitsCoverageWhenNeitherReportCarriesItAndDeltaWhenEqual() throws Exception {
        String cov = "{\"uncovered\":[{\"name\":\"okio\",\"calls\":3}]}";
        Path bare = reportFile("nb-cur.json", null);
        Path bareBase = reportFile("nb-base.json", null);
        List<io.poly.candor.model.Effector> bareFns = Query.load(bare.toString());
        String out = capture(() ->
            Query.gains(bareFns, bare.toString(), bareBase.toString(), List.of(), true, false));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertFalse(o.has("coverage"), "pre-⟨0.15⟩ / fully-covered reports → no coverage key in gains");
        assertFalse(o.has("coverageDelta"), "equal (empty) uncovered sets → no delta");

        // same non-empty ledger on both sides: coverage rides, delta does not (nothing CHANGED)
        Path cur = reportFile("eq-cur.json", cov);
        Path base = reportFile("eq-base.json", cov);
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        String out2 = capture(() ->
            Query.gains(curFns, cur.toString(), base.toString(), List.of(), true, false));
        JsonObject o2 = JsonParser.parseString(out2).getAsJsonObject();
        assertTrue(o2.has("coverage"), "the current ledger still travels");
        assertFalse(o2.has("coverageDelta"), "same uncovered names → no delta");
    }

    @Test
    void gainsHumanOutputIsUnchangedByCoverage() throws Exception {
        Path cur = reportFile("hcur.json", "{\"uncovered\":[{\"name\":\"okio\",\"calls\":3}]}");
        Path base = reportFile("hbase.json", null, "Fs");   // baseline does Fs → cur GAINS Net (a TSV row)
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        String out = capture(() ->
            Query.gains(curFns, cur.toString(), base.toString(), List.of(), false, false));
        assertFalse(out.contains("coverage") || out.contains("okio"),
            "the human TSV is a pinned consumer surface — byte-stable, no coverage lines: " + out);
        assertTrue(out.contains("app.A.f\tNet"), "the TSV rows themselves are intact");
    }
}
