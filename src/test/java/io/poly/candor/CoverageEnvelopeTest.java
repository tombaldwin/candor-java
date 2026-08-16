package io.poly.candor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
        // <0.27> `resolves` is unconditional -- a producer declares what it COMPUTES, regardless of what
        // any given scan found -- unlike `coverage`, which is what this test is actually about.
        // ⟨0.29⟩ `excluded` is unconditional for the same reason `resolves` is, and for one more: for a
        // LEDGER (which is what `coverage` is) empty and absent can mean the same thing, and for a SCOPE
        // they cannot — `[]` says "I looked and excluded nothing", absence says "I cannot answer".
        assertEquals(Set.of("candor", "packages", "analyzed", "resolves", "excluded", "functions"),
            new TreeSet<>(root.keySet()),
            "a fully-covered report has NO coverage key; ⟨0.21⟩ `analyzed` (completeness manifest) is always present");
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
            assertEquals(Set.of("spec", "ok", "analyzed", "violations", "coverage"), new TreeSet<>(v.keySet()),
                "verdict fields spec/ok/violations undisturbed; coverage advisory + ⟨0.21⟩ analyzed count added");
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
        assertEquals(Set.of("spec", "ok", "analyzed", "violations"), new TreeSet<>(v.keySet()),
            "a fully-covered verdict has NO coverage key; ⟨0.21⟩ `analyzed` count is always present");
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

    /** A single-FILE locator: the report SET a full `.json` path names is itself (§3.3.1 rule 2), so the
     *  locator and the resolved path coincide — which is also how the CLI reaches these fixtures. */
    static Query.ReportRef ref(Path p) { return new Query.ReportRef(p.toString(), p.toString()); }

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
            Query.gains(curFns, ref(cur), ref(base), List.of(), true, false));
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
            Query.gains(bareFns, ref(bare), ref(bareBase), List.of(), true, false));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertFalse(o.has("coverage"), "pre-⟨0.15⟩ / fully-covered reports → no coverage key in gains");
        assertFalse(o.has("coverageDelta"), "equal (empty) uncovered sets → no delta");

        // same non-empty ledger on both sides: coverage rides, delta does not (nothing CHANGED)
        Path cur = reportFile("eq-cur.json", cov);
        Path base = reportFile("eq-base.json", cov);
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        String out2 = capture(() ->
            Query.gains(curFns, ref(cur), ref(base), List.of(), true, false));
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
            Query.gains(curFns, ref(cur), ref(base), List.of(), false, false));
        assertFalse(out.contains("coverage") || out.contains("okio"),
            "the human TSV is a pinned consumer surface — byte-stable, no coverage lines: " + out);
        assertTrue(out.contains("app.A.f\tNet"), "the TSV rows themselves are intact");
    }

    // ── 4. ⟨0.28⟩ gains carries the ⟨0.21⟩ MANIFEST too, on BOTH SIDES, disclosed separately ───────
    //
    // SPEC §2: "AND THE SAME MUST CARRIES THE ⟨0.21⟩ MANIFEST, WHICH IS THE STRONGER CAVEAT AND THE ONE
    // THAT DOES NOT TRAVEL." Section 3 above is the live precedent the clause argues from — the mechanism
    // existed and was pointed at the weaker field. `coverage.uncovered` says *I could not see into this
    // dependency*; `unanalyzed` says *I could not read this file of your own code*; `analyzed.count: 0`
    // says *I judged nothing at all*.
    //
    // BOTH SIDES SEPARATELY, because a gains answer rests on two reports that fail differently: an
    // incomplete CURRENT means the gained set may be SHORT, an incomplete BASELINE means the comparison
    // floor is soft so the existing-vs-new `origin` split is unreliable. Every row below asserts the
    // OTHER side's keys are ABSENT — a single combined flag would pass a one-sided assertion.

    /** A report with an explicit ⟨0.21⟩ manifest — `analyzed.count` and `unanalyzed` written verbatim, so
     *  a row can put each cause on either side without the fixture builder guessing. */
    private Path manifestReport(String name, String effect, int analyzed, String unanalyzedJson)
            throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, "{\"candor\":{\"version\":\"t1\",\"toolchain\":\"jvm\",\"spec\":\"test\"},"
                + "\"packages\":[\"app\"],\"analyzed\":{\"count\":" + analyzed + "},"
                + (unanalyzedJson == null ? "" : "\"unanalyzed\":" + unanalyzedJson + ",")
                + "\"functions\":[{\"fn\":\"app.A.f\",\"loc\":\"?\",\"inferred\":[\"" + effect + "\"],"
                + "\"direct\":[\"" + effect + "\"],"
                + "\"declared\":[],\"undeclared\":[],\"overdeclared\":[],\"entryPoint\":false,"
                + "\"unresolved\":false,\"hash\":\"h\"}]}");
        return p;
    }

    private static final String ONE_UNREAD = "[{\"path\":\"src/Broken.java\",\"reason\":\"parse error\"}]";

    private JsonObject gainsJson(Path cur, Path base) throws Exception {
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        return JsonParser.parseString(
                capture(() -> Query.gains(curFns, ref(cur), ref(base), List.of(), true, false)))
                .getAsJsonObject();
    }

    /** CONTROL A — an incomplete BASELINE is disclosed under the `baseline…` names, and ONLY those. This
     *  is conformance PART 39 (ii)'s exact shape: the baseline carries the manifest, the current is
     *  whole, and pre-⟨0.28⟩ the output carried `coverage` while dropping this. */
    @Test
    void gainsDisclosesAnIncompleteBaselineUnderItsOwnKeys() throws Exception {
        Path base = manifestReport("mb1.json", "Fs", 3, ONE_UNREAD);
        Path cur = manifestReport("mc1.json", "Net", 3, null);
        JsonObject o = gainsJson(cur, base);
        assertTrue(o.get("baselineIncomplete").getAsBoolean(), "the comparison FLOOR is soft: " + o);
        assertEquals("src/Broken.java", o.getAsJsonArray("baselineUnanalyzed").get(0)
                .getAsJsonObject().get("path").getAsString());
        assertFalse(o.has("incomplete") || o.has("unanalyzed"),
            "the CURRENT report is whole — a combined flag here would misdirect the repair: " + o);
        assertTrue(o.getAsJsonArray("gained").toString().contains("Net"), "the verdict body is intact");
    }

    /** CONTROL B — an incomplete CURRENT is disclosed under the bare names, and ONLY those. Different
     *  harm, different repair: the GAINED SET may be short, so a reader must not treat it as the whole
     *  list of new capability. */
    @Test
    void gainsDisclosesAnIncompleteCurrentUnderTheBareKeys() throws Exception {
        Path base = manifestReport("mb2.json", "Fs", 3, null);
        Path cur = manifestReport("mc2.json", "Net", 3, ONE_UNREAD);
        JsonObject o = gainsJson(cur, base);
        assertTrue(o.get("incomplete").getAsBoolean(), "the gained set may be SHORT: " + o);
        assertEquals("src/Broken.java", o.getAsJsonArray("unanalyzed").get(0)
                .getAsJsonObject().get("path").getAsString());
        assertFalse(o.has("baselineIncomplete") || o.has("baselineUnanalyzed"),
            "the BASELINE is whole: " + o);
    }

    /** ⟨0.24⟩'s SECOND CAUSE reaches this verb too: `analyzed.count: 0` carries NO `unanalyzed` (there is
     *  no unread FILE to name), so a reader keyed only on the manifest array sees a complete report. Both
     *  sides at once, to pin that the two halves do not overwrite each other. */
    @Test
    void gainsDisclosesJudgedNothingOnEitherSide() throws Exception {
        Path base = manifestReport("mb3.json", "Fs", 0, null);
        Path cur = manifestReport("mc3.json", "Net", 0, null);
        JsonObject o = gainsJson(cur, base);
        assertTrue(o.get("incomplete").getAsBoolean() && o.get("baselineIncomplete").getAsBoolean(), "" + o);
        assertTrue(o.getAsJsonArray("judgedNothing").get(0).getAsString().endsWith("mc3.json"), "" + o);
        assertTrue(o.getAsJsonArray("baselineJudgedNothing").get(0).getAsString().endsWith("mb3.json"),
            "the baseline's own count-0 keeps its own key: " + o);
        assertFalse(o.has("unanalyzed") || o.has("baselineUnanalyzed"),
            "count-0 names no unread file — the array is omitted, never invented: " + o);
    }

    /** CONTROL C — TWO INTACT REPORTS: not one disclosure key, so an ordinary run is byte-identical to a
     *  pre-⟨0.28⟩ one. The control that caught candor-rust's BTreeMap re-sort and this engine's own
     *  `Map.of` salting in the descriptive-verb rung. */
    @Test
    void gainsOverTwoIntactReportsIsUnchanged() throws Exception {
        Path base = manifestReport("mb4.json", "Fs", 3, null);
        Path cur = manifestReport("mc4.json", "Net", 3, null);
        JsonObject o = gainsJson(cur, base);
        assertEquals(List.of("baseline_version", "byFunction", "engine_version", "gained"),
            new ArrayList<>(new TreeSet<>(o.keySet())),
            "a whole pair discloses NOTHING — no key, not even `incomplete: false`: " + o);
    }

    /** CONTROL D — the exit code does not move, in the one place it could: `--strict` keys on the GAINED
     *  SET, which this rung does not touch. An incomplete pair with a gain still exits 1 and an
     *  incomplete pair with no gain still exits 0 — this is a caveat, not a refusal. */
    @Test
    void gainsExitCodesAreUntouchedByTheManifest() throws Exception {
        Path base = manifestReport("mb5.json", "Fs", 0, ONE_UNREAD);
        Path cur = manifestReport("mc5.json", "Net", 0, ONE_UNREAD);
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        List<io.poly.candor.model.Effector> baseFns = Query.load(base.toString());
        int[] rc = new int[4];
        capture(() -> rc[0] = Query.gains(curFns, ref(cur), ref(base), List.of(), true, true));
        capture(() -> rc[1] = Query.gains(curFns, ref(cur), ref(base), List.of(), false, true));
        // no gain: the current does exactly what the baseline did
        capture(() -> rc[2] = Query.gains(baseFns, ref(base), ref(base), List.of(), true, true));
        capture(() -> rc[3] = Query.gains(baseFns, ref(base), ref(base), List.of(), false, true));
        assertEquals(List.of(1, 1, 0, 0), List.of(rc[0], rc[1], rc[2], rc[3]),
            "--strict follows the gained set alone, on both channels");
    }

    /** The human TSV is a pinned consumer surface (whole-line matched by candor-run.sh's seen-file dedup),
     *  so the manifest rides the MACHINE channel only — the same ruling the coverage block above got. */
    @Test
    void gainsHumanTsvIsUnchangedByTheManifest() throws Exception {
        Path base = manifestReport("mb6.json", "Fs", 0, ONE_UNREAD);
        Path cur = manifestReport("mc6.json", "Net", 0, ONE_UNREAD);
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        String out = capture(() -> Query.gains(curFns, ref(cur), ref(base), List.of(), false, false));
        assertEquals("app.A.f\tNet\n", out, "the TSV is byte-stable: " + out);
    }

    /** The manifest is read through the LOCATOR, not the single resolved path: a locator may name a report
     *  SET (§2 "a single analysis world"), and the file the single-report pick chooses need not be the one
     *  carrying the manifest. Here the baseline prefix matches two reports and only the SECOND is
     *  incomplete — reading the pick alone would answer flat. */
    @Test
    void gainsReadsTheManifestOverTheWholeBaselineReportSet() throws Exception {
        Path dir = Files.createDirectories(tmp.resolve("set"));
        Path whole = manifestReport("set/b.aaa.jvm.json", "Fs", 3, null);
        manifestReport("set/b.zzz.jvm.json", "Fs", 3, ONE_UNREAD);
        Path cur = manifestReport("set/c.aaa.jvm.json", "Net", 3, null);
        List<io.poly.candor.model.Effector> curFns = Query.load(cur.toString());
        String basePrefix = dir.resolve("b").toString();
        JsonObject o = JsonParser.parseString(capture(() -> Query.gains(curFns,
                ref(cur), new Query.ReportRef(basePrefix, whole.toString()), List.of(), true, false)))
                .getAsJsonObject();
        assertTrue(o.has("baselineIncomplete"),
            "the sibling's manifest qualifies this answer as much as the chosen file's: " + o);
    }

    // ── 5. coverage is a REVIEW claim, not a resolution outcome ───────────────────────────────────

    /** Two arms whose OBSERVED method is byte-identical; arm B adds an unrelated, CLASSIFIED call into the
     *  same uncurated package. The classifier fires on `FileUtils.readFileToString` (→ Fs) and floors
     *  `FilenameUtils.getName`, and `org.apache.commons.io` is deliberately NOT a curated prefix — the
     *  Rules comment says so in as many words: *"org.hibernate broadly stays LEDGERED — its unclassified
     *  surface is not vouched for"*, the same stance. The lib is compiled off the scan path so the package
     *  is genuinely external. */
    private Path armApp(boolean withClassifiedCall) throws Exception {
        Map<String, String> lib = Map.of(
            "FilenameUtils.java", "package org.apache.commons.io; public class FilenameUtils {"
                + " public static String getName(String p){ return p; } }",
            "FileUtils.java", "package org.apache.commons.io; public class FileUtils {"
                + " public static String readFileToString(java.io.File f, String cs){ return \"\"; } }");
        String other = withClassifiedCall
            ? "  public String other(java.io.File f){ return org.apache.commons.io.FileUtils.readFileToString(f, \"UTF-8\"); }\n"
            : "";
        return compileApp(lib, Map.of("A.java", String.join("\n",
            "package app;",
            "public class A {",
            "  public String nm(String p){ return org.apache.commons.io.FilenameUtils.getName(p); }",
            other + "}")));
    }

    private JsonObject scanToJson(Path app, String name) throws Exception {
        Path report = tmp.resolve(name);
        Files.deleteIfExists(report);          // a stale report read back as this arm's result is the trap
        Run r = runCli(app.toString(), "--json", report.toString());
        assertEquals(0, r.exit(), r.stderr());
        return JsonParser.parseString(Files.readString(report)).getAsJsonObject();
    }

    private static JsonObject fnOrNull(JsonObject root, String fn) {
        for (var fe : root.getAsJsonArray("functions")) {
            JsonObject f = fe.getAsJsonObject();
            if (f.get("fn").getAsString().equals(fn)) return f;
        }
        return null;
    }

    /** A STATIC FIELD READ into an unscanned package is a blind spot, and was disclosed in NEITHER channel.
     *
     *  `Object o = dep.Cls.V` forces that class's `<clinit>`, which may do anything. The κ ledger is driven
     *  from a CALL instruction, so a field read never reached it: `clinitEdge` found no project class and no
     *  chained report, emitted nothing, and the forcing method was omitted from `functions` — under ⟨0.21⟩
     *  a POSITIVE PURITY CLAIM over an initializer this scan never saw. MEASURED beside the call spellings
     *  of the same reach, which were both present carrying `invisible`: the blind spot was disclosed or not
     *  purely by whether the shape happened to be written as a call.
     *
     *  The `calls: 0` assertion is the OTHER half, and it is why this is not simply counted into the ledger.
     *  `Cls.INSTANCE.m()` is ONE reach compiled as a GETSTATIC plus a call; counting both double-counts it
     *  and moves the pinned scan-completeness threshold — measured, it nearly doubled a 49-call fixture and
     *  put two existing tests red. So the package joins the LIST (so `invisible` can never name a package
     *  `coverage.uncovered` omits) while the `calls` tally keeps meaning call volume. */
    /** An S3 TRANSFER THAT NAMES A LOCAL FILE performs Fs as well as Net — and only Net was reported.
     *
     *  `s3.getObject(request, File)` WRITES that file and `putObject(bucket, key, File)` READS it. The
     *  service rule returns NET and `Classifier.classify` returns ONE effect, so the Fs half had nowhere
     *  to go: a `deny Fs` gate over an S3 archival path saw nothing.
     *
     *  NOT the "library moves bytes through a caller-opened handle" caveat, which says a library must not
     *  be charged for I/O the caller's own `open` already carries. `new java.io.File(path)` OPENS NOTHING
     *  in Java — it is a path wrapper, and candor rightly treats it as pure — so the write happens ONLY
     *  inside the SDK and charging nobody loses it entirely.
     *
     *  `meta` is the control and it is what keeps the rule off every AWS call: `getBucketLocation` takes no
     *  File, so it stays Net-only. Without that row a rule that simply added Fs to every S3 call would pass. */
    @Test
    void anS3TransferNamingALocalFileIsAlsoFs() throws Exception {
        Path app = compileApp(
            Map.of("AmazonS3Client.java", "package com.amazonaws.services.s3; import java.io.File;"
                + " public class AmazonS3Client {"
                + " public Object getObject(String r, File d){ return null; }"
                + " public Object putObject(String b, String k, File s){ return null; }"
                + " public String getBucketLocation(String b){ return b; } }"),
            Map.of("S3.java", String.join("\n",
                "package app;",
                "import com.amazonaws.services.s3.AmazonS3Client;",
                "import java.io.File;",
                "public class S3 {",
                "  public static Object download(AmazonS3Client c){ return c.getObject(\"r\", new File(\"/tmp/x\")); }",
                "  public static Object upload(AmazonS3Client c){ return c.putObject(\"b\", \"k\", new File(\"/tmp/x\")); }",
                "  public static String meta(AmazonS3Client c){ return c.getBucketLocation(\"b\"); }",
                "}")));
        JsonObject root = scanToJson(app, "s3-transfer.json");

        for (String fn : List.of("app.S3.download", "app.S3.upload")) {
            JsonObject f = fnOrNull(root, fn);
            assertNotNull(f, fn + " must be in the report");
            String eff = f.getAsJsonArray("inferred").toString();
            assertTrue(eff.contains("Fs"), fn + " names a local File — the SDK reads/writes it, so Fs: " + eff);
            assertTrue(eff.contains("Net"), fn + " must KEEP its Net — the Fs is additive, not a swap: " + eff);
        }
        // REGRESSION, caught in review: the first version of this rule gated on the s3 PACKAGE, so a pure
        // VALUE TYPE that takes a File matched — `PutObjectRequest.withFile(f)` is a builder that performs
        // nothing, and it reported Fs. The Net rule beside it had already learned this ("FABRICATED Net on
        // same-named PURE value types"); the gate now mirrors it (Client/TransferManager owners only).
        Path model = compileApp(
            Map.of("PutObjectRequest.java", "package com.amazonaws.services.s3.model; import java.io.File;"
                + " public class PutObjectRequest { private File f;"
                + " public PutObjectRequest withFile(File file){ this.f = file; return this; } }"),
            Map.of("B.java", String.join("\n",
                "package app;",
                "import com.amazonaws.services.s3.model.PutObjectRequest;",
                "import java.io.File;",
                "public class B {",
                "  public static PutObjectRequest build(){ return new PutObjectRequest().withFile(new File(\"/tmp/x\")); }",
                "}")));
        JsonObject mroot = scanToJson(model, "s3-model.json");
        JsonObject b = fnOrNull(mroot, "app.B.build");
        assertTrue(b == null || !b.getAsJsonArray("inferred").toString().contains("Fs"),
            "a pure S3 model BUILDER taking a File must not gain Fs — it performs nothing: " + b);

        String meta = fnOrNull(root, "app.S3.meta").getAsJsonArray("inferred").toString();
        assertTrue(meta.contains("Net"), "CONTROL: a metadata call is still Net: " + meta);
        assertFalse(meta.contains("Fs"),
            "CONTROL: `getBucketLocation` takes no File and must NOT gain Fs — otherwise the rule is "
            + "'every S3 call touches the disk', which is a fabrication: " + meta);
    }

    /** IMPLICIT STRINGIFICATION of a value from an unscanned package — the sibling of the static-read case.
     *
     *  `"v=" + w` compiles to `String.valueOf(w)` followed by a concat invokedynamic, so the JDK sink
     *  re-enters `w.toString()`. When `w`'s type is neither a project class nor covered by a chained
     *  report, `reentryTargets` is empty and `nearestDepFn` is null, so the site emitted NOTHING and the
     *  concatenating method dropped out of `functions` — a ⟨0.21⟩ purity claim over a body that runs.
     *
     *  MEASURED beside the other spellings of the same reach: `w.doThing()` and `w.toString()` both
     *  carried `invisible`, and only the implicit form was silent. The reach was disclosed or not by
     *  whether it happened to be written as a call.
     *
     *  The JDK-operand row is the control, and it is what keeps this from being a disclosure flood:
     *  `"v=" + anInt + aString` re-enters nothing outside a κ-COVERED package, so it records nothing and
     *  the method stays absent. Without it the fix would pass by disclosing on every concatenation. */
    @Test
    void implicitStringificationOfAnUnscannedTypeIsDisclosed() throws Exception {
        Path app = compileApp(
            Map.of("W.java", "package ext.lib; public class W {"
                + " public String toString(){ try { java.nio.file.Files.readAllBytes("
                + "java.nio.file.Path.of(\"/etc/hosts\")); } catch (Exception e) {} return \"w\"; } }"),
            Map.of("S.java", String.join("\n",
                "package app;",
                "public class S {",
                "  public static String viaImplicit(ext.lib.W w){ return \"v=\" + w; }",
                "  public static String jdkOperandsOnly(int n, String s){ return \"v=\" + n + s; }",
                "}")));
        JsonObject root = scanToJson(app, "implicit-conv.json");

        JsonObject f = fnOrNull(root, "app.S.viaImplicit");
        assertNotNull(f, "the concatenating method must be IN the report — `\"v=\" + w` RUNS w.toString(), "
            + "so absence is a ⟨0.21⟩ purity claim over a body this scan never saw");
        assertTrue(f.has("invisible") && f.getAsJsonArray("invisible").toString().contains("ext.lib"),
            "it must carry invisible:[ext.lib], got " + f);

        assertNull(fnOrNull(root, "app.S.jdkOperandsOnly"),
            "CONTROL: concatenating only κ-COVERED operands re-enters nothing unseen and must stay "
            + "absent — otherwise this fix discloses on every string concatenation in the codebase");
    }

    @Test
    void aStaticReadIntoAnUnscannedPackageIsDisclosedButNotCounted() throws Exception {
        Path app = compileApp(
            Map.of("Cls.java", "package ext.lib; public class Cls {"
                + " public static final Object V = init();"
                + " static Object init(){ try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of(\"/etc/hosts\")); }"
                + " catch (Exception e) {} return new Object(); } }"),
            Map.of("F.java", String.join("\n",
                "package app;",
                "public class F {",
                "  public static void forcer(){ Object o = ext.lib.Cls.V; }",
                "}")));
        JsonObject root = scanToJson(app, "static-read.json");

        JsonObject f = fnOrNull(root, "app.F.forcer");
        assertNotNull(f, "the forcing method must be IN the report — touching `ext.lib.Cls` runs its "
            + "<clinit>, so absence is a ⟨0.21⟩ purity claim over a body this scan never saw");
        assertTrue(f.has("invisible") && f.getAsJsonArray("invisible").toString().contains("ext.lib"),
            "it must carry invisible:[ext.lib], got " + f);

        JsonArray unc = root.getAsJsonObject("coverage").getAsJsonArray("uncovered");
        assertEquals(1, unc.size(), "exactly the one unscanned package, got " + unc);
        assertEquals("ext.lib", unc.get(0).getAsJsonObject().get("name").getAsString());
        assertEquals(0, unc.get(0).getAsJsonObject().get("calls").getAsInt(),
            "NO call went into that package — the tally means call volume and drives the completeness "
            + "threshold, so a non-call reach must not inflate it; the disclosure rides `invisible`");
    }

    @Test
    void aClassifiedCallMustNotClearTheHedgeOnAnUnrelatedCallIntoTheSamePackage() throws Exception {
        Path plain = armApp(false), withHit = armApp(true);
        try {
            JsonObject a = scanToJson(plain, "arm-a.json");
            JsonObject b = scanToJson(withHit, "arm-b.json");

            for (String arm : List.of("A", "B")) {
                JsonObject root = arm.equals("A") ? a : b;
                JsonObject nm = fnOrNull(root, "app.A.nm");
                assertNotNull(nm, "arm " + arm + ": app.A.nm must be IN the report — a floored call into an "
                    + "uncurated package is a blind spot, and absence would read as a purity claim "
                    + "(the ⟨0.21⟩ manifest counts it in `analyzed`, so absence is a POSITIVE claim)");
                assertTrue(nm.has("invisible")
                        && nm.getAsJsonArray("invisible").toString().contains("org.apache.commons.io"),
                    "arm " + arm + ": app.A.nm carries invisible:[org.apache.commons.io], got " + nm);
            }

            // The defect this pins: κ matching FileUtils.readFileToString vouches for THAT call, never for
            // the package. Before the fix arm B's app.A.nm vanished from the report entirely, with no
            // coverage field and no stderr advisory — a hedge silently converted into a purity claim by
            // adding an unrelated method elsewhere in the same file.
            assertEquals(fnOrNull(a, "app.A.nm").getAsJsonArray("invisible"),
                         fnOrNull(b, "app.A.nm").getAsJsonArray("invisible"),
                "identical source must get an identical hedge regardless of an unrelated classified call");

            // The tally must mean the same thing as the name beside it: calls this scan could not see.
            // The classified call is on the record, so it is NOT counted as invisible.
            for (String arm : List.of("A", "B")) {
                JsonObject root = arm.equals("A") ? a : b;
                JsonArray unc = root.getAsJsonObject("coverage").getAsJsonArray("uncovered");
                assertEquals(1, unc.size(), "arm " + arm + ": exactly the one uncurated package");
                JsonObject e0 = unc.get(0).getAsJsonObject();
                assertEquals("org.apache.commons.io", e0.get("name").getAsString());
                assertEquals(1, e0.get("calls").getAsInt(),
                    "arm " + arm + ": ONLY the floored call is counted — a classified call's effect is on "
                    + "the record, so counting it would overstate what is invisible");
            }

            // ...and the classified call itself keeps its effect, with no spurious hedge: the fix discloses
            // more, it does not blur what was already resolved.
            JsonObject other = fnOrNull(b, "app.A.other");
            assertNotNull(other, "the classified call's own method is in the report");
            assertTrue(other.getAsJsonArray("inferred").toString().contains("Fs"),
                "app.A.other keeps its classified Fs, got " + other);
        } finally { rm(plain.getParent()); rm(withHit.getParent()); }
    }
}
