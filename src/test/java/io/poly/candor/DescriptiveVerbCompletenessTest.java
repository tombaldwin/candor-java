package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
 * ⟨0.28⟩ <b>THE RE-DISCLOSURE MUST BINDS ANSWERS, NOT ONLY VERDICTS</b> — SPEC §2, which corrects its own
 * ⟨0.15⟩ clause from <i>"a verb whose VERDICT could change"</i> to <i>"any verb whose output could be read
 * as a negative finding about the code — a verdict, an empty result set, or a zero count"</i>, because the
 * clause's justification was always broader than the clause.
 *
 * <p>{@link Query#advisoryUnanalyzed} was written for the narrow reading and the DESCRIPTIVE verbs were
 * never sent back for it. <b>MEASURED on the jar built from the commit before this one</b>, over a report
 * declaring {@code analyzed.count: 0} and a non-empty {@code unanalyzed} — the standard post-failure
 * artifact since the ⟨0.28⟩ arming rung, i.e. what is on disk after a failed run:
 *
 * <pre>
 *   blindspots   {"sources":[],"totalUnknown":0}                exit 0, no hedge on either channel
 *   containment  {"layerPrefix":"","contained":[],"ambient":{}} exit 0, no hedge
 *   reachable    {"entryPoints":0,"effects":{}}                 exit 0, no hedge
 *   map          {}                                             exit 0, no hedge
 *   tour         {"reaches":[]}                                 exit 0, no hedge
 *   where Fs     {"effect":"Fs","directly":[],"inherited":[]}   exit 0, no hedge
 * </pre>
 *
 * <p><i>"no blind spots"</i> out of a report whose own manifest names a file it could not read. A consumer
 * cannot distinguish <i>nobody performs {@code Fs}</i> from <i>nothing was examined</i>.
 *
 * <p><b>THE MIRROR IS ASSERTED FIRST</b> ({@link #anIntactReportIsUntouchedOnBothChannels}), because the
 * failure mode a disclosure rung introduces is hedging everybody: an implementation that writes the keys
 * unconditionally passes every presence-assert below and destroys the ordinary answer. candor-rust's first
 * draft of this exact rung silently RE-SORTED {@code where} and {@code blindspots} on ordinary runs, and
 * nothing in its suite could see it, because every assertion on those documents reads keys by name — so
 * the mirror here asserts the whole document, byte for byte.
 */
class DescriptiveVerbCompletenessTest {

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

    /** The six verbs SPEC §2 ⟨0.28⟩ names by measurement, in the CLI form a user types. `containment` is
     *  listed twice on purpose: its two modes (diagnostic and RATCHET) are different documents with
     *  different exit codes, and only the ratchet reads a second report. */
    private static List<String[]> verbs(Path baseline) {
        return List.of(
                new String[]{"where", "Fs"},
                new String[]{"map"},
                new String[]{"blindspots"},
                new String[]{"blindspots", "--stats"},
                new String[]{"reachable"},
                new String[]{"containment"},
                new String[]{"containment", baseline.toString()},
                new String[]{"tour"});
    }

    // ── report construction ────────────────────────────────────────────────────────────────────────────

    private static Map<String, Object> entry(String fn, List<String> inferred) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", fn);
        m.put("loc", "X.java:1");
        m.put("inferred", inferred);
        m.put("direct", inferred);
        m.put("declared", List.of());
        m.put("undeclared", List.of());
        m.put("overdeclared", List.of());
        m.put("entryPoint", false);
        m.put("unresolved", false);
        m.put("hash", "");
        return m;
    }

    /** @param analyzedCount the ⟨0.21⟩ {@code analyzed.count}; 0 is SPEC §2's "I JUDGED NOTHING" row
     *  @param unanalyzed    the ⟨0.21⟩ manifest; empty omits the key entirely, which is how a COMPLETE
     *                       report says "I read everything" (absence is not incompleteness). */
    private Path report(String name, List<Map<String, Object>> entries, int analyzedCount,
                        List<Map<String, Object>> unanalyzed) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", analyzedCount, "digest", "0"));
        if (!unanalyzed.isEmpty()) env.put("unanalyzed", unanalyzed);
        env.put("functions", entries);
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    private static final List<Map<String, Object>> MANIFEST =
            List.of(Map.of("path", "app/Unread.java", "reason", "class file failed to parse"));

    /** An ordinary, whole report: two effectful functions, a positive count, no manifest. */
    private Path intact(String name) throws Exception {
        return report(name, List.of(entry("app.repo.read", List.of("Fs")),
                        entry("app.svc.call", List.of("Net"))), 7, List.of());
    }

    /** Run a verb through the CLI dispatcher (so the flag grammar is under test too) and return
     *  {stdout, stderr, exit code}. */
    private String[] run(Path report, String[] verb, boolean json) {
        out.reset();
        err.reset();
        List<String> a = new ArrayList<>(List.of(verb));
        a.addAll(List.of("--report", report.toString()));
        if (json) a.add("--json");
        int rc = Query.run(a.toArray(new String[0]));
        return new String[]{out.toString(), err.toString(), String.valueOf(rc)};
    }

    // ── A. the manifest reaches the MACHINE channel, and the exit code does not move ───────────────────

    /** <b>A.</b> Over the armed artifact — {@code analyzed.count: 0} AND a non-empty {@code unanalyzed} —
     *  every one of the six carries {@code incomplete: true} plus BOTH manifests on its own document, at
     *  its own unchanged exit code. {@code incomplete} is the flag either cause raises, so a consumer that
     *  only branches on it is safe under both. */
    @Test void anArmedReportHedgesEveryDescriptiveVerbOnTheMachineChannel() throws Exception {
        Path rep = report("armed.app.jvm.json", List.of(), 0, MANIFEST);
        for (String[] v : verbs(intact("base.app.jvm.json"))) {
            String[] r = run(rep, v, true);
            JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
            String who = String.join(" ", v);
            assertTrue(o.has("incomplete") && o.get("incomplete").getAsBoolean(),
                    "`" + who + " --json` must carry `incomplete: true` over an armed report: " + r[0]);
            assertEquals("app/Unread.java",
                    o.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().get("path").getAsString(),
                    "…and the ⟨0.21⟩ manifest itself, naming the file: " + r[0]);
            assertEquals(1, o.getAsJsonArray("judgedNothing").size(),
                    "…and the count-0 cause, naming the report: " + r[0]);
            assertEquals("0", r[2], "the caveat travels, the verdict does not move — `" + who + "`");
        }
    }

    /** <b>A (prose half).</b> The clause requires BOTH channels, because a test that reads one channel is
     *  evidence about one channel: candor-rust built a mutant that kept the whole JSON fix and deleted only
     *  the printed line, and it survived that engine's entire suite. The note lands on STDOUT, beside the
     *  answer it qualifies — one {@code 2>/dev/null} would otherwise take it. */
    @Test void anArmedReportHedgesEveryDescriptiveVerbOnTheHumanChannel() throws Exception {
        Path rep = report("armed2.app.jvm.json", List.of(), 0, MANIFEST);
        for (String[] v : verbs(intact("base2.app.jvm.json"))) {
            String[] r = run(rep, v, false);
            String who = String.join(" ", v);
            assertTrue(r[0].contains("⚠ INCOMPLETE"),
                    "`" + who + "` must print the INCOMPLETE note on STDOUT: " + r[0]);
            assertTrue(r[0].contains("app/Unread.java"),
                    "…naming the unread file: " + r[0]);
            assertTrue(r[0].contains("judged NOTHING"),
                    "…and the count-0 cause: " + r[0]);
        }
    }

    /** <b>A (the sentences that ARE the all-clear).</b> Withdrawing the key while leaving the prose
     *  standing MOVES the false all-clear rather than removing it — {@code "no blind spots"} is the
     *  English spelling of {@code {"sources":[],"totalUnknown":0}}. */
    @Test void theReassuringSentencesAreWithdrawn() throws Exception {
        Path rep = report("armed3.app.jvm.json", List.of(), 0, MANIFEST);
        assertFalse(run(rep, new String[]{"blindspots"}, false)[0].contains("every call resolved"),
                "`blindspots` must not say every call resolved over a report naming an unread file");
        assertFalse(run(rep, new String[]{"tour"}, false)[0].contains("nothing hidden — every effect"),
                "`tour` must not print the unqualified `nothing hidden`");
        assertFalse(run(rep, new String[]{"where", "Fs"}, false)[0].contains("no function performs Fs in the report"),
                "`where` must not assert that nothing performs the effect");
        assertFalse(run(rep, new String[]{"reachable"}, false)[0].contains("nothing is marked runtime-invoked)"),
                "`reachable` must not assert the program has no runtime entry point");
        assertFalse(run(rep, new String[]{"map"}, false)[0].contains("no effectful functions in the report"),
                "`map` must not assert the code performs no effects");
        String ratchet = run(rep, new String[]{"containment", intact("base3.app.jvm.json").toString()}, false)[0];
        assertFalse(ratchet.contains("no regressions ✓"),
                "the ratchet's `✓` is the prose spelling of an empty `leaks`: " + ratchet);
    }

    // ── B. THE MIRROR: an intact report is byte-for-byte what it was ───────────────────────────────────

    /** <b>B.</b> Over a whole report this rung is a NO-OP on every channel, asserted as a WHOLE-DOCUMENT
     *  equality rather than key-by-key, for the reason in the class header: candor-rust's first draft
     *  re-sorted these documents on ordinary runs and every by-name assertion in its suite still passed. */
    @Test void anIntactReportIsUntouchedOnBothChannels() throws Exception {
        Path rep = intact("intact.app.jvm.json");
        Path base = intact("intactbase.app.jvm.json");
        assertEquals("{\n  \"effect\": \"Fs\",\n  \"directly\": [\n    \"app.repo.read\"\n  ],"
                     + "\n  \"inherited\": []\n}\n",
                run(rep, new String[]{"where", "Fs"}, true)[0],
                "`where --json` must be byte-identical — key ORDER included");
        for (String[] v : verbs(base)) {
            for (boolean json : new boolean[]{true, false}) {
                String[] r = run(rep, v, json);
                String who = String.join(" ", v) + (json ? " --json" : "");
                assertFalse(r[0].contains("incomplete") || r[0].contains("INCOMPLETE"),
                        "`" + who + "` must say nothing about completeness over a whole report: " + r[0]);
                assertFalse(r[0].contains("judgedNothing") || r[0].contains("judged NOTHING"),
                        "`" + who + "` must not raise the count-0 cause on a positive count: " + r[0]);
                assertEquals("", r[1], "`" + who + "` must write nothing to stderr: " + r[1]);
            }
        }
    }

    /** <b>B (the row that separates the two count-0 shapes).</b> {@code functions: []} alone is the shape
     *  of an ALL-PURE package as well as of one that analyzed nothing, and SPEC §2 chaining rule 3
     *  requires a consumer to believe the first. So the trigger is keyed on the ⟨0.21⟩ COUNT and never on
     *  the emptiness of {@code functions}: a genuinely pure package answers flat, exactly as before. */
    @Test void anAllPureReportIsNotJudgedNothing() throws Exception {
        Path rep = report("pure.app.jvm.json", List.of(), 7, List.of());
        String[] r = run(rep, new String[]{"where", "Fs"}, true);
        assertEquals("{\n  \"effect\": \"Fs\",\n  \"directly\": [],\n  \"inherited\": []\n}\n", r[0],
                "an all-pure package (count 7, no entries) is a CLAIM, not a blind spot: " + r[0]);
        assertEquals("", r[1]);
    }

    // ── C/D. the count-0 cause on its own, and where it stops ──────────────────────────────────────────

    /** <b>D.</b> A report with {@code analyzed.count: 0} and NO {@code unanalyzed} still discloses. This
     *  is the cause that was missing rather than mis-scoped: a report that judged nothing carries no
     *  manifest — there is no unread FILE to name — so a reader keyed only on {@code unanalyzed} saw a
     *  complete report and every verb answered over it just the same. */
    @Test void judgedNothingAloneStillHedges() throws Exception {
        Path rep = report("facade.app.jvm.json", List.of(), 0, List.of());
        for (String[] v : verbs(intact("base4.app.jvm.json"))) {
            String[] r = run(rep, v, true);
            JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
            String who = String.join(" ", v);
            assertTrue(o.has("incomplete"), "`" + who + "` must hedge on the count-0 cause ALONE: " + r[0]);
            assertFalse(o.has("unanalyzed"),
                    "…and must NOT invent a manifest that is not there — the key is omitted when empty, so "
                    + "a document raised by `unanalyzed` alone stays pre-⟨0.28⟩ shaped: " + r[0]);
            assertEquals("0", r[2], "still a disclosure, still not an exit code — `" + who + "`");
        }
    }

    /** <b>C/D.</b> …and it STOPS at the exit code. ⟨0.24⟩ ruled count-0 explicitly the other way for exits
     *  — "a disclosure, not an exit code" — because {@code gate --report} exits 0 over a facade package,
     *  and an advisory verb exiting 2 there would claim it got LESS far than the gate on identical bytes.
     *  So {@code --strict} is unmoved: this rung did not widen
     *  {@link Query.ReportCompleteness#incomplete}, which is what those two exits are computed from.
     *
     *  <p>⟨0.28⟩ {@code ok}, though, is WITHDRAWN — this assert used to pin the opposite ("`ok` is still
     *  answered — the omit-`ok` rule is keyed on `unanalyzed`"), which pinned the false all-clear itself:
     *  {@code {"ok": true}} over a report that judged NOTHING is a determination the run is not entitled
     *  to make, and rust, ts and swift all omit the field here (measured 2026-08-12, candor-spec
     *  {@code conformance/gen_key_shapes.py} harvest). The document hedges; the exit does not move —
     *  the two halves of ⟨0.24⟩'s ruling, each on its own channel. */
    @Test void theCountZeroCauseNeverReachesAStrictExitCode() throws Exception {
        Path rep = report("facade2.app.jvm.json", List.of(), 0, List.of());
        Path pol = tmp.resolve("p.policy");
        Files.writeString(pol, "deny Fs app\n");
        for (String verb : List.of("unverified", "fix-gate")) {
            out.reset();
            int rc = Query.run(new String[]{verb, "--strict", "--report", rep.toString(),
                    "--policy", pol.toString(), "--json"});
            assertEquals(0, rc, "`" + verb + " --strict` must stay at 0 over a judged-nothing report: "
                    + "the gate route exits 0 over the same bytes, and a verb that got LESS far than the "
                    + "gate is the mirror of the over-claim --strict exists to prevent");
            JsonObject o = JsonParser.parseString(out.toString()).getAsJsonObject();
            assertFalse(o.has("ok"), "`" + verb + "` must not answer `ok` over a judged-nothing report — "
                    + "neither boolean is a statement this input licenses (SPEC §2 ⟨0.28⟩): " + out);
            assertTrue(o.has("judgedNothing") && o.get("judgedNothing").isJsonArray(),
                    "…the caveat that takes its place names WHICH report judged nothing, as an ARRAY");
        }
    }

    /** The two causes get OPPOSITE answers about what CI will do, and the note says which. A warning that
     *  sends the reader to a job which then passes teaches them the warning is noise. */
    @Test void theNoteTellsTheTruthAboutWhatTheGateDoes() throws Exception {
        assertTrue(run(report("un.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, MANIFEST),
                        new String[]{"blindspots"}, false)[0].contains("exits 2 over these bytes"),
                "an `unanalyzed` manifest IS one of §3.3's two exit-2 gate causes");
        assertTrue(run(report("jn.app.jvm.json", List.of(), 0, List.of()),
                        new String[]{"blindspots"}, false)[0].contains("NOTHING DOWNSTREAM WILL CATCH THIS"),
                "…and count-0 is NOT: `gate --report` exits 0 over it, so the note is the whole warning");
    }

    // ── the ratchet reads BOTH sides ───────────────────────────────────────────────────────────────────

    /** {@code containment <baseline>} answers a DIFFERENCE, so it is unsound if EITHER side is partial —
     *  in opposite directions: a leak in an unread unit of the CURRENT tree is missed (a false all-clear
     *  at exit 0), one in an unread unit of the BASELINE reads as newly appeared (a fabricated leak, at
     *  exit 1). An intact current side must therefore still hedge on a partial baseline. */
    @Test void theRatchetFoldsInTheBaselinesManifest() throws Exception {
        Path cur = intact("rcur.app.jvm.json");
        Path base = report("rbase.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, MANIFEST);
        String[] r = run(cur, new String[]{"containment", base.toString()}, true);
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.has("incomplete"),
                "a partial BASELINE makes the difference unsound in the fabricated-leak direction: " + r[0]);
        assertEquals("app/Unread.java",
                o.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().get("path").getAsString());
        assertEquals("1", r[2], "…and the ratchet's own exit code is untouched by the caveat");
    }

    /** The ratchet document's key order is FIXED. It used to be built with {@code Map.of}, whose iteration
     *  order is salted per JVM: 8 runs of the identical command gave {@code {cleanups,leaks}} six times
     *  and {@code {leaks,cleanups}} twice. A machine channel whose key order changes between runs cannot
     *  be diffed, and the ⟨0.28⟩ keys need a defined place to land after it. */
    @Test void theRatchetDocumentHasAStableKeyOrder() throws Exception {
        Path cur = intact("scur.app.jvm.json");
        Path base = intact("sbase.app.jvm.json");
        assertEquals("{\n  \"leaks\": [],\n  \"cleanups\": []\n}\n",
                run(cur, new String[]{"containment", base.toString()}, true)[0]);
    }

    // ── ONE predicate, not two spellings ───────────────────────────────────────────────────────────────

    /** The judged-nothing row is decided by {@link Loader#claimsToHaveJudgedNothing} — the predicate the
     *  chained-dep join already used — and the {@code gate --report} route now asks it through the same
     *  {@link Query.Envelope} field rather than its own inline {@code analyzed.count == 0}. This is the
     *  row where the two DIFFER: a legacy bare-array report has no {@code analyzed} key, reads back as
     *  count 0, and LISTS functions it demonstrably judged (⟨0.24⟩ row 3). Two spellings in one file is
     *  how a report comes to be judged-nothing on one route and not on the other. */
    @Test void aLegacyBareArrayReportWithEntriesJudgedSomething() throws Exception {
        Path rep = tmp.resolve("legacy.app.jvm.json");
        Files.writeString(rep, io.poly.candor.model.ReportJson.pretty(
                List.of(entry("app.repo.read", List.of("Fs")))));
        String[] r = run(rep, new String[]{"where", "Fs"}, true);
        assertFalse(r[0].contains("incomplete"),
                "a pre-⟨0.21⟩ producer has no manifest and so makes no claim — judged-nothing iff its "
                + "`functions` is EMPTY, and this one lists a function: " + r[0]);
        Path empty = tmp.resolve("legacyempty.app.jvm.json");
        Files.writeString(empty, "[]\n");
        assertTrue(run(empty, new String[]{"where", "Fs"}, true)[0].contains("incomplete"),
                "…while an EMPTY bare array falls back to the unchained reading and does hedge");
    }

    // ── ⟨0.28⟩ THE THIRD ROW IS NOT THE FIRST ROW — `noManifest` (SPEC §2) ─────────────────────────────

    /** A report carrying NO {@code analyzed} key — SPEC §2's row 3, a pre-⟨0.21⟩ producer — hedges under
     *  the pinned {@code noManifest} key, NOT under {@code judgedNothing}.
     *
     *  <p>MEASURED on the jar built before this split, over {@code {"candor":…,"functions":[]}} with no
     *  {@code analyzed} key: every verb here emitted {@code judgedNothing: ["<path>"]} and the note said
     *  the report <i>"JUDGED NOTHING (`analyzed.count: 0`, or no manifest at all)"</i>. <b>The report
     *  declares nothing.</b> The hedge is the right DIRECTION — row 3's own instruction is <i>no manifest,
     *  no claim</i> — but ⟨0.28⟩ pins {@code judgedNothing} to <i>reports declaring `analyzed.count:
     *  0`</i>, so filing row 3 there makes one key mean two things and loses the distinction §2's table
     *  exists to draw. The repairs differ: row 1 wants a scan that reaches a conclusion, row 3 wants a
     *  producer that emits a manifest at all. */
    @Test void aReportWithNoAnalyzedManifestHedgesUnderNoManifestNotJudgedNothing() throws Exception {
        Path row3 = tmp.resolve("row3.app.jvm.json");
        Files.writeString(row3, "{\"candor\":{\"version\":\"test\",\"spec\":\"0.20\"},"
                + "\"packages\":[\"app\"],\"functions\":[]}\n");
        for (String[] v : verbs(intact("nmbase.app.jvm.json"))) {
            String[] r = run(row3, v, true);
            JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
            String who = String.join(" ", v);
            assertTrue(o.has("incomplete") && o.get("incomplete").getAsBoolean(),
                    "`" + who + "`: row 3's own instruction is `no manifest, no claim`: " + r[0]);
            assertTrue(o.has("noManifest"),
                    "`" + who + "`: SPEC §2 pins `noManifest: [\"<report path>\", …]` verbatim for a "
                    + "report carrying no `analyzed` key — this document has no such key: " + r[0]);
            assertEquals(1, o.getAsJsonArray("noManifest").size(),
                    "`" + who + "`: one entry per row-3 report: " + r[0]);
            assertEquals(row3.toString(), o.getAsJsonArray("noManifest").get(0).getAsString(), r[0]);
            assertFalse(o.has("judgedNothing"),
                    "`" + who + "`: the report DECLARES nothing — filing it under `judgedNothing` asserts "
                    + "an `analyzed.count: 0` that is not on the wire: " + r[0]);
            assertEquals("0", r[2], "row 3 is a DISCLOSURE, not an exit code — the gate exits 0 too");

            // The PROSE half, from the same trigger, or the mutant that deletes one channel survives.
            String prose = run(row3, v, false)[0];
            assertTrue(prose.contains("NO `analyzed` manifest"),
                    "`" + who + "`: the note must name the real cause: " + prose);
            assertFalse(prose.contains("judged NOTHING") || prose.contains("analyzed.count: 0"),
                    "`" + who + "`: …and must not re-assert row 1's claim in prose after removing it from "
                    + "the wire: " + prose);
        }
    }

    /** <b>CONTROL, and the split goes both ways or it is a rename.</b> Row 1 ({@code analyzed.count: 0})
     *  keeps {@code judgedNothing} and never becomes {@code noManifest}; row 2 ({@code count: 7},
     *  {@code functions: []}) is a legitimate all-pure claim §2 rule 3 requires a consumer to BELIEVE and
     *  MUST NOT hedge at all. A fix that hedges all three rows has disabled the feature rather than
     *  implemented the rule — measured over 1997 JVM dependency jars, a predicate keyed on
     *  {@code functions} being empty withdraws 104 real claims to catch 6. */
    @Test void rowOneKeepsJudgedNothingAndRowTwoDoesNotHedgeAtAll() throws Exception {
        Path row1 = report("nmrow1.app.jvm.json", List.of(), 0, List.of());
        JsonObject o1 = JsonParser.parseString(run(row1, new String[]{"where", "Fs"}, true)[0])
                .getAsJsonObject();
        assertTrue(o1.has("judgedNothing"),
                "row 1 (`analyzed.count: 0`) keeps `judgedNothing` — the split goes both ways or it is a "
                + "rename: " + o1);
        assertEquals(1, o1.getAsJsonArray("judgedNothing").size(), o1.toString());
        assertFalse(o1.has("noManifest"), "row 1 HAS a manifest; it declares 0: " + o1);
        assertTrue(run(row1, new String[]{"where", "Fs"}, false)[0].contains("`analyzed.count: 0`"),
                "…and its prose says exactly that, with the stopgap `or no manifest at all` gone");

        Path row2 = report("nmrow2.app.jvm.json", List.of(), 7, List.of());
        String[] r2 = run(row2, new String[]{"where", "Fs"}, true);
        assertEquals("{\n  \"effect\": \"Fs\",\n  \"directly\": [],\n  \"inherited\": []\n}\n", r2[0],
                "row 2 MUST NOT hedge — hedging all three rows disables the feature: " + r2[0]);
        assertEquals("", r2[1], "…on either channel: " + r2[1]);
    }

    /** <b>THE TRAP THE ROW-3 SPLIT SETS, PINNED.</b> {@link Loader#claimsToHaveJudgedNothing} is not only a
     *  disclosure predicate — {@link Loader#loadCrossDeps} reads it to decide COVERAGE
     *  ({@code depCoveredPkgs}, the set that silences the κ ledger's {@code invisible} hedge) and
     *  {@code gate --report} reads it through {@link Query.Envelope}. Row 3's own instruction is <i>no
     *  manifest, no claim</i>, so an absent manifest must keep granting NONE. The tempting fix for the
     *  false label — make that predicate answer {@code false} for a manifest-less report — would turn
     *  every pre-⟨0.21⟩ report into a COVERED one: a silent under-report introduced by a disclosure fix.
     *  So the split adds a SECOND predicate and this asserts the first is unmoved. */
    @Test void theRowThreeSplitDoesNotMoveTheCoveragePredicate() {
        com.google.gson.Gson g = new com.google.gson.Gson();
        com.google.gson.JsonArray none = new com.google.gson.JsonArray();
        com.google.gson.JsonArray one = g.fromJson("[{\"fn\":\"app.f\"}]", com.google.gson.JsonArray.class);
        JsonObject row3 = g.fromJson("{\"package\":\"legacy\"}", JsonObject.class);
        assertTrue(Loader.claimsToHaveJudgedNothing(row3, none),
                "an absent manifest must STILL grant no coverage — row 3 is `no manifest, no claim`");
        assertTrue(Loader.hasNoManifest(row3), "…and it is row 3, not row 1");
        JsonObject row1 = g.fromJson("{\"package\":\"facade\",\"analyzed\":{\"count\":0}}", JsonObject.class);
        assertTrue(Loader.claimsToHaveJudgedNothing(row1, none));
        assertFalse(Loader.hasNoManifest(row1), "row 1 HAS a manifest; it declares 0");
        JsonObject row2 = g.fromJson("{\"package\":\"pure\",\"analyzed\":{\"count\":7}}", JsonObject.class);
        assertFalse(Loader.claimsToHaveJudgedNothing(row2, none),
                "the row-2 control: a believed all-pure claim");
        assertFalse(Loader.hasNoManifest(row2));
        // A manifest-less report that LISTS entries judged something: not row-3-hedged (the disclosure ANDs
        // the two predicates), and it grants coverage exactly as it did before this rung.
        assertFalse(Loader.claimsToHaveJudgedNothing(row3, one));
        assertTrue(Loader.hasNoManifest(row3));
        // The legacy BARE ARRAY has no envelope at all, so it is row 3 too — and row-3-hedged only when it
        // is also empty.
        assertTrue(Loader.hasNoManifest(null));
        assertTrue(Loader.claimsToHaveJudgedNothing(null, none));
        assertFalse(Loader.claimsToHaveJudgedNothing(null, one));
    }

    /** A locator naming ONE OF EACH discloses them under SEPARATE keys — one key meaning two things is
     *  exactly what loses the distinction the three-row table exists to draw. */
    @Test void aLocatorNamingBothRowsDisclosesThemSeparately() throws Exception {
        Path dir = tmp.resolve("both");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("r.aa.jvm.json"),
                "{\"candor\":{\"version\":\"test\",\"spec\":\"0.28\"},\"packages\":[\"app\"],"
                + "\"analyzed\":{\"count\":0,\"digest\":\"0\"},\"functions\":[]}\n");
        Files.writeString(dir.resolve("r.bb.jvm.json"),
                "{\"candor\":{\"version\":\"test\",\"spec\":\"0.20\"},\"packages\":[\"app\"],"
                + "\"functions\":[]}\n");
        String[] r = run(dir.resolve("r"), new String[]{"where", "Fs"}, true);
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.has("judgedNothing") && o.has("noManifest"),
                "a locator naming one of each must disclose them under SEPARATE keys — one key meaning "
                + "two things loses the distinction the three-row table exists to draw: " + r[0]);
        assertEquals(1, o.getAsJsonArray("judgedNothing").size(), r[0]);
        assertEquals(1, o.getAsJsonArray("noManifest").size(), r[0]);
        assertTrue(o.getAsJsonArray("judgedNothing").get(0).getAsString().endsWith("r.aa.jvm.json"), r[0]);
        assertTrue(o.getAsJsonArray("noManifest").get(0).getAsString().endsWith("r.bb.jvm.json"), r[0]);
    }
}
