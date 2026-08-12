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
 * ⟨0.24⟩ <b>THE OMIT-{@code ok} RULE BINDS EVERY ADVISORY VERB, AND THE DISCLOSURE MUST REACH EVERY
 * CHANNEL</b> — SPEC §3.2, ruled in candor-spec {@code ec1a441} (and {@code 93cef40} for the relation it
 * rests on). {@code 0075987} ruled it for {@code whatif}; this engine implemented it for {@code whatif}
 * and the siblings never got sent back.
 *
 * <p><b>MEASURED on the jar built from the commit before this one</b>, over the release reviewer's fixture
 * — a report declaring ONE {@code unanalyzed} unit, <b>no holes at all</b>, and a {@code deny Net app}
 * that nothing violates:
 *
 * <pre>
 *   gate --report        exit 2   ok:false  incomplete:true  + the manifest      ← correct
 *   unverified --strict  exit 0   {"ok": true,  "unverified": []}  and stdout:
 *                                 "every function in a pure/deny layer is PROVABLY clean ✓"
 *   fix-gate  --strict   exit 0   {"ok": true,  "remedies":   []}  and stdout:
 *                                 "no deny/pure boundary crossings in this report ✓"
 * </pre>
 *
 * <p><b>That fixture is the sharp one, and no prior fixture in this repo has an analogue.</b> Every
 * existing incompleteness test pairs the unread file with something the verb DOES find, so the behaviour
 * on <i>"nothing to report, but I could not see everything"</i> — which is the only shape where the false
 * all-clear is the whole output — was never exercised. {@code unverified} is the sharpest verb in the
 * family for the same reason: it exists to say <i>"your green gate is not provably green"</i>, and it was
 * certifying a set it knows it cannot see all of. A function in an unparsed file is absent from
 * {@code functions}, so it cannot be enumerated as an unverified pass, and that absence is exactly what
 * the verb would have to report.
 *
 * <p><b>{@code ok: false} is NOT the repair</b>, for the reason §3.2 gives in {@code whatif}: on an
 * advisory verb {@code false} asserts <i>"a hole exists, here it is"</i> beside an EMPTY array — the
 * fabrication mirror, worse than the silence it replaces. So {@code ok} is OMITTED, {@code incomplete} +
 * the manifest take its place, a consumer writing {@code if (r.ok)} gets a falsy value and fails safe, and
 * {@code --strict} (the CI form) exits 2.
 *
 * <p><b>THE MIRROR IS ASSERTED FIRST</b> ({@link #aCompleteReportIsUnchangedInBothChannels} and the
 * per-verb mirrors below), because the failure mode a fix like this introduces is deleting {@code ok} for
 * everyone: an implementation that omits the field unconditionally passes every absence-assert in the
 * class and takes the verb's whole verdict with it.
 */
class AdvisoryIncompletenessTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void fresh() {
        Candor.resetState();
        Candor.gateViolations.clear();
        Candor.gateCapture = false;
    }

    @AfterEach
    void clear() {
        Candor.gateCapture = false;
        Candor.gateViolations.clear();
        Candor.resetState();
    }

    // ── fixtures ───────────────────────────────────────────────────────────────────────────────────────

    private static Map<String, Object> entry(String fn, List<String> inferred, Map<String, Object> extra) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", fn);
        m.put("loc", "A.java:1");
        m.put("inferred", inferred);
        m.put("direct", inferred);
        m.put("declared", List.of());
        m.put("undeclared", List.of());
        m.put("overdeclared", List.of());
        m.put("entryPoint", false);
        m.put("unresolved", inferred.contains("Unknown"));
        m.put("hash", "");
        if (extra != null) m.putAll(extra);
        return m;
    }

    /** @param unanalyzed the ⟨0.21⟩ manifest rows, or null for a COMPLETE report (the mirror). */
    private Path report(String name, List<Map<String, Object>> entries, List<Map<String, Object>> unanalyzed)
            throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", entries.size(), "digest", "0"));
        if (unanalyzed != null) env.put("unanalyzed", unanalyzed);
        env.put("functions", entries);
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    private static final List<Map<String, Object>> ONE_HOLE =
            List.of(Map.of("path", "app/Unreadable.class", "reason", "class failed to analyze: bad magic"));

    /** <b>THE RELEASE REVIEWER'S FIXTURE.</b> One {@code unanalyzed} unit, and NOTHING ELSE to report: the
     *  single entry performs {@code Fs}, no entry is {@code Unknown}, and the policy denies {@code Net}. So
     *  every array the verbs answer with is EMPTY and the incompleteness is the entire finding. */
    private Path incompleteNothingToFind() throws Exception {
        return report("incomplete.jvm.json",
                List.of(entry("app.writes", List.of("Fs"), Map.of("paths", List.of("/tmp/x")))), ONE_HOLE);
    }

    /** THE MIRROR: byte-identical but for the manifest, so a fix that withdraws `ok` unconditionally is
     *  caught here rather than in production. */
    private Path completeNothingToFind() throws Exception {
        return report("complete.jvm.json",
                List.of(entry("app.writes", List.of("Fs"), Map.of("paths", List.of("/tmp/x")))), null);
    }

    /** COMPLETE and with something to find: an {@code Unknown} that the deny layer PASSES (an `unverified`
     *  hole) and a {@code Net} crossing (a `fix-gate` remedy). Pins that the verbs still ANSWER. */
    private Path completeWithFindings() throws Exception {
        return report("findings.jvm.json", List.of(
                entry("app.hole", List.of("Unknown"), Map.of("unknownWhy", List.of("dispatch:iface"))),
                entry("app.calls", List.of("Net"), Map.of("hosts", List.of("api.example.com")))), null);
    }

    /** INCOMPLETE and with something to find — the shape every PRIOR fixture had. The refusal still wins
     *  over the finding under `--strict`: 2, not the 1 a hole alone would give. */
    private Path incompleteWithFindings() throws Exception {
        return report("both.jvm.json", List.of(
                entry("app.hole", List.of("Unknown"), Map.of("unknownWhy", List.of("dispatch:iface"))),
                entry("app.calls", List.of("Net"), Map.of("hosts", List.of("api.example.com")))), ONE_HOLE);
    }

    private Path policy(String body) throws Exception {
        Path p = tmp.resolve("p" + Math.abs(body.hashCode()) + ".policy");
        Files.writeString(p, body);
        return p;
    }

    // ── drivers (through the CLI dispatcher, so the flag grammar is under test too) ─────────────────────

    private record Run(int exit, String stdout, String stderr) {}

    private static Run run(Path report, Path pol, String verb, String... more) {
        List<String> a = new ArrayList<>(List.of(verb));
        a.addAll(List.of(more));
        a.addAll(List.of("--report", report.toString(), "--policy", pol.toString()));
        PrintStream o = System.out, e = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));
        int code;
        try {
            Candor.resetState();
            code = Query.run(a.toArray(new String[0]));
        } finally {
            System.setOut(o);
            System.setErr(e);
        }
        return new Run(code, out.toString(), err.toString());
    }

    private static JsonObject jsonOf(Run r) {
        return JsonParser.parseString(r.stdout()).getAsJsonObject();
    }

    // ── 1. THE MIRROR — a COMPLETE report is unchanged, in both channels ────────────────────────────────

    /**
     * <b>Written and run FIRST.</b> The fix under test omits a field; the way to get that wrong is to omit
     * it always, and every absence-assert in this class would still pass. So: over a report with NO
     * manifest, both verbs still carry {@code ok}, still print their tick, and still exit 0.
     */
    @Test
    void aCompleteReportIsUnchangedInBothChannels() throws Exception {
        Path rep = completeNothingToFind();
        Path pol = policy("deny Net app\n");

        Run uv = run(rep, pol, "unverified", "--json");
        assertTrue(jsonOf(uv).has("ok"), "a COMPLETE report still carries `ok` — omitting it always would "
                + "delete the verdict for everyone: " + uv.stdout());
        assertTrue(jsonOf(uv).get("ok").getAsBoolean(), "…and it is true: nothing to find, nothing unread");
        assertFalse(jsonOf(uv).has("incomplete"), "no `incomplete` on a complete report");
        assertFalse(jsonOf(uv).has("unanalyzed"), "no manifest on a complete report (byte-compatible)");

        Run fg = run(rep, pol, "fix-gate", "--json");
        assertTrue(jsonOf(fg).has("ok"), "fix-gate mirror: `ok` survives a complete report");
        assertTrue(jsonOf(fg).get("ok").getAsBoolean());
        assertFalse(jsonOf(fg).has("incomplete"));

        assertTrue(run(rep, pol, "unverified").stdout().contains("PROVABLY clean"),
                "the PROSE tick is the prose `ok: true` — it must still be printed when it is TRUE");
        assertTrue(run(rep, pol, "fix-gate").stdout().contains("no deny/pure boundary crossings"),
                "…and so must fix-gate's");
        assertEquals(0, run(rep, pol, "unverified", "--strict").exit(), "complete + clean → --strict exits 0");
        assertEquals(0, run(rep, pol, "fix-gate", "--strict").exit());
        assertEquals(0, run(rep, pol, "gate").exit(), "…and so does the gate over the same bytes");
    }

    /** The other half of the mirror: a COMPLETE report with findings still answers 1 under {@code --strict}
     *  — the code that says "a hole/crossing EXISTS", which the incompleteness exit must not swallow. */
    @Test
    void aCompleteReportWithFindingsStillAnswersOkFalseAndExitsOne() throws Exception {
        Path rep = completeWithFindings();
        Path pol = policy("deny Net app\n");

        JsonObject uv = jsonOf(run(rep, pol, "unverified", "--json"));
        assertTrue(uv.has("ok"), "still a verdict");
        assertFalse(uv.get("ok").getAsBoolean(), "…and it is false: `app.hole` passes the layer while Unknown");
        assertFalse(uv.getAsJsonArray("unverified").isEmpty(), "the hole is named");
        assertEquals(1, run(rep, pol, "unverified", "--strict").exit(), "a FINDING is exit 1, not 2");

        JsonObject fg = jsonOf(run(rep, pol, "fix-gate", "--json"));
        assertFalse(fg.get("ok").getAsBoolean());
        assertFalse(fg.getAsJsonArray("remedies").isEmpty(), "the Net crossing gets a remedy");
        assertEquals(1, run(rep, pol, "fix-gate", "--strict").exit());
    }

    // ── 2. THE DEFECT — an INCOMPLETE report with NOTHING ELSE TO FIND ──────────────────────────────────

    /**
     * The reviewer's row, in JSON. {@code ok} goes; {@code incomplete} + the manifest arrive; the verb's own
     * array still ships, because a partial answer that says it is partial beats a refusal.
     */
    @Test
    void unverifiedOverAnIncompleteReportOmitsOkAndCarriesTheManifest() throws Exception {
        Path rep = incompleteNothingToFind();
        Path pol = policy("deny Net app\n");

        JsonObject o = jsonOf(run(rep, pol, "unverified", "--json"));
        assertFalse(o.has("ok"), "§3.2: `ok` is OMITTED — `true` certifies a universe known to be partial, "
                + "`false` asserts a hole nobody found: " + o);
        assertTrue(o.get("incomplete").getAsBoolean(), "`incomplete: true` takes its place");
        assertEquals(1, o.getAsJsonArray("unanalyzed").size(), "…with the manifest itself");
        JsonObject u = o.getAsJsonArray("unanalyzed").get(0).getAsJsonObject();
        assertEquals("app/Unreadable.class", u.get("path").getAsString());
        assertTrue(u.get("reason").getAsString().contains("bad magic"), "the reason travels too");
        assertTrue(o.has("unverified"), "the verb's own array still ships — partial, and says so");
    }

    /** The same row for {@code fix-gate}: the verb whose {@code ok: true} reads "no crossings left to fix". */
    @Test
    void fixGateOverAnIncompleteReportOmitsOkAndCarriesTheManifest() throws Exception {
        Path rep = incompleteNothingToFind();
        Path pol = policy("deny Net app\n");

        JsonObject o = jsonOf(run(rep, pol, "fix-gate", "--json"));
        assertFalse(o.has("ok"), "§3.2: omitted, not flipped: " + o);
        assertTrue(o.get("incomplete").getAsBoolean());
        assertEquals("app/Unreadable.class",
                o.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().get("path").getAsString());
        assertTrue(o.has("remedies"), "the remedies array still ships");
    }

    /** {@code --strict} is how CI consumes both, and 2 is the gate's own could-not-evaluate code — not the
     *  1 that would claim a finding, and not the 0 that certified. */
    @Test
    void strictExitsTwoOverAnIncompleteReportInBothChannels() throws Exception {
        Path rep = incompleteNothingToFind();
        Path pol = policy("deny Net app\n");

        assertEquals(2, run(rep, pol, "gate").exit(), "the gate over the same bytes");
        assertEquals(2, run(rep, pol, "unverified", "--strict", "--json").exit(), "unverified --strict --json");
        assertEquals(2, run(rep, pol, "unverified", "--strict").exit(), "unverified --strict (prose)");
        assertEquals(2, run(rep, pol, "fix-gate", "--strict", "--json").exit(), "fix-gate --strict --json");
        assertEquals(2, run(rep, pol, "fix-gate", "--strict").exit(), "fix-gate --strict (prose)");
    }

    /** WITHOUT {@code --strict} these verbs stay ADVISORY and exit 0: the agent fix-loop reads the body,
     *  and turning its exit red is a different change than this one. The DISCLOSURE is what changes. */
    @Test
    void withoutStrictTheAdvisoryExitIsStillZero() throws Exception {
        Path rep = incompleteNothingToFind();
        Path pol = policy("deny Net app\n");
        assertEquals(0, run(rep, pol, "unverified", "--json").exit());
        assertEquals(0, run(rep, pol, "fix-gate", "--json").exit());
        assertEquals(0, run(rep, pol, "unverified").exit());
        assertEquals(0, run(rep, pol, "fix-gate").exit());
    }

    // ── 3. THE OTHER CHANNEL ───────────────────────────────────────────────────────────────────────────

    /**
     * <b>The prose tick IS the prose {@code ok: true}.</b> candor-rust built a mutant that kept the whole
     * JSON fix and deleted only the printed line, and it survived that engine's entire suite — an
     * absence-assert on {@code ok} cannot see the other channel. So this test reads STDOUT and asserts the
     * sentence is gone, which is the only assert in this class the JSON repair alone cannot satisfy.
     */
    @Test
    void theProseChannelWithdrawsTheClaimToo() throws Exception {
        Path rep = incompleteNothingToFind();
        Path pol = policy("deny Net app\n");

        Run uv = run(rep, pol, "unverified");
        assertFalse(uv.stdout().contains("PROVABLY clean"),
                "`… is PROVABLY clean ✓` over a report declaring source candor could not read is the prose "
                + "`ok: true`; omitting the JSON field while leaving it standing MOVES the false all-clear "
                + "rather than removing it. stdout was:\n" + uv.stdout());
        assertFalse(uv.stdout().contains("✓"), "no tick of any spelling on this run");
        assertTrue((uv.stdout() + uv.stderr()).contains("app/Unreadable.class"),
                "…and the unit that was not analyzed is NAMED, so the reader can go and fix it");

        Run fg = run(rep, pol, "fix-gate");
        assertFalse(fg.stdout().contains("no deny/pure boundary crossings in this report ✓"),
                "fix-gate's tick is the same sentence one verb over: " + fg.stdout());
        assertFalse(fg.stdout().contains("✓"));
        assertTrue((fg.stdout() + fg.stderr()).contains("app/Unreadable.class"));
    }

    /** {@code fix} answers about ONE function and carries neither {@code ok} nor {@code --strict}, so it
     *  has nothing to withdraw and nothing to fail — but its two "nothing to fix" sentences are the same
     *  all-clear in the same channel, over the same unread source. */
    @Test
    void fixDisclosesTheIncompletenessOnBothChannels() throws Exception {
        Path rep = incompleteNothingToFind();
        Path pol = policy("deny Net app\n");

        List<String> a = List.of("fix", "app.writes", "Fs", "--report", rep.toString(),
                "--policy", pol.toString());
        PrintStream o = System.out, e = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));
        try {
            Candor.resetState();
            Query.run(a.toArray(new String[0]));
        } finally {
            System.setOut(o);
            System.setErr(e);
        }
        String all = out.toString() + err.toString();
        assertTrue(all.contains("app/Unreadable.class"),
                "`no policy forbids it there — nothing to fix` over an incomplete report is the same "
                + "unqualified all-clear: " + all);
    }

    // ── 4. INCOMPLETE **AND** SOMETHING TO FIND — the shape every prior fixture had ─────────────────────

    /** The refusal outranks the finding: {@code --strict} is 2, not the 1 a hole alone gives, and `ok` is
     *  still omitted even though a `false` would here be defensible — one rule for both verbs, and it is
     *  the fail-safe one. */
    @Test
    void incompletenessOutranksAFindingUnderStrict() throws Exception {
        Path rep = incompleteWithFindings();
        Path pol = policy("deny Net app\n");

        JsonObject uv = jsonOf(run(rep, pol, "unverified", "--json"));
        assertFalse(uv.has("ok"), "omitted even with a hole named beside it: " + uv);
        assertFalse(uv.getAsJsonArray("unverified").isEmpty(), "the hole is STILL named — partial, not refused");
        assertTrue(uv.get("incomplete").getAsBoolean());
        assertEquals(2, run(rep, pol, "unverified", "--strict").exit(),
                "could-not-fully-evaluate (2) outranks found-a-hole (1) — the gate exits 2 over these bytes");

        JsonObject fg = jsonOf(run(rep, pol, "fix-gate", "--json"));
        assertFalse(fg.has("ok"));
        assertFalse(fg.getAsJsonArray("remedies").isEmpty(), "the remedy for a crossing it DID see still ships");
        assertEquals(2, run(rep, pol, "fix-gate", "--strict").exit());

        // …and the GATE over these same bytes exits 1, not 2: §3.1 precedence is violation (1) > refusal
        // (2) > incomplete (2), because a violation it FOUND is certain and strictly more informative than
        // "could not fully evaluate". That is not a contradiction of the relation above — §3.2 bounds the
        // advisory verb's CERTAINTY by the gate's, not its exit ranking, and the advisory verbs have no
        // certain finding to promote: their arrays are advice, not a verdict. Byte-aligned with candor-ts
        // and candor-swift, both of which let incompleteness take the exit unconditionally.
        assertEquals(1, run(rep, pol, "gate").exit(),
                "the gate promotes the CERTAIN violation; the advisory verbs have none to promote");
    }

    // ── 5. THE RELATION (SPEC §3.2, candor-spec 93cef40) ───────────────────────────────────────────────

    /**
     * <b>An advisory verb must never be less sensitive to incompleteness than the gate over the same
     * bytes.</b> Stated as a RELATION, so the ELEMENT rule follows from it rather than being chosen: a
     * manifest member the reader cannot make sense of is still a member saying something was not analysed.
     * candor-swift skipped a member with no string {@code path} and thereby read a SHORTER list than the
     * gate read from the identical file — a report the gate calls incomplete, given a clean advisory
     * answer. This engine counts an element the moment it is an object; the assert is that the two verbs
     * agree, not that a particular member survives.
     */
    @Test
    void aMalformedManifestElementIsStillAnElement() throws Exception {
        Path rep = report("malformed.jvm.json",
                List.of(entry("app.writes", List.of("Fs"), Map.of("paths", List.of("/tmp/x")))),
                List.of(Map.of("reason", "no `path` member at all")));
        Path pol = policy("deny Net app\n");

        assertEquals(2, run(rep, pol, "gate").exit(), "the gate reads it as incomplete");
        assertFalse(jsonOf(run(rep, pol, "unverified", "--json")).has("ok"),
                "so the advisory verb cannot be MORE certain: dropping the element would give a clean "
                + "advisory answer over a report the gate exits 2 on");
        assertEquals(2, run(rep, pol, "unverified", "--strict").exit());
        assertEquals(2, run(rep, pol, "fix-gate", "--strict").exit());
    }

    /**
     * …and over the report SET a PREFIX locator names, which is the set the gate reads. Two sibling
     * reports under one prefix, the manifest in the SECOND: {@code gate --report <prefix>} unions them and
     * exits 2, and an advisory verb reading only the lexicographically-first file would answer clean over
     * bytes the gate refused — the same relation, one resolution step out.
     */
    @Test
    void theManifestIsReadOverTheWholeReportSetALocatorNames() throws Exception {
        Path dir = tmp.resolve("set");
        Files.createDirectories(dir);
        Map<String, Object> envA = new LinkedHashMap<>();
        envA.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        envA.put("packages", List.of("app"));
        envA.put("analyzed", Map.of("count", 1, "digest", "0"));
        envA.put("functions", List.of(entry("app.writes", List.of("Fs"), Map.of("paths", List.of("/tmp/x")))));
        Files.writeString(dir.resolve("report.a.jvm.json"), io.poly.candor.model.ReportJson.pretty(envA));
        Map<String, Object> envB = new LinkedHashMap<>(envA);
        envB.put("unanalyzed", ONE_HOLE);
        envB.put("functions", List.of(entry("app.other", List.of("Fs"), Map.of("paths", List.of("/tmp/y")))));
        Files.writeString(dir.resolve("report.b.jvm.json"), io.poly.candor.model.ReportJson.pretty(envB));

        Path pol = policy("deny Net app\n");
        Path prefix = dir.resolve("report");
        assertEquals(2, run(prefix, pol, "gate").exit(),
                "the gate unions the set the locator names and finds the manifest in the second file");
        assertFalse(jsonOf(run(prefix, pol, "unverified", "--json")).has("ok"),
                "the advisory verb reads the SAME set — reading only report.a.jvm.json would certify over "
                + "bytes the gate refused");
        assertEquals(2, run(prefix, pol, "unverified", "--strict").exit());
        assertEquals(2, run(prefix, pol, "fix-gate", "--strict").exit());
    }

    // ── 6. ⟨0.28⟩ THE JUDGED-NOTHING CAUSE — SPEC §2's `analyzed.count: 0` row ──────────────────────────
    //
    // A ⟨0.21⟩ Row-1 report (`functions: []`, `analyzed.count: 0`) is "I judged NOTHING", not "I found
    // nothing" — and it carries no `unanalyzed` (there is no unread FILE to name), so the manifest-only
    // read above saw a complete report. MEASURED on the jar built before this rung, via candor-spec's
    // key-shape harvest (conformance/gen_key_shapes.py, 2026-08-12):
    //
    //     unverified --json   exit 0   {"ok": true, "unverified": []}   stdout: "… PROVABLY clean ✓"
    //     fix-gate   --json   exit 0   {"ok": true, "remedies":   []}   stdout: "no … crossings ✓"
    //
    // while this engine's OWN `where`/`map`/`blindspots` over the same bytes answered `incomplete: true`
    // + `judgedNothing` — and rust, ts and swift all hedge here. The wire form is SPEC §2 ⟨0.28⟩'s ("AND
    // HERE IS WHAT THE TRAVELLING CAVEAT IS CALLED"): `incomplete: true` + `judgedNothing` as an ARRAY of
    // report paths (never a boolean — ts shipped `true` and a consumer doing `.length` threw), each key
    // omitted when not applicable. The EXITS DO NOT MOVE: ⟨0.24⟩ ruled count-0 "a disclosure, not an exit
    // code" — `gate --report` exits 0 over a facade package, and a verb exiting 2 there would claim it
    // got LESS far than the gate on identical bytes.

    /** The ⟨0.21⟩ Row-1 artifact: nothing judged, nothing unanalyzed — the facade/`pub use` shape, and
     *  what a consumer holds after chaining a package whose scan reached no conclusion. */
    private Path judgedNothingReport() throws Exception {
        return report("facade.jvm.json", List.of(), null);
    }

    @Test
    void judgedNothingWithdrawsOkAndCarriesTheArrayCaveat() throws Exception {
        Path rep = judgedNothingReport();
        Path pol = policy("deny Net app\n");
        for (String verb : List.of("unverified", "fix-gate")) {
            Run r = run(rep, pol, verb, "--json");
            JsonObject doc = jsonOf(r);
            assertEquals(0, r.exit(), verb + ": count-0 is a disclosure, not an exit code (⟨0.24⟩)");
            assertFalse(doc.has("ok"), verb + " must not answer `ok` over a report that judged nothing — "
                    + "`true` is the false all-clear this rung closes, `false` asserts a finding nobody "
                    + "found: " + r.stdout());
            assertTrue(doc.has("incomplete") && doc.get("incomplete").getAsBoolean(),
                    verb + ": `incomplete: true` is the one flag every cause raises");
            assertTrue(doc.has("judgedNothing") && doc.get("judgedNothing").isJsonArray(),
                    verb + ": `judgedNothing` is an ARRAY of report paths, never a boolean (SPEC §2 ⟨0.28⟩)");
            assertTrue(doc.get("judgedNothing").getAsJsonArray().get(0).getAsString()
                            .endsWith("facade.jvm.json"),
                    verb + ": the array names WHICH report judged nothing — that is the actionable content");
            assertFalse(doc.has("unanalyzed"),
                    verb + ": no unread file to name here — the key is omitted when not applicable");
            assertEquals(0, run(rep, pol, verb, "--json", "--strict").exit(),
                    verb + " --strict: unchanged — a verb exiting non-zero here would claim it got LESS "
                    + "far than the gate over identical bytes");
        }
    }

    @Test
    void judgedNothingWithdrawsTheTickOnTheHumanChannel() throws Exception {
        Path rep = judgedNothingReport();
        Path pol = policy("deny Net app\n");
        Run uv = run(rep, pol, "unverified");
        assertEquals(0, uv.exit());
        assertFalse(uv.stdout().contains("PROVABLY clean (no Unknown holes) ✓"),
                "the tick IS the prose `ok: true` — it is withdrawn, not annotated: " + uv.stdout());
        assertTrue(uv.stderr().contains("JUDGED NOTHING"),
                "the human channel names the cause (the JSON-only mutant survived rust's whole suite)");
        Run fg = run(rep, pol, "fix-gate");
        assertEquals(0, fg.exit());
        assertFalse(fg.stdout().contains("no deny/pure boundary crossings in this report ✓"),
                "fix-gate's tick likewise: " + fg.stdout());
        assertTrue(fg.stderr().contains("JUDGED NOTHING"));
    }

    /** The BOTH-CAUSES artifact — what the ⟨0.28⟩ arming rung leaves on disk after a failed run:
     *  {@code analyzed.count: 0} AND a non-empty {@code unanalyzed}. Both arrays ride the document, and
     *  the {@code --strict} exit still moves — from the {@code unanalyzed} cause, exactly as before. */
    @Test
    void theArmedArtifactCarriesBothCausesAndKeepsItsStrictExit() throws Exception {
        Path rep = report("armed.jvm.json", List.of(), ONE_HOLE);
        Path pol = policy("deny Net app\n");
        Run r = run(rep, pol, "unverified", "--json");
        JsonObject doc = jsonOf(r);
        assertFalse(doc.has("ok"));
        assertTrue(doc.has("unanalyzed"), "the unread file is still named");
        assertTrue(doc.has("judgedNothing") && doc.get("judgedNothing").isJsonArray(),
                "…and the count-0 cause is no longer shadowed by it: the two want different repairs");
        assertEquals(0, r.exit());
        assertEquals(2, run(rep, pol, "unverified", "--json", "--strict").exit(),
                "--strict still exits 2 here — from the `unanalyzed` cause, unchanged by this rung");
    }
}
