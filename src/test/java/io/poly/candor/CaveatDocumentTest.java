package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
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
 * ⟨0.28⟩ SPEC §2 "AND HERE IS THAT RULING, AND IT IS ONE RULE, NOT ONE PER VERB" — a verb whose pinned
 * shape cannot carry the travelling caveat CHANGES SHAPE over a hedging report. Not a result with the
 * caveat omitted ({@code show}'s oldest answer: a flat {@code []} over a report whose own manifest names
 * a file it could not read), and not the caveat written into a user namespace ({@code map}'s oldest
 * answer: {@code incomplete} beside the operator's own class names, with a stderr apology for any class
 * literally named {@code incomplete} — the deferred collision the ruling rejects).
 *
 * <p>⟨0.32⟩ <b>AND WHAT THAT DOCUMENT CONTAINS WAS RULED AGAIN ON 2026-08-25: THE RESULT <i>AND</i> THE
 * WARNING.</b> Rung A's "the CAVEAT DOCUMENT INSTEAD of its result document" was written while the
 * trigger was a manifest a scan had FAILED to produce. ⟨0.32⟩'s unread-class cause then armed the same
 * substitution on nearly every no-policy report, and {@code show}/{@code map} answered
 * {@code {"incomplete": true}} with the answer gone. Both verbs are DESCRIPTIVE — they certify nothing —
 * so there is no claim for a pessimism rule to protect. The rows now ride under {@code functions} and the
 * class overview under {@code modules}, with the caveat keys at the root; the loud root-type change is
 * unchanged and the nesting removes {@code map}'s collision instead of deferring it.
 *
 * <p>Plus the same rule one level up, and it is on the OTHER side of the boundary: an ADVISORY verb over
 * a CONFIGURED policy that parsed to ZERO RULES emits the caveat document with the result keys WITHHELD,
 * exit UNCHANGED — measured pre-change as {@code {"ok": true, "unverified": []}} exit 0, an empty result
 * set certifying against a gate that asked nothing. Those verbs answer {@code ok}; these two do not, and
 * that difference is the whole boundary. See {@link #theVerbsThatAnswerOkStillRefuseOverAnUnreadClass}.
 */
class CaveatDocumentTest {

    @TempDir Path tmp;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private PrintStream priorOut, priorErr;

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

    private String[] run(String... args) {
        out.reset();
        err.reset();
        int rc = Query.run(args);
        return new String[]{out.toString(), err.toString(), String.valueOf(rc)};
    }

    /** A report whose {@code excluded} names a class the producing scan never OPENED — ⟨0.32⟩'s
     *  {@code peeked: false} with no {@code judgedElsewhere}, the fixture the descriptive-hedge ruling
     *  was measured on. */
    private Path unreadReport(String name) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", 7, "digest", "0"));
        env.put("excluded", List.of(Map.of("class", "generated-source", "count", 1,
                                           "peeked", false, "reason", "generated")));
        env.put("functions", List.of(entry("app.repo.read", List.of("Fs"))));
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    // ── ⟨0.32⟩ THE DESCRIPTIVE/CERTIFYING BOUNDARY, CONTROLLED ─────────────────────────────────────────

    /**
     * ⟨0.32⟩ **THE CONTROL FOR THE BOUNDARY — written BEFORE the Rung A change that made {@code show} and
     * {@code map} return their result BESIDE the caveat, and unchanged by it.** The direction that must
     * NOT move is this one: a verb that answers {@code ok} still REFUSES over a report whose
     * {@code excluded} names a class nothing opened. Getting it wrong in that direction re-opens the
     * cardinal sin; both arms are pinned by conformance PARTs 62 and 67.
     *
     * <p>The descriptive half is asserted here too, because that is what makes this a BOUNDARY rather
     * than a blanket: {@code show}/{@code map} hedge and their exit code does not move.
     */
    @Test void theVerbsThatAnswerOkStillRefuseOverAnUnreadClass() throws Exception {
        Path rep = unreadReport("unread.app.jvm.json");
        Path pol = tmp.resolve("deny.policy");
        Files.writeString(pol, "deny Exec\n");

        String[] g = run("gate", "--report", rep.toString(), "--policy", pol.toString(), "--json");
        assertEquals("2", g[2], "the gate REFUSES over a class nothing opened: " + g[0] + g[1]);
        JsonObject gv = JsonParser.parseString(g[0].substring(g[0].indexOf('{'))).getAsJsonObject();
        assertFalse(gv.get("ok").getAsBoolean(), "…with ok:false: " + g[0]);
        assertTrue(gv.get("incomplete").getAsBoolean(), "…and incomplete:true: " + g[0]);

        for (String v : List.of("unverified", "fix-gate")) {
            String[] a = run(v, "--strict", "--report", rep.toString(), "--policy", pol.toString(), "--json");
            assertEquals("2", a[2], v + ": an advisory verb must never be LESS sensitive than the gate "
                    + "over the same bytes: " + a[0] + a[1]);
            JsonObject av = JsonParser.parseString(a[0].substring(a[0].indexOf('{'))).getAsJsonObject();
            assertFalse(av.has("ok"), v + ": `ok` is OMITTED, never falsified (⟨0.24⟩): " + a[0]);
            assertTrue(av.get("incomplete").getAsBoolean(), v + ": " + a[0]);
        }

        for (String[] argv : List.of(new String[]{"show", "app.repo.read"}, new String[]{"map"})) {
            String[] d = argv.length == 2
                    ? run(argv[0], argv[1], "--report", rep.toString(), "--json")
                    : run(argv[0], "--report", rep.toString(), "--json");
            assertEquals("0", d[2], argv[0] + ": a descriptive verb's hedge is a DISCLOSURE, not an exit "
                    + "code: " + d[0] + d[1]);
            JsonObject dv = JsonParser.parseString(d[0]).getAsJsonObject();
            assertTrue(dv.get("incomplete").getAsBoolean(),
                    argv[0] + ": the hedge must still appear over an unread class: " + d[0]);
        }
    }

    /** A three-method chain ({@code app.web.top -> app.svc.wrapper -> app.repo.read}, the last the Fs
     *  source) so {@code callers}/{@code impact}/{@code path} have a real graph to answer over. The
     *  {@code excluded} class is UNREAD or READ per {@code peeked}, which is the only difference between
     *  the defect fixture and its control. */
    private Path chainReport(String name, boolean peeked) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", 7, "digest", "0"));
        env.put("excluded", List.of(Map.of("class", "generated-source", "count", 1,
                                           "peeked", peeked, "reason", "generated")));
        Map<String, Object> read = new LinkedHashMap<>(entry("app.repo.read", List.of("Fs")));
        Map<String, Object> wrap = new LinkedHashMap<>(entry("app.svc.wrapper", List.of("Fs")));
        wrap.put("direct", List.of());
        wrap.put("calls", List.of("app.repo.read"));
        Map<String, Object> top = new LinkedHashMap<>(entry("app.web.top", List.of("Fs")));
        top.put("direct", List.of());
        top.put("calls", List.of("app.svc.wrapper"));
        env.put("functions", List.of(read, wrap, top));
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    /**
     * ⟨0.32⟩ <b>THE SILENT HALF OF THE SAME CLASS: {@code callers}, {@code impact} AND {@code path}
     * CARRIED NO COMPLETENESS READER AT ALL.</b> {@code show}/{@code map} OVER-hedged (the caveat replaced
     * the data, ruled the other way in {@link #showHedgingKeepsItsRowsBesideTheCaveat}); these three
     * UNDER-hedged — over a report whose own {@code excluded} names a class the producing scan never
     * opened they answered FLAT, at exit 0, with no disclosure on the machine channel and none on the
     * human one. MEASURED at HEAD 2026-08-25 on the fixture below, and reproduced identically in
     * candor-rust and candor-ts (and on candor-ts's MCP tools, where the reader is an agent):
     *
     * <pre>
     *   callers app.svc.wrapper --json  {"of":[…],"direct":["app.web.top"],"transitive":[…]}  no caveat
     *   impact  app.svc.wrapper --json  {"fn":…,"affectedCount":1,"affected":[…],…}           no caveat
     *   path    app.web.top Fs  --json  {"fn":…,"effect":"Fs","path":[…3 steps…]}             no caveat
     * </pre>
     *
     * <p>The ⟨0.28⟩ rung that widened SPEC §2's re-disclosure MUST to <i>"any verb whose output could be
     * read as a NEGATIVE FINDING about the code — a verdict, an empty result set, or a zero count"</i>
     * enumerated six verbs and skipped these three. An empty {@code direct} is <i>nothing calls this</i>;
     * an {@code affectedCount: 0} is <i>safe to edit</i>; an empty {@code path} is <i>this method does not
     * reach that effect</i>.
     *
     * <p>The boundary is UNMOVED — the verbs that answer {@code ok} still refuse over these same bytes,
     * pinned by {@link #theVerbsThatAnswerOkStillRefuseOverAnUnreadClass} and conformance PARTs 62 and 67.
     *
     * <p>Every assertion is on the ROW NAMES and COUNTS, never on key presence: a hedge that shipped an
     * empty answer would pass "the key exists" while deleting the feature.
     */
    @Test void callersImpactAndPathDiscloseAnUnreadClassBesideTheirAnswer() throws Exception {
        Path rep = chainReport("cip.app.jvm.json", false);

        String[] c = run("callers", "app.svc.wrapper", "--report", rep.toString(), "--json");
        assertEquals("0", c[2], "a descriptive verb's hedge is a DISCLOSURE, not an exit code: " + c[0] + c[1]);
        JsonObject cv = JsonParser.parseString(c[0]).getAsJsonObject();
        assertTrue(cv.get("incomplete").getAsBoolean(), "callers answered flat: " + c[0]);
        assertEquals(1, cv.getAsJsonArray("direct").size(), c[0]);
        assertEquals("app.web.top", cv.getAsJsonArray("direct").get(0).getAsString(),
                "…BESIDE the answer, never instead of it — the direct callers by NAME: " + c[0]);
        assertEquals("app.web.top", cv.getAsJsonArray("transitive").get(0).getAsString(), c[0]);

        // The `--include-unknown` frontier arm shares one helper with the plain arm here, unlike the rust
        // reference where it is a SECOND function — driven anyway, because "shares a helper" is a claim
        // about the code and this row is the measurement.
        String[] cu = run("callers", "app.svc.wrapper", "--report", rep.toString(), "--json", "--include-unknown");
        JsonObject cuv = JsonParser.parseString(cu[0]).getAsJsonObject();
        assertTrue(cuv.get("incomplete").getAsBoolean(), "--include-unknown must disclose too: " + cu[0]);
        assertEquals("app.web.top", cuv.getAsJsonArray("direct").get(0).getAsString(), cu[0]);

        String[] i = run("impact", "app.svc.wrapper", "--report", rep.toString(), "--json");
        assertEquals("0", i[2], i[0] + i[1]);
        JsonObject iv = JsonParser.parseString(i[0]).getAsJsonObject();
        assertTrue(iv.get("incomplete").getAsBoolean(), "impact answered flat: " + i[0]);
        assertEquals(1, iv.get("affectedCount").getAsInt(), i[0]);
        assertEquals("app.web.top", iv.getAsJsonArray("affected").get(0).getAsString(),
                "…and the blast radius survives the hedge, by NAME: " + i[0]);

        String[] p = run("path", "app.web.top", "Fs", "--report", rep.toString(), "--json");
        assertEquals("0", p[2], p[0] + p[1]);
        JsonObject pv = JsonParser.parseString(p[0]).getAsJsonObject();
        assertTrue(pv.get("incomplete").getAsBoolean(), "path answered flat: " + p[0]);
        List<String> chain = new ArrayList<>();
        pv.getAsJsonArray("path").forEach(s -> chain.add(s.getAsJsonObject().get("fn").getAsString()));
        assertEquals(List.of("app.web.top", "app.svc.wrapper", "app.repo.read"), chain,
                "…and the WHOLE chain is still there, in order: " + p[0]);

        // `path`'s EMPTY-answer arm is a SEPARATE emit site and the sharpest cell here: `path: []` is
        // *this method does not reach that effect*, the precise reassurance a reader asks `path` for.
        String[] pe = run("path", "app.web.top", "Net", "--report", rep.toString(), "--json");
        assertEquals("0", pe[2], pe[0] + pe[1]);
        JsonObject pev = JsonParser.parseString(pe[0]).getAsJsonObject();
        assertTrue(pev.get("incomplete").getAsBoolean(),
                "an empty `path` over an unread class is a determined negative and must hedge: " + pe[0]);
        assertEquals(0, pev.getAsJsonArray("path").size(), pe[0]);

        // THE HUMAN CHANNEL, asserted separately because a mutant that keeps the whole JSON fix and
        // deletes the printed line survives every absence-assert on the document (candor-spec `ec1a441`).
        for (String[] argv : List.of(new String[]{"callers", "app.svc.wrapper"},
                                     new String[]{"impact", "app.svc.wrapper"},
                                     new String[]{"path", "app.web.top", "Fs"})) {
            String[] h = argv.length == 3
                    ? run(argv[0], argv[1], argv[2], "--report", rep.toString())
                    : run(argv[0], argv[1], "--report", rep.toString());
            assertTrue(h[0].contains("⚠ INCOMPLETE") && h[0].contains("generated-source"),
                    argv[0] + ": the prose channel must carry the note ON STDOUT and NAME the class: " + h[0]);
        }

        // ── THE INTACT CONTROL: the SAME fixture with `peeked: true` — the class was READ, so there is
        //    nothing to disclose. Without it every row above passes just as well from a verb that hedges
        //    unconditionally, which makes every ordinary answer read as partial.
        Path ok = chainReport("cipok.app.jvm.json", true);
        for (String[] argv : List.of(new String[]{"callers", "app.svc.wrapper"},
                                     new String[]{"impact", "app.svc.wrapper"},
                                     new String[]{"path", "app.web.top", "Fs"})) {
            String[] j = argv.length == 3
                    ? run(argv[0], argv[1], argv[2], "--report", ok.toString(), "--json")
                    : run(argv[0], argv[1], "--report", ok.toString(), "--json");
            assertEquals("0", j[2], argv[0] + ": " + j[0] + j[1]);
            JsonObject v = JsonParser.parseString(j[0]).getAsJsonObject();
            assertFalse(v.has("incomplete"), argv[0] + ": a complete report gains NO caveat key: " + j[0]);
            for (String k : v.keySet())
                assertTrue(List.of("of", "direct", "transitive", "possibleViaUnknownDispatch", "fn",
                                   "affectedCount", "affected", "entryPoints", "effect", "path", "note")
                                .contains(k),
                        argv[0] + ": the healthy document keeps its pinned key set exactly, got `" + k
                                + "`: " + j[0]);
            String[] h = argv.length == 3
                    ? run(argv[0], argv[1], argv[2], "--report", ok.toString())
                    : run(argv[0], argv[1], "--report", ok.toString());
            assertFalse(h[0].contains("INCOMPLETE"), argv[0] + ": healthy prose gains no note: " + h[0]);
        }
    }

    // ── R54 (SOUNDNESS.md): `diff` reads TWO locators that fail in OPPOSITE directions ─────────────────

    /** A current+baseline pair for `diff`, one function gaining {@code Fs}. `curUnread`/`baseUnread`
     *  independently control whether EACH SIDE carries an ⟨0.32⟩ unpeeked exclusion class — R54's point is
     *  that the two fail in opposite directions and must be disclosed (and tested) separately, never
     *  collapsed into one flag. */
    private Path[] diffPair(String tag, boolean curUnread, boolean baseUnread, boolean sameEffects)
            throws Exception {
        List<Map<String, Object>> unread = List.of(Map.of("class", "generated-source", "count", 1,
                "peeked", false, "reason", "generated"));
        Map<String, Object> cur = new LinkedHashMap<>();
        cur.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        cur.put("packages", List.of("app"));
        cur.put("analyzed", Map.of("count", 3, "digest", "0"));
        if (curUnread) cur.put("excluded", unread);
        cur.put("functions", List.of(entry("app.svc.act", List.of("Fs"))));
        Path curP = tmp.resolve("cur." + tag + ".app.jvm.json");
        Files.writeString(curP, io.poly.candor.model.ReportJson.pretty(cur));

        Map<String, Object> base = new LinkedHashMap<>();
        base.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        base.put("packages", List.of("app"));
        base.put("analyzed", Map.of("count", 3, "digest", "0"));
        if (baseUnread) base.put("excluded", unread);
        // `sameEffects`: the baseline already has Fs too, so `changes` comes back EMPTY — the sharpest
        // cell, because "no effect changes" is the determined negative this rung withdraws.
        base.put("functions", List.of(entry("app.svc.act", sameEffects ? List.of("Fs") : List.of())));
        Path baseP = tmp.resolve("base." + tag + ".app.jvm.json");
        Files.writeString(baseP, io.poly.candor.model.ReportJson.pretty(base));
        return new Path[]{curP, baseP};
    }

    /**
     * ⟨R54⟩ <b>`diff` ANSWERS `{ baseline_version, engine_version, changes: [] }` WITH NO COMPLETENESS
     * READER AT ALL</b> (SOUNDNESS.md R54) — over TWO reports that fail in OPPOSITE directions: an unread
     * unit in the CURRENT tree can hide a real gain from {@code changes}; one in the BASELINE tree can
     * make a longstanding effect read as newly gained. MEASURED at HEAD before this fix, on exactly this
     * fixture: {@code diff} answered flat on both channels, at exit 0/1, while its sibling {@code gains}
     * already hedges both sides (the PREFIXED shape this test pins {@code diff} onto instead of a fourth
     * spelling).
     *
     * <p>Every JSON assertion is on the CHANGES themselves (by function name), never on key presence alone
     * — a hedge that shipped a flat answer would still pass "the key exists".
     */
    @Test void diffDisclosesEachUnreadSideSeparately() throws Exception {
        // Cause: the CURRENT side unread, baseline intact.
        Path[] curSide = diffPair("cur", true, false, false);
        String[] c = run("diff", curSide[0].toString(), curSide[1].toString(), "--json");
        assertEquals("1", c[2], "the gain-ratchet exit is UNCHANGED by the hedge (diff has no exit-code "
                + "obligation — SOUNDNESS.md's own ⟨0.32⟩ descriptive test): " + c[0] + c[1]);
        JsonObject cv = JsonParser.parseString(c[0]).getAsJsonObject();
        assertTrue(cv.get("incomplete").getAsBoolean(), "diff answered flat over an unread CURRENT class: " + c[0]);
        assertFalse(cv.has("baselineIncomplete"), "the baseline side is intact and must stay unflagged: " + c[0]);
        assertEquals(1, cv.getAsJsonArray("changes").size(),
                "…BESIDE the answer, never instead of it: " + c[0]);
        assertEquals("app.svc.act",
                cv.getAsJsonArray("changes").get(0).getAsJsonObject().get("fn").getAsString(), c[0]);

        // Cause: the BASELINE side unread, current intact — the OTHER prefix, and it must be THIS one, not
        // the bare `incomplete` a single-flag design could not tell apart from the case above.
        Path[] baseSide = diffPair("base", false, true, false);
        String[] b = run("diff", baseSide[0].toString(), baseSide[1].toString(), "--json");
        JsonObject bv = JsonParser.parseString(b[0]).getAsJsonObject();
        assertFalse(bv.has("incomplete"), "the current side is intact and must stay unflagged: " + b[0]);
        assertTrue(bv.get("baselineIncomplete").getAsBoolean(),
                "diff answered flat over an unread BASELINE class: " + b[0]);
        assertEquals(1, bv.getAsJsonArray("changes").size(), b[0]);

        // Cause: BOTH sides unread — both flags present, INDEPENDENTLY (not collapsed into one).
        Path[] bothSide = diffPair("both", true, true, false);
        String[] both = run("diff", bothSide[0].toString(), bothSide[1].toString(), "--json");
        JsonObject bo = JsonParser.parseString(both[0]).getAsJsonObject();
        assertTrue(bo.get("incomplete").getAsBoolean(), both[0]);
        assertTrue(bo.get("baselineIncomplete").getAsBoolean(), both[0]);

        // THE SHARPEST CELL: `changes: []` over an unread side is `nothing about this codebase's effects
        // changed`, asserted from two reports nobody fully read — the determined negative this rung
        // withdraws, on the human channel (the JSON `changes` array is already empty by construction, so
        // JSON has nothing further to withdraw — only the prose sentence changes).
        Path[] emptySide = diffPair("empty", true, true, true);
        String[] eh = run("diff", emptySide[0].toString(), emptySide[1].toString());
        assertTrue(eh[0].contains("IN WHAT CANDOR COULD SEE") && eh[0].contains("NOT \"nothing changed\""),
                "the flat \"no effect changes\" sentence must be WITHDRAWN, not left standing under the "
                        + "note: " + eh[0]);
        assertTrue(eh[0].contains("⚠ INCOMPLETE") && eh[0].contains("CURRENT")
                        && eh[0].contains("⚠ INCOMPLETE") && eh[0].contains("BASELINE"),
                "both sides get their OWN note, never combined into one sentence: " + eh[0]);
        assertTrue(eh[0].contains("generated-source"), "…and each note names the class: " + eh[0]);
        String[] ej = run("diff", emptySide[0].toString(), emptySide[1].toString(), "--json");
        JsonObject ejv = JsonParser.parseString(ej[0]).getAsJsonObject();
        assertTrue(ejv.get("incomplete").getAsBoolean() && ejv.get("baselineIncomplete").getAsBoolean(), ej[0]);
        assertEquals(0, ejv.getAsJsonArray("changes").size(), ej[0]);

        // THE HUMAN CHANNEL on the non-empty cell too, because a mutant that keeps the JSON fix and drops
        // only the printed note survives every JSON-only assertion above (candor-spec `ec1a441`'s shape).
        String[] ch = run("diff", curSide[0].toString(), curSide[1].toString());
        assertTrue(ch[0].contains("⚠ INCOMPLETE") && ch[0].contains("CURRENT") && ch[0].contains("generated-source"),
                "the prose channel must carry the note ON STDOUT, name the SIDE and the class: " + ch[0]);

        // ── THE INTACT CONTROL: NEITHER side carries an unread class — nothing to disclose. Without it
        //    every row above would pass just as well from a `diff` that hedges unconditionally, which
        //    makes every ordinary diff read as partial.
        Path[] ok = diffPair("ok", false, false, false);
        String[] okJson = run("diff", ok[0].toString(), ok[1].toString(), "--json");
        assertEquals("1", okJson[2], okJson[0] + okJson[1]);
        JsonObject okv = JsonParser.parseString(okJson[0]).getAsJsonObject();
        assertFalse(okv.has("incomplete") || okv.has("baselineIncomplete"),
                "a complete pair gains NO caveat key on EITHER side: " + okJson[0]);
        for (String k : okv.keySet())
            assertTrue(List.of("baseline_version", "engine_version", "changes").contains(k),
                    "the healthy document keeps its pinned key set exactly, got `" + k + "`: " + okJson[0]);
        String[] okHuman = run("diff", ok[0].toString(), ok[1].toString());
        assertFalse(okHuman[0].contains("INCOMPLETE"), "healthy prose gains no note: " + okHuman[0]);
    }

    // ── show: the ARRAY shape had nowhere to put the caveat and answered [] flat ────────────────────────

    @Test void showHedgingKeepsItsRowsBesideTheCaveat() throws Exception {
        Path rep = report("inc.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, MANIFEST);
        String[] r = run("show", "app.repo.read", "--report", rep.toString(), "--json");
        JsonElement doc = JsonParser.parseString(r[0]);
        assertTrue(doc.isJsonObject(),
                "the type change is LOUD on purpose — an object where the healthy answer is an array, so a "
                + "`for (const x of doc)` consumer throws instead of silently iterating zero rows: " + r[0]);
        JsonObject o = doc.getAsJsonObject();
        assertTrue(o.get("incomplete").getAsBoolean());
        assertEquals("app/Unread.java",
                o.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().get("path").getAsString());
        assertEquals("0", r[2], "a disclosure, not an exit code");
        // ⟨0.32⟩ THE DEFECT ASSERTION: the ANSWER is still here. Asserted as the ROW and its NAME, not
        // merely as "the key exists" — the safe-looking empty array passes a presence check while
        // deleting exactly what the ruling restored. `show` certifies nothing, so withholding its rows
        // protected no claim; it only cost the reader the answer.
        assertEquals(1, o.getAsJsonArray("functions").size(), "the rows ride BESIDE the caveat: " + r[0]);
        assertEquals("app.repo.read",
                o.getAsJsonArray("functions").get(0).getAsJsonObject().get("fn").getAsString(), r[0]);
    }

    @Test void showHealthyIsByteIdenticalAndShowHumanGainsTheNote() throws Exception {
        Path rep = report("ok.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, List.of());
        String[] r = run("show", "app.repo.read", "--report", rep.toString(), "--json");
        assertEquals("[\n  {\n    \"fn\": \"app.repo.read\",\n    \"inferred\": [\n      \"Fs\"\n    ],\n"
                + "    \"direct\": [\n      \"Fs\"\n    ],\n    \"unresolved\": false\n  }\n]\n", r[0],
                "healthy output byte-identical — the property every engine measured for this rung");
        Path inc = report("inc2.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, MANIFEST);
        String[] h = run("show", "app.repo.read", "--report", inc.toString());
        assertTrue(h[0].contains("⚠ INCOMPLETE"), "the human channel carries the same hedge: " + h[0]);
    }

    // ── map: the USER-NAMESPACE shape must not carry a reserved key beside real class names ─────────────

    @Test void mapHedgingNestsItsModuleRowsBesideTheCaveat() throws Exception {
        Path rep = report("incmap.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, MANIFEST);
        String[] r = run("map", "--report", rep.toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.get("incomplete").getAsBoolean(), "the caveat rides the document: " + r[0]);
        assertFalse(o.has("app.repo"),
                "…and NOT at the root beside the caveat — `map` is keyed by the user's own class names, "
                + "so a reserved key at that level is a deferred collision (an npm scope is spelled "
                + "`@scope/name`; a class can be named `incomplete`): " + r[0]);
        // ⟨0.32⟩ THE DEFECT ASSERTION: the overview is still here, one level down, where the class
        // namespace cannot collide with the caveat vocabulary. `map` certifies nothing.
        assertTrue(o.getAsJsonObject("modules").has("app.repo"),
                "the module rows ride BESIDE the caveat, under `modules`: " + r[0]);
        // The ROOT vocabulary is closed, asserted as a SET rather than a count: the property is that no
        // user class name can appear there, and a count passes just as well when one has replaced a
        // caveat key. `modules` + the ⟨0.28⟩ caveat vocabulary, nothing else.
        assertTrue(List.of("modules", "incomplete", "unanalyzed", "judgedNothing", "noManifest", "unread")
                        .containsAll(o.keySet()),
                "the root carries `modules` + the caveat vocabulary and nothing else: " + r[0]);
        assertEquals("0", r[2]);
    }

    @Test void mapWithAClassNamedIncompleteNoLongerCollides() throws Exception {
        // The exact collision the old answer disclosed on stderr: a class literally named `incomplete`.
        // ⟨0.32⟩ the class row is now a key of `modules` and the boolean a key of the root, so neither can
        // displace the other — no apology, no dropped row, and no withheld answer either.
        Path rep = report("coll.app.jvm.json", List.of(entry("incomplete.read", List.of("Fs"))), 7, MANIFEST);
        String[] r = run("map", "--report", rep.toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.get("incomplete").isJsonPrimitive() && o.get("incomplete").getAsBoolean(),
                "`incomplete` is the disclosure boolean, never a class row: " + r[0]);
        assertTrue(o.getAsJsonObject("modules").get("incomplete").isJsonObject(),
                "…and the class named `incomplete` KEEPS its row, one level down: " + r[0]);
        assertEquals("", r[1].replaceAll("(?m)^candor: locator.*$", "").trim(),
                "no collision apology remains — there is nothing to collide with");
        // …and on a HEALTHY report the class named `incomplete` is an ordinary row (the mirror).
        Path okRep = report("coll2.app.jvm.json", List.of(entry("incomplete.read", List.of("Fs"))), 7, List.of());
        JsonObject ok = JsonParser.parseString(run("map", "--report", okRep.toString(), "--json")[0]).getAsJsonObject();
        assertTrue(ok.get("incomplete").isJsonObject(), "healthy: the operator's class keeps its name");
    }

    // ── the advisory verbs over a ZERO-RULE policy ──────────────────────────────────────────────────────

    @Test void advisoryVerbsOverAZeroRulePolicyEmitTheCaveatAndWithholdResults() throws Exception {
        Path rep = report("zr.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, List.of());
        // whatif resolves its target over the callgraph sidecar and refuses without one — stage it.
        Files.writeString(tmp.resolve("zr.app.jvm.callgraph.json"), "{\"app.repo.read\":[]}");
        Path pol = tmp.resolve("empty.policy");
        Files.writeString(pol, "# no rules yet\n\n# still none\n");
        record Case(String[] argv, String resultKey) {}
        List<Case> cases = List.of(
                new Case(new String[]{"unverified", "--report", rep.toString(), "--policy", pol.toString(), "--json"}, "unverified"),
                new Case(new String[]{"fix-gate", "--report", rep.toString(), "--policy", pol.toString(), "--json"}, "remedies"),
                new Case(new String[]{"whatif", "app.repo.read", "Net", "--report", rep.toString(), "--policy", pol.toString(), "--json"}, "violations"));
        for (Case c : cases) {
            String[] r = run(c.argv());
            JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
            String who = c.argv()[0];
            assertFalse(o.has("ok"), "`" + who + "` must make NO claim over a policy that asked nothing: " + r[0]);
            assertFalse(o.has(c.resultKey()),
                    "`" + who + "` must WITHHOLD `" + c.resultKey() + "` — an empty result over a zero-rule "
                    + "policy is the refusal-document-with-violations defect one level up: " + r[0]);
            assertTrue(o.get("unevaluated").getAsJsonArray().get(0).getAsJsonObject()
                            .get("rule").getAsString().contains("entire policy"),
                    "…the caveat names the WHOLE policy, the §3.1 shape the gate's refusal already uses: " + r[0]);
            assertEquals("0", r[2], "the exit is UNCHANGED — this is a disclosure, not the gate's refusal");
        }
    }

    @Test void theZeroRuleExitIsUnchangedUnderStrictToo() throws Exception {
        // Measured pre-change: `unverified --strict` exits 0 over a zero-rule policy. The clause pins the
        // exit UNCHANGED and deliberately rejects the gate's refusal posture for the advisory verbs.
        Path rep = report("zrs.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, List.of());
        Path pol = tmp.resolve("empty2.policy");
        Files.writeString(pol, "# nothing\n");
        for (String verb : List.of("unverified", "fix-gate")) {
            String[] r = run(verb, "--strict", "--report", rep.toString(), "--policy", pol.toString(), "--json");
            assertEquals("0", r[2], "`" + verb + " --strict` exit UNCHANGED over a zero-rule policy");
        }
    }

    @Test void theZeroRuleHumanChannelWithdrawsTheTick() throws Exception {
        Path rep = report("zrh.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, List.of());
        Path pol = tmp.resolve("empty3.policy");
        Files.writeString(pol, "# no rules\n");
        String[] r = run("unverified", "--report", rep.toString(), "--policy", pol.toString());
        assertFalse(r[0].contains("PROVABLY clean"),
                "the tick is the prose `ok: true` and is WITHDRAWN, not annotated: " + r[0]);
        assertTrue(r[0].contains("NOT an all-clear"), "…replaced by the caveat: " + r[0]);
        assertTrue(r[1].contains("yielded NO RULES"), "stderr names the cause and the remedy: " + r[1]);
    }

    @Test void aRealPolicyStillAnswersNormally() throws Exception {
        // Control: one real rule beside comments is NOT zero rules — the ordinary answer survives.
        Path rep = report("ctl.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, List.of());
        Path pol = tmp.resolve("real.policy");
        Files.writeString(pol, "# a comment\ndeny Net app\n");
        String[] r = run("unverified", "--report", rep.toString(), "--policy", pol.toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.has("ok") && o.get("ok").getAsBoolean(), "an answerable policy answers: " + r[0]);
        assertTrue(o.has("unverified"), "…with its result key: " + r[0]);
        assertEquals("0", r[2]);
    }
}
