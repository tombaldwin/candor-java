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
