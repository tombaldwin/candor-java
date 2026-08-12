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
 * shape cannot carry the travelling caveat MUST emit the CAVEAT DOCUMENT INSTEAD of its result document.
 * Not a result with the caveat omitted ({@code show}'s old answer: a flat {@code []} over a report whose
 * own manifest names a file it could not read), and not the caveat written into a user namespace
 * ({@code map}'s old answer: {@code incomplete} beside the operator's own class names, with a stderr
 * apology for any class literally named {@code incomplete} — the deferred collision the ruling rejects).
 *
 * <p>Plus the same rule one level up: an ADVISORY verb over a CONFIGURED policy that parsed to ZERO RULES
 * emits the caveat document with the result keys WITHHELD, exit UNCHANGED — measured pre-change as
 * {@code {"ok": true, "unverified": []}} exit 0, an empty result set certifying against a gate that asked
 * nothing.
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

    // ── show: the ARRAY shape had nowhere to put the caveat and answered [] flat ────────────────────────

    @Test void showHedgingEmitsTheCaveatDocumentInsteadOfAnArray() throws Exception {
        // The report CARRIES the queried function — the caveat still replaces the result, because a
        // consumer reading rows beside a hedge is still told the row set is the answer.
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

    @Test void mapHedgingWithholdsTheModuleRowsForTheCaveatDocument() throws Exception {
        Path rep = report("incmap.app.jvm.json", List.of(entry("app.repo.read", List.of("Fs"))), 7, MANIFEST);
        String[] r = run("map", "--report", rep.toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.get("incomplete").getAsBoolean(), "the caveat document: " + r[0]);
        assertFalse(o.has("app.repo"),
                "…INSTEAD of the module rows, not beside them — `map` is keyed by the user's own class "
                + "names, so a reserved key beside them is a deferred collision (an npm scope is spelled "
                + "`@scope/name`; a class can be named `incomplete`): " + r[0]);
        assertEquals(2, o.keySet().size(), "nothing but the caveat keys: " + r[0]);
        assertEquals("0", r[2]);
    }

    @Test void mapWithAClassNamedIncompleteNoLongerCollides() throws Exception {
        // The exact collision the old answer disclosed on stderr: a class literally named `incomplete`.
        // Now the hedging document contains ONLY caveat keys, so the class row is withheld WITH the rest
        // of the result — no displacement, no apology, and `incomplete` is unambiguously the boolean.
        Path rep = report("coll.app.jvm.json", List.of(entry("incomplete.read", List.of("Fs"))), 7, MANIFEST);
        String[] r = run("map", "--report", rep.toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.get("incomplete").isJsonPrimitive() && o.get("incomplete").getAsBoolean(),
                "`incomplete` is the disclosure boolean, never a class row: " + r[0]);
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
