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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.28⟩ SPEC §3.1 "AND HERE IS WHAT EACH LOCATOR FORM RESOLVES TO" — a PREFIX locator resolves to the
 * whole matching set, UNIONED, for every verb; a FILE locator to that file and its §2.2 sidecars, and
 * NEVER its prefix siblings.
 *
 * <p>MEASURED on the jar before this change, two sibling reports under one prefix, the Exec-performing
 * function in the (lexicographically) second:
 * <pre>
 *   where Exec --report <prefix> --json
 *     stderr: candor: locator `…` matches 2 reports; using <first>
 *     stdout: {"effect":"Exec","directly":[],"inherited":[]}                exit 0
 * </pre>
 * — "nothing performs Exec", over a locator that NAMES the report where something does. ⟨0.24⟩ ruled the
 * union for the gate and the advisory envelope; the descriptive verbs kept the pick-first, so one flag
 * carried two contracts and the quiet one under-reported by construction.
 */
class PrefixLocatorUnionTest {

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

    private Path report(String name, List<Map<String, Object>> entries) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", entries.size(), "digest", "0"));
        env.put("functions", entries);
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    /** Two sibling reports under prefix `r`: A carries an Fs function, B an Exec one. */
    private String twoSiblings() throws Exception {
        report("r.A.jvm.json", List.of(entry("a.Fs.write", List.of("Fs"))));
        report("r.B.jvm.json", List.of(entry("b.Exec.run", List.of("Exec"))));
        return tmp.resolve("r").toString();
    }

    private String[] run(String... args) {
        out.reset();
        err.reset();
        int rc = Query.run(args);
        return new String[]{out.toString(), err.toString(), String.valueOf(rc)};
    }

    @Test void whereOverAPrefixAnswersFromTheWholeSet() throws Exception {
        String prefix = twoSiblings();
        String[] r = run("where", "Exec", "--report", prefix, "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertEquals("b.Exec.run", o.getAsJsonArray("directly").get(0).getAsString(),
                "the Exec performer sits in the SECOND report of the set the locator names: " + r[0]);
        assertEquals("0", r[2]);
        assertTrue(r[1].contains("as one analysis world"),
                "…and the disclosure says the set is read whole, not which member won a sort: " + r[1]);
        assertFalse(r[1].contains("; using "),
                "the pick-first disclosure is GONE — there is no pick to disclose: " + r[1]);
    }

    @Test void mapOverAPrefixUnionsTheModules() throws Exception {
        String prefix = twoSiblings();
        String[] r = run("map", "--report", prefix, "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.has("a.Fs") && o.has("b.Exec"),
                "both siblings' classes are one analysis world: " + r[0]);
    }

    @Test void aFileLocatorNeverUnionsItsPrefixSiblings() throws Exception {
        // The mirror, and already-correct behaviour VERIFIED rather than changed: the operator named ONE
        // artifact, and `--report r.A.jvm.json` must not mean something different according to what else
        // sits in the directory.
        twoSiblings();
        String[] r = run("where", "Exec", "--report", tmp.resolve("r.A.jvm.json").toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertEquals(0, o.getAsJsonArray("directly").size(),
                "report A carries no Exec — the sibling is NOT read: " + r[0]);
        assertEquals(0, o.getAsJsonArray("inherited").size());
        assertEquals("0", r[2]);
    }

    @Test void callersOverAPrefixUnionsTheCallgraphSidecars() throws Exception {
        // The sidecars travel with the union: a graph anchored on the first member answers "no callers"
        // for every sibling's function — the under-report the old per-verb scoping note predicted.
        twoSiblings();
        Files.writeString(tmp.resolve("r.A.jvm.callgraph.json"), "{\"a.Fs.write\":[]}");
        Files.writeString(tmp.resolve("r.B.jvm.callgraph.json"),
                "{\"b.Exec.main\":[\"b.Exec.run\"],\"b.Exec.run\":[]}");
        String[] r = run("callers", "b.Exec.run", "--report", tmp.resolve("r").toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertEquals("b.Exec.main", o.getAsJsonArray("direct").get(0).getAsString(),
                "the caller is recorded in the SECOND member's sidecar: " + r[0]);
    }

    @Test void anUnreadableSiblingIsDisclosedAndTheAnswerHedged() throws Exception {
        report("r.A.jvm.json", List.of(entry("a.Fs.write", List.of("Fs"))));
        Files.writeString(tmp.resolve("r.B.jvm.json"), "{ \"candor\": { \"spec\": \"0.27\" }, \"functio");
        String[] r = run("where", "Fs", "--report", tmp.resolve("r").toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertEquals("a.Fs.write", o.getAsJsonArray("directly").get(0).getAsString(),
                "the readable member still answers — a partial answer that says it is partial "
                + "beats a refusal: " + r[0]);
        assertTrue(o.has("incomplete") && o.get("incomplete").getAsBoolean(),
                "…and the unreadable sibling hedges the document: " + r[0]);
        assertTrue(r[1].contains("cannot read report") && r[1].contains("INCOMPLETE"),
                "…disclosed on stderr: " + r[1]);
        assertEquals("0", r[2]);
    }

    @Test void aSingleUnreadableFileLocatorStillFailsLoud() throws Exception {
        // Byte-compatibility of the loud arm: a FILE locator naming one unreadable report has no sibling
        // to fall back to — the pre-⟨0.28⟩ exit 2 and message survive exactly.
        Path bad = tmp.resolve("solo.jvm.json");
        Files.writeString(bad, "not json");
        String[] r = run("where", "Fs", "--report", bad.toString(), "--json");
        assertEquals("2", r[2]);
        assertTrue(r[1].contains("candor: cannot read report " + bad),
                "the precise single-file diagnostic survives: " + r[1]);
        assertEquals("", r[0], "nothing on the machine channel");
    }

    @Test void advisoryVerbsAnswerHolesFromTheWholeSet() throws Exception {
        // ⟨0.24⟩ unioned the advisory ENVELOPE; the entries themselves still came from the first member,
        // so a hole in the second was invisible to the verb whose job is naming holes.
        report("r.A.jvm.json", List.of(entry("a.Fs.write", List.of("Fs"))));
        Map<String, Object> unk = entry("b.Dark.call", List.of("Unknown"));
        unk.put("unknownWhy", List.of("dispatch:b.Iface.m"));
        report("r.B.jvm.json", List.of(unk));
        Path pol = tmp.resolve("p.policy");
        Files.writeString(pol, "pure b\n");
        String[] r = run("unverified", "--report", tmp.resolve("r").toString(),
                "--policy", pol.toString(), "--json");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertEquals("b.Dark.call",
                o.getAsJsonArray("unverified").get(0).getAsJsonObject().get("fn").getAsString(),
                "the Unknown hole lives in the set's second member: " + r[0]);
    }
}
