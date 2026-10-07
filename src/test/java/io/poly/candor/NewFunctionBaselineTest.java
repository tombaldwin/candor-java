package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * SPEC §3 baseline guard ⟨0.40⟩ (SOUNDNESS R932) — a function ABSENT from a present baseline is compared
 * against ∅, not exempted as "new code". The four cells are PART 15d's n1–n4, with the SAME `q.G` fixtures
 * the conformance suite compiles, driven through the real CLI with `--gate-json`:
 * <ul>
 *   <li>n1 — a new `fresh()` doing Net: exit 1, an AS-EFF-005 row {fn, effects:[Net], origin:"new"}, and the
 *       message says the function is ABSENT FROM THE BASELINE (not that it "gained").</li>
 *   <li>n2 — a new PURE `tidy()`: exit 0, no AS-EFF-005 (the control: a guard that fires on every absent key
 *       fails here).</li>
 *   <li>n3 — a new Unknown-only `opaquenew()`: exit 0, no AS-EFF-005, but NAMED in the note.</li>
 *   <li>n4 — an existing `keep()` gaining Net: exit 1, origin:"existing".</li>
 * </ul>
 * Plus PART 15b's `absent` arm: the sidecar removed, a new effectful function still fires, labelled
 * origin:"unknown"; and a whole baseline FILE absent keeps its note-and-exit-0 posture.
 */
class NewFunctionBaselineTest {

    @TempDir Path tmp;

    private record Run(int exit, String stdout, String stderr) {}

    private static Run cli(Map<String, String> env, String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().keySet().removeIf(k -> k.startsWith("CANDOR_"));
        pb.environment().putAll(env);
        Process p = pb.start();
        java.util.concurrent.CompletableFuture<String> out =
                java.util.concurrent.CompletableFuture.supplyAsync(() -> drain(p.getInputStream()));
        String err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out.get(), err);
    }

    private static String drain(InputStream in) {
        try { ByteArrayOutputStream b = new ByteArrayOutputStream(); in.transferTo(b); return b.toString(); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    private static final String KEEP =
            " static void keep() throws Exception { java.nio.file.Files.readString(java.nio.file.Path.of(\"/x\")); }";

    private Path classes(String name, String body) throws Exception {
        return TestCompiler.compile(Map.of("q/G.java", "package q;\npublic class G {\n" + body + "\n}\n"));
    }

    /** The baseline: `keep` (Fs), scanned by THIS build, sidecar beside it. */
    private Path baseline() throws Exception {
        Path base = tmp.resolve("base.json");
        Run r = cli(Map.of(), classes("base", KEEP).toString(), "--json", base.toString());
        assertEquals(0, r.exit(), r.stderr());
        assertTrue(Files.exists(tmp.resolve("base.callgraph.json")), "baseline sidecar written");
        return base;
    }

    private Run gate(Path base, Path cls, Path gateJson) throws Exception {
        return cli(Map.of("CANDOR_BASELINE", base.toString()), cls.toString(),
                "--json", tmp.resolve("after-" + gateJson.getFileName()).toString(), "--gate-json", gateJson.toString());
    }

    private static List<JsonObject> rows005(Path gateJson, String leaf) throws Exception {
        List<JsonObject> out = new ArrayList<>();
        JsonArray vs = JsonParser.parseString(Files.readString(gateJson)).getAsJsonObject().getAsJsonArray("violations");
        for (JsonElement e : vs) {
            JsonObject o = e.getAsJsonObject();
            if (o.get("rule").getAsString().equals("AS-EFF-005") && o.get("fn").getAsString().endsWith("." + leaf)) out.add(o);
        }
        return out;
    }

    @Test
    void n1_aNewEffectfulFunctionFiresWithOriginNew() throws Exception {
        Path base = baseline();
        Path gj = tmp.resolve("n1.gate.json");
        Run r = gate(base, classes("n1", KEEP + "\n static void fresh() throws Exception { new java.net.Socket(\"h\", 80); }"), gj);
        assertEquals(1, r.exit(), "a new function doing Net is a gain against ∅\n" + r.stderr() + r.stdout());
        String all = r.stdout() + r.stderr();
        assertTrue(all.contains("[AS-EFF-005]"), all);
        List<JsonObject> g = rows005(gj, "fresh");
        assertEquals(1, g.size(), "one AS-EFF-005 row for fresh: " + Files.readString(gj));
        assertEquals("[\"Net\"]", g.get(0).get("effects").toString());
        assertEquals("new", g.get(0).get("origin").getAsString());
        assertTrue(all.contains("absent from the baseline"), "the message says ABSENT, not gained: " + all);
        assertTrue(all.contains("candor diff "), "the remedy leads with review: " + all);
    }

    @Test
    void n2_aNewPureFunctionPasses() throws Exception {
        Path base = baseline();
        Path gj = tmp.resolve("n2.gate.json");
        Run r = gate(base, classes("n2", KEEP + "\n static int tidy(int a) throws Exception { return a + 1; }"), gj);
        assertEquals(0, r.exit(), r.stderr());
        assertFalse((r.stdout() + r.stderr()).contains("[AS-EFF-005]"));
    }

    @Test
    void n3_aNewUnknownOnlyFunctionIsAdvisoryButNamed() throws Exception {
        Path base = baseline();
        Path gj = tmp.resolve("n3.gate.json");
        Run r = gate(base, classes("n3", KEEP + "\n static int opaquenew(String s) throws Exception {"
                + " return (int) String.class.getMethod(\"length\").invoke(s); }"), gj);
        assertEquals(0, r.exit(), r.stderr());
        String all = r.stdout() + r.stderr();
        assertFalse(all.contains("[AS-EFF-005]"), all);
        assertTrue(all.lines().anyMatch(l -> l.contains("opaquenew") && l.contains("Unknown")),
                "a note line names opaquenew and Unknown: " + all);
    }

    @Test
    void n4_anExistingFunctionsGainIsOriginExisting() throws Exception {
        Path base = baseline();
        Path gj = tmp.resolve("n4.gate.json");
        Run r = gate(base, classes("n4", " static void keep() throws Exception {"
                + " java.nio.file.Files.readString(java.nio.file.Path.of(\"/x\")); new java.net.Socket(\"h\", 80); }"), gj);
        assertEquals(1, r.exit(), r.stderr());
        List<JsonObject> g = rows005(gj, "keep");
        assertEquals(1, g.size(), Files.readString(gj));
        assertEquals("[\"Net\"]", g.get(0).get("effects").toString());
        assertEquals("existing", g.get(0).get("origin").getAsString());
    }

    /** PART 15b `absent`: no sidecar — the new effectful function still fires; only its LABEL degrades. */
    @Test
    void withoutTheSidecarANewEffectfulFunctionStillFiresWithOriginUnknown() throws Exception {
        Path base = baseline();
        Files.delete(tmp.resolve("base.callgraph.json"));
        Path gj = tmp.resolve("ns.gate.json");
        Run r = gate(base, classes("ns", KEEP + "\n static void fresh() throws Exception { new java.net.Socket(\"h\", 80); }"), gj);
        assertEquals(1, r.exit(), r.stderr());
        List<JsonObject> g = rows005(gj, "fresh");
        assertEquals(1, g.size(), Files.readString(gj));
        assertEquals("unknown", g.get(0).get("origin").getAsString());
    }

    /** A whole baseline FILE absent keeps its posture: a note, the guard inactive, exit 0. */
    @Test
    void anAbsentBaselineFileKeepsItsNotePosture() throws Exception {
        Run r = cli(Map.of("CANDOR_BASELINE", tmp.resolve("nope.json").toString()),
                classes("nf", KEEP + "\n static void fresh() throws Exception { new java.net.Socket(\"h\", 80); }").toString());
        assertEquals(0, r.exit(), r.stderr());
        assertTrue(r.stderr().contains("does not exist"), r.stderr());
    }
}
