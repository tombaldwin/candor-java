package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * SPEC §2 {@code switches} / §3.4 / §3.3 cause (e) ⟨0.42⟩ (SOUNDNESS R1634), END TO END through the real CLI. Conformance PART 109
 * pins the cross-engine cells for ONE switch ({@code CANDOR_R1304}); this pins what that part cannot reach for this engine: the
 * lazy-read rule over two switches, a malformed {@code switches}, the advisory verbs, the chained advisory (and that
 * {@code gate --report} chains nothing), and that a cache is never primed by a switched run. Every cell has its control, because a
 * refusal test with no unset arm is vacuous.
 *
 * <p>The fixture is PART 109's: {@code convlib.ArrayConverter.toString} calls {@code elem.toString()} on a package-owned interface, so
 * the PRODUCER publishes a {@code dispatchesOn} key on it — unless {@code CANDOR_R1304=0}, which removes the row. A chained consumer's
 * {@code deny Fs app.App.c_call} goes exit 1 to exit 0 on that one variable: the silent pass the clause exists to disclose.
 */
class SwitchesCliTest {

    static Path lib, app, work;
    static final String POLICY = "deny Fs app.App.c_call\n";

    private record Run(int exit, String out, String err) {}

    @BeforeAll
    static void fixture() throws Exception {
        app = TestCompiler.compileApp(
                Map.of("convlib/Converter.java", "package convlib;\npublic interface Converter { String convert(String s); }\n",
                       "convlib/ArrayConverter.java", "package convlib;\npublic class ArrayConverter {\n  private final Converter elem;\n"
                               + "  public ArrayConverter(Converter e) { elem = e; }\n"
                               + "  @Override public String toString() { return \"AC[\" + elem.toString() + \"]\"; }\n}\n"),
                Map.of("app/MyConv.java", "package app;\npublic class MyConv implements convlib.Converter {\n  public String convert(String s) { return s; }\n"
                               + "  @Override public String toString() { new java.io.File(\"/tmp\").exists(); return \"MyConv\"; }\n}\n",
                       "app/App.java", "package app;\nimport convlib.*;\npublic class App {\n"
                               + "  public static String c_call(ArrayConverter ac) { return ac.toString(); }\n}\n"));
        lib = app.resolveSibling("lib");
        work = Files.createTempDirectory("candor-switches-cli");
        Files.writeString(work.resolve("p.candor"), POLICY);
    }

    @AfterEach
    void clean() { /* every test writes under unique names in `work` */ }

    private static int n = 0;
    private static String uniq(String stem) { return work.resolve(stem + (n++)).toString(); }

    /** Run the CLI with every inherited CANDOR_ variable removed (a switch in the gradle environment would turn the unset arm into a
     *  switched one) and {@code extra} added. */
    private static Run cli(Map<String, String> extra, String... args) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(System.getProperty("java.home") + "/bin/java", "-cp",
                System.getProperty("java.class.path"), "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().keySet().removeIf(k -> k.startsWith("CANDOR_"));
        pb.environment().putAll(extra);
        Process p = pb.start();
        // drain both streams concurrently: a full pipe on the one not being read would deadlock the child
        var errBuf = new ByteArrayOutputStream();
        Thread t = new Thread(() -> { try (InputStream e = p.getErrorStream()) { e.transferTo(errBuf); } catch (Exception ignored) { } });
        t.start();
        String out = new String(p.getInputStream().readAllBytes());
        int code = p.waitFor();
        t.join();
        return new Run(code, out, errBuf.toString());
    }

    private static JsonObject json(String path) throws Exception {
        return JsonParser.parseString(Files.readString(Path.of(path))).getAsJsonObject();
    }

    /** A scan of the PRODUCER (lib) writing a report; returns its path. */
    private static String produce(Map<String, String> env) throws Exception {
        String r = uniq("prod") + ".json";
        Run run = cli(env, lib.toString(), "--json", r);
        assertEquals(0, run.exit(), run.err());
        return r;
    }

    /** The CONSUMER (app) gated over a chained producer report; returns the run, the verdict path and the report path. */
    private record Gate(Run run, String gate, String report) {}
    private static Gate consume(Map<String, String> env, String producer) throws Exception {
        String g = uniq("gate") + ".json", r = uniq("cons") + ".json";
        Map<String, String> e = new HashMap<>(env);
        e.put("CANDOR_DEPS", producer);
        Run run = cli(e, app.toString(), "--json", r, "--policy", work.resolve("p.candor").toString(), "--gate-json", g);
        return new Gate(run, g, r);
    }

    private static boolean hasUnit(JsonObject report, String fn) {
        for (JsonElement f : report.getAsJsonArray("functions"))
            if (f.getAsJsonObject().get("fn").getAsString().equals(fn)) return true;
        return false;
    }

    // ── (a) the report names it ───────────────────────────────────────────────────────────────────

    @Test
    void control_noSwitch_noKey_theChainedPolicyFires() throws Exception {
        String prod = produce(Map.of());
        JsonObject d = json(prod);
        assertFalse(d.has("switches"), "no switch is set: the key is OMITTED, so the report is byte-identical to a pre-rung one");
        assertTrue(hasUnit(d, "convlib.ArrayConverter.toString"), "the fixture: the producer row exists unset");
        Gate g = consume(Map.of(), prod);
        assertEquals(1, g.run().exit(), g.run().err());
        assertFalse(json(g.gate()).has("refused"));
        assertFalse(json(g.gate()).has("switchedDependencies"), "a plain chain carries no `switchedDependencies`");
    }

    @Test
    void theReportNamesAConsultedSwitch_andSpecIsNotChanged() throws Exception {
        String unset = produce(Map.of()), w = produce(Map.of("CANDOR_R1304", "0"));
        JsonObject d = json(w);
        assertFalse(hasUnit(d, "convlib.ArrayConverter.toString"), "the switch demonstrably moved a result (the harness check)");
        assertEquals(List.of("CANDOR_R1304"), strings(d.getAsJsonArray("switches")));
        assertEquals(json(unset).getAsJsonObject("candor").get("spec"), d.getAsJsonObject("candor").get("spec"),
                "§3.4 (b): `spec` is NOT changed — consumers key on it");
    }

    @Test
    void setMeansANonDefaultBranch_soFlagOneIsNotSet_andAnUnreadSwitchIsNotListed() throws Exception {
        assertFalse(json(produce(Map.of("CANDOR_R1304", "1"))).has("switches"), "=1 equals the default (on): not SET");
        assertFalse(json(produce(Map.of("CANDOR_R0_OFF", "1"))).has("switches"),
                "a CANDOR_-prefixed variable the engine never consults is NOT listed (dumping the environment buries the one that mattered)");
        // a switch that is set and whose read never EXECUTES on this fixture: R1306 is read only where a printStackTrace or an
        // Object-protocol cause is reached, and the fixture has neither — so it is not 'consulted'
        JsonObject d = json(produce(Map.of("CANDOR_R1304", "0", "CANDOR_R1306", "0", "CANDOR_R1360", "0")));
        List<String> named = strings(d.getAsJsonArray("switches"));
        assertTrue(named.contains("CANDOR_R1304"), named.toString());
        assertEquals(named.stream().sorted().distinct().toList(), named, "sorted, no duplicates");
    }

    // ── (c)(i) a gate under a set switch refuses ──────────────────────────────────────────────────

    @Test
    void aGateUnderASetSwitchRefuses_theReportIsStillWritten_aViolationDoesNotDominate() throws Exception {
        String prod = produce(Map.of());   // the UNSWITCHED producer: the consumer would FIRE (exit 1) were it not for the refusal
        Gate g = consume(Map.of("CANDOR_R1304", "0"), prod);
        assertEquals(2, g.run().exit(), g.run().err());
        JsonObject d = json(g.gate());
        assertEquals(false, d.get("ok").getAsBoolean());
        assertEquals(true, d.get("refused").getAsBoolean());
        assertFalse(d.has("violations"), "the §3.1 refusal document carries NO `violations` key");
        assertEquals(List.of("CANDOR_R1304"), strings(d.getAsJsonArray("switches")));
        assertTrue(d.get("reason").getAsString().contains("CANDOR_R1304") && d.get("reason").getAsString().contains("Unset"),
                "the reason names the switch and says to unset it: " + d.get("reason"));
        JsonObject rep = json(g.report());
        assertEquals(List.of("CANDOR_R1304"), strings(rep.getAsJsonArray("switches")), "a refused scan still WRITES its report, carrying `switches`");
    }

    // ── (c)(ii) the route that reads a report refuses it ──────────────────────────────────────────

    private static String handWritten(String name, String switchesJson) throws Exception {
        String p = uniq(name) + ".json";
        Files.writeString(Path.of(p), "{\"candor\":{\"version\":\"hand\",\"spec\":\"0.42\"},\"package\":\"app\",\"analyzed\":{\"count\":1,\"digest\":\"0\"},"
                + (switchesJson == null ? "" : "\"switches\":" + switchesJson + ",")
                + "\"functions\":[{\"fn\":\"app.f\",\"hash\":\"app#app.f\",\"inferred\":[\"Fs\"],\"direct\":[\"Fs\"]}]}");
        return p;
    }

    @Test
    void gateReportRefusesAReportCarryingSwitches_andJudgesTheSameReportWithout() throws Exception {
        String plain = handWritten("h", null), sw = handWritten("hs", "[\"CANDOR_B\",\"CANDOR_A\"]");
        String pol = work.resolve("deny-fs.candor").toString();
        Files.writeString(Path.of(pol), "deny Fs\n");
        String g0 = uniq("g") + ".json", g1 = uniq("g") + ".json";
        assertEquals(1, cli(Map.of(), "gate", "--report", plain, "--policy", pol, "--gate-json", g0).exit(), "control: the plain report is judged and fails");
        assertFalse(json(g0).has("refused"));
        Run r = cli(Map.of(), "gate", "--report", sw, "--policy", pol, "--gate-json", g1);
        assertEquals(2, r.exit(), r.err());
        JsonObject d = json(g1);
        assertEquals(true, d.get("refused").getAsBoolean());
        assertFalse(d.has("violations"), "a violation (`app.f` performs Fs) does NOT dominate the refusal (§3.3 (e))");
        assertEquals(List.of("CANDOR_A", "CANDOR_B"), strings(d.getAsJsonArray("switches")), "code-point sorted");
    }

    @Test
    void aMalformedSwitchesKeyImpeachesTheReport_neverReadAsNoSwitches() throws Exception {
        String pol = work.resolve("deny-fs2.candor").toString();
        Files.writeString(Path.of(pol), "deny Fs\n");
        for (String bad : new String[]{"\"CANDOR_X\"", "[1]", "[\"\"]", "{}", "[null]"}) {
            String rep = handWritten("m", bad), g = uniq("g") + ".json";
            Run r = cli(Map.of(), "gate", "--report", rep, "--policy", pol, "--gate-json", g);
            assertEquals(2, r.exit(), "switches=" + bad + " must impeach, not pass as empty: " + r.err());
            assertTrue(json(g).get("refused").getAsBoolean(), bad);
        }
    }

    @Test
    void anEvaluatorThatRanNoAnalysisConsultedNoSwitch_soAScanTimeSwitchInItsEnvironmentChangesNothing() throws Exception {
        String plain = handWritten("e", null), pol = work.resolve("deny-fs3.candor").toString(), g = uniq("g") + ".json";
        Files.writeString(Path.of(pol), "deny Fs\n");
        // every switch java registers, set to the value that selects its non-default branch (SwitchLazinessTest enumerates them from source)
        Map<String, String> all = new HashMap<>(SwitchLazinessTest.everySwitchSet());
        Run r = cli(all, "gate", "--report", plain, "--policy", pol, "--gate-json", g);
        assertEquals(1, r.exit(), "gate --report judges a clean report as it would without the variables: " + r.err());
        assertFalse(json(g).has("refused"), "an engine MUST NOT read every switch at process start (§3.4 (a))");
    }

    @Test
    void everyOtherEvaluatorVerbAlsoRunsUnchangedWithEverySwitchSet() throws Exception {
        String plain = handWritten("ev", null), pol = work.resolve("deny-fs6.candor").toString();
        Files.writeString(Path.of(pol), "deny Fs\n");
        Map<String, String> all = SwitchLazinessTest.everySwitchSet();
        String[][] verbs = {{"where", "Fs", "--report", plain}, {"show", "app.f", "--report", plain}, {"map", "--report", plain},
                {"blindspots", "--report", plain}, {"unverified", "--report", plain, "--policy", pol},
                {"fix-gate", "--report", plain, "--policy", pol}, {"whatif", "app.f", "Net", "--report", plain},
                {"accepts", "--report", plain, "--policy", pol}, {"parsepolicy", pol}, {"--version"}, {"--help"}};
        for (String[] v : verbs) {
            Run unset = cli(Map.of(), v), set = cli(all, v);
            assertEquals(unset.exit(), set.exit(), String.join(" ", v) + ": exit moved under switches that the verb never consults\n" + set.err());
            assertEquals(unset.out(), set.out(), String.join(" ", v) + ": output moved under switches that the verb never consults");
            assertFalse(set.out().contains("result-moving switch") || set.err().contains("result-moving switch"),
                    String.join(" ", v) + " consulted a switch it never runs the logic of:\n" + set.err());
        }
    }

    // ── the advisory verbs that answer `ok` ───────────────────────────────────────────────────────

    @Test
    void theAdvisoryVerbsRefuseOverASwitchedReport_strictOrNot_andFixDoesNot() throws Exception {
        String plain = handWritten("v", null), sw = handWritten("vs", "[\"CANDOR_R1304\"]");
        String pol = work.resolve("deny-fs4.candor").toString();
        Files.writeString(Path.of(pol), "deny Fs\n");
        for (String verb : new String[]{"unverified", "fix-gate"}) {
            Run c = cli(Map.of(), verb, "--report", plain, "--policy", pol);
            assertNotEquals(2, c.exit(), "control: " + verb + " over the plain report is answered: " + c.err());
            Run r = cli(Map.of(), verb, "--report", sw, "--policy", pol);
            assertEquals(2, r.exit(), verb + " (no --strict) over a switched report must refuse: " + r.err());
            JsonObject d = JsonParser.parseString(r.out()).getAsJsonObject();
            assertEquals(true, d.get("refused").getAsBoolean());
            assertEquals(List.of("CANDOR_R1304"), strings(d.getAsJsonArray("switches")));
        }
        // whatif needs a call-graph sidecar; a switched report with none still refuses FIRST (the claim is withdrawn, not hedged)
        Run w = cli(Map.of(), "whatif", "app.f", "Net", "--report", sw, "--policy", pol);
        assertEquals(2, w.exit());
        assertTrue(w.out().contains("\"switches\""), w.out());
        // `fix` answers no `ok`: not bound by this sentence
        Run f = cli(Map.of(), "fix", "app.f", "Fs", "--report", sw, "--policy", pol);
        assertFalse(f.out().contains("\"refused\": true") && f.out().contains("\"switches\""), "`fix` is not bound: " + f.out());
    }

    // ── (d) a chained dependency report carrying `switches` ───────────────────────────────────────

    @Test
    void aChainedReportCarryingSwitchesGetsTheAdvisory_andTheExitIsUntouched() throws Exception {
        String prod = produce(Map.of());
        Gate plain = consume(Map.of(), prod);
        // the same producer report with `switches` INJECTED by hand (PART 109's recipe), sidecars copied beside it
        Path dir = Files.createDirectory(work.resolve("inj" + (n++)));
        JsonObject inj = json(prod);
        com.google.gson.JsonArray a = new com.google.gson.JsonArray();
        a.add("CANDOR_R1304");
        inj.add("switches", a);
        Path injected = dir.resolve("dep.json");
        Files.writeString(injected, inj.toString());
        for (String suf : new String[]{".callgraph.json", ".hierarchy.json"}) {
            Path sc = Path.of(prod.substring(0, prod.length() - ".json".length()) + suf);
            if (Files.exists(sc)) Files.copy(sc, dir.resolve("dep" + suf));
        }
        Gate chained = consume(Map.of(), injected.toString());
        assertEquals(plain.run().exit(), chained.run().exit(), "the exit is UNTOUCHED (§3.4 (d)): the consumer's own run is not switched");
        assertEquals(1, chained.run().exit());
        int hits = chained.run().err().split("CANDOR_R1304", -1).length - 1;
        assertEquals(1, hits, "stderr names the switch ONCE per package: " + chained.run().err());
        assertFalse(plain.run().err().contains("CANDOR_R1304"), "control: a plain chain says nothing");
        JsonObject d = json(chained.gate());
        var sd = d.getAsJsonArray("switchedDependencies");
        assertEquals(1, sd.size());
        assertEquals("dep", sd.get(0).getAsJsonObject().get("package").getAsString(), "a report with no singular `package` is named by its file stem");
        assertEquals(List.of("CANDOR_R1304"), strings(sd.get(0).getAsJsonObject().getAsJsonArray("switches")));
        // everything else in the verdict is what it would be without the key
        d.remove("switchedDependencies");
        assertEquals(json(plain.gate()), d, "the documents are equal but for `switchedDependencies`");
        assertFalse(json(chained.report()).has("switches"), "the CONSUMER's own report is not switched, so it names nothing");
    }

    @Test
    void gateReportChainsNoDependency_soSwitchedDependenciesCannotAppearOnThatRoute() throws Exception {
        // `gate --report` gates the reports its locator names as one analysis world; it never reads CANDOR_DEPS, so there is no
        // chained dependency for the key to describe. The reports it DOES gate are judged under (c)(ii), not (d).
        String prod = produce(Map.of("CANDOR_R1304", "0"));
        String pol = work.resolve("deny-fs5.candor").toString(), g = uniq("g") + ".json";
        Files.writeString(Path.of(pol), "deny Fs\n");
        String clean = handWritten("c", null);
        Run r = cli(Map.of("CANDOR_DEPS", prod), "gate", "--report", clean, "--policy", pol, "--gate-json", g);
        assertEquals(1, r.exit(), r.err());
        assertFalse(json(g).has("switchedDependencies"));
        assertFalse(json(g).has("refused"), "CANDOR_DEPS is ignored by gate --report, so a switched report there is not judged");
    }

    // ── a cache is never primed by a switched run ─────────────────────────────────────────────────

    @Test
    void aSwitchedRunDoesNotPrimeTheRefreshCache_soAnUnsetRunCannotReplayItsRows() throws Exception {
        Path cacheOk = Files.createDirectory(work.resolve("cache" + (n++))), cacheSw = Files.createDirectory(work.resolve("cache" + (n++)));
        Run ok = cli(Map.of("CANDOR_REFRESH", cacheOk.toString()), lib.toString(), "--json", uniq("rf") + ".json");
        assertEquals(0, ok.exit(), ok.err());
        assertTrue(Files.list(cacheOk).anyMatch(f -> f.getFileName().toString().startsWith("candor-refresh")),
                "control: an unswitched run DOES write the cache (else the arm below is vacuous)");
        Run sw = cli(Map.of("CANDOR_REFRESH", cacheSw.toString(), "CANDOR_R1304", "0"), lib.toString(), "--json", uniq("rf") + ".json");
        assertEquals(0, sw.exit(), sw.err());
        assertTrue(Files.list(cacheSw).noneMatch(f -> f.getFileName().toString().startsWith("candor-refresh")),
                "a run that consulted a result-moving switch must store nothing: " + sw.err());
        assertTrue(sw.err().contains("not stored"), sw.err());
    }

    private static List<String> strings(com.google.gson.JsonArray a) {
        List<String> out = new ArrayList<>();
        for (JsonElement e : a) out.add(e.getAsString());
        return out;
    }
}
