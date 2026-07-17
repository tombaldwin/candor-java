package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import io.poly.candor.verify.HonestyCheck;
import io.poly.candor.verify.HonestyCheck.Result;
import io.poly.candor.verify.HonestyCheck.TraceEvent;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨verify⟩ The JVM DYNAMIC HONESTY ORACLE. Two layers:
 *
 * <ol>
 *   <li>UNIT — {@link HonestyCheck} + the effect map: the invariant math (sound-ok / disclosed / VIOLATION,
 *       refinement-aware) checked directly, no subprocess. Always runs.</li>
 *   <li>END-TO-END — compile a fixture with an effectful method (Files.readAllBytes) + a pure method, scan
 *       it with candor to get a report, then run `candor-java verify … --run "java -cp <cls> Main"` via the
 *       BUILT shadowJar (the agent needs the Premain-Class manifest). Asserts HOLDS when the report is sound,
 *       VIOLATION + exit 1 when the effectful method is seeded pure, and HELD when it is disclosed Unknown.
 *       Skipped (JUnit assumption) if the shadowJar isn't built.</li>
 * </ol>
 */
class VerifyOracleTest {

    @TempDir
    Path tmp;

    // ── (1) UNIT: the invariant math ──────────────────────────────────────────────────────────────────

    private static Result check(Map<String, Set<String>> report, List<TraceEvent> events, String scope) {
        return HonestyCheck.honestyCheck(report, HonestyCheck.observedByFn(events, scope), scope);
    }

    private static Set<String> effs(String... e) { return new TreeSet<>(Set.of(e)); }

    @Test
    void soundReportHolds() {
        var report = Map.of("A.reads", effs("Fs"));
        var events = List.of(new TraceEvent("A.reads", "Fs"));
        Result r = check(report, events, "direct");
        assertTrue(r.honestyInvariantHolds);
        assertEquals(1, r.soundCompleteOk);
        assertEquals(0, r.cardinalSinViolations);
    }

    @Test
    void claimedPureButRanEffectIsAViolation() {
        var report = Map.<String, Set<String>>of(); // A.reads ABSENT ⇒ claimed pure
        var events = List.of(new TraceEvent("A.reads", "Fs"));
        Result r = check(report, events, "direct");
        assertFalse(r.honestyInvariantHolds);
        assertEquals(1, r.cardinalSinViolations);
        assertEquals("A.reads", r.violations.get(0).fn);
        assertEquals(List.of("Fs"), r.violations.get(0).escaped);
    }

    @Test
    void unknownDisclosureHolds() {
        var report = Map.of("A.reads", effs("Unknown"));
        var events = List.of(new TraceEvent("A.reads", "Fs"));
        Result r = check(report, events, "direct");
        assertTrue(r.honestyInvariantHolds);
        assertEquals(1, r.disclosedPartial);
        assertEquals(1, r.disclosedUnknownLoadBearing); // the Unknown was load-bearing
    }

    @Test
    void observedRefinementSatisfiedByBaseNet() {
        // candor declared Net (couldn't resolve the db-ness); observed Db is a refinement of Net → covered.
        var report = Map.of("A.query", effs("Net"));
        var events = List.of(new TraceEvent("A.query", "Db"));
        Result r = check(report, events, "all");
        assertTrue(r.honestyInvariantHolds, "an observed Db refines an inferred Net — not a violation");
    }

    @Test
    void directScopeIgnoresOutOfScopeEffects() {
        // Env is out of the `direct` scope, so an unreported Env does NOT violate direct; it does under all.
        var report = Map.<String, Set<String>>of("A.f", effs()); // claimed pure
        var events = List.of(new TraceEvent("A.f", "Env"));
        assertTrue(check(report, events, "direct").honestyInvariantHolds);
        assertFalse(check(report, events, "all").honestyInvariantHolds);
    }

    @Test
    void effectMapCoversTheCommonBoundary() throws Exception {
        // EffectMap is package-private to io.poly.candor.verify; reach it reflectively to pin key mappings
        // without widening its API. A missed mapping is only a missed observation (never a false verdict),
        // so this asserts the HEADLINE entries resolve.
        var cls = Class.forName("io.poly.candor.verify.EffectMap");
        var m = cls.getDeclaredMethod("effectOf", String.class, String.class);
        m.setAccessible(true);
        assertEquals("Fs", m.invoke(null, "java/nio/file/Files", "readAllBytes"));
        assertEquals("Fs", m.invoke(null, "java/io/FileInputStream", "<init>"));
        assertEquals("Net", m.invoke(null, "java/net/Socket", "<init>"));
        assertEquals("Net", m.invoke(null, "java/net/http/HttpClient", "send"));
        assertEquals("Exec", m.invoke(null, "java/lang/ProcessBuilder", "start"));
        assertEquals("Env", m.invoke(null, "java/lang/System", "getenv"));
        assertEquals("Clock", m.invoke(null, "java/lang/System", "nanoTime"));
        assertEquals("Rand", m.invoke(null, "java/security/SecureRandom", "nextBytes"));
        // NOT effects: a plain String method, and java/util/Random (deliberately excluded).
        assertEquals(null, m.invoke(null, "java/lang/String", "length"));
        assertEquals(null, m.invoke(null, "java/util/Random", "nextInt"));
    }

    @Test
    void agentAttributionKeyMatchesReportForOverloads() {
        // The agent forms its emit key with Cha.methodId(class, name, desc, <the class's descs for that name>).
        // An OVERLOADED name must carry the (params) suffix EXACTLY as the report does — else the effectful
        // overload never matches its report entry and reads as a false cardinal-sin VIOLATION.
        var descs = java.util.Set.of("(Ljava/lang/String;)V", "(I)V"); // write(String) + write(int)
        assertEquals("A.write(String)", Cha.methodId("A", "write", "(Ljava/lang/String;)V", descs));
        assertEquals("A.write(int)", Cha.methodId("A", "write", "(I)V", descs));
        // a UNIQUELY-named method stays BARE (no suffix) — matches the report's non-overloaded fn quals.
        assertEquals("A.read", Cha.methodId("A", "read", "()V", java.util.Set.of("()V")));
    }

    // ── (2) END-TO-END through the built shadowJar ────────────────────────────────────────────────────

    private record Run(int exit, String stdout, String stderr) {}

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    /** The built candor shadowJar (Main-Class + Premain-Class) — the agent needs the manifest, so the
     *  end-to-end path can't run from the test classpath. */
    private static Path shadowJar() {
        Path libs = Path.of(System.getProperty("user.dir"), "build", "libs");
        if (!Files.isDirectory(libs)) return null;
        try (var s = Files.list(libs)) {
            return s.filter(p -> p.getFileName().toString().endsWith("-all.jar"))
                    .max((a, b) -> {
                        try { return Long.compare(Files.getLastModifiedTime(a).toMillis(),
                                Files.getLastModifiedTime(b).toMillis()); }
                        catch (Exception e) { return 0; }
                    })
                    .orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private Run runVerifyJar(Path jar, Path clsDir, Path report, String... extra) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(
                System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                "verify", clsDir.toString(), "--report", report.toString(),
                "--run", "\"" + System.getProperty("java.home") + "/bin/java\" -cp \"" + clsDir + "\" app.Main",
                "--json"));
        cmd.addAll(List.of(extra));
        // JAVA_TOOL_OPTIONS is inherited by the outer jar too; clear it so the agent only rides the --run child.
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().remove("JAVA_TOOL_OPTIONS");
        Process p = pb.start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    /** Fixture: an effectful method (Files.readAllBytes on a real temp file), a pure method, a main. */
    private Path compileFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path target = tmp.resolve("data.txt");
        Files.writeString(target, "hello");
        Path src = tmp.resolve("Main.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "import java.nio.file.Files;",
            "import java.nio.file.Path;",
            "public class Main {",
            "  static void reads() throws Exception {",
            "    Files.readAllBytes(Path.of(" + gstr(target.toString()) + "));",
            "  }",
            "  static int pure(int a, int b) { return a + b; }",
            "  public static void main(String[] a) throws Exception {",
            "    System.out.println(\"program stdout must NOT corrupt --json output\");", // regression guard
            "    reads();",
            "    if (pure(2, 3) != 5) throw new IllegalStateException();",
            "  }",
            "}"));
        Path out = tmp.resolve("cls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "fixture must compile");
        return out;
    }

    private static String gstr(String s) { return "\"" + s.replace("\\", "\\\\") + "\""; }

    private static JsonObject metrics(String json) {
        return JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("metrics");
    }

    @Test
    void endToEndHoldsThenSeededViolationThenDisclosed() throws Exception {
        Path jar = shadowJar();
        Assumptions.assumeTrue(jar != null, "no built shadowJar (run ./gradlew shadowJar) — skip end-to-end");
        Path cls = compileFixture();

        // Scan the fixture with candor (via the same jar) to get an HONEST report.
        Path report = tmp.resolve("report.json");
        Process scan = new ProcessBuilder(
                System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                cls.toString(), "--json", report.toString())
                .redirectErrorStream(true).start();
        drain(scan.getInputStream());
        assertEquals(0, scan.waitFor(), "scan must succeed");
        assertTrue(Files.exists(report), "report must be written");

        // (a) HOLDS — candor is sound: reads() ran Fs and the report says Fs.
        Run hold = runVerifyJar(jar, cls, report);
        JsonObject m = metrics(hold.stdout());
        assertTrue(m.get("honestyInvariantHolds").getAsBoolean(),
                "sound report must HOLD; stdout=" + hold.stdout() + " stderr=" + hold.stderr());
        assertEquals(0, hold.exit());
        assertEquals(0, m.get("cardinalSinViolations").getAsInt());
        assertTrue(m.get("executedFunctionsChecked").getAsInt() >= 1, "reads() must be witnessed");
        // The fixture prints to stdout; `metrics(hold.stdout())` parsing above already proves --json stdout is
        // NOT corrupted by the program's output (the inheritIO bug). Also assert `rows` — parity with candor-ts.
        var rows = JsonParser.parseString(hold.stdout()).getAsJsonObject().getAsJsonArray("rows");
        assertTrue(rows.size() >= 1, "per-fn rows present (parity with candor-ts-verify); stdout=" + hold.stdout());
        assertTrue(java.util.stream.StreamSupport.stream(rows.spliterator(), false)
                .anyMatch(e -> "app.Main.reads".equals(e.getAsJsonObject().get("fn").getAsString())
                        && "sound-complete-ok".equals(e.getAsJsonObject().get("verdict").getAsString())),
                "reads() row is sound-complete-ok");

        // (b) VIOLATION — seed a MISS: declare reads() pure, run again → cardinal sin, exit 1, Fs escaped.
        String reportText = Files.readString(report);
        var doc = JsonParser.parseString(reportText).getAsJsonObject();
        for (var el : doc.getAsJsonArray("functions")) {
            var f = el.getAsJsonObject();
            if (f.get("fn").getAsString().equals("app.Main.reads")) {
                f.add("inferred", new com.google.gson.JsonArray()); // claimed pure
            }
        }
        Path seeded = tmp.resolve("report-seeded-pure.json");
        Files.writeString(seeded, doc.toString());
        // Copy the real callgraph sidecar next to the doctored report so the include set covers the analyzed
        // universe (attributionComplete) — a doctored report with no sidecar correctly fails closed (exit 2).
        Files.copy(tmp.resolve("report.callgraph.json"), tmp.resolve("report-seeded-pure.callgraph.json"));
        Run viol = runVerifyJar(jar, cls, seeded);
        JsonObject vm = metrics(viol.stdout());
        assertFalse(vm.get("honestyInvariantHolds").getAsBoolean(), "seeded-pure report must VIOLATE");
        assertEquals(1, viol.exit(), "a cardinal-sin violation exits 1");
        assertEquals(1, vm.get("cardinalSinViolations").getAsInt());
        var vArr = JsonParser.parseString(viol.stdout()).getAsJsonObject().getAsJsonArray("violations");
        var v0 = vArr.get(0).getAsJsonObject();
        assertEquals("app.Main.reads", v0.get("fn").getAsString());
        assertEquals("Fs", v0.getAsJsonArray("escaped").get(0).getAsString());

        // (c) DISCLOSED — declare reads() Unknown → HELD (disclosure carries it), exit 0.
        var doc2 = JsonParser.parseString(reportText).getAsJsonObject();
        for (var el : doc2.getAsJsonArray("functions")) {
            var f = el.getAsJsonObject();
            if (f.get("fn").getAsString().equals("app.Main.reads")) {
                var arr = new com.google.gson.JsonArray();
                arr.add("Unknown");
                f.add("inferred", arr);
            }
        }
        Path disclosed = tmp.resolve("report-unknown.json");
        Files.writeString(disclosed, doc2.toString());
        Files.copy(tmp.resolve("report.callgraph.json"), tmp.resolve("report-unknown.callgraph.json"));
        Run disc = runVerifyJar(jar, cls, disclosed);
        JsonObject dm = metrics(disc.stdout());
        assertTrue(dm.get("honestyInvariantHolds").getAsBoolean(), "Unknown-disclosed report must HOLD");
        assertEquals(0, disc.exit());
        assertEquals(1, dm.get("disclosedPartial").getAsInt());

        // (d) FAIL-CLOSED — a report with NO callgraph sidecar can only instrument the effectful classes, so a
        // secret effect in a wholly-pure class would be missed. verify must DISCLOSE (attributionComplete=false)
        // and exit 2, never a green exit 0 (parity with the ts arm; the review's #2).
        Path noCg = tmp.resolve("report-nocg.json");
        Files.writeString(noCg, reportText); // the SOUND report, but deliberately with no <stem>.callgraph.json beside it
        Run nc = runVerifyJar(jar, cls, noCg);
        JsonObject ncm = metrics(nc.stdout());
        assertFalse(ncm.get("attributionComplete").getAsBoolean(), "no callgraph ⇒ include set is effectful-only ⇒ not sound");
        assertEquals(2, nc.exit(), "an incomplete-attribution HOLD fails closed (exit 2), never a green exit 0");
    }
}
