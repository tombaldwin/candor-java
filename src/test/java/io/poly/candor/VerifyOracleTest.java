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

    @Test
    void genericOverrideBridgeDoesNotFalselyViolate() throws Exception {
        // REGRESSION (found on the zip4j public corpus — every *Task.executeTask override tripped it): a
        // generic/covariant override (Task<String>.exec) makes javac emit a synthetic BRIDGE exec(Object)
        // beside the real exec(String). candor's scan EXCLUDES bridges from its overload index, so the report
        // keys the method BARE (app.Main$FileTask.exec). The agent must exclude the bridge too when forming its
        // emit key — else it counts two `exec` descriptors, renders a param-qualified key, and the effectful
        // override never matches its bare report entry → a SPURIOUS cardinal-sin VIOLATION. Must HOLD.
        Path jar = shadowJar();
        Assumptions.assumeTrue(jar != null, "no built shadowJar (run ./gradlew shadowJar) — skip end-to-end");
        Path cls = compileBridgeFixture();

        Path report = tmp.resolve("bridge-report.json");
        Process scan = new ProcessBuilder(
                System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                cls.toString(), "--json", report.toString())
                .redirectErrorStream(true).start();
        drain(scan.getInputStream());
        assertEquals(0, scan.waitFor(), "scan must succeed");

        Run hold = runVerifyJar(jar, cls, report);
        JsonObject m = metrics(hold.stdout());
        assertTrue(m.get("honestyInvariantHolds").getAsBoolean(),
                "generic-override bridge must not falsely violate; stdout=" + hold.stdout() + " stderr=" + hold.stderr());
        assertEquals(0, hold.exit(), "no spurious violation ⇒ exit 0");
        assertEquals(0, m.get("cardinalSinViolations").getAsInt());
        assertTrue(m.get("executedFunctionsChecked").getAsInt() >= 1, "the effectful override must be witnessed");
        // the bridged override's row is keyed BARE and reads sound-complete-ok (NOT a violation).
        var rows = JsonParser.parseString(hold.stdout()).getAsJsonObject().getAsJsonArray("rows");
        assertTrue(java.util.stream.StreamSupport.stream(rows.spliterator(), false)
                .anyMatch(e -> e.getAsJsonObject().get("fn").getAsString().equals("app.Main$FileTask.exec")
                        && "sound-complete-ok".equals(e.getAsJsonObject().get("verdict").getAsString())),
                "the bridged override matches its bare report entry; stdout=" + hold.stdout());
    }

    @Test
    void agentDoesNotBreakClassLoadingViaFrameRecomputation() throws Exception {
        // REGRESSION (found on the apache/commons-io public suite: the agent broke 194/195 FileUtilsTest tests
        // with `LinkageError: attempted duplicate class definition`). The agent's ClassWriter must NOT use
        // COMPUTE_FRAMES: recomputing a stack-map frame forces getCommonSuperClass to CLASS-LOAD the app's types
        // mid-transform, and force-loading a class whose supertype is being defined on the same loader raises the
        // LinkageError — the agent perturbing the program under test, the one thing it must never do. The Trace.emit
        // injection is frame-NEUTRAL (push two constants, pop them via the call — no branch, no local), so the
        // javac-emitted frames stay valid and are copied through verbatim.
        //
        // This fixture reproduces the reentrancy MINIMALLY: Base.pick has a control-flow merge over two SUBCLASSES
        // of Base (a ternary Sub1|Sub2), whose common supertype is Base ITSELF. Under COMPUTE_FRAMES, transforming
        // Base computes that frame → getCommonSuperClass force-loads Sub1, whose superclass Base is mid-definition
        // (its own load is what triggered the transform) → duplicate-definition LinkageError → the child JVM dies
        // before Base.pick runs. With the fix, the frame is preserved, no class is loaded, pick runs and its Fs is
        // witnessed. The assertion below has teeth: under a COMPUTE_FRAMES regression pick is NOT witnessed
        // sound-complete-ok (the crash precedes it), so the test goes red.
        Path jar = shadowJar();
        Assumptions.assumeTrue(jar != null, "no built shadowJar (run ./gradlew shadowJar) — skip end-to-end");
        Path cls = compileReentrantFrameFixture();

        Path report = tmp.resolve("reentr-report.json");
        Process scan = new ProcessBuilder(
                System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                cls.toString(), "--json", report.toString())
                .redirectErrorStream(true).start();
        drain(scan.getInputStream());
        assertEquals(0, scan.waitFor(), "scan must succeed");

        Run hold = runVerifyJar(jar, cls, report);
        JsonObject m = metrics(hold.stdout());
        assertEquals(0, hold.exit(), "instrumented run must not crash (no LinkageError); stderr=" + hold.stderr());
        assertTrue(m.get("honestyInvariantHolds").getAsBoolean(),
                "frame-carrying effectful method must instrument+run cleanly; stdout=" + hold.stdout() + " stderr=" + hold.stderr());
        assertEquals(0, m.get("cardinalSinViolations").getAsInt());
        // The effect must be WITNESSED sound-complete-ok — proving Base loaded, was instrumented, and its injected
        // bytecode verified and RAN. Under a COMPUTE_FRAMES regression the child crashes before pick executes, so
        // this row is absent → the test fails (teeth confirmed against the reverted-COMPUTE_FRAMES build).
        var rows = JsonParser.parseString(hold.stdout()).getAsJsonObject().getAsJsonArray("rows");
        assertTrue(java.util.stream.StreamSupport.stream(rows.spliterator(), false)
                .anyMatch(e -> "app.Main$Base.pick".equals(e.getAsJsonObject().get("fn").getAsString())
                        && "sound-complete-ok".equals(e.getAsJsonObject().get("verdict").getAsString())),
                "Base.pick (frame merging its own subclasses) is witnessed sound-complete-ok; stdout=" + hold.stdout());
    }

    @Test
    void nonZeroRunExitFailsClosedUnlessAllowed() throws Exception {
        // A --run command that does NOT complete cleanly (non-zero exit — a crash, or a failing test suite) may
        // have produced a PARTIAL trace, so a clean all-clear cannot be certified over it: verify fails closed
        // (exit 2, attributionComplete=false), never a green exit 0 — the same posture as a torn trace / missing
        // callgraph. The honesty invariant itself still HOLDS on what WAS witnessed (the effect ran and was
        // reported); only completeness is in doubt. `--allow-run-failure` opts out for a suite with EXPECTED
        // failures (effects still fully exercised): the verdict is kept and the non-zero exit only disclosed.
        Path jar = shadowJar();
        Assumptions.assumeTrue(jar != null, "no built shadowJar (run ./gradlew shadowJar) — skip end-to-end");
        Path cls = compileExitNonZeroFixture();

        Path report = tmp.resolve("exit-report.json");
        Process scan = new ProcessBuilder(
                System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                cls.toString(), "--json", report.toString())
                .redirectErrorStream(true).start();
        drain(scan.getInputStream());
        assertEquals(0, scan.waitFor(), "scan must succeed");

        // DEFAULT — the --run child exits 3 → fail closed (exit 2), attribution incomplete, exit code disclosed,
        // but the witnessed effect still HOLDS.
        Run def = runVerifyJar(jar, cls, report);
        JsonObject dm = metrics(def.stdout());
        assertEquals(2, def.exit(), "a non-clean --run fails closed (exit 2); stdout=" + def.stdout() + " stderr=" + def.stderr());
        assertFalse(dm.get("attributionComplete").getAsBoolean(), "a non-zero run exit ⇒ attribution not certified complete");
        assertEquals(3, dm.get("programExitCode").getAsInt(), "the child exit code is disclosed in the verdict");
        assertTrue(dm.get("honestyInvariantHolds").getAsBoolean(), "the effect WAS witnessed; only completeness is in doubt");

        // OPT-OUT — --allow-run-failure keeps the verdict (advisory) and exits 0.
        Run allow = runVerifyJar(jar, cls, report, "--allow-run-failure");
        JsonObject am = metrics(allow.stdout());
        assertEquals(0, allow.exit(), "--allow-run-failure keeps the green verdict; stdout=" + allow.stdout() + " stderr=" + allow.stderr());
        assertTrue(am.get("attributionComplete").getAsBoolean(), "opt-out ⇒ the run-exit gap is not raised");
        assertEquals(3, am.get("programExitCode").getAsInt(), "the non-zero exit is still disclosed under the opt-out");
        assertTrue(am.get("honestyInvariantHolds").getAsBoolean());
    }

    @Test
    void transitiveCallerMissIsCaught() throws Exception {
        // The core of candor is a TRANSITIVE effect report: a caller that reaches an effect through a callee is
        // itself effectful. The oracle must therefore attribute a runtime effect TRANSITIVELY — to the enclosing
        // method AND every analyzed caller on the live stack — or it cannot falsify the dangerous cardinal sin:
        // a CALLER (not the leaf) that reaches an effect through a dropped/dynamic edge and is reported pure. A
        // direct-only (leaf-only) oracle is structurally blind to it (the effect lands on the leaf; the caller's
        // obs is empty ⇒ vacuously holds). fixture: main → middle → leaf(Fs). We seed the miss at the CALLER
        // `middle` (declare it pure, leave the leaf correct) and require a witnessed violation on middle.
        Path jar = shadowJar();
        Assumptions.assumeTrue(jar != null, "no built shadowJar (run ./gradlew shadowJar) — skip end-to-end");
        Path cls = compileTransitiveFixture();

        Path report = tmp.resolve("trans-report.json");
        Process scan = new ProcessBuilder(
                System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                cls.toString(), "--json", report.toString())
                .redirectErrorStream(true).start();
        drain(scan.getInputStream());
        assertEquals(0, scan.waitFor(), "scan must succeed");
        String reportText = Files.readString(report);
        // candor's report is transitive: middle and main both carry Fs though only leaf calls java.nio.
        var doc0 = JsonParser.parseString(reportText).getAsJsonObject();
        assertTrue(fnInferred(doc0, "app.Main.middle").contains("Fs"), "candor reports middle Fs (transitive)");
        assertTrue(fnInferred(doc0, "app.Main.main").contains("Fs"), "candor reports main Fs (transitive)");

        // POSITIVE — sound report holds, witnessing all three functions transitively (leaf, middle, main).
        Run hold = runVerifyJar(jar, cls, report);
        JsonObject hm = metrics(hold.stdout());
        assertTrue(hm.get("honestyInvariantHolds").getAsBoolean(), "sound transitive report holds; stdout=" + hold.stdout());
        assertTrue(hm.get("executedFunctionsChecked").getAsInt() >= 3,
                "transitive attribution witnesses the caller chain, not just the leaf; stdout=" + hold.stdout());

        // VIOLATION — seed the miss at the CALLER `middle`; leave the leaf correct. Must be CAUGHT on middle.
        var doc = JsonParser.parseString(reportText).getAsJsonObject();
        for (var el : doc.getAsJsonArray("functions")) {
            var f = el.getAsJsonObject();
            if (f.get("fn").getAsString().equals("app.Main.middle")) f.add("inferred", new com.google.gson.JsonArray());
        }
        Path seeded = tmp.resolve("trans-seeded-caller.json");
        Files.writeString(seeded, doc.toString());
        Files.copy(tmp.resolve("trans-report.callgraph.json"), tmp.resolve("trans-seeded-caller.callgraph.json"));
        Run viol = runVerifyJar(jar, cls, seeded);
        JsonObject vm = metrics(viol.stdout());
        assertFalse(vm.get("honestyInvariantHolds").getAsBoolean(), "a transitive-caller miss must VIOLATE; stdout=" + viol.stdout());
        assertEquals(1, viol.exit(), "a cardinal-sin violation exits 1");
        var vArr = JsonParser.parseString(viol.stdout()).getAsJsonObject().getAsJsonArray("violations");
        assertTrue(java.util.stream.StreamSupport.stream(vArr.spliterator(), false)
                .anyMatch(e -> "app.Main.middle".equals(e.getAsJsonObject().get("fn").getAsString())),
                "the violation is on the CALLER middle, not only the leaf; stdout=" + viol.stdout());
    }

    @Test
    void transitiveAttributionResolvesOverloadedCallerCorrectly() throws Exception {
        // Transitive attribution resolves each stack frame's candor qual through a registry keyed on the method
        // DESCRIPTOR (a bare frame carries no overload info). This guards that path: an OVERLOADED caller —
        // `middle(String)` reaches Fs, `middle(int)` is pure — must attribute the effect to the EXACT overload
        // that ran. Seed `middle(String)` pure → the violation must land on `app.Main.middle(String)`, and
        // `middle(int)` must stay clean (no misattribution across overloads = no spurious violation, no silent miss).
        Path jar = shadowJar();
        Assumptions.assumeTrue(jar != null, "no built shadowJar (run ./gradlew shadowJar) — skip end-to-end");
        Path cls = compileOverloadFixture();
        Path report = tmp.resolve("ovl-report.json");
        Process scan = new ProcessBuilder(
                System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                cls.toString(), "--json", report.toString())
                .redirectErrorStream(true).start();
        drain(scan.getInputStream());
        assertEquals(0, scan.waitFor(), "scan must succeed");
        String reportText = Files.readString(report);
        assertTrue(fnInferred(JsonParser.parseString(reportText).getAsJsonObject(), "app.Main.middle(String)").contains("Fs"),
                "candor reports the Fs-reaching overload middle(String) as Fs (transitive)");
        // seed ONLY middle(String) pure → violation must be on middle(String), not middle(int).
        var doc = JsonParser.parseString(reportText).getAsJsonObject();
        for (var el : doc.getAsJsonArray("functions"))
            if (el.getAsJsonObject().get("fn").getAsString().equals("app.Main.middle(String)"))
                el.getAsJsonObject().add("inferred", new com.google.gson.JsonArray());
        Path seeded = tmp.resolve("ovl-seed.json");
        Files.writeString(seeded, doc.toString());
        Files.copy(tmp.resolve("ovl-report.callgraph.json"), tmp.resolve("ovl-seed.callgraph.json"));
        Run viol = runVerifyJar(jar, cls, seeded);
        var vArr = JsonParser.parseString(viol.stdout()).getAsJsonObject().getAsJsonArray("violations");
        assertEquals(1, viol.exit(), "exactly the seeded overload violates; stdout=" + viol.stdout());
        assertTrue(java.util.stream.StreamSupport.stream(vArr.spliterator(), false)
                .anyMatch(e -> "app.Main.middle(String)".equals(e.getAsJsonObject().get("fn").getAsString())),
                "the violation lands on the exact overload middle(String); stdout=" + viol.stdout());
        assertFalse(java.util.stream.StreamSupport.stream(vArr.spliterator(), false)
                .anyMatch(e -> "app.Main.middle(int)".equals(e.getAsJsonObject().get("fn").getAsString())),
                "the pure overload middle(int) must NOT be misattributed a violation; stdout=" + viol.stdout());
    }

    /** Fixture: an OVERLOADED caller — middle(String) reaches Fs, middle(int) is pure — to stress the transitive
     *  attribution's descriptor-keyed overload registry. */
    private Path compileOverloadFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path target = tmp.resolve("ovl-data.txt");
        Files.writeString(target, "hello");
        Path src = tmp.resolve("Main.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "import java.nio.file.Files;",
            "import java.nio.file.Path;",
            "public class Main {",
            "  static void leaf(String p) throws Exception { Files.readAllBytes(Path.of(p)); }",
            "  static void middle(String p) throws Exception { leaf(p); }",  // reaches Fs
            "  static void middle(int n) { if (n < 0) throw new IllegalStateException(); }",  // pure
            "  public static void main(String[] a) throws Exception { middle(" + gstr(target.toString()) + "); middle(3); }",
            "}"));
        Path out = tmp.resolve("ocls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "overload fixture must compile");
        return out;
    }

    private static java.util.Set<String> fnInferred(JsonObject report, String fn) {
        var out = new java.util.HashSet<String>();
        for (var el : report.getAsJsonArray("functions")) {
            var f = el.getAsJsonObject();
            if (f.get("fn").getAsString().equals(fn) && f.has("inferred"))
                f.getAsJsonArray("inferred").forEach(e -> out.add(e.getAsString()));
        }
        return out;
    }

    @Test
    void asyncSubmitterAcrossThreadHandoffIsThePerThreadBoundary() throws Exception {
        // DOCUMENTED BOUNDARY (not a bug to fix): the transitive stack walk is PER-THREAD. An effect performed on
        // a pool/worker thread attributes to that worker's stack (the task body + its leaf), NOT to the caller that
        // SUBMITTED the task and has since returned on another thread. So a same-thread caller miss is caught
        // (transitiveCallerMissIsCaught), but an async submitter's miss is not — its runtime `charged` set is empty
        // because the effect surfaced on the worker. This test pins that boundary in BOTH directions: the pool
        // task body IS witnessed (within-thread transitive attribution works), and the seeded-pure submitter is
        // NOT flagged (the cross-handoff edge the walk cannot reach). If cross-thread attribution is ever added,
        // this test should be revisited.
        Path jar = shadowJar();
        Assumptions.assumeTrue(jar != null, "no built shadowJar (run ./gradlew shadowJar) — skip end-to-end");
        Path cls = compileAsyncFixture();
        Path report = tmp.resolve("async-report.json");
        Process scan = new ProcessBuilder(System.getProperty("java.home") + "/bin/java", "-jar", jar.toString(),
                cls.toString(), "--json", report.toString()).redirectErrorStream(true).start();
        drain(scan.getInputStream());
        assertEquals(0, scan.waitFor(), "scan must succeed");
        String reportText = Files.readString(report);
        // (a) within-worker-thread attribution works: the task body (a lambda) is witnessed Fs and holds.
        Run hold = runVerifyJar(jar, cls, report);
        var rows = JsonParser.parseString(hold.stdout()).getAsJsonObject().getAsJsonArray("rows");
        assertTrue(java.util.stream.StreamSupport.stream(rows.spliterator(), false)
                .anyMatch(e -> e.getAsJsonObject().get("fn").getAsString().contains("lambda")
                        && "sound-complete-ok".equals(e.getAsJsonObject().get("verdict").getAsString())),
                "the pool task body (lambda) is witnessed Fs on the worker thread; stdout=" + hold.stdout());
        // (b) the cross-handoff boundary: seed the SUBMITTER `submit` pure — it reaches Fs only via the pool, so
        // the per-thread walk does NOT witness it → HOLDS (the documented limitation, not a false all-clear the
        // oracle claims to catch: candor over-reported here, and an under-report across this edge is the residual).
        var doc = JsonParser.parseString(reportText).getAsJsonObject();
        for (var el : doc.getAsJsonArray("functions"))
            if (el.getAsJsonObject().get("fn").getAsString().equals("app.Main.submit"))
                el.getAsJsonObject().add("inferred", new com.google.gson.JsonArray());
        Path seeded = tmp.resolve("async-seed.json");
        Files.writeString(seeded, doc.toString());
        Files.copy(tmp.resolve("async-report.callgraph.json"), tmp.resolve("async-seed.callgraph.json"));
        Run viol = runVerifyJar(jar, cls, seeded);
        JsonObject vm = metrics(viol.stdout());
        assertTrue(vm.get("honestyInvariantHolds").getAsBoolean(),
                "per-thread boundary: an async submitter's miss is NOT witnessed (effect fires on the worker); stdout=" + viol.stdout());
    }

    /** Fixture: main → submit(pool) → [worker thread] lambda → leaf(Fs). The Fs fires on the pool thread. */
    private Path compileAsyncFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path target = tmp.resolve("async-data.txt");
        Files.writeString(target, "hello");
        Path src = tmp.resolve("Main.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "import java.nio.file.*;",
            "import java.util.concurrent.*;",
            "public class Main {",
            "  static void leaf(String p) throws Exception { Files.readAllBytes(Path.of(p)); }",
            "  static void submit(ExecutorService ex, String p) { ex.submit(() -> { try { leaf(p); } catch (Exception e) {} }); }",
            "  public static void main(String[] a) throws Exception {",
            "    ExecutorService ex = Executors.newSingleThreadExecutor();",
            "    submit(ex, " + gstr(target.toString()) + ");",
            "    ex.shutdown(); ex.awaitTermination(5, TimeUnit.SECONDS);",
            "  }",
            "}"));
        Path out = tmp.resolve("acls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "async fixture must compile");
        return out;
    }

    /** Fixture: main → middle → leaf, where only `leaf` calls java.nio (Fs); `middle`/`main` are transitive. */
    private Path compileTransitiveFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path target = tmp.resolve("trans-data.txt");
        Files.writeString(target, "hello");
        Path src = tmp.resolve("Main.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "import java.nio.file.Files;",
            "import java.nio.file.Path;",
            "public class Main {",
            "  static void leaf(String p) throws Exception { Files.readAllBytes(Path.of(p)); }",
            "  static void middle(String p) throws Exception { leaf(p); }",   // transitive caller, no direct effect
            "  public static void main(String[] a) throws Exception { middle(" + gstr(target.toString()) + "); }",
            "}"));
        Path out = tmp.resolve("tcls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "transitive fixture must compile");
        return out;
    }

    /** Fixture: an effectful method that fully runs (Fs witnessed) and then the program exits NON-ZERO. */
    private Path compileExitNonZeroFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path target = tmp.resolve("exit-data.txt");
        Files.writeString(target, "hello");
        Path src = tmp.resolve("Main.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "import java.nio.file.Files;",
            "import java.nio.file.Path;",
            "public class Main {",
            "  static void reads(String p) throws Exception { Files.readAllBytes(Path.of(p)); }",
            "  public static void main(String[] a) throws Exception {",
            "    reads(" + gstr(target.toString()) + ");",  // effect fully runs + is flushed
            "    System.exit(3);",                          // ...then a non-zero exit
            "  }",
            "}"));
        Path out = tmp.resolve("xcls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "exit fixture must compile");
        return out;
    }

    /** Fixture: an effectful method whose control-flow merge is over two SUBCLASSES of the enclosing class, so the
     *  merge's stack-map frame type is the enclosing class itself — recomputing it force-loads a class whose
     *  supertype is mid-definition (the reentrancy that raised the duplicate-definition LinkageError). */
    private Path compileReentrantFrameFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path target = tmp.resolve("reentr-data.txt");
        Files.writeString(target, "hello");
        Path src = tmp.resolve("Main.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "import java.nio.file.Files;",
            "import java.nio.file.Path;",
            "public class Main {",
            "  static class Base {",
            "    Base pick(boolean c, String path) throws Exception {",
            "      Base b = c ? new Sub1() : new Sub2();",  // merge over subclasses → frame type = Base (mid-load)
            "      Files.readAllBytes(Path.of(path));",     // Fs leaf ⇒ Base.pick is instrumented
            "      return b;",
            "    }",
            "  }",
            "  static class Sub1 extends Base {}",
            "  static class Sub2 extends Base {}",
            "  public static void main(String[] a) throws Exception {",
            "    new Base().pick(a.length == 0, " + gstr(target.toString()) + ");",
            "  }",
            "}"));
        Path out = tmp.resolve("rcls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "reentrant fixture must compile");
        return out;
    }

    /** Fixture: a generic override (Task&lt;String&gt;.exec) that does Fs — javac emits a synthetic bridge exec(Object). */
    private Path compileBridgeFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path target = tmp.resolve("bridge-data.txt");
        Files.writeString(target, "hello");
        Path src = tmp.resolve("Main.java");
        Files.writeString(src, String.join("\n",
            "package app;",
            "import java.nio.file.Files;",
            "import java.nio.file.Path;",
            "public class Main {",
            "  abstract static class Task<T> { abstract void exec(T p) throws Exception; }",
            "  static class FileTask extends Task<String> {",
            "    void exec(String path) throws Exception { Files.readAllBytes(Path.of(path)); }",
            "  }",
            "  public static void main(String[] a) throws Exception {",
            "    new FileTask().exec(" + gstr(target.toString()) + ");",
            "  }",
            "}"));
        Path out = tmp.resolve("bcls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "bridge fixture must compile");
        return out;
    }
}
