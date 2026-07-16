package io.poly.candor;

import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The CLI / GATE / adversarial-input BEHAVIOUR MATRIX, asserted via a real subprocess (split stdout/stderr +
 * exit code) — this layer (argument parsing, the gate exit-code contract, fail-closed on unreadable/malformed
 * input) is where the well-tested analysis core's guarantees meet the shell, and where the bugs this session
 * found actually lived. JsonStdoutGateTest pins the --json + gate stream-split; this is the broader grid:
 * bare scan, --json with/without a gate, the --policy exit codes (1 violating / 0 clean / 2 unreadable —
 * NEVER gate-green on a missing policy), --version/-V/--help/-h, unknown-flag rejection, and the
 * robustness cases (corrupt jar, truncated zip, empty jar, nonexistent path, empty dir, a dir of non-class
 * files) which must all be a clean one-line stderr + exit 2 with NO stack trace.
 *
 * main() calls System.exit, so the CLI runs as a subprocess (reusing the test JVM's classpath, which Gradle
 * populates with the main classes + asm/gson) — the same harness as JsonStdoutGateTest.
 */
class CliBehaviourTest {

    private record Run(int exit, String stdout, String stderr) {}

    /** Run `java -cp <test-jvm-classpath> io.poly.candor.Candor <args...>` and capture the split streams. */
    private static Run runCli(String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        int code = p.waitFor();
        return new Run(code, out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    /** No stack trace ever leaks to the user — a raw exception dump is the failure mode these robustness
     *  cases guard against (a clean one-liner is the contract, not a `at io.poly...` trace). */
    private static void assertNoStackTrace(Run r) {
        assertFalse(r.stderr().contains("\tat ") || r.stderr().contains("Exception in thread"),
                "no raw stack trace may reach the user\nSTDERR:\n" + r.stderr());
    }

    // ── fixtures ─────────────────────────────────────────────────────────────────────────────────────
    // A scratch tree per test (cleaned in @AfterEach); javac-compiled fixtures live under it.

    private Path scratch;

    @BeforeEach
    void mkScratch() throws Exception {
        scratch = Files.createTempDirectory("candor-cli");
    }

    @AfterEach
    void rmScratch() throws Exception {
        if (scratch == null || !Files.exists(scratch)) return;
        try (Stream<Path> s = Files.walk(scratch)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private static javax.tools.JavaCompiler compiler() {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        return jc;
    }

    /** A Net-performing class (opens a URL connection) compiled into {@code <scratch>/net} → classes dir. */
    private Path compileNetFixture() throws Exception {
        javax.tools.JavaCompiler jc = compiler();
        Path src = scratch.resolve("Svc.java");
        Files.writeString(src, """
            package app;
            import java.net.URL;
            public class Svc {
                public void fetch() throws Exception {
                    new URL("http://example.com").openConnection().getInputStream();
                }
            }
            """);
        Path out = scratch.resolve("net");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "fixture must compile");
        return out;
    }

    /** A pure class (no effects) compiled into {@code <scratch>/pure} → classes dir. */
    private Path comparePureFixture() throws Exception {
        javax.tools.JavaCompiler jc = compiler();
        Path src = scratch.resolve("Pure.java");
        Files.writeString(src, """
            package app;
            public class Pure {
                public int add(int a, int b) { return a + b; }
            }
            """);
        Path out = scratch.resolve("pure");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "fixture must compile");
        return out;
    }

    private Path policy(String body) throws Exception {
        Path p = scratch.resolve("p" + Integer.toHexString(body.hashCode()) + ".policy");
        Files.writeString(p, body);
        return p;
    }

    // ── bare scan ────────────────────────────────────────────────────────────────────────────────────

    @Test
    void bareScanPrintsAReportAndExitsZero() throws Exception {
        Run r = runCli(compileNetFixture().toString());
        assertEquals(0, r.exit(), "a bare scan (no gate) always succeeds\nSTDERR:\n" + r.stderr());
        assertTrue(r.stdout().contains("effect audit"), "the human report goes to stdout\nSTDOUT:\n" + r.stdout());
        assertTrue(r.stdout().contains("Net"), "the Net effect must be reported");
    }

    // ── --json (no gate) ─────────────────────────────────────────────────────────────────────────────

    @Test
    void bareJsonStreamsPureJsonAndWritesNoFiles() throws Exception {
        Path classes = compileNetFixture();
        Run r = runCli(classes.toString(), "--json");
        assertEquals(0, r.exit(), "bare --json (no gate) exits 0\nSTDERR:\n" + r.stderr());
        JsonParser.parseString(r.stdout()); // stdout PARSES as JSON (throws otherwise)
        // bare --json is the "-" sentinel: report ENVELOPE to stdout, NO sidecar/report files on disk.
        try (Stream<Path> s = Files.walk(classes)) {
            assertFalse(s.anyMatch(p -> p.getFileName().toString().endsWith(".json")),
                    "bare --json must NOT write any report/sidecar .json file");
        }
    }

    // ── --json + gate: stdout stays pure JSON, the human gate text is on stderr ──────────────────────

    @Test
    void jsonWithViolatingPolicyKeepsStdoutPureAndPutsViolationOnStderr() throws Exception {
        Run r = runCli(compileNetFixture().toString(), "--json", "--policy", policy("deny Net\n").toString());
        assertEquals(1, r.exit(), "a denied Net effect fails the gate (exit 1)\nSTDERR:\n" + r.stderr());
        assertFalse(r.stdout().isBlank(), "the --json report must stream to stdout");
        JsonParser.parseString(r.stdout()); // pure JSON on stdout
        assertFalse(r.stdout().contains("AS-EFF"), "the AS-EFF violation must NOT bleed into stdout JSON\nSTDOUT:\n" + r.stdout());
        assertTrue(r.stderr().contains("AS-EFF"), "the AS-EFF violation belongs on stderr\nSTDERR:\n" + r.stderr());
    }

    @Test
    void jsonWithCleanPolicyKeepsStdoutPureAndExitsZero() throws Exception {
        Run r = runCli(compileNetFixture().toString(), "--json", "--policy", policy("deny Fs\n").toString());
        assertEquals(0, r.exit(), "no Fs effect → the gate passes (exit 0)\nSTDERR:\n" + r.stderr());
        JsonParser.parseString(r.stdout()); // pure JSON on stdout
        assertFalse(r.stdout().contains("no violations"), "the no-violations line must be on stderr, not stdout");
    }

    // ── --policy exit-code contract (no --json) ──────────────────────────────────────────────────────

    @Test
    void policyViolatingExitsOne() throws Exception {
        Run r = runCli(compileNetFixture().toString(), "--policy", policy("deny Net\n").toString());
        assertEquals(1, r.exit(), "a denied effect fails the gate (exit 1)\nSTDERR:\n" + r.stderr());
    }

    @Test
    void policyCleanExitsZero() throws Exception {
        Run r = runCli(compileNetFixture().toString(), "--policy", policy("deny Fs\n").toString());
        assertEquals(0, r.exit(), "no matching effect → the gate passes (exit 0)\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("no violations") || r.stdout().contains("no violations"),
                "a clean gate states it found no violations");
    }

    @Test
    void missingPolicyFileExitsTwoNeverGateGreen() throws Exception {
        // a non-empty real scan target so we reach the policy stage; the policy path does not exist.
        Run r = runCli(comparePureFixture().toString(), "--policy", scratch.resolve("nope.policy").toString());
        assertEquals(2, r.exit(), "an unreadable policy must FAIL (exit 2), never silently pass gateless\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void directoryAsPolicyExitsTwo() throws Exception {
        // a directory is not a readable policy file → exit 2 (fail-closed), not gate-green.
        Path dir = scratch.resolve("poldir");
        Files.createDirectories(dir);
        Run r = runCli(comparePureFixture().toString(), "--policy", dir.toString());
        assertEquals(2, r.exit(), "a directory-as-policy must FAIL (exit 2)\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void valuelessPolicyFlagExitsTwo() throws Exception {
        Run r = runCli(comparePureFixture().toString(), "--policy");
        assertEquals(2, r.exit(), "a valueless --policy must FAIL, never run gateless\nSTDERR:\n" + r.stderr());
    }

    // ── --version / -V / --help / -h ─────────────────────────────────────────────────────────────────

    @Test
    void versionPrintsBuildAndSpecAndExitsZero() throws Exception {
        for (String flag : new String[] {"--version", "-V"}) {
            Run r = runCli(flag);
            assertEquals(0, r.exit(), flag + " exits 0\nSTDERR:\n" + r.stderr());
            // contract: `candor-java <ver> (spec <X>)` — assert the shape + the spec version, not the
            // exact release string (it is baked from the build and changes every release).
            assertTrue(r.stdout().matches("(?s)candor-java \\S+ \\(spec " + Candor.SPEC_VERSION + "\\).*"),
                    flag + " must print `candor-java <ver> (spec " + Candor.SPEC_VERSION + ")`\nSTDOUT:\n" + r.stdout());
        }
    }

    @Test
    void helpPrintsUsageAndExitsZero() throws Exception {
        for (String flag : new String[] {"--help", "-h"}) {
            Run r = runCli(flag);
            assertEquals(0, r.exit(), flag + " exits 0\nSTDERR:\n" + r.stderr());
            assertTrue(r.stdout().contains("USAGE") || r.stdout().toLowerCase().contains("usage"),
                    flag + " must print usage\nSTDOUT:\n" + r.stdout());
        }
    }

    // ── unknown-flag rejection ───────────────────────────────────────────────────────────────────────

    @Test
    void unknownFlagExitsTwo() throws Exception {
        Run r = runCli(comparePureFixture().toString(), "--bogus");
        assertEquals(2, r.exit(), "an unknown --flag must FAIL (exit 2)\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("unknown flag"), "must diagnose the unknown flag\nSTDERR:\n" + r.stderr());
    }

    @Test
    void bareDashExitsTwo() throws Exception {
        Run r = runCli(comparePureFixture().toString(), "-");
        assertEquals(2, r.exit(), "a bare `-` is an unknown flag (candor reads no stdin) → exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("unknown flag -"), "must diagnose the bare dash\nSTDERR:\n" + r.stderr());
    }

    // ── adversarial / robustness: clean one-line stderr + exit 2, NO stack trace ─────────────────────

    @Test
    void corruptJarExitsTwoNoStackTrace() throws Exception {
        Path bad = scratch.resolve("bad.jar");
        Files.writeString(bad, "this is plainly not a zip archive");
        Run r = runCli(bad.toString());
        assertEquals(2, r.exit(), "a corrupt jar must be a clean exit 2\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
        assertTrue(r.stderr().contains("candor"), "the diagnostic must be candor's, not a raw dump");
    }

    @Test
    void truncatedZipExitsTwoNoStackTrace() throws Exception {
        // a valid local-file-header prefix with no central directory / END record — a truncated zip.
        Path trunc = scratch.resolve("trunc.jar");
        Files.write(trunc, new byte[] {'P', 'K', 3, 4, 20, 0, 0, 0, 8, 0, 1, 2, 3, 4});
        Run r = runCli(trunc.toString());
        assertEquals(2, r.exit(), "a truncated zip must be a clean exit 2\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void emptyJarExitsTwo() throws Exception {
        // a structurally valid but empty zip (just the end-of-central-directory record) → no .class files.
        Path empty = scratch.resolve("empty.jar");
        Files.write(empty, new byte[] {'P', 'K', 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        Run r = runCli(empty.toString());
        assertEquals(2, r.exit(), "an empty jar (no .class) must FAIL (exit 2), not read as a clean pure project\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void nonexistentPathExitsTwoNoStackTrace() throws Exception {
        Run r = runCli(scratch.resolve("does-not-exist.jar").toString());
        assertEquals(2, r.exit(), "a nonexistent path must be a clean exit 2\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
        assertTrue(r.stderr().contains("no such path"), "must diagnose the missing path\nSTDERR:\n" + r.stderr());
    }

    @Test
    void emptyDirExitsTwo() throws Exception {
        Path dir = scratch.resolve("emptydir");
        Files.createDirectories(dir);
        Run r = runCli(dir.toString());
        assertEquals(2, r.exit(), "an empty dir (no .class) must FAIL (exit 2), not read as clean/pure\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
        assertTrue(r.stderr().contains("nothing to analyze"), "must say there was nothing to analyze\nSTDERR:\n" + r.stderr());
    }

    @Test
    void dirOfNonClassFilesExitsTwo() throws Exception {
        Path dir = scratch.resolve("txtdir");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("readme.txt"), "not bytecode");
        Files.writeString(dir.resolve("data.json"), "{}");
        Run r = runCli(dir.toString());
        assertEquals(2, r.exit(), "a dir with no .class files must FAIL (exit 2)\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    // ── --gate-json (spec 0.17): the structured gate verdict, end-to-end through the real CLI ────────────

    @Test
    void gateJsonWritesTheVerdictWithEffectsAndFailsClosed() throws Exception {
        // The whole flag path: parse --gate-json, run the gate, write { spec, ok, violations[] } — and the
        // file MUST agree with the exit code (a violation ⇒ ok:false ⇒ exit 1). Covers writeGateJson + the
        // envelope + the denied `effects`, which the unit-level GateJsonTest (checkPolicy only) can't reach.
        Path classes = compileNetFixture();
        Path pol = scratch.resolve("p.policy");
        Files.writeString(pol, "deny Net app\n");
        Path out = scratch.resolve("gate.json");
        Run r = runCli(classes.toString(), "--policy", pol.toString(), "--gate-json", out.toString());
        assertEquals(1, r.exit(), "a violation fails the gate\nSTDERR:\n" + r.stderr());
        assertTrue(Files.exists(out), "the verdict file is written (before exit)");
        var v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertEquals(Candor.SPEC_VERSION, v.get("spec").getAsString(), "verdict declares the spec version");
        assertFalse(v.get("ok").getAsBoolean(), "ok:false on a failing gate");
        var viol = v.getAsJsonArray("violations");
        assertEquals(1, viol.size(), "one violation");
        var e = viol.get(0).getAsJsonObject();
        assertEquals("AS-EFF-006", e.get("rule").getAsString());
        assertEquals("app.Svc.fetch", e.get("fn").getAsString());
        assertEquals(1, e.getAsJsonArray("effects").size());
        assertEquals("Net", e.getAsJsonArray("effects").get(0).getAsString(), "effects = the denied set");
        assertTrue(e.get("detail").getAsString().contains("forbidden by policy"), "detail carries the message");
    }

    @Test
    void gateJsonOnACleanRunWritesOkTrueEmpty() throws Exception {
        // No gate configured + --gate-json ⇒ the clean verdict, exit 0. (The `enforce` path must still emit.)
        Path out = scratch.resolve("gate.json");
        Run r = runCli(comparePureFixture().toString(), "--gate-json", out.toString());
        assertEquals(0, r.exit(), "a clean run passes\nSTDERR:\n" + r.stderr());
        var v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertTrue(v.get("ok").getAsBoolean(), "ok:true on a clean run");
        assertEquals(0, v.getAsJsonArray("violations").size(), "no violations");
    }

    @Test
    void candorConfigDrivesTheGate() throws Exception {
        // .candor/config (via CANDOR_CONFIG) supplies the policy — NO --policy flag, NO CANDOR_POLICY. The
        // config layer must reach main()'s gate resolution end to end (exit 1 on the Net violation).
        Path classes = compileNetFixture();
        Path pol = scratch.resolve("p.policy");
        Files.writeString(pol, "deny Net app\n");
        Path cfg = scratch.resolve("config");
        Files.writeString(cfg, "# checked-in\npolicy " + pol + "\n");

        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", cp, "io.poly.candor.Candor", classes.toString());
        pb.environment().put("CANDOR_CONFIG", cfg.toString());
        Process p = pb.start();
        String err = drain(p.getErrorStream());
        int code = p.waitFor();
        assertEquals(1, code, ".candor/config's policy must gate the run (exit 1 on the Net violation)\nSTDERR:\n" + err);
    }

    @Test
    void gateJsonValuelessFailsClosed() throws Exception {
        // A valueless gate flag must FAIL (exit 2), never silently run without emitting — like --policy/--json.
        Run r = runCli(comparePureFixture().toString(), "--gate-json");
        assertEquals(2, r.exit(), "a valueless --gate-json must fail (exit 2)\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void gateJsonDashWritesTheVerdictToStdout() throws Exception {
        // `--gate-json -` streams the verdict to stdout (the pipe form, like `--json`) — and stdout MUST
        // be PURE JSON: the AS-EFF lines / "no violations" go to stderr, else the piped verdict is
        // unparseable (`… --gate-json - | candor-sarif` was the broken consumer).
        Path classes = compileNetFixture();
        Path pol = scratch.resolve("p.policy");
        Files.writeString(pol, "deny Net app\n");
        Run r = runCli(classes.toString(), "--policy", pol.toString(), "--gate-json", "-");
        assertEquals(1, r.exit());
        var v = JsonParser.parseString(r.stdout()).getAsJsonObject();   // parses ⇔ stdout is pure JSON
        assertFalse(v.get("ok").getAsBoolean());
        assertTrue(r.stderr().contains("[AS-EFF-006]"),
                "the human AS-EFF line goes to stderr in --gate-json - mode\nSTDERR:\n" + r.stderr());
    }

    @Test
    void corruptBaselineFailsClosedNotOpen() throws Exception {
        // A present-but-unparseable baseline is invalid gate input → exit 2, not a fail-open note.
        Path classes = compileNetFixture();
        Path base = scratch.resolve("corrupt-baseline.json");
        Files.writeString(base, "<<<<<<< HEAD\n{\"functions\":[]}\n=======  garbage");
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", cp, "io.poly.candor.Candor", classes.toString());
        pb.environment().put("CANDOR_BASELINE", base.toString());
        Process p = pb.start();
        String err = drain(p.getErrorStream());
        assertEquals(2, p.waitFor(), "a corrupt baseline must fail closed\nSTDERR:\n" + err);
        assertTrue(err.contains("could not be parsed"), err);
    }

    @Test
    void corruptBaselineSidecarFailsClosedNotOpen() throws Exception {
        // ⟨0.16⟩ The baseline callgraph sidecar keys the guard's existence check (it lists the pure
        // leaves the report omits). A PRESENT-but-corrupt sidecar is invalid gate input → exit 2, exactly
        // like a corrupt baseline REPORT: it must not silently narrow the guard to report-only existence
        // (dropping the pure-leaf nodes would let a formerly-pure→effectful gain masquerade as new code).
        Path classes = compileNetFixture();
        // 1) produce a real baseline (report + valid .callgraph.json sidecar) from this same build.
        Path base = scratch.resolve("baseline"); // --json <path>: report at <path>, sidecar at <path>.callgraph.json
        Run scan = runCli(classes.toString(), "--json", base.toString());
        assertEquals(0, scan.exit(), "the baseline scan itself must succeed\nSTDERR:\n" + scan.stderr());
        Path sidecar = scratch.resolve("baseline.callgraph.json");
        assertTrue(Files.exists(sidecar), "the scan must have emitted the callgraph sidecar");
        // 2) corrupt the sidecar (truncate to `{`), then rescan with the baseline guard active.
        Files.writeString(sidecar, "{");
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", cp, "io.poly.candor.Candor", classes.toString());
        pb.environment().put("CANDOR_BASELINE", base.toString());
        Process p = pb.start();
        String err = drain(p.getErrorStream());
        String out = drain(p.getInputStream());
        assertEquals(2, p.waitFor(), "a corrupt baseline sidecar must fail closed (exit 2)\nSTDERR:\n" + err);
        assertTrue(err.contains("call-graph sidecar") && err.contains("corrupt"),
                "the message names the corrupt sidecar and the fail-closed posture: " + err);
        assertFalse(out.contains("[AS-EFF-005]") || err.contains("[AS-EFF-005]"),
                "the guard must NOT evaluate on a corrupt sidecar — no 005 finding");
    }

    @Test
    void staleBaselineFailsClosedWithoutEvaluating() throws Exception {
        // The aligned family posture: a baseline from another engine build is INVALID GATE INPUT — the
        // unreadable-policy class. No AS-EFF-005 wave (evaluation would be semi-garbage), no silent skip
        // (an unbounded fail-open window): one clear message, exit 2.
        Path classes = compileNetFixture();
        Path base = scratch.resolve("stale-baseline.json");
        Files.writeString(base, "{\"candor\":{\"version\":\"aaaaaaa\"},\"functions\":[]}");
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", cp, "io.poly.candor.Candor", classes.toString());
        pb.environment().put("CANDOR_BASELINE", base.toString());
        Process p = pb.start();
        String err = drain(p.getErrorStream());
        String out = drain(p.getInputStream());
        assertEquals(2, p.waitFor(), "a stale baseline fails closed\nSTDERR:\n" + err);
        assertTrue(err.contains("baseline-invalidating") && err.contains("aaaaaaa"),
                "the message names the posture and the stale build: " + err);
        assertFalse(out.contains("AS-EFF-005") || err.contains("[AS-EFF-005]"),
                "no bogus 005 wave — the gate refuses to evaluate stale input");
    }

    @Test
    void gateJsonRejectsAFlagShapedValue() throws Exception {
        // `--gate-json --policy arch.policy` must FAIL (exit 2) — without the dash-check it swallowed
        // `--policy` as the verdict path and the displaced `arch.policy` was silently dropped: a GATELESS
        // green run (found by the max review against the released 0.8.0 jar).
        Path classes = compileNetFixture();
        Path pol = scratch.resolve("arch.policy");
        Files.writeString(pol, "deny Net app\n");
        Run r = runCli(classes.toString(), "--gate-json", "--policy", pol.toString());
        assertEquals(2, r.exit(), "a flag-shaped --gate-json value must fail closed\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void unexpectedBarePositionalFailsClosed() throws Exception {
        // The scan grammar has exactly ONE positional (the target): a stray bare token is a displaced
        // value or a typo, and silently ignoring it is the other half of the gateless-green chain.
        Run r = runCli(comparePureFixture().toString(), "stray.policy");
        assertEquals(2, r.exit(), "an unexpected bare argument must fail (exit 2)\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void candorConfigTypoFailsClosed() throws Exception {
        // CANDOR_CONFIG set to a missing path must FAIL (exit 2) — a configured gate source silently
        // ignored is the §6.2 gateless-green class (the config may carry the policy).
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", cp, "io.poly.candor.Candor",
                comparePureFixture().toString());
        pb.environment().put("CANDOR_CONFIG", scratch.resolve("no-such-config").toString());
        Process p = pb.start();
        String err = drain(p.getErrorStream());
        assertEquals(2, p.waitFor(), "a typo'd CANDOR_CONFIG must fail closed\nSTDERR:\n" + err);
    }

    @Test
    void candorConfigIsDiscoveredFromTheScanTarget() throws Exception {
        // The checked-in config is anchored to the SCAN TARGET (walk up from <repo>/classes to
        // <repo>/.candor/config), NOT the process CWD — the test JVM's CWD is the gradle project, which
        // has no .candor/config, so a pass here proves target-anchored discovery.
        Path classes = compileNetFixture();                       // <scratch>/net
        Path pol = scratch.resolve("arch.policy");
        Files.writeString(pol, "deny Net app\n");
        Files.createDirectories(scratch.resolve(".candor"));
        Files.writeString(scratch.resolve(".candor/config"), "policy " + pol + "\n");
        Run r = runCli(classes.toString());                       // absolute target; CWD elsewhere
        assertEquals(1, r.exit(), "the repo's .candor/config (found via the target's ancestors) must gate\n"
                + "STDERR:\n" + r.stderr() + "\nSTDOUT:\n" + r.stdout());
    }

    @Test
    void gainsCorruptBaselineDisclosesOnStderrAndKeepsStdoutEmpty() throws Exception {
        // `gains --json` stdout is a MACHINE channel: a corrupt baseline must be exit 2 with the
        // disclosure on STDERR and NOTHING on stdout — the old handler printed the diagnostic on
        // stdout (garbage to a JSON consumer) and left stderr empty where the corrupt-report
        // loudness rule wants it.
        Path cur = scratch.resolve("cur.json");
        Files.writeString(cur, "{\"candor\":{},\"functions\":[{\"fn\":\"app.Svc.fetch\",\"inferred\":[\"Net\"]}]}");
        Path base = scratch.resolve("base.json");
        Files.writeString(base, "[1,2,3]"); // parses as JSON; every entry malformed — a corrupt report
        Run r = runCli("gains", cur.toString(), base.toString(), "--json");
        assertEquals(2, r.exit(), "a corrupt gains baseline is exit 2\nSTDERR:\n" + r.stderr());
        assertEquals("", r.stdout(), "the --json stdout channel stays EMPTY on a corrupt baseline");
        assertTrue(r.stderr().contains("cannot read baseline"),
                "stderr carries the disclosure\nSTDERR:\n" + r.stderr());
        assertNoStackTrace(r);
    }

    @Test
    void gainsPartialBaselineCallgraphYieldsUnknownOriginNotNew() throws Exception {
        // A PARTIAL baseline callgraph (a matched sidecar existed but is corrupt) must label a fn known
        // only to the dropped sidecar "unknown", never "new" — "new" downgrades the supply-chain attack
        // signal (existing fn gained an effect) to a feature. Two reports under one prefix; sidecar `a`
        // is readable, sidecar `b` is corrupt.
        Files.writeString(scratch.resolve("base.a.jvm.json"),
                "{\"candor\":{},\"functions\":[{\"fn\":\"app.F.f\",\"inferred\":[\"Fs\"]}]}");
        Files.writeString(scratch.resolve("base.a.jvm.callgraph.json"), "{\"app.H.h\":[]}");
        Files.writeString(scratch.resolve("base.b.jvm.json"), "{\"candor\":{},\"functions\":[]}");
        Files.writeString(scratch.resolve("base.b.jvm.callgraph.json"), "{corrupt"); // exists, unreadable
        Path cur = scratch.resolve("cur.json");
        Files.writeString(cur, "{\"candor\":{},\"functions\":["
                + "{\"fn\":\"app.F.f\",\"inferred\":[\"Fs\",\"Net\"]},"   // baseline-report hit → existing
                + "{\"fn\":\"app.G.g\",\"inferred\":[\"Net\"]},"          // only in the CORRUPT sidecar → unknown
                + "{\"fn\":\"app.H.h\",\"inferred\":[\"Net\"]}]}");        // readable sidecar node → existing
        Run r = runCli("gains", cur.toString(), scratch.resolve("base").toString(), "--json");
        assertEquals(0, r.exit(), "gains discloses, exit 0\nSTDERR:\n" + r.stderr());
        var byFn = new java.util.HashMap<String, String>();
        for (var e : JsonParser.parseString(r.stdout()).getAsJsonObject().getAsJsonArray("byFunction"))
            byFn.put(e.getAsJsonObject().get("fn").getAsString(),
                     e.getAsJsonObject().get("origin").getAsString());
        assertEquals("existing", byFn.get("app.F.f"), "a baseline-report hit is existing");
        assertEquals("existing", byFn.get("app.H.h"), "a readable-sidecar node is existing");
        assertEquals("unknown", byFn.get("app.G.g"),
                "a fn evidenced only by the DROPPED sidecar is unknown, not new\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("unreadable"),
                "the corrupt sidecar is disclosed on stderr\nSTDERR:\n" + r.stderr());
    }

    @Test
    void gainsForeignEngineSidecarNeverMintsNewOrigin() throws Exception {
        // A FOREIGN engine's report+sidecar (rust: `report.<crate>.scan.json` + `.callgraph.json`)
        // beside a sidecar-LESS jvm baseline must NOT make "the graph decides": rust quals (`m::f`)
        // can never contain JVM quals (`m.f`), so a foreign graph's "evidence" is systematically
        // absent and every gained fn would read "new" — downgrading the supply-chain attack signal
        // (existing fn gained an effect) to a feature. The union is ENGINE-OWNED (`.jvm.json`
        // siblings only): with no java sidecar the graph is ABSENT → origin "unknown", never "new".
        Files.writeString(scratch.resolve("base.app.jvm.json"),
                "{\"candor\":{},\"functions\":[{\"fn\":\"app.F.f\",\"inferred\":[\"Fs\"]}]}");
        // deliberately NO base.app.jvm.callgraph.json — the jvm baseline carries no sidecar
        Files.writeString(scratch.resolve("base.mycrate.scan.json"),
                "{\"candor\":{},\"functions\":[{\"fn\":\"mycrate::lib::run\",\"inferred\":[\"Net\"]}]}");
        Files.writeString(scratch.resolve("base.mycrate.scan.callgraph.json"),
                "{\"mycrate::lib::run\":[\"mycrate::util::fetch\"]}");
        Path cur = scratch.resolve("cur.json");
        Files.writeString(cur, "{\"candor\":{},\"functions\":["
                + "{\"fn\":\"app.F.f\",\"inferred\":[\"Fs\",\"Net\"]},"   // baseline-report hit → existing
                + "{\"fn\":\"app.G.g\",\"inferred\":[\"Net\"]}]}");        // absent + graph ABSENT → unknown
        Run r = runCli("gains", cur.toString(), scratch.resolve("base").toString(), "--json");
        assertEquals(0, r.exit(), "gains runs, exit 0\nSTDERR:\n" + r.stderr());
        var byFn = new java.util.HashMap<String, String>();
        for (var e : JsonParser.parseString(r.stdout()).getAsJsonObject().getAsJsonArray("byFunction"))
            byFn.put(e.getAsJsonObject().get("fn").getAsString(),
                     e.getAsJsonObject().get("origin").getAsString());
        assertEquals("existing", byFn.get("app.F.f"), "a baseline-report hit is existing");
        assertEquals("unknown", byFn.get("app.G.g"),
                "with no ENGINE-OWNED sidecar the graph is absent — a foreign graph must not decide\n"
                + "STDERR:\n" + r.stderr());
        assertFalse(byFn.containsValue("new"),
                "a foreign engine's graph can never mint \"new\"\nSTDOUT:\n" + r.stdout());
    }

    @Test
    void gateJsonUnwritablePathDoesNotCrashTheGate() throws Exception {
        // A bad --gate-json path must be a clean diagnostic, never a crash — and MUST NOT change the gate
        // verdict (the exit code is the source of truth; the verdict file is a surfacing side-output).
        Path classes = compileNetFixture();
        Path pol = scratch.resolve("p.policy");
        Files.writeString(pol, "deny Net app\n");
        Run r = runCli(classes.toString(), "--policy", pol.toString(),
                "--gate-json", scratch.resolve("no/such/dir/gate.json").toString());
        assertEquals(1, r.exit(), "the gate still fails on the violation despite the unwritable verdict path");
        assertNoStackTrace(r);
    }
}
