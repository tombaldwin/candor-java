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
}
