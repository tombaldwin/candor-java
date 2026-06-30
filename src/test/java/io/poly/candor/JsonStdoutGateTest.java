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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * [#1] `--json` stdout mode must be PURE JSON even when a gate runs. The earlier --json-stdout fix only
 * redirected the !enforce first-run summary to stderr; the GATE output path (the AS-EFF diagnostics via
 * diag() + the "no violations" line) still went to stdout, so `candor <classes> --json --policy p | jq`
 * produced malformed JSON. No test exercised --json + a gate, which is why it shipped.
 *
 * main() calls System.exit, so this runs the CLI as a SUBPROCESS (reusing the test JVM's classpath, which
 * Gradle populates with the main classes + asm/gson) and asserts the stdout/stderr split + exit code.
 */
class JsonStdoutGateTest {

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

    /** Compile a Net-performing class (opens a URL connection) into a temp dir; return the classes dir. */
    private static Path compileNetFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-jsongate");
        Path f = dir.resolve("Svc.java");
        Files.writeString(f, """
            package app;
            import java.net.URL;
            public class Svc {
                public void fetch() throws Exception {
                    new URL("http://example.com").openConnection().getInputStream();
                }
            }
            """);
        Path out = dir.resolve("cls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), f.toString()), "fixture must compile");
        return out;
    }

    private static void deleteTree(Path root) throws Exception {
        if (root == null || !Files.exists(root)) return;
        // walk up from the classes dir to the temp root created by createTempDirectory
        Path top = root.getParent() != null ? root.getParent() : root;
        try (Stream<Path> s = Files.walk(top)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Test
    void jsonStdoutStaysPureWhenAGateRunsAndViolates() throws Exception {
        Path classes = compileNetFixture();
        Path policy = Files.createTempFile("deny", ".policy");
        Files.writeString(policy, "deny Net\n");
        try {
            Run r = runCli(classes.toString(), "--json", "--policy", policy.toString());
            // exit 1 — the gate found a violation (app.Svc.fetch performs Net, denied)
            assertEquals(1, r.exit(), "a denied Net effect must fail the gate (exit 1)\nSTDERR:\n" + r.stderr());
            // stdout is the report envelope and NOTHING else — must parse as JSON
            assertFalse(r.stdout().isBlank(), "the --json report must stream to stdout");
            JsonParser.parseString(r.stdout());   // throws if stdout is not valid JSON (the bug's symptom)
            assertFalse(r.stdout().contains("[AS-EFF-006]"), "the diagnostic must NOT bleed into stdout JSON");
            assertFalse(r.stdout().contains("no violations"), "the no-violations line must NOT bleed into stdout");
            // the AS-EFF-006 diagnostic is on stderr instead
            assertTrue(r.stderr().contains("[AS-EFF-006]"), "the gate diagnostic must be on stderr\nSTDERR:\n" + r.stderr());
        } finally {
            deleteTree(classes);
            Files.deleteIfExists(policy);
        }
    }

    @Test
    void jsonStdoutStaysPureWhenAGatePasses() throws Exception {
        // a deny that doesn't match (deny Fs over a Net-only fixture) → 0 violations → the "no violations"
        // line must go to stderr, leaving stdout pure JSON.
        Path classes = compileNetFixture();
        Path policy = Files.createTempFile("denyfs", ".policy");
        Files.writeString(policy, "deny Fs\n");
        try {
            Run r = runCli(classes.toString(), "--json", "--policy", policy.toString());
            assertEquals(0, r.exit(), "no Fs effect → the gate passes (exit 0)\nSTDERR:\n" + r.stderr());
            JsonParser.parseString(r.stdout());   // pure JSON on stdout
            assertFalse(r.stdout().contains("no violations"), "the no-violations line must be on stderr, not stdout");
            assertTrue(r.stderr().contains("no violations"), "the no-violations line must be on stderr");
        } finally {
            deleteTree(classes);
            Files.deleteIfExists(policy);
        }
    }

    @Test
    void bareDashArgumentIsRejected() throws Exception {
        // [#4] a bare `-` (not a known flag, candor reads no stdin) must FAIL with exit 2, not be dropped.
        Path classes = compileNetFixture();
        try {
            Run r = runCli(classes.toString(), "-");
            assertEquals(2, r.exit(), "a bare `-` is an unknown flag → exit 2\nSTDERR:\n" + r.stderr());
            assertTrue(r.stderr().contains("unknown flag -"), "must diagnose the bare dash\nSTDERR:\n" + r.stderr());
        } finally {
            deleteTree(classes);
        }
    }
}
