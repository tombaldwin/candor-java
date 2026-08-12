package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * ⟨0.28⟩ SPEC §3.3.1 — WHAT ARMING MUST NEVER TOUCH, asserted on BYTES, via a real subprocess (main()
 * calls System.exit; same harness as CliBehaviourTest). Three defects from the adversarial review of the
 * report-sink arming rung, each of which passed every exit-code assertion while destroying or preserving
 * the wrong file — which is why every test here reads the artifact back and compares bytes, not codes:
 *
 *   1. THE TARGET IS AN INPUT. `candor app.jar --json app.jar` overwrote the jar with the fail-closed
 *      placeholder and then reported it unreadable ("zip END header not found") — the run destroyed the
 *      thing it was asked to scan, and `--gate-json app.jar` did the same. SPEC §3.3.1 (3) lists the
 *      target among the inputs arming must not touch; runInputs registered policy/env/deps/config and
 *      never the target. Exact-artifact, not containment — the control test writes a report INSIDE the
 *      scanned tree and must stay permitted.
 *
 *   2. A SYMLINKED SIDECAR IS NOT OURS TO CONSUME. removeArmedReportSidecars deleted the LINK, leaving
 *      the stale data readable under the target's other name and severing the operator's layout. The
 *      family ruling (rust and swift already hold it): leave the link alone, disclose the pair.
 *
 *   3. THE PRE-PASS MUST AGREE WITH THE PARSE LOOP. `--policy --json X` — the loop consumes `--json` as
 *      the policy path and rejects X as a surplus positional, but the pre-pass read `--json X` as the
 *      report sink and armed X. SPEC (1)'s "parsed and accepted" precondition was false, and the run can
 *      never complete, so X's previous report became a PERMANENT placeholder.
 */
class SinkArmingIntegrityTest {

    private record Run(int exit, String stdout, String stderr) {}

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

    private Path scratch;

    @BeforeEach
    void mkScratch() throws Exception {
        scratch = Files.createTempDirectory("candor-arm");
    }

    @AfterEach
    void rmScratch() throws Exception {
        if (scratch == null || !Files.exists(scratch)) return;
        try (Stream<Path> s = Files.walk(scratch)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    /** A Net-performing class compiled into {@code <scratch>/cls} → classes dir. */
    private Path compileNetFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
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
        Path out = scratch.resolve("cls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "fixture must compile");
        return out;
    }

    /** The compiled fixture packed into {@code <scratch>/app.jar} — the reproduced defect's target form. */
    private Path jarOf(Path classesDir) throws Exception {
        Path jar = scratch.resolve("app.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> files = Files.walk(classesDir)) {
            for (Path f : files.filter(Files::isRegularFile).sorted().toList()) {
                z.putNextEntry(new ZipEntry(classesDir.relativize(f).toString().replace('\\', '/')));
                z.write(Files.readAllBytes(f));
                z.closeEntry();
            }
        }
        return jar;
    }

    // ── defect 1: the scan target named as a sink ────────────────────────────────────────────────────

    @Test
    void jsonSinkNamingTheScanTargetIsRefusedWithTheTargetIntact() throws Exception {
        Path jar = jarOf(compileNetFixture());
        byte[] before = Files.readAllBytes(jar);
        Run r = runCli(jar.toString(), "--json", jar.toString());
        assertArrayEquals(before, Files.readAllBytes(jar),
                "--json <the scan target> DESTROYED the target: arming overwrote the jar this run was "
                + "asked to scan (SPEC §3.3.1 (3) — the target is an input)\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a sink naming an input is refused, exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("the scan target"),
                "the refusal names WHICH input the sink collided with\nSTDERR:\n" + r.stderr());
    }

    @Test
    void gateJsonSinkNamingTheScanTargetIsRefusedWithTheTargetIntact() throws Exception {
        // The verdict sink reaches its arm through the same runInputs list — asserted separately because
        // "registering it once covers both" is exactly the kind of claim that has to be measured, not
        // assumed (the sibling-route habit).
        Path jar = jarOf(compileNetFixture());
        byte[] before = Files.readAllBytes(jar);
        Run r = runCli(jar.toString(), "--gate-json", jar.toString());
        assertArrayEquals(before, Files.readAllBytes(jar),
                "--gate-json <the scan target> DESTROYED the target: arming overwrote the jar this run "
                + "was asked to scan\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a sink naming an input is refused, exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("the scan target"),
                "the refusal names WHICH input the sink collided with\nSTDERR:\n" + r.stderr());
    }

    @Test
    void reportInsideTheScannedTreeStaysPermitted() throws Exception {
        // CONTROL — exact-artifact, never containment: a report written into `.candor/` INSIDE the tree
        // being scanned is ordinary usage. A directory-aware "sameness" would refuse this legal run.
        Path cls = compileNetFixture();
        Path out = cls.resolve(".candor");
        Files.createDirectories(out);
        Path report = out.resolve("report.json");
        Run r = runCli(cls.toString(), "--json", report.toString());
        assertEquals(0, r.exit(),
                "a report inside the scanned tree is ordinary usage and must not be refused as \"the "
                + "target\"\nSTDERR:\n" + r.stderr());
        assertTrue(Files.exists(report), "the report was written where asked");
    }

}
