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
 *   3. THE PRE-PASS MUST AGREE WITH THE PARSE LOOP. `--policy --json X` — the loop consumed `--json` as
 *      the policy path and rejected X as a surplus positional, but the pre-pass read `--json X` as the
 *      report sink and armed X. SPEC (1)'s "parsed and accepted" precondition was false, and the run can
 *      never complete, so X's previous report became a PERMANENT placeholder. That alignment then
 *      exposed WHICH side of the disagreement was wrong: the loop was fail-open, reading a flag-shaped
 *      token as a filename — so `--policy --gate-json -` swallowed the operator's verdict sink and
 *      exited 2 with nothing on the stream (conformance §3.1 (b13)). SPEC §3.2 ⟨0.28⟩ ruled: a
 *      value-taking flag whose next token is flag-shaped has been GIVEN NO VALUE (usage error, exit 2),
 *      and the sinks named elsewhere in that argv are STILL SINKS — the pre-pass now leaves the
 *      flag-shaped token live, and the defect-3 tests below pin the ruling's side of the agreement.
 */
class SinkArmingIntegrityTest {

    private record Run(int exit, String stdout, String stderr) {}

    private static Run runCli(String... args) throws Exception {
        return runCliIn(null, args);
    }

    /** {@link #runCli} with extra environment — the baseline-pair rows need CANDOR_BASELINE set, which
     *  the scrub below would otherwise remove. */
    private static Run runCliEnv(java.util.Map<String, String> env, String... args) throws Exception {
        return runCliIn(null, env, args);
    }

    private static Run runCliIn(Path dir, String... args) throws Exception {
        return runCliIn(dir, java.util.Map.of(), args);
    }

    /** {@link #runCli} with a working directory — the ⟨0.28⟩ discovery spelling has no report anywhere
     *  in argv, so the test can only pose it by standing WHERE the engine will discover one. */
    private static Run runCliIn(Path dir, java.util.Map<String, String> env, String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (dir != null) pb.directory(dir.toFile());
        // The conformance rows these tests mirror run env-scrubbed (`env -u CANDOR_…`); a policy or
        // baseline inherited from the HARNESS environment must not turn one of these into a different
        // run (a clean-gate control with a CANDOR_BASELINE set would gate against it).
        for (String k : List.of("CANDOR_POLICY", "CANDOR_CONFIG", "CANDOR_BASELINE", "CANDOR_REPORT"))
            pb.environment().remove(k);
        pb.environment().putAll(env);
        Process p = pb.start();
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

    // ── defect 2: the symlinked sidecar ──────────────────────────────────────────────────────────────

    @Test
    void armingLeavesASymlinkedSidecarAloneAndSaysSo() throws Exception {
        Path cls = compileNetFixture();
        Path report = scratch.resolve("r.json");
        Files.writeString(report, "{\"previous\": \"report\"}\n");
        // The operator's layout: the callgraph sidecar is a LINK to a file kept elsewhere.
        Path elsewhere = scratch.resolve("kept");
        Files.createDirectories(elsewhere);
        Path linkTarget = elsewhere.resolve("real.callgraph.json");
        byte[] kept = "{\"app.Svc.fetch\": []}\n".getBytes();
        Files.write(linkTarget, kept);
        Path link = scratch.resolve("r.callgraph.json");
        try {
            Files.createSymbolicLink(link, linkTarget);
        } catch (UnsupportedOperationException | java.io.IOException e) {
            Assumptions.assumeTrue(false, "filesystem does not support symlinks — skip");
        }
        // A regular sidecar beside it: the ruling is scoped to LINKS, deletion stays the rule otherwise.
        Path regular = scratch.resolve("r.hierarchy.json");
        Files.writeString(regular, "{}\n");
        // A failing run (unknown flag) isolates ARM time: the report is armed, then the run exits 2.
        Run r = runCli(cls.toString(), "--json", report.toString(), "--zzz-not-a-flag");
        assertEquals(2, r.exit(), "the unknown flag still fails the run\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isSymbolicLink(link),
                "arming CONSUMED the symlinked sidecar — the link is the operator's layout, not this "
                + "run's artifact (the family ruling: leave it alone)\nSTDERR:\n" + r.stderr());
        assertArrayEquals(kept, Files.readAllBytes(linkTarget),
                "the link's target was modified — it may have other readers and is outside the report's stem");
        assertFalse(Files.exists(regular),
                "CONTROL: a REGULAR sidecar beside the armed report is still deleted — the symlink "
                + "ruling must not disarm sidecar removal itself");
        assertTrue(r.stderr().contains("SYMLINK"),
                "leaving the pair in place is DISCLOSED, not silent\nSTDERR:\n" + r.stderr());
    }

    // ── defect 3: the pre-pass arming a sink the parse loop never accepts ────────────────────────────

    @Test
    void aReportSinkNamedAfterABrokenFlagIsStillArmed() throws Exception {
        // SPEC §3.2 ⟨0.28⟩ — the successor to a test that pinned the OPPOSITE. While the loop consumed
        // a flag-shaped token as a value, `--policy --json X` meant *policy = the file named `--json`*,
        // X was never a sink, and this test asserted its previous report had to survive untouched. The
        // ruling overturned the premise: `--policy` followed by a flag-shaped token was GIVEN NO VALUE
        // (usage error, exit 2), `--json X` is parsed as itself, and X IS this run's report sink — so
        // what stands there after the refusal is the fail-closed placeholder, never the previous run's
        // report presented as current.
        Path cls = compileNetFixture();
        Path prev = scratch.resolve("X.json");
        Files.writeString(prev, "{\"previous\": \"run's report\"}\n");
        Run r = runCli(cls.toString(), "--policy", "--json", prev.toString());
        assertEquals(2, r.exit(), "--policy was given no value — a usage error\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("--policy"),
                "the refusal names the broken flag, not the sink\nSTDERR:\n" + r.stderr());
        String now = Files.readString(prev);
        assertTrue(now.contains("armed") || now.contains("refused"),
                "X is still this run's --json sink (the broken command line does not un-name it) — it "
                + "must hold the fail-closed placeholder, not the previous run's report\nCONTENT:\n" + now);
    }

    @Test
    void b13FlagShapedPolicyValueIsRefusedWithTheDocumentOnTheSwallowedStreamSink() throws Exception {
        // Conformance §3.1 (b13), SPEC §3.2 ⟨0.28⟩. `--policy --gate-json -`: the loop used to read
        // `--gate-json` as the policy FILENAME, so the verdict sink the operator named was never a sink
        // — measured on this engine as exit 2 with NOTHING on the stream where the fail-closed refusal
        // document belongs. BOTH halves are asserted: the exit-code half alone passes against the
        // broken behaviour, which also exited 2.
        Path cls = compileNetFixture();
        Run r = runCli(cls.toString(), "--policy", "--gate-json", "-");
        assertEquals(2, r.exit(), "a flag-shaped --policy value is a usage error\nSTDERR:\n" + r.stderr());
        assertTrue(r.stdout().contains("\"refused\": true") && r.stdout().contains("\"ok\": false"),
                "the `--gate-json -` stream sink must carry the fail-closed refusal document — it was "
                + "swallowed as the policy filename and the stream stayed EMPTY\nSTDOUT:\n" + r.stdout()
                + "\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("--policy") && r.stderr().contains("--gate-json"),
                "stderr names the flag given no value AND the token that is not one\nSTDERR:\n" + r.stderr());
        // The boundary the rule must not eat: a bare `-` stays a legitimate VALUE, so the stream form
        // still works on an intact command line (a clean policy → a real verdict on stdout, exit 0).
        Path pol = scratch.resolve("deny-exec.policy");
        Files.writeString(pol, "deny Exec\n");
        Run ok = runCli(cls.toString(), "--policy", pol.toString(), "--gate-json", "-");
        assertEquals(0, ok.exit(), "the intact stream form still gates\nSTDERR:\n" + ok.stderr());
        assertTrue(ok.stdout().contains("\"ok\": true"),
                "`--gate-json -` still streams the real verdict\nSTDOUT:\n" + ok.stdout());
    }

    @Test
    void valuelessTrailingPolicyStillArmsTheAcceptedJsonSink() throws Exception {
        // CONTROL — the fix must not weaken arming where `--json X` IS parsed and accepted: here the
        // failure is --policy's own (valueless, exit 2), and X must hold the fail-closed placeholder,
        // not the previous run's report.
        Path cls = compileNetFixture();
        Path prev = scratch.resolve("X.json");
        Files.writeString(prev, "{\"previous\": \"run's report\"}\n");
        Run r = runCli(cls.toString(), "--json", prev.toString(), "--policy");
        assertEquals(2, r.exit(), "a valueless --policy fails the run\nSTDERR:\n" + r.stderr());
        String now = Files.readString(prev);
        assertTrue(now.contains("armed"),
                "an ACCEPTED --json sink on a failed run must hold the fail-closed placeholder, not "
                + "the previous run's report\nCONTENT:\n" + now);
    }

    @Test
    void gateVerbSinkNamedAfterABrokenPolicyFlagStillGetsTheRefusal() throws Exception {
        // THE SIBLING ROUTE: `gate --report …` has its own pre-pass and flag loop in Query.run — the
        // rule fixed on the scan CLI and nowhere else is this project's recorded habit, so the ruling
        // and the test both walk the sibling. Successor to a test that pinned the pre-ruling behaviour
        // (G untouched because the loop had swallowed `--gate-json` as the policy path): under SPEC
        // §3.2 ⟨0.28⟩ the broken `--policy` is a usage error and `--gate-json G` — parsed, not
        // swallowed — is STILL A SINK, so G must hold the fail-closed refusal, never a previous run's
        // green presented as current.
        Path prev = scratch.resolve("G.json");
        Files.writeString(prev, "{\"ok\": true, \"previous\": \"verdict\"}\n");
        Run r = runCli("gate", "--report", scratch.resolve("no-such-report.json").toString(),
                "--policy", "--gate-json", prev.toString());
        assertEquals(2, r.exit(), "--policy was given no value — a usage error\nSTDERR:\n" + r.stderr());
        String now = Files.readString(prev);
        assertTrue(now.contains("\"refused\": true") && now.contains("\"ok\": false"),
                "the sink the broken command line still named must hold the fail-closed refusal, not "
                + "the stale green\nCONTENT:\n" + now + "\nSTDERR:\n" + r.stderr());
        // …and the stream spelling of the same sibling (b13's gate-verb form): the refusal document
        // reaches `-` via the shutdown hook the pre-pass armed.
        Run s = runCli("gate", "--report", scratch.resolve("no-such-report.json").toString(),
                "--policy", "--gate-json", "-");
        assertEquals(2, s.exit(), "STDERR:\n" + s.stderr());
        assertTrue(s.stdout().contains("\"refused\": true"),
                "the gate verb's `--gate-json -` stream must carry the refusal document on this exit-2 "
                + "cause too, not 0 bytes\nSTDOUT:\n" + s.stdout() + "\nSTDERR:\n" + s.stderr());
    }

    // ── SPEC §3.3.1 (3) ⟨0.28⟩: the gate's input guard covers what the `--report` locator EXPANDS to ──
    //
    // The guard compared the sink against the raw locator TOKEN while the loader reads the token's
    // EXPANSION (Query.locatorReportSet). MEASURED on this engine 2026-08-12, each at the bytes because
    // each also "failed" with a plausible exit code:
    //
    //   gate --report r --policy P --gate-json r.app.jvm.json   → exit 2, the operator's report replaced
    //       by the armed refusal — and the diagnostic blamed the report ("object has no 'functions'
    //       array") for the corruption this run inflicted;
    //   the discovery spelling (no --report, sink = the discovered .candor report) — identical;
    //   gate … --gate-json r.app.jvm.callgraph.json              → the §2.2 sidecar half of the pair,
    //       destroyed at a SUCCESS exit: the report loads fine, the gate runs, and a REAL verdict lands
    //       where the callgraph belongs.

    /** A minimal hand-written §2 report + callgraph sidecar under {@code <scratch>/r} — the stable wire
     *  shape the gate consumes, so no compile is needed. Returns the report path. */
    private Path writeGateReportPair() throws Exception {
        Path report = scratch.resolve("r.app.jvm.json");
        Files.writeString(report, """
            {"candor":{"version":"t","toolchain":"t","spec":"0.28"},"package":"app",
             "functions":[{"fn":"app.Store.save","loc":"Store.java:3","inferred":["Fs"],"hash":"h"}],
             "analyzed":{"count":1,"digest":"0"}}
            """);
        Files.writeString(scratch.resolve("r.app.jvm.callgraph.json"), "{\"app.Store.save\":[]}\n");
        Files.writeString(scratch.resolve("deny-fs.policy"), "deny Fs\n");
        return report;
    }

    @Test
    void gateJsonNamingAnExpandedReportIsRefusedWithTheReportIntact() throws Exception {
        Path report = writeGateReportPair();
        byte[] before = Files.readAllBytes(report);
        Run r = runCli("gate", "--report", scratch.resolve("r").toString(),
                "--policy", scratch.resolve("deny-fs.policy").toString(),
                "--gate-json", report.toString());
        assertArrayEquals(before, Files.readAllBytes(report),
                "--gate-json <one of the locator's expanded reports> DESTROYED the report the gate was "
                + "asked to judge (SPEC §3.3.1 (3) ⟨0.28⟩ — compare the EXPANSION, never the token)"
                + "\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a sink naming an input is refused, exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("a file this gate reads"),
                "the refusal names the collision — not a downstream 'cannot read report' over the "
                + "wreckage\nSTDERR:\n" + r.stderr());
    }

    @Test
    void gateJsonNamingADiscoveredReportIsRefusedWithTheReportIntact() throws Exception {
        // The no-`--report` spelling: nothing in argv names the report at all, and the reports this
        // gate is about to read from the discovered `.candor/` are inputs just the same.
        Path candor = scratch.resolve(".candor");
        Files.createDirectories(candor);
        Path report = candor.resolve("report.app.jvm.json");
        Files.writeString(report, """
            {"candor":{"version":"t","toolchain":"t","spec":"0.28"},"package":"app",
             "functions":[{"fn":"app.Store.save","loc":"Store.java:3","inferred":["Fs"],"hash":"h"}],
             "analyzed":{"count":1,"digest":"0"}}
            """);
        Files.writeString(scratch.resolve("deny-fs.policy"), "deny Fs\n");
        byte[] before = Files.readAllBytes(report);
        Run r = runCliIn(scratch, "gate", "--policy", "deny-fs.policy",
                "--gate-json", ".candor/report.app.jvm.json");
        assertArrayEquals(before, Files.readAllBytes(report),
                "the DISCOVERED report is an input too — this spelling destroyed it before the fix"
                + "\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "refused, exit 2\nSTDERR:\n" + r.stderr());
    }

    @Test
    void gateJsonNamingTheReportsSidecarIsRefusedAndAGateJsonSiblingStillGates() throws Exception {
        Path report = writeGateReportPair();
        Path sidecar = scratch.resolve("r.app.jvm.callgraph.json");
        byte[] sideBefore = Files.readAllBytes(sidecar);
        Run r = runCli("gate", "--report", scratch.resolve("r").toString(),
                "--policy", scratch.resolve("deny-fs.policy").toString(),
                "--gate-json", sidecar.toString());
        assertArrayEquals(sideBefore, Files.readAllBytes(sidecar),
                "the pair's other half is part of what the locator names — before the fix a REAL "
                + "verdict landed here at a success exit, and every later `callers`/`rewire` read a "
                + "verdict document where the graph belongs\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "refused, exit 2\nSTDERR:\n" + r.stderr());

        // THE CONTROL, and it is load-bearing: `<report-stem>.gate.json` is a sibling matching
        // `<stem>.*.json` — the exact file a fix that guarded "everything sharing the stem" would
        // refuse — and it is the beside-the-report verdict layout (`gate` is excluded from
        // Loader.reportSidecarSegments for the same reason). It must still gate, with a REAL verdict.
        Path sink = scratch.resolve("r.app.jvm.gate.json");
        byte[] reportBefore = Files.readAllBytes(report);
        Run c = runCli("gate", "--report", scratch.resolve("r").toString(),
                "--policy", scratch.resolve("deny-fs.policy").toString(),
                "--gate-json", sink.toString());
        assertEquals(1, c.exit(),
                "deny Fs over the Fs fixture is a VIOLATION verdict, never a refusal — a guard that "
                + "reddens the beside-the-report layout has broken the default, not implemented the rule"
                + "\nSTDERR:\n" + c.stderr());
        String verdict = Files.readString(sink);
        assertTrue(verdict.contains("\"violations\"") && !verdict.contains("\"refused\""),
                "the sink carries the verdict, not the armed placeholder:\n" + verdict);
        assertArrayEquals(reportBefore, Files.readAllBytes(report),
                "…and the reports the gate read are byte-identical after the control run");
    }

    // ── defect 5: the BASELINE pair on the SCAN side (SPEC §3.3.1 (3), measured 2026-08-12) ─────────
    //
    // checkBaseline reads `<baseline-stem>.callgraph.json` (the ⟨0.16⟩ pure→effectful ratchet answers
    // FROM the sidecar) while runInputs registered only the token — so a sink naming the sidecar
    // destroyed the ratchet's other half. And the sink is a SET too: a file-mode `--json <stem>` also
    // writes `<stem>.callgraph.json`, the exact defect candor-scan fixed as `baseline_artifact_files`
    // (`CANDOR_BASELINE=base … --out base`), reproduced here at a SUCCESS exit before the fix.

    /** Scan the fixture once into {@code <scratch>/base.json} so the baseline PAIR exists on disk. */
    private Path scanBaselinePair(Path cls) throws Exception {
        Path base = scratch.resolve("base.json");
        Run r = runCli(cls.toString(), "--json", base.toString());
        assertEquals(0, r.exit(), "the baseline-producing scan must succeed\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isRegularFile(scratch.resolve("base.callgraph.json")),
                "the file-mode scan writes the callgraph sidecar the ratchet reads");
        return base;
    }

    @Test
    void jsonSinkNamingTheBaselinesCallgraphSidecarIsRefusedBytesUnchanged() throws Exception {
        Path cls = compileNetFixture();
        Path base = scanBaselinePair(cls);
        Path sidecar = scratch.resolve("base.callgraph.json");
        byte[] before = Files.readAllBytes(sidecar);
        Run r = runCliEnv(java.util.Map.of("CANDOR_BASELINE", base.toString()),
                cls.toString(), "--json", sidecar.toString());
        assertArrayEquals(before, Files.readAllBytes(sidecar),
                "--json <the baseline's callgraph sidecar> DESTROYED it: before the fix the run wrote "
                + "its report over the ratchet's sidecar (98 → 1180 bytes measured), then read the "
                + "wreckage back and called the baseline corrupt\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a sink naming an input's expansion is refused, exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("sidecar"),
                "the refusal names the sidecar relationship, so the operator learns WHY a file they "
                + "never typed is protected\nSTDERR:\n" + r.stderr());
    }

    @Test
    void gateJsonSinkNamingTheConfigDeclaredBaselinesSidecarIsRefusedBytesUnchanged() throws Exception {
        // The config spelling — SPEC records that a gate declared via `.candor/config` rather than a
        // flag is the spelling that defeated the FIRST version of this guard in all four engines.
        Path cls = compileNetFixture();
        Path base = scanBaselinePair(cls);
        Path dotCandor = scratch.resolve(".candor");
        Files.createDirectories(dotCandor);
        Files.writeString(dotCandor.resolve("config"), "baseline " + base + "\n");
        Path sidecar = scratch.resolve("base.callgraph.json");
        byte[] before = Files.readAllBytes(sidecar);
        Run r = runCli(cls.toString(), "--gate-json", sidecar.toString());
        assertArrayEquals(before, Files.readAllBytes(sidecar),
                "--gate-json <the config-declared baseline's sidecar> DESTROYED it (the armed verdict "
                + "landed where the callgraph belongs; 98 → 326 bytes measured)\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "refused, exit 2\nSTDERR:\n" + r.stderr());
    }

    /** GUARD-DELETION SWEEP: {@code refuseGateJsonAtConfig}/{@code gateJsonIsAtConfig} — SPEC §3.3.1
     *  ⟨0.27⟩, "`.candor/config` is never a verdict sink, wherever it is" — had ZERO test coverage of its
     *  own contribution. Pointing {@code --gate-json} at the config THIS run actually discovers is
     *  already caught by the ordinary input-collision guard ({@code refuseGateJsonOverInput} — the
     *  discovered config is registered as a run input), so that shape does not exercise this method at
     *  all; MEASURED by running the real binary both ways before writing this test. This guard's actual
     *  distinctive job is a {@code .candor/config} the run does NOT discover — some OTHER directory's
     *  config, named directly and not on the target's upward walk — which the input-collision guard has
     *  no way to know about, because it was never told about it. Deleting this guard left that path
     *  unprotected: MEASURED live, `--gate-json <unrelated>/.candor/config` exited 0 and overwrote the
     *  unrelated config with the verdict placeholder; restoring the guard refused it, exit 2, bytes
     *  unchanged. The full unit suite AND `smoke.sh` stayed green with the guard deleted — this exact
     *  shape (an unrelated, non-discovered `.candor/config`) had never been posed. */
    @Test
    void gateJsonSinkNamingAnUnrelatedConfigIsRefusedBytesUnchanged() throws Exception {
        Path cls = compileNetFixture();
        // A SEPARATE .candor/config, in a directory that is not on cls's upward walk — this run never
        // discovers it as an input, so only the SHAPE-based guard can protect it.
        Path elsewhere = scratch.resolve("elsewhere");
        Path dotCandor = elsewhere.resolve(".candor");
        Files.createDirectories(dotCandor);
        Path config = dotCandor.resolve("config");
        Files.writeString(config, "unrelated-marker\n");
        byte[] before = Files.readAllBytes(config);
        Run r = runCli(cls.toString(), "--gate-json", config.toString());
        assertArrayEquals(before, Files.readAllBytes(config),
                "--gate-json <an UNRELATED .candor/config> DESTROYED it (measured live on candor-swift's "
                + "shape — the run then exited 0 with no gate at all)\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a gate-json sink naming any .candor/config is refused, exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains(".candor/config"),
                "the refusal names the .candor/config shape it matched\nSTDERR:\n" + r.stderr());
    }

    /** GUARD-DELETION SWEEP, ROUND 3: {@code gateJsonIsAtConfig}'s <b>OTHER</b> call site — inside
     *  {@code gateJsonIsInput} (Candor.java ~3126), reached only from the DUPLICATE {@code --gate-json}
     *  branch (~line 2038), never from {@link #gateJsonSinkNamingAnUnrelatedConfigIsRefusedBytesUnchanged}
     *  above, which drives the SINGLE-sink path ({@code refuseGateJsonOverAnyInput} ->
     *  {@code refuseGateJsonAtConfig}, a sibling call one hop away). Same guard, same shape check, a
     *  second independent call site that nothing before this test drove — the exact A.2 shape (a test
     *  inherits the blind spot of the bug report that prompted it): the config spelling that defeated the
     *  first version of this guard was fixed and fixture'd on ONE of its two call sites and not the other.
     *
     *  <p>MEASURED: with {@code gateJsonIsAtConfig(gateJson)} deleted from {@code gateJsonIsInput}'s OR
     *  chain, the config sink here is no longer found in {@code offending} (it is not under the target,
     *  not a discovered run input, and not at a config the run walked to — nothing else in the duplicate
     *  branch asks the SHAPE question), so {@code offending.size() != namedSinks.size()} takes the
     *  "write the refusal to every non-offending path" branch and writes the fail-closed placeholder text
     *  straight over the unrelated {@code .candor/config} — the same destruction the single-sink guard
     *  exists to prevent, through the sink-count-two spelling instead of the sink-count-one one. */
    @Test
    void duplicateGateJsonSinksStillRefuseAnUnrelatedConfigOneOfTwo() throws Exception {
        Path cls = compileNetFixture();
        // A SEPARATE .candor/config this run never discovers (not on cls's upward walk) — only the
        // SHAPE-based check can protect it, exactly as in the single-sink sibling above.
        Path elsewhere = scratch.resolve("elsewhere");
        Path dotCandor = elsewhere.resolve(".candor");
        Files.createDirectories(dotCandor);
        Path config = dotCandor.resolve("config");
        Files.writeString(config, "unrelated-marker\n");
        byte[] before = Files.readAllBytes(config);
        Path other = scratch.resolve("verdict.json");
        // TWO --gate-json sinks: the duplicate-sinks branch, whose OWN gateJsonIsInput call is the one
        // under test — never reached by a single `--gate-json <config>` invocation.
        Run r = runCli(cls.toString(), "--gate-json", other.toString(), "--gate-json", config.toString());
        assertArrayEquals(before, Files.readAllBytes(config),
                "--gate-json <verdict.json> --gate-json <an UNRELATED .candor/config> DESTROYED the config "
                + "— the DUPLICATE-sinks branch's own is-input check let it through even though the "
                + "single-sink path already refuses this exact shape\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a gate-json sink naming any .candor/config is refused, even beside "
                + "another named sink\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains(config.toString()) && r.stderr().contains("INPUT"),
                "the offending sink is named as an input in the duplicate-sinks message\nSTDERR:\n"
                + r.stderr());
    }

    // ── ROUND 4: the config-shape guard, pinned per ROUTE rather than per call site ───────────────────
    //
    // WHY A FOURTH ROUND ON ONE GUARD. Rounds 1–3 above each closed the call site in hand and left the
    // next one, so this round enumerated SINKS instead of call sites: every argv spelling that can write
    // a document to an operator-named path was driven at an unrelated `.candor/config`, and every guard
    // on each of those paths was mutated to see which route it actually protects. Six routes exist:
    //
    //   R1  scan `--json <cfg>`                                   Candor#refuseJsonAtConfig
    //   R2  scan `--json a --json <cfg>`   (duplicate report)     Candor#gateJsonIsInput's shape arm
    //   R3  scan `--gate-json <cfg>`                              Candor#refuseGateJsonAtConfig
    //   R4  scan `--gate-json a --gate-json <cfg>`                Candor#gateJsonIsInput's shape arm
    //   R5  `gate --report R --gate-json <cfg>`                   Query pre-pass → refuseGateJsonAtConfig
    //   R6  `gate --report R --gate-json v --gate-json <cfg>`     Query pre-pass, per-sink
    //
    // MEASURED before these tests were written, by disarming each guard, recompiling and driving the real
    // binary — only R3 and R4 had a test that could tell armed from disarmed:
    //
    //   disarm refuseJsonAtConfig       → R1 EXIT 0, config 17 → 698 bytes, "nothing hidden"   888/888 GREEN
    //   disarm the duplicate-`--json`   → R2 exit 2, config 17 → 500 bytes                     888/888 GREEN
    //     branch's is-input question
    //   disarm BOTH Query pre-pass      → R5 exit 2, config 17 → 228 bytes                     888/888 GREEN
    //     refuseGateJsonOverAnyInput      R6 exit 2, config 17 → 386 bytes
    //     calls
    //   disarm refuseGateJsonAtConfig   → R3 EXIT 0, config → 91 bytes  (and R5, R6 too)       1 RED (R3's test)
    //   disarm the is-input shape arm   → R4 exit 2, config → 386 bytes (and R2 too)           1 RED (R4's test)
    //
    // Note what the exit codes say: R1 is the QUIETEST route — exit 0 and a success banner over a
    // destroyed config — and it was the one with no test. R2/R5/R6 destroy at exit 2, which reads as a
    // clean refusal to anyone checking only the status. Bytes, not exit codes, are the assertion.
    //
    // The Query pair (R5/R6) is pinned by ROUTE deliberately: `Query` asks the guard twice, once for
    // `preGate` and once per named sink, so either call alone can be deleted with no observable effect —
    // the redundancy is fine, but it means no single-call mutation is measurable and only a test that
    // drives the VERB can notice the route losing its guard entirely.

    /** R1 — the single `--json` sink at an unrelated `.candor/config`. The quietest destroyer in the
     *  family: {@code refuseJsonAtConfig} is CORRECT, and until this test nothing could tell it from
     *  {@code if (true) return;} — measured, 888/888 green with the body disarmed while the binary exited
     *  0, truncated a 17-byte config to a 698-byte report and printed "nothing hidden". The `--gate-json`
     *  sibling three tests up has had this coverage since round 1; the report sink one hop upstream never
     *  did, because each round scoped itself to the flag its own bug report named. */
    @Test
    void jsonSinkNamingAnUnrelatedConfigIsRefusedBytesUnchanged() throws Exception {
        Path cls = compileNetFixture();
        Path config = unrelatedConfig();
        byte[] before = Files.readAllBytes(config);
        Run r = runCli(cls.toString(), "--json", config.toString());
        assertArrayEquals(before, Files.readAllBytes(config),
                "--json <an UNRELATED .candor/config> DESTROYED it — and at EXIT 0 with the ordinary "
                + "success banner, so nothing in the output says a config was lost\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a report sink naming any .candor/config is refused, exit 2\nSTDERR:\n"
                + r.stderr());
        assertTrue(r.stderr().contains(".candor/config") && r.stderr().contains("--json"),
                "the refusal names the shape it matched AND the flag that named it\nSTDERR:\n" + r.stderr());
    }

    /** R2 — the DUPLICATE `--json` branch. A second, independent route to the shape question: the
     *  repeated-sink branch asks {@code gateJsonIsInput} rather than calling {@code refuseJsonAtConfig},
     *  and skips arming only the sinks that came back offending. MEASURED with that question disarmed in
     *  this branch alone: exit 2 (the duplicate refusal), config 17 → 500 bytes — the fail-closed report
     *  written straight over it — and 888/888 green, because round 3's duplicate test drives
     *  `--gate-json` and this branch is `--json`'s own copy of the same shape. */
    @Test
    void duplicateJsonSinksStillRefuseAnUnrelatedConfigOneOfTwo() throws Exception {
        Path cls = compileNetFixture();
        Path config = unrelatedConfig();
        byte[] before = Files.readAllBytes(config);
        Path other = scratch.resolve("report.json");
        Run r = runCli(cls.toString(), "--json", other.toString(), "--json", config.toString());
        assertArrayEquals(before, Files.readAllBytes(config),
                "--json <report.json> --json <an UNRELATED .candor/config> DESTROYED the config — the "
                + "duplicate branch arms every non-offending sink, and the config was not recognised as "
                + "offending\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "a repeated report sink is refused, exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains(config.toString()) && r.stderr().contains("INPUT"),
                "the config sink is named as an INPUT, which is what kept it out of the arming loop"
                + "\nSTDERR:\n" + r.stderr());
    }

    /** R5 — the `gate` VERB's route into the same guard. `Query`'s pre-pass reaches
     *  {@code refuseGateJsonAtConfig} through {@code refuseGateJsonOverAnyInput}, and it makes that call
     *  TWICE (once for {@code preGate}, once per named sink), so neither call alone is observable —
     *  deleting either leaves the other covering it. MEASURED with BOTH deleted: exit 2 and the config
     *  17 → 228 bytes (armGateJson's fail-closed placeholder), 888/888 green. The scan verb's identical
     *  shape has been pinned since round 1; this verb — the one §3.3.1's own worked example is written
     *  about (`gate --report R --policy P --gate-json P`) — had no route-level test at all. */
    @Test
    void gateVerbGateJsonSinkNamingAnUnrelatedConfigIsRefusedBytesUnchanged() throws Exception {
        Path report = scanReport();
        Path config = unrelatedConfig();
        byte[] before = Files.readAllBytes(config);
        Run r = runCli("gate", "--report", report.toString(), "--gate-json", config.toString());
        assertArrayEquals(before, Files.readAllBytes(config),
                "gate --gate-json <an UNRELATED .candor/config> DESTROYED it. Note the exit code is 2 "
                + "either way — a caller checking only the status cannot tell this from a clean refusal, "
                + "which is why the assertion is on BYTES\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "refused, exit 2\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains(".candor/config"),
                "the refusal names the .candor/config shape it matched\nSTDERR:\n" + r.stderr());
    }

    /** R6 — the `gate` verb's DUPLICATE-sink route. Same verb, the other branch: the per-sink loop asks
     *  the input question for every named sink and then WRITES the duplicate-refusal document to each one
     *  ({@code Query} ~line 485) — so a config that slipped past the loop is overwritten by the refusal
     *  itself. MEASURED with the loop's guard call deleted alongside the single-sink one: exit 2, config
     *  17 → 386 bytes, 888/888 green. */
    @Test
    void gateVerbDuplicateGateJsonSinksStillRefuseAnUnrelatedConfig() throws Exception {
        Path report = scanReport();
        Path config = unrelatedConfig();
        byte[] before = Files.readAllBytes(config);
        Path other = scratch.resolve("verdict.json");
        Run r = runCli("gate", "--report", report.toString(),
                "--gate-json", other.toString(), "--gate-json", config.toString());
        assertArrayEquals(before, Files.readAllBytes(config),
                "gate --gate-json <verdict.json> --gate-json <an UNRELATED .candor/config> DESTROYED the "
                + "config — with the DUPLICATE-REFUSAL document, the very write that announces the "
                + "refusal\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "refused, exit 2\nSTDERR:\n" + r.stderr());
    }

    // ── THE OVER-CHARGE CONTROLS for the shape rule ──────────────────────────────────────────────────
    //
    // The rule is `config` AND a `.candor` parent, and a guard that refuses everything has deleted the
    // feature rather than fixed the sin. Both near misses are asserted, plus the ordinary sink: each
    // differs from a refused run in exactly ONE thing (the filename, the parent directory, or neither).

    /** CONTROL — an ORDINARY `--json <path>.json` still runs and still exits 0, writing its report. If
     *  this goes red the guard has stopped being a shape test and started refusing report sinks. */
    @Test
    void anOrdinaryJsonSinkStillWorksAndExitsZero() throws Exception {
        Path cls = compileNetFixture();
        Path out = scratch.resolve("ordinary.json");
        Run r = runCli(cls.toString(), "--json", out.toString());
        assertEquals(0, r.exit(), "an ordinary report sink is ordinary usage\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isRegularFile(out), "the report was written where asked");
        assertTrue(Files.readString(out).contains("\"functions\""), "and it is a real report, not a stub");
    }

    /** CONTROL, NEAR MISS 1 — a file NAMED `config` whose parent is NOT `.candor`. One field's value
     *  different from the refused shape (the parent), and it must still be a permitted sink: `config` is
     *  an ordinary filename and the rule is about candor's own directory, not about the word. */
    @Test
    void aFileNamedConfigOutsideADotCandorDirectoryStaysPermitted() throws Exception {
        Path cls = compileNetFixture();
        Path dir = scratch.resolve("conf");
        Files.createDirectories(dir);
        Path sink = dir.resolve("config");
        Run r = runCli(cls.toString(), "--json", sink.toString());
        assertEquals(0, r.exit(), "`config` is only protected INSIDE a `.candor` directory — a file of "
                + "that name anywhere else is the operator's business\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isRegularFile(sink), "the report was written where asked");
    }

    /** CONTROL, NEAR MISS 2 — a file INSIDE a `.candor` directory that is not named `config`. The other
     *  half of the conjunction, and the recommended layout: `.candor/report.json` and `.candor/gate.json`
     *  are where the docs tell operators to put these. A guard that refused the whole directory would
     *  break the shipped convention. */
    @Test
    void anOtherFileInsideADotCandorDirectoryStaysPermitted() throws Exception {
        Path cls = compileNetFixture();
        Path dot = scratch.resolve("out").resolve(".candor");
        Files.createDirectories(dot);
        Run r = runCli(cls.toString(), "--json", dot.resolve("report.json").toString(),
                "--gate-json", dot.resolve("gate.json").toString());
        assertEquals(0, r.exit(), "the recommended `.candor/report.json` + `.candor/gate.json` layout is "
                + "ordinary usage\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isRegularFile(dot.resolve("report.json")), "the report landed");
        assertTrue(Files.isRegularFile(dot.resolve("gate.json")), "and the verdict landed");
    }

    /** A `.candor/config` in a directory that is NOT on the fixture's upward walk, so this run never
     *  discovers it as an input — the shape guard is then the only thing that can protect it. (Pointing a
     *  sink at the config the run DOES discover is caught by the ordinary input-collision guard and does
     *  not exercise the shape test at all; measured in round 1.) */
    private Path unrelatedConfig() throws Exception {
        Path dotCandor = scratch.resolve("elsewhere").resolve(".candor");
        Files.createDirectories(dotCandor);
        Path config = dotCandor.resolve("config");
        Files.writeString(config, "unrelated-marker\n");
        return config;
    }

    /** A real report for the `gate` verb to read, produced by the engine's own scan of the fixture —
     *  `gate` needs an input before its sink handling is worth anything. */
    private Path scanReport() throws Exception {
        Path cls = compileNetFixture();
        Path rep = scratch.resolve("gate-input.json");
        Run r = runCli(cls.toString(), "--json", rep.toString());
        assertEquals(0, r.exit(), "the gate-verb fixture's own scan must succeed\nSTDERR:\n" + r.stderr());
        return rep;
    }

    @Test
    void jsonSinkStemWhoseSidecarIsTheBaselinesSidecarIsRefusedBytesUnchanged() throws Exception {
        // THE SINK EXPANDS TOO: `--json base` (no .json) writes `base` AND `base.callgraph.json` — with
        // CANDOR_BASELINE=base.json that second write replaces the ratchet's sidecar with the CURRENT
        // call graph at a success exit, so the next run gates against a baseline half it never produced.
        Path cls = compileNetFixture();
        Path base = scanBaselinePair(cls);
        // DRIFT the code before the attack run — with an identical tree the overwrite writes the SAME
        // bytes back and the byte assertion is vacuous (measured: this test's first draft failed only
        // on the exit code). A new caller changes the current call graph, so a sidecar overwrite is
        // byte-visible.
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Path extra = scratch.resolve("Extra.java");
        Files.writeString(extra, "package app;\npublic class Extra { void go() { new Svc(); } }\n");
        assertEquals(0, jc.run(null, null, null, "-d", cls.toString(), "-cp", cls.toString(),
                extra.toString()), "drift fixture must compile");
        Path sidecar = scratch.resolve("base.callgraph.json");
        byte[] sideBefore = Files.readAllBytes(sidecar);
        byte[] baseBefore = Files.readAllBytes(base);
        Path stemSink = scratch.resolve("base");
        Run r = runCliEnv(java.util.Map.of("CANDOR_BASELINE", base.toString()),
                cls.toString(), "--json", stemSink.toString());
        assertArrayEquals(sideBefore, Files.readAllBytes(sidecar),
                "the sink's OWN sidecar write replaced the baseline's callgraph — the half-updated pair "
                + "silently narrows the pure→effectful ratchet from the next run on\nSTDERR:\n" + r.stderr());
        assertArrayEquals(baseBefore, Files.readAllBytes(base), "the baseline report is untouched too");
        assertEquals(2, r.exit(), "refused, exit 2\nSTDERR:\n" + r.stderr());
        assertFalse(Files.exists(stemSink),
                "NOTHING was written to the refused sink's stem either — refusal writes nothing");
    }

    // ── ⟨0.28⟩ the scan target EXPANDS to the files the run will parse ───────────────────────────────

    @Test
    void jsonSinkWithAParseableExtensionUnderTheTargetIsRefused() throws Exception {
        // MEASURED before the change: `--json <target>/evil.class` ARMED the placeholder into the class
        // tree, the walk read the JSON bytes back as bytecode ("Unsupported class file major version
        // 24942" — the placeholder's own text), and the run finished GREEN with a report at a .class
        // path. A real class there would have been destroyed AND silently skipped.
        Path cls = compileNetFixture();
        Path evil = cls.resolve("app").resolve("Svc.class");   // a REAL class of the operator's code
        byte[] before = Files.readAllBytes(evil);
        Run r = runCli(cls.toString(), "--json", evil.toString());
        assertArrayEquals(before, Files.readAllBytes(evil),
                "arming destroyed a source file of the tree being scanned\nSTDERR:\n" + r.stderr());
        assertEquals(2, r.exit(), "refused at parse time, nothing written\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("extension this engine parses"),
                "the refusal names the rule (under the target + a parseable extension)\nSTDERR:\n" + r.stderr());
    }

    @Test
    void gateJsonSinkWithAParseableExtensionUnderTheTargetIsRefusedToo() throws Exception {
        // The sibling route, asserted separately — the rule is about the SINK, not one flag; `.jar` and a
        // not-yet-existing path exercise the extension set and the target-need-not-contain-it arm.
        Path cls = compileNetFixture();
        Run r = runCli(cls.toString(), "--gate-json", cls.resolve("lib").resolve("x.jar").toString());
        assertEquals(2, r.exit(), "refused\nSTDERR:\n" + r.stderr());
        assertFalse(Files.exists(cls.resolve("lib").resolve("x.jar")), "nothing was written there");
        assertTrue(r.stderr().contains("extension this engine parses"), r.stderr());
    }

    @Test
    void aParseableExtensionOutsideTheTargetStaysPermitted() throws Exception {
        // CONTROL — the rule is under-the-target AND parseable, never extension alone: an odd sink name
        // OUTSIDE the tree is the operator's business (nothing this run will parse lives there).
        Path cls = compileNetFixture();
        Path odd = scratch.resolve("odd.class");
        Run r = runCli(cls.toString(), "--json", odd.toString());
        assertEquals(0, r.exit(), "an out-of-tree sink is permitted whatever its name\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isRegularFile(odd), "the report was written where asked");
    }

    @Test
    void aJsonSinkUnderTheTargetStaysPermitted() throws Exception {
        // CONTROL — `<dir>/.candor/report.json` is under the target and is NOT a source file: the
        // recommended layout, the control the ruling says this fix must not break (exact-artifact /
        // extension, never containment — one engine tried containment and it "took 33 tests with it").
        Path cls = compileNetFixture();
        Files.createDirectories(cls.resolve(".candor"));
        Run r = runCli(cls.toString(), "--json", cls.resolve(".candor").resolve("report.json").toString());
        assertEquals(0, r.exit(), "the recommended in-tree layout is ordinary usage\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isRegularFile(cls.resolve(".candor").resolve("report.json")));
    }

    // ── ⟨0.28⟩ a repeated `--json` is one rule with the repeated `--gate-json`, not two spellings ─────

    @Test
    void repeatedJsonSinksAreRefusedAndBothFailClosed() throws Exception {
        // MEASURED before the change: `--json one.json --json two.json` wrote the report to the LAST
        // path and left the first byte-identical at exit 0 — a previous run's document standing as
        // current, the ⟨0.27⟩ stale green through the report sink.
        Path cls = compileNetFixture();
        Path one = scratch.resolve("one.json"), two = scratch.resolve("two.json");
        Files.writeString(one, "{\"stale\": true}");
        Run r = runCli(cls.toString(), "--json", one.toString(), "--json", two.toString());
        assertEquals(2, r.exit(), "a run publishes ONE report to ONE sink\nSTDERR:\n" + r.stderr());
        assertTrue(r.stderr().contains("--json given more than once"), r.stderr());
        String oneAfter = Files.readString(one);
        assertFalse(oneAfter.contains("stale"),
                "the losing sink must NOT keep a previous run's document — it gets the fail-closed "
                + "armed report: " + oneAfter);
        assertTrue(oneAfter.contains("\"analyzed\"") && oneAfter.contains("armed:"),
                "…the §3.3.1 (2) manifest-carrying empty, not a bare refusal: " + oneAfter);
        assertTrue(Files.readString(two).contains("armed:"), "every named sink fails closed");
    }

    @Test
    void theSameArtifactNamedTwiceIsOneSink() throws Exception {
        // CONTROL — two spellings of one path are ONE sink (the §3.3.1 artifact rule), exactly as the
        // repeated --gate-json guard treats them: the run proceeds and writes the real report.
        Path cls = compileNetFixture();
        Path out = scratch.resolve("r.json");
        Run r = runCli(cls.toString(), "--json", out.toString(),
                "--json", scratch.resolve(".").resolve("r.json").toString());
        assertEquals(0, r.exit(), "one artifact, one sink — not a duplicate\nSTDERR:\n" + r.stderr());
        assertTrue(Files.readString(out).contains("app.Svc.fetch"), "the real report landed");
    }

    @Test
    void aFileSinkAndTheStreamFormAreTwoSinks() throws Exception {
        // `--json r.json --json` names a file AND stdout — two places for one report. The stream half of
        // the refusal is the armReportStream hook: stdout carries the fail-closed document, exactly once.
        Path cls = compileNetFixture();
        Path out = scratch.resolve("r.json");
        Run r = runCli(cls.toString(), "--json", out.toString(), "--json");
        assertEquals(2, r.exit(), r.stderr());
        assertTrue(r.stderr().contains("--json given more than once"), r.stderr());
        assertTrue(r.stdout().contains("\"count\": 0") && r.stdout().contains("NOT a claim"),
                "the stream form's fail-closed document reaches stdout (the hook)\nSTDOUT:\n" + r.stdout());
    }

    @Test
    void jsonSinkBesideTheBaselineStaysPermitted() throws Exception {
        // CONTROL — the recommended layout: report and baseline side by side under `.candor/`. A guard
        // that refused any stem NEAR the baseline would break the default, not implement the rule.
        Path cls = compileNetFixture();
        Path base = scanBaselinePair(cls);
        Path out = scratch.resolve("report.json");
        Run r = runCliEnv(java.util.Map.of("CANDOR_BASELINE", base.toString()),
                cls.toString(), "--json", out.toString());
        assertEquals(0, r.exit(),
                "a distinct sink beside the baseline is ordinary usage (same code → no AS-EFF-005)"
                + "\nSTDERR:\n" + r.stderr());
        assertTrue(Files.isRegularFile(out) && Files.isRegularFile(scratch.resolve("report.callgraph.json")),
                "the report pair was written where asked");
    }

    // ── ⟨0.34⟩ defect 4: the DECLARED PEEK CLASSPATH was not an input ────────────────────────────────
    //
    // `runInputs` registered the target, `--policy`, CANDOR_POLICY/BASELINE/CONFIG/DEPS and the config's
    // `policy`/`baseline`/`deps` — every path-bearing input except the ⟨0.32⟩ `peek-classpath`, whose
    // jars `javac` READS during the compile-peek. All three spellings destroyed the declared artifact,
    // and unlike the target case that prompted this whole guard they did it AT EXIT 0, after printing a
    // report summary. MEASURED before the fix, target `cls`, `libs/dep.jar` 716 bytes, everything else
    // held constant — the siblings are the control:
    //
    //   --policy libs/gate.pol         --json <same path>       → exit 2, intact
    //   config `deps libs/dep.jar`     --json <same path>       → exit 2, intact
    //   --peek-classpath libs/dep.jar  --json <same path>       → EXIT 0, jar → a 279-byte report
    //   --peek-classpath libs/dep.jar  --gate-json <same path>  → EXIT 0, jar → a 91-byte verdict
    //   config `peek-classpath …`      --json <same path>       → EXIT 0, destroyed
    //   CANDOR_PEEK_CLASSPATH=…        --json <same path>       → EXIT 0, destroyed

    /** A jar under {@code <scratch>/libs} that stands in for an operator-declared dependency. */
    private Path declaredJar(Path classesDir) throws Exception {
        Path libs = scratch.resolve("libs");
        Files.createDirectories(libs);
        Path jar = libs.resolve("dep.jar");
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

    @Test
    void aPeekClasspathJarNamedAsTheReportSinkIsRefusedWithTheJarIntact() throws Exception {
        Path cls = compileNetFixture();
        Path jar = declaredJar(cls);
        byte[] before = Files.readAllBytes(jar);
        Run r = runCli(cls.toString(), "--peek-classpath", jar.toString(), "--json", jar.toString());
        assertEquals(2, r.exit(), "a sink naming a declared peek-classpath entry must be refused"
                + "\nSTDERR:\n" + r.stderr());
        assertArrayEquals(before, Files.readAllBytes(jar),
                "the declared dependency must be BYTE-identical — nothing was written");
        assertTrue(r.stderr().contains("--peek-classpath"),
                "the refusal must name the channel the input arrived through: " + r.stderr());
    }

    @Test
    void aPeekClasspathJarNamedAsTheVerdictSinkIsRefusedWithTheJarIntact() throws Exception {
        // THE SIBLING SINK, tested separately: `--gate-json` was the QUIETER of the two — it printed
        // "no violations" and exited 0 over the jar it had just overwritten with a 91-byte verdict.
        Path cls = compileNetFixture();
        Path jar = declaredJar(cls);
        byte[] before = Files.readAllBytes(jar);
        Run r = runCli(cls.toString(), "--peek-classpath", jar.toString(), "--gate-json", jar.toString());
        assertEquals(2, r.exit(), r.stderr());
        assertArrayEquals(before, Files.readAllBytes(jar), "the declared dependency must be BYTE-identical");
    }

    @Test
    void aConfigDeclaredPeekClasspathEntryNamedAsASinkIsRefused() throws Exception {
        // The `.candor/config` spelling — SPEC records that the CONFIG spelling is the one that defeated
        // the FIRST version of this guard in all four engines, so it gets its own row rather than being
        // assumed to ride the flag's.
        Path cls = compileNetFixture();
        Path jar = declaredJar(cls);
        Files.createDirectories(scratch.resolve(".candor"));
        Files.writeString(scratch.resolve(".candor/config"), "peek-classpath libs/dep.jar\n");
        byte[] before = Files.readAllBytes(jar);
        Run r = runCli(cls.toString(), "--json", jar.toString());
        assertEquals(2, r.exit(), r.stderr());
        assertArrayEquals(before, Files.readAllBytes(jar), "the declared dependency must be BYTE-identical");
        assertTrue(r.stderr().contains("peek-classpath"), r.stderr());
    }

    @Test
    void anEnvDeclaredPeekClasspathEntryNamedAsASinkIsRefused() throws Exception {
        Path cls = compileNetFixture();
        Path jar = declaredJar(cls);
        byte[] before = Files.readAllBytes(jar);
        Run r = runCliEnv(java.util.Map.of("CANDOR_PEEK_CLASSPATH", jar.toString()),
                cls.toString(), "--json", jar.toString());
        assertEquals(2, r.exit(), r.stderr());
        assertArrayEquals(before, Files.readAllBytes(jar), "the declared dependency must be BYTE-identical");
        assertTrue(r.stderr().contains("CANDOR_PEEK_CLASSPATH"), r.stderr());
    }

    /**
     * ⟨0.34⟩ defect 5 — THE PRE-PASS MUST AGREE WITH THE PARSE LOOP, on this flag too.
     *
     * <p>The arming pre-pass did not know {@code --peek-classpath} takes a value, and the branch that
     * ends its chain takes the first non-flag token as the scan TARGET. So whenever the flag PRECEDED
     * the real target, the flag's VALUE became the target and every §3.3.1 guard was computed against
     * the wrong tree — including the walk that discovers {@code .candor/config}, so a config-declared
     * {@code policy} was never registered and the sink destroyed it at exit 0.
     *
     * <p>The two arms are the SAME argv tokens in a different order; that is the only thing that differs.
     * Asserting them TOGETHER rather than only on the broken order is the point: the property is that
     * argv order does not change what arming protects.
     *
     * <p><b>THE DECLARED JAR MUST LIVE OUTSIDE THE CONFIG'S TREE, and the first draft of this test did
     * not.</b> With the jar under {@code <scratch>/libs} and the config at {@code <scratch>/.candor},
     * discovery walking up from the WRONG target still reached the SAME config — so deleting the pre-pass
     * fix left this test green while the other rows went red. Measured, not reasoned: the mutation run is
     * what exposed it. The jar now sits in a sibling tree the mis-taken target's walk cannot reach.
     */
    @Test
    void peekClasspathBeforeTheTargetIsNotMistakenForTheScanTarget() throws Exception {
        Path proj = scratch.resolve("proj");
        Path cls = proj.resolve("cls");
        Files.createDirectories(cls);
        try (Stream<Path> s = Files.walk(compileNetFixture())) {
            for (Path f : s.filter(Files::isRegularFile).toList()) {
                Path rel = scratch.resolve("cls").relativize(f);
                Files.createDirectories(cls.resolve(rel).getParent());
                Files.copy(f, cls.resolve(rel));
            }
        }
        // OUTSIDE `proj`: walking up from here can never reach proj/.candor/config.
        Path jar = declaredJar(scratch.resolve("cls"));
        Files.createDirectories(proj.resolve(".candor"));
        Files.writeString(proj.resolve(".candor/config"), "policy .candor/gate.pol\n");
        Path pol = proj.resolve(".candor/gate.pol");

        for (boolean flagFirst : new boolean[] {false, true}) {
            Files.writeString(pol, "deny Net app\n");
            byte[] before = Files.readAllBytes(pol);
            Run r = flagFirst
                    ? runCli("--peek-classpath", jar.toString(), cls.toString(), "--json", pol.toString())
                    : runCli(cls.toString(), "--peek-classpath", jar.toString(), "--json", pol.toString());
            String where = flagFirst ? "flag BEFORE the target" : "flag AFTER the target";
            assertEquals(2, r.exit(), where + ": the config-declared policy is an input\nSTDERR:\n" + r.stderr());
            assertArrayEquals(before, Files.readAllBytes(pol),
                    where + ": the operator's gate policy must be BYTE-identical");
        }
    }

    /**
     * THE OVER-CHARGE CONTROL for all of the above — the direction the fix did NOT intend. A declared
     * peek classpath beside a sink that names something ELSE is ordinary usage and must still run to
     * completion and publish. Without this, registering the classpath as an input could have been
     * "fixed" by refusing every run that declares one, which passes every assertion above.
     */
    @Test
    void aPeekClasspathBesideAnUnrelatedSinkStaysPermitted() throws Exception {
        Path cls = compileNetFixture();
        Path jar = declaredJar(cls);
        byte[] before = Files.readAllBytes(jar);
        Path out = scratch.resolve("report.json");
        Run r = runCli(cls.toString(), "--peek-classpath", jar.toString(), "--json", out.toString());
        assertEquals(0, r.exit(), "a declared peek classpath is not itself a reason to refuse"
                + "\nSTDERR:\n" + r.stderr());
        assertTrue(Files.readString(out).contains("app.Svc.fetch"), "the real report landed");
        assertArrayEquals(before, Files.readAllBytes(jar), "…and the declared jar was not touched");
    }

    /** …and the pre-pass's new consumption must not swallow a flag-shaped token: `--peek-classpath` with
     *  no value is still the parse loop's usage error, which is the agreement half of the ruling. */
    @Test
    void peekClasspathWithNoValueIsStillAUsageError() throws Exception {
        Path cls = compileNetFixture();
        Run r = runCli(cls.toString(), "--peek-classpath", "--json", scratch.resolve("r.json").toString());
        assertEquals(2, r.exit(), r.stderr());
        assertTrue(r.stderr().contains("--peek-classpath requires a value"), r.stderr());
    }
}
