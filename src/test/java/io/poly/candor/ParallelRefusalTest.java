package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;

/**
 * <b>THE SIBLING ROUTE SWALLOWED THE REFUSAL.</b> A target that EXISTS but holds no {@code .class} is
 * unevaluable, and the single-target route says so: it prints the bytecode-not-source remedy, refuses the
 * verdict sink, and exits 2 without ever writing a report. {@code --parallel} — the same engine, one
 * argument over — ran the same scan, found the same nothing, and wrote an ORDINARY report:
 * {@code analyzed.count: 0}, {@code functions: []}, no refusal marker anywhere. {@code gate --report}
 * over it then printed a note about judging nothing and <b>exited 0</b>. A note beside exit 0 is not a
 * verdict; CI reads the exit code. Measured over a 560-artifact local corpus, 9 artifacts have that
 * shape — 9 green gates over jars nothing was ever read from.
 *
 * <p>It also collides with the rung's own rule that <b>a refusal must produce no report</b> (SPEC §3.1
 * binds "any report a scan produced"): the parallel arm produced one, and its naive read is PASS.
 *
 * <p>A NONEXISTENT path was already handled — {@code Files.exists} is checked before the scan. So the
 * hole was never "the parallel arm ignores bad targets"; it was that the one unevaluable kind decided
 * INSIDE {@code runScan} had no way back out to the arm that collects failures.
 *
 * <p>The controls here are the deliverable as much as the defect assertion is: an over-charged fix that
 * refuses targets which DO have classes, or that throws away a healthy target's findings because a
 * sibling was classless, would pass the defect assertion while deleting the feature.
 */
class ParallelRefusalTest {

    private record Run(int exit, String stdout, String stderr) {}

    private static Run runCli(Path cwd, String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp",
                System.getProperty("java.class.path"), "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).directory(cwd.toFile()).start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    private static String drain(InputStream in) throws Exception {
        try (in) { return new String(in.readAllBytes()); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> json(Path p) throws Exception {
        return new Gson().fromJson(Files.readString(p), Map.class);
    }

    @SuppressWarnings("unchecked")
    private static List<String> fnNames(Path report) throws Exception {
        var out = new ArrayList<String>();
        Object fns = json(report).get("functions");
        if (fns == null) return out;
        for (Map<String, Object> e : (List<Map<String, Object>>) fns) out.add((String) e.get("fn"));
        return out;
    }

    /** A jar holding a readme and NOT ONE `.class` — the corpus shape (a resources-only artifact, a
     *  sources jar, a failed build). It EXISTS and it opens; there is simply nothing in it to read. */
    private static Path classlessJar(Path dir, String name) throws Exception {
        Path jar = dir.resolve(name);
        try (OutputStream os = Files.newOutputStream(jar); ZipOutputStream zos = new ZipOutputStream(os)) {
            zos.putNextEntry(new ZipEntry("readme.txt"));
            zos.write("no bytecode here\n".getBytes());
            zos.closeEntry();
        }
        return jar;
    }

    /** A directory that exists and holds SOURCE only — the other spelling of the same unevaluable. */
    private static Path sourceOnlyDir(Path base) throws Exception {
        Path d = base.resolve("srcOnly");
        Files.createDirectories(d);
        Files.writeString(d.resolve("A.java"), "public class A { void go() {} }\n");
        return d;
    }

    private static Path goodTarget() throws Exception {
        return TestCompiler.compile(Map.of("app/Fx.java",
                "package app;\npublic class Fx {\n"
                + "  public void reads() throws Exception { java.nio.file.Files.readString(java.nio.file.Path.of(\"x\")); }\n}\n"));
    }

    // ── CONTROL ────────────────────────────────────────────────────────────────────────────────────
    /** THE OVER-CHARGE CONTROL, and it runs first on purpose. Targets that DO have classes must exit 0
     *  and write ORDINARY reports with real findings — a refusal that fires one target too wide deletes
     *  the whole verb while passing every assertion below. */
    @Test
    void parallelOverTargetsThatHaveClassesIsUnchanged() throws Exception {
        Path good = goodTarget();
        Path base = good.getParent();
        Path outDir = base.resolve("out-control");
        rm(outDir);
        Run r = runCli(base, "--parallel", outDir.toString(), good.toString());
        assertEquals(0, r.exit(), "a --parallel run over a target with classes must still exit 0. "
                + "stderr: " + r.stderr());
        assertTrue(r.stdout().contains("scanned 1 target(s)"), "and say so. stdout: " + r.stdout());
        Path rep = outDir.resolve("cls.json");
        assertTrue(Files.exists(rep), "one ordinary report per target");
        assertTrue(fnNames(rep).contains("app.Fx.reads"),
                "and it is a REAL report — the finding is present. Got " + fnNames(rep));
        assertFalse(json(rep).containsKey("unanalyzed"),
                "a healthy scan carries no unanalyzed manifest — if it does, the refusal fired on a "
                + "target it had no business refusing and every gate downstream goes INCOMPLETE.");
        // the §2.2 sidecars a healthy parallel run has always written are still written
        assertTrue(Files.exists(outDir.resolve("cls.callgraph.json")), "callgraph sidecar still written");
        assertTrue(Files.exists(outDir.resolve("cls.hierarchy.json")), "hierarchy sidecar still written");
        rm(base);
    }

    // ── THE DEFECT ─────────────────────────────────────────────────────────────────────────────────
    /** The classless jar: the single route refuses it, so the parallel route must too — and the refusal
     *  has to survive into the ARTIFACT, because the artifact is all the gate ever reads. */
    @Test
    void parallelRefusesAClasslessJarAndTheGateSeesIt() throws Exception {
        Path base = Files.createTempDirectory("candor-par-refuse");
        try {
            Path jar = classlessJar(base, "empty.jar");
            Files.writeString(base.resolve("policy.txt"), "deny Exec\n");

            // the SINGLE route — the behaviour being propagated, asserted here so the two arms can
            // never be said to agree without one of them having been measured.
            Run single = runCli(base, jar.toString(), "--policy", "policy.txt", "--json", "single.json");
            assertEquals(2, single.exit(), "precondition: the single route refuses a classless target");
            assertTrue(single.stderr().contains("no .class files found"), single.stderr());

            Path outDir = base.resolve("out");
            Run par = runCli(base, "--parallel", outDir.toString(), jar.toString());
            assertNotEquals(0, par.exit(),
                    "a --parallel run whose only target was unevaluable must NOT exit 0. stderr: " + par.stderr());
            assertTrue(par.stderr().contains("no .class files"),
                    "and it must name the cause the single route names. stderr: " + par.stderr());

            Path rep = outDir.resolve("empty.json");
            assertTrue(Files.exists(rep),
                    "the document is WRITTEN, not withheld: a consumer that reads a missing file as "
                    + "'nothing to report' fails open by the other route (the §3.1 ruling behind "
                    + "writeRefusedGateJson). What must change is what the document SAYS.");
            var doc = json(rep);
            assertTrue(doc.get("unanalyzed") instanceof List<?> l && !l.isEmpty(),
                    "…and it says it judged nothing, in the one key a ⟨0.24⟩ consumer already reads as "
                    + "'no purity licence'. Got " + doc);
            assertEquals(List.of(), doc.get("functions"), "no findings are claimed either way");

            // THE POINT OF THE WHOLE FIX: what CI reads.
            Run gate = runCli(base, "gate", "--report", outDir.resolve("empty").toString(),
                    "--policy", "policy.txt", "--gate-json", "gate.json");
            assertEquals(2, gate.exit(),
                    "`gate --report` over the refusal must be INCOMPLETE (exit 2), not a green 0 with a "
                    + "note on stderr. A note beside exit 0 is not a verdict. stderr: " + gate.stderr());
            var verdict = json(base.resolve("gate.json"));
            assertEquals(Boolean.FALSE, verdict.get("ok"), "and the verdict document agrees. " + verdict);

            // ⟨0.28⟩ pairing rule: no LIVE sidecar beside a report that judged nothing.
            assertFalse(Files.exists(outDir.resolve("empty.callgraph.json")),
                    "a refused report must not sit beside a live §2.2 call-graph sidecar — `callers`/"
                    + "`whatif` are answered FROM the sidecar, and a confident blast radius over a scan "
                    + "that read no bytecode is the cardinal sin one file over.");
        } finally {
            rm(base);
        }
    }

    /** The same unevaluable spelled as a SOURCE directory — the shape a repo root has before a build.
     *  Both spellings reach {@code ctx().ALL.isEmpty()}; asking only about jars pins half the fix. */
    @Test
    void parallelRefusesASourceOnlyDirectory() throws Exception {
        Path base = Files.createTempDirectory("candor-par-src");
        try {
            Path src = sourceOnlyDir(base);
            Path outDir = base.resolve("out");
            Run par = runCli(base, "--parallel", outDir.toString(), src.toString());
            assertNotEquals(0, par.exit(), "stderr: " + par.stderr());
            var doc = json(outDir.resolve("srcOnly.json"));
            assertTrue(doc.get("unanalyzed") instanceof List<?> l && !l.isEmpty(), "got " + doc);
        } finally {
            rm(base);
        }
    }

    // ── CONTROL + DEFECT TOGETHER ──────────────────────────────────────────────────────────────────
    /** THE MIXED RUN. One good target, one classless: the run must refuse AND keep the good target's
     *  findings. The parallel arm's existing failure posture already says this for a MISSING target
     *  ("a crashing target must never vanish under a green exit, and the healthy work isn't thrown
     *  away"); the refusal has to inherit it rather than invent a stricter one. */
    @Test
    void aMixedRunRefusesWithoutLosingTheGoodTargetsFindings() throws Exception {
        Path good = goodTarget();
        Path base = good.getParent();
        try {
            Path jar = classlessJar(base, "empty.jar");
            Path outDir = base.resolve("out-mixed");
            rm(outDir);
            Run par = runCli(base, "--parallel", outDir.toString(), good.toString(), jar.toString());
            assertNotEquals(0, par.exit(), "one unevaluable target fails the run. stderr: " + par.stderr());

            Path goodRep = outDir.resolve("cls.json");
            assertTrue(Files.exists(goodRep), "the good target's report still lands");
            assertTrue(fnNames(goodRep).contains("app.Fx.reads"),
                    "…with its findings intact — a refusal must not throw away work that succeeded. "
                    + "Got " + fnNames(goodRep));
            assertFalse(json(goodRep).containsKey("unanalyzed"),
                    "and the good target must NOT be marked unanalyzed because a SIBLING was: the "
                    + "refusal is per-target, and a run-wide one would turn every multi-module CI sweep "
                    + "INCOMPLETE on one resources-only jar.");

            var badDoc = json(outDir.resolve("empty.json"));
            assertTrue(badDoc.get("unanalyzed") instanceof List<?> l && !l.isEmpty(),
                    "…while the classless one is refused. Got " + badDoc);
        } finally {
            rm(base);
        }
    }
}
