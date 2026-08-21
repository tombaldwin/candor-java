package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * THE A/A CAPTURE: the same verb, the same build, the same inputs, in SEPARATE JVM LAUNCHES, must emit
 * byte-identical JSON. `Map.of` with 2+ pairs is a MapN whose iteration order is SALTED PER LAUNCH, so a
 * single-process test can never see this defect — each test here drives several real subprocesses and
 * byte-compares, then pins the intended key order explicitly so a lucky salt cannot pass either.
 *
 * <p>The containment verb's fix (and its 8-run measurement) already sits in Query.java; these are the
 * three verbs the review found still living four lines from that comment: `path --json` (top-level
 * {fn,effect,path} flipped per launch), `parsepolicy` (the allow/forbid ROW order flipped too, because
 * the byJson comparator sorts rows by their serialized string), and `rewire`'s dropped rows.
 */
class JsonEmitDeterminismTest {

    /** Launches per capture. The salt is per-JVM-launch and constant within one, so N independent
     *  launches all agreeing with the pinned order is what "deterministic" means here. */
    private static final int LAUNCHES = 4;

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

    /** Run the same argv LAUNCHES times; every stdout must be byte-identical to the first. */
    private static String capture(String... args) throws Exception {
        String first = null;
        for (int i = 0; i < LAUNCHES; i++) {
            Run r = runCli(args);
            if (first == null) first = r.stdout();
            else assertEquals(first, r.stdout(),
                    "launch " + (i + 1) + " of the identical command emitted DIFFERENT bytes — a salted "
                    + "`Map.of` iteration order is deciding this document's shape per JVM launch");
        }
        return first;
    }

    /** Pin `keys` to appear in exactly this order in `json` — the salt-cannot-get-lucky half. */
    private static void assertKeyOrder(String json, String... keys) {
        int at = -1;
        for (String k : keys) {
            int i = json.indexOf("\"" + k + "\"");
            assertTrue(i > at, "key \"" + k + "\" is missing or out of place — expected "
                    + String.join(" < ", keys) + " in:\n" + json);
            at = i;
        }
    }

    private Path scratch;

    @BeforeEach
    void mkScratch() throws Exception {
        scratch = Files.createTempDirectory("candor-aa");
    }

    @AfterEach
    void rmScratch() throws Exception {
        if (scratch == null || !Files.exists(scratch)) return;
        try (Stream<Path> s = Files.walk(scratch)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    /** caller() → fetch() → Net, scanned once into {@code <scratch>/report.json} (+ sidecars). */
    private Path chainReport() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path src = scratch.resolve("Svc.java");
        Files.writeString(src, """
            package app;
            import java.net.URL;
            public class Svc {
                public void caller() throws Exception { fetch(); }
                public void fetch() throws Exception {
                    new URL("http://example.com").openConnection().getInputStream();
                }
            }
            """);
        Path cls = scratch.resolve("cls");
        Files.createDirectories(cls);
        assertEquals(0, jc.run(null, null, null, "-d", cls.toString(), src.toString()), "fixture must compile");
        Path report = scratch.resolve("report.json");
        Run r = runCli(cls.toString(), "--json", report.toString());
        assertEquals(0, r.exit(), "the fixture scan must succeed\nSTDERR:\n" + r.stderr());
        return report;
    }

    @Test
    void pathJsonIsLaunchStable() throws Exception {
        Path report = chainReport();
        // The found-chain emit: caller → fetch [Net source].
        String out = capture("path", "caller", "Net", "--report", report.toString(), "--json");
        assertKeyOrder(out, "fn", "effect", "path");
        assertTrue(out.contains("fetch"), "the chain reaches the Net source\n" + out);
        // The no-such-effect emit ({fn, effect, path: []}) is a separate literal in the verb.
        //
        // `Db`, not `Time`. This line used to say `Time`, which is not a candor effect at all (the
        // vocabulary has `Clock`) — so it was reaching the empty emit through a TYPO, and pinning the
        // defect PART 61 closes: `path` scored an unknown effect name as a confident "does not perform"
        // at exit 0. A known effect the report genuinely lacks is the real shape of this case, and it
        // still exercises exactly what this test is about — that the empty emit is launch-stable.
        String none = capture("path", "caller", "Db", "--report", report.toString(), "--json");
        assertKeyOrder(none, "fn", "effect", "path");
    }

    @Test
    void parsepolicyIsLaunchStable() throws Exception {
        // TWO allow rules on purpose: the byJson comparator sorts rows by their serialized string, so a
        // salted per-row key order flipped the ROW order too — the doubly-bad case, and the reason one
        // allow rule cannot pin this.
        Path pol = scratch.resolve("p.policy");
        Files.writeString(pol, """
            allow Net in com.acme.integration api.stripe.com
            allow Fs in com.acme.io /tmp
            forbid com.acme.web -> com.acme.db
            """);
        String out = capture("parsepolicy", pol.toString());
        assertKeyOrder(out, "deny", "allow", "forbid");
        assertKeyOrder(out, "effect", "scope", "values");
        assertKeyOrder(out, "from", "to");
    }

    @Test
    void rewireDroppedRowsAreLaunchStable() throws Exception {
        // Hand-written sidecars: rewire answers FROM the callgraph sidecars, and two dropped edges give
        // two rows — enough for both the per-row key order and the row order to matter.
        Files.writeString(scratch.resolve("cur.json"), "{\"candor\": {}, \"functions\": []}\n");
        Files.writeString(scratch.resolve("base.json"), "{\"candor\": {}, \"functions\": []}\n");
        Files.writeString(scratch.resolve("cur.callgraph.json"),
                "{\"app.A.f\": [\"app.A.g\"], \"app.A.m\": []}\n");
        Files.writeString(scratch.resolve("base.callgraph.json"),
                "{\"app.A.f\": [\"app.A.g\", \"app.A.h\"], \"app.A.m\": [\"app.A.n\"]}\n");
        String out = capture("rewire", scratch.resolve("cur.json").toString(),
                scratch.resolve("base.json").toString(), "--json");
        assertKeyOrder(out, "caller", "no_longer_calls");
        assertKeyOrder(out, "app.A.f", "app.A.m");   // TreeMap row order, launch-independent
    }
}
