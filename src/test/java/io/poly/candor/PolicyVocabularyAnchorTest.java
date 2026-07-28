package io.poly.candor;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * ⟨0.24⟩ SPEC §3.1 / candor-spec {@code 99eb4e9} — <b>POLICY VOCABULARY ANCHORS AT THE POLICY FILE, ON
 * EVERY CHANNEL.</b> {@code unknown-alias} is part of the policy's own vocabulary, so it resolves relative
 * to the RESOLVED policy path however that path was supplied — {@code --policy}, {@code CANDOR_POLICY}, or
 * the config {@code policy} key. TARGET-scoped keys ({@code net-partner}, {@code deps}, scan settings) keep
 * anchoring at the target, because they describe the thing being scanned; that half is the mirror below.
 */
class PolicyVocabularyAnchorTest {

    private record Run(int exit, String stdout, String stderr) {}

    private Path scratch;

    @BeforeEach
    void mkScratch() throws Exception {
        scratch = Files.createTempDirectory("candor-vocab-anchor");
    }

    @AfterEach
    void rmScratch() throws Exception {
        if (scratch == null || !Files.exists(scratch)) return;
        try (Stream<Path> s = Files.walk(scratch)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    /** Run the real CLI as a subprocess (main() calls System.exit), with an env overlay. */
    private static Run runCli(Map<String, String> env, String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().putAll(env);
        Process p = pb.start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    private Path compile(String dir, String src) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path srcDir = scratch.resolve("src-" + dir);   // public class Svc ⇒ the file MUST be named Svc.java
        Files.createDirectories(srcDir);
        Path file = srcDir.resolve("Svc.java");
        Files.writeString(file, src);
        Path out = scratch.resolve(dir);
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), file.toString()), "fixture must compile");
        return out;
    }

    private static JsonObject doc(Path p) throws Exception {
        return JsonParser.parseString(Files.readString(p)).getAsJsonObject();
    }


    /**
     * SPEC §3.1 ⟨0.24⟩ / candor-spec {@code 99eb4e9}: `unknown-alias` resolves relative to the POLICY
     * file's directory on both routes. This engine keyed that on {@code --policy} being passed as a FLAG,
     * so a policy supplied through `CANDOR_POLICY` — CI's primary channel — anchored at the TARGET
     * instead. Measured before the fix, same policy and same target:
     * <pre>
     *   --policy &lt;file&gt;      exit 1, resolved at the policy's config
     *   gate --report        exit 1, resolved at the policy's config
     *   CANDOR_POLICY        exit 0, ok:true, resolved at the TARGET's config   ← a silent gate PASS
     * </pre>
     */
    @Test
    void theVocabularyAnchorFollowsThePolicyThroughEveryChannel() throws Exception {
        // A reflect-caused Unknown: `corp` = reflect fires, `corp` = native does not.
        Path classes = compile("dyn", """
            package app;
            public class Svc {
                public Object go(String n) throws Exception {
                    return Class.forName(n).getDeclaredConstructor().newInstance();
                }
            }
            """);
        // the TARGET's own config defines `corp` NARROWLY — the rule would not fire under it
        Path targetCfg = scratch.resolve("dyn/.candor/config");
        Files.createDirectories(targetCfg.getParent());
        Files.writeString(targetCfg, "unknown-alias corp = native\n");
        // …and the config beside the POLICY defines it as the class the code actually carries
        Path polDir = scratch.resolve("polhome");
        Files.createDirectories(polDir.resolve(".candor"));
        Files.writeString(polDir.resolve(".candor/config"), "unknown-alias corp = reflect\n");
        Path pol = polDir.resolve("p.policy");
        Files.writeString(pol, "deny Unknown[corp] app\n");

        Path report = scratch.resolve("report.json");
        assertEquals(0, runCli(Map.of(), classes.toString(), "--json", report.toString()).exit(), "scan");

        // The THIRD supply channel — the checked-in config's own `policy` key — is the sharpest case: the
        // file that NAMES the policy is the very file whose (narrower) alias would win under the old
        // anchor. Appended AFTER the report scan above, which must not be gated.
        Files.writeString(targetCfg, "unknown-alias corp = native\npolicy " + pol + "\n");

        Path a = scratch.resolve("a.json"), b = scratch.resolve("b.json"),
             c = scratch.resolve("c.json"), d = scratch.resolve("d.json");
        Run flag = runCli(Map.of(), classes.toString(), "--policy", pol.toString(), "--gate-json", a.toString());
        Run gate = runCli(Map.of(), "gate", "--report", report.toString(), "--policy", pol.toString(),
                "--gate-json", b.toString());
        Run env = runCli(Map.of("CANDOR_POLICY", pol.toString()), classes.toString(), "--gate-json", c.toString());
        Run cfg = runCli(Map.of(), classes.toString(), "--gate-json", d.toString());

        assertEquals(1, flag.exit(), "--policy <file>: the alias resolves at the policy's config\nSTDERR:\n" + flag.stderr());
        assertEquals(1, gate.exit(), "gate --report: likewise\nSTDERR:\n" + gate.stderr());
        assertEquals(1, env.exit(),
                "CANDOR_POLICY is the SAME policy — anchoring its vocabulary at the TARGET is a silent "
                + "gate PASS on CI's primary channel\nSTDERR:\n" + env.stderr());
        assertEquals(1, cfg.exit(),
                "…and so is the config `policy` key: the anchor is the RESOLVED policy path, not the "
                + "channel it arrived on\nSTDERR:\n" + cfg.stderr());

        String polConfig = polDir.resolve(".candor/config").toAbsolutePath().normalize().toString();
        for (Path p : List.of(a, b, c, d)) {
            JsonObject v = doc(p);
            assertFalse(v.get("ok").getAsBoolean(), p.getFileName() + ": ok:false\nDOC:\n" + v);
            assertEquals(polConfig, v.getAsJsonObject("policyVocabulary").get("config").getAsString(),
                    p.getFileName() + ": the disclosed vocabulary source is the POLICY's config on every "
                    + "channel — §3.1's ambience disclosure and the anchor must name the same file\nDOC:\n" + v);
        }
    }

    /**
     * THE MIRROR: a TARGET-scoped config key must NOT move to the policy's directory. `net-partner`
     * describes the thing being scanned, so it keeps anchoring at the target on every channel — if the
     * anchor generalisation had been applied to the whole config rather than to the vocabulary keys, this
     * `deny Net[known-partner]` would stop firing.
     */
    @Test
    void targetScopedConfigKeysStillAnchorAtTheTarget() throws Exception {
        Path classes = compile("net", """
            package app;
            import java.net.URL;
            public class Svc {
                public void fetch() throws Exception {
                    new URL("http://partner.example/x").openConnection().getInputStream();
                }
            }
            """);
        Path targetCfg = scratch.resolve("net/.candor/config");
        Files.createDirectories(targetCfg.getParent());
        Files.writeString(targetCfg, "net-partner partner.example\n");
        Path polDir = scratch.resolve("polhome2");
        Files.createDirectories(polDir);
        Path pol = polDir.resolve("p.policy");
        Files.writeString(pol, "deny Net[known-partner] app\n");

        Map<String, String> envOnly = new LinkedHashMap<>();
        envOnly.put("CANDOR_POLICY", pol.toString());
        Run env = runCli(envOnly, classes.toString());
        Run flag = runCli(Map.of(), classes.toString(), "--policy", pol.toString());
        assertEquals(1, env.exit(),
                "`net-partner` is TARGET-scoped: it must still be read from the target's config when the "
                + "policy came from the environment\nSTDERR:\n" + env.stderr());
        assertEquals(1, flag.exit(),
                "…and from the target's config when the policy came from the flag\nSTDERR:\n" + flag.stderr());
    }
}
