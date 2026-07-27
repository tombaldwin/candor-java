package io.poly.candor;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * `--parallel` PROMISES BYTE-IDENTITY WITH THE STANDALONE RUN, so it has to read the same config.
 *
 * <p>{@code Candor.config} is a process-wide static assigned at exactly one place — the single-target
 * branch of {@code main}. The `--parallel` branch returns before it, so every parallel target scanned
 * with {@code Config.empty()} and every key of a checked-in `.candor/config` was silently dropped. The
 * consequential key is `deps`: the dependency effects simply did not arrive, and the report read CLEANER
 * than a standalone run over the same bytes, which is the direction that matters.
 *
 * <p>Both paths call {@code System.exit}, so this drives the real CLI in a subprocess — the surface the
 * promise is made on.
 */
class ParallelConfigTest {

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
    private static Map<String, List<String>> effectsByFn(Path report) throws Exception {
        Map<String, Object> root = new Gson().fromJson(Files.readString(report), Map.class);
        Map<String, List<String>> out = new java.util.TreeMap<>();
        for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
            out.put((String) e.get("fn"), (List<String>) e.getOrDefault("inferred", List.of()));
        return out;
    }

    /** `lib.Deep.go` reflects; the app calls it, so with the lib's report chained the app is Unknown and
     *  without it the app is bare. The two arms must not disagree about which. */
    @Test
    void parallelHonoursTheTargetsCandorConfig() throws Exception {
        Path appDir = compileApp(
            Map.of("lib/Deep.java", "package lib;\npublic class Deep {\n"
                + "  public void go() throws Exception { Class.forName(\"x.Y\").getMethod(\"m\").invoke(null); }\n}\n"),
            Map.of("app/A.java", "package app;\npublic class A {\n"
                + "  public void run() throws Exception { new lib.Deep().go(); }\n}\n"));
        Path base = appDir.getParent();
        try {
            Path dep = base.resolve("dep.json");
            Files.deleteIfExists(dep);                              // standing-bar item 7
            assertEquals(0, runCli(base, base.resolve("lib").toString(), "--json", dep.toString()).exit());
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + dep + "\n");

            Path single = base.resolve("single.json");
            Files.deleteIfExists(single);
            assertEquals(0, runCli(base, appDir.toString(), "--json", single.toString()).exit());
            var std = effectsByFn(single);
            assertTrue(std.getOrDefault("app.A.run", List.of()).contains("Unknown"),
                    "precondition: the standalone run reads the config, chains the dep and inherits its "
                    + "Unknown — without this the two arms would agree for the wrong reason, and the test "
                    + "would prove nothing. Got " + std);

            Path outDir = base.resolve("par");
            rm(outDir);
            assertEquals(0, runCli(base, "--parallel", outDir.toString(), appDir.toString()).exit());
            var par = effectsByFn(outDir.resolve("app.json"));

            assertEquals(std, par,
                    "`--parallel`'s own contract is that each report is byte-identical to a standalone "
                    + "`candor <target> --json`. Reading the config on one path and not the other made the "
                    + "parallel report read CLEANER than the standalone one over the same bytes.");
        } finally { rm(base); }
    }
}
