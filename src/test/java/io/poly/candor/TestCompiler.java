package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;

/**
 * The shared in-process javac harness for fixture-compiling tests: write {name → source} fixtures to a
 * fresh temp dir, compile them with the system compiler, hand back the classes dir for {@code
 * Candor.runScan}. Skips (JUnit assumption) on a JRE-only runtime; a fixture that fails to compile fails
 * the test. {@link #compileApp} is the two-phase variant: the lib map is compiled to a SEPARATE dir used
 * only as {@code -classpath} (never scanned), the app map is compiled against it — the harness for
 * external-framework fixtures (Panache / inherited-persistence / HTTP-client tests).
 */
final class TestCompiler {

    private TestCompiler() {}

    /** Compile the given {name → source} fixtures; returns the classes dir ({@code <temp>/cls}). */
    static Path compile(Map<String, String> sources, String... javacFlags) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-test");
        List<String> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path p = dir.resolve(e.getKey());
            Files.createDirectories(p.getParent());
            Files.writeString(p, e.getValue());
            files.add(p.toString());
        }
        Path out = dir.resolve("cls");
        Files.createDirectories(out);
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        // Extra javac flags (e.g. `-XDstringConcat=inline` to force the classic StringBuilder concat shape
        // instead of the JDK 9+ default `invokedynamic makeConcatWithConstants`).
        for (String f : javacFlags) args.add(f);
        args.addAll(files);
        assertEquals(0, jc.run(null, null, null, args.toArray(new String[0])), "fixture must compile");
        return out;
    }

    /** Two-phase harness: {@code lib} → a separate dir used only as {@code -classpath} (NOT scanned);
     *  {@code app} compiled against it. Returns the app classes dir ({@code <temp>/app}). */
    static Path compileApp(Map<String, String> lib, Map<String, String> app) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path base = Files.createTempDirectory("candor-test");
        Path libOut = compileTo(jc, base.resolve("src-lib"), lib, base.resolve("lib"), null);
        compileTo(jc, base.resolve("src-app"), app, base.resolve("app"), libOut);
        return base.resolve("app");
    }

    private static Path compileTo(javax.tools.JavaCompiler jc, Path src, Map<String, String> sources,
            Path out, Path classpath) throws Exception {
        List<String> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path p = src.resolve(e.getKey());
            Files.createDirectories(p.getParent());
            Files.writeString(p, e.getValue());
            files.add(p.toString());
        }
        Files.createDirectories(out);
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        if (classpath != null) { args.add("-cp"); args.add(classpath.toString()); }
        args.addAll(files);
        assertEquals(0, jc.run(null, null, null, args.toArray(new String[0])), "fixture must compile");
        return out;
    }

    /** Recursively delete {@code dir} (test cleanup — a missing dir or a failed delete is ignored). */
    static void rm(Path dir) {
        if (dir == null || !Files.exists(dir)) return;
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> { try { Files.delete(p); } catch (Exception ignored) {} });
        } catch (Exception ignored) {
        }
    }
}
