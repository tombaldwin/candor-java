package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * ⟨0.39⟩ A WARM CACHE MUST NOT REPUBLISH THE SILENCE THIS RUNG CLOSES.
 *
 * <p>{@link Refresh} caches, per class, exactly what that class's {@code analyze} WROTE. ⟨0.39⟩ adds one
 * accumulator to that delta — {@code AnalysisContext#dispatchDirect}, the abstraction members a body
 * dispatches on — so a delta written by the PRE-RUNG build carries no such key, and replaying it reproduces
 * the pre-rung report byte for byte: the dispatching row is not merely missing its {@code dispatchesOn}, it
 * is ABSENT from {@code functions} altogether, because naming a dispatch is the only reason a PURE row is
 * emitted at all. Absence is a purity claim, so the cache would serve the exact silence SOUNDNESS R475 is
 * about — invisibly, on a warm run, which is the normal CI configuration (SOUNDNESS R151 is the record of
 * what that costs: a {@code deny Net} that went exit 1 to exit 0).
 *
 * <p>The engine-build check in {@link Refresh#readFile} does not cover it: a build that keeps its version
 * string while gaining an accumulator is precisely this case. The remedy is the {@code FORMAT} bump
 * ({@code candor-refresh-1} → {@code -2}), which also changes the cache FILENAME, so an old file is never
 * opened rather than being opened and reconciled.
 *
 * <p><b>Both arms are EXECUTED.</b> Asserting that the bump discards an old file proves only that the
 * engine looks at the name. The control replays the SAME stripped delta under the NEW name and requires the
 * silence to come back — which is what makes "the bump is load-bearing" a measurement instead of a claim.
 */
class RefreshDispatchesOnTest {

    /** The abstraction is NESTED, for the reason {@link ChainedDispatchUnionTest} gives. */
    private static final Map<String, String> LIB = Map.of(
        "iface/backend/Backend.java", "package iface.backend;\npublic interface Backend { int size(); }\n",
        "iface/TestBackend.java", "package iface;\nimport iface.backend.Backend;\n"
            + "public class TestBackend implements Backend { public int size() { return 7; } }\n",
        "iface/Terminal.java", "package iface;\nimport iface.backend.Backend;\n"
            + "public class Terminal { public static int termSize(Backend b) { return b.size(); } }\n");

    private static final String ROW = "iface.Terminal.termSize";

    @Test
    void aPreRungCacheIsDiscardedRatherThanReplayed() throws Exception {
        Path cls = TestCompiler.compile(LIB);
        Path base = cls.getParent();
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Path cache = base.resolve("cache");
            Files.createDirectories(cache);

            String cold = scan(cls, null);
            assertTrue(cold.contains(ROW) && cold.contains("dispatchesOn"),
                    "the fixture must produce the ⟨0.39⟩ row at all, else every arm below is vacuous: " + cold);

            // Prime, and prove the cache ENGAGES — a build ignoring the refresh passes every byte-equality
            // arm here by comparing two cold scans.
            scan(cls, cache);
            Run warm = scanRun(cls, cache);
            assertTrue(warm.reused > 0, "the cache never reused a class; the comparison below is vacuous");
            assertEquals(cold, warm.report, "a warm run over an unchanged tree must reproduce the cold bytes");

            // THE PRE-RUNG DELTA: the same cache with `dispatchDirect` removed from every stored delta,
            // which is exactly the shape a build without this accumulator writes.
            Path old = base.resolve("cache-old");
            Files.createDirectories(old);
            int stripped = stripDispatchDirect(cache.resolve("candor-refresh-2.json"),
                    old.resolve("candor-refresh-1.json"));
            assertTrue(stripped > 0, "no stored delta carried `dispatchDirect`, so stripping it proves"
                    + " nothing — the fixture is not exercising the accumulator this test is about");

            assertEquals(cold, scan(cls, old),
                    "a cache file written under the PREVIOUS format must be discarded, not replayed —"
                    + " replaying it republishes the pre-rung report, and the dispatching row's ABSENCE"
                    + " from `functions` is a purity claim (SOUNDNESS R475, via R151's mechanism)");

            // THE CONTROL. The identical stripped delta under the CURRENT name: the silence must return.
            // Without this the arm above passes on any build that merely looks at the file name.
            Path unbumped = base.resolve("cache-unbumped");
            Files.createDirectories(unbumped);
            stripDispatchDirect(cache.resolve("candor-refresh-2.json"),
                    unbumped.resolve("candor-refresh-2.json"));
            String replayed = scan(cls, unbumped);
            assertNotEquals(cold, replayed, "THE CONTROL DID NOT DISCRIMINATE: replaying a pre-rung delta"
                    + " under the current name produced the post-rung report, so the FORMAT bump is not"
                    + " what is protecting anything and this test cannot fail");
            assertFalse(replayed.contains("dispatchesOn"),
                    "…and the shape it produces is the pre-rung one: " + replayed);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** Copy {@code from} to {@code to} with every stored class delta's {@code dispatchDirect} key removed;
     *  returns how many deltas carried one. A NEAR-MISS, not an absence: the document stays structurally
     *  valid and differs only in the one key the rung added. */
    private static int stripDispatchDirect(Path from, Path to) throws Exception {
        JsonObject root = new Gson().fromJson(Files.readString(from), JsonObject.class);
        int n = 0;
        for (var e : root.getAsJsonObject("classes").entrySet()) {
            JsonObject delta = e.getValue().getAsJsonObject().getAsJsonObject("delta");
            if (delta != null && delta.has("dispatchDirect")) {
                delta.remove("dispatchDirect");
                n++;
            }
        }
        root.addProperty("format", to.getFileName().toString().replace(".json", ""));
        Files.writeString(to, root.toString());
        return n;
    }

    private record Run(String report, int reused) {}

    private static String scan(Path dir, Path cache) throws Exception {
        return scanRun(dir, cache).report();
    }

    private static Run scanRun(Path dir, Path cache) throws Exception {
        Candor.config = withRefresh(Config.empty(), cache);
        Path out = Files.createTempFile(dir.getParent(), "report", ".json");
        PrintStream savedErr = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(buf, true, StandardCharsets.UTF_8));
            ReportWriter.writeJson(Candor.runScan(dir), out.toString());
        } finally {
            System.setErr(savedErr);
            savedErr.print(buf.toString(StandardCharsets.UTF_8));   // never swallow a warning
        }
        var m = java.util.regex.Pattern.compile("reused (\\d+) of (\\d+)")
                .matcher(buf.toString(StandardCharsets.UTF_8));
        return new Run(Files.readString(out), m.find() ? Integer.parseInt(m.group(1)) : 0);
    }

    /** {@code refresh} is env-only ({@code CANDOR_REFRESH}) and a JUnit test cannot set an environment
     *  variable for its own process, so this writes the same slot the env read lands in — the state the CLI
     *  reaches every time someone exports it. Same device as {@code RefreshDepDigestTest#withRefresh}. */
    @SuppressWarnings("unchecked")
    private static Config withRefresh(Config cfg, Path cache) throws Exception {
        if (cache == null) return cfg;
        java.lang.reflect.Field f = Config.class.getDeclaredField("values");
        f.setAccessible(true);
        ((Map<String, String>) f.get(cfg)).put("refresh", cache.toString());
        return cfg;
    }
}
