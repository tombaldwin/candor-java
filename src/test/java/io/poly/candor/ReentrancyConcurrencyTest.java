package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The LB-1b guarantee: the analysis context is thread-local, so concurrent scans on different threads are
 * isolated. Two threads each scan a different target in a tight loop; an effect from one must never leak
 * into the other's result. With the pre-LB-1b single static handle, one thread's {@code resetState()}
 * would swap the context out from under the other mid-scan, corrupting results (or throwing) — this test
 * is the teeth that would catch a regression back to a shared handle.
 */
class ReentrancyConcurrencyTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-conc");
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
        args.addAll(files);
        assertEquals(0, jc.run(null, null, null, args.toArray(new String[0])), "fixture must compile");
        return out;
    }

    private static void rm(Path dir) {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (Exception ignored) {
        }
    }

    @Test
    void concurrentScansDoNotClobberEachOther() throws Exception {
        // Target NET: a method that opens a socket. Target PURE: arithmetic only, no effect anywhere.
        Path net = compile(Map.of("app/Netter.java",
                "package app; public class Netter { public void hit(){ try { new java.net.Socket(\"h\",80).close(); }"
                        + " catch(Exception e){} } }"));
        Path pure = compile(Map.of("app/Adder.java",
                "package app; public class Adder { public int add(int a,int b){ return a+b; } }"));

        int iterations = 60;
        CountDownLatch start = new CountDownLatch(1);
        List<String> failures = new CopyOnWriteArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(2);

        Runnable netJob = () -> {
            try {
                start.await();
                for (int i = 0; i < iterations; i++) {
                    Map<String, EffectSet> inf = Candor.runScan(net);
                    EffectSet e = inf.get("app.Netter.hit");
                    if (e == null || !e.contains(Effect.NET))
                        failures.add("net-thread iter " + i + ": app.Netter.hit lost Net (got " + e + ")");
                }
            } catch (Throwable t) {
                failures.add("net-thread threw: " + t);
            }
        };
        Runnable pureJob = () -> {
            try {
                start.await();
                for (int i = 0; i < iterations; i++) {
                    Map<String, EffectSet> inf = Candor.runScan(pure);
                    // No method in the pure target may carry Net — that would be cross-thread contamination.
                    for (var en : inf.entrySet())
                        if (en.getValue().contains(Effect.NET))
                            failures.add("pure-thread iter " + i + ": " + en.getKey() + " leaked Net");
                }
            } catch (Throwable t) {
                failures.add("pure-thread threw: " + t);
            }
        };

        pool.submit(netJob);
        pool.submit(pureJob);
        start.countDown();                 // release both threads together to maximize interleaving
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS), "scans did not finish — possible deadlock");

        rm(net);
        rm(pure);
        assertTrue(failures.isEmpty(), "concurrent scans clobbered each other:\n  " + String.join("\n  ", failures));
    }
}
