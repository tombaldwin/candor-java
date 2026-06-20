package corpus;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

/** Corpus entry: real Exec performed THROUGH concurrency mechanisms (a plain Thread and a
 *  CompletableFuture). The leaf-instrumenting agent records the actual ProcessBuilder.start at runtime
 *  and attributes Exec to the project frame on the executing thread (the lambda body) — runtime
 *  ground-truth confirmation that the deferred/async Exec the synthetic sweep checked statically really
 *  surfaces. Uses /bin/echo (present on macOS and Linux).
 *
 *  FAIL LOUD: the effect MUST actually run for the oracle to mean anything — a swallowed failure (no
 *  /bin/echo, fork denied) would make the entry record no effect and false-green the diff. So any failure
 *  propagates out of main (nonzero exit), which the corpus harness surfaces. */
public class AsyncExec {
    public static void main(String[] a) throws Exception {
        execViaThread();
        execViaCompletableFuture();
    }

    static void execViaThread() throws Exception {
        AtomicReference<Throwable> err = new AtomicReference<>();
        Thread t = new Thread(() -> {
            try {
                new ProcessBuilder("/bin/echo", "candor-oracle-exec").start().waitFor();
            } catch (Exception e) {
                err.set(e);   // captured + rethrown after join (an uncaught throw here wouldn't reach main)
            }
        });
        t.start();
        t.join();
        if (err.get() != null) throw new RuntimeException("execViaThread effect did not run", err.get());
    }

    static void execViaCompletableFuture() {
        CompletableFuture.runAsync(() -> {
            try {
                new ProcessBuilder("/bin/echo", "candor-oracle-exec").start().waitFor();
            } catch (Exception e) {
                throw new RuntimeException(e);   // join() below rethrows -> fails loud
            }
        }).join();
    }
}
