package corpus;

import java.util.concurrent.*;

/** Corpus entry: real Exec performed THROUGH concurrency mechanisms (a plain Thread and a
 *  CompletableFuture). The leaf-instrumenting agent records the actual ProcessBuilder.start at runtime
 *  and attributes Exec to the project frame on the executing thread (the lambda body) — runtime
 *  ground-truth confirmation that the deferred/async Exec the synthetic sweep checked statically really
 *  surfaces. Uses /bin/echo (present on macOS and Linux). */
public class AsyncExec {
    public static void main(String[] a) throws Exception {
        execViaThread();
        execViaCompletableFuture();
    }

    static void execViaThread() throws Exception {
        Thread t = new Thread(() -> {
            try {
                new ProcessBuilder("/bin/echo", "candor-oracle-exec").start().waitFor();
            } catch (Exception ignored) {
            }
        });
        t.start();
        t.join();
    }

    static void execViaCompletableFuture() throws Exception {
        CompletableFuture.runAsync(() -> {
            try {
                new ProcessBuilder("/bin/echo", "candor-oracle-exec").start().waitFor();
            } catch (Exception ignored) {
            }
        }).join();
    }
}
