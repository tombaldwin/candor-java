package corpus;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/** Corpus entry: real Net + Fs effects performed THROUGH concurrency mechanisms (virtual thread,
 *  CompletableFuture, parallel stream). The JFR oracle records the actual Socket/File I/O with stack
 *  traces and attributes it to the project frame on the executing thread (the lambda body); this gives
 *  RUNTIME ground-truth confirmation of the "lambda effects attributed at the creation site" model the
 *  synthetic sweep only checked statically. Uses java.io streams (JFR sees those; pure-NIO it doesn't). */
public class AsyncNetFs {
    public static void main(String[] a) throws Exception {
        loopbackNetViaVirtualThread();
        fsViaCompletableFuture();
        fsViaParallelStream();
    }

    /** Real loopback Socket I/O — the client side runs inside a virtual-thread lambda. */
    static void loopbackNetViaVirtualThread() throws Exception {
        try (ServerSocket server = new ServerSocket(0)) {
            int port = server.getLocalPort();
            Thread vt = Thread.ofVirtual().start(() -> {
                try (Socket c = new Socket("127.0.0.1", port)) {
                    c.getOutputStream().write("hi".getBytes());   // SocketWrite (on the virtual thread)
                    c.getInputStream().read();                    // SocketRead
                } catch (IOException ignored) {
                }
            });
            try (Socket s = server.accept()) {
                s.getInputStream().read();                        // SocketRead (on the main thread)
                s.getOutputStream().write("yo".getBytes());       // SocketWrite
            }
            vt.join();
        }
    }

    /** Real file write inside a CompletableFuture task. */
    static void fsViaCompletableFuture() throws Exception {
        File f = File.createTempFile("candor-oracle-cf", ".txt");
        CompletableFuture.runAsync(() -> {
            try (FileOutputStream o = new FileOutputStream(f)) {
                o.write("x".getBytes());                          // FileWrite (on a CF worker thread)
            } catch (IOException ignored) {
            }
        }).join();
        f.delete();
    }

    /** Real file writes inside a parallel-stream forEach. */
    static void fsViaParallelStream() throws Exception {
        List<File> files = new ArrayList<>();
        for (int i = 0; i < 3; i++) files.add(File.createTempFile("candor-oracle-ps" + i, ".txt"));
        files.parallelStream().forEach(f -> {
            try (FileOutputStream o = new FileOutputStream(f)) {
                o.write("y".getBytes());                          // FileWrite (on FJ pool threads)
            } catch (IOException ignored) {
            }
        });
        for (File f : files) f.delete();
    }
}
