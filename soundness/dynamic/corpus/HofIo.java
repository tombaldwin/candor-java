package corpus;

import java.io.*;
import java.net.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Corpus entry (jfr_diff: Fs + Net) — effects reached through DYNAMIC DISPATCH and a JDK higher-order
 * function callback, two paths a purely-syntactic analysis can miss.
 *
 *   Fs  : main -> List.forEach(this::sink)  [JDK HOF] -> sink -> Task.run (interface dispatch)
 *         -> FileTask.run -> FileOutputStream.write
 *   Net : main -> netTask via the SAME Task interface -> SocketTask.run -> Socket.getOutputStream().write
 *
 * The leaf effects are real java.io / java.net writes, so JFR will record them; the question the harness
 * answers is whether candor connects the call through the lambda passed to List.forEach AND through the
 * Task interface to the concrete FileTask / SocketTask bodies.
 */
public class HofIo {

    interface Task { void run() throws Exception; }

    static final class FileTask implements Task {
        public void run() throws Exception {
            try (FileOutputStream f = new FileOutputStream("/tmp/dyn-corpus/hof.txt")) {
                f.write("hof-dispatch-fs".getBytes());
            }
        }
    }

    static final class SocketTask implements Task {
        final int port;
        SocketTask(int port) { this.port = port; }
        public void run() throws Exception {
            try (Socket s = new Socket("127.0.0.1", port)) {
                s.getOutputStream().write("hof-dispatch-net".getBytes());
            }
        }
    }

    /** Invoked as a JDK HOF callback (List.forEach(this::sink)) — and dispatches via the Task interface. */
    static void sink(Task t) {
        try { t.run(); } catch (Exception e) { throw new RuntimeException(e); }
    }

    public static void main(String[] args) throws Exception {
        new File("/tmp/dyn-corpus").mkdirs();

        // Net plumbing: a loopback acceptor so the SocketTask write completes.
        ServerSocket ss = new ServerSocket(0);
        int port = ss.getLocalPort();
        Thread acceptor = new Thread(() -> {
            try (Socket c = ss.accept()) { c.getInputStream().read(); } catch (Exception e) {}
        });
        acceptor.start();

        List<Task> tasks = List.of(new FileTask(), new SocketTask(port));
        Consumer<Task> via = HofIo::sink;     // method ref handed to a JDK HOF
        tasks.forEach(via);                   // List.forEach -> sink -> Task.run (dynamic dispatch)

        acceptor.join();
        ss.close();
        System.out.println("HofIo: ran FileTask + SocketTask via List.forEach/Task dispatch");
    }
}
