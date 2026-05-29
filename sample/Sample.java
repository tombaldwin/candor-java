import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

// candor-java sample target. Expected effects in comments.
public class Sample {
    static String readConfig(Path p) throws IOException {
        return Files.readString(p);                 // Fs
    }

    static void spawn() throws IOException {
        new ProcessBuilder("ls").start();           // Exec
    }

    static String home() {
        return System.getenv("HOME");               // Env
    }

    static long now() {
        return System.currentTimeMillis();          // Clock
    }

    static String pure(int a, int b) {
        return Integer.toString(a + b);             // pure -> {}
    }

    // transitive: { Exec*, Env*, Fs*, Clock* }
    static void handle(Path p) throws IOException {
        readConfig(p);
        home();
        now();
        spawn();
    }

    // reflection -> Unknown (candor can't see what Method.invoke dispatches to)
    static Object dynamic(Object o, String m) throws Exception {
        return o.getClass().getMethod(m).invoke(o);
    }

    // transitive Unknown
    static void viaReflection(Object o) throws Exception {
        dynamic(o, "toString");
    }

    public static void main(String[] args) {}
}
