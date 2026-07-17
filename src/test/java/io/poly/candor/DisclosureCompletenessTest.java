package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The DISCLOSURE-COMPLETENESS gate (DISCLOSURE-COMPLETENESS-DESIGN.md): for every way a call edge can arise,
 * a reachable effect is either RESOLVED into the report or DISCLOSED as `Unknown` — never SILENTLY dropped.
 * Each fixture has exactly one Net effect reachable only through one edge kind; the entry method's signature
 * must be non-empty (Net = resolved, or Unknown = disclosed). An EMPTY signature = a silent false all-clear,
 * the exact cardinal-sin class candor exists to prevent — a red test here is a real soundness bug, not noise.
 * This is the static, by-construction complement to the dynamic honesty oracle: universal over enumerated
 * kinds, where the oracle is existential over executed paths.
 */
class DisclosureCompletenessTest {

    private Path scratch;

    @BeforeEach void mk() throws Exception { scratch = Files.createTempDirectory("candor-dc"); }

    @AfterEach void rm() throws Exception {
        if (scratch == null) return;
        try (Stream<Path> s = Files.walk(scratch)) { s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
    }

    private static JavaCompiler compiler() {
        JavaCompiler jc = ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        return jc;
    }

    /** Compile the named sources into <scratch>/classes and return that dir. */
    private Path compile(Map<String, String> sources) throws Exception {
        Path src = scratch.resolve("src"), out = scratch.resolve("classes");
        Files.createDirectories(src);
        Files.createDirectories(out);
        List<String> files = new ArrayList<>();
        for (var e : sources.entrySet()) {
            Path f = src.resolve(e.getKey());
            Files.createDirectories(f.getParent());
            Files.writeString(f, e.getValue());
            files.add(f.toString());
        }
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        args.addAll(files);
        int rc = compiler().run(null, null, null, args.toArray(new String[0]));
        org.junit.jupiter.api.Assertions.assertEquals(0, rc, "fixture must compile");
        return out;
    }

    /** Run `candor <classesDir> --json` in a subprocess and return the report JSON. */
    private static String scanJson(Path classesDir) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        Process p = new ProcessBuilder(javaBin, "-cp", cp, "io.poly.candor.Candor", classesDir.toString(), "--json").start();
        String out = drain(p.getInputStream());
        drain(p.getErrorStream());
        p.waitFor();
        return out;
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    /** The inferred effect names (incl. "Unknown") of the function whose name ends with fnSuffix; empty if
     *  the function is absent from the report — i.e. claimed pure `(∅, ∅)`. */
    private static List<String> signatureOf(String json, String fnSuffix) {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonArray fns = root.getAsJsonArray("functions");
        List<String> names = new ArrayList<>();
        if (fns == null) return names;
        for (var el : fns) {
            JsonObject o = el.getAsJsonObject();
            if (o.get("fn").getAsString().endsWith(fnSuffix)) {
                JsonArray inf = o.getAsJsonArray("inferred");
                if (inf != null) inf.forEach(x -> names.add(x.getAsString()));
            }
        }
        return names;
    }

    /** The disclosure-completeness assertion for a single-effect fixture: the entry method is not silently pure. */
    private void assertReachesOrDiscloses(String kind, Path classesDir) throws Exception {
        List<String> sig = signatureOf(scanJson(classesDir), "Entry.entry");
        assertFalse(sig.isEmpty(),
                "[" + kind + "] a Net effect reachable only via this edge kind was SILENTLY DROPPED — entry() reads pure "
                + "(∅,∅). It must be RESOLVED (Net present) or DISCLOSED (Unknown + reason), never absent.");
    }

    private static final String SVC = """
        package app;
        public class Svc {
            public void doNet() throws Exception { new java.net.URL("http://x.example").openConnection().getInputStream(); }
        }
        """;

    @Test void directCall() throws Exception {
        assertReachesOrDiscloses("direct", compile(Map.of(
            "app/Svc.java", SVC,
            "app/Entry.java", "package app; public class Entry { public void entry() throws Exception { new Svc().doNet(); } }")));
    }

    @Test void reflection() throws Exception {
        assertReachesOrDiscloses("reflection", compile(Map.of(
            "app/Svc.java", SVC,
            "app/Entry.java", """
                package app;
                public class Entry {
                    public void entry() throws Exception {
                        Object s = Class.forName("app.Svc").getConstructor().newInstance();
                        Class.forName("app.Svc").getMethod("doNet").invoke(s);
                    }
                }
                """)));
    }

    @Test void callbackIndirection() throws Exception {
        assertReachesOrDiscloses("callback", compile(Map.of(
            "app/Svc.java", SVC,
            "app/Entry.java", """
                package app;
                public class Entry {
                    interface R { void run() throws Exception; }
                    private R held;
                    private void store(R r) { held = r; }
                    public void entry() throws Exception { store(new Svc()::doNet); held.run(); }
                }
                """)));
    }

    @Test void nativeBoundary() throws Exception {
        // A native method has no bytecode body — candor cannot see through it, so calls to it must DISCLOSE
        // `native`, never read as pure. (The method is never linked; analysis only reads the declaration.)
        assertReachesOrDiscloses("native", compile(Map.of(
            "app/Entry.java", """
                package app;
                public class Entry {
                    private native void doNativeIo();
                    public void entry() { doNativeIo(); }
                }
                """)));
    }

    @Test void virtualDispatch() throws Exception {
        assertReachesOrDiscloses("virtual-dispatch", compile(Map.of(
            "app/Svc.java", SVC,
            "app/Entry.java", """
                package app;
                public class Entry {
                    interface Rate { void fetch() throws Exception; }
                    static class HttpRate implements Rate { public void fetch() throws Exception { new Svc().doNet(); } }
                    public void entry() throws Exception { Rate r = new HttpRate(); r.fetch(); }
                }
                """)));
    }
}
