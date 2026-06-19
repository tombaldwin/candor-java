import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runtime sink for the candor leaf-instrumenting agent.
 *
 * Instrumented application classes contain {@code INVOKESTATIC EffectRecorder.record(String)} inserted
 * immediately before a genuine effect-leaf call (e.g. ProcessBuilder.start). When that leaf is about to
 * run, we walk the current thread's stack and attribute the effect to EVERY project frame on it, so the
 * effect lands on the method that actually performed it AND every method on the path that reached it —
 * exactly the per-method attribution candor's static report uses, independent of how the path was reached
 * (direct call, reflection, dynamic dispatch, library callback).
 *
 * MUST be on the SYSTEM classpath so the instrumented app classes can resolve the INVOKESTATIC target.
 * The agent achieves this with Instrumentation.appendToSystemClassLoaderSearch in premain.
 */
public final class EffectRecorder {
    private EffectRecorder() {}

    // "<dotted.Class>.<method>" -> set of candor effect names observed on it.
    private static final Map<String, Set<String>> OBSERVED = new ConcurrentHashMap<>();
    private static final boolean DEBUG = Boolean.getBoolean("candor.agent.debug");

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(EffectRecorder::dump, "candor-agent-dump"));
    }

    /** Inserted by the transformer right before each instrumented leaf call. */
    public static void record(String effect) {
        StackTraceElement[] st = Thread.currentThread().getStackTrace();
        // st[0] = Thread.getStackTrace, st[1] = this record() method. Start at the caller.
        for (int i = 2; i < st.length; i++) {
            StackTraceElement f = st[i];
            String cls = f.getClassName();
            // Never attribute to JDK / agent infra frames — same skip set as the transformer.
            if (cls.startsWith("java.") || cls.startsWith("jdk.") || cls.startsWith("sun.")
                    || cls.startsWith("com.sun.") || cls.equals("EffectRecorder")
                    || cls.equals("EffectAgent") || cls.startsWith("org.objectweb.asm.")) {
                continue;
            }
            // Synthetic lambda/proxy bridge frames are not source methods candor names. Skip.
            if (cls.contains("$$Lambda") || cls.contains("$$")) {
                continue;
            }
            String key = cls + "." + f.getMethodName();
            OBSERVED.computeIfAbsent(key, k -> ConcurrentHashMap.newKeySet()).add(effect);
        }
        if (DEBUG) {
            System.err.println("[candor-agent] record " + effect + " @ "
                    + (st.length > 2 ? st[2].getClassName() + "." + st[2].getMethodName() : "?"));
        }
    }

    private static void dump() {
        String out = System.getProperty("candor.agent.out", "./agent-observed.json");
        try (Writer w = Files.newBufferedWriter(Paths.get(out), StandardCharsets.UTF_8)) {
            w.write("{\n");
            List<String> keys = new ArrayList<>(OBSERVED.keySet());
            keys.sort(String::compareTo);
            for (int i = 0; i < keys.size(); i++) {
                String k = keys.get(i);
                Set<String> effs = new TreeSet<>(OBSERVED.get(k));
                w.write("  " + quote(k) + ": [");
                int j = 0;
                for (String e : effs) {
                    if (j++ > 0) w.write(", ");
                    w.write(quote(e));
                }
                w.write("]");
                w.write(i + 1 < keys.size() ? ",\n" : "\n");
            }
            w.write("}\n");
        } catch (IOException e) {
            System.err.println("[candor-agent] failed to write " + out + ": " + e);
        }
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
