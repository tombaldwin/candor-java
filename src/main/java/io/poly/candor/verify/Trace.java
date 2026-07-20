package io.poly.candor.verify;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ⟨verify⟩ The runtime CAPTURE sink of the JVM honesty oracle. The {@link EffectTransformer}-injected
 * bytecode calls {@link #emit} immediately BEFORE each effect-bearing JDK call. Attribution is
 * <b>transitive</b>, matching candor's transitive report: {@code emit} walks the live stack and attributes
 * the effect to the enclosing method AND every caller on it that candor analyzed — so the oracle falsifies a
 * dropped effect at a CALLER (the {@code (A3)} dispatch-edge-drop cardinal-sin class), not only at the leaf.
 * (A direct-only, leaf-only attribution — the transform-time constant this once baked in — is structurally
 * blind to a transitive miss: the effect lands on the leaf method, so a caller wrongly reported pure is never
 * tested. The stack walk closes that hole.) Each distinct {@code (fn,effect)} appends one NDJSON line
 * {@code {"fn":…,"effect":…}} to {@code CANDOR_VERIFY_TRACE}, which {@link HonestyCheck} later reads.
 *
 * <p>The runtime frame carries no descriptor for the analyzed classifier's overload key, so we cannot form
 * candor's fn qual from a stack frame alone. Instead {@link EffectTransformer} REGISTERS, at transform time,
 * a map from each analyzed method's runtime stack key ({@code dotted-owner # name # JVM-descriptor}) to its
 * candor qual (bare, or {@code Class.method(params)} for an overload); {@code emit}'s walk resolves each
 * frame through that registry, so an overloaded caller attributes to the exact qual the report uses.
 *
 * <p>This class is loaded into the TARGET jvm and runs inside its threads. Two hard rules: (1) a trace
 * write failure must NEVER crash the app under test — every I/O path swallows its exception; (2) it shares
 * no code with candor's static classifier (independence — it observes reality, it does not re-derive an
 * opinion). A distinct {@code (fn,effect)} is written once (the oracle is set-based), which bounds the trace
 * to the program's distinct effect-sites regardless of how many times its loops run.
 */
public final class Trace {

    private Trace() {}

    private static BufferedWriter writer;
    private static boolean opened;         // lazy-open attempted (success or hard failure)
    private static boolean disabled;       // no trace file configured, or open failed — emit is a no-op

    // TRANSITIVE-ATTRIBUTION registry: (dotted-owner # name # JVM-descriptor) -> candor fn qual. Populated at
    // transform time by EffectTransformer for EVERY analyzed method — not only effect-leaf ones, because a
    // transitive caller performs no effect in its own body yet must be attributed the effects it reaches.
    private static final Map<String, String> QUALS = new ConcurrentHashMap<>();
    // Each distinct (fn,effect) is written once — the oracle is set-based, so this is loss-free and bounds
    // the trace to distinct effect-sites (a hot loop over one effectful call contributes one line per caller).
    private static final Set<String> SEEN = ConcurrentHashMap.newKeySet();
    private static final StackWalker WALKER = StackWalker.getInstance();

    // Packages candor's classifier cannot see (the report's `coverage.packages`, ⟨0.15⟩). An effect reached
    // THROUGH such a package is one candor's static analysis legitimately cannot follow (and disclosed via the
    // per-fn `invisible` field), so the transitive attribution must STOP at that boundary: a project caller
    // sitting OUTSIDE (above) an uncovered frame reached the effect through code candor never saw, and must
    // not be blamed for it — else the oracle false-positives a "violation" for any library using an unmodelled
    // dep. Loaded once from CANDOR_VERIFY_UNCOVERED (empty ⇒ no boundary ⇒ attribution exactly as before).
    private static final String[] UNCOVERED = loadUncovered();

    private static String[] loadUncovered() {
        String path = System.getenv("CANDOR_VERIFY_UNCOVERED");
        if (path == null || path.isEmpty()) return new String[0];
        try {
            java.util.List<String> out = new java.util.ArrayList<>();
            for (String l : java.nio.file.Files.readAllLines(java.nio.file.Path.of(path))) {
                String t = l.trim();
                if (!t.isEmpty()) out.add(t);
            }
            return out.toArray(new String[0]);
        } catch (Exception e) {
            return new String[0]; // unreadable ⇒ no boundary ⇒ normal attribution (sound: no false crediting)
        }
    }

    /** True when {@code className} (dotted) is in — or under — a package candor disclosed as uncovered. */
    private static boolean inUncoveredPackage(String className) {
        if (UNCOVERED.length == 0 || className == null) return false;
        for (String p : UNCOVERED)
            if (className.length() > p.length() && className.startsWith(p) && className.charAt(p.length()) == '.')
                return true;
        return false;
    }

    private static synchronized void openLazily() {
        if (opened) return;
        opened = true;
        String path = System.getenv("CANDOR_VERIFY_TRACE");
        if (path == null || path.isEmpty()) {
            disabled = true;
            return;
        }
        try {
            writer = new BufferedWriter(new FileWriter(path, true /* append */));
        } catch (IOException | RuntimeException e) {
            disabled = true; // opening failed — degrade to a no-op, never crash the app
        }
    }

    /** Called from {@link EffectTransformer} at transform time for each analyzed method: map its runtime stack
     *  key ({@code dotted-owner # name # descriptor}) to candor's fn qual, so {@link #emit}'s stack walk can
     *  attribute precisely (overload-correct). First registration wins — a method is transformed once. */
    public static void registerQual(String key, String qual) {
        if (key != null && qual != null) QUALS.putIfAbsent(key, qual);
    }

    /**
     * Called from injected bytecode immediately BEFORE an effect-leaf call. Attributes {@code effect}
     * TRANSITIVELY — to the enclosing method and every analyzed caller on the live stack — so a caller wrongly
     * reported pure is falsified, not only the leaf. Never throws: any failure is swallowed so the instrumented
     * program runs exactly as if un-instrumented.
     */
    public static void emit(String effect) {
        if (effect == null) return;
        try {
            // Walk from the leaf outward. An ANALYZED project frame (registered at transform time — in QUALS) is
            // ALWAYS attributed and is NEVER a boundary: candor CAN see it, so it must be blamed if it reached
            // the effect (this is checked FIRST so a project package that merely sits UNDER an uncovered ANCESTOR
            // prefix — e.g. project `com.acme.vendor.app` while `com.acme.vendor` is uncovered — is not falsely
            // treated as uncovered and dropped). Only a NON-project frame (qual == null) in an uncovered package
            // is the boundary: every project caller BEYOND it reached the effect through code candor could not
            // see (a broken static chain it disclosed via `invisible`), so blaming those would be a false
            // positive. With no uncovered set this is identical to the plain attribution.
            boolean[] crossed = {false};
            WALKER.forEach(f -> {
                if (crossed[0]) return;
                String cn = f.getClassName();
                String qual = QUALS.get(cn + '#' + f.getMethodName() + '#' + f.getDescriptor());
                if (qual != null) { recordOne(qual, effect); return; } // a covered project frame — attribute, never a boundary
                if (inUncoveredPackage(cn)) crossed[0] = true;          // a non-project frame in an uncovered package = the boundary
            });
        } catch (Throwable ignored) {
            // A capture failure must never perturb the program under test.
        }
    }

    private static void recordOne(String fn, String effect) {
        if (!SEEN.add(fn + ' ' + effect)) return; // this (fn,effect) already written — set-based oracle
        try {
            synchronized (Trace.class) {
                if (!opened) openLazily();
                if (disabled || writer == null) return;
                writer.write("{\"fn\":");
                writeJsonString(writer, fn);
                writer.write(",\"effect\":");
                writeJsonString(writer, effect);
                writer.write("}\n");
                writer.flush(); // flush eagerly: the app may exit hard (System.exit / crash) with no shutdown hook
            }
        } catch (Throwable ignored) {
            // A capture failure must never perturb the program under test.
        }
    }

    /** Minimal JSON string escaping — no dependency on Gson in the TARGET jvm's instrumented path. */
    private static void writeJsonString(BufferedWriter w, String s) throws IOException {
        w.write('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> w.write("\\\"");
                case '\\' -> w.write("\\\\");
                case '\n' -> w.write("\\n");
                case '\r' -> w.write("\\r");
                case '\t' -> w.write("\\t");
                default -> {
                    if (c < 0x20) {
                        w.write(String.format("\\u%04x", (int) c));
                    } else {
                        w.write(c);
                    }
                }
            }
        }
        w.write('"');
    }
}
