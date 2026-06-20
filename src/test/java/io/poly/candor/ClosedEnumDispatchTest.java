package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Teeth for the CLOSED-ENUM CHA carve-out ({@link Candor#isClosedEnumOwner}). An enum cannot be
 * extended, so a virtual dispatch over it resolves EXACTLY to its constant bodies — a finite, fully
 * visible set — and resolving all of them is sound even past {@code CHA_FANOUT_LIMIT}, where an OPEN
 * abstract class / interface stays honest {@code Unknown} (an external subtype may exist).
 *
 * <p>The bug this fixes: an enum state machine with per-constant method bodies (jsoup
 * HtmlTreeBuilderState/TokeniserState — 26/68 constants) overflows the fan-out bound and drops to a
 * CIRCULAR {@code Unknown} (each state dispatches to the others) that smears across its whole
 * transitive caller set — the dominant Unknown driver on real OO code.
 */
class ClosedEnumDispatchTest {

    private static Map<String, EffectSet> compileAndScan(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-enum");
        try {
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
            return Candor.runScan(out);
        } finally {
            try (Stream<Path> s = Files.walk(dir)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** Build an enum with {@code n} per-constant bodies (each compiles to a synthetic subclass, so the
     *  abstract {@code act()} fans out to {@code n} CHA targets); the LAST constant's body runs {@code body}. */
    private static String enumWith(String name, int n, String lastBody) {
        StringBuilder b = new StringBuilder("enum ").append(name).append(" {\n");
        for (int i = 0; i < n - 1; i++) b.append("  C").append(i).append(" { void act(){} },\n");
        b.append("  C").append(n - 1).append(" { void act(){ ").append(lastBody).append(" } };\n");
        b.append("  abstract void act();\n}\n");
        return b.toString();
    }

    /** A >12-constant enum where ONE constant performs Net: a base-typed dispatch must report Net —
     *  the closed hierarchy resolves to the constant bodies' effect UNION, not Unknown. */
    @Test
    void effectfulConstantSurfacesThroughBroadEnumDispatch() throws Exception {
        // 14 constants (> CHA_FANOUT_LIMIT = 12), the last opens a Socket.
        String e = enumWith("Eff", 14, "try { new java.net.Socket(\"h\",80); } catch(Exception ex){}");
        Map<String, EffectSet> r = compileAndScan(Map.of("Main.java", String.join("\n",
            e,
            "public class Main {",
            "  void run(Eff x){ x.act(); }",   // polymorphic receiver → CHA over all 14 constants
            "}")));
        EffectSet run = eff(r, "Main.run");
        assertTrue(run.toNames().contains("Net"),
                "a >12-constant enum dispatch must surface the effectful constant's Net, got " + run);
        assertFalse(run.toNames().contains("Unknown"),
                "a closed enum is fully resolved — it must NOT read Unknown, got " + run);
    }

    /** A >12-constant enum whose every constant body is pure: a base-typed dispatch must read PURE,
     *  NOT Unknown. This is the precision win — the smear the old >12-drop produced collapses. */
    @Test
    void pureBroadEnumDispatchIsPureNotUnknown() throws Exception {
        String e = enumWith("Pure", 16, "/* pure */");
        Map<String, EffectSet> r = compileAndScan(Map.of("Main.java", String.join("\n",
            e,
            "public class Main {",
            "  void run(Pure x){ x.act(); }",
            "}")));
        assertTrue(eff(r, "Main.run").isEmpty(),
                "a >12-constant pure enum dispatch must be pure (no Unknown smear), got " + r.get("Main.run"));
    }

    /** The carve-out is ENUM-ONLY: an OPEN abstract class with >12 project subclasses (extensible by an
     *  unseen subtype) dispatched on the base type must STILL read Unknown — the fan-out bound holds for
     *  open hierarchies, so this is no fabrication-by-blanket-disabling-the-limit. */
    @Test
    void openAbstractHierarchyStillReadsUnknown() throws Exception {
        StringBuilder src = new StringBuilder("abstract class Base { abstract void act(); }\n");
        for (int i = 0; i < 14; i++)  // 14 > 12 concrete subclasses, all pure
            src.append("class Sub").append(i).append(" extends Base { void act(){} }\n");
        src.append("public class Main { void run(Base b){ b.act(); } }\n");
        Map<String, EffectSet> r = compileAndScan(Map.of("Main.java", src.toString()));
        assertTrue(eff(r, "Main.run").toNames().contains("Unknown"),
                "a >12 OPEN abstract hierarchy must stay Unknown (bound guards external subtypes), got " + r.get("Main.run"));
    }
}
