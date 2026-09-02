package io.poly.candor;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;

import io.poly.candor.model.Effect;

/**
 * SOUNDNESS R151 — A CHAINED DEPENDENCY THAT KEEPS ITS KEY AND CHANGES ITS VALUE MUST DISCARD THE CACHE.
 *
 * <p>{@link Refresh}'s whole-program digest folded in {@code crossDeps.keySet()} and none of the VALUES,
 * while {@link Candor#inheritDepFn} writes those values — effects, the four literal surfaces,
 * {@code netClass}, {@code incomplete}, {@code unknownWhy} — into the per-class accumulators the cache
 * stores. So a dependency function that kept its key and GAINED an effect was replayed from cache
 * without it. Measured on the published 0.34.0 jar, one variable, app bytecode byte-identical: a warm
 * cache primed under a dep reporting {@code ['Db']}, rerun under the same dep reporting
 * {@code ['Db','Net']}, exits 0 with "no violations" and "reused 1 of 1" under {@code deny Net}, while
 * the fresh-cache and no-cache controls both exit 1. It needs only a warm cache, which is the normal
 * CI configuration.
 *
 * <p><b>Two tests, because the defect has two halves and only one of them is about this fixture.</b>
 * {@link #aDependencyThatGainsAnEffectIsNotReplayedFromCache} is the end-to-end regression: the whole
 * pipeline, real compiled fixtures, dep reports written by this build, byte equality against a cold
 * scan. {@link #everyDepValueMovesTheDigest} is the one that stops it coming back, and it exists
 * because of HOW the hole opened: {@code DepFn} grew four fields after the digest was written
 * ({@code unknownWhy} ⟨0.19⟩, {@code netClass} ⟨0.20⟩, {@code fn} ⟨0.24⟩, {@code incomplete} ⟨0.29⟩)
 * and every one escaped a hand-written rendering. That test enumerates the record's fields
 * REFLECTIVELY and requires each one, individually, to move the digest — so a field added tomorrow is
 * covered by a test nobody has to remember to update, and one that is NOT folded in fails by name.
 */
class RefreshDepDigestTest {

    // lib v1 and lib v2 declare the SAME method — same owner, name and descriptor, so the same
    // `crossDeps` key — and differ only in what that method does. v2 reaches the network as well.
    private static final Map<String, String> LIB_V1 = Map.of("lib/Repo.java", """
            package lib;
            import java.nio.file.*;
            public class Repo {
                public void go() throws Exception { Files.readAllBytes(Path.of("/tmp/alpha")); }
            }
            """);
    private static final Map<String, String> LIB_V2 = Map.of("lib/Repo.java", """
            package lib;
            import java.nio.file.*; import java.net.*;
            public class Repo {
                public void go() throws Exception {
                    Files.readAllBytes(Path.of("/tmp/alpha"));
                    new URL("http://dep.example.com/x").openConnection().getInputStream().close();
                }
            }
            """);
    private static final Map<String, String> APP = Map.of("app/Main.java", """
            package app;
            public class Main {
                public static void main(String[] a) throws Exception { new lib.Repo().go(); }
            }
            """);

    @Test
    void aDependencyThatGainsAnEffectIsNotReplayedFromCache() throws Exception {
        Path appDir = compileApp(LIB_V1, APP);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            // The dependency's own reports, produced by THIS build so the §2.1 version gate trusts them
            // (a distrusted report is downgraded to Unknown, which would mask exactly what this measures).
            Path dep1 = base.resolve("dep-v1.json");
            Path dep2 = base.resolve("dep-v2.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(compileApp(LIB_V1, APP).getParent().resolve("lib")),
                    dep1.toString(), null);
            ReportWriter.writeReport(Candor.runScan(compileApp(LIB_V2, APP).getParent().resolve("lib")),
                    dep2.toString(), null);

            Path cache = base.resolve("cache");
            Run prime  = scan(appDir, base, dep1, cache);   // prime the cache under v1
            Run sameV1 = scan(appDir, base, dep1, cache);   // …and prove the cache ENGAGES here
            Run warmV2 = scan(appDir, base, dep2, cache);   // the arm under test
            Run coldV2 = scan(appDir, base, dep2, null);    // the answer it must reproduce
            Run coldV1 = scan(appDir, base, dep1, null);

            // THE PERTURBATION HAS TO REACH THE CONSUMER. Without this the equality below is passed
            // perfectly by a fixture whose dep report the app never joins with — the vacuous arm this
            // family keeps finding. Checked on the two COLD scans, so it says nothing about the cache.
            assertNotEquals(coldV1.report, coldV2.report,
                    "the dep perturbation moved no cold report — the cross-jar join never happened, so "
                    + "every other assertion here is vacuous");
            assertTrue(coldV2.report.contains("\"Net\""), "the v2 dep's Net must reach the consumer's report");

            // …AND THE CACHE HAS TO ENGAGE. A build that ignored the refresh entirely would pass the
            // equality too, having compared two cold scans. The engine discloses its reuse on stderr, and
            // the run that has to show one is the UNCHANGED rerun — not the arm under test, which after
            // the fix correctly reuses nothing.
            assertEquals(prime.report, sameV1.report, "two runs over an unchanged fixture must agree");
            assertTrue(sameV1.reused > 0,
                    "the cache never reused a class on this fixture; the comparison below is vacuous");

            assertEquals(coldV2.report, warmV2.report,
                    "SOUNDNESS R151: the dependency function kept its key and changed its value, and the "
                    + "refresh replayed the consumer from a cache primed under the OLD value. A stale "
                    + "entry read as current is a silent under-report — here it is `deny Net` exit 1 -> 0.");
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** Every field of {@link DepFn}, one at a time, must move the whole-program digest.
     *
     *  <p>Reflective over {@code DepFn}'s own declared fields rather than a list written here, for the
     *  reason the defect existed: a hand-written list covers the fields its author remembered, and the
     *  field most likely to be missing is the one just added. A new field of a shape this test cannot
     *  perturb fails LOUDLY rather than passing silently — an unperturbable field is exactly the one
     *  that would slip through the digest too. */
    @Test
    void everyDepValueMovesTheDigest() throws Exception {
        Path classes = Path.of("build/classes/java/main");
        if (!Files.isDirectory(classes)) classes = Path.of("build/classes/java/test");
        assertTrue(Files.isDirectory(classes), "no compiled classes to measure against");

        Path cacheDir = Files.createTempDirectory("candor-r151");
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            List<ClassNode> cns = Candor.prepareScan(classes, null, false);
            AnalysisContext ctx = AnalysisState.ctx();
            Refresh r = Refresh.forScan(withRefresh(Config.empty(), cacheDir), cns);

            // A baseline entry under one key, and the digest that entry produces.
            ctx.crossDeps.clear();
            DepFn base = new DepFn();
            base.effects.add(Effect.FS);
            base.hosts.add("a.example.com");
            base.cmds.add("ls");
            base.paths.add("/tmp/alpha");
            base.tables.add("users");
            base.netClass.add("resolved");
            base.incomplete.add("Fs");
            base.unknownWhy.add("reflect:java.lang.Class.forName");
            base.fn = "lib.Repo.go";
            base.stale = false;
            ctx.crossDeps.put("lib/Repo.go()V", base);
            String baseline = r.wholeProgramDigest(cns);

            List<String> unmoved = new ArrayList<>();
            for (java.lang.reflect.Field f : DepFn.class.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) continue;
                f.setAccessible(true);
                DepFn mutated = copyOf(base);
                perturb(f, mutated);
                ctx.crossDeps.put("lib/Repo.go()V", mutated);
                if (baseline.equals(r.wholeProgramDigest(cns))) unmoved.add(f.getName());
                ctx.crossDeps.put("lib/Repo.go()V", base);
            }
            assertTrue(unmoved.isEmpty(), "SOUNDNESS R151: changing DepFn." + String.join("/", unmoved)
                    + " leaves the refresh digest identical, so a cache primed under the old value is "
                    + "replayed after it changes. Every field of a chained dep entry is folded into a "
                    + "per-class accumulator, so every field has to be in the key.");

            // The dep's own call graph, read during per-class analyze through Candor#depTransitiveWhy.
            ctx.crossDeps.put("lib/Repo.go()V", base);
            String before = r.wholeProgramDigest(cns);
            ctx.depCallsByFn.put("lib.Repo.go", List.of("lib.Deep.reflect"));
            assertNotEquals(before, r.wholeProgramDigest(cns), "depCallsByFn is not in the digest");
            before = r.wholeProgramDigest(cns);
            ctx.depWhyByFn.put("lib.Deep.reflect", List.of("reflect:java.lang.Class.forName"));
            assertNotEquals(before, r.wholeProgramDigest(cns), "depWhyByFn is not in the digest");

            // THE CONTROL FOR OVER-INVALIDATION. Rendering is order-insensitive on the wire surfaces
            // (they are "Lists on the wire but sets in meaning"), because CANDOR_DEPS is walked in an
            // order Files.walk does not fix — a digest that flapped with that order would miss every
            // run and delete the feature while passing every equivalence arm.
            DepFn reordered = copyOf(base);
            reordered.hosts = new ArrayList<>(List.of("z.example.com", "a.example.com"));
            base.hosts = new ArrayList<>(List.of("a.example.com", "z.example.com"));
            ctx.crossDeps.put("lib/Repo.go()V", base);
            String ordered = r.wholeProgramDigest(cns);
            ctx.crossDeps.put("lib/Repo.go()V", reordered);
            assertEquals(ordered, r.wholeProgramDigest(cns),
                    "the same surface in a different LIST ORDER must give the same digest");
        } finally {
            Candor.config = saved;
            rm(cacheDir);
        }
    }

    /** The batched feed must not let an identity hash slip past the guard.
     *
     *  <p>{@link Refresh#wholeProgramDigest} feeds the dep rendering in 64 KB batches and asserts that
     *  "a batch breaks at an entry boundary, and an identity hash is emitted inside one value, so the
     *  pattern still cannot span a break". That is an assertion written by the change that needed it to
     *  be true, which is the shape this project keeps finding to be false — so it is measured. Enough
     *  entries to force many batches, with the offending value in a LATE one, well past the first break. */
    @Test
    void anIdentityHashIsCaughtEvenWhenTheRenderingIsFedInBatches() throws Exception {
        Path classes = Path.of("build/classes/java/main");
        if (!Files.isDirectory(classes)) classes = Path.of("build/classes/java/test");
        assertTrue(Files.isDirectory(classes), "no compiled classes to measure against");

        Path cacheDir = Files.createTempDirectory("candor-r151-batch");
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            List<ClassNode> cns = Candor.prepareScan(classes, null, false);
            AnalysisContext ctx = AnalysisState.ctx();
            Refresh r = Refresh.forScan(withRefresh(Config.empty(), cacheDir), cns);

            ctx.crossDeps.clear();
            for (int i = 0; i < 4000; i++) {           // ~64 bytes each: several batches
                DepFn d = new DepFn();
                d.effects.add(Effect.FS);
                d.paths.add("/tmp/entry-" + i);
                ctx.crossDeps.put("lib/Repo.m" + i + "()V", d);
            }
            r.wholeProgramDigest(cns);                 // clean: no identity hash anywhere

            DepFn poisoned = new DepFn();
            poisoned.effects.add(Effect.FS);
            poisoned.hosts.add("org.objectweb.asm.tree.AnnotationNode@7a81197d");
            ctx.crossDeps.put("lib/Repo.zzzLast()V", poisoned);   // sorts last: a late batch
            IllegalStateException e = org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalStateException.class, () -> r.wholeProgramDigest(cns));
            assertTrue(e.getMessage().contains("identity hash"),
                    "the digest raised, but not for the identity hash: " + e.getMessage());
        } finally {
            Candor.config = saved;
            rm(cacheDir);
        }
    }

    // ---- harness -------------------------------------------------------------------------------------

    /** One scan of the app with {@code dep} chained and, when {@code cache} is non-null, the refresh on.
     *  Returns the report DOCUMENT, because byte equality over the document is the refresh's own
     *  acceptance standard — an effect-set comparison is blind to `paths`, `incomplete` and `unknownWhy`,
     *  which is where three of this defect's eight axes live. */
    /** One scan: the report document it wrote, and the reuse it disclosed. */
    private record Run(String report, int reused) {}

    private static Run scan(Path appDir, Path base, Path dep, Path cache) throws Exception {
        Files.createDirectories(base.resolve(".candor"));
        Files.writeString(base.resolve(".candor/config"), "deps " + dep + "\n");
        Candor.config = withRefresh(Config.forTarget(appDir), cache);
        Path out = Files.createTempFile(base, "report", ".json");
        // The reuse count is DISCLOSED ON STDERR and nowhere else, and it is the only thing that
        // distinguishes a cache that engaged from one that never did — the byte-equality arms are passed
        // perfectly by a build that ignores the cache entirely. So capture it rather than infer it.
        PrintStream savedErr = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(buf, true, StandardCharsets.UTF_8));
            ReportWriter.writeReport(Candor.runScan(appDir), out.toString(), null);
        } finally {
            System.setErr(savedErr);
            savedErr.print(buf.toString(StandardCharsets.UTF_8));   // never swallow a warning
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("reused (\\d+) of (\\d+)").matcher(buf.toString(StandardCharsets.UTF_8));
        return new Run(Files.readString(out), m.find() ? Integer.parseInt(m.group(1)) : 0);
    }

    /** Set the {@code refresh} value on a Config.
     *
     *  <p>{@code refresh} is deliberately NOT one of {@code Config.KNOWN_KEYS} — it is env-only
     *  ({@code CANDOR_REFRESH}), and the cross-engine key vocabulary is not this test's to widen. A JUnit
     *  test cannot set an environment variable for its own process, so it writes the same slot the env
     *  read lands in. {@code Config#value} consults env then this map and cannot tell them apart, so this
     *  is a state the CLI reaches every time someone exports CANDOR_REFRESH — not a fixture that could
     *  never occur. */
    @SuppressWarnings("unchecked")
    private static Config withRefresh(Config cfg, Path cache) throws Exception {
        if (cache == null) return cfg;
        java.lang.reflect.Field f = Config.class.getDeclaredField("values");
        f.setAccessible(true);
        ((Map<String, String>) f.get(cfg)).put("refresh", cache.toString());
        return cfg;
    }

    private static DepFn copyOf(DepFn d) {
        DepFn c = new DepFn();
        c.effects = d.effects.copy();
        c.hosts = new ArrayList<>(d.hosts);
        c.cmds = new ArrayList<>(d.cmds);
        c.paths = new ArrayList<>(d.paths);
        c.tables = new ArrayList<>(d.tables);
        c.netClass = new ArrayList<>(d.netClass);
        c.incomplete = new ArrayList<>(d.incomplete);
        c.unknownWhy = new ArrayList<>(d.unknownWhy);
        c.stale = d.stale;
        c.fn = d.fn;
        return c;
    }

    /** Change one field to a DIFFERENT value of the same shape — near-miss, never absence. An empty
     *  value would only prove the digest looks at the key; it has to look at what the key SAYS. */
    @SuppressWarnings("unchecked")
    private static void perturb(java.lang.reflect.Field f, DepFn d) throws Exception {
        Object v = f.get(d);
        if (v instanceof io.poly.candor.model.EffectSet es) { es.add(Effect.NET); return; }
        if (v instanceof List<?>) { ((List<String>) v).add("PERTURBED"); return; }
        if (v instanceof Boolean b) { f.set(d, !b); return; }
        if (v == null || v instanceof String) { f.set(d, "PERTURBED-" + f.getName()); return; }
        throw new AssertionError("DepFn." + f.getName() + " is a " + v.getClass().getName()
                + ", which this test cannot perturb — add a case. A field nobody can perturb here is "
                + "exactly the field that would slip out of the digest unnoticed (SOUNDNESS R151).");
    }
}
