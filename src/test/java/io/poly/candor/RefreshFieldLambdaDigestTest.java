package io.poly.candor;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;

/**
 * SOUNDNESS R163 — A WHOLE-PROGRAM PRE-PASS INPUT DERIVED FROM OTHER CLASSES' BODIES MUST BE IN THE
 * REFRESH DIGEST.
 *
 * <p>R151's class, one field over. ⟨0.35⟩ added {@code fieldLambdaBindings} to {@link AnalysisContext}:
 * {@link Cha#collectFieldLambdaBindings} walks every method's INSTRUCTIONS to bind each functional-
 * interface field to the lambdas/method-refs written into it, and {@link Cha#fieldBoundImplementors}
 * reads it during per-class analyze. So class A's cached delta depends on class B's BODY — precisely
 * what {@link Refresh#wholeProgramDigest} does not cover structurally — and the field reached that
 * digest by no route at all.
 *
 * <p>Measured on the pre-fix HEAD, one variable: {@code Widget.bindSecondary()} goes from a no-op to
 * {@code this.task = Effector::act}. A bound METHOD REFERENCE is chosen deliberately, so javac emits no
 * new synthetic lambda body and {@code Widget}'s structure is byte-identical under {@code javap -p};
 * {@code Caller.class}, {@code Effector.class} and {@code Main.class} are sha256-identical across the two
 * arms. Executed: v1 writes nothing, v2 really writes the witness file through {@code Caller.go}. Cold v1
 * reports {@code Caller.go} absent (pure, correct); cold v2 reports it {@code Fs}, calling
 * {@code Effector.act}. A cache primed under v1 and rerun under v2 replays it as PURE — a report
 * byte-identical to the cold v1 one, {@code refresh — reused 3 of 4}, and {@code pure Caller.go} exit
 * 1 -> 0.
 *
 * <p><b>Two tests, because the defect has two halves and only one of them is about this fixture.</b>
 * {@link #aFieldThatGainsALambdaBindingIsNotReplayedFromCache} is the end-to-end regression.
 * {@link #everySharedInputIsInTheDigestOrIsExplicitlyExcused} is the one that stops the next one, and it
 * exists because of HOW this hole opened: R151's agent audited every non-final non-memo
 * {@code AnalysisContext} field and ruled the remainder byte-derived or recomputed at write time — and it
 * missed this one, which had been added in the very release it was auditing. A prose audit cannot see a
 * field that appears after it. So the shared-input set is now read from
 * {@link AnalysisContext#inputNames()} — the same authority the overlay split and
 * {@code assertNoInputGrowth} already use — and every name in it must be either perturbable-into-the-
 * digest or carry a written excuse here. A field added tomorrow is in neither list and fails BY NAME.
 *
 * <p>{@link RefreshBodyIndependenceTest} cannot see this class of defect and its doc used to say the
 * opposite: it runs {@code prepareScan} over the real bodies in BOTH arms, so every pre-pass output is
 * identical in the two arms by construction. It measures the DIRECT half (analyze reading another
 * class's instructions); this file measures the INDIRECT half (analyze reading an index BUILT from
 * another class's instructions).
 */
class RefreshFieldLambdaDigestTest {

    // Caller dispatches through a functional-interface FIELD. Effector performs the effect. Main binds
    // both and drives the call, so the fixture is executable rather than merely compilable (§E3: an
    // absence-shaped control over a program that cannot run is asserting something about nothing).
    private static final Map<String, String> BASE = Map.of(
            "Caller.java", """
            public class Caller {
                public void go(Widget w) { if (w.task != null) w.task.run(); }
            }
            """,
            "Effector.java", """
            public class Effector {
                public static void act() {
                    try {
                        java.nio.file.Files.write(
                                java.nio.file.Path.of(System.getProperty("candor.r163.witness")),
                                "L2 ran\\n".getBytes(),
                                java.nio.file.StandardOpenOption.CREATE,
                                java.nio.file.StandardOpenOption.APPEND);
                    } catch (Exception e) { throw new RuntimeException(e); }
                }
            }
            """,
            "Main.java", """
            public class Main {
                public static void main(String[] args) {
                    Widget w = new Widget();
                    w.bindPrimary();
                    w.bindSecondary();
                    new Caller().go(w);
                }
            }
            """);

    // v1 and v2 declare the SAME field and the SAME two methods — same names, same descriptors, same
    // access, so the same STRUCTURAL digest — and differ only in what bindSecondary's BODY does.
    private static final String WIDGET_V1 = """
            public class Widget {
                public Runnable task;
                public void bindPrimary() { this.task = () -> { int z = 1 + 1; }; }
                public void bindSecondary() { int noop = 0; }
            }
            """;
    private static final String WIDGET_V2 = """
            public class Widget {
                public Runnable task;
                public void bindPrimary() { this.task = () -> { int z = 1 + 1; }; }
                public void bindSecondary() { this.task = Effector::act; }
            }
            """;

    @Test
    void aFieldThatGainsALambdaBindingIsNotReplayedFromCache() throws Exception {
        Path v1 = compile(withWidget(WIDGET_V1));
        Path v2 = compile(withWidget(WIDGET_V2));
        Path base = Files.createTempDirectory("candor-r163");
        Config saved = Candor.config;
        try {
            Path work = base.resolve("classes");
            Files.createDirectories(work);

            // THE FIXTURE HAS TO RUN, AND THE TWO ARMS HAVE TO DIFFER IN EXACTLY ONE CLASS. Both are
            // controls, not decoration: an absent `Caller.go` is what a BROKEN engine emits too, so the
            // arms must be shown to be a real behavioural difference reached through the field dispatch,
            // and the difference must be Widget's BODY rather than anything the structural digest sees.
            for (String c : List.of("Caller.class", "Effector.class", "Main.class"))
                assertEquals(sha256(v1.resolve(c)), sha256(v2.resolve(c)),
                        c + " differs between the arms — then this measures more than one variable");
            assertNotEquals(sha256(v1.resolve("Widget.class")), sha256(v2.resolve("Widget.class")),
                    "the two Widget bodies compiled to the same bytes; there is nothing to measure");
            assertEquals("", runFixture(v1, base.resolve("witness-v1.txt")),
                    "v1 must NOT reach the effect at runtime — otherwise the 'cold v1 is pure' arm is "
                    + "measuring a wrong engine answer rather than a correct one");
            assertEquals("L2 ran\n", runFixture(v2, base.resolve("witness-v2.txt")),
                    "v2 must really perform the write through Caller.go's field dispatch, or the "
                    + "under-report below is about a program that never had the effect");

            Path cache = base.resolve("cache");
            Run coldV1 = scan(work, v1, base, null);
            Run coldV2 = scan(work, v2, base, null);
            Run prime  = scan(work, v1, base, cache);    // prime the cache under v1
            Run sameV1 = scan(work, v1, base, cache);    // …and prove the cache ENGAGES here
            Run warmV2 = scan(work, v2, base, cache);    // the arm under test

            // THE PERTURBATION HAS TO REACH THE CONSUMER — checked on the two COLD scans, so it says
            // nothing about the cache. Without it the equality below is passed perfectly by a fixture
            // whose binding the dispatch never consults.
            assertNotEquals(coldV1.report, coldV2.report,
                    "the body change moved no cold report — the field-lambda binding never reached "
                    + "Caller.go's dispatch, so every other assertion here is vacuous");
            assertTrue(coldV2.report.contains("Caller.go"),
                    "cold v2 must report Caller.go as reaching the effect: " + coldV2.report);
            assertTrue(!coldV1.report.contains("Caller.go"),
                    "cold v1 must report Caller.go as pure (absent): " + coldV1.report);

            // …AND THE CACHE HAS TO ENGAGE. A build that ignored the refresh entirely would pass the
            // equality too, having compared two cold scans. The run that has to show reuse is the
            // UNCHANGED rerun — not the arm under test, which after the fix correctly reuses nothing.
            assertEquals(prime.report, sameV1.report, "two runs over an unchanged fixture must agree");
            assertTrue(sameV1.reused > 0,
                    "the cache never reused a class on this fixture; the comparison below is vacuous");

            assertEquals(coldV2.report, warmV2.report,
                    "SOUNDNESS R163: Widget's BODY gained a second lambda write to a bound field while "
                    + "Widget's STRUCTURE held still, so the whole-program digest did not move and "
                    + "Caller's delta was replayed from a cache primed under the old binding set. "
                    + "Caller.go comes back PURE over a program that really writes the file — here "
                    + "`pure Caller.go` exit 1 -> 0.");
        } finally {
            Candor.config = saved;
            rm(base);
            rm(v1.getParent());
            rm(v2.getParent());
        }
    }

    /** EVERY SHARED INPUT, FROM THE ENGINE'S OWN LIST, IS EITHER IN THE DIGEST OR EXCUSED IN WRITING.
     *
     *  <p>{@link AnalysisContext#inputNames()} is the authority for "what analyze reads and does not
     *  write" — it is what the overlay split and {@code assertNoInputGrowth} are already derived from —
     *  so it is what this test enumerates, rather than a list of its own. Each name lands in exactly one
     *  of two places: {@link #EXCUSED}, with the reason it cannot go stale, or the perturbation sweep,
     *  which changes the field and requires {@link Refresh#wholeProgramDigest} to MOVE.
     *
     *  <p>The exactness assertion is the load-bearing part. A field added tomorrow appears in
     *  {@code inputNames()} and in neither list, and this test names it. That is the property R151's
     *  prose audit could not have: it enumerated the fields that existed when it ran, and
     *  {@code fieldLambdaBindings} was added in the same release.
     *
     *  <p>Near-miss, never absence (§D): the probe changes a field to a DIFFERENT value of its own shape.
     *  An unperturbable type fails LOUDLY here rather than passing silently — a field nobody can perturb
     *  is exactly the one that would slip out of the digest unnoticed. */
    @Test
    void everySharedInputIsInTheDigestOrIsExplicitlyExcused() throws Exception {
        Path classes = Path.of("build/classes/java/main");
        if (!Files.isDirectory(classes)) classes = Path.of("build/classes/java/test");
        assertTrue(Files.isDirectory(classes), "no compiled classes to measure against");

        List<String> inputs = AnalysisContext.inputNames();
        List<String> covered = new ArrayList<>(EXCUSED.keySet());
        List<String> probed = new ArrayList<>();
        for (String n : inputs) if (!EXCUSED.containsKey(n)) probed.add(n);
        covered.addAll(probed);
        assertEquals(new TreeSet<>(inputs), new TreeSet<>(covered),
                "the shared-INPUT set changed. Every name in AnalysisContext.inputNames() must be either "
                + "folded into Refresh#wholeProgramDigest or listed in EXCUSED with the reason it cannot "
                + "go stale across a refresh. Decide which — do not just make this line pass. SOUNDNESS "
                + "R163 is what happens when a body-derived shared input is neither.");

        Path cacheDir = Files.createTempDirectory("candor-r163-digest");
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            List<ClassNode> cns = Candor.prepareScan(classes, null, false);
            AnalysisContext ctx = AnalysisState.ctx();
            Refresh r = Refresh.forScan(withRefresh(Config.empty(), cacheDir), cns);

            List<String> unmoved = new ArrayList<>();
            for (String name : probed) {
                java.lang.reflect.Field f = AnalysisContext.class.getDeclaredField(name);
                f.setAccessible(true);
                Object before = f.get(ctx);
                String baseline = r.wholeProgramDigest(cns);
                perturb(ctx, f);
                if (baseline.equals(r.wholeProgramDigest(cns))) unmoved.add(name);
                restore(ctx, f, before);
                assertEquals(baseline, r.wholeProgramDigest(cns),
                        "this test failed to restore AnalysisContext." + name + ", so every probe after "
                        + "it measured a moving baseline");
            }
            assertTrue(unmoved.isEmpty(), "SOUNDNESS R163: changing AnalysisContext."
                    + String.join("/", unmoved) + " leaves the refresh digest identical, so a cache "
                    + "primed under the old value is replayed after it changes. A shared input is read "
                    + "during per-class analyze and is not re-derived from the cached class's own bytes, "
                    + "so it has to be in the key.");

            // THE CONTROL FOR OVER-INVALIDATION, on the field this row is about. The binding lists are
            // built in class/method/instruction walk order, which Files.walk does not fix; a digest that
            // flapped with that order would miss every run and delete the feature while passing every
            // equivalence arm above.
            ctx.fieldLambdaBindings.clear();
            ctx.fieldLambdaBindings.put("p/Widget#task", new ArrayList<>(List.of("p.Widget.lambda$a", "p.Effector.act")));
            String ordered = r.wholeProgramDigest(cns);
            ctx.fieldLambdaBindings.put("p/Widget#task", new ArrayList<>(List.of("p.Effector.act", "p.Widget.lambda$a")));
            assertEquals(ordered, r.wholeProgramDigest(cns),
                    "the same binding set in a different LIST ORDER must give the same digest");
            ctx.fieldLambdaBindings.put("p/Widget#task", new ArrayList<>(List.of("p.Effector.act")));
            assertNotEquals(ordered, r.wholeProgramDigest(cns),
                    "…but LOSING a bound implementor must move it — the whole point of the row");
        } finally {
            Candor.config = saved;
            rm(cacheDir);
        }
    }

    // ---- the excuse list ------------------------------------------------------------------------------

    private static final String STRUCTURE =
            "a function of the class STRUCTURE the per-class loop of wholeProgramDigest already hashes "
            + "(name, supertypes, access, every method/field name+descriptor+access, annotations)";
    private static final String DEP_DERIVED =
            "a memoized derivation of crossDeps, which is folded in value-by-value (R151)";
    private static final String AFTER_ANALYZE =
            "never read during per-class analyze: written and read only by the peek / scope / report-write "
            + "phases, which run after the analyze loop and are recomputed on every run, cached or not";

    /** The shared inputs that are deliberately NOT in the digest, each with the reason it cannot make a
     *  cached per-class delta stale. These are ARGUED, not measured — say so rather than let the shape of
     *  the list imply otherwise. What IS measured is that the list is exhaustive: a name that is in
     *  neither this map nor the perturbation sweep fails the test above by name. */
    private static final Map<String, String> EXCUSED = excuses();

    private static Map<String, String> excuses() {
        Map<String, String> m = new LinkedHashMap<>();
        for (String n : List.of("ALL", "byName", "projectClasses", "subtypeIndex", "overloadDescs",
                "classHash")) m.put(n, STRUCTURE);
        for (String n : List.of("depFnsByOwner", "depFnsByOwnerName", "depOwnersBySigBuilt"))
            m.put(n, DEP_DERIVED);
        for (String n : List.of("vocabularySource", "netPartnersSource", "unanalyzed", "excluded",
                "archives", "sourceFiles", "classpathRoots", "scanRoot", "outOfScope", "scannedUnder",
                "peekedClasses")) m.put(n, AFTER_ANALYZE);
        return Map.copyOf(m);
    }

    // ---- harness -------------------------------------------------------------------------------------

    private static final String PROBE = "R163-PERTURB";

    /** Change one shared input to a DIFFERENT value of the same shape. */
    @SuppressWarnings("unchecked")
    private static void perturb(AnalysisContext ctx, java.lang.reflect.Field f) throws Exception {
        Object v = f.get(ctx);
        if (v instanceof Map<?, ?>) { ((Map<Object, Object>) v).put(PROBE, probeValueFor(f)); return; }
        if (v instanceof Collection<?>) { ((Collection<Object>) v).add(PROBE); return; }
        if (v instanceof Boolean b) { f.set(ctx, !b); return; }
        if (v instanceof Integer i) { f.set(ctx, i + 1); return; }
        if (v == null || v instanceof String) { f.set(ctx, PROBE + '-' + f.getName()); return; }
        throw new AssertionError("AnalysisContext." + f.getName() + " is a "
                + v.getClass().getName() + ", which this test cannot perturb — add a case, or excuse the "
                + "field in EXCUSED with a reason. A shared input nobody can perturb here is exactly the "
                + "one that would slip out of the digest unnoticed (SOUNDNESS R163).");
    }

    /** A value of the map's own declared VALUE type, so the digest renders it the way it renders a real
     *  one — a {@code Collection}-valued map is read back as a collection by the rendering, and a
     *  {@code DepFn}-valued one through {@link DepFn#renderTo}. Reading the declared type rather than
     *  naming the fields keeps this honest when a new map is added. */
    private static Object probeValueFor(java.lang.reflect.Field f) {
        java.lang.reflect.Type t = f.getGenericType();
        Class<?> raw = null;
        if (t instanceof java.lang.reflect.ParameterizedType pt && pt.getActualTypeArguments().length == 2) {
            java.lang.reflect.Type v = pt.getActualTypeArguments()[1];
            if (v instanceof java.lang.reflect.ParameterizedType inner) v = inner.getRawType();
            if (v instanceof Class<?> c) raw = c;
        }
        if (raw == null) throw new AssertionError("cannot read the value type of AnalysisContext."
                + f.getName() + " — add a case rather than guessing (SOUNDNESS R163)");
        if (Collection.class.isAssignableFrom(raw)) return new ArrayList<>(List.of(PROBE));
        if (raw == DepFn.class) { DepFn d = new DepFn(); d.fn = PROBE; return d; }
        if (raw == String.class) return PROBE;
        throw new AssertionError("AnalysisContext." + f.getName() + " holds a " + raw.getName()
                + " value, which this test cannot fabricate — add a case (SOUNDNESS R163).");
    }

    @SuppressWarnings("unchecked")
    private static void restore(AnalysisContext ctx, java.lang.reflect.Field f, Object before) throws Exception {
        Object v = f.get(ctx);
        if (v instanceof Map<?, ?> m) { ((Map<Object, Object>) m).remove(PROBE); return; }
        if (v instanceof Collection<?> c) { ((Collection<Object>) c).remove(PROBE); return; }
        f.set(ctx, before);
    }

    private static Map<String, String> withWidget(String widget) {
        Map<String, String> m = new HashMap<>(BASE);
        m.put("Widget.java", widget);
        return m;
    }

    /** Run the compiled fixture and return what it wrote through the field dispatch. */
    private static String runFixture(Path classes, Path witness) throws Exception {
        String saved = System.getProperty("candor.r163.witness");
        System.setProperty("candor.r163.witness", witness.toString());
        try (URLClassLoader cl = new URLClassLoader(new URL[]{classes.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            cl.loadClass("Main").getMethod("main", String[].class)
                    .invoke(null, (Object) new String[0]);
        } finally {
            if (saved == null) System.clearProperty("candor.r163.witness");
            else System.setProperty("candor.r163.witness", saved);
        }
        return Files.exists(witness) ? Files.readString(witness) : "";
    }

    /** One scan of {@code work} after populating it from {@code from}; the refresh is on when
     *  {@code cache} is non-null. Byte equality over the whole report DOCUMENT is the refresh's own
     *  acceptance standard, so that is what comes back. */
    private record Run(String report, int reused) {}

    private static Run scan(Path work, Path from, Path base, Path cache) throws Exception {
        try (var s = Files.list(work)) {
            for (Path p : s.toList()) Files.delete(p);
        }
        try (var s = Files.list(from)) {
            for (Path p : s.toList())
                Files.copy(p, work.resolve(p.getFileName().toString()), StandardCopyOption.REPLACE_EXISTING);
        }
        Candor.config = withRefresh(Config.forTarget(work), cache);
        Path out = Files.createTempFile(base, "report", ".json");
        // The reuse count is DISCLOSED ON STDERR and nowhere else, and it is the only thing that tells a
        // cache that engaged from one that never did — the byte-equality arms are passed perfectly by a
        // build that ignores the cache entirely. So capture it rather than infer it.
        PrintStream savedErr = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(buf, true, StandardCharsets.UTF_8));
            ReportWriter.writeReport(Candor.runScan(work), out.toString(), null);
        } finally {
            System.setErr(savedErr);
            savedErr.print(buf.toString(StandardCharsets.UTF_8));   // never swallow a warning
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("reused (\\d+) of (\\d+)").matcher(buf.toString(StandardCharsets.UTF_8));
        return new Run(Files.readString(out), m.find() ? Integer.parseInt(m.group(1)) : 0);
    }

    /** {@code refresh} is env-only (CANDOR_REFRESH) and a JUnit test cannot set an environment variable
     *  for its own process, so this writes the same slot the env read lands in — a state the CLI reaches
     *  every time someone exports it, not a fixture that could never occur. */
    @SuppressWarnings("unchecked")
    private static Config withRefresh(Config cfg, Path cache) throws Exception {
        if (cache == null) return cfg;
        java.lang.reflect.Field f = Config.class.getDeclaredField("values");
        f.setAccessible(true);
        ((Map<String, String>) f.get(cfg)).put("refresh", cache.toString());
        return cfg;
    }

    private static String sha256(Path p) throws Exception {
        return java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));
    }
}
