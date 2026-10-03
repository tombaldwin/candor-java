package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R867 / conformance PART 94 — A CALL ON A CHAINED DEPENDENCY'S NON-FINAL CLASS RUNS THAT
 * DEPENDENCY'S OWN SUBCLASS OVERRIDES TOO.
 *
 * <pre>
 *   dep:  class BaseO { void m() {Fs} }        class SubO extends BaseO { void m() {Env} }
 *   app:  viaTyped(BaseO b) { b.m(); }          -- EXECUTED with a SubO: the program reads the environment
 * </pre>
 *
 * Before the fix the chained consumer read {@code [Fs]} — {@code BaseO.m}'s body alone — and {@code deny Env}
 * and {@code deny Env Unknown} both exited 0, while the SAME source scanned as one tree reads
 * {@code [Env, Fs]}. Every arm here was executed in a scratch harness under a SecurityManager oracle before it
 * was written down (the commit message carries the table); the effects asserted are the ones the program
 * performed, and every CONTROL asserts an effect the program provably does NOT perform.
 *
 * <p>Each test is one variable: the consumer text is fixed, and the dependency moves.
 */
class DepOverrideUnionTest {

    private static final String FS = "new java.io.File(\"/tmp\").exists();";
    private static final String ENV = "System.getenv(\"HOME\");";
    private static final String EXEC = "try { new ProcessBuilder(\"/usr/bin/true\").start(); } catch (Exception e) {}";

    /** The PART 94 consumer, byte-identical across the override and control dependencies. */
    private static final String APP = "package app;\nimport dep.*;\npublic class App {\n"
            + "  public static void viaTyped(BaseO b) { b.m(); }\n"
            + "  public static void viaChain() { BaseO.make().m(); }\n"
            + "  public static void viaBound() { BaseO b = BaseO.make(); b.m(); }\n"
            + "  public static void viaNewSub() { BaseO b = new SubO(); b.m(); }\n"
            + "  public static void viaNewBase() { BaseO b = new BaseO(); b.m(); }\n"
            + "  public static void caller() { viaTyped(BaseO.make()); }\n}\n";

    private static Map<String, String> dep(String subBody) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("dep/BaseO.java", "package dep;\npublic class BaseO {\n  public void m() { " + FS + " }\n"
                + "  public static BaseO make() { return new SubO(); }\n}\n");
        m.put("dep/SubO.java", "package dep;\npublic class SubO extends BaseO {\n" + subBody + "}\n");
        return m;
    }

    private static final Map<String, String> OVERRIDE = dep("  @Override public void m() { " + ENV + " }\n");
    /** CONTROL: SubO does NOT override m — its Env sits in a sibling method no consumer path reaches. */
    private static final Map<String, String> SIBLING = dep("  public void n() { " + ENV + " }\n");

    // ---- harness ------------------------------------------------------------------------------------------

    /** Scan `lib` alone, chain its report (and the hierarchy sidecar beside it), scan `app` alone. */
    private static Map<String, EffectSet> chained(Map<String, String> lib, Map<String, String> app) throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path depReport = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            assertTrue(Files.isRegularFile(base.resolve("dep.hierarchy.json")),
                    "the fixture must chain the hierarchy sidecar, or the walk under test has nothing to walk");
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** The SAME source as ONE tree — the engine's own unchained answer, the reference. */
    private static Map<String, EffectSet> whole(Map<String, String> lib, Map<String, String> app) throws Exception {
        Map<String, String> all = new LinkedHashMap<>(lib);
        all.putAll(app);
        Path cls = TestCompiler.compile(all);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            return Candor.runScan(cls);
        } finally {
            Candor.config = saved;
            rm(cls.getParent());
        }
    }

    private static TreeSet<String> eff(Map<String, EffectSet> r, String fn) {
        TreeSet<String> out = new TreeSet<>();
        EffectSet e = r.get(fn);
        if (e != null) for (var x : e.effects()) out.add(x.name());
        return out;
    }

    private static TreeSet<String> set(String... xs) {
        return new TreeSet<>(List.of(xs));
    }

    // ---- the defect: PART 94's three o* arms, and the caller ----------------------------------------------

    @Test
    void aChainedDependencysOwnOverrideReachesEveryPolymorphicCallSite() throws Exception {
        Map<String, EffectSet> c = chained(OVERRIDE, Map.of("app/App.java", APP));
        Map<String, EffectSet> w = whole(OVERRIDE, Map.of("app/App.java", APP));
        for (String fn : List.of("app.App.viaTyped", "app.App.viaChain", "app.App.viaBound", "app.App.caller")) {
            assertEquals(set("ENV", "FS"), eff(w, fn), "reference: one tree must attribute the override at " + fn);
            assertEquals(eff(w, fn), eff(c, fn), fn + ": the chained consumer must carry SubO.m's Env — the"
                    + " dependency's own override is an implementor visible to the consumer (SPEC §4 ⟨0.39⟩),"
                    + " and the one-tree scan of the same source attributes it. Chained read " + eff(c, fn));
        }
    }

    @Test
    void aProvablyTypedReceiverReadsTheBodyItsTypeRuns() throws Exception {
        Map<String, EffectSet> c = chained(OVERRIDE, Map.of("app/App.java", APP));
        assertTrue(eff(c, "app.App.viaNewSub").contains("ENV"), "`BaseO b = new SubO(); b.m()` runs SubO.m:"
                + " the join keyed the static owner BaseO and never looked at the exact receiver. Got "
                + eff(c, "app.App.viaNewSub"));
        assertEquals(set("FS"), eff(c, "app.App.viaNewBase"), "CONTROL: `new BaseO()` is exact — no subtype can"
                + " run, so SubO's override must NOT be charged");
    }

    // ---- the controls: nothing over-charged, nothing hedged ------------------------------------------------

    @Test
    void aSubclassThatDoesNotOverrideAddsNothing() throws Exception {
        Map<String, EffectSet> c = chained(SIBLING, Map.of("app/App.java", APP));
        for (String fn : List.of("app.App.viaTyped", "app.App.viaChain", "app.App.viaBound", "app.App.caller",
                "app.App.viaNewSub", "app.App.viaNewBase"))
            assertEquals(set("FS"), eff(c, fn), fn + ": SubO declares n, not m — its Env is unreachable from"
                    + " every consumer path, so neither the effect nor an Unknown hedge may appear (PART 94 k*)");
    }

    @Test
    void aPureOverrideAddsNothing() throws Exception {
        Map<String, EffectSet> c = chained(dep("  @Override public void m() { }\n  public void n() { " + ENV + " }\n"),
                Map.of("app/App.java", APP));
        assertEquals(set("FS"), eff(c, "app.App.viaTyped"), "a pure override publishes no row; the union adds"
                + " exactly nothing for it");
    }

    /** The walk this change deliberately does NOT take, pinned from the side that would break: a static owner
     *  whose override is PURE publishes no row, and a naive walk UP would charge the base body to a call that
     *  runs nothing (executed: no effect). */
    @Test
    void aPureOverrideAtTheStaticOwnerIsNotChargedTheBaseBody() throws Exception {
        String app = "package app;\nimport dep.*;\npublic class App {\n"
                + "  public static void viaSub(SubO s) { s.m(); }\n}\n";
        Map<String, EffectSet> c = chained(dep("  @Override public void m() { }\n"), Map.of("app/App.java", app));
        assertTrue(eff(c, "app.App.viaSub").isEmpty(), "SubO.m is a pure body the JVM runs instead of BaseO.m;"
                + " charging BaseO's Fs here is a fabrication. Got " + eff(c, "app.App.viaSub"));
    }

    @Test
    void aJdkOwnerIsNeverWalkedIntoADependencysOverride() throws Exception {
        Map<String, String> lib = Map.of("dep/LoudStream.java", "package dep;\n"
                + "public class LoudStream extends java.io.InputStream {\n  public int read() { " + ENV + " return -1; }\n}\n");
        String app = "package app;\npublic class App {\n"
                + "  public static int viaJdk(java.io.InputStream in) throws Exception { return in.read(); }\n}\n";
        Map<String, EffectSet> c = chained(lib, Map.of("app/App.java", app));
        assertFalse(eff(c, "app.App.viaJdk").contains("ENV"), "only an owner a chained dependency DECLARED is"
                + " walked: one library's InputStream.read override must not be charged to every in.read() in"
                + " the consumer. Got " + eff(c, "app.App.viaJdk"));
    }

    // ---- the siblings ------------------------------------------------------------------------------------

    @Test
    void anAbstractBasesConcreteMemberReachesItsOverride() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("dep/AbsO.java", "package dep;\npublic abstract class AbsO {\n  public void m() { " + FS + " }\n}\n");
        lib.put("dep/SubA.java", "package dep;\npublic class SubA extends AbsO {\n  @Override public void m() { " + ENV + " }\n}\n");
        String app = "package app;\nimport dep.*;\npublic class App {\n  public static void viaAbs(AbsO a) { a.m(); }\n}\n";
        assertEquals(set("ENV", "FS"), eff(chained(lib, Map.of("app/App.java", app)), "app.App.viaAbs"));
    }

    @Test
    void everyLevelOfAMultiLevelOverrideIsATarget() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("dep/BaseO.java", "package dep;\npublic class BaseO {\n  public void m() { " + FS + " }\n}\n");
        lib.put("dep/Mid.java", "package dep;\npublic class Mid extends BaseO {\n  public void other() { }\n}\n");
        lib.put("dep/Sub2.java", "package dep;\npublic class Sub2 extends Mid {\n  @Override public void m() { " + EXEC + " }\n}\n");
        lib.put("dep/SubO.java", "package dep;\npublic class SubO extends BaseO {\n  @Override public void m() { " + ENV + " }\n}\n");
        String app = "package app;\nimport dep.*;\npublic class App {\n"
                + "  public static void viaBase(BaseO b) { b.m(); }\n"
                + "  public static void viaMid(Mid s) { s.m(); }\n}\n";
        Map<String, EffectSet> c = chained(lib, Map.of("app/App.java", app));
        assertEquals(set("ENV", "EXEC", "FS"), eff(c, "app.App.viaBase"), "Sub2 overrides TWO levels down,"
                + " through a Mid that declares nothing — the walk is transitive");
        assertTrue(eff(c, "app.App.viaMid").contains("EXEC"), "from Mid the override below is still a target");
        assertFalse(eff(c, "app.App.viaMid").contains("ENV"), "…and SubO, a SIBLING of Mid, is not");
    }

    /** RESIDUAL, pinned so that closing it is a deliberate act. {@code SubG.m(String)} overrides
     *  {@code BaseG.m(Object)} through a synthetic bridge the report never keys. The report cannot tell that
     *  apart from a subclass OVERLOAD (the next test), and a wider match measured 51 overloads in 192 on the
     *  corpus — so the consumer reads exactly what it read before this change (executed: Env). Closing it
     *  needs the producer to publish the bridge's descriptor. If this starts carrying Env, check the
     *  overload control below is still green, then flip this assertion. */
    @Test
    void aGenericParameterOverrideIsAResidual() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("dep/BaseG.java", "package dep;\npublic class BaseG<T> {\n  public void m(T t) { " + FS + " }\n}\n");
        lib.put("dep/SubG.java", "package dep;\npublic class SubG extends BaseG<String> {\n"
                + "  @Override public void m(String s) { " + ENV + " }\n}\n");
        String app = "package app;\nimport dep.*;\npublic class App {\n"
                + "  public static void viaG(BaseG<String> g) { g.m(\"x\"); }\n}\n";
        assertEquals(set("FS"), eff(chained(lib, Map.of("app/App.java", app)), "app.App.viaG"));
    }

    /** THE CONTROL the generic residual is priced against: a NON-generic {@code m(Object)} and a subclass
     *  OVERLOAD {@code m(String)}. The JVM runs BaseO.m (executed: Fs only); charging SubO's Env is a
     *  fabrication, and it is exactly what the wider bridge match did. */
    @Test
    void aSubclassOverloadIsNeverTakenForAnOverride() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("dep/BaseO.java", "package dep;\npublic class BaseO {\n  public void m(Object o) { " + FS + " }\n}\n");
        lib.put("dep/SubO.java", "package dep;\npublic class SubO extends BaseO {\n"
                + "  public void m(String s) { " + ENV + " }\n}\n");
        String app = "package app;\nimport dep.*;\npublic class App {\n"
                + "  public static void viaO(BaseO b) { b.m(\"x\"); }\n}\n";
        assertEquals(set("FS"), eff(chained(lib, Map.of("app/App.java", app)), "app.App.viaO"));
    }

    @Test
    void aCovariantReturnOverrideIsReachedThroughItsBridge() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("dep/BaseC.java", "package dep;\npublic class BaseC {\n  public BaseC self() { " + FS + " return this; }\n}\n");
        lib.put("dep/SubC.java", "package dep;\npublic class SubC extends BaseC {\n"
                + "  @Override public SubC self() { " + ENV + " return this; }\n}\n");
        String app = "package app;\nimport dep.*;\npublic class App {\n  public static void viaC(BaseC b) { b.self(); }\n}\n";
        assertEquals(set("ENV", "FS"), eff(chained(lib, Map.of("app/App.java", app)), "app.App.viaC"));
    }

    @Test
    void finalAndStaticMembersNeverUnion() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("dep/BaseF.java", "package dep;\npublic class BaseF {\n  public final void m() { " + FS + " }\n"
                + "  public static void s() { " + FS + " }\n}\n");
        lib.put("dep/SubF.java", "package dep;\npublic class SubF extends BaseF {\n  public void n() { " + ENV + " }\n"
                + "  public static void s() { " + ENV + " }\n}\n");
        String app = "package app;\nimport dep.*;\npublic class App {\n"
                + "  public static void viaFinal(BaseF b) { b.m(); }\n"
                + "  public static void viaStatic() { BaseF.s(); }\n}\n";
        Map<String, EffectSet> c = chained(lib, Map.of("app/App.java", app));
        assertEquals(set("FS"), eff(c, "app.App.viaFinal"), "a final member has no override to find");
        assertEquals(set("FS"), eff(c, "app.App.viaStatic"), "a HIDDEN static is not a dispatch");
    }

    /** The in-scan bound, applied at the join: past CHA_FANOUT_LIMIT an open hierarchy is disclosed as
     *  Unknown[dispatch] — what the one-tree scan of the same source says — and never unioned. */
    @Test
    void aBroadOverrideFanOutDisclosesRatherThanUnions() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("dep/BaseO.java", "package dep;\npublic class BaseO {\n  public void m() { " + FS + " }\n}\n");
        for (int i = 0; i < Rules.CHA_FANOUT_LIMIT; i++)
            lib.put("dep/S" + i + ".java", "package dep;\npublic class S" + i + " extends BaseO {\n"
                    + "  @Override public void m() { " + (i == 0 ? ENV : EXEC) + " }\n}\n");
        String app = "package app;\nimport dep.*;\npublic class App {\n  public static void viaTyped(BaseO b) { b.m(); }\n}\n";
        Map<String, String> a = Map.of("app/App.java", app);
        assertTrue(eff(whole(lib, a), "app.App.viaTyped").contains("UNKNOWN"),
                "reference: the one-tree scan discloses this fan-out");
        TreeSet<String> got = eff(chained(lib, a), "app.App.viaTyped");
        assertTrue(got.contains("UNKNOWN"), "chained must disclose the same broad dispatch: " + got);
        assertFalse(got.contains("ENV") || got.contains("EXEC"), "…and must not union past the bound: " + got);
    }

    // ---- the gate flip, on the unit and on its caller, through the real CLI ----------------------------------

    private record Run(int exit, String out) {}

    private static Run cli(Map<String, String> env, String... args) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(System.getProperty("java.home") + "/bin/java",
                "-cp", System.getProperty("java.class.path"), "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        pb.environment().remove("CANDOR_DEPS");
        pb.environment().remove("CANDOR_POLICY");
        pb.environment().putAll(env);
        Process p = pb.start();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        p.getInputStream().transferTo(bos);
        return new Run(p.waitFor(), bos.toString());
    }

    @Test
    void denyEnvFiresOnTheUnitAndItsCallerAndNotOnTheControl() throws Exception {
        for (boolean override : new boolean[] { true, false }) {
            Path appDir = compileApp(override ? OVERRIDE : SIBLING, Map.of("app/App.java", APP));
            Path base = appDir.getParent();
            try {
                Path dep = base.resolve("dep.json");
                Run d = cli(Map.of(), base.resolve("lib").toString(), "--json", dep.toString());
                assertTrue(Files.isRegularFile(dep), "dependency scan produced no report: " + d.out());
                for (String scope : List.of("app.App.viaTyped", "app.App.caller")) {
                    for (String pol : List.of("deny Env", "deny Env Unknown")) {
                        Path pp = base.resolve("p.pol");
                        Files.writeString(pp, pol + " " + scope + "\n");
                        Run r = cli(Map.of("CANDOR_DEPS", dep.toString()), appDir.toString(),
                                "--json", base.resolve("app.json").toString(), "--policy", pp.toString());
                        assertEquals(override ? 1 : 0, r.exit(), "`" + pol + " " + scope + "` over the "
                                + (override ? "OVERRIDE dependency must FIRE — the executed program reads env"
                                            : "CONTROL dependency must stay 0 — nothing reachable reads env")
                                + ":\n" + r.out());
                    }
                }
                // The carrier: the scope names a real row and the chain reached the consumer.
                Path pp = base.resolve("p.pol");
                Files.writeString(pp, "deny Fs app.App.viaTyped\n");
                assertEquals(1, cli(Map.of("CANDOR_DEPS", dep.toString()), appDir.toString(), "--json",
                        base.resolve("app.json").toString(), "--policy", pp.toString()).exit(),
                        "deny Fs is the carrier: without it every exit 0 above could be a scope matching nothing");
            } finally {
                rm(base);
            }
        }
    }

    @Test
    void theWalkIsInertWithNothingChained() throws Exception {
        // No CANDOR_DEPS: the consumer of an unchained dependency reads exactly what it did — the override
        // index is empty, so nothing here can invent a charge. (The dep's classes are not in the scan.)
        Path appDir = compileApp(OVERRIDE, Map.of("app/App.java", APP));
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(appDir);
            assertFalse(eff(r, "app.App.viaTyped").contains("ENV"),
                    "an unchained consumer has nothing to walk and must not gain the override's effect: " + r);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }
}
