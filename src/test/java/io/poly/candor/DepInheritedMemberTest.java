package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R868 / R916 / R869 — vein D, dispatch at a chained consumer over a dependency's types: the
 * members the JVM can run that the consumer's one exact-key join never named.
 *
 * <pre>
 *   R868  dep: class BaseO { void m() {Fs} }   class SubK extends BaseO {}         app: u(SubK s) { s.m(); }
 *   R916  dep: class MyOut extends java.io.FileOutputStream {}                      app: u(MyOut o) { o.write(1); }
 *   R869  dep: class BaseG&lt;T&gt; { void m(T) {Fs} }  class SubG extends BaseG&lt;String&gt; { void m(String) {Env} }
 *                                                                                   app: u(BaseG&lt;String&gt; g) { g.m("x"); }
 * </pre>
 *
 * Before: R868 and R916 ABSENT, R869 {@code [Fs]}; {@code deny Fs} / {@code deny Env} and {@code deny Unknown}
 * all exit 0. Every arm was EXECUTED in the lane's harness (javaagent-veinD/fx/vd, a marker file per body and
 * a printed token per call) before it was written down, and the one-tree scan of the same source is the
 * reference each arm agrees with, except where named: the ⟨0.40⟩ walk-up fabrication (pinned in
 * {@link DepOverrideUnionTest}) and the unloadable-ancestor MISS, where chained now DISCLOSES and the one-tree
 * scan is silent.
 *
 * <p>Each test is one variable against the fixed consumer shape.
 */
class DepInheritedMemberTest {

    private static final String FS = "new java.io.File(\"/tmp\").exists();";
    private static final String ENV = "System.getenv(\"HOME\");";
    private static final String CLOCK = "System.currentTimeMillis();";
    private static final String RAND = "new java.util.Random().nextInt();";

    private static final String BASE_O = "package dep;\npublic class BaseO {\n  public void m() { " + FS + " }\n"
            + "  public static void sm() { " + FS + " }\n}\n";

    // ---- harness (the DepOverrideUnionTest one, plus a report reader) ----------------------------------------

    private record Scan(Map<String, EffectSet> app, Map<String, JsonObject> dep, Map<String, List<String>> why) {}

    private static Scan chained(Map<String, String> lib, Map<String, String> app) throws Exception {
        return chained(lib, app, true);
    }

    /** {@code keepCallgraph=false} deletes the dependency's call-graph sidecar before the consumer scan — the
     *  input SOUNDNESS R1336's declaring-subtype count reads — so a test can show that input is what decides. */
    private static Scan chained(Map<String, String> lib, Map<String, String> app, boolean keepCallgraph)
            throws Exception {
        return chained(lib, app, keepCallgraph ? "present" : "deleted");
    }

    /** The call-graph sidecar's state for SPEC PART 30 P6: {@code present}, {@code deleted}, {@code keysdropped}
     *  (valid JSON, half the keys gone — incomplete), {@code garbage} (unparseable), {@code unpaired} (renamed so it is
     *  no report's stem sibling). */
    private static Scan chained(Map<String, String> lib, Map<String, String> app, String sidecar)
            throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path depReport = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            Map<String, JsonObject> depRows = rowsByHash(depReport);
            Path cg = base.resolve("dep.callgraph.json");
            assertTrue(Files.isRegularFile(cg), "the call-graph sidecar this arm degrades must have existed");
            switch (sidecar) {
                case "present" -> { }
                case "deleted" -> Files.delete(cg);
                case "keysdropped" -> {
                    JsonObject o = JsonParser.parseString(Files.readString(cg)).getAsJsonObject();
                    List<String> ks = new ArrayList<>(o.keySet());
                    for (int i = 0; i < ks.size(); i += 2) o.remove(ks.get(i));
                    Files.writeString(cg, o.toString());
                }
                case "garbage" -> Files.writeString(cg, "{\"truncated\": [");
                case "unpaired" -> Files.move(cg, base.resolve("other.callgraph.json"));
                default -> throw new IllegalArgumentException(sidecar);
            }
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            Path appReport = base.resolve("app.json");
            Map<String, EffectSet> r = Candor.runScan(appDir);
            ReportWriter.writeReport(r, appReport.toString(), null);
            return new Scan(r, depRows, whyByFn(appReport));
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

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

    private static Map<String, JsonObject> rowsByHash(Path report) throws Exception {
        Map<String, JsonObject> out = new LinkedHashMap<>();
        for (JsonElement e : JsonParser.parseString(Files.readString(report)).getAsJsonObject().getAsJsonArray("functions"))
            out.put(e.getAsJsonObject().get("hash").getAsString(), e.getAsJsonObject());
        return out;
    }

    private static Map<String, List<String>> whyByFn(Path report) throws Exception {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (JsonElement e : JsonParser.parseString(Files.readString(report)).getAsJsonObject().getAsJsonArray("functions")) {
            JsonObject o = e.getAsJsonObject();
            List<String> w = new ArrayList<>();
            if (o.has("unknownWhy")) for (JsonElement x : o.getAsJsonArray("unknownWhy")) w.add(x.getAsString());
            out.put(o.get("fn").getAsString(), w);
        }
        return out;
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

    private static Map<String, String> lib(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    private static Map<String, String> app(String body) {
        return Map.of("app/App.java", "package app;\nimport dep.*;\npublic class App {\n" + body
                + "  public static void caller() { }\n}\n");
    }

    // ---- R868: the member a dependency subtype INHERITS ------------------------------------------------------

    @Test
    void anInheritedMemberIsChargedOnTheUnitAndAgreesWithTheOneTreeScan() throws Exception {
        Map<String, String> l = lib("dep/BaseO.java", BASE_O,
                "dep/SubK.java", "package dep;\npublic class SubK extends BaseO { public void other() { } }\n",
                "dep/SubK2.java", "package dep;\npublic class SubK2 extends SubK { }\n");
        Map<String, String> a = app("  public static void viaSubK(SubK s) { s.m(); }\n"
                + "  public static void viaSubK2(SubK2 s) { s.m(); }\n"
                + "  public static void viaExact() { SubK s = new SubK(); s.m(); }\n"
                + "  public static void viaStatic() { SubK.sm(); }\n");
        Scan c = chained(l, a);
        Map<String, EffectSet> w = whole(l, a);
        for (String fn : List.of("app.App.viaSubK", "app.App.viaSubK2", "app.App.viaExact", "app.App.viaStatic")) {
            assertEquals(set("FS"), eff(c.app(), fn), fn + ": executed, BaseO's body runs (a file is touched)");
            assertEquals(eff(w, fn), eff(c.app(), fn), fn + ": chained must agree with the one-tree scan");
        }
    }

    @Test
    void anInterfaceDefaultInheritedByADependencyClassIsCharged() throws Exception {
        Map<String, String> l = lib("dep/I.java", "package dep;\npublic interface I { default void d() { " + ENV + " } }\n",
                "dep/DK.java", "package dep;\npublic class DK implements I { public void other() { } }\n");
        Scan c = chained(l, app("  public static void viaDK(DK d) { d.d(); }\n"));
        assertEquals(set("ENV"), eff(c.app(), "app.App.viaDK"));
    }

    /** The trap the §2.2 callgraph sidecar would have walked into: OvK DECLARES an `m` — of another arity — and
     *  inherits `m()`. A bare-name member manifest says "OvK has an m" and would stop the walk; the JVM runs
     *  BaseO.m (executed). This is why the walk does not read that sidecar. */
    @Test
    void aSameNamedMemberOfAnotherArityDoesNotStopTheWalk() throws Exception {
        Map<String, String> l = lib("dep/BaseO.java", BASE_O,
                "dep/OvK.java", "package dep;\npublic class OvK extends BaseO { public void m(int x) { } }\n");
        Scan c = chained(l, app("  public static void viaOvK(OvK k) { k.m(); }\n"));
        assertEquals(set("FS"), eff(c.app(), "app.App.viaOvK"));
    }

    @Test
    void aSuperCallFromAConsumerSubclassReachesTheInheritedBody() throws Exception {
        Map<String, String> l = lib("dep/BaseO.java", BASE_O,
                "dep/SubK.java", "package dep;\npublic class SubK extends BaseO { }\n");
        Map<String, String> a = Map.of("app/Mine.java",
                "package app;\npublic class Mine extends dep.SubK { @Override public void m() { super.m(); } }\n");
        Scan c = chained(l, a);
        assertEquals(set("FS"), eff(c.app(), "app.Mine.m"), "invokespecial dep/SubK.m()V resolves to BaseO.m");
    }

    /** UP and DOWN together: SubKE inherits BaseO.m (Fs, executed with a plain SubKE) and SubKE2 overrides it
     *  (Env, executed with a SubKE2). R867 alone gave only the override. */
    @Test
    void theWalkUpAndTheWalkDownAreUnioned() throws Exception {
        Map<String, String> l = lib("dep/BaseO.java", BASE_O,
                "dep/SubKE.java", "package dep;\npublic class SubKE extends BaseO { }\n",
                "dep/SubKE2.java", "package dep;\npublic class SubKE2 extends SubKE { @Override public void m() { " + ENV + " } }\n");
        Scan c = chained(l, app("  public static void viaSubKE(SubKE s) { s.m(); }\n"));
        assertEquals(set("ENV", "FS"), eff(c.app(), "app.App.viaSubKE"));
    }

    /** A FOREIGN package's ⟨0.39⟩ union keyed under a type that only INHERITS the member is not that type's
     *  declaration: `dep2.D2 extends dep.SubKD` overrides `m`, publishes `dep/SubKD.m()V`, and the walk must
     *  still reach BaseO.m, which a plain SubKD runs (executed). Before: [Env] — Fs dropped. */
    @Test
    void aForeignUnionUnderTheOwnerDoesNotStopTheWalk() throws Exception {
        Map<String, String> l = lib("dep/BaseO.java", BASE_O,
                "dep/SubKD.java", "package dep;\npublic class SubKD extends BaseO { }\n",
                "dep2/D2.java", "package dep2;\npublic class D2 extends dep.SubKD { @Override public void m() { " + ENV + " } }\n");
        Path appDir = compileApp(l, Map.of("app/App.java",
                "package app;\npublic class App {\n  public static void viaSubKD(dep.SubKD s) { s.m(); }\n}\n"));
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path d1 = split(base, "dep"), d2 = split(base, "dep2");
            Path r1 = base.resolve("dep.json"), r2 = base.resolve("dep2.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(d1), r1.toString(), null);
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + r1 + "\n");
            Candor.config = Config.forTarget(d2);
            ReportWriter.writeReport(Candor.runScan(d2), r2.toString(), null);
            assertTrue(rowsByHash(r2).containsKey("dep/SubKD.m()V"),
                    "the fixture must reproduce the shape: dep2 publishes its union under dep's key");
            Files.writeString(base.resolve(".candor/config"), "deps " + r1 + "," + r2 + "\n");
            Candor.config = Config.forTarget(appDir);
            assertEquals(set("ENV", "FS"), eff(Candor.runScan(appDir), "app.App.viaSubKD"));
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** The same foreign union from a SPLIT PACKAGE: `D2` is declared in package `dep` too, but by another jar.
     *  "Is this entry the owner's own declaration?" is answered by the types the producing report's OWN
     *  hierarchy sidecar keys, not by package — a package-based test reads dep2's union under `dep/SubKD`
     *  as SubKD's declaration and stops the walk, and BaseO.m's Fs (executed by a plain SubKD) is dropped. */
    @Test
    void aForeignUnionFromASplitPackageDoesNotStopTheWalk() throws Exception {
        Map<String, String> l = lib("dep/BaseO.java", BASE_O,
                "dep/SubKD.java", "package dep;\npublic class SubKD extends BaseO { }\n",
                "dep/D2.java", "package dep;\npublic class D2 extends SubKD { @Override public void m() { " + ENV + " } }\n");
        Path appDir = compileApp(l, Map.of("app/App.java",
                "package app;\npublic class App {\n  public static void viaSubKD(dep.SubKD s) { s.m(); }\n}\n"));
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path d1 = splitClasses(base, "j1", "dep/BaseO", "dep/SubKD"), d2 = splitClasses(base, "j2", "dep/D2");
            Path r1 = base.resolve("j1.json"), r2 = base.resolve("j2.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(d1), r1.toString(), null);
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + r1 + "\n");
            Candor.config = Config.forTarget(d2);
            ReportWriter.writeReport(Candor.runScan(d2), r2.toString(), null);
            assertTrue(rowsByHash(r2).containsKey("dep/SubKD.m()V"),
                    "the fixture must reproduce the shape: j2 publishes its union under j1's key, same package");
            Files.writeString(base.resolve(".candor/config"), "deps " + r1 + "," + r2 + "\n");
            Candor.config = Config.forTarget(appDir);
            assertEquals(set("ENV", "FS"), eff(Candor.runScan(appDir), "app.App.viaSubKD"));
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    private static Path splitClasses(Path base, String name, String... internals) throws Exception {
        Path to = base.resolve("split-" + name);
        for (String c : internals) {
            Path dst = to.resolve(c + ".class");
            Files.createDirectories(dst.getParent());
            Files.copy(base.resolve("lib").resolve(c + ".class"), dst);
        }
        return to;
    }

    /** Copy one package's classes out of the compiled lib tree, so it can be scanned as its own dependency. */
    private static Path split(Path base, String pkg) throws Exception {
        Path to = base.resolve("split-" + pkg);
        Path from = base.resolve("lib").resolve(pkg);
        Files.createDirectories(to.resolve(pkg));
        try (Stream<Path> s = Files.list(from)) {
            for (Path p : (Iterable<Path>) s::iterator) Files.copy(p, to.resolve(pkg).resolve(p.getFileName()));
        }
        return to;
    }

    /** ⟨0.40⟩'s structural MISS: the ancestor is in a package nobody chained and candor cannot load, so the walk
     *  cannot know what it contributes and ADDS Unknown[dispatch] (executed: LBase.m writes a file). The one-tree
     *  scan of dep+app is SILENT here — the library is not in it either — so this arm is a disclosure the
     *  reference does not make, named rather than hidden. */
    @Test
    void anAncestorNobodyChainedIsAMissThatDiscloses() throws Exception {
        Map<String, String> l = lib("lib3/LBase.java", "package lib3;\npublic class LBase { public void m() { " + FS + " } }\n",
                "dep/SubX.java", "package dep;\npublic class SubX extends lib3.LBase { public void other() { } }\n");
        Path appDir = compileApp(l, Map.of("app/App.java",
                "package app;\npublic class App {\n  public static void viaSubX(dep.SubX x) { x.m(); }\n}\n"));
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path d = split(base, "dep");
            Path r = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(d), r.toString(), null);
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + r + "\n");
            Candor.config = Config.forTarget(appDir);
            Map<String, EffectSet> got = Candor.runScan(appDir);
            assertEquals(set("UNKNOWN"), eff(got, "app.App.viaSubX"));
            Path out = base.resolve("app.json");
            ReportWriter.writeReport(got, out.toString(), null);
            assertEquals(List.of("dispatch:dep.SubX.m"), whyByFn(out).get("app.App.viaSubX"),
                    "the hole is a dispatch the walk could not resolve, named at the call");
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    // ---- R916: the walk ends in the JDK ----------------------------------------------------------------------

    @Test
    void aJdkMemberInheritedThroughADependencySubtypeIsCharged() throws Exception {
        Map<String, String> l = lib("dep/MyOut.java", "package dep;\npublic class MyOut extends java.io.FileOutputStream {\n"
                + "  public MyOut(String p) throws java.io.IOException { super(p); }\n  public void hello() { }\n}\n");
        Map<String, String> a = app("  public static void viaJdkBase(MyOut o) throws Exception { o.write(1); }\n"
                + "  public static void viaOwnPure(MyOut o) { o.hello(); }\n");
        Scan c = chained(l, a);
        Map<String, EffectSet> w = whole(l, a);
        assertEquals(set("FS"), eff(c.app(), "app.App.viaJdkBase"), "executed: one byte written");
        assertEquals(eff(w, "app.App.viaJdkBase"), eff(c.app(), "app.App.viaJdkBase"));
        // THE CONTROL that keeps FileOutputStream's WHOLE-OWNER rule from charging what the dependency type
        // adds: `hello` is not a member of FileOutputStream (read off its bytecode), so nothing is charged.
        assertTrue(eff(c.app(), "app.App.viaOwnPure").isEmpty(), "a dependency type's OWN pure method is not a"
                + " FileOutputStream member and must not be charged its blanket Fs: " + eff(c.app(), "app.App.viaOwnPure"));
    }

    /** The JDK half of the ⟨0.40⟩ licensed fabrication: MyOutP overrides write(int) with a PURE body (executed:
     *  nothing written), publishes no row, and the walk reaches FileOutputStream.write. Pinned so that removing
     *  it — which needs a member manifest (rung B) — is a deliberate act. */
    @Test
    void aPureJdkOverrideInTheDependencyIsChargedTheJdkBody_licensedByV040() throws Exception {
        Map<String, String> l = lib("dep/MyOutP.java", "package dep;\npublic class MyOutP extends java.io.FileOutputStream {\n"
                + "  public MyOutP(String p) throws java.io.IOException { super(p); }\n"
                + "  @Override public void write(int b) { }\n}\n");
        Scan c = chained(l, app("  public static void viaPure(MyOutP o) throws Exception { o.write(1); }\n"));
        assertEquals(set("FS"), eff(c.app(), "app.App.viaPure"));
    }

    // ---- R869: the bridge the producer publishes ---------------------------------------------------------

    private static final String BASE_G = "package dep;\npublic class BaseG<V> { public void m(V v) { " + FS + " } }\n";

    @Test
    void theProducerPublishesTheBridgeDescriptorAsASyntheticRow() throws Exception {
        Map<String, String> l = lib("dep/BaseG.java", BASE_G,
                "dep/SubG.java", "package dep;\npublic class SubG extends BaseG<String> { @Override public void m(String s) { " + ENV + " } }\n",
                "dep/PureG.java", "package dep;\npublic class PureG extends BaseG<String> { @Override public void m(String s) { } }\n");
        Scan c = chained(l, app("  public static void viaG(BaseG<String> g) { g.m(\"x\"); }\n"));
        JsonObject real = c.dep().get("dep/SubG.m(Ljava/lang/String;)V");
        JsonObject bridge = c.dep().get("dep/SubG.m(Ljava/lang/Object;)V");
        assertTrue(real != null && bridge != null, "both descriptors must be keyed: " + c.dep().keySet());
        assertFalse(real.has("interfaceUnion"), "the analysed entry is untouched");
        assertTrue(bridge.get("interfaceUnion").getAsBoolean(), "the bridge row is synthetic — not a unit");
        assertEquals("dep.SubG.m(java.lang.Object)", bridge.get("fn").getAsString(),
                "its own fn, so gate --report never sees the real name twice");
        assertEquals(real.get("inferred"), bridge.get("inferred"), "it republishes the node's effects");
        assertFalse(c.dep().containsKey("dep/PureG.m(Ljava/lang/Object;)V"), "a pure node has nothing to republish");
        assertEquals(set("ENV", "FS"), eff(c.app(), "app.App.viaG"), "executed with a SubG: the environment is read");
    }

    /** ⟨0.40⟩ SOUNDNESS R1239 — a bridge row is an `interfaceUnion` entry, so when it carries `Unknown` its
     *  `unknownWhy` projects to its contributor's TRANSITIVE classes (SPEC §3.1). Here the override reaches
     *  reflection through a helper, so the real entry's own (direct-only) field is empty and the bridge used to
     *  publish none. */
    @Test
    void aBridgeRowCarryingUnknownCarriesItsContributorsTransitiveReason() throws Exception {
        Map<String, String> l = lib("dep/BaseG.java", BASE_G,
                "dep/SubG.java", "package dep;\npublic class SubG extends BaseG<String> { @Override public void m(String s) { h(); }\n"
                        + "  static void h() { try { Class.forName(s()); } catch (Exception e) { } }\n"
                        + "  static String s() { return String.valueOf(System.nanoTime()); } }\n");
        Scan c = chained(l, app("  public static void viaG(BaseG<String> g) { g.m(\"x\"); }\n"));
        JsonObject real = c.dep().get("dep/SubG.m(Ljava/lang/String;)V");
        JsonObject bridge = c.dep().get("dep/SubG.m(Ljava/lang/Object;)V");
        assertTrue(real != null && bridge != null, "both descriptors must be keyed: " + c.dep().keySet());
        assertTrue(bridge.get("inferred").toString().contains("Unknown"), "the bridge carries the inherited Unknown");
        assertFalse(real.has("unknownWhy"), "precondition: the real entry's Unknown is INHERITED (direct-only field empty)");
        assertTrue(bridge.has("unknownWhy") && bridge.get("unknownWhy").toString().contains("reflect:"),
                "the bridge row names its contributor's transitive reflect reason: " + bridge);
    }

    @Test
    void boundedAndMultiLevelGenericOverridesAreReached() throws Exception {
        Map<String, String> l = lib(
                "dep/BaseB.java", "package dep;\npublic class BaseB<V extends CharSequence> { public void m(V v) { " + FS + " }\n"
                        + "  public static BaseB<String> make() { return new SubB(); } }\n",
                "dep/SubB.java", "package dep;\npublic class SubB extends BaseB<String> { @Override public void m(String s) { " + ENV + " } }\n",
                "dep/BaseG2.java", "package dep;\npublic class BaseG2<V> { public void m(V v) { " + FS + " } }\n",
                "dep/MidG2.java", "package dep;\npublic class MidG2 extends BaseG2<String> { @Override public void m(String s) { " + ENV + " } }\n",
                "dep/LeafG2.java", "package dep;\npublic class LeafG2 extends MidG2 { @Override public void m(String s) { " + CLOCK + " } }\n");
        Scan c = chained(l, app("  public static void viaB() { BaseB.make().m(\"x\"); }\n"
                + "  public static void viaG2(BaseG2<String> g) { g.m(\"x\"); }\n"));
        assertEquals(set("ENV", "FS"), eff(c.app(), "app.App.viaB"));
        assertEquals(set("CLOCK", "ENV", "FS"), eff(c.app(), "app.App.viaG2"), "LeafG2 overrides two levels below the bridge");
    }

    /** WHAT R869 PRICED, R1336 NOW COUNTS. R867's DOWN walk unions a base member's overrides up to CHA_FANOUT_LIMIT
     *  and past it discloses {@code Unknown[dispatch]} instead. When bridge rows (R869) made generic overrides
     *  findable, a site whose ordinary overrides used to UNION could be pushed past the bound by them — measured on
     *  jackson-databind ({@code StdScalarSerializer.serialize}, {@code Clock}) — and R869 kept the union priced on
     *  the non-bridge ROWS, adding an {@code Unknown} beside it. That pricing was the R1336 defect in one of its
     *  forms: the verdict followed what the producer happened to publish, not the hierarchy. The bound now counts
     *  overriding SUBTYPES from the call-graph sidecar (14 here, past it), bridged or not, pure or not — the
     *  quantity the in-scan bound counts — so this site hedges exactly as the one-tree scan of the same code does,
     *  and the overrides' {@code Env}/{@code Rand}/{@code Clock} are not unioned. Measured cost of that trade
     *  against v0.40.15 on the 304-entry chained census: 39 concrete cells in 20 consumer units, every one
     *  absent from the published one-tree scan of the same code, and every unit keeping {@code Unknown}. */
    @Test
    void anOverrideSitePastTheBoundHedgesAsTheOneTreeScanDoes() throws Exception {
        Map<String, String> l = new LinkedHashMap<>();
        l.put("dep/BaseG.java", BASE_G);
        int plain = Rules.CHA_FANOUT_LIMIT - 2;              // ROWS: plain + base = LIMIT - 1, under the bound
        for (int i = 0; i < plain; i++)
            l.put("dep/P" + i + ".java", "package dep;\npublic class P" + i + " extends BaseG<Object> {"
                    + " @Override public void m(Object o) { " + (i == 0 ? ENV : RAND) + " } }\n");
        for (int i = 0; i < 4; i++)                          // bridged: the SUBTYPES carry the count past it
            l.put("dep/G" + i + ".java", "package dep;\npublic class G" + i + " extends BaseG<String> {"
                    + " @Override public void m(String s) { " + CLOCK + " } }\n");
        Map<String, String> a = app("  public static void viaG(BaseG<String> g) { g.m(\"x\"); }\n");
        Scan c = chained(l, a);
        TreeSet<String> got = eff(c.app(), "app.App.viaG");
        assertTrue(got.contains("UNKNOWN"), "past the bound, disclosed: " + got);
        assertTrue(c.why().get("app.App.viaG").contains("dispatch:dep.BaseG.m"), "" + c.why().get("app.App.viaG"));
        for (String e : List.of("ENV", "RAND", "CLOCK"))
            assertFalse(got.contains(e), "no override is unioned past the bound (" + e + "): " + got);
        TreeSet<String> one = eff(whole(l, a), "app.App.viaG");
        for (String e : List.of("ENV", "RAND", "CLOCK"))
            assertFalse(one.contains(e), "…which is the one-tree answer too (" + e + "): " + one);
    }

    /** SOUNDNESS R1336 — THE BOUND COUNTS OVERRIDING SUBTYPES, NOT OVERRIDE ROWS. {@code dep.Cmd.parse} has
     *  {@code n} overriding subtypes: {@code Sub0} writes the file it is handed, the rest are PURE and publish no row
     *  (§2 rule 3). The consumer's {@code go(Cmd c)} dispatches {@code parse}. Executed in
     *  {@code javaagent-0416/fx1336} (pick 0 writes the file, pick 1 and the base write nothing). In-scan, the one-tree
     *  scan counts all {@code n} + the base as CHA targets; the chained walk counted ROWS, i.e. one, so past the bound
     *  it unioned {@code Fs} and dropped the hedge one-tree reads — and when the producer published rows for the pure
     *  overrides too (R1304's named rows, {@code CANDOR_R1304}) it hedged instead: one jar, one hierarchy, two
     *  verdicts. The count now comes from the dependency's call-graph sidecar, which keys every analysed unit.
     *  <ul>
     *    <li>13 subtypes (past the bound): {@code Unknown[dispatch:dep.Cmd.parse]}, no {@code Fs} — the one-tree
     *        answer. CONTROL: with the call-graph sidecar deleted the walk can see only the one row, and the old
     *        union comes back, so the sidecar is shown to be what decides.</li>
     *    <li>6 subtypes (under it): the union is kept, {@code Fs} and no {@code Unknown} — the resolution.</li>
     *  </ul> */
    @Test
    void pureOverridingSubtypesCountTowardTheOverrideBound() throws Exception {
        for (int n : new int[] { 13, 6 }) {
            Map<String, String> l = new LinkedHashMap<>();
            l.put("dep/Cmd.java", "package dep;\npublic class Cmd { public void parse(String a) { } }\n");
            l.put("dep/Sub0.java", "package dep;\npublic class Sub0 extends Cmd { public void parse(String a) {"
                    + " try { java.nio.file.Files.writeString(java.nio.file.Path.of(a), \"x\"); } catch (Exception e) { } } }\n");
            for (int i = 1; i < n; i++)
                l.put("dep/Sub" + i + ".java", "package dep;\npublic class Sub" + i + " extends Cmd {"
                        + " public String last; public void parse(String a) { last = a.trim(); } }\n");
            Map<String, String> a = app("  public static void go(Cmd c, String a) { c.parse(a); }\n");
            Scan c = chained(l, a);
            long rows = c.dep().keySet().stream().filter(h -> h.contains(".parse(")).count();
            assertEquals(1, rows, "precondition: only the effectful override publishes a row");
            TreeSet<String> got = eff(c.app(), "app.App.go");
            TreeSet<String> one = eff(whole(l, a), "app.App.go");
            if (n + 1 > Rules.CHA_FANOUT_LIMIT) {
                assertEquals(set("UNKNOWN"), got, n + " overriding subtypes: past the bound, the hedge — got " + got);
                assertTrue(c.why().get("app.App.go").contains("dispatch:dep.Cmd.parse"), "" + c.why().get("app.App.go"));
                assertEquals(one, got, "and it is the one-tree answer");
                TreeSet<String> noCg = eff(chained(l, a, false).app(), "app.App.go");
                assertEquals(set("FS", "UNKNOWN"), noCg, "control: without the sidecar the count is unanswerable, and"
                        + " the row is unioned BESIDE the hedge (P6: never more resolved than with it) — got " + noCg);
            } else {
                assertEquals(set("FS"), got, n + " overriding subtypes: under the bound, the union — got " + got);
                assertEquals(one, got, "and it is the one-tree answer");
            }
        }
    }

    /** SOUNDNESS R1360 — THE §4 OBJECT PROTOCOL ON A DEPENDENCY-TYPED RECEIVER TAKES THE OVERRIDE BOUND. A chained
     *  {@code go(dep.Node n) { return n.toString(); }} over {@code n} subclasses overriding {@code toString}, the first
     *  {@code k} reading the environment. The walk used to return NOTHING past the bound for this protocol, so 13
     *  environment readers read ABSENT chained — {@code deny Env}, {@code deny Unknown}, {@code deny Env Unknown} all
     *  exit 0 — where the one-tree scan hedges (executed in {@code javaagent-0416/fx1360}: {@code go(new N0())} prints
     *  $HOME). Every arm is compared with the one-tree scan of the same code:
     *  <ul>
     *    <li>13 / 13 — the silence: now {@code Unknown[dispatch:dep.Node.toString]}.</li>
     *    <li>13 / 1 — the disclosure the fix TRADES: v0.40.15 unioned the one row ({@code Env}); past the bound the
     *        one-tree scan hedges, and so does this.</li>
     *    <li>4 / 1 — under the bound the union is kept and no hedge is added: the effect the fix must not delete.</li>
     *    <li>13 / 0 — past the bound with every override pure: pure, as the in-scan S4 floor leaves it.</li>
     *  </ul> */
    @Test
    void anObjectProtocolDispatchOnADependencyClassTakesTheOverrideBound() throws Exception {
        int[][] shapes = { { 13, 13 }, { 13, 1 }, { 4, 1 }, { 13, 0 } };
        for (int[] sh : shapes) {
            int n = sh[0], k = sh[1];
            Map<String, String> l = new LinkedHashMap<>();
            l.put("dep/Node.java", "package dep;\npublic class Node { public String toString() { return \"n\"; } }\n");
            for (int i = 0; i < n; i++)
                l.put("dep/N" + i + ".java", "package dep;\npublic class N" + i + " extends Node {"
                        + " public String toString() { return " + (i < k ? "System.getenv(\"HOME\")" : "\"n" + i + "\"")
                        + "; } }\n");
            Map<String, String> a = app("  public static String go(Node n) { return n.toString(); }\n");
            Scan c = chained(l, a);
            TreeSet<String> got = eff(c.app(), "app.App.go");
            TreeSet<String> one = eff(whole(l, a), "app.App.go");
            String tag = n + " subtypes / " + k + " effectful: ";
            assertEquals(one, got, tag + "chained must read what the one-tree scan reads — got " + got + ", one-tree " + one);
            if (n + 1 > Rules.CHA_FANOUT_LIMIT && k > 0) {
                assertEquals(set("UNKNOWN"), got, tag + got);
                assertTrue(c.why().get("app.App.go").contains("dispatch:dep.Node.toString"), tag + c.why().get("app.App.go"));
            } else if (k > 0) {
                assertEquals(set("ENV"), got, tag + "under the bound the union survives, unhedged: " + got);
            } else {
                assertTrue(got.isEmpty(), tag + "all-pure stays pure: " + got);
            }
        }
    }

    /** SPEC PART 30 P6 for R1336 — DEGRADING THE CALL-GRAPH SIDECAR MAY ONLY WIDEN A DISCLOSURE. Each shape is scanned
     *  with the sidecar present, deleted, half its keys dropped, unparseable, and renamed out of its pair; every
     *  degraded arm must carry {@code Unknown} wherever the present arm does (8cb94c8 unioned the rows instead on the
     *  concrete 13-subtype shape: {@code [FS]}, no hedge). And the narrow pure union (the abstract member whose three
     *  implementors are pure — PART 92's c3_pure_only) must read pure in EVERY arm: a missing file is not a reason to
     *  invent indeterminacy. Executed in {@code javaagent-0416/fxP6}. */
    @Test
    void degradingTheCallGraphSidecarOnlyWidensTheOverrideVerdict() throws Exception {
        String[][] shapes = { { "concrete", "13", "1" }, { "abstract", "13", "1" }, { "concrete", "13", "0" },
                { "concrete", "6", "1" }, { "abstract", "3", "0" },
                // x12 (Fable REVIEW3 F2): an abstract member with EXACTLY 12 declaring subtypes is within the bound
                // in-scan (no owner body to count); present must not hedge where the producer's union is narrow.
                { "abstract", "12", "0" }, { "abstract", "12", "1" } };
        for (String[] sh : shapes) {
            boolean abs = sh[0].equals("abstract");
            int n = Integer.parseInt(sh[1]), k = Integer.parseInt(sh[2]);
            Map<String, String> l = new LinkedHashMap<>();
            l.put("dep/Cmd.java", abs ? "package dep;\npublic abstract class Cmd { public abstract void parse(String a); }\n"
                    : "package dep;\npublic class Cmd { public void parse(String a) { } }\n");
            for (int i = 0; i < n; i++)
                l.put("dep/Sub" + i + ".java", "package dep;\npublic class Sub" + i + " extends Cmd { public String last;"
                        + " public void parse(String a) { " + (i < k
                        ? "try { java.nio.file.Files.writeString(java.nio.file.Path.of(a), \"x\"); } catch (Exception e) { }"
                        : "last = a.trim();") + " } }\n");
            Map<String, String> a = app("  public static void go(Cmd c, String a) { c.parse(a); }\n");
            String tag = String.join("/", sh) + ": ";
            TreeSet<String> present = eff(chained(l, a, "present").app(), "app.App.go");
            if (abs && n == 12)
                assertEquals(eff(whole(l, a), "app.App.go"), present, tag + "present must read the one-tree answer");
            for (String mode : List.of("deleted", "keysdropped", "garbage", "unpaired")) {
                TreeSet<String> got = eff(chained(l, a, mode).app(), "app.App.go");
                if (present.contains("UNKNOWN"))
                    assertTrue(got.contains("UNKNOWN"), tag + mode + " must not resolve the hedge away — got " + got
                            + ", present " + present);
                assertTrue(got.containsAll(present), tag + mode + " must not drop what present charges — got " + got);
                if (abs && k == 0)
                    assertTrue(got.isEmpty(), tag + mode + ": the narrow pure union stays pure — got " + got);
            }
        }
    }

    /** R1336/P6 — AN OVERLOADED OWNER'S OWN-KEY HEDGE IS NOT THE UNION'S VERDICT. log4j's shape: {@code P.format(Object,
     *  StringBuilder)} is a REAL body that dispatches {@code format(String,StringBuilder)} over 13 overriding subtypes
     *  (past the bound, so the body carries {@code dispatch:dep.P.format}); one subtype ALSO overrides
     *  {@code format(Object,StringBuilder)} and writes a file. The subtypes' bare {@code format} quals are undecided
     *  (the owner is overloaded), so the consumer's count is unanswerable — and the fallback once read the body's
     *  descriptor-less {@code dispatch:dep.P.format} as the producer's union verdict and dropped the overriding row:
     *  {@code Fs} lost where the one-tree scan charges it (measured on log4j, 7 effects). */
    @Test
    void anOverloadedOwnersOwnKeyHedgeDoesNotStandInForItsUnion() throws Exception {
        Map<String, String> l = new LinkedHashMap<>();
        l.put("dep/P.java", "package dep;\npublic abstract class P {\n"
                + "  public void format(Object o, StringBuilder b) { format(String.valueOf(o), b); }\n"
                + "  public abstract void format(String s, StringBuilder b);\n}\n");
        l.put("dep/W.java", "package dep;\npublic class W extends P {\n"
                + "  public void format(Object o, StringBuilder b) { try { java.nio.file.Files.writeString("
                + "java.nio.file.Path.of(String.valueOf(o)), \"x\"); } catch (Exception e) { } }\n"
                + "  public void format(String s, StringBuilder b) { b.append(s); }\n}\n");
        for (int i = 0; i < 13; i++)
            l.put("dep/S" + i + ".java", "package dep;\npublic class S" + i + " extends P {"
                    + " public void format(String s, StringBuilder b) { b.append(s); } }\n");
        Map<String, String> a = app("  public static void go(P p, Object o) { p.format(o, new StringBuilder()); }\n");
        TreeSet<String> one = eff(whole(l, a), "app.App.go");
        assertTrue(one.contains("FS"), "precondition: the one-tree scan charges W's override — " + one);
        for (String mode : List.of("present", "deleted")) {
            TreeSet<String> got = eff(chained(l, a, mode).app(), "app.App.go");
            assertTrue(got.contains("FS"), mode + ": the overriding row survives — got " + got);
        }
        // ovl2 (Fable REVIEW3 F1): the sibling overload is declared on an ANCESTOR. The owner P has one `format`, so its
        // qual is bare and nothing on P's row says "overloaded"; deleted, P's own-key hedge (the body's dispatch to the
        // inherited abstract sibling) was taken for the union's verdict and W's Fs dropped: deny Fs 0 against 1 present.
        Map<String, String> l2 = new LinkedHashMap<>();
        l2.put("dep/A.java", "package dep;\npublic abstract class A { public void format(Object o, StringBuilder b) {"
                + " b.append(\"a\"); } public abstract void format(String s, StringBuilder b); }\n");
        l2.put("dep/P.java", "package dep;\npublic abstract class P extends A { public void format(Object o,"
                + " StringBuilder b) { format(String.valueOf(o), b); } }\n");
        l2.put("dep/W.java", l.get("dep/W.java"));
        for (int i = 0; i < 13; i++)
            l2.put("dep/S" + i + ".java", "package dep;\npublic class S" + i + " extends P {"
                    + " public void format(String s, StringBuilder b) { b.append(s); } }\n");
        TreeSet<String> one2 = eff(whole(l2, a), "app.App.go");
        assertTrue(one2.contains("FS"), "ovl2 precondition: the one-tree scan charges W — " + one2);
        for (String mode : List.of("present", "deleted", "unpaired")) {
            TreeSet<String> got = eff(chained(l2, a, mode).app(), "app.App.go");
            assertTrue(got.contains("FS"), "ovl2 " + mode + ": the overriding row survives — got " + got);
        }
    }

    /** SOUNDNESS R1336/P6 — THE WHOLE OVERLOAD FAMILY, one fixture (Fable REVIEW2–4: ovl1 → ovl2 → ovl3 each landed one
     *  shape past a separately-computed rule, so the rules are now ONE, Candor#depLineState, and the family is pinned
     *  together). Ancestor A, owner P, W (overrides `format(Object,StringBuilder)` and writes the file), S0..S12. The
     *  consumer calls `p.format(o, sb)`. The overload `format(String,StringBuilder)` sits on the owner, on the ancestor,
     *  split across them (A.format(String) a pure body, P.format(Object)), or nowhere (all overrides `format(Object)`).
     *  A is in P's report or in its own report chained under P's. Each of the call-graph sidecars and A's whole report
     *  is degraded in turn. Present must read the one-tree answer; every degraded arm must charge everything present
     *  charges. The OWNER's HIERARCHY sidecar is not in the arm list: without it no walk can see W at all, on this
     *  build and on v0.40.15 alike — a separate, pre-existing route (reported, not closed here). */
    @Test
    void theOverloadFamilyNeverResolvesMoreWhenASidecarDegrades() throws Exception {
        String wbody = "try { java.nio.file.Files.writeString(java.nio.file.Path.of(String.valueOf(o)), \"x\"); } catch (Exception e) { }";
        for (String ovl : List.of("owner", "ancestor", "split", "neither")) {
            String a, pp;
            switch (ovl) {
                case "ancestor" -> { a = "public abstract class A { public void format(Object o, StringBuilder b) { b.append(\"a\"); } public abstract void format(String s, StringBuilder b); }";
                                     pp = "public abstract class P extends A { public void format(Object o, StringBuilder b) { format(String.valueOf(o), b); } }"; }
                case "owner" -> { a = "public abstract class A { public void hello() { } }";
                                  pp = "public abstract class P extends A { public void format(Object o, StringBuilder b) { format(String.valueOf(o), b); } public abstract void format(String s, StringBuilder b); }"; }
                case "split" -> { a = "public abstract class A { public void format(String s, StringBuilder b) { b.append(s); } }";
                                  pp = "public abstract class P extends A { public void format(Object o, StringBuilder b) { format(String.valueOf(o), b); } }"; }
                default -> { a = "public abstract class A { public void hello() { } }";
                             pp = "public abstract class P extends A { public void format(Object o, StringBuilder b) { b.append(o); } }"; }
            }
            Map<String, String> l = new LinkedHashMap<>();
            l.put("dep/A.java", "package dep;\n" + a + "\n");
            l.put("dep/P.java", "package dep;\n" + pp + "\n");
            boolean nei = ovl.equals("neither");
            l.put("dep/W.java", "package dep;\npublic class W extends P { public void format(Object o, StringBuilder b) { " + wbody + " }"
                    + (nei ? "" : " public void format(String s, StringBuilder b) { b.append(s); }") + " }\n");
            for (int i = 0; i < 13; i++)
                l.put("dep/S" + i + ".java", "package dep;\npublic class S" + i + " extends P {"
                        + (nei ? " public void format(Object o, StringBuilder b) { b.append(\"s\"); } }\n"
                               : " public void format(String s, StringBuilder b) { b.append(s); } }\n"));
            Map<String, String> app = app("  public static void go(P p, Object o) { p.format(o, new StringBuilder()); }\n");
            TreeSet<String> one = eff(whole(l, app), "app.App.go");
            for (boolean sep : new boolean[] { false, true }) {
                TreeSet<String> present = null;
                for (String arm : sep ? List.of("present", "Pcg", "Pcgunp", "Ahier", "Acg", "Acgunp", "Arep")
                                      : List.of("present", "Pcg", "Pcgunp")) {
                    TreeSet<String> got = eff(twoReports(l, app, sep, arm), "app.App.go");
                    String tag = ovl + (sep ? "/sep/" : "/same/") + arm + ": ";
                    if (arm.equals("present")) {
                        present = got;
                        assertEquals(one, got, tag + "present must read the one-tree answer");
                    } else {
                        assertTrue(got.containsAll(present), tag + "must charge all present charges — got " + got + ", present " + present);
                    }
                }
            }
        }
    }

    /** The family harness: {@code lib} compiled once; scanned as ONE report, or as A's report and the rest's report
     *  chained under it; the consumer chains the DIRECTORY holding them, after {@code arm} degrades one file. */
    private static Map<String, EffectSet> twoReports(Map<String, String> lib, Map<String, String> app, boolean sep,
            String arm) throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent(), all = base.resolve("lib"), deps = base.resolve("deps");
        Files.createDirectories(deps);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            if (!sep) {
                ReportWriter.writeReport(Candor.runScan(all), deps.resolve("P.json").toString(), null);
            } else {
                Path la = base.resolve("la/dep"), lp = base.resolve("lp/dep");
                Files.createDirectories(la); Files.createDirectories(lp);
                try (Stream<Path> st = Files.list(all.resolve("dep"))) {
                    for (Path c : st.toList())
                        Files.copy(c, (c.getFileName().toString().startsWith("A") ? la : lp).resolve(c.getFileName()));
                }
                ReportWriter.writeReport(Candor.runScan(la.getParent()), deps.resolve("A.json").toString(), null);
                Files.createDirectories(base.resolve("lp/.candor"));
                Files.writeString(base.resolve("lp/.candor/config"), "deps " + deps.resolve("A.json") + "\n");
                Candor.config = Config.forTarget(lp.getParent());
                ReportWriter.writeReport(Candor.runScan(lp.getParent()), deps.resolve("P.json").toString(), null);
                Candor.config = Config.empty();
            }
            switch (arm) {
                case "present" -> { }
                case "Pcg" -> Files.delete(deps.resolve("P.callgraph.json"));
                case "Pcgunp" -> Files.move(deps.resolve("P.callgraph.json"), deps.resolve("Px.callgraph.json"));
                case "Ahier" -> Files.delete(deps.resolve("A.hierarchy.json"));
                case "Acg" -> Files.delete(deps.resolve("A.callgraph.json"));
                case "Acgunp" -> Files.move(deps.resolve("A.callgraph.json"), deps.resolve("Ax.callgraph.json"));
                case "Arep" -> { for (String f : List.of("A.json", "A.hierarchy.json", "A.callgraph.json"))
                                     Files.delete(deps.resolve(f)); }
                default -> throw new IllegalArgumentException(arm);
            }
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + deps + "\n");
            Candor.config = Config.forTarget(appDir);
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** BRIDGE ROWS ANSWER EXACT KEYS ONLY. untypedDepReceiver's conjunct 5 asks whether the dependency declares
     *  the call's signature on ANOTHER type, and a generic implementor's bridge row has exactly the interface's
     *  erased signature. Indexing bridge rows there turned a pure interface call into a fresh
     *  `Unknown[dispatch]`. Measured on the standard chained arm with the first cut, which also published
     *  covariant bridges: 759 consumer rows, e.g. amqp-client's `Command.getMethod`, implemented by a PURE
     *  `AMQCommand.getMethod`. So the by-signature and by-name indexes keep the shape they had. */
    @Test
    void aBridgeRowDoesNotManufactureAnInterfaceDisclosure() throws Exception {
        Map<String, String> l = lib("dep/Cmd.java", "package dep;\npublic interface Cmd<T> { void put(T t); }\n",
                "dep/Src.java", "package dep;\npublic interface Src { String s(); }\n",
                "dep/SrcImpl.java", "package dep;\npublic class SrcImpl implements Src { public String s() { return \"\"; } }\n",
                "dep/Impl.java", "package dep;\npublic class Impl implements Cmd<String> {\n  public Src src;\n"
                        + "  @Override public void put(String v) { src.s(); }\n}\n");
        Scan c = chained(l, app("  public static void use(Cmd<String> k) { k.put(\"x\"); }\n"));
        assertTrue(c.dep().containsKey("dep/Impl.put(Ljava/lang/Object;)V"),
                "the fixture must reach the shape: the generic bridge is published: " + c.dep().keySet());
        assertTrue(c.dep().get("dep/Impl.put(Ljava/lang/String;)V").getAsJsonArray("inferred").isEmpty(),
                "Impl.put is a PURE dispatching row, as AMQCommand.getMethod is");
        assertFalse(eff(c.app(), "app.App.use").contains("UNKNOWN"),
                "a bridge row is not evidence of an implementor keyed elsewhere: " + eff(c.app(), "app.App.use"));
    }

    /** A covariant-RETURN bridge is NOT published: R867's covariant match already reaches it. */
    @Test
    void aCovariantReturnBridgeIsNotPublished() throws Exception {
        Map<String, String> l = lib("dep/BaseC.java", "package dep;\npublic class BaseC { public BaseC self() { " + FS + " return this; } }\n",
                "dep/SubC.java", "package dep;\npublic class SubC extends BaseC { @Override public SubC self() { " + ENV + " return this; } }\n");
        Scan c = chained(l, app("  public static void viaC(BaseC b) { b.self(); }\n"));
        assertFalse(c.dep().containsKey("dep/SubC.self()Ldep/BaseC;"), c.dep().keySet().toString());
        assertEquals(set("ENV", "FS"), eff(c.app(), "app.App.viaC"));
    }

    /** The control R869 must not break: a subclass OVERLOAD of another type carries no bridge, so nothing is
     *  published under the base descriptor and the JVM-unreachable body is never charged (executed: Fs only). */
    @Test
    void aGenericSubclassOverloadIsStillNeverTaken() throws Exception {
        Map<String, String> l = lib("dep/BaseG.java", BASE_G,
                "dep/OvG.java", "package dep;\npublic class OvG extends BaseG<String> { public void m(Integer i) { " + RAND + " } }\n");
        Scan c = chained(l, app("  public static void viaG(BaseG<String> g) { g.m(\"x\"); }\n"));
        assertEquals(set("FS"), eff(c.app(), "app.App.viaG"));
        assertFalse(c.dep().containsKey("dep/OvG.m(Ljava/lang/Object;)V"));
    }

    @Test
    void aBridgeRowIsNotAnAnalysedUnit() throws Exception {
        Map<String, String> l = lib("dep/BaseG.java", BASE_G,
                "dep/SubG.java", "package dep;\npublic class SubG extends BaseG<String> { @Override public void m(String s) { " + ENV + " } }\n");
        Path cls = TestCompiler.compile(l);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Path r = cls.getParent().resolve("r.json");
            ReportWriter.writeReport(Candor.runScan(cls), r.toString(), null);
            JsonObject env = JsonParser.parseString(Files.readString(r)).getAsJsonObject();
            Path cg = cls.getParent().resolve("r.callgraph.json");
            int nodes = JsonParser.parseString(Files.readString(cg)).getAsJsonObject().size();
            assertEquals(nodes, env.getAsJsonObject("analyzed").get("count").getAsInt(),
                    "⟨0.21⟩ analyzed counts the node once; the bridge row adds no unit");
        } finally {
            Candor.config = saved;
            rm(cls.getParent());
        }
    }

    // ---- the gate, through the real CLI, on the unit and its caller ------------------------------------------

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
    void theGatesFireOnTheUnitAndItsCaller() throws Exception {
        Map<String, String> l = lib("dep/BaseO.java", BASE_O,
                "dep/SubK.java", "package dep;\npublic class SubK extends BaseO { }\n",
                "dep/MyOut.java", "package dep;\npublic class MyOut extends java.io.FileOutputStream {\n"
                        + "  public MyOut(String p) throws java.io.IOException { super(p); }\n}\n",
                "dep/BaseG.java", BASE_G,
                "dep/SubG.java", "package dep;\npublic class SubG extends BaseG<String> { @Override public void m(String s) { " + ENV + " } }\n");
        Map<String, String> a = Map.of("app/App.java", "package app;\nimport dep.*;\npublic class App {\n"
                + "  public static void k(SubK s) { s.m(); }\n"
                + "  public static void kCaller() { k(null); }\n"
                + "  public static void o(MyOut s) throws Exception { s.write(1); }\n"
                + "  public static void oCaller() throws Exception { o(null); }\n"
                + "  public static void g(BaseG<String> s) { s.m(\"x\"); }\n"
                + "  public static void gCaller() { g(null); }\n}\n");
        Path appDir = compileApp(l, a);
        Path base = appDir.getParent();
        try {
            Path dep = base.resolve("dep.json");
            Run d = cli(Map.of(), base.resolve("lib").toString(), "--json", dep.toString());
            assertTrue(Files.isRegularFile(dep), "dependency scan produced no report: " + d.out());
            String[][] cells = {
                    { "deny Fs app.App.k", "1" }, { "deny Fs app.App.kCaller", "1" }, { "deny Unknown app.App.k", "0" },
                    { "deny Fs app.App.o", "1" }, { "deny Fs app.App.oCaller", "1" },
                    { "deny Env app.App.g", "1" }, { "deny Env app.App.gCaller", "1" }, { "deny Env Unknown app.App.g", "1" },
                    // controls: an effect no executed path performs
                    { "deny Env app.App.k", "0" }, { "deny Exec app.App.g", "0" } };
            for (String[] cell : cells) {
                Path pp = base.resolve("p.pol");
                Files.writeString(pp, cell[0] + "\n");
                Run r = cli(Map.of("CANDOR_DEPS", dep.toString()), appDir.toString(),
                        "--json", base.resolve("app.json").toString(), "--policy", pp.toString());
                assertEquals(Integer.parseInt(cell[1]), r.exit(), "`" + cell[0] + "`:\n" + r.out());
            }
        } finally {
            rm(base);
        }
    }
}
