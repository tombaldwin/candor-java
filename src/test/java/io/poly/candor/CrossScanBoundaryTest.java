package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * CROSSING THE SCAN BOUNDARY (candor-spec {@code SOUNDNESS-VEIN-crossing-the-scan-boundary.md}).
 *
 * <p>Code candor analyses soundly in ONE scanned tree lost the effect entirely when the same code was
 * split across a scan boundary and the dependency's report chained via {@code CANDOR_DEPS} — the
 * arrangement candor's own docs recommend. Thirteen JVM mechanisms read silent-PURE that way, and the
 * gate diverged on identical source ({@code deny Env}: exit 1 together, exit 0 chained — a false
 * all-clear, the cardinal sin in its most consequential form).
 *
 * <p>Every test here is a TWO-TREE fixture with its own single-tree control: the lib is compiled and
 * scanned SEPARATELY, its report chained, and the app scanned alone. The control is what candor says when
 * both trees are scanned together — the answer the chained arrangement must reproduce.
 */
class CrossScanBoundaryTest {

    // ---- harness ---------------------------------------------------------------------------------------

    /** Scan `app` alone with `lib`'s own report chained, exactly as {@code CANDOR_DEPS} would. Returns the
     *  app's inferred effects. The dep report is produced by THIS engine build, so the §2.1 version gate
     *  trusts it (a stale report is downgraded to Unknown, which would mask what these tests measure). */
    private static Map<String, EffectSet> scanChained(Map<String, String> lib, Map<String, String> app)
            throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Path libDir = base.resolve("lib");
        Config saved = Candor.config;
        try {
            Path depReport = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(libDir), depReport.toString(), null);
            // Drive the same `deps` key the CLI reads, via a checked-in .candor/config next to the app tree.
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** Scan `app` alone with NOTHING chained — the honest baseline (the dep package is disclosed invisible). */
    private static Map<String, EffectSet> scanUnchained(Map<String, String> lib, Map<String, String> app)
            throws Exception {
        Path appDir = compileApp(lib, app);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(appDir.getParent());
        }
    }

    private static boolean env(Map<String, EffectSet> r, String m) {
        return r.getOrDefault(m, EffectSet.empty()).toNames().contains("Env");
    }

    /** A dependency whose `toString`, `equals` and `hashCode` read the environment, plus PURE siblings that
     *  every fabrication control below leans on. */
    private static final Map<String, String> LIB = Map.of(
        "lib/Entry.java", "package lib;\npublic class Entry {\n"
            + "  public String toString(){ return \"e:\" + System.getenv(\"HOME\"); }\n}\n",
        "lib/PureEntry.java", "package lib;\npublic class PureEntry {\n"
            + "  public String toString(){ return \"pure\"; }\n}\n",
        "lib/DepKey.java", "package lib;\npublic class DepKey {\n"
            + "  public boolean equals(Object o){ System.getenv(\"HOME\"); return o == this; }\n"
            + "  public int hashCode(){ System.getenv(\"HOME\"); return 1; }\n}\n");

    // ---- M1: implicit stringification of a DEPENDENCY type ---------------------------------------------

    @Test
    void stringificationReachesADependencyToString() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Entry;",
            "public class S {",
            "  public String concat(Entry e){ return \"x\" + e; }",
            "  public String valueOf(Entry e){ return String.valueOf(e); }",
            "  public String format(Entry e){ return String.format(\"%s\", e); }",
            "  public String append(Entry e){ StringBuilder b = new StringBuilder(); b.append(e); return b.toString(); }",
            "  public void println(Entry e){ System.out.println(e); }",
            "}")));
        for (String m : new String[] {"concat", "valueOf", "format", "append", "println"})
            assertTrue(env(r, "app.S." + m),
                    "`" + m + "` stringifies a dep type whose toString reads Env — the dep report carries"
                    + " lib/Entry.toString()Ljava/lang/String; -> [Env]; got " + r.get("app.S." + m));
    }

    @Test
    void aDependencyWithAPureToStringContributesNothing() throws Exception {
        // The fabrication control: the mechanism must add NOTHING unless the dep's own report says the
        // body is effectful. A dep type candor has analysed and found pure stays pure at every sink.
        Map<String, EffectSet> r = scanChained(LIB, Map.of("app/S.java", String.join("\n",
            "package app; import lib.PureEntry;",
            "public class S { public String concat(PureEntry e){ return \"x\" + e; } }")));
        assertFalse(env(r, "app.S.concat"), "a dep type with a PURE toString must not gain an effect");
    }

    @Test
    void aProjectOverrideShadowingTheDependencyBodyIsNotCharged() throws Exception {
        // A project subclass that OVERRIDES toString is the body the JVM runs; charging the dep
        // superclass's shadowed implementation on top of it would fabricate an effect that never happens.
        Map<String, EffectSet> r = scanChained(LIB, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Entry;",
            "public class S {",
            "  public static class Quiet extends Entry { public String toString(){ return \"q\"; } }",
            "  public String concat(Quiet q){ return \"x\" + q; }",
            "}")));
        assertFalse(env(r, "app.S.concat"),
                "an overriding PROJECT toString shadows the dep body — nothing to inherit, got " + r.get("app.S.concat"));
    }

    @Test
    void aProjectSubclassInheritingTheDependencyBodyIsCharged() throws Exception {
        // The other side of the same walk: no override, so the dep superclass's toString IS what runs.
        Map<String, EffectSet> r = scanChained(LIB, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Entry;",
            "public class S {",
            "  public static class Plain extends Entry { }",
            "  public String concat(Plain p){ return \"x\" + p; }",
            "}")));
        assertTrue(env(r, "app.S.concat"),
                "a project subclass with no override inherits the dep's effectful toString, got " + r.get("app.S.concat"));
    }

    // ---- M3: equals/hashCode reentry on a DEPENDENCY key -----------------------------------------------

    @Test
    void equalsAndHashCodeReentryReachesADependencyKey() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB, Map.of("app/S.java", String.join("\n",
            "package app; import lib.DepKey; import java.util.*;",
            "public class S {",
            "  public boolean contains(Set<DepKey> s, DepKey k){ return s.contains(k); }",
            "  public Object mapGet(Map<DepKey,String> m, DepKey k){ return m.get(k); }",
            "}")));
        assertTrue(env(r, "app.S.contains"), "set.contains(depKey) re-enters the dep's equals/hashCode");
        assertTrue(env(r, "app.S.mapGet"), "map.get(depKey) re-enters the dep's equals/hashCode");
    }

    @Test
    void aDependencyKeyWithNoEffectfulContractContributesNothing() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB, Map.of("app/S.java", String.join("\n",
            "package app; import lib.PureEntry; import java.util.*;",
            "public class S { public boolean contains(Set<PureEntry> s, PureEntry k){ return s.contains(k); } }")));
        assertFalse(env(r, "app.S.contains"), "a dep key with no effectful equals/hashCode must stay pure");
    }

    // ---- M2: an INHERITED / DEFAULT method from a DEPENDENCY supertype ----------------------------------

    /** A dependency supplying a class to extend and an interface to implement, plus the PURE siblings the
     *  fabrication controls need, plus an ABSTRACT method with no implementor inside the dependency — whose
     *  own report entry is therefore a bare `Unknown`. */
    private static final Map<String, String> LIB2 = Map.of(
        "lib/Base.java", "package lib;\npublic class Base {\n"
            + "  public void load(){ System.getenv(\"HOME\"); }\n"
            + "  public void quiet(){ }\n"
            + "  public void hook(){ System.getenv(\"HOME\"); }\n}\n",
        "lib/Iface.java", "package lib;\npublic interface Iface {\n"
            + "  default void dflt(){ System.getenv(\"HOME\"); }\n"
            + "  void req();\n}\n",
        "lib/Abs.java", "package lib;\npublic abstract class Abs {\n"
            + "  public abstract int raw();\n"
            + "  public boolean flag(){ return raw() > 0; }\n}\n");

    @Test
    void anInheritedMethodFromADependencySuperclassIsCharged() throws Exception {
        // `s.load()` compiles to INVOKEVIRTUAL with the PROJECT class as owner, so the cross-dep join was
        // never even reached (it requires a non-project owner) and the local CHA walks project-only indexes.
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Base;",
            "public class S {",
            "  public static class Sub extends Base { public void self(){ load(); } }",
            "  public void callInherited(Sub s){ s.load(); }",
            "}")));
        assertTrue(env(r, "app.S$Sub.self"), "this.load() on a dep superclass must carry its Env");
        assertTrue(env(r, "app.S.callInherited"), "s.load() on a project subclass of a dep must carry its Env");
    }

    @Test
    void aDefaultMethodFromADependencyInterfaceIsCharged() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Iface;",
            "public class S {",
            "  public static class Impl implements Iface { public void req(){} public void self(){ dflt(); } }",
            "  public void callDefault(Impl i){ i.dflt(); }",
            "}")));
        assertTrue(env(r, "app.S$Impl.self"), "an inherited dep DEFAULT method must carry its Env");
        assertTrue(env(r, "app.S.callDefault"), "a dep default reached through a project impl must carry its Env");
    }

    @Test
    void anInheritedPureDependencyMethodContributesNothing() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Base;",
            "public class S {",
            "  public static class Sub extends Base { public void self(){ quiet(); } }",
            "}")));
        assertFalse(env(r, "app.S$Sub.self"), "a dep method the report shows as pure must add nothing");
    }

    @Test
    void aProjectOverrideOfTheInheritedMethodIsNotCharged() throws Exception {
        // The override is the body the JVM runs; the dep superclass's is shadowed and must not be charged.
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Base;",
            "public class S {",
            "  public static class Sub extends Base { public void hook(){ } public void self(){ hook(); } }",
            "}")));
        assertFalse(env(r, "app.S$Sub.self"),
                "a project override shadows the dep body — nothing to inherit, got " + r.get("app.S$Sub.self"));
    }

    @Test
    void anAbstractProjectDeclarationShadowsTheDependencyBody() throws Exception {
        // An ABSTRACT project declaration also overrides: every concrete subtype must supply its own body,
        // which CHA enumerates. Charging the dep's implementation on top would fabricate.
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Base;",
            "public class S {",
            "  public static abstract class Mid extends Base { public abstract void hook(); }",
            "  public static class Leaf extends Mid { public void hook(){ } }",
            "  public void call(Mid m){ m.hook(); }",
            "}")));
        assertFalse(env(r, "app.S.call"),
                "an abstract project declaration redirects dispatch to the project subtypes, got " + r.get("app.S.call"));
    }

    @Test
    void aDependencysBareUnknownIsNotImportedOverAResolvedLocalDispatch() throws Exception {
        // `lib.Abs.flag()` is a concrete body whose OWN dispatch (`raw()`) has no implementor inside the
        // dependency, so the dep's report entry for it is a bare `Unknown` — "I could not resolve this".
        // Here the project resolves the same signature (`Leaf.flag` is in this scan), so importing that
        // Unknown would replace a complete answer with an unresolved one. This is the EXACT shape measured
        // on jackson-databind chained onto jackson-core, where `ResolvedType.isReferenceType()` — one
        // concrete body whose `getReferencedType()` dispatch jackson-core alone cannot resolve — turned 12
        // fully-resolved databind functions Unknown.
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Abs;",
            "public class S {",
            "  public static abstract class Mid extends Abs { }",
            "  public static class Leaf extends Mid { public int raw(){ return 3; } public boolean flag(){ return true; } }",
            "  public boolean call(Mid m){ return m.flag(); }",
            "}")));
        assertFalse(r.getOrDefault("app.S.call", EffectSet.empty()).toNames().contains("Unknown"),
                "a dep's bare Unknown must not overwrite a dispatch this scan resolves, got " + r.get("app.S.call"));
    }

    // ---- the no-report baseline ------------------------------------------------------------------------

    @Test
    void withNoChainedReportNothingIsInvented() throws Exception {
        // Nobody has scanned the dep, so candor genuinely does not know — and must not pretend either way.
        // The effect is absent (and the dep package is separately disclosed as invisible); crucially the
        // lookup itself invents nothing when `crossDeps` is empty, which is every unchained scan.
        Map<String, EffectSet> r = scanUnchained(LIB, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Entry;",
            "public class S { public String concat(Entry e){ return \"x\" + e; } }")));
        assertFalse(env(r, "app.S.concat"), "with no dep report there is nothing to inherit");
    }
}
