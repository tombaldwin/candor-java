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
