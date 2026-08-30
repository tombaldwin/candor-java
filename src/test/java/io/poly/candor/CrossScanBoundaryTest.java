package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
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

    /** {@link #scanChained}, with a chance to REWRITE the hierarchy sidecar between the two scans — the only
     *  way to test what a consumer does with a sidecar it did not write (an older producer's, say). */
    private static Map<String, EffectSet> scanChainedRewritingSidecar(Map<String, String> lib,
            Map<String, String> app, java.util.function.UnaryOperator<String> rewrite) throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path depReport = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            Path side = base.resolve("dep.hierarchy.json");
            Files.writeString(side, rewrite.apply(Files.readString(side)));
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** Scan `lib` and `app` as ONE tree — the control that says whether a chained answer is a boundary
     *  defect or a general limitation. */
    private static Map<String, EffectSet> scanOneTree(Map<String, String> lib, Map<String, String> app)
            throws Exception {
        Map<String, String> both = new java.util.HashMap<>(lib);
        both.putAll(app);
        Path dir = TestCompiler.compile(both);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            return Candor.runScan(dir);
        } finally {
            Candor.config = saved;
            rm(dir.getParent());
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

    /** Like {@link #scanChained} / {@link #scanUnchained} but returns the WRITTEN REPORT, keyed by `fn` —
     *  the only view that shows the two things the untyped-receiver rung is about: `unknownWhy`, and
     *  whether a function is PRESENT at all (absence from `functions` is itself a purity claim). */
    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> report(Map<String, String> lib, Map<String, String> app,
            boolean chained) throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            if (chained) {
                Path depReport = base.resolve("dep.json");
                ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
                Files.createDirectories(base.resolve(".candor"));
                Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
                Candor.config = Config.forTarget(appDir);
            }
            Path out = base.resolve("app.json");
            Files.deleteIfExists(out);                       // standing-bar item 7: never read a stale arm
            ReportWriter.writeJson(Candor.runScan(appDir), out.toString());
            Map<String, Object> root = new Gson().fromJson(Files.readString(out), Map.class);
            Map<String, Map<String, Object>> byFn = new java.util.HashMap<>();
            for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
                byFn.put((String) e.get("fn"), e);
            return byFn;
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> field(Map<String, Map<String, Object>> r, String fn, String key) {
        Map<String, Object> e = r.get(fn);
        return e == null ? List.of() : (List<String>) e.getOrDefault(key, List.of());
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
    void aMonomorphicNewReceiverOfAnInheritedDependencyMethodIsCharged() throws Exception {
        // The 2026-08-27 cardinal sin: `callInherited` above only ever exercises the PARAMETER-receiver
        // shape (`s.load()` where `s` is a param). `new Sub().load()` takes a DIFFERENT branch in
        // virtualDispatch — the provably-monomorphic-receiver fast path (Candor.java ~4846), which used to
        // `return true` unconditionally once it proved `monoRecv` locally, even when `monomorphicTarget`
        // found no concrete impl in Sub's OWN chain (the body lives only in the dependency superclass
        // Base). That skipped crossDepJoin's nearestDepFn entirely — added 2026-07-26 for exactly this
        // shape, but never exercised together with the 2026-07-09 fast path — and `new Sub().load()` read
        // silently pure though Base.load() performs real I/O. Two temporal siblings, never tested together.
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Base;",
            "public class S {",
            "  public static class Sub extends Base { public void extra(){ } }",
            "  public void callViaNew(){ Sub s = new Sub(); s.load(); }",
            "}")));
        assertTrue(env(r, "app.S.callViaNew"),
                "new Sub().load() on a dep superclass's inherited method must carry its Env, got "
                        + r.get("app.S.callViaNew"));
    }

    @Test
    void aMonomorphicNewReceiverThatDOESOverrideStillTakesTheFastPath() throws Exception {
        // The other half of the same audit: the fast path is an OPTIMISATION, not just a bug — a
        // monomorphic receiver whose type DOES declare a concrete override must still resolve LOCALLY,
        // never inheriting the shadowed dependency body (the sibling of
        // aProjectOverrideOfTheInheritedMethodIsNotCharged, but through a `new` receiver instead of a
        // parameter, so it also proves the fast-path return-true branch itself is untouched).
        Map<String, EffectSet> r = scanChained(LIB2, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Base;",
            "public class S {",
            "  public static class Sub extends Base { public void load(){ } }",
            "  public void callViaNew(){ Sub s = new Sub(); s.load(); }",
            "}")));
        assertFalse(env(r, "app.S.callViaNew"),
                "new Sub().load() must resolve to Sub's own PURE override, not inherit the dep's Env, got "
                        + r.get("app.S.callViaNew"));
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

    // ---- M4: CALLBACK / higher-order hand-off of a DEPENDENCY body -------------------------------------

    /** A dependency supplying a functional impl, a task type, static + instance method-ref targets, a PURE
     *  functional impl, and an ordinary value type with an effectful method that must never be charged. */
    private static final Map<String, String> LIB4 = Map.of(
        "lib/DepConsumer.java", "package lib;\nimport java.util.function.Consumer;\n"
            + "public class DepConsumer implements Consumer<String> {\n"
            + "  public void accept(String s){ System.getenv(\"HOME\"); }\n}\n",
        "lib/PureConsumer.java", "package lib;\nimport java.util.function.Consumer;\n"
            + "public class PureConsumer implements Consumer<String> {\n"
            + "  public void accept(String s){ }\n}\n",
        "lib/DepRunnable.java", "package lib;\npublic class DepRunnable implements Runnable {\n"
            + "  public void run(){ System.getenv(\"HOME\"); }\n}\n",
        "lib/DepUtil.java", "package lib;\npublic class DepUtil {\n"
            + "  public static void write(String s){ System.getenv(\"HOME\"); }\n"
            + "  public void writeInst(String s){ System.getenv(\"HOME\"); }\n}\n",
        "lib/DepValue.java", "package lib;\npublic class DepValue {\n"
            + "  public void touch(){ System.getenv(\"HOME\"); }\n}\n");

    @Test
    void aDependencyFunctionalHandedToAnInvokingHofIsCharged() throws Exception {
        // `new DepConsumer()` HAS a newType, so the opaque-handoff Unknown is suppressed; and
        // `functionalSamSurface` reads the project ClassNode, so a dep type yields no edge either.
        Map<String, EffectSet> r = scanChained(LIB4, Map.of("app/S.java", String.join("\n",
            "package app; import lib.DepConsumer; import java.util.*;",
            "public class S { public void each(List<String> xs){ xs.forEach(new DepConsumer()); } }")));
        assertTrue(env(r, "app.S.each"), "forEach(new DepConsumer()) must carry the dep body's Env");
    }

    @Test
    void aDependencyTaskSubmittedToAnExecutorIsCharged() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB4, Map.of("app/S.java", String.join("\n",
            "package app; import lib.DepRunnable; import java.util.concurrent.*;",
            "public class S { public void go(ExecutorService es){ es.submit(new DepRunnable()); } }")));
        assertTrue(env(r, "app.S.go"), "es.submit(new DepRunnable()) must carry the dep task's Env");
    }

    @Test
    void aMethodReferenceIntoADependencyIsCharged() throws Exception {
        // A method handle carries the exact owner+name+desc, so this joins on the same hash the direct call
        // would. Both the static and the bound-instance form.
        Map<String, EffectSet> r = scanChained(LIB4, Map.of("app/S.java", String.join("\n",
            "package app; import lib.DepUtil; import java.util.*;",
            "public class S {",
            "  public void staticRef(List<String> xs){ xs.forEach(DepUtil::write); }",
            "  public void instRef(List<String> xs, DepUtil d){ xs.forEach(d::writeInst); }",
            "}")));
        assertTrue(env(r, "app.S.staticRef"), "forEach(DepUtil::write) must carry the dep body's Env");
        assertTrue(env(r, "app.S.instRef"), "forEach(d::writeInst) must carry the dep body's Env");
    }

    @Test
    void aPureDependencyFunctionalContributesNothing() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB4, Map.of("app/S.java", String.join("\n",
            "package app; import lib.PureConsumer; import java.util.*;",
            "public class S { public void each(List<String> xs){ xs.forEach(new PureConsumer()); } }")));
        assertFalse(env(r, "app.S.each"), "a dep functional the report shows as pure must add nothing");
    }

    @Test
    void anOrdinaryValueConstructedAtAHofCallSiteIsNotCharged() throws Exception {
        // `Map.merge` IS an invoking HOF, but its second argument is the VALUE, not the function. Charging
        // the whole surface of anything constructed at a HOF call site would fabricate; the hand-off join
        // is gated on the PARAMETER's declared type being a functional interface.
        Map<String, EffectSet> r = scanChained(LIB4, Map.of("app/S.java", String.join("\n",
            "package app; import lib.DepValue; import java.util.*;",
            "public class S {",
            "  public void put(Map<String,DepValue> m){ m.merge(\"k\", new DepValue(), (a,b) -> a); }",
            "}")));
        assertFalse(env(r, "app.S.put"),
                "a non-functional argument must not be charged its type's surface, got " + r.get("app.S.put"));
    }

    // ---- M5: the UNTYPED CROSS-PACKAGE RECEIVER (candor-spec DEP-RECEIVER-TYPING-DESIGN.md, half 1) -----

    /** A dependency whose effectful body sits behind an INTERFACE it also exports, reached through a
     *  factory — so the call site names {@code lib/Store} and the body is keyed {@code lib/FileStore.save}.
     *  Plus the four things the controls need: a PURE member of the same interface, a pure static, and a
     *  pure/effectful pair of same-signature CLASS methods. */
    private static final Map<String, String> LIB5 = Map.of(
        "lib/Store.java", "package lib;\npublic interface Store {\n"
            + "  void save(String s);\n  String label();\n}\n",
        "lib/FileStore.java", "package lib;\npublic class FileStore implements Store {\n"
            + "  public void save(String s){ System.getenv(\"HOME\"); }\n"
            + "  public String label(){ return \"f\"; }\n}\n",
        "lib/Factory.java", "package lib;\npublic class Factory {\n"
            + "  public static Store build(){ return new FileStore(); }\n}\n",
        "lib/Pure.java", "package lib;\npublic class Pure {\n"
            + "  public static int twice(int n){ return n * 2; }\n}\n",
        "lib/Plain.java", "package lib;\npublic class Plain {\n  public void tick(){ }\n}\n",
        "lib/Noisy.java", "package lib;\npublic class Noisy {\n"
            + "  public void tick(){ System.getenv(\"HOME\"); }\n}\n");

    private static final String CALL_THROUGH_IFACE = String.join("\n",
        "package app; import lib.*;",
        "public class S {",
        "  public void run(){ Store s = Factory.build(); s.save(\"x\"); }",
        "}");

    @Test
    void anUntypedDependencyInterfaceReceiverDisclosesRatherThanReadingPure() throws Exception {
        // THE DEFECT. `Store s = Factory.build(); s.save("x")` compiles to INVOKEINTERFACE on lib/Store;
        // the dep report keys the body lib/FileStore.save, the factory is PURE so it is absent from the
        // report entirely, and the CHA over project classes is empty — and an empty CHA emits no Unknown,
        // only a dropped edge. The caller was therefore ABSENT from `functions` while counted in ⟨0.21⟩
        // `analyzed`: a confident purity claim about a method that reads the environment.
        Map<String, Map<String, Object>> r = report(LIB5, Map.of("app/S.java", CALL_THROUGH_IFACE), true);
        assertTrue(r.containsKey("app.S.run"),
                "the caller must not be ABSENT from the report — absence IS a purity claim");
        assertTrue(field(r, "app.S.run", "inferred").contains("Unknown"),
                "an unformed key across the scan boundary must disclose, got " + r.get("app.S.run"));
        assertTrue(field(r, "app.S.run", "unknownWhy").contains("dispatch:lib.Store.save"),
                "the disclosure must name the dispatch it could not resolve, got "
                        + field(r, "app.S.run", "unknownWhy"));
    }

    @Test
    void aKeyedAndMissedDependencyLookupStaysSilent() throws Exception {
        // THE CONTROL THAT MAKES THE RUNG NARROW. A lookup whose key WAS formed and came back empty is a
        // genuine purity claim — a dep report omits its pure functions (SPEC §2 rule 3) — so silence is
        // the honest answer and a hedge here would be manufactured uncertainty. Two forms: an exact
        // static key (`Pure.twice`), and an interface member whose signature has no effectful body
        // anywhere in the chained report (`Store.label` — conjunct 5).
        Map<String, Map<String, Object>> r = report(LIB5, Map.of("app/S.java", String.join("\n",
            "package app; import lib.*;",
            "public class S {",
            "  public int calc(){ return Pure.twice(21); }",
            "  public String lbl(){ Store s = Factory.build(); return s.label(); }",
            "}")), true);
        assertFalse(field(r, "app.S.calc", "inferred").contains("Unknown"),
                "an EXACT key that missed is a purity claim, not a gap, got " + r.get("app.S.calc"));
        assertFalse(field(r, "app.S.lbl", "inferred").contains("Unknown"),
                "an interface member with no effectful body in the chained report must stay silent, got "
                        + r.get("app.S.lbl"));
    }

    @Test
    void anUnchainedDependencyIsUnchangedAndKeepsItsInvisible() throws Exception {
        // CONJUNCT 3, the one rust found by measuring. With NOTHING chained the κ ledger already discloses
        // `invisible: [lib]`, so a second voice would be pure false uncertainty. It is precisely when the
        // dep IS chained that the ledger correctly falls silent and the silence becomes the confident claim.
        Map<String, Map<String, Object>> r = report(LIB5, Map.of("app/S.java", CALL_THROUGH_IFACE), false);
        assertTrue(field(r, "app.S.run", "invisible").contains("lib"),
                "the unchained arm's κ disclosure must be intact, got " + r.get("app.S.run"));
        assertFalse(field(r, "app.S.run", "inferred").contains("Unknown"),
                "an unchained dep must not gain a SECOND disclosure, got " + r.get("app.S.run"));
    }

    @Test
    void aProvablyTypedDependencyReceiverIsKeyedNotDisclosed() throws Exception {
        // CONJUNCT 2. A monomorphic `new FileStore()` receiver IS typed, so the concrete key is formed and
        // the real effect comes back. Disclosing Unknown here instead would be a strict loss of precision.
        Map<String, EffectSet> r = scanChained(LIB5, Map.of("app/S.java", String.join("\n",
            "package app; import lib.*;",
            "public class S { public void run(){ Store s = new FileStore(); s.save(\"x\"); } }")));
        assertTrue(env(r, "app.S.run"), "a provably-typed dep receiver keys the concrete body, got " + r.get("app.S.run"));
        assertFalse(r.getOrDefault("app.S.run", EffectSet.empty()).toNames().contains("Unknown"),
                "a resolved dispatch must not also be hedged, got " + r.get("app.S.run"));
    }

    @Test
    void aProjectImplementationOfTheDependencyInterfaceAnswersTheDispatch() throws Exception {
        // CONJUNCT 4. A non-empty CHA means the dispatch HAS a local answer; whether that answer is
        // complete is the documented bounded-CHA trade, not this rung's business.
        Map<String, EffectSet> r = scanChained(LIB5, Map.of("app/S.java", String.join("\n",
            "package app; import lib.*;",
            "public class S {",
            "  public static class Mine implements Store { public void save(String s){} public String label(){ return \"m\"; } }",
            "  public void run(Store s){ s.save(\"x\"); }",
            "}")));
        assertFalse(r.getOrDefault("app.S.run", EffectSet.empty()).toNames().contains("Unknown"),
                "a dispatch the project CHA resolves must not be hedged, got " + r.get("app.S.run"));
    }

    @Test
    void anInvokevirtualOnADependencyClassIsNotDisclosed() throws Exception {
        // CONJUNCT 1, and the reason this rung is not "unresolved receiver". `p.tick()` on a dep CLASS is
        // INVOKEVIRTUAL: the static owner usually IS the body, so its absence from the report is a real
        // purity claim. Every other conjunct holds here — lib is chained, no project impl, the receiver is
        // a parameter, and lib/Noisy.tick()V IS an effectful same-signature body in the chained report —
        // so INVOKEINTERFACE is the only thing keeping this silent. Fire on INVOKEVIRTUAL too and the
        // trigger degenerates into the 5.4%-of-all-functions flood measured on nine chained JVM corpora.
        Map<String, EffectSet> r = scanChained(LIB5, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Plain;",
            "public class S { public void run(Plain p){ p.tick(); } }")));
        assertFalse(r.getOrDefault("app.S.run", EffectSet.empty()).toNames().contains("Unknown"),
                "a virtual call on a dep CLASS names its own body — a miss there is a purity claim, got "
                        + r.get("app.S.run"));
    }

    /** GUARD-DELETION SWEEP: {@code untypedDepReceiver} has an unnumbered guard ahead of the documented
     *  5 conjuncts — {@code isChaExemptMethod}, "the conventionally-pure surface" — that had zero coverage
     *  of its own contribution: deleting it left the full unit suite AND {@code smoke.sh} green. It matters
     *  for exactly one shape: a generic {@code Comparable<T>} bridge. {@code a.compareTo(b)} through a
     *  chained-dep interface erases to INVOKEINTERFACE {@code lib.Store.compareTo(Ljava/lang/Object;)I} —
     *  every other conjunct (interface dispatch, non-mono receiver, chained pkg, empty project CHA, AND a
     *  same-signature effectful body elsewhere in the dep — {@code LoudKey}'s bridge) is satisfied, so
     *  without this guard the SPEC §4 conventionally-pure {@code compareTo} bridge fabricates an Unknown.
     *  (Ordinary {@code toString}/{@code equals}/{@code hashCode} calls through an interface-typed receiver
     *  do NOT reach this code at all — javac resolves them to {@code invokevirtual java/lang/Object.*}
     *  regardless of the receiver's static interface type, confirmed via javap — so {@code compareTo} is
     *  the only member of the Object-protocol set this conjunct-chain can ever see.) */
    @Test
    void comparableBridgeThroughChainedInterfaceStaysPureWithNoVisibleImpl() throws Exception {
        Map<String, String> lib5WithComparable = new java.util.HashMap<>(LIB5);
        lib5WithComparable.put("lib/Ordered.java",
            "package lib;\npublic interface Ordered extends Comparable<Ordered> {}\n");
        // A RAW Comparable (no generic argument) declares compareTo(Object) directly — not a synthetic
        // bridge (candor's scanner does not analyse bridge/synthetic methods, so a generic
        // Comparable<LoudKey>'s auto-generated bridge never appears in the dep report at all; this is the
        // one shape that puts a REAL, analysed method under the erased `(Ljava/lang/Object;)I` descriptor).
        lib5WithComparable.put("lib/LoudKey.java", String.join("\n",
            "package lib;",
            "@SuppressWarnings({\"unchecked\", \"rawtypes\"})",
            "public class LoudKey implements Comparable {",
            "  public int compareTo(Object o){ System.getenv(\"HOME\"); return 0; }",
            "}"));
        Map<String, EffectSet> r = scanChained(lib5WithComparable, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Ordered;",
            "public class S { public int run(Ordered a, Ordered b){ return a.compareTo(b); } }")));
        assertFalse(r.getOrDefault("app.S.run", EffectSet.empty()).toNames().contains("Unknown"),
                "a Comparable bridge (Object-protocol, SPEC §4 conventionally pure) through a chained "
                        + "interface with no visible impl must stay pure, not fabricate Unknown, got "
                        + r.get("app.S.run"));
    }

    /** A hand-off invokes ONE member of the constructed type — the interface's SAM — plus the constructor.
     *  The rest of the type's reported surface is unreachable through it, and inheriting all of it charged
     *  a scheduling method with effects no call path reaches. */
    @Test
    void aTaskHandoffInheritsOnlyWhatTheRuntimeInvokes() throws Exception {
        Map<String, String> lib = Map.of("lib/ReportJob.java", String.join("\n",
            "package lib;",
            "import java.io.*;",
            "public class ReportJob implements Runnable {",
            "  public void run(){ }",
            "  public void exportCsv(){ try (FileWriter w = new FileWriter(\"/tmp/r\")) { w.write(\"x\"); } catch (Exception e) {} }",
            "  public void upload(){ try { new java.net.Socket(\"example.com\", 80).close(); } catch (Exception e) {} }",
            "}"));
        Map<String, EffectSet> r = scanChained(lib, Map.of("app/Sched.java", String.join("\n",
            "package app; import java.util.concurrent.*;",
            "public class Sched { public void enqueue(ExecutorService es){ es.submit(new lib.ReportJob()); } }")));
        var got = r.getOrDefault("app.Sched.enqueue", EffectSet.empty()).toNames();
        assertFalse(got.contains("Fs") || got.contains("Net"),
                "the executor invokes run() and nothing else — exportCsv()'s Fs and upload()'s Net are "
                        + "public helpers no call path reaches from here, got " + got);
    }

    // ---- M6: the by-NAME reentry contracts (compareTo / append / write) --------------------------------

    /** {@code toString}/{@code equals}/{@code hashCode} each have ONE descriptor, so M1/M3 could compute the
     *  dependency's exact hash. {@code Comparable.compareTo}, {@code Appendable.append} and
     *  {@code Writer.write} are re-entered over whichever overload the JDK sink picks, and the consumer's
     *  bytecode names none of them — {@code treeSet.add(depItem)} carries no descriptor at all. This lib
     *  supplies one effectful case per contract, plus everything the fabrication controls need: a PURE
     *  comparable, a same-named NON-contract member, a partially-overridden multi-overload sink, and an
     *  unrelated dependency type whose method merely SHARES the leaf name {@code write}. */
    private static final Map<String, String> LIB6 = Map.of(
        "lib/Item.java", "package lib;\npublic class Item implements Comparable<Item> {\n"
            + "  public int compareTo(Item o){ System.getenv(\"HOME\"); return 0; }\n}\n",
        "lib/PureItem.java", "package lib;\npublic class PureItem implements Comparable<PureItem> {\n"
            + "  public int compareTo(PureItem o){ return 0; }\n}\n",
        "lib/Odd.java", "package lib;\npublic class Odd implements Comparable<Odd> {\n"
            + "  public int compareTo(Odd o){ return 0; }\n"
            + "  public void compareTo(String a, int b){ System.getenv(\"HOME\"); }\n}\n",
        "lib/Sink.java", "package lib;\npublic class Sink implements Appendable {\n"
            + "  public Appendable append(CharSequence c){ System.getenv(\"HOME\"); return this; }\n"
            + "  public Appendable append(char c){ new java.io.File(\"/tmp/candor-x\").exists(); return this; }\n"
            + "  public Appendable append(CharSequence c, int s, int e){ return this; }\n}\n",
        "lib/LoudWriter.java", "package lib;\npublic class LoudWriter extends java.io.Writer {\n"
            + "  public void write(char[] c, int o, int n){ System.getenv(\"HOME\"); }\n"
            + "  public void flush(){}\n  public void close(){}\n}\n",
        "lib/QuietWriter.java", "package lib;\npublic class QuietWriter extends java.io.Writer {\n"
            + "  public void write(char[] c, int o, int n){ }\n"
            + "  public void flush(){}\n  public void close(){}\n}\n",
        "lib/Session.java", "package lib;\npublic class Session {\n"
            + "  public void write(String s){ new java.io.File(\"/tmp/candor-x\").exists(); }\n}\n",
        "lib/LoudReader.java", "package lib;\npublic class LoudReader extends java.io.Reader {\n"
            + "  public int read(char[] c, int o, int n){ System.getenv(\"HOME\"); return -1; }\n"
            + "  public void close(){}\n}\n",
        // NOT a stream, and it declares the very overload a relaxed io gate would reach for. The
        // fabrication control for the hierarchy consumer: `l.write("x")` runs the PURE `write(String)`.
        "lib/Ledger.java", "package lib;\npublic class Ledger {\n"
            + "  public void write(char[] c, int o, int n){ System.getenv(\"HOME\"); }\n"
            + "  public void write(String s){ }\n}\n");

    private static boolean fs(Map<String, EffectSet> r, String m) {
        return r.getOrDefault(m, EffectSet.empty()).toNames().contains("Fs");
    }

    private static boolean exec(Map<String, EffectSet> r, String m) {
        return r.getOrDefault(m, EffectSet.empty()).toNames().contains("Exec");
    }

    // ---- JVM RESOLUTION ORDER FOR A CHAIN LYING ENTIRELY INSIDE THE DEPENDENCY --------------------------
    // `9f8e71c` made all four supertype walks resolve the CLASS chain before any interface and left ONE
    // residual: the sidecar recorded a dep type's supertypes as a sorted set with no superclass marker, so
    // for those types the kind was unknown and the JLS rule could not be applied. Its own tests put the
    // branching class in the APP, where a project ClassNode states the split. Here every link is in `lib`.

    private static final Map<String, String> LIB9 = Map.of(
        // the body the JVM actually runs — Fs
        "lib/Root9.java", "package lib;\npublic class Root9 {\n"
            + "  public void emit(String s){ new java.io.File(\"/tmp/candor-y\").exists(); }\n}\n",
        "lib/Mid9.java", "package lib;\npublic class Mid9 extends Root9 {}\n",
        // NEARER in a depth-ordered walk, and a different effect so either error is visible — Env
        "lib/Trace9.java", "package lib;\npublic interface Trace9 {\n"
            + "  default void emit(String s){ System.getenv(\"HOME\"); }\n}\n",
        "lib/Half9.java", "package lib;\npublic class Half9 extends Mid9 implements Trace9 {}\n",
        // a THIRD effect, reachable only if an unknown-kind supertype is demoted to the interface phase.
        // Exec rather than Log: `System.out.println` produces no report entry at all, and with no entry
        // the mutant that reads an unmarked list as all-interfaces changes nothing and the second fixture
        // could not fail — which is exactly what mutating it showed before this line was Exec.
        "lib/Loud9.java", "package lib;\npublic interface Loud9 {\n"
            + "  default void emit(String s){ try { new ProcessBuilder(s).start(); } catch (Exception e) {} }\n}\n");

    /** The app's own class implements a dep interface DIRECTLY, so the readings of an unmarked supertype
     *  list — walk it in the phase we are already in (what shipped) versus demote it to the interface phase
     *  — give different answers instead of coinciding. Without this the second fixture could not fail. */
    private static final Map<String, String> APP9 = Map.of("app/S.java", String.join("\n",
        "package app; import lib.*;",
        "public class S extends Half9 implements Loud9 {",
        "  public void go(){ emit(\"x\"); }",
        "}"));

    @Test
    void anUnmarkedHierarchySidecarKeepsEXACTLYTodaysDepthOrderedAnswer() throws Exception {
        // THE SECOND FIXTURE, AND IT WAS WRITTEN FIRST. A sidecar an older producer wrote carries no
        // superclass marker, and the fallback for it must be the behaviour that shipped, not a guess:
        // reading an unmarked list as ALL INTERFACES would push a real superclass below an interface and
        // charge `Loud9`'s body, which the JVM never runs here. Mutate `resolutionOrder`'s unknown-kind
        // branch to `ifaceQ.addAll(dep)` and this test fails.
        Map<String, EffectSet> r = scanChainedRewritingSidecar(LIB9, APP9, CrossScanBoundaryTest::unmark);
        assertTrue(env(r, "app.S.go"),
                "an unmarked sidecar must keep the depth-ordered answer that shipped, got " + r.get("app.S.go"));
        assertFalse(exec(r, "app.S.go"),
                "an unmarked supertype list read as ALL INTERFACES puts a dep interface above a dep "
                        + "superclass — a body the JVM never runs, got " + r.get("app.S.go"));
    }

    @Test
    void aChainInsideTheDependencyResolvesClassFirstOnceTheSidecarMarksItsSuperclass() throws Exception {
        // THE ROW. `S.go` resolves to `Root9.emit` (Fs) — JLS 15.12.2.5 / 8.4.8, the class wins at any
        // depth — where the depth-ordered walk settled on `Trace9`'s default (Env) two hops earlier.
        Map<String, EffectSet> r = scanChained(LIB9, APP9);
        assertTrue(fs(r, "app.S.go"),
                "a chain lying entirely inside the dependency must resolve CLASS-first: Root9.emit is the "
                        + "body the JVM runs, got " + r.get("app.S.go"));
        assertFalse(env(r, "app.S.go"),
                "Trace9's default is SHADOWED by the inherited class body — charging its Env is a "
                        + "fabrication on a method that never runs, got " + r.get("app.S.go"));
        assertFalse(exec(r, "app.S.go"),
                "Loud9 loses to the whole class chain, got " + r.get("app.S.go"));
        // THE SINGLE-TREE CONTROL: as one tree candor already says Fs, so the split was the thing wrong.
        Map<String, EffectSet> one = scanOneTree(LIB9, APP9);
        assertTrue(one.get("app.S.go").toNames().contains("Fs"),
                "the single-tree control must be Fs, or this is a limitation and not a boundary defect; got "
                        + one.get("app.S.go"));
        assertFalse(one.get("app.S.go").toNames().contains("Env"), "single-tree control");
    }

    /** Strip the {@code @superclass} object from a sidecar — the shape every producer before this rung
     *  wrote. Asserts it actually removed something, so the second fixture cannot pass vacuously. */
    @SuppressWarnings("unchecked")
    private static String unmark(String sidecar) {
        Map<String, Object> m = new Gson().fromJson(sidecar, Map.class);
        assertTrue(m.remove(ReportWriter.SUPERCLASS_KEY) != null,
                "the producer never wrote a marker — this fixture would pass vacuously");
        return new Gson().toJson(m);
    }

    /** Run a chained scan purely to CAPTURE the sidecar this engine writes, unmodified. */
    private static String capturedSidecar(Map<String, String> lib, Map<String, String> app) throws Exception {
        StringBuilder seen = new StringBuilder();
        scanChainedRewritingSidecar(lib, app, s -> { seen.append(s); return s; });
        assertFalse(seen.isEmpty(), "no sidecar was written — this fixture would pass vacuously");
        return seen.toString();
    }

    // ---- THE SIDECAR IS A WIRE, AND ITS THIRD READER IS IN ANOTHER LANGUAGE ------------------------------

    @Test
    void theSidecarLoadsUnderTheSTRICTLYTypedDeserializerCandorQueryUses() throws Exception {
        // THE THIRD READER. candor-rust's `candor-query::load_hierarchy` deserializes this file as
        // `BTreeMap<String, Vec<String>>` — one strict typed call, no per-entry loop to skip anything — and
        // its `if let Ok(map)` drops the WHOLE file when that fails. `--report <a java report>.json` is an
        // explicitly supported route into it (candor_report::report_files: "so one engine can query
        // another's report by path"), so an OBJECT value under `@superclass` silently discarded a java
        // sidecar there exactly as it did in `Query.loadHierarchy` — the same failure, in a second reader,
        // introduced by the fix for the first. Reproduced before this test was written: `candor-query
        // callers app.Sink.touch --include-unknown` over a real java scan disclosed a frontier function the
        // hierarchy rules out, and stripping the marker from the same sidecar dropped it again.
        //
        // The model below IS that deserializer: every value an array of strings, no exceptions. Mutate
        // `writeHierarchy` back to `h.put(SUPERCLASS_KEY, supers)` with a Map value and this test fails.
        String sidecar = capturedSidecar(LIB9, APP9);
        Map<String, List<String>> strict;
        try {
            strict = new Gson().fromJson(sidecar,
                    new com.google.gson.reflect.TypeToken<Map<String, List<String>>>() {}.getType());
        } catch (RuntimeException e) {
            throw new AssertionError("the sidecar does not parse under the strict `BTreeMap<String, "
                    + "Vec<String>>` model candor-query uses — it discards the WHOLE hierarchy there, with "
                    + "no diagnostic: " + e, e);
        }
        assertTrue(strict.containsKey("lib.Half9"), "a strict reader must still see the class keys");
        // The writer-side constraint, stated as an assertion rather than as a comment: EVERY value in this
        // file is an array. That — not a name — is what keeps a typed reader working, and it is the property
        // the `@superclass` rung broke.
        for (var e : com.google.gson.JsonParser.parseString(sidecar).getAsJsonObject().entrySet())
            assertTrue(e.getValue().isJsonArray(),
                    "every value in the hierarchy sidecar must be an ARRAY (a typed reader models it as "
                            + "one); `" + e.getKey() + "` is " + e.getValue());
    }

    @Test
    void aSidecarCarryingTheOLDObjectFormOfTheMarkerStillSplitsTheChain() throws Exception {
        // THE SECOND DIRECTION, and it is a real deployed shape: candor-java 0.23.1 shipped the marker as an
        // OBJECT, so every dep report and sidecar written by it carries that form. Narrowing the reader to
        // the new array form alone would silently drop the split for all of them — a fabrication fix
        // manufacturing the under-report it was closing (standing-bar item 0). Mutate the object branch out
        // of `Loader.readSuperclassMarker` and this test fails.
        Map<String, EffectSet> r = scanChainedRewritingSidecar(LIB9, APP9,
                CrossScanBoundaryTest::markerAsObject);
        assertTrue(fs(r, "app.S.go"),
                "a 0.23.1-shaped sidecar must still resolve CLASS-first, got " + r.get("app.S.go"));
        assertFalse(env(r, "app.S.go"), "Trace9's default is shadowed, got " + r.get("app.S.go"));
    }

    @Test
    void aReservedMetadataKeyNeverBecomesADependencyTYPE() throws Exception {
        // The marker's value is an array like every type's now, so SHAPE no longer tells them apart and
        // `Loader.loadDepHierarchy` has to skip the reserved `@` namespace by NAME. Without that skip the
        // marker lands in `depSupers` as a type whose "supertypes" are the flattened pair list — a
        // fabricated structural fact, and one that makes `depSupers.isEmpty()` (a live short-circuit in
        // `Candor.isJavaIoStreamType`) non-empty for a sidecar naming no type at all. Mutate the
        // `startsWith("@")` skip out of `Loader.loadDepHierarchy` and this test fails.
        Path base = Files.createTempDirectory("candor-meta");
        try {
            Path side = base.resolve("dep.hierarchy.json");
            Files.writeString(side, "{\"lib.A\": [\"lib.B\"], \"" + ReportWriter.SUPERCLASS_KEY
                    + "\": [\"lib.A\", \"lib.B\"]}");
            AnalysisState.newContext();
            Loader.loadDepHierarchy(side);
            assertEquals(List.of("lib/B"), AnalysisState.ctx().depSupers.get("lib/A"),
                    "the class key must load, or this fixture proves nothing");
            for (String k : AnalysisState.ctx().depSupers.keySet())
                assertFalse(k.startsWith("@"), "a reserved metadata key became a dependency TYPE: " + k);
        } finally {
            AnalysisState.remove();
            rm(base);
        }
    }

    /** Rewrite the marker into the OBJECT form candor-java 0.23.1 wrote. Asserts it changed something. */
    @SuppressWarnings("unchecked")
    private static String markerAsObject(String sidecar) {
        Map<String, Object> m = new Gson().fromJson(sidecar, Map.class);
        List<String> flat = (List<String>) m.get(ReportWriter.SUPERCLASS_KEY);
        assertTrue(flat != null && !flat.isEmpty(),
                "the producer wrote no marker pairs — this fixture would pass vacuously");
        Map<String, String> obj = new java.util.LinkedHashMap<>();
        for (int i = 0; i + 1 < flat.size(); i += 2) obj.put(flat.get(i), flat.get(i + 1));
        m.put(ReportWriter.SUPERCLASS_KEY, obj);
        return new Gson().toJson(m);
    }

    // ---- THE MARKER MUST NOT BE THE ONLY KEY IN THE FILE -------------------------------------------------
    // A sidecar that used to serialize as `{}` became `{"@superclass":{}}`, and TWO consumers gate the
    // PRECISE dispatch frontier on the map being non-empty — candor-ts `Object.keys(h).length > 0`,
    // candor-rust `!hier.is_empty()`. The metadata key alone flips that gate from its documented
    // over-listing fallback to the precise path over an EMPTY hierarchy, so a disclosure is withdrawn on
    // zero information. Reproduced with candor-ts before the fix: `callers app.Sink.touch
    // --include-unknown` over a flat java project listed one frontier function with `{}` and NONE with
    // `{"@superclass":{}}`.

    /** A dep type with NO superclass, whose interface must therefore be walked in the INTERFACE phase. */
    private static final Map<String, String> LIB10 = Map.of(
        "lib/IA.java", "package lib;\npublic interface IA {\n"
            + "  default void emit(String s){ try { new ProcessBuilder(s).start(); } catch (Exception e) {} }\n}\n",
        "lib/IB.java", "package lib;\npublic interface IB extends IA {\n"
            + "  default void emit(String s){ System.getenv(\"HOME\"); }\n}\n",
        "lib/DepA.java", "package lib;\npublic class DepA implements IA {}\n");

    private static final Map<String, String> APP10 = Map.of("app/S.java", String.join("\n",
        "package app; import lib.*;",
        "public class S extends DepA implements IB {",
        "  public void go(){ emit(\"x\"); }",
        "}"));

    @Test
    void aDepTypeWithNoSuperclassSTILLNeedsTheMarkerToOrderItsInterfacesLast() throws Exception {
        // THE SECOND FIXTURE, WRITTEN FIRST, and it is what stops "omit the marker whenever it is empty"
        // from being the fix for the emptiness-gate flip. `DepA` has no superclass, so it contributes no
        // marker PAIR — but the marker's presence is still what says so. With it, `DepA`'s `IA` is enqueued
        // in the INTERFACE phase and `S`'s own `IB` (which overrides `IA.emit`, and is what the JVM runs)
        // is reached first. Without it the kinds are unknown, `IA` goes into the CLASS queue, and `IA.emit`
        // wins — a body that never runs. Mutate `writeHierarchy` to skip the marker when `supers` is empty
        // and this test fails.
        Map<String, EffectSet> r = scanChained(LIB10, APP10);
        assertTrue(env(r, "app.S.go"),
                "IB.emit overrides IA.emit and is what the JVM runs, got " + r.get("app.S.go"));
        assertFalse(exec(r, "app.S.go"),
                "IA.emit is shadowed by IB.emit — charging its Exec is a fabrication, got " + r.get("app.S.go"));
        Map<String, EffectSet> one = scanOneTree(LIB10, APP10);
        assertTrue(one.get("app.S.go").toNames().contains("Env"),
                "single-tree control, got " + one.get("app.S.go"));
        // And the arm that proves the assertion above is not vacuous: an UNMARKED sidecar gets the shipped
        // depth-ordered answer, which here is the wrong one. That is the documented residual for a sidecar
        // an older producer wrote, and it is exactly what the mutant would make the marked case do too.
        Map<String, EffectSet> unmarked = scanChainedRewritingSidecar(LIB10, APP10,
                CrossScanBoundaryTest::unmark);
        assertTrue(exec(unmarked, "app.S.go"),
                "an unmarked sidecar keeps the shipped unknown-kind behaviour — if this is Env the marked "
                        + "arm above proves nothing, got " + unmarked.get("app.S.go"));
    }

    @Test
    void aSidecarThatNamesNoTypeCarriesNoMetadataKeyAtAll() throws Exception {
        // The gate flip itself. A project whose types have no supertype at all wrote `{}` before this rung
        // and `{"@superclass":{}}` after, and that key ALONE takes candor-ts's and candor-rust's frontier
        // off the over-listing fallback. The marker is provably inert here — `Loader.loadDepHierarchy` only
        // consults it INSIDE the per-type loop, so with no type key it is read zero times — which is what
        // makes omitting it free rather than a trade. Mutate the `h.isEmpty()` guard out and this fails.
        String sidecar = capturedSidecar(
                Map.of("lib/Flat.java", "package lib;\npublic class Flat { public void go(){ System.getenv(\"HOME\"); } }\n"),
                Map.of("app/S.java", "package app;\npublic class S { public void go(){ new lib.Flat().go(); } }\n"));
        // ⟨0.26⟩ THE ASSERTION MOVED WITH THE CONTRACT, and both halves are kept.
        //
        // It used to require exactly `{}` here, because the project's one type has no supertype and the
        // pre-rung producer omitted such types — so "names no type" and "has nothing to say" were the same
        // file. SPEC §2.2 ⟨0.26⟩ makes the KEY SET THE MANIFEST: an indexed type appears with `[]`, and
        // ABSENCE is what now means "never indexed". `lib.Flat` IS indexed, so naming it is the point, not
        // a regression — and naming it is precisely what lets a consumer answer about it without guessing.
        //
        // THE ORIGINAL HAZARD IS UNCHANGED AND STILL ASSERTED: `@superclass` must never be the file's ONLY
        // key. candor-ts (`Object.keys(h).length > 0`) and candor-rust (`!hier.is_empty()`) take the
        // PRECISE frontier iff the map is non-empty, so a metadata key alone would flip them off the
        // over-listing fallback onto a precise walk over an empty hierarchy — a disclosure withdrawn on
        // zero information, in another engine. That is what this row exists for and it survives the rung.
        var obj = com.google.gson.JsonParser.parseString(sidecar).getAsJsonObject();
        assertTrue(obj.has("lib.Flat") && obj.getAsJsonArray("lib.Flat").isEmpty(),
                "⟨0.26⟩ an INDEXED type with no supertypes must appear with `[]` — the key set is the "
                        + "manifest, and omitting it is what made absence ambiguous; got " + sidecar);
        var typeKeys = obj.keySet().stream().filter(k -> !k.startsWith("@")).count();
        assertTrue(typeKeys > 0,
                "the metadata key must never be the file's ONLY key — two engines gate the precise "
                        + "frontier on non-emptiness; got " + sidecar);
    }

    @Test
    void byNameContractReentryReachesADependencyBody() throws Exception {
        // THE DEFECT. Each of these resolves in a SINGLE tree (the control below) and read silent-pure once
        // the same source was split and lib's report chained: `reentryTargets`' by-NAME arm ends in the
        // project-only subtype index, and the cross-boundary join beside it handled only the three
        // fixed-descriptor contracts.
        Map<String, EffectSet> r = scanChained(LIB6, Map.of("app/S.java", String.join("\n",
            "package app; import lib.*; import java.util.*;",
            "public class S {",
            "  public void treeAdd(TreeSet<Item> s, Item i){ s.add(i); }",
            "  public void treeMapPut(TreeMap<Item,String> m, Item i){ m.put(i, \"x\"); }",
            "  public void formatter(Sink k){ new java.util.Formatter(k).format(\"x\"); }",
            "  public void printWriter(LoudWriter w){ new java.io.PrintWriter(w).println(\"x\"); }",
            "}")));
        assertTrue(env(r, "app.S.treeAdd"), "TreeSet.add(depItem) re-enters the dep's compareTo, got " + r.get("app.S.treeAdd"));
        assertTrue(env(r, "app.S.treeMapPut"), "TreeMap.put(depKey,..) re-enters the dep's compareTo, got " + r.get("app.S.treeMapPut"));
        assertTrue(env(r, "app.S.formatter"), "new Formatter(depAppendable) drives the dep's append, got " + r.get("app.S.formatter"));
        assertTrue(env(r, "app.S.printWriter"), "new PrintWriter(depWriter) drives the dep's write, got " + r.get("app.S.printWriter"));
    }

    @Test
    void byNameContractReentryMatchesItsSingleTreeControl() throws Exception {
        // The control that makes it a BOUNDARY defect rather than a general limitation: identical source,
        // one tree, nothing chained.
        Map<String, String> all = new java.util.LinkedHashMap<>(LIB6);
        all.put("app/S.java", String.join("\n",
            "package app; import lib.*; import java.util.*;",
            "public class S {",
            "  public void treeAdd(TreeSet<Item> s, Item i){ s.add(i); }",
            "  public void formatter(Sink k){ new java.util.Formatter(k).format(\"x\"); }",
            "  public void printWriter(LoudWriter w){ new java.io.PrintWriter(w).println(\"x\"); }",
            "}"));
        Path dir = TestCompiler.compile(all);
        Config saved = Candor.config;
        Map<String, EffectSet> r;
        try {
            Candor.config = Config.empty();
            r = Candor.runScan(dir);
        } finally {
            Candor.config = saved;
            rm(dir.getParent());
        }
        for (String m : new String[] {"treeAdd", "formatter", "printWriter"})
            assertTrue(env(r, "app.S." + m), "single-tree control: `" + m + "` must carry Env, got " + r.get("app.S." + m));
    }

    @Test
    void aPureDependencyComparableContributesNothing() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB6, Map.of("app/S.java", String.join("\n",
            "package app; import lib.PureItem; import java.util.*;",
            "public class S { public void add(TreeSet<PureItem> s, PureItem i){ s.add(i); } }")));
        assertFalse(env(r, "app.S.add"), "a dep comparable the report shows as pure must add nothing");
    }

    @Test
    void aSameNamedNonContractMemberIsNotCharged() throws Exception {
        // The join keys on `owner.name` over ANY descriptor, so the DESCRIPTOR SHAPE is what stops a
        // coincidental same-named helper being charged: `Comparable.compareTo` takes one reference and
        // returns int, and `lib.Odd.compareTo(String,int)V` is not that. Its real compareTo IS pure, so
        // any Env here came from the helper.
        Map<String, EffectSet> r = scanChained(LIB6, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Odd; import java.util.*;",
            "public class S { public void add(TreeSet<Odd> s, Odd o){ s.add(o); } }")));
        assertFalse(env(r, "app.S.add"),
                "a same-named member that cannot BE the contract must not be charged, got " + r.get("app.S.add"));
    }

    @Test
    void anUnrelatedDependencyTypeSharingTheLeafNameIsNotCharged() throws Exception {
        // THE LEAF-NAME TRAP this vein has been burned by twice. `write`, `read` and `append` are among the
        // most common method names there are; a join that matched the NAME across owners would charge
        // `lib.Session.write`'s Fs at a PrintWriter site that never touches a Session. The owner is pinned
        // to the sink argument's declared type, and `lib.QuietWriter`'s own write is pure.
        Map<String, EffectSet> r = scanChained(LIB6, Map.of("app/S.java", String.join("\n",
            "package app; import lib.QuietWriter;",
            "public class S { public void quiet(QuietWriter w){ new java.io.PrintWriter(w).println(\"x\"); } }")));
        assertFalse(fs(r, "app.S.quiet"),
                "another dep type's same-named method must not reach this sink, got " + r.get("app.S.quiet"));
        assertFalse(env(r, "app.S.quiet"), "a pure dep sink must stay pure, got " + r.get("app.S.quiet"));
    }

    @Test
    void shadowingIsPerOverloadNotPerName() throws Exception {
        // BOTH directions of item 0 in one fixture. `lib.Sink` declares two effectful `append` overloads —
        // `append(CharSequence)` reads Env, `append(char)` touches the filesystem — and the project subclass
        // overrides ONLY `append(char)`. Shadow the whole NAME and the inherited `append(CharSequence)`'s Env
        // is dropped (an under-report); shadow nothing and the overridden `append(char)`'s Fs is charged to a
        // body the JVM never runs (a fabrication). Neither is acceptable, so the walk settles per DESCRIPTOR.
        Map<String, EffectSet> r = scanChained(LIB6, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Sink;",
            "public class S {",
            "  public static class Half extends Sink { public Appendable append(char c){ return this; } }",
            "  public void half(Half h){ new java.util.Formatter(h).format(\"x\"); }",
            "}")));
        assertTrue(env(r, "app.S.half"),
                "the NON-overridden append(CharSequence) still runs the dep body — its Env must survive, got "
                        + r.get("app.S.half"));
        assertFalse(fs(r, "app.S.half"),
                "the OVERRIDDEN append(char) is shadowed by the project body — its Fs must not be charged, got "
                        + r.get("app.S.half"));
    }

    @Test
    void anOrderingSinkOverAContainerIsNotChargedTheContainersOwnContract() throws Exception {
        // `Collections.sort(list)` orders the list's ELEMENTS, and the element type is erased inside the
        // generic — the argument's declared type is the CONTAINER. A container that happens to implement
        // Comparable would otherwise be charged for an ordering the JVM performs on something else.
        Map<String, String> lib = Map.of("lib/Roster.java", "package lib;\nimport java.util.*;\n"
            + "public class Roster extends ArrayList<String> implements Comparable<Roster> {\n"
            + "  public int compareTo(Roster o){ System.getenv(\"HOME\"); return 0; }\n}\n");
        Map<String, EffectSet> r = scanChained(lib, Map.of("app/S.java", String.join("\n",
            "package app; import lib.Roster; import java.util.*;",
            "public class S { public void sort(Roster r){ Collections.sort(r); } }")));
        assertFalse(env(r, "app.S.sort"),
                "sorting a container does not invoke the CONTAINER's compareTo, got " + r.get("app.S.sort"));
    }

    @Test
    void theContainerGuardIsADenylistSoTheNextSinkAddedStillCrosses() {
        // WHICH DIRECTION THE GUARD DEFAULTS IN, pinned — the thing no scan can show. `comparesArgZero` and
        // `isCompareToSink` spell the same partition today, so no corpus and no fixture distinguishes an
        // allowlist of the element-taking sinks from a denylist of the container-taking ones. They differ
        // only for the NEXT sink somebody adds, and an allowlist would default it to SUPPRESSING the
        // dependency join: a guard whose omissions are silent under-reports. That is exactly how this vein's
        // sibling fix shipped an allowlist of SAM names with four already missing.
        for (String[] elementSink : new String[][] {
                {"java/util/PriorityQueue", "add"}, {"java/util/concurrent/ConcurrentSkipListSet", "add"},
                {"java/util/Collections", "binarySearch"}, {"java/util/TreeSet", "headSet"}})
            assertTrue(Candor.comparesArgZero(elementSink[0], elementSink[1]),
                    elementSink[0] + "." + elementSink[1] + " is not a container-typed sink, so the guard must "
                            + "default to ASKING the dep join — an allowlist here under-reports silently");
        for (String[] containerSink : new String[][] {
                {"java/util/Collections", "sort"}, {"java/util/Arrays", "sort"},
                {"java/util/List", "sort"}, {"java/util/stream/Stream", "sorted"}})
            assertFalse(Candor.comparesArgZero(containerSink[0], containerSink[1]),
                    containerSink[0] + "." + containerSink[1] + " takes a CONTAINER — its element type is "
                            + "erased, so the argument's declared type is not the value whose contract runs");
    }

    @Test
    void theReceiverDrivenIoFormCrossesOnceTheDependencysHierarchyIsRead() throws Exception {
        // THE RESIDUAL, CLOSED — and closed the way its own pinned test said to close it. `w.write("x")`
        // drives the receiver's abstract `write(char[],int,int)` through a JDK-provided overload; it
        // resolved in one tree and not across the boundary, and the missing ingredient was never the
        // by-name join. It was `isJavaIoStreamType`: proving the receiver IS a stream needs the
        // DEPENDENCY's supertypes, and a dep's classes are not on candor's classpath.
        //
        // Relaxing the gate instead was MEASURED and refused — eleven libraries split and chained, 161
        // qualifying sites over 31 dep types, only THREE of the 31 actually java.io streams (the rest are
        // `PacketLineOut.writeString`, `RebaseState.readFile`, `ObjectWriter.writeValueAsString`, already
        // resolved by the exact-hash join), a ~90% wrong-receiver rate. The hierarchy answers the question
        // the gate was asking rather than dropping it, so the same call sites now discriminate.
        Map<String, EffectSet> r = scanChained(LIB6, Map.of("app/S.java", String.join("\n",
            "package app; import lib.*;",
            "public class S {",
            "  public void directWrite(LoudWriter w) throws Exception { w.write(\"x\"); }",
            "  public void directRead(LoudReader d) throws Exception { d.read(); }",
            "  public void quiet(QuietWriter w) throws Exception { w.write(\"x\"); }",
            "  public void ledger(Ledger l){ l.write(\"x\"); }",
            "}")));
        assertTrue(env(r, "app.S.directWrite"),
                "`w.write(String)` runs the dep's own `write(char[],int,int)` — its Env must cross, got "
                        + r.get("app.S.directWrite"));
        assertTrue(env(r, "app.S.directRead"),
                "`r.read()` runs the dep's own `read(char[],int,int)` — its Env must cross, got "
                        + r.get("app.S.directRead"));
        // THE OTHER DIRECTION, which is the whole reason the gate was kept rather than relaxed. `Ledger` is
        // NOT a stream and declares the exact overload a relaxed gate would have reached for; `l.write("x")`
        // runs its PURE `write(String)`. A hierarchy that answers "no java.io ancestor" must still refuse.
        assertFalse(env(r, "app.S.ledger"),
                "a NON-stream dep type was charged its `write(char[],int,int)` surface — the ~90% "
                        + "wrong-receiver fabrication the gate exists to prevent, got " + r.get("app.S.ledger"));
        assertFalse(env(r, "app.S.quiet"), "a pure dep stream must stay pure, got " + r.get("app.S.quiet"));
    }

    @Test
    void theDependencyHierarchyIsReadFromTheSidecarBesideTheReport() throws Exception {
        // The sidecar `ReportWriter.writeHierarchy` has written beside EVERY scan since it was added, which
        // nothing on the consumer side ever opened. This asserts the WIRING, separately from any effect it
        // enables: a dep class's supertypes must be visible to `Cha.externalSupers`, which reads candor's
        // own classpath and therefore could never see a scanned project's third-party types.
        Path base = Files.createTempDirectory("candor-hier");
        try {
            Path rep = base.resolve("dep.json");
            Files.writeString(rep, "{\"candor\":{\"version\":\"x\"},\"functions\":[]}");
            Files.writeString(base.resolve("dep.hierarchy.json"),
                    "{\"lib.LoudWriter\": [\"java.io.Writer\"], \"lib.Ledger\": [\"lib.Base\"]}");
            AnalysisState.newContext();
            Loader.loadCrossDeps(rep.toString(), "x");
            assertEquals(List.of("java/io/Writer"), Cha.depDirectSupers("lib/LoudWriter"),
                    "the sidecar beside a report named as a FILE was not read");
            assertTrue(Candor.isJavaIoStreamType("lib/LoudWriter"),
                    "a dep type extending java.io.Writer must now answer as a stream");
            assertFalse(Candor.isJavaIoStreamType("lib/Ledger"),
                    "a dep type with a non-stream ancestor must not answer as a stream");
            assertEquals(List.of(), Cha.depDirectSupers("lib/Unlisted"),
                    "a type the sidecar does not mention keeps the empty pre-sidecar answer");
            // THE SCOPE, asserted rather than described: the sidecar must NOT reach the project subtype
            // index, where a newly non-empty CHA would suppress the honest `callback:`/dispatch Unknown.
            assertEquals(List.of(), Cha.externalSupers("lib/LoudWriter"),
                    "the dep hierarchy leaked into externalSupers — that feeds buildSubtypeIndex, where a "
                            + "wider hierarchy turns a disclosed Unknown into a confident purity claim");
        } finally {
            AnalysisState.remove();
            rm(base);
        }
    }

    // ---- JVM RESOLUTION ORDER: the class chain beats an interface default, across the boundary ----------
    // `nearestDepFnsNamed` polled ONE queue seeded from "superclass and interfaces" flattened together, so
    // it interleaved the two BY DEPTH and a nearer interface `default` settled a descriptor before the
    // superclass body was reached. JLS 15.12.2.5 / 8.4.8: a concrete method inherited from a superclass
    // beats a `default` at ANY depth. `Half extends Mid implements Trace`, `Mid extends Root`: the walk
    // settled `append(CharSequence)` on Trace at depth 1 and skipped Root's body at depth 2 as already
    // decided. The JVM runs Root's. Both halves of the honesty invariant failed at once — the real Fs was
    // dropped (a silent under-report) and Trace's Env was charged to a body that never runs (a fabrication).

    private static final Map<String, String> LIB7 = Map.of(
        // the body the JVM actually runs — Fs
        "lib/Root.java", "package lib;\npublic class Root implements Appendable {\n"
            + "  public Appendable append(CharSequence c){ new java.io.File(\"/tmp/candor-x\").exists(); return this; }\n"
            + "  public Appendable append(char c){ return this; }\n"
            + "  public Appendable append(CharSequence c, int s, int e){ return this; }\n}\n",
        "lib/Mid.java", "package lib;\npublic class Mid extends Root {}\n",
        // NEARER in the depth-ordered walk, and a different effect so either error is visible — Env
        "lib/Trace.java", "package lib;\npublic interface Trace {\n"
            + "  default Appendable append(CharSequence c){ System.getenv(\"HOME\"); return null; }\n}\n",
        // the OTHER direction: a genuine default with NO competing class declaration anywhere
        "lib/LoudTrace.java", "package lib;\npublic interface LoudTrace extends Appendable {\n"
            + "  default Appendable append(CharSequence c){ System.getenv(\"HOME\"); return this; }\n}\n",
        "lib/IfaceOnly.java", "package lib;\npublic class IfaceOnly implements LoudTrace {\n"
            + "  public Appendable append(char c){ return this; }\n"
            + "  public Appendable append(CharSequence c, int s, int e){ return this; }\n}\n");

    @Test
    void aSuperclassBodyBeatsANearerInterfaceDefaultAcrossTheBoundary() throws Exception {
        Map<String, EffectSet> r = scanChained(LIB7, Map.of("app/S.java", String.join("\n",
            "package app; import lib.*;",
            "public class S {",
            "  public static class Half extends Mid implements Trace {}",
            "  public void half(Half h){ new java.util.Formatter(h).format(\"x\"); }",
            "}")));
        assertTrue(fs(r, "app.S.half"),
                "Half inherits Root.append(CharSequence) — a CLASS body beats Trace's default at any depth, "
                        + "and that is the body the JVM runs, got " + r.get("app.S.half"));
        assertFalse(env(r, "app.S.half"),
                "Trace's default is SHADOWED by the inherited class body — charging its Env is a "
                        + "fabrication on a method that never runs, got " + r.get("app.S.half"));
    }

    @Test
    void aDependencyInterfaceDefaultWithNoCompetingClassStillResolves() throws Exception {
        // Item 0's second fixture, and it was written first. "The class wins" must not be implemented by
        // dropping interfaces from the walk: with no class declaration anywhere in the chain, the interface
        // `default` IS the body the JVM runs and its effect must still cross.
        Map<String, EffectSet> r = scanChained(LIB7, Map.of("app/S.java", String.join("\n",
            "package app; import lib.*;",
            "public class S {",
            "  public void direct(IfaceOnly k){ new java.util.Formatter(k).format(\"x\"); }",
            "  public static class Sub extends IfaceOnly {}",
            "  public void viaSubclass(Sub s){ new java.util.Formatter(s).format(\"x\"); }",
            "}")));
        assertTrue(env(r, "app.S.direct"),
                "a dep interface DEFAULT with no competing class declaration must still be charged, got "
                        + r.get("app.S.direct"));
        assertTrue(env(r, "app.S.viaSubclass"),
                "the same default, reached through a project subclass that declares nothing, must still be "
                        + "charged — the interface phase must run after the class phase, not instead of it, got "
                        + r.get("app.S.viaSubclass"));
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

    // ---- the entry collision: two reports, one key -----------------------------------------------------

    /** Scan `app` with lib's report chained TWICE — once as produced (trusted) and once with the producing
     *  version rewritten so §2.1 refuses it. Both land in one deps DIRECTORY, so both are walked and both
     *  resolve to the same {@code crossDeps} key: the collision, in the shape a real dep directory produces
     *  it. {@code order} decides which filename sorts first, because the defect being pinned was
     *  order-dependent and a fixture that fixes the order cannot see that. */
    private static Map<String, EffectSet> scanChainedTwice(Map<String, String> lib, Map<String, String> app,
            boolean staleFirst) throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path deps = base.resolve("deps");
            Files.createDirectories(deps);
            Path fresh = deps.resolve((staleFirst ? "b-" : "a-") + "fresh.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), fresh.toString(), null);
            // The SAME report, with only the producing build rewritten — so the two entries are identical
            // but for the trust level, and anything that changes is the collision rule and nothing else.
            String staleText = Files.readString(fresh)
                    .replaceAll("\"version\"\\s*:\\s*\"[^\"]*\"", "\"version\": \"candor-0.0.1-ancient\"");
            Files.writeString(deps.resolve((staleFirst ? "a-" : "b-") + "stale.json"), staleText);
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + deps + "\n");
            Candor.config = Config.forTarget(appDir);
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** A TRUSTED REPORT'S EFFECT SURVIVES A STALE ONE BESIDE IT — the gate flip that
     *  candor-spec/ENTRY-COLLISION-DECISION.md measured, in both file orders.
     *
     *  <p>The old rule was {@code if (!de.effects.isEmpty()) crossDeps.put(h, de)} — last non-empty wins.
     *  The guard was read for a long time as a safety property, on the grounds that a pure claim
     *  ({@code []}) can never erase an effectful one. <b>{@code Unknown} is non-empty.</b> §2.1 downgrades
     *  every entry of an untrusted report to exactly {@code {Unknown}}, which passes the guard and
     *  OVERWRITES the trusted report's concrete effect — so the consumer saw {@code ['Unknown']}, the
     *  {@code Fs} was gone, and {@code deny Fs} went exit 1 to exit 0. A report the engine explicitly
     *  refused to trust erased a fact from one it does.
     *
     *  <p>BOTH ORDERS ARE ASSERTED because the defect was order-dependent: the same two reports gave
     *  {@code ['Net']} one way round and {@code ['Exec']} the other. Rename a file, change the effect. A
     *  fixture that pins one order would pass over half the bug. */
    @org.junit.jupiter.api.Test
    void aStaleReportBesideATrustedOneCannotEraseItsEffect() throws Exception {
        Map<String, String> lib = Map.of("lib/Entry.java", String.join("\n",
            "package lib;",
            "public class Entry { public static void touch() throws Exception {",
            "  java.nio.file.Files.readString(java.nio.file.Path.of(\"/etc/hosts\")); } }"));
        Map<String, String> app = Map.of("app/S.java", String.join("\n",
            "package app; import lib.Entry;",
            "public class S { public void run() throws Exception { Entry.touch(); } }"));
        for (boolean staleFirst : new boolean[] { false, true }) {
            Map<String, EffectSet> r = scanChainedTwice(lib, app, staleFirst);
            java.util.List<String> got = r.getOrDefault("app.S.run", EffectSet.empty()).toNames();
            String where = " (stale report sorting " + (staleFirst ? "FIRST" : "SECOND") + "), got " + got;
            assertTrue(got.contains("Fs"),
                    "the TRUSTED report's Fs was erased by a stale report beside it — this is the `deny Fs` "
                            + "exit 1 -> 0 flip, and the union exists to stop it" + where);
            assertTrue(got.contains("Unknown"),
                    "the stale report's §2.1 downgrade must ALSO survive: the union adds, it does not pick, "
                            + "and dropping the Unknown would hide that one of the two reports is not "
                            + "believable" + where);
        }
    }

    // ── ⟨0.29⟩ AN EFFECT-LESS DEP ENTRY'S `incomplete` MUST REACH ITS CALLER ────────────────────────────

    /** {@link #scanChained}, rewriting the dep REPORT (not its sidecar) between the two scans — the only
     *  way to pose a dep entry shape whose natural producers all attach an effect alongside the marker. */
    private static Map<String, EffectSet> scanChainedRewritingReport(Map<String, String> lib,
            Map<String, String> app, java.util.function.UnaryOperator<String> rewrite) throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path depReport = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            Files.writeString(depReport, rewrite.apply(Files.readString(depReport)));
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** Blank every entry's effects, optionally leaving `incomplete:["Db"]` behind. JSON-AWARE on purpose:
     *  a string-replace fixture here silently matched nothing when the writer's indentation differed, and
     *  a rewrite that does not apply makes the row pass for the wrong reason. */
    private static String reshape(String json, boolean keepMarker) {
        com.google.gson.JsonObject o = new Gson().fromJson(json, com.google.gson.JsonObject.class);
        for (com.google.gson.JsonElement e : o.getAsJsonArray("functions")) {
            com.google.gson.JsonObject f = e.getAsJsonObject();
            f.add("inferred", new com.google.gson.JsonArray());
            f.add("direct", new com.google.gson.JsonArray());
            if (keepMarker) {
                com.google.gson.JsonArray inc = new com.google.gson.JsonArray();
                inc.add("Db");
                f.add("incomplete", inc);
            }
        }
        return new Gson().toJson(o);
    }

    /**
     * A DEPENDENCY'S DISCLOSED UNCERTAINTY MUST REACH ITS CALLERS EVEN WHEN IT CARRIES NO EFFECT.
     *
     * <p>SPEC §2 makes this a MUST: the chained join applies <b>every</b> surface the ordinary join
     * applies — {@code hosts}/{@code cmds}/{@code paths}/{@code tables}/{@code invisible}/{@code
     * incomplete} — because <i>"a join that carries the effect and drops `incomplete` lets a benign
     * literal in the consumer certify what the dependency declared uncertifiable"</i>.
     *
     * <p><b>WHY THE SHAPE HAD TO BE INJECTED.</b> Every natural producer attaches an EFFECT beside the
     * marker (a runtime-SQL call yields {@code Db} AND {@code incomplete:[Db]}), and such an entry is
     * admitted by the effects arm, so it cannot tell a fixed loader from a broken one. This engine's own
     * report writer began emitting the effect-less shape at 0.29.1 (see
     * {@link IncompleteOnlyReachesTheReportTest}), so our own reports contain entries the chaining path
     * could not carry — the defect was measured on its own output, not hypothesised.
     *
     * <p><b>THE CONTROL IS THAT NO MARKER IS INVENTED.</b> The fix widens {@code Loader}'s admission gate
     * from {@code !effects.isEmpty()} to also admit an entry carrying {@code incomplete} — so the failure
     * mode to guard is a join that hedges everything it now admits, which would drown every consumer of
     * every chained report. The second arm poses an entry with an EFFECT and NO marker and requires the
     * caller to come back unhedged.
     *
     * <p><b>WHAT IS DELIBERATELY NOT ASSERTED, because it was MEASURED not to manifest.</b> The gate's own
     * comment records the hazard that kept it narrow: admitting EMPTY entries "would make a key that is
     * currently ABSENT resolve as present-and-pure, which is a new purity claim". That was checked here
     * both ways — with the gate shipped, with the gate opened to everything — and the caller reads the
     * same either way, because the dep report's PACKAGE registration already covers the call and the
     * caller is pure before any entry is admitted. An assertion on it would be a control with no teeth,
     * and this suite has measured enough of those to prefer saying so to shipping one. The narrow
     * condition still holds the line: only an entry carrying a marker is newly admitted, and a marker is
     * a hedge, never a purity claim.
     */
    @Test
    void anEffectLessDepEntrysIncompleteReachesTheCaller() throws Exception {
        // The lib function is EFFECTFUL so the writer emits a real entry, with the real `hash` the join
        // keys on; the rewrite below then strips the effect and leaves only the marker. Posing it as a
        // pure function instead does not work — java omits effect-less functions from the report
        // entirely, so there would be no entry to rewrite and the row would pass for the wrong reason.
        Map<String, String> lib = Map.of("lib/L.java", String.join("\n",
            "package lib;",
            "public class L {",
            "  public static byte[] f() throws Exception {",
            "    return java.nio.file.Files.readAllBytes(java.nio.file.Path.of(\"/tmp/x\"));",
            "  }",
            "}"));
        Map<String, String> app = Map.of("app/A.java", String.join("\n",
            "package app;",
            "public class A { public static byte[] run() throws Exception { return lib.L.f(); } }"));

        // (1) THE DEFECT: strip the effect, keep the marker — no effects, `incomplete:["Db"]`.
        scanChainedRewritingReport(lib, app, j -> reshape(j, true));
        assertTrue(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.A.run", new TreeSet<>())
                        .contains("Db"),
            "an effect-less dep entry's `incomplete` was DROPPED before it could propagate — the caller "
            + "reads certainly-nothing about a callee that declared it could not be fully seen, which is "
            + "the propagation invariant SPEC §2 states as a MUST. Got: "
            + AnalysisState.ctx().surfaceIncomplete.get("app.A.run"));

        // (2) THE OVER-CHARGE CONTROL: an entry with an EFFECT and NO marker must join as it always did,
        // and must NOT acquire a hedge. A fix that hedged everything it newly admits would pass the arm
        // above and make every consumer of every chained report read uncertain.
        Map<String, EffectSet> plain = scanChainedRewritingReport(lib, app, j -> j);
        assertTrue(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.A.run", new TreeSet<>()).isEmpty(),
            "the caller of a dep entry that declared NO uncertainty came back hedged — the join is "
            + "inventing a marker the dependency never published: "
            + AnalysisState.ctx().surfaceIncomplete.get("app.A.run"));
        assertTrue(plain.getOrDefault("app.A.run", EffectSet.empty()).toNames().contains("Fs"),
            "fixture precondition: the ordinary chained join must still carry the dep's Fs, or the arm "
            + "above passes because nothing joined at all. Got: "
            + plain.getOrDefault("app.A.run", EffectSet.empty()).toNames());
    }
}
