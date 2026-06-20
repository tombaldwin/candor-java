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
 * Teeth for the round-6 Java-sweep fixes: literal-host fabrication (#1), overload simple-name collision
 * fabrication (#2), Spring reactive/store repo Db (#5), meta/composed-annotation rooting (#6), ForkJoinTask
 * rooting (#7), and corrupt-dep-report → Unknown (#8). Each compiles a real fixture and drives a full scan;
 * the two fabrications assert the pure path stays pure.
 */
class Round6FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-r6");
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
        return out;
    }

    private static void rm(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** #1 — the Net HOST literal must come from the call's OWN argument, never a prior statement's string.
     *  `new Socket(runtimeHost, 443)` preceded by `String tag = "internal.metrics.svc"` must capture NO host
     *  (defeating the AS-EFF-008 allowlist was the bug); a genuine literal host is still captured. */
    @Test
    void literalHostIsNotStolenFromAPriorStatement() throws Exception {
        Path cls = compile(Map.of("F.java", String.join("\n",
            "import java.net.Socket;",
            "public class F {",
            "  void exfil(String h) throws Exception { String tag=\"internal.metrics.svc\"; new Socket(h, 443).close(); }",
            "  void realLit() throws Exception { new Socket(\"api.stripe.com\", 443).close(); }",
            "}")));
        try {
            Candor.runScan(cls);
            TreeSet<String> exfilHosts = AnalysisState.hostsDirect.getOrDefault("F.exfil", new TreeSet<>());
            assertTrue(exfilHosts.isEmpty(), "a runtime host must capture NO literal, got " + exfilHosts);
            assertTrue(AnalysisState.hostsDirect.getOrDefault("F.realLit", new TreeSet<>()).contains("api.stripe.com:443"),
                    "a genuine literal host must still be captured");
        } finally { rm(cls.getParent()); }
    }

    /** #2 — overloads whose param types share a SIMPLE name across packages (`f(a.User)` vs `f(b.User)`)
     *  must NOT collapse to one node and union effects; the pure overload's caller stays pure. */
    @Test
    void overloadSimpleNameCollisionDoesNotMergeEffects() throws Exception {
        Path cls = compile(Map.of(
            "a/User.java", "package a; public class User {}",
            "b/User.java", "package b; public class User {}",
            "G.java", String.join("\n",
                "public class G {",
                "  static void f(a.User u) { try { new java.io.FileOutputStream(\"/tmp/eff\").close(); } catch(Exception e){} }",
                "  static int  f(b.User u) { return 0; }",
                "  static void callEff()  { f(new a.User()); }",
                "  static void callPure() { f(new b.User()); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "G.callEff").toNames().contains("Fs"), "the effectful overload's caller must read Fs");
            assertTrue(eff(r, "G.callPure").isEmpty(),
                    "the pure overload's caller must stay pure (no simple-name-collision fabrication), got " + r.get("G.callPure"));
        } finally { rm(cls.getParent()); }
    }

    /** #5 — a reactive/store Spring Data repo's inherited CRUD (ReactiveCrudRepository.findAll) reads Db
     *  (REPO_MARKERS was JPA/JDBC-centric; isSpringDataRepoBase catches the org.springframework.data.* bases). */
    @Test
    void reactiveSpringDataRepoIsDb() throws Exception {
        Path cls = compile(Map.of(
            "org/springframework/data/repository/reactive/ReactiveCrudRepository.java",
            "package org.springframework.data.repository.reactive;\n"
                + "public interface ReactiveCrudRepository<T,ID> { Object findAll(); Object save(T e); }",
            "app/App.java", String.join("\n",
                "package app;",
                "import org.springframework.data.repository.reactive.ReactiveCrudRepository;",
                "interface DocRepo extends ReactiveCrudRepository<String,Long> {}",
                "public class App { final DocRepo repo; App(DocRepo r){this.repo=r;}",
                "  public Object loadAll(){ return repo.findAll(); } }")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.App.loadAll").toNames().contains("Db"), "reactive repo inherited findAll must be Db, got " + r.get("app.App.loadAll"));
        } finally { rm(cls.getParent()); }
    }

    /** #6 — a method carrying a COMPOSED annotation (`@ApiEndpoint` meta-annotated `@GetMapping`) is rooted
     *  as a framework entry point; an UNRELATED `@com.myapp.GetMapping` whose meta-chain never reaches a
     *  real marker is NOT rooted (no fabrication). */
    @Test
    void composedAnnotationIsRootedDecoyIsNot() throws Exception {
        Path cls = compile(Map.of(
            "org/springframework/web/bind/annotation/GetMapping.java",
            "package org.springframework.web.bind.annotation; import java.lang.annotation.*;\n"
                + "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.METHOD,ElementType.ANNOTATION_TYPE}) public @interface GetMapping {}",
            "app/ApiEndpoint.java",
            "package app; import java.lang.annotation.*; import org.springframework.web.bind.annotation.GetMapping;\n"
                + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) @GetMapping public @interface ApiEndpoint {}",
            "com/myapp/GetMapping.java",
            "package com.myapp; import java.lang.annotation.*;\n"
                + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface GetMapping {}",
            "app/App.java", String.join("\n",
                "package app;",
                "public class App {",
                "  @ApiEndpoint public void composed(){ try { new java.net.Socket(\"h\",80).close(); } catch(Exception e){} }",
                "  @com.myapp.GetMapping public void decoy(){ try { new java.net.Socket(\"h\",80).close(); } catch(Exception e){} }",
                "}")));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.entryPoints.contains("app.App.composed"), "composed @ApiEndpoint→@GetMapping must root");
            assertFalse(AnalysisState.entryPoints.contains("app.App.decoy"), "unrelated @com.myapp.GetMapping must NOT root (no fabrication)");
        } finally { rm(cls.getParent()); }
    }

    /** #7 — a RecursiveTask handed to a ForkJoinPool: compute() is rooted and the scheduling site reaches
     *  its effect. */
    @Test
    void forkJoinTaskComputeIsRootedAndReached() throws Exception {
        Path cls = compile(Map.of("F.java", String.join("\n",
            "import java.util.concurrent.*;",
            "public class F {",
            "  static void deepNet(){ try { new java.net.Socket(\"h\",80).close(); } catch(Exception e){} }",
            "  static class RT extends RecursiveTask<Integer> { protected Integer compute(){ deepNet(); return 1; } }",
            "  int viaInvoke(ForkJoinPool p){ return p.invoke(new RT()); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "F.viaInvoke").toNames().contains("Net"), "pool.invoke(new RT()) must reach compute()'s Net, got " + r.get("F.viaInvoke"));
            assertTrue(AnalysisState.entryPoints.contains("F$RT.compute"), "RecursiveTask.compute must be rooted");
        } finally { rm(cls.getParent()); }
    }

    /** #8 — a CORRUPT same-version dep report (JSON-null version here) must downgrade its effects to Unknown,
     *  never silently drop the whole file (which made every caller read PURE, defeating §2.1). */
    @Test
    void corruptDepReportDowngradesToUnknownNotPure() throws Exception {
        Path dir = Files.createTempDirectory("candor-deps");
        try {
            Files.writeString(dir.resolve("lib.json"),
                "{\"candor\":{\"version\":null,\"spec\":\"0.5\"},\"functions\":"
                + "[{\"fn\":\"dep.Lib.phone\",\"hash\":\"dep/Lib.phone()V\",\"inferred\":[\"Net\"]}]}");
            Candor.resetState();
            Loader.loadCrossDeps(dir.toString(), "any-own-version");
            AnalysisState.DepFn de = AnalysisState.crossDeps.get("dep/Lib.phone()V");
            assertTrue(de != null && de.effects.contains(Effect.UNKNOWN),
                    "a null-version dep entry must inherit Unknown (not be dropped to pure), got " + (de == null ? "null" : de.effects));
        } finally { rm(dir); }
    }
}
