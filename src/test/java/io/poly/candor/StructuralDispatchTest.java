package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * Teeth for the four STRUCTURAL soundness fixes (round-5 follow-up): named task-type rooting at NEW,
 * CHA through an EXTERNAL superclass, opaque-task executor hand-off → Unknown, and framework entry-point
 * rooting. Each compiles a real fixture (javac emits the real bytecode shapes — bridges, indy handles,
 * external superchains) and drives a full {@link Candor#runScan}. The no-fabrication controls (a plain
 * {@code new ArrayList().add()}, a pure lambda hand-off, a non-task class) are asserted pure.
 */
class StructuralDispatchTest {

    /** Compile the given {name→source} set and scan the output dir; returns the inferred-effects map. */
    private static Map<String, TreeSet<String>> compileAndScan(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-struct");
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

    private static TreeSet<String> eff(Map<String, TreeSet<String>> r, String fn) {
        return r.getOrDefault(fn, new TreeSet<>());
    }

    /** #1 — a NAMED Runnable/Callable/Thread-subclass handed to an executor / Thread is rooted at its NEW
     *  site (its run()/call() reaches the scheduler); a non-task class is NOT attributed (no fabrication). */
    @Test
    void namedTaskTypeIsAttributedAtNew() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("A.java", String.join("\n",
            "import java.util.concurrent.*;",
            "class R implements Runnable { public void run(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} } }",
            "class MyThread extends Thread { public void run(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} } }",
            "class C implements Callable<String> { public String call(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} return \"\"; } }",
            "class Plain { void run(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} } }",
            "public class A {",
            "  void namedThread(){ new Thread(new R()).start(); }",
            "  void execSubmit(ExecutorService es){ es.submit(new R()); }",
            "  void subclass(){ new MyThread().start(); }",
            "  void callable(ExecutorService es){ es.submit(new C()); }",
            "  void plain(){ new Plain(); }",
            "}")));
        assertTrue(eff(r, "A.namedThread").contains("Net"), "new Thread(new R()).start() must reach R.run");
        assertTrue(eff(r, "A.execSubmit").contains("Net"), "es.submit(new R()) must reach R.run");
        assertTrue(eff(r, "A.subclass").contains("Net"), "new MyThread().start() must reach MyThread.run");
        assertTrue(eff(r, "A.callable").contains("Net"), "es.submit(new C()) must reach C.call");
        // a fresh new-task hand-off must NOT also pick up the opaque-task Unknown (it's pinned)
        assertEquals(new TreeSet<>(List.of("Net")), eff(r, "A.execSubmit"), "pinned new R() must be Net only, no Unknown");
        // Plain is not a task type → its run() must NOT be attributed to the constructor (no fabrication).
        // (runScan keeps pure methods with an EMPTY set; the JSON report is what omits them.)
        assertTrue(eff(r, "A.plain").isEmpty(), "constructing a non-task class must stay pure, got " + r.get("A.plain"));
    }

    /** #2 — a project class extending an EXTERNAL type (ArrayList) and overriding a method declared further
     *  up the external chain (List.add) is reached via a base-typed (List) receiver; a plain
     *  new ArrayList().add() (pinned to the external type) must NOT pick up the override (no fabrication). */
    @Test
    void chaThroughExternalSuperclass() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("Main.java", String.join("\n",
            "import java.util.*;",
            "class LoudList extends ArrayList<String> {",
            "  public boolean add(String s){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} return super.add(s); } }",
            "public class Main {",
            "  void run(List<String> l){ l.add(\"x\"); }",
            "  void plainList(){ new ArrayList<String>().add(\"y\"); }",
            "}")));
        TreeSet<String> run = eff(r, "Main.run");
        assertTrue(run.contains("Net") || run.contains("Unknown"),
                "unpinned List.add must reach the project override (Net) or Unknown, got " + run);
        assertTrue(eff(r, "Main.plainList").isEmpty(),
                "pinned new ArrayList().add() must stay pure (no sibling-override fabrication), got " + r.get("Main.plainList"));
    }

    /** #3 — an OPAQUE Runnable/Callable task (field/param) handed to an executor reads Unknown (its body is
     *  unknown); an inline pure lambda hand-off must NOT (its body is edged at the indy). */
    @Test
    void opaqueTaskHandoffReadsUnknown() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("B.java", String.join("\n",
            "import java.util.concurrent.*;",
            "public class B {",
            "  Runnable handler;",
            "  void fieldSubmit(ExecutorService es){ es.submit(handler); }",
            "  void paramSubmit(ExecutorService es, Runnable rr){ es.submit(rr); }",
            "  void lambdaSubmit(ExecutorService es){ es.submit(() -> {}); }",
            "}")));
        assertTrue(eff(r, "B.fieldSubmit").contains("Unknown"), "es.submit(field) must read Unknown");
        assertTrue(eff(r, "B.paramSubmit").contains("Unknown"), "es.submit(param) must read Unknown");
        assertTrue(eff(r, "B.lambdaSubmit").isEmpty(), "es.submit(pure lambda) must stay pure, got " + r.get("B.lambdaSubmit"));
    }

    /** #3b — the SAME opaque-task hand-off must read Unknown for CompletableFuture `*Async` stages and
     *  java.util.Timer.schedule (not only ExecutorService.submit). An opaque field/param Runnable/Supplier/
     *  TimerTask whose body is unknown → Unknown; an inline lambda or `new R()` with a real effect must keep
     *  the REAL effect (edged at the indy/NEW site), NOT be downgraded to Unknown; a pure inline lambda stays
     *  pure (no fabrication). Mirrors B.fieldSubmit/B.lambdaSubmit for the CF/Timer owners. */
    @Test
    void opaqueTaskHandoffToCompletableFutureAndTimerReadsUnknown() throws Exception {
        Map<String, TreeSet<String>> r = compileAndScan(Map.of("CFT.java", String.join("\n",
            "import java.util.concurrent.*;",
            "import java.util.function.*;",
            "import java.util.*;",
            "class MyR implements Runnable {",
            "  public void run(){ try { new java.io.FileInputStream(\"y\"); } catch(Exception e){} } }",
            "public class CFT {",
            "  Runnable task; Supplier<String> sup; TimerTask tt;",
            // executor baseline (must stay Unknown — unchanged)
            "  void viaExecutor(ExecutorService es){ es.submit(task); }",
            // the bug: opaque task → CF.runAsync / supplyAsync, and opaque TimerTask → timer.schedule
            "  void viaCF(){ CompletableFuture.runAsync(task); }",
            "  void viaSupply(){ CompletableFuture.supplyAsync(sup); }",
            "  void viaTimer(Timer timer){ timer.schedule(tt, 0L); }",
            // no-regression: inline lambda / new R() with a real Fs effect keep Fs (not Unknown)
            "  void inlineLambda(){ CompletableFuture.runAsync(() -> { try { new java.io.FileInputStream(\"x\"); } catch(Exception e){} }); }",
            "  void newRunnable(){ CompletableFuture.runAsync(new MyR()); }",
            // no-fabrication: a pure inline lambda to runAsync stays pure
            "  void pureLambda(){ CompletableFuture.runAsync(() -> {}); }",
            "}")));
        assertTrue(eff(r, "CFT.viaExecutor").contains("Unknown"), "es.submit(field) must read Unknown");
        assertTrue(eff(r, "CFT.viaCF").contains("Unknown"), "CompletableFuture.runAsync(opaque) must read Unknown");
        assertTrue(eff(r, "CFT.viaSupply").contains("Unknown"), "CompletableFuture.supplyAsync(opaque) must read Unknown");
        assertTrue(eff(r, "CFT.viaTimer").contains("Unknown"), "Timer.schedule(opaque TimerTask) must read Unknown");
        // no-regression: the inline-lambda / new-task body's REAL effect is preserved, NOT downgraded.
        assertTrue(eff(r, "CFT.inlineLambda").contains("Fs"), "runAsync(inline effect lambda) must keep Fs, got " + r.get("CFT.inlineLambda"));
        assertTrue(!eff(r, "CFT.inlineLambda").contains("Unknown"), "runAsync(inline lambda) must NOT be downgraded to Unknown, got " + r.get("CFT.inlineLambda"));
        assertTrue(eff(r, "CFT.newRunnable").contains("Fs"), "runAsync(new effect Runnable) must keep Fs, got " + r.get("CFT.newRunnable"));
        assertTrue(!eff(r, "CFT.newRunnable").contains("Unknown"), "runAsync(new R()) must NOT be downgraded to Unknown, got " + r.get("CFT.newRunnable"));
        // no-fabrication: a genuinely pure inline lambda stays pure.
        assertTrue(eff(r, "CFT.pureLambda").isEmpty(), "runAsync(pure lambda) must stay pure, got " + r.get("CFT.pureLambda"));
    }

    /** #4 — framework-invoked methods with no in-project call site are rooted as entry points (so a
     *  reachability/blast-radius walk surfaces them): Spring @Async, JAX-RS @GET, AspectJ @Around,
     *  ConstraintValidator.isValid, and TimerTask.run (the last via external-supertype resolution). */
    @Test
    void frameworkEntryPointsAreRooted() throws Exception {
        Map<String, String> src = Map.of(
            "org/springframework/scheduling/annotation/Async.java",
            "package org.springframework.scheduling.annotation; import java.lang.annotation.*;\n"
                + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Async {}",
            "jakarta/ws/rs/GET.java",
            "package jakarta.ws.rs; import java.lang.annotation.*;\n"
                + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface GET {}",
            "org/aspectj/lang/annotation/Around.java",
            "package org.aspectj.lang.annotation; import java.lang.annotation.*;\n"
                + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Around { String value() default \"\"; }",
            "jakarta/validation/ConstraintValidator.java",
            "package jakarta.validation; public interface ConstraintValidator<A,T> { boolean isValid(T v, Object ctx); }",
            "App.java", String.join("\n",
                "import org.springframework.scheduling.annotation.Async;",
                "import jakarta.ws.rs.GET;",
                "import org.aspectj.lang.annotation.Around;",
                "import jakarta.validation.ConstraintValidator;",
                "public class App {",
                "  @Async public void asyncTask(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} }",
                "  @GET public void restGet(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} }",
                "  @Around(\"x\") public void advice(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} }",
                "}"),
            "MyTask.java",
                "public class MyTask extends java.util.TimerTask {"
                + " public void run(){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} } }",
            "V.java", String.join("\n",
                "import jakarta.validation.ConstraintValidator;",
                "public class V implements ConstraintValidator<Object,String> {",
                "  public boolean isValid(String v, Object ctx){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} return true; } }"));
        compileAndScan(src);  // populates Candor.entryPoints + inferred as a side effect
        for (String fn : List.of("App.asyncTask", "App.restGet", "App.advice", "MyTask.run", "V.isValid"))
            assertTrue(Candor.entryPoints.contains(fn), fn + " must be rooted as a framework entry point");
    }
}
