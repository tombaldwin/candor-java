package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
    private static Map<String, EffectSet> compileAndScan(Map<String, String> sources) throws Exception {
        Path out = TestCompiler.compile(sources);
        try {
            return Candor.runScan(out);
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** #1 — a NAMED Runnable/Callable/Thread-subclass handed to an executor / Thread is rooted at its NEW
     *  site (its run()/call() reaches the scheduler); a non-task class is NOT attributed (no fabrication). */
    @Test
    void namedTaskTypeIsAttributedAtNew() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("A.java", String.join("\n",
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
        assertTrue(eff(r, "A.namedThread").toNames().contains("Net"), "new Thread(new R()).start() must reach R.run");
        assertTrue(eff(r, "A.execSubmit").toNames().contains("Net"), "es.submit(new R()) must reach R.run");
        assertTrue(eff(r, "A.subclass").toNames().contains("Net"), "new MyThread().start() must reach MyThread.run");
        assertTrue(eff(r, "A.callable").toNames().contains("Net"), "es.submit(new C()) must reach C.call");
        // a fresh new-task hand-off must NOT also pick up the opaque-task Unknown (it's pinned)
        assertEquals(EffectSet.of(Effect.NET), eff(r, "A.execSubmit"), "pinned new R() must be Net only, no Unknown");
        // Plain is not a task type → its run() must NOT be attributed to the constructor (no fabrication).
        // (runScan keeps pure methods with an EMPTY set; the JSON report is what omits them.)
        assertTrue(eff(r, "A.plain").isEmpty(), "constructing a non-task class must stay pure, got " + r.get("A.plain"));
    }

    /** #2 — a project class extending an EXTERNAL type (ArrayList) and overriding a method declared further
     *  up the external chain (List.add) is reached via a base-typed (List) receiver; a plain
     *  new ArrayList().add() (pinned to the external type) must NOT pick up the override (no fabrication). */
    @Test
    void chaThroughExternalSuperclass() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("Main.java", String.join("\n",
            "import java.util.*;",
            "class LoudList extends ArrayList<String> {",
            "  public boolean add(String s){ try { new java.net.Socket(\"h\",80);}catch(Exception e){} return super.add(s); } }",
            "public class Main {",
            "  void run(List<String> l){ l.add(\"x\"); }",
            "  void plainList(){ new ArrayList<String>().add(\"y\"); }",
            "}")));
        EffectSet run = eff(r, "Main.run");
        assertTrue(run.toNames().contains("Net") || run.toNames().contains("Unknown"),
                "unpinned List.add must reach the project override (Net) or Unknown, got " + run);
        assertTrue(eff(r, "Main.plainList").isEmpty(),
                "pinned new ArrayList().add() must stay pure (no sibling-override fabrication), got " + r.get("Main.plainList"));
    }

    /** #2c — a java.io FILTER-stream close/flush (reached e.g. via `super.close()` from a filter subclass)
     *  delegates to a wrapped stream of unknown concrete type → its I/O is undetermined → Unknown (never
     *  silent-pure). REGRESSION: found by the runtime oracle on Apache commons-compress
     *  (CompressFilterOutputStream.close / ZipArchiveOutputStream.destroy → super.close()). */
    @Test
    void filterStreamCloseDelegatesToUnknownWrappedSink() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("Main.java", String.join("\n",
            "import java.io.*;",
            "class Wrap extends FilterOutputStream {",
            "  Wrap(OutputStream o){ super(o); }",
            "  @Override public void close() throws IOException { super.close(); }",   // super.close() → Unknown
            "}",
            "public class Main {}")));
        assertTrue(eff(r, "Wrap.close").toNames().contains("Unknown"),
                "a filter-stream super.close() (unknown wrapped sink) must read Unknown, got " + r.get("Wrap.close"));
    }

    /** VALUE-PROVENANCE Phase 1: a stream-consuming utility (IOUtils.read) reading a stream NOT opened in
     *  this method (a param or field — newType==null) discloses Unknown (the honest external-stream answer);
     *  a stream opened IN THIS METHOD (`new FileInputStream` — newType set) stays pure-relative and gets NO
     *  redundant Unknown (the precision the source/sink stance is meant to preserve). IOUtils is compiled but
     *  NOT scanned (external, matching reality). Found by the runtime oracle on commons-compress readFully. */
    @Test
    void externalStreamReadViaUtilityIsUnknownButInScopeOpenStaysPure() throws Exception {
        Path app = TestCompiler.compileApp(
            Map.of("org/apache/commons/io/IOUtils.java", String.join("\n",
                "package org.apache.commons.io;",
                "import java.io.InputStream;",
                "public class IOUtils {",
                "  public static int read(InputStream in, byte[] b, int off, int len) { return 0; }",
                "}")),
            Map.of("A.java", String.join("\n",
                "import java.io.*;",
                "import org.apache.commons.io.IOUtils;",
                "public class A {",
                "  InputStream in;",
                "  void readField(byte[] b) throws IOException { IOUtils.read(this.in, b, 0, b.length); }",
                "  void readParam(InputStream p, byte[] b) throws IOException { IOUtils.read(p, b, 0, b.length); }",
                "  void readFresh(byte[] b) throws IOException { InputStream s = new FileInputStream(\"x\"); IOUtils.read(s, b, 0, b.length); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "A.readField").toNames().contains("Unknown"),
                    "external FIELD stream read must be Unknown, got " + r.get("A.readField"));
            assertTrue(eff(r, "A.readParam").toNames().contains("Unknown"),
                    "external PARAM stream read must be Unknown, got " + r.get("A.readParam"));
            assertTrue(eff(r, "A.readFresh").toNames().contains("Fs"),
                    "an in-scope open must still be Fs, got " + r.get("A.readFresh"));
            assertFalse(eff(r, "A.readFresh").toNames().contains("Unknown"),
                    "an in-scope open must NOT get a redundant Unknown (source/sink precision), got " + r.get("A.readFresh"));
        } finally {
            TestCompiler.rm(app.getParent());
        }
    }

    /** #2a-bis — the READ/WRITE half of the wrapped-sink delegate: a BufferedOutputStream/FilterInputStream
     *  subclass whose write/read calls `super.write`/`super.read` delegates the actual syscall to a wrapped
     *  stream of unknown concrete type → Unknown (never silent-pure). Found by the runtime oracle on
     *  commons-vfs2 (MonitorOutputStream.write/flush → super.write → a RAM sink's Clock; the MonitorInputStream
     *  mirror; the http/ftp/sftp RandomAccessContent readers reaching Net). The close/flush half is the test
     *  above; this pins the active-I/O methods on both the buffered and filter bases. */
    @Test
    void bufferedAndFilterStreamReadWriteDelegateToUnknownWrappedSink() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("Main.java", String.join("\n",
            "import java.io.*;",
            "class MonOut extends BufferedOutputStream {",                            // super = BufferedOutputStream
            "  MonOut(OutputStream o){ super(o); }",
            "  @Override public synchronized void write(byte[] b,int off,int len) throws IOException { super.write(b,off,len); }",
            "  @Override public synchronized void flush() throws IOException { super.flush(); }",
            "}",
            "class MonIn extends FilterInputStream {",                                // super.read → wrapped `in`
            "  MonIn(InputStream i){ super(i); }",
            "  @Override public int read() throws IOException { return super.read(); }",
            "  @Override public int read(byte[] b,int off,int len) throws IOException { return super.read(b,off,len); }",
            "}",
            "public class Main {}")));
        assertTrue(eff(r, "MonOut.write").toNames().contains("Unknown"),
                "BufferedOutputStream super.write (unknown sink) must read Unknown, got " + r.get("MonOut.write"));
        assertTrue(eff(r, "MonOut.flush").toNames().contains("Unknown"),
                "BufferedOutputStream super.flush (unknown sink) must read Unknown, got " + r.get("MonOut.flush"));
        assertTrue(eff(r, "MonIn.read()").toNames().contains("Unknown"),
                "FilterInputStream super.read (unknown source) must read Unknown, got " + r.get("MonIn.read()"));
        assertTrue(eff(r, "MonIn.read(byte[],int,int)").toNames().contains("Unknown"),
                "FilterInputStream super.read(byte[],int,int) (unknown source) must read Unknown, got " + r.get("MonIn.read(byte[],int,int)"));
    }

    /** #2b — a super-call to a method INHERITED through a GENERIC intermediate superclass must propagate the
     *  superclass method's effect. `Poolable extends Delegating<C> extends Trace`, `Trace.tick()` does Clock,
     *  `Delegating` does not override; `super.tick()` in Poolable compiles to INVOKESPECIAL owner=Delegating,
     *  which does NOT DECLARE tick — so an edge to `Delegating.tick` dangles on a non-existent node and the
     *  Clock is silently lost. The edge must instead resolve to the nearest superclass that declares it
     *  (Trace.tick). REGRESSION: found by the runtime oracle on Apache commons-dbcp2
     *  (PoolableConnection.setLastUsed → super.setLastUsed() → Instant.now(), reported pure — an escaped Clock). */
    @Test
    void superCallThroughGenericIntermediateSuperclassPropagatesEffect() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("Main.java", String.join("\n",
            "import java.time.Instant;",
            "class Trace { protected void tick(){ Instant.now(); } }",                      // Clock leaf (grandparent)
            "class Delegating<C> extends Trace { }",                                        // GENERIC middle, no override
            "class Poolable extends Delegating<Object> { @Override protected void tick(){ super.tick(); } }",
            "public class Main { void go(){ new Poolable().tick(); } }")));
        assertTrue(eff(r, "Poolable.tick").toNames().contains("Clock"),
                "super.tick() through a generic intermediate must reach Trace.tick (Clock), got " + r.get("Poolable.tick"));
        assertTrue(eff(r, "Main.go").toNames().contains("Clock"),
                "the caller must transitively reach Clock through Poolable.tick, got " + r.get("Main.go"));
    }

    /** #3 — an OPAQUE Runnable/Callable task (field/param) handed to an executor reads Unknown (its body is
     *  unknown); an inline pure lambda hand-off must NOT (its body is edged at the indy). */
    @Test
    void opaqueTaskHandoffReadsUnknown() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("B.java", String.join("\n",
            "import java.util.concurrent.*;",
            "public class B {",
            "  Runnable handler;",
            "  void fieldSubmit(ExecutorService es){ es.submit(handler); }",
            "  void paramSubmit(ExecutorService es, Runnable rr){ es.submit(rr); }",
            "  void lambdaSubmit(ExecutorService es){ es.submit(() -> {}); }",
            "}")));
        assertTrue(eff(r, "B.fieldSubmit").toNames().contains("Unknown"), "es.submit(field) must read Unknown");
        assertTrue(eff(r, "B.paramSubmit").toNames().contains("Unknown"), "es.submit(param) must read Unknown");
        assertTrue(eff(r, "B.lambdaSubmit").isEmpty(), "es.submit(pure lambda) must stay pure, got " + r.get("B.lambdaSubmit"));
    }

    /** #3c — the SAME opaque-callback rule for SYNCHRONOUS invokers (Iterator.forEachRemaining / Stream.forEach /
     *  Optional.ifPresent), not only executor hand-offs. An OPAQUE (field/param) Consumer handed to such a HOF has
     *  an unknown body invoked outside project code → Unknown; an inline lambda stays pure (edged at its indy).
     *  REGRESSION: found by the runtime oracle on Apache commons-compress (`ArchiveInputStream.forEach` →
     *  `iterator().forEachRemaining(param)` read silent-pure), and covers commons-io's IOIterator/IOConsumer too. */
    @Test
    void syncCallbackInvokerOpaqueArgReadsUnknown() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("B.java", String.join("\n",
            "import java.util.*;",
            "import java.util.function.Consumer;",
            "import java.util.stream.Stream;",
            "public class B {",
            "  Consumer<String> handler;",
            "  void iterField(Iterator<String> it){ it.forEachRemaining(handler); }",
            "  void iterParam(Iterator<String> it, Consumer<String> c){ it.forEachRemaining(c); }",
            "  void streamParam(Stream<String> s, Consumer<String> c){ s.forEach(c); }",
            "  void optParam(Optional<String> o, Consumer<String> c){ o.ifPresent(c); }",
            "  void iterLambda(Iterator<String> it){ it.forEachRemaining(x -> {}); }",
            "}")));
        assertTrue(eff(r, "B.iterField").toNames().contains("Unknown"), "forEachRemaining(field) must read Unknown");
        assertTrue(eff(r, "B.iterParam").toNames().contains("Unknown"), "forEachRemaining(param) must read Unknown");
        assertTrue(eff(r, "B.streamParam").toNames().contains("Unknown"), "Stream.forEach(param) must read Unknown");
        assertTrue(eff(r, "B.optParam").toNames().contains("Unknown"), "Optional.ifPresent(param) must read Unknown");
        assertTrue(eff(r, "B.iterLambda").isEmpty(), "forEachRemaining(pure lambda) must stay pure, got " + r.get("B.iterLambda"));
    }

    /** The owner-agnostic forEach family: `list.forEach(opaqueConsumer)` is the SINGLE most common form,
     *  and its bytecode owner is the static receiver type (java/util/List, ArrayList, HashSet, a user
     *  collection), NOT the java/lang/Iterable where the default method is declared. An owner-exact table
     *  silently missed it — the four-way conformance differential (sync_callback_opaque) caught the miss.
     *  Matched by NAME now (parity with the Rust/TS/Swift arms). Opaque args disclose; inline lambdas stay. */
    @Test
    void syncCallbackInvokerOwnerAgnosticListForEach() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("B.java", String.join("\n",
            "import java.util.*;",
            "import java.util.function.*;",
            "public class B {",
            "  interface MyColl { void forEach(Consumer<String> c); }",
            "  void listParam(List<String> xs, Consumer<String> c){ xs.forEach(c); }",
            "  void arrayListParam(ArrayList<String> xs, Consumer<String> c){ xs.forEach(c); }",
            "  void setParam(Set<String> xs, Consumer<String> c){ xs.forEach(c); }",
            "  void mapParam(Map<String,String> m, BiConsumer<String,String> c){ m.forEach(c); }",
            "  void userCollParam(MyColl xs, Consumer<String> c){ xs.forEach(c); }",
            "  void listLambdaPure(List<String> xs){ xs.forEach(x -> {}); }",
            "}")));
        assertTrue(eff(r, "B.listParam").toNames().contains("Unknown"), "List.forEach(param) must read Unknown");
        assertTrue(eff(r, "B.arrayListParam").toNames().contains("Unknown"), "ArrayList.forEach(param) must read Unknown");
        assertTrue(eff(r, "B.setParam").toNames().contains("Unknown"), "Set.forEach(param) must read Unknown");
        assertTrue(eff(r, "B.mapParam").toNames().contains("Unknown"), "Map.forEach(param) must read Unknown");
        assertTrue(eff(r, "B.userCollParam").toNames().contains("Unknown"), "user-collection forEach(param) must read Unknown");
        assertTrue(eff(r, "B.listLambdaPure").isEmpty(), "List.forEach(pure lambda) must stay pure, got " + r.get("B.listLambdaPure"));
    }

    /** #3b — the SAME opaque-task hand-off must read Unknown for CompletableFuture `*Async` stages and
     *  java.util.Timer.schedule (not only ExecutorService.submit). An opaque field/param Runnable/Supplier/
     *  TimerTask whose body is unknown → Unknown; an inline lambda or `new R()` with a real effect must keep
     *  the REAL effect (edged at the indy/NEW site), NOT be downgraded to Unknown; a pure inline lambda stays
     *  pure (no fabrication). Mirrors B.fieldSubmit/B.lambdaSubmit for the CF/Timer owners. */
    @Test
    void opaqueTaskHandoffToCompletableFutureAndTimerReadsUnknown() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of("CFT.java", String.join("\n",
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
        assertTrue(eff(r, "CFT.viaExecutor").toNames().contains("Unknown"), "es.submit(field) must read Unknown");
        assertTrue(eff(r, "CFT.viaCF").toNames().contains("Unknown"), "CompletableFuture.runAsync(opaque) must read Unknown");
        assertTrue(eff(r, "CFT.viaSupply").toNames().contains("Unknown"), "CompletableFuture.supplyAsync(opaque) must read Unknown");
        assertTrue(eff(r, "CFT.viaTimer").toNames().contains("Unknown"), "Timer.schedule(opaque TimerTask) must read Unknown");
        // no-regression: the inline-lambda / new-task body's REAL effect is preserved, NOT downgraded.
        assertTrue(eff(r, "CFT.inlineLambda").toNames().contains("Fs"), "runAsync(inline effect lambda) must keep Fs, got " + r.get("CFT.inlineLambda"));
        assertTrue(!eff(r, "CFT.inlineLambda").toNames().contains("Unknown"), "runAsync(inline lambda) must NOT be downgraded to Unknown, got " + r.get("CFT.inlineLambda"));
        assertTrue(eff(r, "CFT.newRunnable").toNames().contains("Fs"), "runAsync(new effect Runnable) must keep Fs, got " + r.get("CFT.newRunnable"));
        assertTrue(!eff(r, "CFT.newRunnable").toNames().contains("Unknown"), "runAsync(new R()) must NOT be downgraded to Unknown, got " + r.get("CFT.newRunnable"));
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
        compileAndScan(src);  // populates AnalysisState.ctx().entryPoints + inferred as a side effect
        for (String fn : List.of("App.asyncTask", "App.restGet", "App.advice", "MyTask.run", "V.isValid"))
            assertTrue(AnalysisState.ctx().entryPoints.contains(fn), fn + " must be rooted as a framework entry point");
    }
}
