package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * End-to-end teeth for the round-11 fixes:
 *  - the AS-EFF-008 literal-attribution gate-evasion (a benign URL/SQL literal in a method whose actual
 *    sink uses a RUNTIME value must NOT be captured as that method's host/table — but a literal that
 *    really reaches the sink, even through a const local, MUST be);
 *  - the exempt function-object broad-fan-out silent-pure (a &gt;12-impl unpinned Kotlin FunctionN dispatch
 *    with one effectful NAMED impl must reach Unknown, not pure);
 *  - the new JDK runtime-callback roots (Flow.Subscriber, Thread.UncaughtExceptionHandler) + a decoy.
 *
 * <p>Originally review round 11 (Round11FixesTest).
 */
class PerCallLiteralAttributionTest {

    /** GATE-EVASION: a benign URL literal in a method whose real sink host is a RUNTIME param must NOT be
     *  captured as the method's host (else `allow Net api.stripe.com` certifies the runtime host). A URL
     *  literal that really reaches the sink — inline OR via a const local — MUST still be captured. */
    @Test
    void hostLiteralAttributedPerCallNotMethodWide() throws Exception {
        Path cls = compile(Map.of("app/A.java", String.join("\n",
            "package app;",
            "import java.net.URL;",
            "public class A {",
            // real sink uses a runtime host; a benign URL literal is only logged → must NOT be captured
            "  void evade(String runtimeHost) throws Exception {",
            "    String docs = \"https://api.stripe.com/v1/docs\";",
            "    new URL(runtimeHost).openStream();",
            "    System.out.println(docs);",
            "  }",
            // inline literal that IS the sink arg → captured
            "  void inline() throws Exception { new URL(\"https://inline.example.com/x\").openStream(); }",
            // const local that flows to the sink arg → captured (dataflow-lite)
            "  void viaLocal() throws Exception { String u = \"https://local.example.com/y\"; new URL(u).openStream(); }",
            "}")));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().hostsDirect.getOrDefault("app.A.evade", new TreeSet<>()).isEmpty(),
                    "a benign URL literal must NOT be captured when the real host is runtime, got "
                            + AnalysisState.ctx().hostsDirect.get("app.A.evade"));
            assertTrue(AnalysisState.ctx().hostsDirect.getOrDefault("app.A.inline", new TreeSet<>()).contains("inline.example.com"),
                    "an inline URL host must be captured");
            assertTrue(AnalysisState.ctx().hostsDirect.getOrDefault("app.A.viaLocal", new TreeSet<>()).contains("local.example.com"),
                    "a const-local URL host must be captured (dataflow-lite)");
        } finally { rm(cls.getParent()); }
    }

    /** Same per-call attribution for SQL tables: a SQL-shaped log line in a method with a runtime query must
     *  NOT poison the table set; a const-local SQL string that reaches the sink MUST be extracted. */
    @Test
    void tableLiteralAttributedPerCall() throws Exception {
        Path cls = compile(Map.of("app/D.java", String.join("\n",
            "package app;",
            "import java.sql.*;",
            "public class D {",
            "  void evade(Connection c, String runtimeSql) throws Exception {",
            "    String log = \"SELECT failed for orders table; retrying\";",  // a log line, not executed
            "    c.prepareStatement(runtimeSql).execute();",
            "    System.out.println(log);",
            "  }",
            "  void viaLocal(Connection c) throws Exception {",
            "    String sql = \"SELECT * FROM customers\";",
            "    c.prepareStatement(sql).execute();",
            "  }",
            "}")));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().tablesDirect.getOrDefault("app.D.evade", new TreeSet<>()).isEmpty(),
                    "a SQL-shaped log must NOT be attributed, got " + AnalysisState.ctx().tablesDirect.get("app.D.evade"));
            assertTrue(AnalysisState.ctx().tablesDirect.getOrDefault("app.D.viaLocal", new TreeSet<>()).contains("customers"),
                    "a const-local SQL table must be extracted");
        } finally { rm(cls.getParent()); }
    }

    /** Exempt function-object broad fan-out: 14 NAMED Kotlin Function0 impls (one effectful) dispatched over
     *  an unpinned param must drive the caller to Unknown — not silent-pure (the dropped named impl could do
     *  I/O). With ≤12 impls the fan-out is narrow and the effect is reached precisely. */
    @Test
    void exemptBroadFanoutRaisesUnknown() throws Exception {
        Map<String, String> src = new java.util.HashMap<>();
        src.put("kotlin/jvm/functions/Function0.java",
            "package kotlin.jvm.functions; public interface Function0<R> { R invoke(); }");
        StringBuilder impls = new StringBuilder("package app;\n");
        for (int i = 0; i < 14; i++) {
            String body = i == 7
                ? "{ try { new java.net.Socket(\"h\", 80).close(); } catch (Exception e) {} return null; }"
                : "{ return null; }";
            impls.append("class Fn").append(i).append(" implements kotlin.jvm.functions.Function0<Object> {")
                 .append(" public Object invoke() ").append(body).append(" }\n");
        }
        impls.append("public class Big { Object call(kotlin.jvm.functions.Function0<Object> f){ return f.invoke(); } }\n");
        src.put("app/Big.java", impls.toString());
        Path cls = compile(src);
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            EffectSet eff = r.getOrDefault("app.Big.call", EffectSet.empty());
            assertFalse(eff.isEmpty(),
                    "a broad unpinned FunctionN dispatch dropping NAMED impls must NOT be silent-pure");
            assertTrue(eff.toNames().contains("Unknown") || eff.toNames().contains("Net"),
                    "must be Unknown (or the effect) — the dropped named impl could do I/O, got " + eff);
        } finally { rm(cls.getParent()); }
    }

    /** New JDK runtime-callback roots: Flow.Subscriber.onNext (the JDK analog of the already-rooted
     *  reactivestreams Subscriber) + Thread.UncaughtExceptionHandler.uncaughtException; a non-implementor
     *  decoy is NOT rooted. */
    @Test
    void jdkRuntimeCallbacksRooted() throws Exception {
        Path cls = compile(Map.of("app/A.java", String.join("\n",
            "package app;",
            "class Sub implements java.util.concurrent.Flow.Subscriber<Object> {",
            "  public void onSubscribe(java.util.concurrent.Flow.Subscription s){}",
            "  public void onNext(Object o){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",
            "  public void onError(Throwable t){} public void onComplete(){} }",
            "class Ueh implements Thread.UncaughtExceptionHandler {",
            "  public void uncaughtException(Thread t, Throwable e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception x){} } }",
            "class NotAHandler { public void uncaughtException(Thread t, Throwable e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception x){} } }",
            "public class A {}")));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Sub.onNext"), "Flow.Subscriber.onNext must be rooted");
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Ueh.uncaughtException"),
                    "Thread.UncaughtExceptionHandler.uncaughtException must be rooted");
            assertFalse(AnalysisState.ctx().entryPoints.contains("app.NotAHandler.uncaughtException"),
                    "a non-implementor with the same method must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }
}
