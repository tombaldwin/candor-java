package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Teeth for the round-7 Java-sweep fixes: orphaned runtime-invoked callback rooting (deser frameworks #3,
 * runtime-gen proxy interceptors #4, logging appenders #6, gRPC handlers #10) and the CANDOR_NO_AMBIENT
 * scope-matcher divergence (#8). Compiles real fixtures with RUNTIME-retention stubs at the real FQNs.
 *
 * <p>Originally review round 7 (Round7FixesTest).
 */
class FrameworkCallbackRootingTest {

    /** #3/#4/#6/#10 — a project implementor of a (de)serialization callback, a runtime-gen proxy
     *  interceptor, a logging appender, and a gRPC handler are each rooted as framework entry points (they
     *  have NO in-project call site); a same-named non-implementor DECOY is NOT rooted (no fabrication). */
    @Test
    void orphanedRuntimeCallbacksAreRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("com/fasterxml/jackson/databind/JsonDeserializer.java",
                "package com.fasterxml.jackson.databind; public abstract class JsonDeserializer<T> { public abstract T deserialize(Object p); }"),
            Map.entry("net/sf/cglib/proxy/MethodInterceptor.java",
                "package net.sf.cglib.proxy; public interface MethodInterceptor { Object intercept(Object o, java.lang.reflect.Method m, Object[] a, Object p); }"),
            Map.entry("ch/qos/logback/core/Appender.java",
                "package ch.qos.logback.core; public interface Appender<E> { void append(E e); }"),
            Map.entry("io/grpc/stub/StreamObserver.java",
                "package io.grpc.stub; public interface StreamObserver<V> { void onNext(V v); }"),
            Map.entry("io/grpc/GreeterImplBase.java",
                "package io.grpc; import io.grpc.stub.StreamObserver; public abstract class GreeterImplBase { public void sayHello(Object r, StreamObserver<Object> o){} }"),
            Map.entry("app/App.java", String.join("\n",
                "package app;",
                "import com.fasterxml.jackson.databind.JsonDeserializer;",
                "import net.sf.cglib.proxy.MethodInterceptor;",
                "import ch.qos.logback.core.Appender;",
                "import io.grpc.stub.StreamObserver;",
                "class MyDeser extends JsonDeserializer<Object> { public Object deserialize(Object p){ io(); return null; } static void io(){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class MyItc implements MethodInterceptor { public Object intercept(Object o,java.lang.reflect.Method m,Object[] a,Object p){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }",
                "class MyApp2 implements Appender<Object> { public void append(Object e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception x){} } }",
                "class Greeter extends io.grpc.GreeterImplBase { public void sayHello(Object r, StreamObserver<Object> o){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class Decoy { Object deserialize(Object p){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }", // same name, NOT an implementor
                "public class App {}"))));
        try {
            Candor.runScan(cls);
            for (String fn : List.of("app.MyDeser.deserialize", "app.MyItc.intercept",
                    "app.MyApp2.append", "app.Greeter.sayHello"))
                assertTrue(AnalysisState.ctx().entryPoints.contains(fn), fn + " must be rooted as a framework entry point");
            assertFalse(AnalysisState.ctx().entryPoints.contains("app.Decoy.deserialize"),
                    "a same-named non-implementor must NOT be rooted (no fabrication)");
        } finally { rm(cls.getParent()); }
    }

    /** #8 — the CANDOR_NO_AMBIENT / strict gate scope matcher is now segment- and `::`-aware (it used a raw
     *  startsWith that silently disabled a `::`-written or non-prefix scope and prefix-bled). */
    @Test
    void gateScopeIsSegmentAndDoubleColonAware() {
        assertTrue(Candor.gateScopeCovers("gate::Gate", "gate.Gate.directEnv"));   // :: scope matches dotted name
        assertTrue(Candor.gateScopeCovers("gate.Gate", "gate.Gate.directEnv"));    // dot scope still works
        assertTrue(Candor.gateScopeCovers("Gate", "gate.Gate.directEnv"));         // segment
        assertTrue(Candor.gateScopeCovers("1", "anything.at.all"));                // whole-project flag
        assertTrue(Candor.gateScopeCovers("", "anything.at.all"));                 // empty = whole project
        assertFalse(Candor.gateScopeCovers("other::scope", "gate.Gate.directEnv"));// no match
        assertFalse(Candor.gateScopeCovers("gate.Gat", "gateExtra.Gate.x"));       // no prefix-bleed (segment-aware)
    }
}
