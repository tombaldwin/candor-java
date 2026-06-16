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
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Teeth for the round-8 fixes: the per-class fail-soft (a malformed-descriptor overload must NOT abort the
 * whole scan), and the scheduler/Android-lifecycle orphaned-callback rooting (+ decoy control).
 */
class Round8FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-r8");
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

    /** A class with an OVERLOADED method one of whose descriptors is malformed (missing `;`) used to abort
     *  the WHOLE scan in methodId→Type.getArgumentTypes (the 0.5.6 crash class, re-surfaced). The scan must
     *  now skip that class and still analyze the GOOD effectful class in the same dir. */
    @Test
    void malformedOverloadDescriptorDoesNotAbortTheScan() throws Exception {
        Path dir = Files.createTempDirectory("candor-bad");
        try {
            // Bad class: two overloads of `h`, one with a malformed descriptor `(Ljava/lang/String)V` (no `;`).
            ClassWriter cw = new ClassWriter(0);
            cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "Trunc", null, "java/lang/Object", null);
            for (String d : new String[] {"(I)V", "(Ljava/lang/String)V"}) {  // 2nd is malformed
                MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "h", d, null, null);
                mv.visitCode(); mv.visitInsn(Opcodes.RETURN); mv.visitMaxs(0, 3); mv.visitEnd();
            }
            cw.visitEnd();
            Files.write(dir.resolve("Trunc.class"), cw.toByteArray());
            // Good effectful class in the SAME dir — must survive the bad one.
            Path good = compile(Map.of("Good.java",
                "public class Good { public void io(){ try{ new java.net.Socket(\"h\",80).close(); }catch(Exception e){} } }"));
            try (Stream<Path> s = Files.walk(good)) {
                s.filter(p -> p.toString().endsWith("Good.class"))
                 .forEach(p -> { try { Files.copy(p, dir.resolve("Good.class")); } catch (Exception e) { throw new RuntimeException(e); } });
            }
            rm(good.getParent());
            Map<String, TreeSet<String>> r = Candor.runScan(dir);   // must NOT throw
            assertTrue(r.getOrDefault("Good.io", new TreeSet<>()).contains("Net"),
                    "the good class must still be analyzed despite the malformed-overload class");
        } finally { rm(dir); }
    }

    /** Scheduler/job + Android-lifecycle callbacks are rooted as framework entry points; a same-named
     *  non-implementor decoy is NOT rooted (no fabrication). */
    @Test
    void schedulerAndAndroidCallbacksAreRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("org/quartz/Job.java", "package org.quartz; public interface Job { void execute(Object c); }"),
            Map.entry("com/amazonaws/services/lambda/runtime/RequestHandler.java",
                "package com.amazonaws.services.lambda.runtime; public interface RequestHandler<I,O> { O handleRequest(I in, Object ctx); }"),
            Map.entry("android/content/BroadcastReceiver.java",
                "package android.content; public abstract class BroadcastReceiver { public abstract void onReceive(Object c, Object i); }"),
            Map.entry("app/App.java", String.join("\n",
                "package app;",
                "class Qz implements org.quartz.Job { public void execute(Object c){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class Lam implements com.amazonaws.services.lambda.runtime.RequestHandler<Object,Object> { public Object handleRequest(Object in, Object ctx){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }",
                "class Rcv extends android.content.BroadcastReceiver { public void onReceive(Object c, Object i){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class Decoy { public void execute(Object c){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",  // same name, not a Job
                "public class App {}"))));
        try {
            Candor.runScan(cls);
            for (String fn : List.of("app.Qz.execute", "app.Lam.handleRequest", "app.Rcv.onReceive"))
                assertTrue(Candor.entryPoints.contains(fn), fn + " must be rooted");
            assertFalse(Candor.entryPoints.contains("app.Decoy.execute"),
                    "a same-named non-implementor must NOT be rooted (no fabrication)");
        } finally { rm(cls.getParent()); }
    }
}
