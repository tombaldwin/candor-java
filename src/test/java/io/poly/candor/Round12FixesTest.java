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
 * Round-12 teeth: the new framework runtime-callback roots (Spring ApplicationListener, JMS/Kafka
 * listeners) + a decoy; and the exempt-fanout precision fix — a broad (&gt;12) higher-order dispatch over
 * PURE SYNTHETIC LAMBDA impls must NOT flood Unknown (while named impls still do, per Round11FixesTest).
 */
class Round12FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-r12");
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

    /** Spring ApplicationListener.onApplicationEvent + JMS MessageListener.onMessage + Kafka
     *  ConsumerRebalanceListener.onPartitionsRevoked are container-invoked roots; a non-implementor decoy
     *  with the same method name is NOT rooted. */
    @Test
    void frameworkInterfaceCallbacksRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("org/springframework/context/ApplicationListener.java",
                "package org.springframework.context; public interface ApplicationListener<E> { void onApplicationEvent(E e); }"),
            Map.entry("javax/jms/MessageListener.java",
                "package javax.jms; public interface MessageListener { void onMessage(Object m); }"),
            Map.entry("org/apache/kafka/clients/consumer/ConsumerRebalanceListener.java",
                "package org.apache.kafka.clients.consumer; import java.util.*; public interface ConsumerRebalanceListener { void onPartitionsRevoked(Collection<?> p); void onPartitionsAssigned(Collection<?> p); }"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "class L implements org.springframework.context.ApplicationListener<Object> {",
                "  public void onApplicationEvent(Object e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception x){} } }",
                "class M implements javax.jms.MessageListener {",
                "  public void onMessage(Object m){ try{new java.net.Socket(\"h\",80).close();}catch(Exception x){} } }",
                "class R implements org.apache.kafka.clients.consumer.ConsumerRebalanceListener {",
                "  public void onPartitionsRevoked(java.util.Collection<?> p){ try{new java.net.Socket(\"h\",80).close();}catch(Exception x){} }",
                "  public void onPartitionsAssigned(java.util.Collection<?> p){} }",
                "class NotAListener { public void onMessage(Object m){ try{new java.net.Socket(\"h\",80).close();}catch(Exception x){} } }",
                "public class A {}"))));
        try {
            Candor.runScan(cls);
            assertTrue(Candor.entryPoints.contains("app.L.onApplicationEvent"), "ApplicationListener must be rooted");
            assertTrue(Candor.entryPoints.contains("app.M.onMessage"), "JMS MessageListener must be rooted");
            assertTrue(Candor.entryPoints.contains("app.R.onPartitionsRevoked"), "ConsumerRebalanceListener must be rooted");
            assertFalse(Candor.entryPoints.contains("app.NotAListener.onMessage"),
                    "a non-implementor with onMessage must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }

    /** A broad (>12) unpinned Kotlin Function0 dispatch over SYNTHETIC LAMBDA impls must reach Unknown — NOT
     *  be silent-pure. A synthetic lambda CLASS's invoke() body is reachable ONLY through this dispatch edge
     *  (a `new Lam()` edges <init>, not invoke), so an earlier "suppress Unknown for all-synthetic" fix
     *  (chaImplsAllSynthetic) made an effectful lambda SILENT-PURE — reverted. The broad-dispatch Unknown is
     *  the sound over-approximation (the dispatcher invokes an unresolvable function). */
    @Test
    void exemptBroadFanoutOverLambdasReachesUnknownNotSilentPure() throws Exception {
        Path dir = Files.createTempDirectory("candor-r12-syn");
        Path out = dir.resolve("cls");
        Files.createDirectories(out.resolve("app"));
        Files.createDirectories(out.resolve("kotlin/jvm/functions"));
        write(out.resolve("kotlin/jvm/functions/Function0.class"), ifaceFunction0());
        // 13 PURE synthetic lambda impls + 1 EFFECTFUL (Net) — the effectful one must not be silently dropped
        for (int i = 0; i < 13; i++)
            write(out.resolve("app/Lam" + i + ".class"), syntheticPureFn("app/Lam" + i));
        write(out.resolve("app/Lam13.class"), syntheticNetFn("app/Lam13"));
        write(out.resolve("app/Big.class"), bigCaller());
        try {
            Map<String, TreeSet<String>> r = Candor.runScan(out);
            TreeSet<String> eff = r.getOrDefault("app.Big.call", new TreeSet<>());
            assertFalse(eff.isEmpty(),
                    "a broad dispatch dropping a synthetic lambda whose invoke() does I/O must NOT be silent-pure");
            assertTrue(eff.contains("Unknown") || eff.contains("Net"),
                    "broad lambda dispatch must reach Unknown (or the effect), got " + eff);
        } finally { rm(dir); }
    }

    private static void write(Path p, byte[] b) throws Exception {
        Files.createDirectories(p.getParent());
        Files.write(p, b);
    }

    private static byte[] ifaceFunction0() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE,
                "kotlin/jvm/functions/Function0", null, "java/lang/Object", null);
        cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "invoke", "()Ljava/lang/Object;", null, null).visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** A SYNTHETIC class implementing Function0.invoke() with a PURE body (returns null) — the shape a
     *  Kotlin/Scala lambda compiles to (ACC_SYNTHETIC, named impl in byName). */
    private static byte[] syntheticPureFn(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC, internal, null,
                "java/lang/Object", new String[] {"kotlin/jvm/functions/Function0"});
        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
        MethodVisitor inv = cw.visitMethod(Opcodes.ACC_PUBLIC, "invoke", "()Ljava/lang/Object;", null, null);
        inv.visitCode();
        inv.visitInsn(Opcodes.ACONST_NULL);
        inv.visitInsn(Opcodes.ARETURN);
        inv.visitMaxs(0, 0);
        inv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** A SYNTHETIC Function0 impl whose invoke() does real Net I/O (new Socket) — reachable only via the
     *  dispatch edge, so a broad fan-out that drops it must still surface Unknown/Net at the caller. */
    private static byte[] syntheticNetFn(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC, internal, null,
                "java/lang/Object", new String[] {"kotlin/jvm/functions/Function0"});
        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
        MethodVisitor inv = cw.visitMethod(Opcodes.ACC_PUBLIC, "invoke", "()Ljava/lang/Object;", null, null);
        inv.visitCode();
        // new java.net.Socket("h", 80)  (effect: Net) — value popped, then return null
        inv.visitTypeInsn(Opcodes.NEW, "java/net/Socket");
        inv.visitInsn(Opcodes.DUP);
        inv.visitLdcInsn("h");
        inv.visitIntInsn(Opcodes.BIPUSH, 80);
        inv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/net/Socket", "<init>", "(Ljava/lang/String;I)V", false);
        inv.visitInsn(Opcodes.POP);
        inv.visitInsn(Opcodes.ACONST_NULL);
        inv.visitInsn(Opcodes.ARETURN);
        inv.visitMaxs(0, 0);
        inv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] bigCaller() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "app/Big", null, "java/lang/Object", null);
        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
        // Object call(Function0 f) { return f.invoke(); }  — unpinned receiver → broad CHA over the 14 impls
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "call", "(Lkotlin/jvm/functions/Function0;)Ljava/lang/Object;", null, null);
        m.visitCode();
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEINTERFACE, "kotlin/jvm/functions/Function0", "invoke", "()Ljava/lang/Object;", true);
        m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        // static void main: new each Lam so they land in the scanned graph
        MethodVisitor main = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        main.visitCode();
        for (int i = 0; i < 14; i++) {
            main.visitTypeInsn(Opcodes.NEW, "app/Lam" + i);
            main.visitInsn(Opcodes.DUP);
            main.visitMethodInsn(Opcodes.INVOKESPECIAL, "app/Lam" + i, "<init>", "()V", false);
            main.visitInsn(Opcodes.POP);
        }
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(0, 0);
        main.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
