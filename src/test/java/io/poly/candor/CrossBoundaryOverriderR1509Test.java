package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * SOUNDNESS R1509 — a dispatch over a DEPENDENCY type whose project implementor reaches that type only THROUGH a
 * dependency class. {@code class BadPeriod extends org.joda.time.base.BasePeriod} implements {@code ReadablePeriod}
 * only because joda's {@code BasePeriod} does, and the consumer's CHA ({@code Cha#buildSubtypeIndex}) files a project
 * class under the supertypes its class path can show — not joda's. So {@code viaIface(ReadablePeriod p) { return
 * p.hashCode(); }}, handed a {@code BadPeriod} whose {@code hashCode} reads a file (EXECUTED: 600, the size of
 * /etc/hosts), had NO ROW, chained and unchained, after the framework table's {@code A ReadablePeriod.hashCode} hedge
 * was (correctly, for joda's own implementers) withdrawn by fad65b2. The same hole with no hedge to hide it was
 * already in published 0.41.3: {@code p.getValue(0)} over {@code ReadablePeriod} unchained and over
 * {@code AbstractPeriod} both ways, and any chained non-framework dependency.
 *
 * <p>The resolution: {@link Cha#crossBoundaryTargets} walks a project class's supertypes past the scan — a chained
 * sidecar, else the framework table's {@code H} lines, else the class path — and joins the project bodies so reached.
 * Controls on the SAME override so each can fail: an interface the class does NOT reach, a final framework type, and
 * an exact framework receiver.
 */
class CrossBoundaryOverriderR1509Test {

    static final String RP = "org/joda/time/ReadablePeriod";
    static final String AP = "org/joda/time/base/AbstractPeriod";
    static final String BP = "org/joda/time/base/BasePeriod";

    static void fileLength(MethodVisitor m) {
        m.visitTypeInsn(Opcodes.NEW, "java/io/File"); m.visitInsn(Opcodes.DUP); m.visitLdcInsn("/etc/hosts");
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "length", "()J", false);
        m.visitInsn(Opcodes.L2I);
    }

    /** {@code class r1509/Bad extends BasePeriod} overriding {@code hashCode()} and {@code getValue(int)} with a file stat. */
    static byte[] bad() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1509/Bad", null, BP, null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "hashCode", "()I", null, null);
        m.visitCode(); fileLength(m); m.visitInsn(Opcodes.IRETURN); m.visitMaxs(3, 1); m.visitEnd();
        m = cw.visitMethod(Opcodes.ACC_PUBLIC, "getValue", "(I)I", null, null);
        m.visitCode(); fileLength(m); m.visitInsn(Opcodes.IRETURN); m.visitMaxs(3, 2); m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static void call(ClassWriter cw, String name, String owner, String member, String mdesc, boolean iface, int extra) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + owner + ";)I", null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
        if (extra >= 0) m.visitInsn(Opcodes.ICONST_0);
        m.visitMethodInsn(iface ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL, owner, member, mdesc, iface);
        m.visitInsn(Opcodes.IRETURN); m.visitMaxs(2, 1); m.visitEnd();
    }

    static byte[] consumer() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1509/C", null, "java/lang/Object", null);
        call(cw, "viaIface", RP, "hashCode", "()I", true, -1);          // R1509: the A line's member
        call(cw, "viaIfaceGet", RP, "getValue", "(I)I", true, 0);       // in 0.41.3 already: no hedge, no row
        call(cw, "viaAbsHash", AP, "hashCode", "()I", false, -1);       // a U line's member
        call(cw, "viaAbsGet", AP, "getValue", "(I)I", false, 0);
        // CONTROLS: Bad is no ReadableInstant; Days is final (no consumer subclass); the same name on an unrelated type
        call(cw, "ctlInstant", "org/joda/time/ReadableInstant", "hashCode", "()I", true, -1);
        call(cw, "ctlDays", "org/joda/time/Days", "hashCode", "()I", false, -1);
        call(cw, "ctlPartialGet", "org/joda/time/ReadablePartial", "getValue", "(I)I", true, 0);
        cw.visitEnd();
        return cw.toByteArray();
    }

    static boolean has(Map<String, EffectSet> r, String fn, String eff) {
        EffectSet e = r.get(fn);
        return e != null && e.effects().stream().anyMatch(x -> x.name().equals(eff));
    }

    static void write(Path cls, String internal, byte[] b) throws Exception {
        Path p = cls.resolve(internal + ".class");
        Files.createDirectories(p.getParent());
        Files.write(p, b);
    }

    @Test
    void theTableCarriesTheSurveyedHierarchy() {
        assertTrue(FrameworkReach.surveyedSupers(BP).contains(RP), "BasePeriod implements ReadablePeriod (an H line)");
        assertTrue(FrameworkReach.surveyedSupers(BP).contains(AP));
        assertTrue(FrameworkReach.surveyedSupers("java/util/ArrayList") == null, "the JDK is read off the class path");
    }

    @Test
    void unchainedAProjectClassReachingAFrameworkTypeThroughAFrameworkClassIsJoined() throws Exception {
        Path dir = Files.createTempDirectory("r1509u");
        Config saved = Candor.config;
        try {
            write(dir.resolve("cls"), "r1509/C", consumer());
            write(dir.resolve("cls"), "r1509/Bad", bad());
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(dir.resolve("cls"));
            for (String fn : new String[] { "viaIface", "viaIfaceGet", "viaAbsHash", "viaAbsGet" })
                assertTrue(has(r, "r1509.C." + fn, "FS"), fn + " was absent over a file stat (R1509)");
            for (String fn : new String[] { "ctlInstant", "ctlDays", "ctlPartialGet" })
                assertFalse(has(r, "r1509.C." + fn, "FS"), "CONTROL " + fn + ": Bad is not a subtype of that owner");
            // (ctlInstant and ctlPartialGet keep their table `A` hedge, which is about joda's own implementers)
            assertFalse(has(r, "r1509.C.ctlDays", "UNKNOWN"), "CONTROL: Days is final, its hashCode resolved pure (fad65b2)");
            assertFalse(has(r, "r1509.C.viaIface", "UNKNOWN"), "a resolution, not a hedge: the override is the answer");
        } finally {
            Candor.config = saved;
            rm(dir);
        }
    }

    /** {@code class r1509/It extends scala.collection.AbstractIterator} with a file-stat {@code next()}, and a consumer
     *  calling {@code scala.collection.Iterator.next()} — the shape that, joined, smeared one union over 368
     *  scala-compiler rows (a Range's own iterator edged into every compiler iterator). A language runtime's library is
     *  excluded as the JDK is; the joda call in the SAME scan proves the walk ran. */
    @Test
    void aLanguageRuntimeOwnerIsNotJoinedLikeTheJdk() throws Exception {
        assertTrue(FrameworkReach.surveyedSupers("scala/collection/AbstractIterator").contains("scala/collection/Iterator"),
                "the walk could reach scala.collection.Iterator (an H line): the exclusion, not the table, decides");
        // CANDOR_R1509_LANG=0 (the measurement arm) lifts the exclusion; run that way this test proves the fixture
        // reaches the join — the same scan then reads Fs — so the default arm's absence is the exclusion's doing
        boolean on = Cha.R1509_LANG;
        assertEquals(on, Cha.languageRuntimeOwned("scala/collection/Iterator"));
        assertEquals(on, Cha.languageRuntimeOwned("kotlin/collections/AbstractList"));
        assertEquals(on, Cha.languageRuntimeOwned("groovy/lang/Closure"));
        assertFalse(Cha.languageRuntimeOwned("kotlinx/coroutines/Job"), "kotlinx is an ordinary library");
        assertFalse(Cha.languageRuntimeOwned(RP));
        Path dir = Files.createTempDirectory("r1509s");
        Config saved = Candor.config;
        try {
            ClassWriter it = new ClassWriter(0);
            it.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1509/It", null, "scala/collection/AbstractIterator", null);
            MethodVisitor m = it.visitMethod(Opcodes.ACC_PUBLIC, "next", "()Ljava/lang/Object;", null, null);
            m.visitCode(); fileLength(m);
            m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
            m.visitInsn(Opcodes.ARETURN); m.visitMaxs(3, 1); m.visitEnd();
            it.visitEnd();
            ClassWriter cw = new ClassWriter(0);
            cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1509/S", null, "java/lang/Object", null);
            m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "viaScalaIter",
                    "(Lscala/collection/Iterator;)Ljava/lang/Object;", null, null);
            m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
            m.visitMethodInsn(Opcodes.INVOKEINTERFACE, "scala/collection/Iterator", "next", "()Ljava/lang/Object;", true);
            m.visitInsn(Opcodes.ARETURN); m.visitMaxs(1, 1); m.visitEnd();
            cw.visitEnd();
            write(dir.resolve("cls"), "r1509/It", it.toByteArray());
            write(dir.resolve("cls"), "r1509/S", cw.toByteArray());
            write(dir.resolve("cls"), "r1509/C", consumer());
            write(dir.resolve("cls"), "r1509/Bad", bad());
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(dir.resolve("cls"));
            assertTrue(has(r, "r1509.C.viaIface", "FS"), "the walk ran in this scan (R1509's own shape)");
            assertEquals(!on, has(r, "r1509.S.viaScalaIter", "FS"),
                    "scala-library is excluded as the JDK is (the residual is SOUNDNESS R1510; flip this when it closes)");
        } finally {
            Candor.config = saved;
            rm(dir);
        }
    }

    @Test
    void chainedTheDependencySidecarSuppliesTheWalk() throws Exception {
        Map<String, String> lib = Map.of(
                "zdep/Iface.java", "package zdep; public interface Iface { int hashCode(); int work(); }",
                "zdep/Other.java", "package zdep; public interface Other { int work(); }",
                "zdep/Base.java", "package zdep; public abstract class Base implements Iface {"
                        + " public int hashCode() { return 1; } public int work() { return 2; } }");
        Map<String, String> app = Map.of("app/A.java", "package app; public class A {"
                + " static class Bad extends zdep.Base {"
                + "  public int hashCode() { return (int) new java.io.File(\"/etc/hosts\").length(); }"
                + "  public int work() { return (int) new java.io.File(\"/etc/hosts\").length(); } }"
                + " public static int viaIfaceHash(zdep.Iface i) { return i.hashCode(); }"
                + " public static int viaIfaceWork(zdep.Iface i) { return i.work(); }"
                + " public static int ctlOther(zdep.Other o) { return o.work(); } }");
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path dep = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), dep.toString(), null);
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + dep + "\n");
            Candor.config = Config.forTarget(appDir);
            Map<String, EffectSet> r = Candor.runScan(appDir);
            assertTrue(has(r, "app.A.viaIfaceHash", "FS"), "absent in 0.41.3 and at fad65b2 (the one-tree scan reads Fs)");
            assertTrue(has(r, "app.A.viaIfaceWork", "FS"), "[] in 0.41.3 (the one-tree scan reads Fs)");
            assertFalse(has(r, "app.A.ctlOther", "FS"), "CONTROL: Bad does not implement Other");
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }
}
