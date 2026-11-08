package io.poly.candor;

import io.poly.candor.model.EffectSet;

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
 * SOUNDNESS R1511 — a framework body a project class INHERITS calls back that class's own override.
 * {@code class Cb extends org.joda.time.base.BasePeriod} overrides {@code getValue(int)} with a file read;
 * {@code p.hashCode()}, {@code p.getValues()} and {@code p.equals(q)} run joda's {@code AbstractPeriod} bodies, which call
 * {@code this.getValue(i)} (EXECUTED: 8 reads per call). The consumer scan has no joda bytes and read the table's pure
 * row: the caller had NO ROW. The table's {@code T} lines name the members each surveyed body calls back on its own
 * receiver, and {@link Cha#templateCallbacks} joins the project overrides of those. Controls on the same scan: an
 * override the body does NOT call back, a final framework type, and an exact framework receiver.
 */
class TemplateCallbackR1511Test {

    static final String RP = "org/joda/time/ReadablePeriod";
    static final String BP = "org/joda/time/base/BasePeriod";

    static void fileLength(MethodVisitor m) {
        m.visitTypeInsn(Opcodes.NEW, "java/io/File"); m.visitInsn(Opcodes.DUP); m.visitLdcInsn("/etc/hosts");
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "length", "()J", false);
        m.visitInsn(Opcodes.L2I);
    }

    /** {@code class name extends BasePeriod} overriding {@code member} (returning int or String) with a file stat; with
     *  {@code viaSuper}, also {@code int viaSuper() { return super.hashCode(); }}. */
    static byte[] sub(String name, String member, String desc, boolean viaSuper) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, BP, null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, member, desc, null, null);
        m.visitCode(); fileLength(m);
        if (desc.endsWith("I")) m.visitInsn(Opcodes.IRETURN);
        else { m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/String", "valueOf", "(I)Ljava/lang/String;", false); m.visitInsn(Opcodes.ARETURN); }
        m.visitMaxs(3, 2); m.visitEnd();
        if (viaSuper) {
            m = cw.visitMethod(Opcodes.ACC_PUBLIC, "viaSuper", "()I", null, null);
            m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
            m.visitMethodInsn(Opcodes.INVOKESPECIAL, BP, "hashCode", "()I", false);
            m.visitInsn(Opcodes.IRETURN); m.visitMaxs(1, 1); m.visitEnd();
        }
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** {@code class name extends BasePeriod} overriding {@code size()} and {@code getFieldType(int)} purely (when
     *  {@code bypass}) and {@code getPeriodType()} with a file stat. hashCode reaches getPeriodType only THROUGH size
     *  and getFieldType, so with both overridden it is never called back (EXECUTED: 0 reads; without them, 9). */
    static byte[] viaSub(String name, boolean bypass) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, BP, null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "getPeriodType", "()Lorg/joda/time/PeriodType;", null, null);
        m.visitCode(); fileLength(m); m.visitInsn(Opcodes.POP); m.visitInsn(Opcodes.ACONST_NULL); m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(3, 1); m.visitEnd();
        if (bypass) {
            m = cw.visitMethod(Opcodes.ACC_PUBLIC, "size", "()I", null, null);
            m.visitCode(); m.visitInsn(Opcodes.ICONST_0); m.visitInsn(Opcodes.IRETURN); m.visitMaxs(1, 1); m.visitEnd();
            m = cw.visitMethod(Opcodes.ACC_PUBLIC, "getFieldType", "(I)Lorg/joda/time/DurationFieldType;", null, null);
            m.visitCode(); m.visitInsn(Opcodes.ACONST_NULL); m.visitInsn(Opcodes.ARETURN); m.visitMaxs(1, 2); m.visitEnd();
        }
        cw.visitEnd();
        return cw.toByteArray();
    }

    static void call(ClassWriter cw, String name, String owner, String member, String mdesc, String ret, boolean iface) {
        boolean eq = member.equals("equals");
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + owner + ";)" + ret, null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
        if (eq) m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitMethodInsn(iface ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL, owner, member, mdesc, iface);
        if (ret.equals("I") || ret.equals("Z")) m.visitInsn(Opcodes.IRETURN); else m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(2, 1); m.visitEnd();
    }

    static byte[] consumer() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1511/C", null, "java/lang/Object", null);
        call(cw, "viaBaseHash", BP, "hashCode", "()I", "I", false);
        call(cw, "viaIfaceHash", RP, "hashCode", "()I", "I", true);
        call(cw, "viaValues", BP, "getValues", "()[I", "[I", false);
        call(cw, "viaEq", BP, "equals", "(Ljava/lang/Object;)Z", "Z", false);
        call(cw, "direct", "r1511/Cb", "hashCode", "()I", "I", false);
        call(cw, "superHash", "r1511/R", "viaSuper", "()I", "I", false);
        // CONTROLS: Q overrides toString, which no hashCode body calls back; Days is final
        call(cw, "ctlQHash", "r1511/Q", "hashCode", "()I", "I", false);
        call(cw, "ctlDays", "org/joda/time/Days", "hashCode", "()I", "I", false);
        call(cw, "xHash", "r1511/X", "hashCode", "()I", "I", false);
        call(cw, "ctlWHash", "r1511/W", "hashCode", "()I", "I", false);   // CONTROL: W overrides the members in between
        eq2(cw, "cmpEq", "Ljava/lang/Object;");           // R1511's concrete cell: the ARGUMENT's getLowerLimit runs
        eq2(cw, "ctlCmpEqQ", "Lr1511/Q;");               // CONTROL: a Q is never a DateTimeComparator
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** {@code static boolean name(DateTimeComparator c, <arg> o) { return c.equals(o); }} */
    static void eq2(ClassWriter cw, String name, String arg) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + DTC + ";" + arg + ")Z", null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0); m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, DTC, "equals", "(Ljava/lang/Object;)Z", false);
        m.visitInsn(Opcodes.IRETURN); m.visitMaxs(2, 2); m.visitEnd();
    }

    static final String DTC = "org/joda/time/DateTimeComparator";

    /** {@code class r1511/Cmp extends DateTimeComparator} whose {@code getLowerLimit()} stats a file. */
    static byte[] cmp() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1511/Cmp", null, DTC, null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "getLowerLimit", "()Lorg/joda/time/DateTimeFieldType;", null, null);
        m.visitCode(); fileLength(m); m.visitInsn(Opcodes.POP); m.visitInsn(Opcodes.ACONST_NULL); m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(3, 1); m.visitEnd();
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
    void theTableNamesTheCallbacksAndTheLookupWalksToThem() {
        assertTrue(FrameworkReach.templateMembers(BP, "hashCode", "()I").contains(">getValue(I)I"),
                "AbstractPeriod.hashCode calls this.getValue(i), as inherited by BasePeriod");
        assertTrue(FrameworkReach.templateMembers(BP, "hashCode", "()I").contains("size()I>getPeriodType()Lorg/joda/time/PeriodType;"),
                "getPeriodType is reached THROUGH size(): an edge of the graph, not a flat member");
        assertFalse(FrameworkReach.templateMembers(BP, "hashCode", "()I").contains(">getPeriodType()Lorg/joda/time/PeriodType;"));
        assertTrue(FrameworkReach.templateMembers("org/joda/time/MutablePeriod", "hashCode", "()I").contains(">getValue(I)I"),
                "an inherited member's line is suppressed and found one class up the H lines");
        assertTrue(FrameworkReach.templateMembers(DTC, "equals", "(Ljava/lang/Object;)Z")
                .contains("p0:" + DTC + ".getLowerLimit()Lorg/joda/time/DateTimeFieldType;"),
                "equals runs the ARGUMENT's getLowerLimit (R1511's cmpEq cell)");
        assertFalse(FrameworkReach.templateMembers(BP, "hashCode", "()I").stream().anyMatch(e -> e.endsWith(">toString()Ljava/lang/String;")));
    }

    @Test
    void anInheritedFrameworkBodyIsChargedTheProjectOverrideItCallsBack() throws Exception {
        Path dir = Files.createTempDirectory("r1511u");
        Config saved = Candor.config;
        try {
            Path cls = dir.resolve("cls");
            write(cls, "r1511/C", consumer());
            write(cls, "r1511/Cb", sub("r1511/Cb", "getValue", "(I)I", false));
            write(cls, "r1511/R", sub("r1511/R", "getValue", "(I)I", true));
            write(cls, "r1511/Q", sub("r1511/Q", "toString", "()Ljava/lang/String;", false));
            write(cls, "r1511/Cmp", cmp());
            write(cls, "r1511/X", viaSub("r1511/X", false));
            write(cls, "r1511/W", viaSub("r1511/W", true));
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String fn : new String[] { "viaBaseHash", "viaIfaceHash", "viaValues", "viaEq", "direct", "superHash", "cmpEq", "xHash" })
                assertEquals(Cha.R1511, has(r, "r1511.C." + fn, "FS"), fn + ": the inherited joda body calls back getValue (R1511)");
            assertFalse(has(r, "r1511.C.ctlQHash", "FS"), "CONTROL: hashCode never calls back toString");
            assertFalse(has(r, "r1511.C.ctlDays", "FS"), "CONTROL: Days is final");
            assertFalse(has(r, "r1511.C.ctlWHash", "FS"), "CONTROL: W's own size/getFieldType run, not joda's");
            assertFalse(has(r, "r1511.C.ctlCmpEqQ", "FS"), "CONTROL: the argument is declared a Q, never a Cmp");
            assertFalse(has(r, "r1511.C.ctlDays", "UNKNOWN"), "CONTROL: Days.hashCode stays resolved pure (fad65b2)");
            assertFalse(has(r, "r1511.C.viaBaseHash", "UNKNOWN"), "a resolution, not a hedge");
        } finally {
            Candor.config = saved;
            rm(dir);
        }
    }
}
