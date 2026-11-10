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
 * SOUNDNESS R1573 — a framework member DISPATCHED on a consumer object whose class INHERITS it runs the framework body,
 * and that body calls back the object's own override. EXECUTED: commons-validator 1.9.0 {@code new Form().addField(c)}
 * with {@code Cb extends Field} overriding only {@code isIndexed()} with an env read — {@code Form.addField} runs
 * {@code c.getKey()}, {@code Field.getKey} runs {@code this.generateKey()} -> {@code this.isIndexed()}: hits=1, and the
 * consumer had no row. joda-time's {@code PeriodConverter.setInto(c, ..)} runs the inherited
 * {@code MutablePeriod.setPeriod}, which calls {@code this.setValues}: hits=1, silent. The direct {@code c.getKey()} was
 * already charged (R1511); the parameter entry ({@code p0:Field.getKey}) and the D key
 * ({@code ReadWritablePeriod.setPeriod}) looked only for a project BODY of the dispatched member.
 * Pure twins (unique names), an over-join control (an override the inherited body never calls back), and both arms of
 * the kill switch.
 */
class InheritedDispatchCallbackR1573Test {

    static final String FIELD = "org/apache/commons/validator/Field";
    static final String FORM = "org/apache/commons/validator/Form";
    static final String MP = "org/joda/time/MutablePeriod";
    static final String PC = "org/joda/time/convert/PeriodConverter";

    static void fileLength(MethodVisitor m) {
        m.visitTypeInsn(Opcodes.NEW, "java/io/File"); m.visitInsn(Opcodes.DUP); m.visitLdcInsn("/etc/hosts");
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "length", "()J", false);
        m.visitInsn(Opcodes.POP2);
    }

    static void ctor(ClassWriter cw, String sup) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, sup, "<init>", "()V", false);
        m.visitInsn(Opcodes.RETURN); m.visitMaxs(1, 1); m.visitEnd();
    }

    /** {@code class name extends sup} overriding {@code member+desc} (void, boolean or String return) — with a file
     *  stat when {@code effect}, else a pure body; no override at all when {@code member} is null. */
    static byte[] sub(String name, String sup, boolean abs, String member, String desc, boolean effect) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | (abs ? Opcodes.ACC_ABSTRACT : 0), name, null, sup, null);
        ctor(cw, sup);
        if (member != null) {
            MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, member, desc, null, null);
            m.visitCode();
            if (effect) fileLength(m);
            if (desc.endsWith(")V")) m.visitInsn(Opcodes.RETURN);
            else if (desc.endsWith(")Z")) { m.visitInsn(Opcodes.ICONST_0); m.visitInsn(Opcodes.IRETURN); }
            else { m.visitInsn(Opcodes.ACONST_NULL); m.visitInsn(Opcodes.ARETURN); }
            m.visitMaxs(3, 2); m.visitEnd();
        }
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** {@code static void name(<arg> c) { new Form().addField(c); }} */
    static void addField(ClassWriter cw, String name, String arg) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + arg + ";)V", null, null);
        m.visitCode();
        m.visitTypeInsn(Opcodes.NEW, FORM); m.visitInsn(Opcodes.DUP);
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, FORM, "<init>", "()V", false);
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, FORM, "addField", "(L" + FIELD + ";)V", false);
        m.visitInsn(Opcodes.RETURN); m.visitMaxs(3, 1); m.visitEnd();
    }

    /** {@code static void name(PeriodConverter pc, <arg> c) { pc.setInto(c, null, null); }} */
    static void setInto(ClassWriter cw, String name, String arg) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + PC + ";L" + arg + ";)V", null, null);
        m.visitCode();
        m.visitVarInsn(Opcodes.ALOAD, 0); m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitInsn(Opcodes.ACONST_NULL); m.visitInsn(Opcodes.ACONST_NULL);
        m.visitMethodInsn(Opcodes.INVOKEINTERFACE, PC, "setInto",
                "(Lorg/joda/time/ReadWritablePeriod;Ljava/lang/Object;Lorg/joda/time/Chronology;)V", true);
        m.visitInsn(Opcodes.RETURN); m.visitMaxs(4, 2); m.visitEnd();
    }

    static byte[] consumer(String name, boolean joda) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        if (!joda) {
            addField(cw, "add", "r1573/Cb");                 // the R1573 cell
            addField(cw, "addMid", "r1573/CbMid");           // through an intermediate project class
            addField(cw, "addAbs", "r1573/Abs");             // an abstract consumer, its concrete subclass inherits
            addField(cw, "addGen", "r1573/CbGen");           // the first hop overridden (generateKey)
            addField(cw, "addPure", "r1573/CbPure");         // PURE TWIN
            addField(cw, "addUnrel", "r1573/CbUnrel");       // CONTROL: an override getKey never calls back
        } else {
            setInto(cw, "into", "r1573/Mp");                 // the D-key cell
        }
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

    static Map<String, EffectSet> scan(Path cls) throws Exception {
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            return Candor.runScan(cls);
        } finally {
            Candor.config = saved;
        }
    }

    @Test
    void theTableCarriesBothShapes() {
        assertTrue(FrameworkReach.templateMembers(FORM, "addField", "(L" + FIELD + ";)V")
                .contains("p0:" + FIELD + ".getKey()Ljava/lang/String;"), "addField dispatches getKey on its argument");
        assertTrue(FrameworkReach.templateMembers(FIELD, "getKey", "()Ljava/lang/String;").contains("generateKey()V>isIndexed()Z"),
                "Field.getKey reaches isIndexed through generateKey");
        assertTrue(FrameworkReach.dispatchMembers(PC, "setInto",
                "(Lorg/joda/time/ReadWritablePeriod;Ljava/lang/Object;Lorg/joda/time/Chronology;)V")
                .contains("org/joda/time/ReadWritablePeriod.setPeriod(Lorg/joda/time/ReadablePeriod;)V"));
        assertTrue(FrameworkReach.templateMembers(MP, "setPeriod", "(Lorg/joda/time/ReadablePeriod;)V").contains(">setValues([I)V"));
    }

    @Test
    void anArgumentThatInheritsTheDispatchedMemberIsChargedItsCallback() throws Exception {
        Path dir = Files.createTempDirectory("r1573p");
        try {
            Path cls = dir.resolve("cls");
            write(cls, "r1573/C", consumer("r1573/C", false));
            write(cls, "r1573/Cb", sub("r1573/Cb", FIELD, false, "isIndexed", "()Z", true));
            write(cls, "r1573/Mid", sub("r1573/Mid", FIELD, false, null, null, false));
            write(cls, "r1573/CbMid", sub("r1573/CbMid", "r1573/Mid", false, "isIndexed", "()Z", true));
            write(cls, "r1573/Abs", sub("r1573/Abs", FIELD, true, "isIndexed", "()Z", true));
            write(cls, "r1573/AbsCb", sub("r1573/AbsCb", "r1573/Abs", false, null, null, false));
            write(cls, "r1573/CbGen", sub("r1573/CbGen", FIELD, false, "generateKey", "()V", true));
            write(cls, "r1573/CbPure", sub("r1573/CbPure", FIELD, false, "isIndexed", "()Z", false));
            write(cls, "r1573/CbUnrel", sub("r1573/CbUnrel", FIELD, false, "getVarValue", "(Ljava/lang/String;)Ljava/lang/String;", true));
            Map<String, EffectSet> r = scan(cls);
            for (String fn : new String[] { "add", "addMid", "addAbs", "addGen" })
                assertEquals(Cha.R1573, has(r, "r1573.C." + fn, "FS"), fn + ": the inherited getKey calls back the override (R1573)");
            assertFalse(has(r, "r1573.C.addPure", "FS"), "PURE TWIN: the override it calls back is pure");
            assertFalse(has(r, "r1573.C.addUnrel", "FS"), "CONTROL: getKey never calls back getVarValue");
            assertFalse(has(r, "r1573.C.add", "UNKNOWN"), "a resolution, not a hedge");
        } finally {
            rm(dir);
        }
    }

    @Test
    void aDispatchKeyTheConsumerClassInheritsIsChargedItsCallback() throws Exception {
        for (boolean effect : new boolean[] { true, false }) {
            Path dir = Files.createTempDirectory("r1573d");
            try {
                Path cls = dir.resolve("cls");
                String c = effect ? "r1573/D" : "r1573/DPure";
                write(cls, c, consumer(c, true));
                // effect: Mp overrides setValues with a file stat; the pure twin (its own scan: the D join is not
                // narrowed by the argument, R1565) overrides it purely
                write(cls, "r1573/Mp", sub("r1573/Mp", MP, false, "setValues", "([I)V", effect));
                Map<String, EffectSet> r = scan(cls);
                String fn = c.replace('/', '.') + ".into";
                if (effect) assertEquals(Cha.R1573, has(r, fn, "FS"), "the inherited setPeriod calls back setValues (R1573)");
                else assertFalse(has(r, fn, "FS"), "PURE TWIN");
            } finally {
                rm(dir);
            }
        }
    }
}
