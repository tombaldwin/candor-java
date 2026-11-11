package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.InheritedDispatchCallbackR1573Test.ctor;
import static io.poly.candor.InheritedDispatchCallbackR1573Test.fileLength;
import static io.poly.candor.InheritedDispatchCallbackR1573Test.has;
import static io.poly.candor.InheritedDispatchCallbackR1573Test.scan;
import static io.poly.candor.InheritedDispatchCallbackR1573Test.write;
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
 * SOUNDNESS R1574 — a consumer class that implements a framework INTERFACE itself runs that interface's DEFAULT
 * bodies, and a default calls back the consumer's own override. EXECUTED (spring 6.1.10): {@code Cb implements
 * AnnotationMetadata} overriding only {@code getAnnotations()} with an env read, handed to
 * {@code AutoProxyRegistrar.registerBeanDefinitions}, which runs {@code getAnnotationTypes()} — a default that calls
 * {@code this.getAnnotations()}: hits=1, the caller's row was {@code ['Log']}, {@code deny Env} exit 0. R1573's
 * inherited-callback join asked only the class's nearest framework SUPERCLASS ({@code Object} here), and the table had
 * no T lines for interfaces. Cells: the parameter entry ({@code p0:}), the direct call, a project interface between,
 * a project superclass between, the D key ({@code TypeFilter.match} dispatches {@code AnnotationMetadata.hasAnnotation}),
 * and {@code AnnotationMetadata.super.getAnnotationTypes()}. Pure twins (unique names), an over-join control (the
 * class overrides the default itself, which never calls back), and the kill switch.
 */
class InterfaceDefaultCallbackR1574Test {

    static final String AM = "org/springframework/core/type/AnnotationMetadata";
    static final String APR = "org/springframework/context/annotation/AutoProxyRegistrar";
    static final String TF = "org/springframework/core/type/filter/TypeFilter";
    static final String MR = "org/springframework/core/type/classreading/MetadataReader";
    static final String MRF = "org/springframework/core/type/classreading/MetadataReaderFactory";
    static final String GA = "()Lorg/springframework/core/annotation/MergedAnnotations;";
    static final String GAT = "()Ljava/util/Set;";
    static final String REG = "(L" + AM + ";Lorg/springframework/beans/factory/support/BeanDefinitionRegistry;)V";

    /** {@code class name extends sup implements ifaces}; {@code getAnnotations()} with a file stat when {@code effect}
     *  (pure otherwise, none when {@code ga} is false); {@code getAnnotationTypes()} overridden when {@code gat} is
     *  "pure" (returns null) or "super" ({@code AnnotationMetadata.super.getAnnotationTypes()}). */
    static byte[] cls(String name, String sup, int acc, String[] ifaces, boolean ga, boolean effect, String gat) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, acc, name, null, sup, ifaces);
        if ((acc & Opcodes.ACC_INTERFACE) == 0) ctor(cw, sup);
        if (ga) {
            MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "getAnnotations", GA, null, null);
            m.visitCode();
            if (effect) fileLength(m);
            m.visitInsn(Opcodes.ACONST_NULL); m.visitInsn(Opcodes.ARETURN); m.visitMaxs(3, 1); m.visitEnd();
        }
        if (gat != null) {
            MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "getAnnotationTypes", GAT, null, null);
            m.visitCode();
            if (gat.equals("super")) {
                m.visitVarInsn(Opcodes.ALOAD, 0);
                m.visitMethodInsn(Opcodes.INVOKESPECIAL, AM, "getAnnotationTypes", GAT, true);
            } else m.visitInsn(Opcodes.ACONST_NULL);
            m.visitInsn(Opcodes.ARETURN); m.visitMaxs(1, 1); m.visitEnd();
        }
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] impl(String name, boolean effect) {
        return cls(name, "java/lang/Object", Opcodes.ACC_PUBLIC, new String[] { AM }, true, effect, null);
    }

    /** {@code static void name(<arg> c) { new AutoProxyRegistrar().registerBeanDefinitions(c, null); }} */
    static void reg(ClassWriter cw, String name, String arg) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + arg + ";)V", null, null);
        m.visitCode();
        m.visitTypeInsn(Opcodes.NEW, APR); m.visitInsn(Opcodes.DUP);
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, APR, "<init>", "()V", false);
        m.visitVarInsn(Opcodes.ALOAD, 0); m.visitInsn(Opcodes.ACONST_NULL);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, APR, "registerBeanDefinitions", REG, false);
        m.visitInsn(Opcodes.RETURN); m.visitMaxs(4, 1); m.visitEnd();
    }

    /** {@code static void name(<arg> c) { c.getAnnotationTypes(); }} */
    static void direct(ClassWriter cw, String name, String arg) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + arg + ";)V", null, null);
        m.visitCode();
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, arg, "getAnnotationTypes", GAT, false);
        m.visitInsn(Opcodes.POP); m.visitInsn(Opcodes.RETURN); m.visitMaxs(1, 1); m.visitEnd();
    }

    /** {@code static void name(TypeFilter f, MetadataReader r) { f.match(r, null); }} */
    static void match(ClassWriter cw, String name) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + TF + ";L" + MR + ";)V", null, null);
        m.visitCode();
        m.visitVarInsn(Opcodes.ALOAD, 0); m.visitVarInsn(Opcodes.ALOAD, 1); m.visitInsn(Opcodes.ACONST_NULL);
        m.visitMethodInsn(Opcodes.INVOKEINTERFACE, TF, "match", "(L" + MR + ";L" + MRF + ";)Z", true);
        m.visitInsn(Opcodes.POP); m.visitInsn(Opcodes.RETURN); m.visitMaxs(3, 2); m.visitEnd();
    }

    @Test
    void theTableCarriesTheDefaultsCallbackAsAYLineOnly() {
        assertTrue(FrameworkReach.templateMembers(AM, "getAnnotationTypes", GAT, true).contains(">getAnnotations" + GA),
                "the default getAnnotationTypes calls back this.getAnnotations()");
        assertTrue(FrameworkReach.templateMembers(AM, "getAnnotationTypes", GAT).isEmpty(),
                "a T walk never reads a Y line");
        assertTrue(FrameworkReach.templateMembers(APR, "registerBeanDefinitions", REG)
                .contains("p0:" + AM + ".getAnnotationTypes" + GAT), "registerBeanDefinitions dispatches it on its argument");
        assertTrue(FrameworkReach.dispatchMembers(TF, "match", "(L" + MR + ";L" + MRF + ";)Z")
                .contains(AM + ".hasAnnotation(Ljava/lang/String;)Z"), "TypeFilter.match dispatches hasAnnotation");
    }

    @Test
    void aConsumerImplementingTheInterfaceIsChargedTheDefaultsCallback() throws Exception {
        Path dir = Files.createTempDirectory("r1574");
        try {
            Path c = dir.resolve("cls");
            ClassWriter cw = new ClassWriter(0);
            cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1574/C", null, "java/lang/Object", null);
            reg(cw, "reg", "r1574/Cb");                  // the executed cell: the p0: entry
            direct(cw, "direct", "r1574/Cb");            // the direct call
            reg(cw, "regMid", "r1574/CbMid");            // through a project interface
            reg(cw, "regSup", "r1574/CbSup");            // through a project abstract superclass
            reg(cw, "regPure", "r1574/QuietPure");       // PURE TWIN
            direct(cw, "directPure", "r1574/QuietPure"); // PURE TWIN, direct
            reg(cw, "regOwn", "r1574/OwnBody");          // CONTROL: overrides the default itself; it never calls back
            reg(cw, "regSuper", "r1574/CbSuper");        // AnnotationMetadata.super.getAnnotationTypes()
            cw.visitEnd();
            write(c, "r1574/C", cw.toByteArray());
            write(c, "r1574/Cb", impl("r1574/Cb", true));
            write(c, "r1574/Meta", cls("r1574/Meta", "java/lang/Object",
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT, new String[] { AM }, false, false, null));
            write(c, "r1574/CbMid", cls("r1574/CbMid", "java/lang/Object", Opcodes.ACC_PUBLIC, new String[] { "r1574/Meta" }, true, true, null));
            write(c, "r1574/Base", cls("r1574/Base", "java/lang/Object", Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, new String[] { AM }, false, false, null));
            write(c, "r1574/CbSup", cls("r1574/CbSup", "r1574/Base", Opcodes.ACC_PUBLIC, null, true, true, null));
            write(c, "r1574/QuietPure", impl("r1574/QuietPure", false));
            write(c, "r1574/OwnBody", cls("r1574/OwnBody", "java/lang/Object", Opcodes.ACC_PUBLIC, new String[] { AM }, true, true, "pure"));
            write(c, "r1574/CbSuper", cls("r1574/CbSuper", "java/lang/Object", Opcodes.ACC_PUBLIC, new String[] { AM }, true, true, "super"));
            Map<String, EffectSet> r = scan(c);
            for (String fn : new String[] { "reg", "direct", "regMid", "regSup", "regSuper" })
                assertEquals(Cha.R1574, has(r, "r1574.C." + fn, "FS"), fn + ": the default calls back getAnnotations (R1574)");
            assertEquals(Cha.R1574, has(r, "r1574.CbSuper.getAnnotationTypes", "FS"), "I.super.m() runs the default on this");
            assertFalse(has(r, "r1574.C.regPure", "FS"), "PURE TWIN");
            assertFalse(has(r, "r1574.C.directPure", "FS"), "PURE TWIN, direct");
            assertFalse(has(r, "r1574.C.regOwn", "FS"), "CONTROL: the class's own getAnnotationTypes never calls back");
            assertFalse(has(r, "r1574.C.reg", "UNKNOWN"), "a resolution, not a hedge");
        } finally {
            rm(dir);
        }
    }

    @Test
    void aDispatchKeyTheConsumerInheritsFromAnInterfaceDefaultIsChargedItsCallback() throws Exception {
        for (boolean effect : new boolean[] { true, false }) {
            Path dir = Files.createTempDirectory("r1574d");
            try {
                Path c = dir.resolve("cls");
                String con = effect ? "r1574/D" : "r1574/DQuiet";
                ClassWriter cw = new ClassWriter(0);
                cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, con, null, "java/lang/Object", null);
                match(cw, "m");
                cw.visitEnd();
                write(c, con, cw.toByteArray());
                // the pure twin is its own scan: the D join is not narrowed by the argument (R1565)
                write(c, effect ? "r1574/Md" : "r1574/MdQuiet", impl(effect ? "r1574/Md" : "r1574/MdQuiet", effect));
                Map<String, EffectSet> r = scan(c);
                String fn = con.replace('/', '.') + ".m";
                if (effect) assertEquals(Cha.R1574, has(r, fn, "FS"), "the default hasAnnotation calls back getAnnotations (R1574)");
                else assertFalse(has(r, fn, "FS"), "PURE TWIN");
            } finally {
                rm(dir);
            }
        }
    }
}
