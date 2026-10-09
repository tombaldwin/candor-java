package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * SOUNDNESS R1092 — JDK 25 callback invokers in already-granted packages read PURE.
 *
 * <p>{@code ScopedValue.where(sv, v).call(op)} (JDK 25, JEP 506: {@code ScopedValue.CallableOp}) and
 * {@code StableValue.orElseSet(supplier)} (JDK 25 preview) with an OPAQUE argument run that argument synchronously.
 * EXECUTED on Temurin 25.0.4 (the harness is {@code Run25} in the lane's scratch): both wrote their file, and
 * published v0.40.3 read both units pure ({@code deny Unknown} 0). Two causes, both closed:
 * <ul>
 *   <li>the invoking-HOF and SAM indexes were the build JDK's (R1094), which knew neither member — pinning them to a
 *       Temurin 17/21/25 union supplies both facts, and that alone discloses {@code orElseSet};
 *   <li>{@code opaqueFunctionalToHof} still gated on the hand list {@code isFunctionalIface}, which does not name
 *       {@code ScopedValue.CallableOp}; where the index has proven THIS argument invoked, the index is now the gate.
 * </ul>
 * The fixture is written with ASM because the test JDK (21) cannot compile JDK 25 API; the engine reads bytecode and
 * never loads the referenced classes. The CONTROL is the JDK 21 spelling {@code Carrier.run(Runnable)}, which already
 * disclosed.
 */
class Jdk25CallbackR1092Test {

    static final String SV = "java/lang/ScopedValue", CARRIER = "java/lang/ScopedValue$Carrier",
            OP = "java/lang/ScopedValue$CallableOp", STABLE = "java/lang/StableValue", SUP = "java/util/function/Supplier";

    static byte[] fixture() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "r1092/J25", null, "java/lang/Object", null);
        // static Object callOp(ScopedValue sv, CallableOp op) { return ScopedValue.where(sv, "v").call(op); }
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "callOp",
                "(L" + SV + ";L" + OP + ";)Ljava/lang/Object;", null, null);
        m.visitCode();
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitLdcInsn("v");
        m.visitMethodInsn(Opcodes.INVOKESTATIC, SV, "where", "(L" + SV + ";Ljava/lang/Object;)L" + CARRIER + ";", false);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, CARRIER, "call", "(L" + OP + ";)Ljava/lang/Object;", false);
        m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(3, 2);
        m.visitEnd();
        // static void runRunnable(ScopedValue sv, Runnable r) { ScopedValue.where(sv, "v").run(r); }  -- the control
        m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "runRunnable", "(L" + SV + ";Ljava/lang/Runnable;)V", null, null);
        m.visitCode();
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitLdcInsn("v");
        m.visitMethodInsn(Opcodes.INVOKESTATIC, SV, "where", "(L" + SV + ";Ljava/lang/Object;)L" + CARRIER + ";", false);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, CARRIER, "run", "(Ljava/lang/Runnable;)V", false);
        m.visitInsn(Opcodes.RETURN);
        m.visitMaxs(3, 2);
        m.visitEnd();
        // static Object orElseSet(StableValue v, Supplier s) { return v.orElseSet(s); }
        m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "stableSet", "(L" + STABLE + ";L" + SUP + ";)Ljava/lang/Object;", null, null);
        m.visitCode();
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEINTERFACE, STABLE, "orElseSet", "(L" + SUP + ";)Ljava/lang/Object;", true);
        m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(2, 2);
        m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static boolean unknown(Map<String, EffectSet> r, String fn) {
        EffectSet e = r.get(fn);
        return e != null && e.effects().stream().anyMatch(x -> x.name().equals("UNKNOWN"));
    }

    @Test
    void jdk25CallbackInvokersWithAnOpaqueArgumentDisclose() throws Exception {
        Path dir = Files.createTempDirectory("r1092");
        Config saved = Candor.config;
        try {
            Files.createDirectories(dir.resolve("cls/r1092"));
            Files.write(dir.resolve("cls/r1092/J25.class"), fixture());
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(dir.resolve("cls"));
            assertTrue(unknown(r, "r1092.J25.runRunnable"), "CONTROL: the Runnable spelling already disclosed");
            assertTrue(unknown(r, "r1092.J25.callOp"), "ScopedValue.Carrier.call(CallableOp) runs the op — must disclose");
            assertTrue(unknown(r, "r1092.J25.stableSet"), "StableValue.orElseSet(Supplier) runs the supplier — must disclose");
        } finally {
            Candor.config = saved;
            rm(dir);
        }
    }
}
