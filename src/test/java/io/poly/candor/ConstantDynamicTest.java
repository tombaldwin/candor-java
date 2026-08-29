package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Teeth for a CARDINAL SIN: a {@code CONSTANT_Dynamic} (condy) constant is a DIFFERENT bytecode form
 * from {@code invokedynamic} — ASM surfaces it as an {@link org.objectweb.asm.tree.LdcInsnNode} whose
 * {@code cst} is a {@link ConstantDynamic}, never as an
 * {@link org.objectweb.asm.tree.InvokeDynamicInsnNode} — and the per-instruction dispatch in
 * {@code Candor#analyze} only ever reached {@code handleInvokeDynamic}. A condy `ldc` fell through
 * every branch silently: no edge, no effect, and (because absence from {@code functions[]} means PURE
 * — spec §2 rule 3) the calling method vanished from a report entirely, never {@code Unknown}, never
 * {@code unresolved}. A hand-built bootstrap that genuinely execs a subprocess at resolution time
 * (verified with a real {@code defineHiddenClass}+invoke runtime probe, separate from this suite)
 * reproduced the silence; {@code deny Exec} passed it with "no violations", exit 0.
 *
 * <p>CALIBRATION (disproving the first hypothesis): the bootstrap owner used below
 * ({@code "G"}, this fixture's own class) is not a member of {@link Rules#STRUCTURAL_INDY_BSM} by any
 * reading — so if the cause were an over-broad allowlist letting an in-allowlist owner through, this
 * owner would already have been caught and disclosed Unknown pre-fix. It was NOT: the silence
 * persisted identically, because {@code handleInvokeDynamic}'s allowlist check never ran at all for a
 * condy site — proving the cause is the missing dispatch branch, not the allowlist's contents.
 *
 * <p>Control: a condy whose bootstrap IS a JVM structural condy factory
 * ({@code java.lang.invoke.ConstantBootstraps}, already in {@link Rules#STRUCTURAL_INDY_BSM} for the
 * indy case) must NOT gain a fabricated Unknown — the fix reuses that one decision for both bytecode
 * forms rather than writing a second one that could disagree.
 */
class ConstantDynamicTest {

    /** Emit a class `G` with one static method whose body is a single `ldc <condy>` + `areturn`, where
     *  the condy's bootstrap is {@code (bsmOwner, bsmName)} with the standard condy bootstrap descriptor
     *  {@code (Lookup, String, Class)Object}. */
    private static byte[] classWithCondy(String bsmOwner, String bsmName) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "G", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "doWork",
                "()Ljava/lang/Object;", null, null);
        mv.visitCode();
        Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, bsmOwner, bsmName,
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;",
                false);
        mv.visitLdcInsn(new ConstantDynamic("x", "Ljava/lang/Object;", bsm));
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static EffectSet scanSingleClass(byte[] cls) throws Exception {
        Path dir = Files.createTempDirectory("candor-condy");
        try {
            Files.write(dir.resolve("G.class"), cls);
            Map<String, EffectSet> r = Candor.runScan(dir);
            return r.getOrDefault("G.doWork", EffectSet.empty());
        } finally {
            try (Stream<Path> s = Files.walk(dir)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void nonStructuralCondyDisclosesUnknown() throws Exception {
        // "G" (this fixture's own class) is emphatically NOT in STRUCTURAL_INDY_BSM — the calibration
        // case: an allowlist-outside owner, proving the silence was never about allowlist membership.
        EffectSet eff = scanSingleClass(classWithCondy("G", "boot"));
        assertTrue(eff.toNames().contains("Unknown"),
                "a condy whose bootstrap is not a known-structural factory must read Unknown "
                        + "(the calling method must not vanish from the report), got " + eff);
    }

    @Test
    void structuralCondyDoesNotFabricateUnknown() throws Exception {
        // A genuine JVM condy factory (nullConstant) is provably inert -> must stay quiet, exactly as
        // the indy case already treats this owner. Reused decision, not a second one.
        EffectSet eff = scanSingleClass(classWithCondy("java/lang/invoke/ConstantBootstraps", "nullConstant"));
        assertFalse(eff.toNames().contains("Unknown"),
                "a structural condy factory (ConstantBootstraps) must NOT fabricate Unknown, got " + eff);
    }

    @Test
    void nonCondyClassStaysUnaffected() throws Exception {
        // Anti-regression: a class with no condy/indy at all must stay pure (the new branch must not
        // fire, or fabricate anything, off a plain ldc of a String/int).
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "G", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "doWork",
                "()Ljava/lang/Object;", null, null);
        mv.visitCode();
        mv.visitLdcInsn("plain-string-constant");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        EffectSet eff = scanSingleClass(cw.toByteArray());
        assertTrue(eff.isEmpty(), "a plain String ldc must stay pure, got " + eff);
    }
}
