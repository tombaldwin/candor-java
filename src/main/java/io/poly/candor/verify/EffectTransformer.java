package io.poly.candor.verify;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.Set;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ⟨verify⟩ The bytecode instrumentation of the JVM honesty oracle. For each class in the INCLUDE SET (the
 * project classes candor's report names — passed from the CLI), it rewrites every method so that, right
 * BEFORE each effect-bearing JDK call (per {@link EffectMap}), it inserts a
 * {@code Trace.emit(<enclosing-fn>, <effect>)}.
 *
 * <p>ATTRIBUTION is the ENCLOSING method, resolved at transform time from the class + method being visited
 * — deterministic, no stack unwinding. {@code qual = <dotted class>.<method name>}, which matches candor's
 * report {@code fn} format ({@code pkg.Class.method}). Only INCLUDE-SET classes are touched; the JDK, deps,
 * and the verify package itself return unchanged so the target runs at full speed everywhere else.
 */
final class EffectTransformer implements ClassFileTransformer {

    private final Set<String> includeDotted; // dotted class names candor's report covers

    EffectTransformer(Set<String> includeDotted) {
        this.includeDotted = includeDotted;
    }

    @Override
    public byte[] transform(ClassLoader loader, String internalName, Class<?> classBeingRedefined,
            ProtectionDomain pd, byte[] classfileBuffer) {
        if (internalName == null) return null;
        // Never instrument the oracle's own runtime — a self-emit would be nonsense (and could recurse).
        if (internalName.startsWith("io/poly/candor/verify/")) return null;
        String dotted = internalName.replace('/', '.');
        if (!includeDotted.contains(dotted)) return null; // JDK / deps / anything the report doesn't name

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            // COMPUTE_FRAMES rebuilds stack-map frames after we insert instructions; COMPUTE_MAXS the
            // max stack/locals. Both are needed because we push two string constants before each call.
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
            cr.accept(new EmitInjector(cw, dotted), ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Throwable t) {
            // Instrumentation failure of one class must not abort class loading — leave it unchanged (that
            // class's effects simply go unwitnessed: disclosed by the coverage count, never a false verdict).
            return null;
        }
    }

    /** ClassVisitor that wraps each method with an {@link EmitMethod}. */
    private static final class EmitInjector extends ClassVisitor {
        private final String dottedClass;

        EmitInjector(ClassVisitor cv, String dottedClass) {
            super(Opcodes.ASM9, cv);
            this.dottedClass = dottedClass;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null) return null;
            // qual = the candor `fn` of the ENCLOSING method: <dotted class>.<method name>. For a ctor the
            // name is `<init>` (candor may not list it — those emits just won't attribute, which is fine).
            String qual = dottedClass + "." + name;
            return new EmitMethod(mv, qual);
        }
    }

    /** MethodVisitor that, before each effect-bearing call, injects the Trace.emit(fn, effect). */
    private static final class EmitMethod extends MethodVisitor {
        private final String qual;

        EmitMethod(MethodVisitor mv, String qual) {
            super(Opcodes.ASM9, mv);
            this.qual = qual;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            String effect = EffectMap.effectOf(owner, name);
            if (effect != null) {
                // Inject BEFORE the original call: push (fn, effect), invoke Trace.emit, THEN the call.
                super.visitLdcInsn(qual);
                super.visitLdcInsn(effect);
                super.visitMethodInsn(Opcodes.INVOKESTATIC, "io/poly/candor/verify/Trace", "emit",
                        "(Ljava/lang/String;Ljava/lang/String;)V", false);
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }
}
