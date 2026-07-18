package io.poly.candor.verify;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import io.poly.candor.Cha;

/**
 * ⟨verify⟩ The bytecode instrumentation of the JVM honesty oracle. For each class in the INCLUDE SET (the
 * project classes candor analyzed — passed from the CLI), it rewrites every method so that, right BEFORE each
 * effect-bearing JDK call (per {@link EffectMap}), it inserts a {@code Trace.emit(<enclosing-fn>, <effect>)}.
 *
 * <p>ATTRIBUTION is the ENCLOSING method, resolved at transform time from the class + method being visited —
 * deterministic, no stack unwinding. The emit key is candor's report {@code fn} qual: {@code pkg.Class.method}
 * for a uniquely-named method, and — for an OVERLOADED name — {@code pkg.Class.method(paramTypes)} exactly as
 * {@link Cha#methodId} forms it, so an overloaded effectful method still matches its report entry (a bare-name
 * key would miss it and read as a false cardinal-sin VIOLATION). The per-class descriptor set that drives the
 * disambiguation is collected from the bytecode in a pre-pass (the agent has no scan context). Only
 * INCLUDE-SET classes are touched; the JDK, deps, and the verify package itself return unchanged.
 */
final class EffectTransformer implements ClassFileTransformer {

    private final Set<String> includeDotted; // dotted class names candor analyzed (from the callgraph universe)

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
        if (!includeDotted.contains(dotted)) return null; // JDK / deps / anything candor didn't analyze

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            // Pre-pass: the distinct descriptors declared under each method NAME in THIS class — the same set
            // candor's overload index holds for the declaring class, so Cha.methodId keys agree with the report.
            Map<String, Set<String>> descsByName = new HashMap<>();
            cr.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
                    // Match candor's scan-side overload index (Candor.java): EXCLUDE compiler-generated
                    // bridge/synthetic forwarders. A generic/covariant override (e.g. executeTask(T) beside
                    // the erased bridge executeTask(Object)) is a UNIQUE method — counting the bridge would
                    // split it into a param-qualified id here while the report keeps it bare, so the emitted
                    // key would miss its report entry and manufacture a spurious cardinal-sin violation.
                    if ((a & (Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC)) != 0) return null;
                    descsByName.computeIfAbsent(n, k -> new HashSet<>()).add(d);
                    return null;
                }
            }, ClassReader.SKIP_CODE);
            // COMPUTE_FRAMES rebuilds stack-map frames after we insert instructions; COMPUTE_MAXS the max
            // stack/locals. getCommonSuperClass is overridden to resolve via the TARGET application's
            // classloader (not the agent's) and to fall back to Object — otherwise a common-supertype lookup
            // of an app class the agent's loader can't see throws, the whole class is left uninstrumented, and
            // its runtime effects go unwitnessed (a silent false all-clear). Object is always a valid common
            // supertype, so the fallback yields verifiable (if slightly loose) frames rather than aborting.
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    try {
                        Class<?> c1 = Class.forName(type1.replace('/', '.'), false, loader);
                        Class<?> c2 = Class.forName(type2.replace('/', '.'), false, loader);
                        if (c1.isAssignableFrom(c2)) return type1;
                        if (c2.isAssignableFrom(c1)) return type2;
                        if (c1.isInterface() || c2.isInterface()) return "java/lang/Object";
                        do { c1 = c1.getSuperclass(); } while (c1 != null && !c1.isAssignableFrom(c2));
                        return c1 == null ? "java/lang/Object" : c1.getName().replace('.', '/');
                    } catch (Throwable t) {
                        return "java/lang/Object";
                    }
                }
            };
            cr.accept(new EmitInjector(cw, dotted, descsByName), ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Throwable t) {
            // Instrumentation failure of one class must not abort class loading — leave it unchanged (that
            // class's effects simply go unwitnessed: disclosed by the coverage count, never a false verdict).
            return null;
        }
    }

    /** ClassVisitor that wraps each method with an {@link EmitMethod}, keyed by its overload-disambiguated qual. */
    private static final class EmitInjector extends ClassVisitor {
        private final String dottedClass;
        private final Map<String, Set<String>> descsByName;

        EmitInjector(ClassVisitor cv, String dottedClass, Map<String, Set<String>> descsByName) {
            super(Opcodes.ASM9, cv);
            this.dottedClass = dottedClass;
            this.descsByName = descsByName;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null) return null;
            // qual = the candor `fn` of the ENCLOSING method — bare `Class.method`, or `Class.method(params)`
            // for an overloaded name, matching Cha.methodId exactly. For a ctor the name is `<init>` (candor
            // may not list it — those emits just won't attribute, which is fine).
            String qual = Cha.methodId(dottedClass, name, descriptor, descsByName.get(name));
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
