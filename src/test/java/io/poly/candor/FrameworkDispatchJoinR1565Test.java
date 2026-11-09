package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * SOUNDNESS R1565/R1569 — a framework body dispatches on a receiver the CONSUMER supplies: a field
 * ({@code EventListenerWrapper.listener.hashCode()}), a value a getter returns ({@code PreciseDurationField.getType().hashCode()}),
 * or a parameter the body wraps into an object it creates ({@code AggregationSpELExpression.toDocument(ctx)} ->
 * {@code ctx.getReference(..)}). The framework table's scan sees only the jar's own implementers, which are pure, and since
 * the 2026-11-07 regeneration a consumer whose implementer reads a file (EXECUTED, 15 members) read the call pure. The
 * table's D lines carry the dispatched members, and {@link Cha#frameworkDispatchJoin} joins the consumer's implementers of
 * them, as a chained row's {@code dispatchesOn} is joined. Controls: the same calls with a PURE implementer, in a scan of
 * their own (the join is over the whole scan's implementers, so a control sharing the effectful one's scan would not
 * discriminate).
 */
class FrameworkDispatchJoinR1565Test {

    static final String DFT = "org/joda/time/DurationFieldType";
    static final String PDF = "org/joda/time/field/PreciseDurationField";
    static final String CEL = "org/ehcache/event/CacheEventListener";
    static final String ELW = "org/ehcache/core/events/EventListenerWrapper";
    static final String AOC = "org/springframework/data/mongodb/core/aggregation/AggregationOperationContext";
    static final String ASE = "org/springframework/data/mongodb/core/aggregation/AggregationSpELExpression";
    static final String REF = "org/springframework/data/mongodb/core/aggregation/ExposedFields$FieldReference";

    static void fileLength(MethodVisitor m) {
        m.visitTypeInsn(Opcodes.NEW, "java/io/File"); m.visitInsn(Opcodes.DUP); m.visitLdcInsn("/etc/hosts");
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "length", "()J", false);
        m.visitInsn(Opcodes.L2I);
    }

    /** {@code class name extends|implements sup} with one member {@code member+desc} that stats a file (or not). */
    static byte[] impl(String name, String sup, boolean iface, String member, String desc, boolean effect) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, iface ? "java/lang/Object" : sup, iface ? new String[] { sup } : null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, member, desc, null, null);
        m.visitCode();
        if (effect) fileLength(m); else m.visitInsn(Opcodes.ICONST_1);
        if (desc.endsWith(")I") || desc.endsWith(")Z")) m.visitInsn(Opcodes.IRETURN);
        else { m.visitInsn(Opcodes.POP); m.visitInsn(Opcodes.ACONST_NULL); m.visitInsn(Opcodes.ARETURN); }
        m.visitMaxs(3, 3); m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static void call(ClassWriter cw, String name, String owner, String member, String mdesc, String argDesc) {
        String ret = mdesc.substring(mdesc.indexOf(')') + 1);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + owner + ";" + argDesc + ")" + ret, null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
        if (!argDesc.isEmpty()) m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, owner, member, mdesc, false);
        m.visitInsn(ret.equals("I") || ret.equals("Z") ? Opcodes.IRETURN : Opcodes.ARETURN);
        m.visitMaxs(2, 2); m.visitEnd();
    }

    static byte[] consumer() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1565/C", null, "java/lang/Object", null);
        call(cw, "viaPrecise", PDF, "hashCode", "()I", "");                       // getType().hashCode()
        call(cw, "viaWrapper", ELW, "hashCode", "()I", "");                       // listener.hashCode()
        call(cw, "viaWrapperEq", ELW, "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/Object;");
        call(cw, "viaToDocument", ASE, "toDocument", "(L" + AOC + ";)Lorg/bson/Document;", "L" + AOC + ";");   // R1569
        cw.visitEnd();
        return cw.toByteArray();
    }

    static Map<String, EffectSet> scan(boolean effect) throws Exception {
        Path dir = Files.createTempDirectory("r1565");
        Config saved = Candor.config;
        try {
            Path cls = dir.resolve("cls");
            write(cls, "r1565/C", consumer());
            write(cls, "r1565/T", impl("r1565/T", DFT, false, "hashCode", "()I", effect));
            write(cls, "r1565/L", impl("r1565/L", CEL, true, "hashCode", "()I", effect));
            write(cls, "r1565/E", impl("r1565/E", CEL, true, "equals", "(Ljava/lang/Object;)Z", effect));
            write(cls, "r1565/X", impl("r1565/X", AOC, true, "getReference", "(Ljava/lang/String;)L" + REF + ";", effect));
            Candor.config = Config.empty();
            return Candor.runScan(cls);
        } finally {
            Candor.config = saved;
            rm(dir);
        }
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
    void theTableNamesTheDispatchedMembers() {
        assertTrue(FrameworkReach.dispatchMembers(PDF, "hashCode", "()I").contains(DFT + ".hashCode()I"),
                "PreciseDurationField.hashCode runs getType().hashCode()");
        assertTrue(FrameworkReach.dispatchMembers(ELW, "hashCode", "()I").contains(CEL + ".hashCode()I"),
                "EventListenerWrapper.hashCode runs listener.hashCode()");
        assertTrue(FrameworkReach.dispatchMembers(ASE, "toDocument", "(L" + AOC + ";)Lorg/bson/Document;")
                .contains(AOC + ".getReference(Ljava/lang/String;)L" + REF + ";"),
                "toDocument(ctx) wraps ctx and calls getReference on it (R1569)");
        assertTrue(FrameworkReach.dispatchMembers("org/joda/time/Period", "hashCode", "()I").contains(DFT + ".hashCode()I"),
                "an inherited member (Period.hashCode is AbstractPeriod's) is found up the H lines");
        assertTrue(FrameworkReach.dispatchMembers("kotlinx/coroutines/Dispatchers", "getMain", "()Lkotlinx/coroutines/MainCoroutineDispatcher;")
                .contains("kotlinx/coroutines/internal/MainDispatcherFactory.createDispatcher(Ljava/util/List;)Lkotlinx/coroutines/MainCoroutineDispatcher;"),
                "a class initialiser is followed: MainDispatcherLoader.<clinit> loads the consumer's factory through ServiceLoader");
        assertFalse(FrameworkReach.dispatchMembers("com/fasterxml/jackson/core/base/GeneratorBase", "close", "()V").stream()
                .anyMatch(k -> k.startsWith("com/fasterxml/jackson/core/util/JacksonFeature.")),
                "CONTROL: JsonGenerator.<clinit> hands fromDefaults its own enum's values()");
        assertTrue(FrameworkReach.dispatchMembers(PDF, "getUnitMillis", "()J").isEmpty(),
                "CONTROL: a field accessor dispatches on nothing");
        assertFalse(FrameworkReach.dispatchMembers("org/joda/time/base/AbstractPeriod", "hashCode", "()I")
                .contains("org/joda/time/base/AbstractPeriod.getValue(I)I"),
                "CONTROL: a callback on `this` is R1511's T line, not a D key");
    }

    @Test
    void aConsumerImplementerTheFrameworkBodyDispatchesOnIsCharged() throws Exception {
        // the expectation is the BEHAVIOUR, not the switch: under CANDOR_R1565=0 (a measurement arm) the test is skipped,
        // never turned into an assertion that the call is silent
        assumeTrue(Cha.R1565, "CANDOR_R1565=0: the join is switched off");
        Map<String, EffectSet> r = scan(true);
        for (String fn : new String[] { "viaPrecise", "viaWrapper", "viaWrapperEq", "viaToDocument" })
            assertTrue(has(r, "r1565.C." + fn, "FS"), fn + ": the framework body runs the consumer's implementer");
    }

    @Test
    void aPureImplementerAddsNothing() throws Exception {
        Map<String, EffectSet> r = scan(false);
        for (String fn : new String[] { "viaPrecise", "viaWrapper", "viaWrapperEq", "viaToDocument" }) {
            assertFalse(has(r, "r1565.C." + fn, "FS"), "CONTROL " + fn + ": the implementer performs nothing");
            assertFalse(has(r, "r1565.C." + fn, "UNKNOWN"), "CONTROL " + fn + ": a resolution, not a hedge");
        }
    }

    static final String ACR = "org/springframework/beans/factory/support/AutowireCandidateResolver";
    static final String BDH = "org/springframework/beans/factory/config/BeanDefinitionHolder";
    static final String DD = "org/springframework/beans/factory/config/DependencyDescriptor";

    /** R1565 review, shape (a): a project class that IMPLEMENTS a framework interface and inherits its default body.
     *  `AutowireCandidateResolver.isAutowireCandidate(holder, descriptor)` runs `holder.getBeanDefinition().isAutowireCandidate()`
     *  (EXECUTED: one read through a file-reading `GenericBeanDefinition` subclass). The lookup used to walk superclasses only. */
    @Test
    void anInheritedInterfaceDefaultIsLookedUpToo() throws Exception {
        assumeTrue(Cha.R1565, "CANDOR_R1565=0: the join is switched off");
        Path dir = Files.createTempDirectory("r1565a");
        Config saved = Candor.config;
        try {
            Path cls = dir.resolve("cls");
            ClassWriter cw = new ClassWriter(0);
            cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1565/R", null, "java/lang/Object", new String[] { ACR });
            cw.visitEnd();
            write(cls, "r1565/R", cw.toByteArray());
            write(cls, "r1565/B", impl("r1565/B", "org/springframework/beans/factory/support/GenericBeanDefinition", false,
                    "isAutowireCandidate", "()Z", true));
            cw = new ClassWriter(0);
            cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1565/U", null, "java/lang/Object", null);
            MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "viaDefault", "(Lr1565/R;L" + BDH + ";)Z", null, null);
            m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0); m.visitVarInsn(Opcodes.ALOAD, 1); m.visitInsn(Opcodes.ACONST_NULL);
            m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "r1565/R", "isAutowireCandidate", "(L" + BDH + ";L" + DD + ";)Z", false);
            m.visitInsn(Opcodes.IRETURN); m.visitMaxs(3, 2); m.visitEnd();
            cw.visitEnd();
            write(cls, "r1565/U", cw.toByteArray());
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(has(r, "r1565.U.viaDefault", "FS"), "the interface default runs the consumer's BeanDefinition");
        } finally {
            Candor.config = saved;
            rm(dir);
        }
    }
}
