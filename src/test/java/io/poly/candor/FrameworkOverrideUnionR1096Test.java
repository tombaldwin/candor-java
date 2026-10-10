package io.poly.candor;

import io.poly.candor.model.Effect;
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
 * SOUNDNESS R1096 — the κ framework table resolved a consumer's call to the DECLARED body only, so a surveyed same-jar
 * override was never unioned. EXECUTED (spring-batch-infrastructure 5.1.2): {@code viaBase(AbstractSqlPagingQueryProvider
 * p, DataSource ds) { p.init(ds); }} handed a {@code DerbyPagingQueryProvider} reaches {@code DataSource.getConnection};
 * on v0.40.3 {@code deny Db} exited 0 there and 1 on the {@code DerbyPagingQueryProvider} spelling. The generator
 * ({@code FrameworkReachGen#overriders}) now unions the same-jar overrides at a consumer-facing member; the CONTROL is
 * {@code generateFirstPageQuery(int)}, whose surveyed overrides only build a String and which stays uncharged.
 *
 * <p>And the disclosure it must not cost: a member whose declared body the scan read only as Unknown, now charged
 * through an override, keeps its {@code U} line, and the engine applies it beside the charge (before this the generator's
 * "charged rows carry no hedge" rule would have dropped every one). And a member whose overrides are more than
 * {@code Rules.CHA_FANOUT_LIMIT} — the engine's own CHA bound — is disclosed ({@code A}), not charged with all of them.
 *
 * <p>The consumer is written with ASM, so the test needs no framework jar on its classpath: the engine answers an
 * external call from the table by owner, name and descriptor.
 */
class FrameworkOverrideUnionR1096Test {

    static final String PROVIDER = "org/springframework/batch/item/database/support/AbstractSqlPagingQueryProvider";
    static final String STREAM = "org/springframework/batch/item/ItemStreamReader";
    static final String JODA = "org/joda/time/field/BaseDateTimeField";

    @Test
    void theTableUnionsSameJarOverrides() {
        assertTrue(FrameworkReach.charges(PROVIDER, "init", "(Ljavax/sql/DataSource;)V").contains(Effect.DB),
                "AbstractSqlPagingQueryProvider.init reaches Db through DerbyPagingQueryProvider.init (and its siblings)");
        assertTrue(FrameworkReach.charges(PROVIDER, "generateFirstPageQuery", "(I)Ljava/lang/String;").isEmpty(),
                "CONTROL: every surveyed override of generateFirstPageQuery only builds a String");
        assertEquals("U", FrameworkReach.hedgeKind(STREAM, "open", "(Lorg/springframework/batch/item/ExecutionContext;)V"),
                "an override-only charge keeps the declared body's U disclosure");
        assertFalse(FrameworkReach.charges(STREAM, "open", "(Lorg/springframework/batch/item/ExecutionContext;)V").isEmpty());
        // BROAD: BaseDateTimeField.add(long,int) has more overrides than Rules.CHA_FANOUT_LIMIT and some do what the
        // declared body does not — disclosed (A, dispatch), not smeared into the row, exactly as the engine's own CHA.
        assertEquals("A", FrameworkReach.hedgeKind(JODA, "add", "(JI)J"));
    }

    static byte[] consumer() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1096/C", null, "java/lang/Object", null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "viaBase", "(L" + PROVIDER + ";Ljavax/sql/DataSource;)V", null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0); m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, PROVIDER, "init", "(Ljavax/sql/DataSource;)V", false);
        m.visitInsn(Opcodes.RETURN); m.visitMaxs(2, 2); m.visitEnd();
        m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "control", "(L" + PROVIDER + ";)Ljava/lang/String;", null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0); m.visitIntInsn(Opcodes.BIPUSH, 10);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, PROVIDER, "generateFirstPageQuery", "(I)Ljava/lang/String;", false);
        m.visitInsn(Opcodes.ARETURN); m.visitMaxs(2, 1); m.visitEnd();
        m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "streamOpen", "(L" + STREAM + ";Lorg/springframework/batch/item/ExecutionContext;)V", null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0); m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEINTERFACE, STREAM, "open", "(Lorg/springframework/batch/item/ExecutionContext;)V", true);
        m.visitInsn(Opcodes.RETURN); m.visitMaxs(2, 2); m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static boolean has(Map<String, EffectSet> r, String fn, String eff) {
        EffectSet e = r.get(fn);
        return e != null && e.effects().stream().anyMatch(x -> x.name().equals(eff));
    }

    @Test
    void aConsumerOfTheBaseTypeIsChargedAndTheControlIsNot() throws Exception {
        Path dir = Files.createTempDirectory("r1096");
        Config saved = Candor.config;
        try {
            Files.createDirectories(dir.resolve("cls/r1096"));
            Files.write(dir.resolve("cls/r1096/C.class"), consumer());
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(dir.resolve("cls"));
            assertTrue(has(r, "r1096.C.viaBase", "DB"), "p.init(ds) on the base type can run DerbyPagingQueryProvider.init");
            assertFalse(has(r, "r1096.C.control", "DB") || has(r, "r1096.C.control", "FS") || has(r, "r1096.C.control", "NET"),
                    "CONTROL: no override of generateFirstPageQuery does I/O");
            assertTrue(has(r, "r1096.C.streamOpen", "UNKNOWN"), "the U disclosure stands beside the override charge");
        } finally {
            Candor.config = saved;
            rm(dir);
        }
    }
}
