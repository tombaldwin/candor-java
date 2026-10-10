package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * SOUNDNESS R1097 — R1096's override union reads ONE jar's hierarchy, so a surveyed framework member whose override
 * ships in ANOTHER surveyed jar was charged its declared body alone and read ABSENT at a consumer. EXECUTED (spec lane,
 * and again by the java v046 lane on ktor 2.3.12): {@code klen(OutgoingContent c) { return c.getContentLength(); }}
 * handed ktor-server-core's {@code LocalFileContent} returns 12345 for a 12,345-byte file, 7 after it is rewritten,
 * 0 after it is deleted — the filesystem's answer — while the row was ABSENT and {@code deny Fs} / {@code deny Fs
 * Unknown} both exited 0 on v0.40.3 and v0.40.4.
 *
 * <p>The table cannot charge the other jar's body (it does not know that jar is on a consumer's class path), so it
 * records the member with its overriding classes ({@code O} lines) and the engine decides at the call: an overriding
 * class a CHAINED report can see is resolved through its published row; one nobody can see is disclosed as
 * {@code Unknown[dispatch]}. Controls, each on the SAME key as an arm that fires so it can fail: a provably-exact
 * receiver of a non-overriding type, {@code super.init()} (invokespecial), and a member of the same owner with no
 * cross-jar override.
 *
 * <p>Consumer and "overriding jar" are written with ASM, so the test needs no framework jar on its class path: the
 * engine answers an external call from the bundled table by owner, name and descriptor.
 */
class FrameworkCrossJarOverrideR1097Test {

    static final String OC = "io/ktor/http/content/OutgoingContent";
    static final String SERVER_LFC = "io/ktor/server/http/content/LocalFileContent";
    static final String CLIENT_LFC = "io/ktor/client/content/LocalFileContent";
    static final String RES = "org/springframework/core/io/AbstractResource";
    static final String SERVLET = "javax/servlet/GenericServlet";
    static final String LEN = "()Ljava/lang/Long;";

    @Test
    void theTableNamesTheCrossJarOverridersAndOnlyThose() {
        assertEquals(List.of(CLIENT_LFC, SERVER_LFC), FrameworkReach.crossJarOverriders(OC, "getContentLength", LEN),
                "ktor-http's getContentLength is overridden by both LocalFileContent classes, each in another jar");
        assertEquals(List.of("org/springframework/web/context/support/ServletContextResource"),
                FrameworkReach.crossJarOverriders(RES, "isFile", "()Z"));
        assertTrue(FrameworkReach.crossJarOverriders(SERVLET, "init", "()V").contains("org/apache/struts/action/ActionServlet"));
        assertTrue(FrameworkReach.crossJarOverriders(OC, "getContentType", "()Lio/ktor/http/ContentType;").isEmpty(),
                "CONTROL: no override of getContentType in another jar does anything its row lacks");
        // A protected member is reachable from a consumer only on a receiver of the consumer's own subtype.
        assertTrue(FrameworkReach.crossJarOverriders("org/springframework/transaction/support/AbstractPlatformTransactionManager",
                "doCleanupAfterCompletion", "(Ljava/lang/Object;)V").isEmpty());
    }

    static void staticCall(ClassWriter cw, String name, String owner, String member, String mdesc, String ret, boolean iface) {
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(L" + owner + ";)" + ret, null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitMethodInsn(iface ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL, owner, member, mdesc, iface);
        m.visitInsn(ret.equals("V") ? Opcodes.RETURN : ret.equals("Z") ? Opcodes.IRETURN : Opcodes.ARETURN);
        m.visitMaxs(1, 1); m.visitEnd();
    }

    static byte[] consumer() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1097/C", null, "java/lang/Object", null);
        staticCall(cw, "klen", OC, "getContentLength", LEN, "Ljava/lang/Object;", false);
        staticCall(cw, "rfile", RES, "isFile", "()Z", "Z", false);
        staticCall(cw, "sinit", SERVLET, "init", "()V", "V", false);
        staticCall(cw, "qtype", OC, "getContentType", "()Lio/ktor/http/ContentType;", "Ljava/lang/Object;", false);
        // CONTROL: AbstractResource r = new ByteArrayResource(b); r.isFile() — the receiver is provably that type.
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "wexact", "([B)Z", null, null);
        m.visitCode();
        m.visitTypeInsn(Opcodes.NEW, "org/springframework/core/io/ByteArrayResource"); m.visitInsn(Opcodes.DUP);
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "org/springframework/core/io/ByteArrayResource", "<init>", "([B)V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, RES, "isFile", "()Z", false);
        m.visitInsn(Opcodes.IRETURN); m.visitMaxs(3, 1); m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** CONTROL: {@code class Sv extends GenericServlet { public void init() { super.init(); } }} — an exact call. */
    static byte[] servlet() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "r1097/Sv", null, SERVLET, null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "init", "()V", null, null);
        m.visitCode(); m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, SERVLET, "init", "()V", false);
        m.visitInsn(Opcodes.RETURN); m.visitMaxs(1, 1); m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** A stand-in for the overriding jar: {@code owner extends OutgoingContent} whose getContentLength stats a file. */
    static byte[] overrider(String owner) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, owner, null, OC, null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "getContentLength", LEN, null, null);
        m.visitCode();
        m.visitTypeInsn(Opcodes.NEW, "java/io/File"); m.visitInsn(Opcodes.DUP); m.visitLdcInsn("/tmp/r1097");
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "length", "()J", false);
        m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false);
        m.visitInsn(Opcodes.ARETURN); m.visitMaxs(3, 1); m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static boolean has(Map<String, EffectSet> r, String fn, String eff) {
        EffectSet e = r.get(fn);
        return e != null && e.effects().stream().anyMatch(x -> x.name().equals(eff));
    }

    static String why(String fn) {
        var s = AnalysisState.ctx().unknownWhy.get(fn);
        return s == null ? "" : s.toString();
    }

    static void write(Path cls, String internal, byte[] b) throws Exception {
        Path p = cls.resolve(internal + ".class");
        Files.createDirectories(p.getParent());
        Files.write(p, b);
    }

    @Test
    void unchainedTheConsumerDisclosesAndTheControlsDoNot() throws Exception {
        Path dir = Files.createTempDirectory("r1097");
        Config saved = Candor.config;
        try {
            write(dir.resolve("cls"), "r1097/C", consumer());
            write(dir.resolve("cls"), "r1097/Sv", servlet());
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(dir.resolve("cls"));
            assertTrue(has(r, "r1097.C.klen", "UNKNOWN"), "klen was ABSENT over a real file stat");
            assertTrue(why("r1097.C.klen").contains("dispatch:io.ktor.http.content.OutgoingContent.getContentLength"), why("r1097.C.klen"));
            assertTrue(has(r, "r1097.C.rfile", "UNKNOWN"));
            assertTrue(has(r, "r1097.C.sinit", "UNKNOWN"), "the dispatched init() is the same key the super call names");
            assertFalse(has(r, "r1097.C.wexact", "UNKNOWN"), "CONTROL: a provably-exact ByteArrayResource runs no override");
            assertFalse(has(r, "r1097.Sv.init", "UNKNOWN"), "CONTROL: super.init() is invokespecial — exact");
            assertFalse(has(r, "r1097.C.qtype", "UNKNOWN"), "CONTROL: same owner, no cross-jar override");
        } finally {
            Candor.config = saved;
            rm(dir);
        }
    }

    /** Scan the stand-in overriding jar(s) alone, chain the report and its hierarchy sidecar, scan the consumer. */
    static Map<String, EffectSet> chained(Path dir, String... overriders) throws Exception {
        Config saved = Candor.config;
        try {
            for (String o : overriders) write(dir.resolve("lib"), o, overrider(o));
            write(dir.resolve("app"), "r1097/C", consumer());
            Path dep = dir.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(dir.resolve("lib")), dep.toString(), null);
            assertTrue(Files.isRegularFile(dir.resolve("dep.hierarchy.json")), "the chain must carry the hierarchy sidecar");
            Files.createDirectories(dir.resolve(".candor"));
            Files.writeString(dir.resolve(".candor/config"), "deps " + dep + "\n");
            Candor.config = Config.forTarget(dir.resolve("app"));
            return Candor.runScan(dir.resolve("app"));
        } finally {
            Candor.config = saved;
        }
    }

    @Test
    void aChainedOverriderIsResolvedAndAnUnchainedOneStillDisclosed() throws Exception {
        Path one = Files.createTempDirectory("r1097a"), both = Files.createTempDirectory("r1097b");
        try {
            Map<String, EffectSet> r = chained(one, SERVER_LFC);
            assertTrue(has(r, "r1097.C.klen", "FS"), "the chained LocalFileContent's Fs is joined");
            assertTrue(has(r, "r1097.C.klen", "UNKNOWN"), "the client LocalFileContent, not chained, is still disclosed");
            r = chained(both, SERVER_LFC, CLIENT_LFC);
            assertTrue(has(r, "r1097.C.klen", "FS"));
            assertFalse(has(r, "r1097.C.klen", "UNKNOWN"),
                    "RESOLVED: every overriding class is in a chained report, so nothing is left to disclose");
            assertFalse(has(r, "r1097.C.qtype", "FS") || has(r, "r1097.C.qtype", "UNKNOWN"), "CONTROL");
        } finally {
            rm(one);
            rm(both);
        }
    }
}
