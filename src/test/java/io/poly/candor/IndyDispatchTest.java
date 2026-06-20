package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Teeth for the dynamic-language invokedynamic rule. Compiled DYNAMIC Groovy (the default, non-
 * {@code @CompileStatic} mode) emits an {@code invokedynamic} for every method call whose bootstrap is
 * {@code org.codehaus.groovy.vmplugin.v8.IndyInterface.bootstrap} — and whose {@code bsmArgs} carry only
 * a call-NAME string, no resolvable target handle. The analyzer can't follow that to a body, so the call
 * is OPAQUE like reflection and must read {@code Unknown}, never silent-pure. We can't depend on a Groovy
 * compiler in CI, so we synthesize the exact bytecode shape with ASM and drive a real scan.
 *
 * Control: an {@code invokedynamic} whose bootstrap IS a JVM structural factory (LambdaMetafactory etc.)
 * must NOT raise Unknown — that path is precise (or conventionally pure), so a structural indy stays clean.
 */
class IndyDispatchTest {

    /** Emit a class `G` with one method that performs a single invokedynamic with the given bootstrap. */
    private static byte[] classWithIndy(String bsmOwner) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "G", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "doWork", "()V", null, null);
        mv.visitCode();
        // The CallSite-bootstrap descriptor every indy bootstrap shares.
        Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, bsmOwner, "bootstrap",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                        + "[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
                false);
        // Groovy passes a call-name string + an int flags constant as bsmArgs (no method handle).
        mv.visitInvokeDynamicInsn("readAllBytes", "()V", bsm, "readAllBytes", Integer.valueOf(0));
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 1);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static EffectSet scanSingleClass(byte[] cls) throws Exception {
        Path dir = Files.createTempDirectory("candor-indy");
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
    void dynamicLanguageIndyReadsUnknown() throws Exception {
        // Groovy's dynamic-dispatch bootstrap → opaque → Unknown (was silent-pure: empty effect set).
        EffectSet eff = scanSingleClass(classWithIndy("org/codehaus/groovy/vmplugin/v8/IndyInterface"));
        assertTrue(eff.toNames().contains("Unknown"),
                "a dynamic-language invokedynamic must read Unknown, got " + eff);
    }

    @Test
    void structuralIndyDoesNotFabricateUnknown() throws Exception {
        // A JVM structural factory bootstrap (string concat here) is precise/pure → no Unknown fabricated.
        EffectSet eff = scanSingleClass(classWithIndy("java/lang/invoke/StringConcatFactory"));
        assertFalse(eff.toNames().contains("Unknown"),
                "a structural-factory invokedynamic must NOT fabricate Unknown, got " + eff);
    }

    /** A method REFERENCE to a NON-project JDK effect method, handed to a stream/functional stage that
     *  invokes it (`removeIf(File::delete)`, `map(System::getenv)`), was silent-pure — the LambdaMetafactory
     *  indy carries the target as a method handle whose owner is a JDK class, which the handler edged only
     *  for project owners and never classified. Compile a real fixture (javac emits the real indy) and scan. */
    @Test
    void methodRefToJdkEffectIsClassified() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        org.junit.jupiter.api.Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path dir = Files.createTempDirectory("candor-mref");
        try {
            Path src = dir.resolve("M.java");
            Files.writeString(src, String.join("\n",
                "import java.io.File;",
                "import java.util.List;",
                "import java.util.stream.Collectors;",
                "public class M {",
                "  void refDelete(List<File> fs) { fs.removeIf(File::delete); }",          // Fs
                "  Object refGetenv(List<String> ks) {",
                "    return ks.stream().map(System::getenv).collect(Collectors.toList()); }", // Env
                "}"));
            Path out = dir.resolve("cls");
            Files.createDirectories(out);
            int rc = jc.run(null, null, null, "-d", out.toString(), src.toString());
            org.junit.jupiter.api.Assertions.assertEquals(0, rc, "fixture must compile");
            Map<String, EffectSet> r = Candor.runScan(out);
            assertTrue(r.getOrDefault("M.refDelete", EffectSet.empty()).toNames().contains("Fs"),
                    "removeIf(File::delete) must read Fs, got " + r.get("M.refDelete"));
            assertTrue(r.getOrDefault("M.refGetenv", EffectSet.empty()).toNames().contains("Env"),
                    "map(System::getenv) must read Env, got " + r.get("M.refGetenv"));
        } finally {
            try (Stream<Path> s = Files.walk(dir)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }
}
