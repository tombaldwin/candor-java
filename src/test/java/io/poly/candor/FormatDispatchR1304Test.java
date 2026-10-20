package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * SOUNDNESS R1304 — SPEC §4 ⟨0.40⟩: a formatting/equality/hashing member called on a receiver typed by the
 * dependency's OWN abstraction is a dispatch through that abstraction, and the producer names it, so a CHAINED
 * consumer joins its own implementor. Every {@code c_*} wrote a file on JDK 21 with the effectful consumer
 * (javaagent-c fx/r1304b) and read pure chained on 65b5907 while charging {@code Fs} as one tree. The control
 * consumer's implementors are pure and its {@code Other} (not a Converter) has an effectful toString: it must
 * stay pure — a key under {@code java/lang/Object} would join Other's body onto every formatting call.
 *
 * <p>BOTH javac spellings: javac 18+ emits {@code invokeinterface Converter.toString} for {@code elem.toString()};
 * javac 17 and older emit {@code invokevirtual java/lang/Object.toString}. The in-process compiler is the newer
 * one, so the older form is produced by rewriting the instruction exactly as javac 17 writes it (measured:
 * javac 17.0.20.1 on the same source).
 */
class FormatDispatchR1304Test {

    private static final String FS = "new java.io.File(\"/tmp\").exists();";

    static Map<String, String> lib() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("convlib/Converter.java", "package convlib;\npublic interface Converter { String convert(String s); }\n");
        m.put("convlib/ArrayConverter.java", "package convlib;\npublic class ArrayConverter {\n  private final Converter elem;\n"
                + "  public ArrayConverter(Converter e) { elem = e; }\n"
                + "  @Override public String toString() { return \"AC[\" + elem.toString() + \"]\"; }\n}\n");
        m.put("convlib/ConcatConverter.java", "package convlib;\npublic class ConcatConverter {\n  private final Converter elem;\n"
                + "  public ConcatConverter(Converter e) { elem = e; }\n"
                + "  @Override public String toString() { return \"CC[\" + elem + \"]\"; }\n}\n");
        m.put("convlib/AbsConv.java", "package convlib;\npublic abstract class AbsConv { public abstract String convert(String s); }\n");
        m.put("convlib/Holder.java", "package convlib;\npublic class Holder {\n  private final AbsConv a;\n"
                + "  public Holder(AbsConv a) { this.a = a; }\n"
                + "  @Override public String toString() { return \"H[\" + a.toString() + \"]\"; }\n}\n");
        m.put("convlib/Base.java", "package convlib;\npublic class Base { @Override public String toString() { return \"Base\"; } }\n");
        m.put("convlib/Holder2.java", "package convlib;\npublic class Holder2 {\n  private final Base b;\n"
                + "  public Holder2(Base b) { this.b = b; }\n"
                + "  @Override public String toString() { return \"H2[\" + b.toString() + \"]\"; }\n}\n");
        m.put("convlib/KeyBox.java", "package convlib;\npublic class KeyBox {\n  private final Converter k;\n"
                + "  public KeyBox(Converter k) { this.k = k; }\n  @Override public int hashCode() { return 31 * k.hashCode(); }\n}\n");
        m.put("convlib/Impls.java", "package convlib;\npublic class Impls {\n"
                + "  public static class Upper implements Converter { public String convert(String s) { return s; } @Override public String toString() { return \"U\"; } }\n"
                + "  public static class Lower extends AbsConv { public String convert(String s) { return s; } @Override public String toString() { return \"L\"; } }\n}\n");
        return m;
    }

    static Map<String, String> app(boolean effectful) {
        String b = effectful ? FS : "";
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/MyConv.java", "package app;\npublic class MyConv implements convlib.Converter {\n"
                + "  public String convert(String s) { return s; }\n"
                + "  @Override public String toString() { " + b + " return \"MyConv\"; }\n"
                + "  @Override public int hashCode() { " + b + " return 7; }\n}\n");
        m.put("app/MyAbs.java", "package app;\npublic class MyAbs extends convlib.AbsConv {\n  public String convert(String s) { return s; }\n"
                + "  @Override public String toString() { " + b + " return \"MyAbs\"; }\n}\n");
        m.put("app/MySub.java", "package app;\npublic class MySub extends convlib.Base { @Override public String toString() { " + b + " return \"MySub\"; } }\n");
        m.put("app/Other.java", "package app;\npublic class Other { @Override public String toString() { " + FS + " return \"Other\"; } }\n");
        m.put("app/App.java", "package app;\nimport convlib.*;\npublic class App {\n"
                + "  public static String c_call(ArrayConverter ac) { return ac.toString(); }\n"
                + "  public static String c_interp(ArrayConverter ac) { return \"\" + ac; }\n"
                + "  public static String c_concat(ConcatConverter cc) { return cc.toString(); }\n"
                + "  public static String c_cls(Holder h) { return h.toString(); }\n"
                + "  public static String c_concrete(Holder2 h) { return h.toString(); }\n"
                + "  public static int c_hash(KeyBox kb) { return kb.hashCode(); }\n"
                + "  public static String c_other(Other o) { return o.toString(); }\n}\n");
        return m;
    }

    static final String[] CELLS = {"c_call", "c_interp", "c_concat", "c_cls", "c_concrete", "c_hash"};

    /** Rewrite ArrayConverter.toString's `invokeinterface Converter.toString` into javac 17's `invokevirtual Object.toString`. */
    static void javac17Form(Path libDir) throws Exception {
        Path p = libDir.resolve("convlib/ArrayConverter.class");
        ClassNode cn = new ClassNode();
        new ClassReader(Files.readAllBytes(p)).accept(cn, 0);
        int n = 0;
        for (MethodNode mn : cn.methods)
            for (AbstractInsnNode in : mn.instructions)
                if (in instanceof MethodInsnNode mi && mi.owner.equals("convlib/Converter") && mi.name.equals("toString")) {
                    mi.setOpcode(Opcodes.INVOKEVIRTUAL);
                    mi.owner = "java/lang/Object";
                    mi.itf = false;
                    n++;
                }
        assertTrue(n == 1, "the fixture must hold the javac 18+ form to rewrite — found " + n);
        ClassWriter cw = new ClassWriter(0);
        cn.accept(cw);
        Files.write(p, cw.toByteArray());
    }

    static Map<String, EffectSet> chained(boolean effectful, boolean javac17) throws Exception {
        Path appDir = compileApp(lib(), app(effectful));
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            if (javac17) javac17Form(base.resolve("lib"));
            Path depReport = base.resolve("dep.json");
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            return Candor.runScan(appDir);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    static boolean fs(Map<String, EffectSet> r, String cell) {
        return r.getOrDefault("app.App." + cell, EffectSet.empty()).contains(Effect.FS);
    }

    @Test
    void aChainedConsumersImplementorIsJoinedThroughTheDependencysFormattingCall() throws Exception {
        for (boolean j17 : new boolean[] {false, true}) {
            Map<String, EffectSet> r = chained(true, j17);
            for (String c : CELLS)
                assertTrue(fs(r, c), "R1304 (" + (j17 ? "javac 17" : "javac 18+") + " form): " + c + " — got " + r.get("app.App." + c));
            assertTrue(fs(r, "c_other"), "the Other seed is live — got " + r.get("app.App.c_other"));
        }
    }

    @Test
    void aPureImplementorAndANonConverterOtherChargeNothing() throws Exception {
        for (boolean j17 : new boolean[] {false, true}) {
            Map<String, EffectSet> r = chained(false, j17);
            assertTrue(fs(r, "c_other"), "the Other seed is live — got " + r.get("app.App.c_other"));
            for (String c : CELLS)
                assertFalse(fs(r, c), "control (" + (j17 ? "javac 17" : "javac 18+") + " form): " + c + " — got " + r.get("app.App." + c));
        }
    }
}
