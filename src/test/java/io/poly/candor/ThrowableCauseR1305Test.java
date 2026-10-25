package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

/**
 * SOUNDNESS R1305 — {@code new RuntimeException(cause)} RUNS {@code cause.toString()}. {@code Throwable(Throwable)} sets
 * {@code detailMessage = cause.toString()}, which for a project exception runs its {@code getMessage} (R1235). Every
 * {@code w*} method wrote a file on JDK 21 (javaagent-c fx/r1305) and read ABSENT on 1d15e76; the {@code k*} controls
 * wrote nothing: a pure {@code getMessage}, and the {@code (String, Throwable)} form, which does not stringify.
 */
class ThrowableCauseR1305Test {

    static final String SRC = ""
            + "package q;\n"
            + "class W { static void hit() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1305/x\"), \"x\"); } catch (Exception e) {} } }\n"
            + "class MsgEx extends RuntimeException { @Override public String getMessage() { W.hit(); return \"m\"; } }\n"
            + "class PureMsgEx extends RuntimeException { @Override public String getMessage() { return \"m\"; } }\n"
            + "class MsgIoEx extends java.io.IOException { @Override public String getMessage() { W.hit(); return \"m\"; } }\n"
            + "class MyEx extends RuntimeException { MyEx(Throwable c) { super(c); } }\n"
            + "public class Use {\n"
            + "  public static RuntimeException wParam(MsgEx c) { return new RuntimeException(c); }\n"
            + "  public static RuntimeException wLocal() { return new IllegalStateException(new MsgEx()); }\n"
            + "  public static RuntimeException wSuper(MsgEx c) { return new MyEx(c); }\n"
            + "  public static RuntimeException wUnchecked(MsgIoEx c) { return new java.io.UncheckedIOException(c); }\n"
            + "  public static RuntimeException wCatch() { try { throw new MsgEx(); } catch (RuntimeException e) { return new IllegalStateException(e); } }\n"
            + "  public static RuntimeException kPure(PureMsgEx c) { return new RuntimeException(c); }\n"
            + "  public static RuntimeException kMessage(MsgEx c) { return new RuntimeException(\"m\", c); }\n"
            + "}\n";

    @Test
    void aThrowableConstructorChargesItsCausesToString() throws Exception {
        Path cls = TestCompiler.compile(Map.of("q/Use.java", SRC));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String w : List.of("wParam", "wLocal", "wSuper", "wUnchecked", "wCatch"))
                assertTrue(inf.getOrDefault("q.Use." + w, EffectSet.empty()).contains(Effect.FS), "R1305: " + w + " — got " + inf.get("q.Use." + w));
            for (String k : List.of("kPure", "kMessage")) {
                EffectSet e = inf.getOrDefault("q.Use." + k, EffectSet.empty());
                assertFalse(e.contains(Effect.FS) || e.contains(Effect.UNKNOWN), "control " + k + " — got " + e);
            }
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    // ---- the table is DERIVED: re-derive it on the JDK the tests run on, and require every entry -----------------

    private FileSystem jrt;
    private final Map<String, ClassNode> classes = new HashMap<>();
    private final Map<String, Set<Integer>> memo = new HashMap<>();

    @Test
    void theTableCoversEveryStringifyingConstructorOfThisJdk() throws Exception {
        jrt = FileSystems.getFileSystem(URI.create("jrt:/"));
        Map<String, Set<Integer>> derived = new TreeMap<>();
        for (Path m : Files.newDirectoryStream(jrt.getPath("/modules"))) {
            try (var w = Files.walk(m)) {
                for (Path p : (Iterable<Path>) w.filter(x -> x.toString().endsWith(".class"))::iterator) {
                    String r = m.relativize(p).toString();
                    if (!r.startsWith("java/")) continue;
                    String c = r.substring(0, r.length() - 6);
                    if (!isThrowable(c)) continue;
                    for (MethodNode mn : load(c).methods) {
                        if (!mn.name.equals("<init>") || (mn.access & Opcodes.ACC_PRIVATE) != 0) continue;
                        Set<Integer> s = stringified(c, mn.desc);
                        if (!s.isEmpty()) derived.put(c + "." + mn.desc, s);
                    }
                }
            }
        }
        assertTrue(derived.containsKey("java/lang/Throwable.(Ljava/lang/Throwable;)V"), "the derivation is blind: " + derived.size());
        assertTrue(derived.size() >= 60, "the derivation found too little to be a reading: " + derived.size());
        // call-target round 2: the table the engine reads is the derived JDK site table (JdkSites). This test is the
        // second, independent derivation on the JDK the tests run on; every stringifying constructor a USER can call
        // (a public class, a public/protected constructor) on an argument a user can supply (not a final class such as
        // String, which has no override to run) must be a hook there.
        int checked = 0;
        for (var e : derived.entrySet()) {
            String k = e.getKey();
            String c = k.substring(0, k.indexOf(".(")), desc = k.substring(k.indexOf(".(") + 1);
            ClassNode cn = load(c);
            MethodNode ctor = null;
            for (MethodNode mn : cn.methods) if (mn.name.equals("<init>") && mn.desc.equals(desc)) ctor = mn;
            if ((cn.access & Opcodes.ACC_PUBLIC) == 0 || ctor == null || (ctor.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) == 0) continue;
            org.objectweb.asm.Type[] at = org.objectweb.asm.Type.getArgumentTypes(desc);
            Set<Integer> want = new TreeSet<>();
            for (int i : e.getValue()) {
                ClassNode pc = at[i].getSort() == org.objectweb.asm.Type.OBJECT ? load(at[i].getInternalName()) : null;
                if (pc != null && (pc.access & Opcodes.ACC_FINAL) != 0) continue;
                want.add(i);
            }
            if (want.isEmpty()) continue;
            int[] have = JdkSites.argsHooking(c, "<init>", desc, "toString()Ljava/lang/String;");
            for (int i : want)
                assertTrue(Arrays.stream(have).anyMatch(x -> x == i),
                        "R1305: this JDK's " + k + " stringifies argument " + i + " and the JDK site table has no such hook");
            checked++;
        }
        assertTrue(checked >= 60, "the cross-check compared too little to be a reading: " + checked);
    }

    private ClassNode load(String n) {
        return classes.computeIfAbsent(n, k -> {
            try {
                for (Path m : Files.newDirectoryStream(jrt.getPath("/modules"))) {
                    Path p = m.resolve(k + ".class");
                    if (Files.exists(p)) { ClassNode cn = new ClassNode(); new ClassReader(Files.readAllBytes(p)).accept(cn, 0); return cn; }
                }
            } catch (Exception e) { /* unreadable: not a Throwable here */ }
            return null;
        });
    }

    private boolean isThrowable(String n) {
        for (String x = n; x != null; ) {
            if (x.equals("java/lang/Throwable")) return true;
            ClassNode c = load(x);
            if (c == null) return false;
            x = c.superName;
        }
        return false;
    }

    /** The parameter indices {@code owner.<init>desc} runs toString on, directly or through this/super. */
    private Set<Integer> stringified(String owner, String desc) {
        String key = owner + desc;
        if (memo.containsKey(key)) return memo.get(key);
        memo.put(key, Set.of());
        Set<Integer> out = new TreeSet<>();
        ClassNode cn = load(owner);
        MethodNode mn = null;
        if (cn != null) for (MethodNode m : cn.methods) if (m.name.equals("<init>") && m.desc.equals(desc)) mn = m;
        if (mn == null || mn.instructions.size() == 0) { memo.put(key, out); return out; }
        Type[] at = Type.getArgumentTypes(desc);
        int[] slot = new int[at.length];
        for (int i = 0, s = 1; i < at.length; s += at[i].getSize(), i++) slot[i] = s;
        Frame<SourceValue>[] fr;
        try { fr = new Analyzer<>(new SourceInterpreter()).analyze(owner, mn); } catch (Exception e) { memo.put(key, out); return out; }
        for (int i = 0; i < mn.instructions.size(); i++) {
            if (!(mn.instructions.get(i) instanceof MethodInsnNode mi) || fr[i] == null) continue;
            int base = fr[i].getStackSize() - Type.getArgumentTypes(mi.desc).length;
            if (mi.name.equals("toString") && mi.desc.equals("()Ljava/lang/String;") && mi.getOpcode() != Opcodes.INVOKESTATIC) {
                int p = param(mn, fr, fr[i].getStack(base - 1), slot);
                if (p >= 0) out.add(p);
            } else if ((mi.owner.equals("java/lang/String") && mi.name.equals("valueOf") && mi.desc.equals("(Ljava/lang/Object;)Ljava/lang/String;"))
                    || (mi.name.equals("append") && mi.desc.startsWith("(Ljava/lang/Object;)"))) {
                int p = param(mn, fr, fr[i].getStack(base), slot);
                if (p >= 0) out.add(p);
            } else if (mi.name.equals("<init>") && mi.getOpcode() == Opcodes.INVOKESPECIAL
                    && (mi.owner.equals(owner) || mi.owner.equals(cn.superName))) {
                boolean onThis = false;
                for (AbstractInsnNode r : fr[i].getStack(base - 1).insns)
                    if (r instanceof VarInsnNode v && v.var == 0 && v.getOpcode() == Opcodes.ALOAD) onThis = true;
                if (!onThis) continue;
                for (int j : stringified(mi.owner, mi.desc)) {
                    int p = param(mn, fr, fr[i].getStack(base + j), slot);
                    if (p >= 0) out.add(p);
                }
            }
        }
        memo.put(key, out);
        return out;
    }

    private static int param(MethodNode mn, Frame<SourceValue>[] fr, SourceValue v, int[] slot) {
        if (v == null || v.insns.size() != 1) return -1;
        AbstractInsnNode in = v.insns.iterator().next();
        if (in.getOpcode() == Opcodes.CHECKCAST) {
            int ix = mn.instructions.indexOf(in);
            return param(mn, fr, fr[ix].getStack(fr[ix].getStackSize() - 1), slot);
        }
        if (in instanceof MethodInsnNode rn && rn.owner.equals("java/util/Objects") && rn.name.equals("requireNonNull")) {
            int ix = mn.instructions.indexOf(rn);
            return param(mn, fr, fr[ix].getStack(fr[ix].getStackSize() - Type.getArgumentTypes(rn.desc).length), slot);
        }
        if (in instanceof VarInsnNode vi && vi.getOpcode() == Opcodes.ALOAD) {
            for (AbstractInsnNode x : mn.instructions)
                if (x instanceof VarInsnNode st && st.getOpcode() == Opcodes.ASTORE && st.var == vi.var) return -1;
            for (int k = 0; k < slot.length; k++) if (slot[k] == vi.var) return k;
        }
        return -1;
    }
}
