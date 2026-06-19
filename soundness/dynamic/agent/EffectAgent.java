import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarFile;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * The candor leaf-instrumenting agent — the non-Fs/Net counterpart to the JFR dynamic differential.
 *
 * JFR only emits jdk.{File,Socket}{Read,Write} events, so the JFR oracle (jfr_diff.py) is blind to
 * Exec/Db/Env/Clock/Rand. This agent fills that hole: it rewrites application bytecode to call
 * EffectRecorder.record(effect) immediately before every genuine effect-LEAF call (a method in the
 * LEAF table below), recording the ACTUAL effect with the live Java call stack — a runtime oracle
 * independent of what candor's static analysis can connect.
 *
 * CLASSLOADER FIX: instrumented app classes contain INVOKESTATIC EffectRecorder.record, so
 * EffectRecorder must resolve from the system classloader. We append THIS agent jar to the system
 * classloader search in premain before installing the transformer.
 */
public class EffectAgent {

    /**
     * LEAF TABLE: (owner internal name, method name) -> candor effect.
     * These are the genuine effect leaves we observe. Editable: add (owner,name,effect) rows.
     *
     * For java/sql/* (INTERFACES) the INVOKEINTERFACE owner in bytecode IS the static interface type
     * (e.g. java/sql/Statement), so matching the static owner catches the call regardless of the
     * concrete driver implementation behind it.
     */
    static final Map<String, String> LEAVES = new HashMap<>();
    static {
        // --- Exec ---
        leaf("java/lang/ProcessBuilder", "start", "Exec");
        leaf("java/lang/Runtime", "exec", "Exec");           // matches all exec(...) overloads (by name)
        // --- Db (java.sql.* are interfaces; static owner == interface in bytecode) ---
        leaf("java/sql/Statement", "execute", "Db");
        leaf("java/sql/Statement", "executeQuery", "Db");
        leaf("java/sql/Statement", "executeUpdate", "Db");
        leaf("java/sql/Statement", "executeBatch", "Db");
        leaf("java/sql/Statement", "executeLargeUpdate", "Db");
        leaf("java/sql/PreparedStatement", "execute", "Db");
        leaf("java/sql/PreparedStatement", "executeQuery", "Db");
        leaf("java/sql/PreparedStatement", "executeUpdate", "Db");
        leaf("java/sql/PreparedStatement", "executeLargeUpdate", "Db");
        leaf("java/sql/Connection", "prepareStatement", "Db");
        leaf("java/sql/Connection", "prepareCall", "Db");
        leaf("java/sql/Connection", "createStatement", "Db");
        // --- Env (no syscall → no JFR event; call-site instrumentation catches it) ---
        leaf("java/lang/System", "getenv", "Env");
        // --- Clock ---
        leaf("java/lang/System", "currentTimeMillis", "Clock");
        leaf("java/lang/System", "nanoTime", "Clock");
        for (String t : new String[] {"java/time/Instant", "java/time/LocalDate", "java/time/LocalDateTime",
                "java/time/LocalTime", "java/time/ZonedDateTime", "java/time/OffsetDateTime", "java/time/Year"})
            leaf(t, "now", "Clock");
        leaf("java/time/Clock", "instant", "Clock");
        leaf("java/time/Clock", "millis", "Clock");
        // --- Rand (entropy draws across the RNG owners; matched by name = all overloads) ---
        for (String owner : new String[] {"java/util/Random", "java/security/SecureRandom",
                "java/util/concurrent/ThreadLocalRandom"})
            for (String m : new String[] {"nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean",
                    "nextBytes", "nextGaussian", "ints", "longs", "doubles"})
                leaf(owner, m, "Rand");
        leaf("java/lang/Math", "random", "Rand");
        leaf("java/util/UUID", "randomUUID", "Rand");
        // --- Log (emit verbs across the logging facades; java.lang.System.Logger is the JDK platform one) ---
        for (String m : new String[] {"trace", "debug", "info", "warn", "error"})
            leaf("org/slf4j/Logger", m, "Log");
        for (String m : new String[] {"trace", "debug", "info", "warn", "error", "fatal", "log"})
            leaf("org/apache/logging/log4j/Logger", m, "Log");
        for (String m : new String[] {"log", "logp", "logrb", "info", "warning", "severe", "fine", "finer",
                "finest", "config"})
            leaf("java/util/logging/Logger", m, "Log");
        leaf("java/lang/System$Logger", "log", "Log");
    }

    private static void leaf(String owner, String name, String effect) {
        LEAVES.put(owner + "#" + name, effect);
    }

    public static void premain(String args, Instrumentation inst) {
        // Make EffectRecorder visible to instrumented app classes (system classloader).
        try {
            File self = new File(EffectAgent.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            inst.appendToSystemClassLoaderSearch(new JarFile(self));
            System.err.println("[candor-agent] appended to system classpath: " + self);
        } catch (Exception e) {
            System.err.println("[candor-agent] FATAL: could not append agent jar to system classpath: " + e);
            return;
        }
        inst.addTransformer(new Transformer(), true);
        System.err.println("[candor-agent] installed leaf transformer; " + LEAVES.size() + " leaf rule(s)");
    }

    static boolean skip(String internalName) {
        if (internalName == null) return true;
        return internalName.startsWith("java/") || internalName.startsWith("jdk/")
                || internalName.startsWith("sun/") || internalName.startsWith("com/sun/")
                || internalName.startsWith("org/objectweb/asm/")
                || internalName.equals("EffectRecorder") || internalName.equals("EffectAgent");
    }

    static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain pd, byte[] classfileBuffer) {
            if (skip(className)) return null;
            try {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassNode cn = new ClassNode();
                cr.accept(cn, 0);

                boolean changed = false;
                for (MethodNode mn : cn.methods) {
                    if (mn.instructions == null || mn.instructions.size() == 0) continue;
                    for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                        if (!(insn instanceof MethodInsnNode)) continue;
                        MethodInsnNode call = (MethodInsnNode) insn;
                        String effect = LEAVES.get(call.owner + "#" + call.name);
                        if (effect == null) continue;
                        // Insert before the leaf call: LDC effect ; INVOKESTATIC EffectRecorder.record(String)V
                        // record(String) pops exactly its one pushed arg, so the leaf call's receiver and
                        // args remain on the stack untouched immediately after — stack-safe.
                        InsnList probe = new InsnList();
                        probe.add(new LdcInsnNode(effect));
                        probe.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "EffectRecorder", "record",
                                "(Ljava/lang/String;)V", false));
                        mn.instructions.insertBefore(call, probe);
                        changed = true;
                    }
                }
                if (!changed) return null;

                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                cn.accept(cw);
                return cw.toByteArray();
            } catch (Throwable t) {
                // Never break the application because of instrumentation.
                System.err.println("[candor-agent] skipped " + className + " (transform error): " + t);
                return null;
            }
        }
    }
}
