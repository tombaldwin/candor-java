import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

/**
 * SOUNDNESS R1094 — THE THREE DERIVED JDK INDEXES, FROM NAMED JDK IMAGES, NOT FROM WHATEVER JDK RUNS GRADLE.
 *
 * <p>{@code jdk-supertypes.idx.gz} (the native-image hierarchy), {@code jdk-sams.idx.gz} (R191) and
 * {@code jdk-hof-invokes.idx.gz} (R237) were written by {@code build.gradle.kts} at build time from {@code jrt:/}
 * of the Gradle daemon's JVM — not the toolchain. Measured 2026-10-09: the published v0.40.3 jar's three indexes
 * are byte-identical to a build whose daemon ran Corretto 17.0.14, and differ from a JDK 21 build of the same commit
 * (3,151 / 100 / 425 lines). So the shipped engine knew JDK 17's functional interfaces and invoking HOFs, and every
 * JDK 18+ one read as a plain call. This generator is the same derivation, ported line for line from those Gradle
 * tasks, run over the pinned images in {@code images.tsv}; the outputs are checked in and the build copies them.
 *
 * <pre>
 *   bash soundness/jdk_index/derive.sh            # regenerate the checked-in indexes and manifest.txt
 *   bash soundness/jdk_index/derive.sh --check    # regenerate to a temp dir; exit 1 on any drift
 *   java -cp tool:asm*.jar JdkIndexGen --image &lt;java.home&gt; &lt;outdir&gt;   # one image, plain text (a probe)
 * </pre>
 * Run it on a JVM at least as new as the newest image: {@code jrt:/} of another image loads THAT image's
 * {@code lib/jrt-fs.jar}, whose classes a older runtime cannot load.
 *
 * <p>THE UNION, and why it is the sound direction. Each image is derived separately (its own SAM set, its own
 * identity-wrapper set and forwarding fixpoint), then the outputs are unioned: an HOF key's argument set is the
 * union; a SAM is the newest image's where images disagree (each disagreement is printed); a class's supertypes take its superclass from the newest image that has it and union the
 * interfaces. Both consumer-side uses of SAM/HOF facts fail toward SILENCE when a fact is missing (an opaque
 * functional argument reads as a plain call), so a fact present in any pinned image is kept. A fact from a newer
 * image can only matter to bytecode that names that newer member, and a (name, desc) collision with a non-JDK method
 * over-reports, which is the bound R237 already accepted.
 */
public final class JdkIndexGen {
    private JdkIndexGen() {}

    static final String SUPERS = "jdk-supertypes.idx", SAMS = "jdk-sams.idx", HOF = "jdk-hof-invokes.idx";
    static final Set<String> OBJECT_METHODS = Set.of("equals(Ljava/lang/Object;)Z", "hashCode()I", "toString()Ljava/lang/String;");
    static final int IDENTITY_BODY_LIMIT = 24;

    public static void main(String[] a) throws Exception {
        if (a.length >= 3 && a[0].equals("--image")) {
            Path out = Path.of(a[2]);
            Files.createDirectories(out);
            Image im = derive(Path.of(a[1]));
            Files.writeString(out.resolve(SUPERS), im.supersText(), StandardCharsets.UTF_8);
            Files.writeString(out.resolve(SAMS), im.samsText(), StandardCharsets.UTF_8);
            Files.writeString(out.resolve(HOF), im.hofText(), StandardCharsets.UTF_8);
            return;
        }
        if (a.length >= 3 && a[0].equals("--union")) {
            Path out = Path.of(a[1]);
            Files.createDirectories(out);
            List<Image> ims = new ArrayList<>();
            for (int i = 2; i < a.length; i++) ims.add(derive(Path.of(a[i])));
            Image u = union(ims);
            writeGz(out.resolve(SUPERS + ".gz"), u.supersText());
            writeGz(out.resolve(SAMS + ".gz"), u.samsText());
            writeGz(out.resolve(HOF + ".gz"), u.hofText());
            System.err.printf("jdk-index: %d images -> %d supertype lines, %d SAMs, %d HOF keys%n",
                    ims.size(), u.supers.size(), u.sams.size(), u.hof.size());
            return;
        }
        if (a.length >= 2 && a[0].equals("--cat")) {   // decompress a checked-in index (the drift check compares TEXT)
            System.out.print(readGz(Path.of(a[1])));
            return;
        }
        throw new IllegalArgumentException("usage: --image <java.home> <outdir> | --union <outdir> <java.home>... | --cat <file.gz>");
    }

    /** One image's three indexes. Keys sorted, so the text is reproducible. */
    static final class Image {
        final String home;
        final int feature;
        final TreeMap<String, List<String>> supers = new TreeMap<>();   // class -> [superName, iface...]
        final TreeMap<String, String> sams = new TreeMap<>();           // iface -> sam name
        final TreeMap<String, TreeSet<Integer>> hof = new TreeMap<>();  // "name desc" -> invoked arg indexes
        Image(String home, int feature) { this.home = home; this.feature = feature; }

        String supersText() {
            StringBuilder sb = new StringBuilder();
            for (var e : supers.entrySet()) sb.append(e.getKey()).append(' ').append(String.join(" ", e.getValue())).append('\n');
            return sb.toString();
        }
        String samsText() {
            StringBuilder sb = new StringBuilder();
            for (var e : sams.entrySet()) sb.append(e.getKey()).append(' ').append(e.getValue()).append('\n');
            return sb.toString();
        }
        /** Byte-compatible with the Gradle task's output: lines joined by '\n' with NO trailing newline. */
        String hofText() {
            List<String> lines = new ArrayList<>();
            for (var e : hof.entrySet()) {
                StringBuilder s = new StringBuilder(e.getKey()).append(' ');
                boolean first = true;
                for (int i : e.getValue()) { if (!first) s.append(','); s.append(i); first = false; }
                lines.add(s.toString());
            }
            return String.join("\n", lines);
        }
    }

    static Image union(List<Image> ims) {
        Image u = new Image("union", 0);
        List<Image> byFeature = new ArrayList<>(ims);
        byFeature.sort(Comparator.comparingInt(i -> i.feature));          // newest last: its superclass wins
        int superConflicts = 0;
        for (Image im : byFeature) {
            for (var e : im.supers.entrySet()) {
                List<String> prev = u.supers.get(e.getKey());
                if (prev == null) { u.supers.put(e.getKey(), new ArrayList<>(e.getValue())); continue; }
                List<String> cur = e.getValue();
                if (!prev.get(0).equals(cur.get(0))) superConflicts++;
                LinkedHashSet<String> ifs = new LinkedHashSet<>(prev.subList(1, prev.size()));
                ifs.addAll(cur.subList(1, cur.size()));
                List<String> merged = new ArrayList<>();
                merged.add(cur.get(0));
                merged.addAll(ifs);
                u.supers.put(e.getKey(), merged);
            }
            for (var e : im.sams.entrySet()) {
                String prev = u.sams.put(e.getKey(), e.getValue());   // newest image last, so it wins
                if (prev != null && !prev.equals(e.getValue()))
                    System.err.println("jdk-index: SAM of " + e.getKey() + " differs between images: " + prev + " -> "
                            + e.getValue() + " (" + im.home + "; kept)");
            }
            for (var e : im.hof.entrySet()) u.hof.computeIfAbsent(e.getKey(), k -> new TreeSet<>()).addAll(e.getValue());
        }
        System.err.println("jdk-index: " + superConflicts + " class(es) whose superclass differs between images (newest kept)");
        return u;
    }

    static void writeGz(Path p, String text) throws IOException {
        // GZIPOutputStream writes a fixed header (MTIME 0), so the bytes are a function of the text and the zlib
        // in use; the drift check compares the DECOMPRESSED text, never the .gz bytes.
        try (OutputStream o = new GZIPOutputStream(Files.newOutputStream(p))) { o.write(text.getBytes(StandardCharsets.UTF_8)); }
    }

    static String readGz(Path p) throws IOException {
        try (var in = new GZIPInputStream(Files.newInputStream(p))) { return new String(in.readAllBytes(), StandardCharsets.UTF_8); }
    }

    // ---------------------------------------------------------------------------------------------------------
    // The derivation, per image. Each pass mirrors the Gradle task it replaces (build.gradle.kts before R1094).
    // ---------------------------------------------------------------------------------------------------------

    static Image derive(Path home) throws IOException {
        int feature = 0;
        for (String l : Files.readAllLines(home.resolve("release"), StandardCharsets.UTF_8))
            if (l.startsWith("JAVA_VERSION=")) {
                String v = l.substring("JAVA_VERSION=".length()).replace("\"", "");
                feature = Integer.parseInt(v.split("[.+-]")[0]);
            }
        Image im = new Image(home.toString(), feature);
        try (FileSystem fs = FileSystems.newFileSystem(URI.create("jrt:/"), Map.of("java.home", home.toString()))) {
            List<Path> paths = new ArrayList<>();
            try (Stream<Path> st = Files.walk(fs.getPath("/modules"))) {
                st.filter(p -> { String s = p.toString(); return s.endsWith(".class") && !s.endsWith("module-info.class"); })
                  .forEach(paths::add);
            }
            supertypes(paths, im);
            sams(paths, im);
            hof(paths, im);
        }
        return im;
    }

    /** generateJdkSupertypes: every class's direct super + interfaces, via ClassReader (super_class of an
     *  interface is java/lang/Object; java/lang/Object itself has none and is not written). */
    static void supertypes(List<Path> paths, Image im) {
        for (Path p : paths) {
            ClassReader cr;
            try { cr = new ClassReader(Files.readAllBytes(p)); } catch (Exception e) { continue; }
            List<String> s = new ArrayList<>();
            if (cr.getSuperName() != null) s.add(cr.getSuperName());
            s.addAll(List.of(cr.getInterfaces()));
            if (!s.isEmpty()) im.supers.put(cr.getClassName(), s);
        }
    }

    record M(String name, String desc, int access) {}

    static Map<String, List<String>> ifaceSupers;
    static Map<String, List<M>> ifaceMethods;

    static void readInterfaces(List<Path> paths) {
        ifaceSupers = new HashMap<>();
        ifaceMethods = new HashMap<>();
        for (Path p : paths) {
            ClassReader cr;
            try { cr = new ClassReader(Files.readAllBytes(p)); } catch (Exception e) { continue; }
            if ((cr.getAccess() & Opcodes.ACC_INTERFACE) == 0) continue;
            List<M> ms = new ArrayList<>();
            cr.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override public MethodVisitor visitMethod(int acc, String n, String d, String sig, String[] ex) {
                    ms.add(new M(n, d, acc)); return null;
                }
            }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            ifaceSupers.put(cr.getClassName(), List.of(cr.getInterfaces()));
            ifaceMethods.put(cr.getClassName(), ms);
        }
    }

    /** generateJdkSams: the single abstract method over the interface and its super-interfaces, statics ignored,
     *  the three Object methods ignored (JLS 9.8), any signature a default supplies subtracted. */
    static String samOf(String name) {
        LinkedHashMap<String, String> abstracts = new LinkedHashMap<>();
        Set<String> concrete = new HashSet<>();
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> q = new ArrayDeque<>();
        q.add(name);
        while (!q.isEmpty()) {
            String n = q.removeFirst();
            if (!seen.add(n)) continue;
            for (M m : ifaceMethods.getOrDefault(n, List.of())) {
                if ((m.access & Opcodes.ACC_STATIC) != 0) continue;
                String key = m.name + m.desc;
                if ((m.access & Opcodes.ACC_ABSTRACT) != 0) { if (!OBJECT_METHODS.contains(key)) abstracts.putIfAbsent(key, m.name); }
                else concrete.add(key);
            }
            q.addAll(ifaceSupers.getOrDefault(n, List.of()));
        }
        abstracts.keySet().removeAll(concrete);
        return abstracts.size() == 1 ? abstracts.values().iterator().next() : null;
    }

    static void sams(List<Path> paths, Image im) {
        readInterfaces(paths);
        for (String n : ifaceMethods.keySet()) {
            String s = samOf(n);
            if (s != null) im.sams.put(n, s);
        }
    }

    static ClassNode readClass(Path p) {
        try {
            ClassNode cn = new ClassNode();
            new ClassReader(Files.readAllBytes(p)).accept(cn, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            return cn;
        } catch (Exception e) { return null; }
    }

    static Map<Integer, Integer> argSlots(MethodNode mn) {
        Type[] args = Type.getArgumentTypes(mn.desc);
        Map<Integer, Integer> m = new HashMap<>();
        int slot = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        for (int i = 0; i < args.length; i++) { m.put(slot, i); slot += args[i].getSize(); }
        return m;
    }

    record Fwd(String name, String desc, int arg) {}

    static Map<String, Integer> returnsArg;
    static Frame<SourceValue>[] curFrames;
    static MethodNode curMethod;

    static Frame<SourceValue> frameAt(AbstractInsnNode i) {
        int idx = curMethod.instructions.indexOf(i);
        if (curFrames == null || idx < 0 || idx >= curFrames.length) return null;
        return curFrames[idx];
    }

    static boolean fromParam(SourceValue v, int slot, int depth) {
        if (v == null || v.insns.isEmpty() || depth > 3) return false;
        for (AbstractInsnNode i : v.insns) {
            if (i.getOpcode() == Opcodes.ALOAD && ((VarInsnNode) i).var == slot) continue;
            if (i.getOpcode() == Opcodes.CHECKCAST) {
                Frame<SourceValue> cf = frameAt(i);
                if (cf == null) return false;
                if (cf.getStackSize() == 0 || !fromParam(cf.getStack(cf.getStackSize() - 1), slot, depth + 1)) return false;
                continue;
            }
            if (i instanceof MethodInsnNode mi) {
                Integer j = returnsArg.get(mi.name + " " + mi.desc);
                if (j == null) return false;
                Frame<SourceValue> cf = frameAt(i);
                if (cf == null) return false;
                Type[] cargs = Type.getArgumentTypes(mi.desc);
                if (j >= cargs.length) return false;
                int cur = cf.getStackSize() - cargs.length + j;   // value-indexed, not slot-indexed
                if (cur < 0 || cur >= cf.getStackSize()) return false;
                if (!fromParam(cf.getStack(cur), slot, depth + 1)) return false;
                continue;
            }
            return false;
        }
        return true;
    }

    /** generateJdkHofInvokes (R237): which functional parameter each JDK method INVOKES, directly, through a
     *  CHECKCAST or an identity wrapper, or by FORWARDING it to a method that does (a backwards fixpoint). */
    static void hof(List<Path> paths, Image im) {
        // pass 1: the SAM of every interface (ifaceMethods is still the one sams() read for this image)
        Map<String, String> sam = new HashMap<>();
        for (String n : ifaceMethods.keySet()) { String s = samOf(n); if (s != null) sam.put(n, s); }

        // pass 2: identity wrappers — small methods whose every ARETURN returns the same argument
        returnsArg = new HashMap<>();
        for (Path p : paths) {
            ClassNode cn = readClass(p);
            if (cn == null) continue;
            for (MethodNode mn : cn.methods) {
                if (Type.getReturnType(mn.desc).getSort() != Type.OBJECT) continue;
                InsnList insns = mn.instructions;
                if (insns == null || insns.size() == 0 || insns.size() > IDENTITY_BODY_LIMIT) continue;
                Map<Integer, Integer> argOf = argSlots(mn);
                if (argOf.isEmpty()) continue;
                boolean reassigned = false;
                for (AbstractInsnNode i : insns) if (i.getOpcode() == Opcodes.ASTORE && argOf.containsKey(((VarInsnNode) i).var)) reassigned = true;
                if (reassigned) continue;
                Frame<SourceValue>[] frames;
                try { frames = new Analyzer<>(new SourceInterpreter()).analyze(cn.name, mn); } catch (Exception e) { continue; }
                Integer answer = null;
                boolean ok = true;
                for (AbstractInsnNode i : insns) {
                    if (i.getOpcode() != Opcodes.ARETURN) continue;
                    Frame<SourceValue> f = frames[insns.indexOf(i)];
                    if (f == null || f.getStackSize() == 0) { ok = false; break; }
                    SourceValue v = f.getStack(f.getStackSize() - 1);
                    if (v.insns.isEmpty()) { ok = false; break; }
                    Integer arg = null;
                    for (AbstractInsnNode src : v.insns) {
                        if (src.getOpcode() != Opcodes.ALOAD) { ok = false; break; }
                        Integer ai = argOf.get(((VarInsnNode) src).var);
                        if (ai == null || (arg != null && !arg.equals(ai))) { ok = false; break; }
                        arg = ai;
                    }
                    if (!ok) break;
                    if (answer != null && !answer.equals(arg)) { ok = false; break; }
                    answer = arg;
                }
                if (ok && answer != null) returnsArg.put(mn.name + " " + mn.desc, answer);
            }
        }

        // pass 3: which functional parameter each method INVOKES, or FORWARDS
        Map<String, Set<Integer>> invokes = new HashMap<>();
        Map<String, Map<Integer, Set<Fwd>>> forwards = new HashMap<>();
        for (Path p : paths) {
            ClassNode cn = readClass(p);
            if (cn == null) continue;
            for (MethodNode mn : cn.methods) {
                Type[] args = Type.getArgumentTypes(mn.desc);
                List<Integer> fparams = new ArrayList<>();
                for (int i = 0; i < args.length; i++)
                    if (args[i].getSort() == Type.OBJECT && sam.containsKey(args[i].getInternalName())) fparams.add(i);
                if (fparams.isEmpty()) continue;
                InsnList insns = mn.instructions;
                if (insns == null || insns.size() == 0) continue;
                Map<Integer, Integer> slotOf = new HashMap<>();
                int slot = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
                for (int i = 0; i < args.length; i++) { slotOf.put(i, slot); slot += args[i].getSize(); }
                Set<Integer> reassigned = new HashSet<>();
                for (AbstractInsnNode i : insns) if (i.getOpcode() == Opcodes.ASTORE) reassigned.add(((VarInsnNode) i).var);
                Frame<SourceValue>[] frames;
                try { frames = new Analyzer<>(new SourceInterpreter()).analyze(cn.name, mn); } catch (Exception e) { continue; }
                curFrames = frames; curMethod = mn;
                String key = mn.name + " " + mn.desc;
                for (int i : fparams) {
                    int s = slotOf.get(i);
                    if (reassigned.contains(s)) continue;
                    String samName = sam.get(args[i].getInternalName());
                    for (AbstractInsnNode ins : insns) {
                        if (!(ins instanceof MethodInsnNode mi)) continue;
                        Frame<SourceValue> f = frames[insns.indexOf(ins)];
                        if (f == null) continue;
                        Type[] cargs = Type.getArgumentTypes(mi.desc);
                        if (mi.getOpcode() != Opcodes.INVOKESTATIC && mi.name.equals(samName)) {
                            int ri = f.getStackSize() - cargs.length - 1;
                            if (ri >= 0 && ri < f.getStackSize() && fromParam(f.getStack(ri), s, 0)) {
                                invokes.computeIfAbsent(key, k -> new HashSet<>()).add(i);
                                break;
                            }
                        }
                        int cur = f.getStackSize() - cargs.length;
                        for (int j = 0; j < cargs.length; j++) {
                            if (cur >= 0 && cur < f.getStackSize() && fromParam(f.getStack(cur), s, 0))
                                forwards.computeIfAbsent(key, k -> new HashMap<>()).computeIfAbsent(i, k -> new HashSet<>())
                                        .add(new Fwd(mi.name, mi.desc, j));
                            cur += 1;
                        }
                    }
                }
            }
        }
        // fixpoint: INVOKES propagates backwards through FORWARDS
        boolean moved = true;
        int rounds = 0;
        while (moved && rounds++ < 20) {
            moved = false;
            for (var e : forwards.entrySet())
                for (var pa : e.getValue().entrySet())
                    for (Fwd t : pa.getValue()) {
                        Set<Integer> ti = invokes.get(t.name + " " + t.desc);
                        if (ti != null && ti.contains(t.arg))
                            if (invokes.computeIfAbsent(e.getKey(), k -> new HashSet<>()).add(pa.getKey())) moved = true;
                    }
        }
        for (var e : invokes.entrySet()) im.hof.put(e.getKey(), new TreeSet<>(e.getValue()));
        curFrames = null; curMethod = null; returnsArg = null;
    }
}
