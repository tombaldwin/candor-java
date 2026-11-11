package io.poly.candor;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceValue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static io.poly.candor.AnalysisState.ctx;

/** SOUNDNESS R1461 — THE GENERIC-INCOMPATIBILITY HEDGE on a JDK-owned CHA dispatch.
 *
 *  <p>{@code Candor#virtualDispatch} edges a call over a JDK generic type ({@code Collection.iterator()},
 *  {@code Iterator.next()}, {@code Supplier.get()}…) to every project implementor of that type, whatever the type
 *  ARGUMENTS say: a {@code for (Integer x : Collection<Integer>)} is charged the {@code Fs} of the program's only
 *  {@code Iterator<Span>}. Dropping that edge by generic type is UNSOUND — the JVM does not enforce generics, and an
 *  executed raw override (H1) or an unchecked upcast (H2, no bytecode trace at all) makes the incompatible implementor
 *  the one that runs. So the edge is not dropped, it is DEMOTED: where the class files PROVE the receiver's declared
 *  type argument and the implementor's are both resolved classes and neither is a subtype of the other, the edge is
 *  replaced by a disclosed {@code Unknown[dispatch:<owner>.<member>]} on the same site — decided after the fixpoint
 *  ({@code ArgContract#hedgeFloor}), where the demoted body carries a concrete effect the site lacks, any
 *  {@code Unknown}, or an {@code invisible} package the site lacks; a body carrying none of them lost nothing. The reason is true: the engine
 *  cannot name the runtime class, and only heap pollution makes it this implementor.
 *
 *  <p>Everything this reader cannot resolve keeps today's edge: a raw type, a missing {@code Signature}, a wildcard, a
 *  type variable, {@code Object}, a CHECKCAST, an array, a dependency class not on the classpath, a merge of an
 *  unresolved producer with a resolved one. The receiver's declared type is read from the program's own declarations:
 *  the {@code LocalVariableTypeTable}, a parameter's slot in the method {@code Signature}, a field's {@code Signature},
 *  or a call's generic return type with the declaring class's variables bound from ITS receiver (so
 *  {@code c.iterator()} over a {@code Collection<Integer>} is an {@code Iterator<Integer>}). A NEW instrument:
 *  calibrated in {@code GenericHedgeTest} (a compatible pair it must keep, an incompatible pair it must demote, an
 *  unresolvable one it must keep). {@code -Dcandor.r1461=off} restores the pre-hedge edges. */
final class GenericHedge {
    private GenericHedge() {}

    // the environment variable is read FIRST and unconditionally: `-Dcandor.r1461=off` beside it must not hide that it was set
    static final boolean OFF = "off".equals(Env.switchRead("CANDOR_R1461", "off"::equals)) | "off".equals(Env.propertySwitchRead("candor.r1461", "off"::equals));
    static final boolean DEBUG = Env.trace("CANDOR_R1461_DEBUG") != null;
    /** A MEASUREMENT ARM, off by default and not a setting: {@code CANDOR_R1461_WIDE=1} (or {@code -Dcandor.r1461.wide=on})
     *  extends the hedge from the collection owners to EVERY generic JDK owner ({@code java.util.function},
     *  {@code java.util.concurrent}, …) and reads those owners' signatures off the host JDK's class files — so it is
     *  jar-only and host-dependent, which is one more reason it does not ship. */
    static final boolean WIDE = "1".equals(Env.switchRead("CANDOR_R1461_WIDE", "1"::equals)) | "on".equals(Env.propertySwitchRead("candor.r1461.wide", "on"::equals));
    private static final int MAX_DEPTH = 8;

    // ---- the generic type model -------------------------------------------------------------------------------
    /** kind 'C' = a class type (internal name + type arguments), 'V' = a type variable, 'U' = anything this reader
     *  does not resolve (a wildcard, an array, a primitive). Only a 'C' argument can decide incompatibility. */
    record G(char kind, String name, List<G> args) {
        static final G U = new G('U', null, List.of());
        static G cls(String n, List<G> a) { return new G('C', n, a); }
        static G var(String n) { return new G('V', n, List.of()); }
        @Override public String toString() {
            if (kind == 'U') return "?";
            if (kind == 'V') return "T" + name;
            return args.isEmpty() ? name : name + args;
        }
    }

    record ClassSig(List<String> typeParams, List<G> supers) {}
    record MethodSig(List<String> typeParams, List<G> params, G ret) {}

    /** A recursive-descent reader for JVMS §4.7.9.1 signatures. Never throws to the caller (see {@link #parseOr}). */
    static final class P {
        final String s; int i;
        P(String s) { this.s = s; }
        char peek() { return s.charAt(i); }
        List<String> typeParams() {
            List<String> out = new ArrayList<>();
            if (i < s.length() && peek() == '<') {
                i++;
                while (peek() != '>') {
                    int c = s.indexOf(':', i);
                    out.add(s.substring(i, c));
                    i = c;
                    while (peek() == ':') { i++; if (peek() != ':' && peek() != '>' && isRefStart(peek())) type(); }
                }
                i++;
            }
            return out;
        }
        static boolean isRefStart(char c) { return c == 'L' || c == 'T' || c == '['; }
        G type() {
            char c = s.charAt(i++);
            switch (c) {
                case 'L': {
                    int st = i;
                    while (peek() != '<' && peek() != ';' && peek() != '.') i++;
                    String name = s.substring(st, i);
                    List<G> args = peek() == '<' ? args() : List.of();
                    while (peek() == '.') {
                        i++;
                        int st2 = i;
                        while (peek() != '<' && peek() != ';' && peek() != '.') i++;
                        name = name + "$" + s.substring(st2, i);
                        args = peek() == '<' ? args() : List.of();
                    }
                    i++; // ';'
                    return G.cls(name, args);
                }
                case 'T': {
                    int e = s.indexOf(';', i);
                    String n = s.substring(i, e);
                    i = e + 1;
                    return G.var(n);
                }
                case '[': type(); return G.U;
                default: return G.U;   // a base type or V
            }
        }
        List<G> args() {
            i++; // '<'
            List<G> out = new ArrayList<>();
            while (peek() != '>') {
                char c = peek();
                if (c == '*') { i++; out.add(G.U); }
                else if (c == '+' || c == '-') { i++; type(); out.add(G.U); }
                else out.add(type());
            }
            i++;
            return out;
        }
    }

    static ClassSig parseClass(String sig) {
        P p = new P(sig);
        List<String> tp = p.typeParams();
        List<G> supers = new ArrayList<>();
        while (p.i < sig.length()) supers.add(p.type());
        return new ClassSig(tp, supers);
    }

    static MethodSig parseMethod(String sig) {
        P p = new P(sig);
        List<String> tp = p.typeParams();
        p.i++; // '('
        List<G> params = new ArrayList<>();
        while (p.peek() != ')') params.add(p.type());
        p.i++;
        G ret = p.type();
        return new MethodSig(tp, params, ret);
    }

    static G parseField(String sig) { return new P(sig).type(); }

    static <T> T parseOr(java.util.function.Supplier<T> f) {
        try { return f.get(); } catch (RuntimeException e) { return null; }
    }

    /** The erased type of a descriptor, as a class type with no arguments (raw), else unresolved. */
    static G raw(Type t) {
        return t.getSort() == Type.OBJECT ? G.cls(t.getInternalName(), List.of()) : G.U;
    }

    static G subst(G g, Map<String, G> b) {
        if (g.kind == 'V') return b.getOrDefault(g.name, g);
        if (g.kind != 'C' || g.args.isEmpty()) return g;
        List<G> a = new ArrayList<>(g.args.size());
        for (G x : g.args) a.add(subst(x, b));
        return G.cls(g.name, a);
    }

    // ---- class information: the project's ClassNodes, else the JDK's class files ------------------------------
    /** Type parameters, generic supertypes (superclass first) and member signatures of one class. */
    record Info(String name, List<String> typeParams, List<G> supers, Map<String, String> methodSigs,
                Map<String, String> fieldSigs, Map<String, String> fieldDescs, Set<String> methods) {}

    private static final Map<String, Optional<Info>> JDK = new ConcurrentHashMap<>();

    static Info info(String internal) {
        if (internal == null) return null;
        ClassNode cn = ctx().byName.get(internal);
        if (cn != null) return fromNode(cn);
        if (!JdkSites.isJdk(internal)) return null;   // a dependency: not on this classpath, so unresolved
        if (WIDE) return JDK.computeIfAbsent(internal, GenericHedge::readJdk).orElse(null);
        return INDEXED.computeIfAbsent(internal, GenericHedge::fromIndex).orElse(null);
    }

    /** Tom's ruling (2026-11-05) covers the R1461 shape: the JDK COLLECTION owners — {@code java.lang.Iterable} and the
     *  {@code java.util} types whose supertypes reach {@code Iterable}, {@code Map}, {@code Iterator} or
     *  {@code Map.Entry} (Collection/List/Set/Queue/Map/Iterator/ListIterator/Map.Entry and the JDK classes
     *  implementing them). The generics index carries a class line for exactly that scope. */
    static boolean collectionOwner(String owner) {
        if (WIDE) return true;
        if (!owner.equals("java/lang/Iterable") && !(owner.startsWith("java/util/") && owner.indexOf('/', 10) < 0)) return false;
        return JdkGenerics.CLASS.containsKey(owner);
    }

    private static final Map<String, Optional<Info>> INDEXED = new ConcurrentHashMap<>();

    /** A JDK class's generic facts from the PINNED {@code jdk-generics.idx.gz}, on the jar and the native image alike (a
     *  native image has no JDK class files, so reading them off the host is what made the two diverge); its raw
     *  supertypes from {@link Cha#externalSupers}. A class neither knows is unresolved. */
    private static Optional<Info> fromIndex(String internal) {
        String sig = JdkGenerics.CLASS.get(internal);
        // raw supertypes through the engine's one JDK-hierarchy chokepoint: ClassReader on the jar, the pinned
        // jdk-supertypes index in a native image — the route every other CHA question already takes (native == jar)
        List<String> raw = Cha.externalSupers(internal);
        if (sig == null && raw.isEmpty() && !internal.equals("java/lang/Object")) return Optional.empty();
        ClassSig cs = sig == null || sig.equals("-") ? null : parseOr(() -> parseClass(sig));
        List<G> supers = new ArrayList<>();
        List<String> tp = List.of();
        if (cs != null) { supers.addAll(cs.supers); tp = cs.typeParams; }
        else for (String r : raw) supers.add(G.cls(r, List.of()));
        Map<String, String> ms = new HashMap<>(), fs = new HashMap<>(), fd = new HashMap<>();
        Set<String> methods = new HashSet<>();
        for (var e : JdkGenerics.METHODS.getOrDefault(internal, Map.of()).entrySet()) {
            methods.add(e.getKey());
            if (!e.getValue().equals("-")) ms.put(e.getKey(), e.getValue());
        }
        for (var e : JdkGenerics.FIELDS.getOrDefault(internal, Map.of()).entrySet()) {
            fd.put(e.getKey(), e.getValue()[0]);
            if (!e.getValue()[1].equals("-")) fs.put(e.getKey(), e.getValue()[1]);
        }
        return Optional.of(new Info(internal, tp, supers, ms, fs, fd, methods));
    }

    /** The checked-in {@code candor/jdk-generics.idx.gz} (soundness/jdk_index/derive.sh). Missing or unreadable, every
     *  map is empty and every JDK question is unresolved — the hedge then never fires and every edge is kept. */
    static final class JdkGenerics {
        static final Map<String, String> CLASS = new HashMap<>();
        static final Map<String, Map<String, String>> METHODS = new HashMap<>();
        static final Map<String, Map<String, String[]>> FIELDS = new HashMap<>();
        static {
            try (var in = GenericHedge.class.getResourceAsStream("/candor/jdk-generics.idx.gz")) {
                if (in != null) try (var br = new java.io.BufferedReader(new java.io.InputStreamReader(
                        new java.util.zip.GZIPInputStream(in), java.nio.charset.StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        String[] a = line.split("\t");
                        switch (a[0]) {
                            case "C" -> { if (a.length == 3) CLASS.put(a[1], a[2]); }
                            case "M" -> { if (a.length == 4) METHODS.computeIfAbsent(a[1], k -> new HashMap<>()).put(a[2], a[3]); }
                            case "F" -> { if (a.length == 5) FIELDS.computeIfAbsent(a[1], k -> new HashMap<>()).put(a[2], new String[] {a[3], a[4]}); }
                            default -> { }
                        }
                    }
                }
            } catch (java.io.IOException | RuntimeException e) {
                CLASS.clear(); METHODS.clear(); FIELDS.clear();
            }
        }
    }

    private static Info fromNode(ClassNode cn) {
        ClassSig cs = cn.signature == null ? null : parseOr(() -> parseClass(cn.signature));
        List<String> tp = cs == null ? List.of() : cs.typeParams;
        List<G> supers = new ArrayList<>();
        if (cs != null) supers.addAll(cs.supers);
        else {
            if (cn.superName != null) supers.add(G.cls(cn.superName, List.of()));
            for (String itf : cn.interfaces) supers.add(G.cls(itf, List.of()));
        }
        Map<String, String> ms = new HashMap<>();
        Set<String> methods = new HashSet<>();
        for (MethodNode m : cn.methods) {
            methods.add(m.name + m.desc);
            if (m.signature != null) ms.put(m.name + m.desc, m.signature);
        }
        Map<String, String> fs = new HashMap<>(), fd = new HashMap<>();
        for (FieldNode f : cn.fields) {
            fd.put(f.name, f.desc);
            if (f.signature != null) fs.put(f.name, f.signature);
        }
        return new Info(cn.name, tp, supers, ms, fs, fd, methods);
    }

    private static Optional<Info> readJdk(String internal) {
        try {
            ClassReader cr = new ClassReader(internal);
            String[] sig = new String[1];
            Map<String, String> ms = new HashMap<>(), fs = new HashMap<>(), fd = new HashMap<>();
            Set<String> methods = new HashSet<>();
            cr.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override public void visit(int v, int a, String n, String s, String sup, String[] itfs) { sig[0] = s; }
                @Override public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
                    methods.add(n + d);
                    if (s != null) ms.put(n + d, s);
                    return null;
                }
                @Override public FieldVisitor visitField(int a, String n, String d, String s, Object v) {
                    fd.put(n, d);
                    if (s != null) fs.put(n, s);
                    return null;
                }
            }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            ClassSig cs = sig[0] == null ? null : parseOr(() -> parseClass(sig[0]));
            List<G> supers = new ArrayList<>();
            List<String> tp = List.of();
            if (cs != null) { supers.addAll(cs.supers); tp = cs.typeParams; }
            else {
                if (cr.getSuperName() != null) supers.add(G.cls(cr.getSuperName(), List.of()));
                for (String itf : cr.getInterfaces()) supers.add(G.cls(itf, List.of()));
            }
            return Optional.of(new Info(internal, tp, supers, ms, fs, fd, methods));
        } catch (Throwable t) {
            // a GraalVM native image has no JDK class files: every JDK question is unresolved, so the edge is kept
            return Optional.empty();
        }
    }

    /** The binding of {@code ci}'s type parameters for the class type {@code t} (a raw use binds them unresolved,
     *  JLS 4.8: the supertypes of a raw type are erased). */
    static Map<String, G> bind(Info ci, G t) {
        Map<String, G> b = new HashMap<>();
        for (int k = 0; k < ci.typeParams.size(); k++)
            b.put(ci.typeParams.get(k), t.args.size() == ci.typeParams.size() ? t.args.get(k) : G.U);
        return b;
    }

    /** {@code t} viewed as its supertype {@code target}, with arguments substituted; null where the walk cannot
     *  reach {@code target} over classes it can read. */
    static G asSuper(G t, String target) { return asSuper(t, target, 0, new HashSet<>()); }

    private static G asSuper(G t, String target, int depth, Set<String> seen) {
        if (t == null || t.kind != 'C') return null;
        if (t.name.equals(target)) return t;
        if (depth > 24 || !seen.add(t.name)) return null;
        Info ci = info(t.name);
        if (ci == null) return null;
        Map<String, G> b = bind(ci, t);
        for (G s : ci.supers) {
            G r = asSuper(subst(s, b), target, depth + 1, seen);
            if (r != null) return r;
        }
        return null;
    }

    /** Every supertype (self included) of a class, or null where any class on the way cannot be read — so a
     *  disjointness verdict is never drawn over a hierarchy with a hole in it. */
    static Set<String> allSupers(String c) {
        Set<String> out = new LinkedHashSet<>();
        List<String> work = new ArrayList<>(List.of(c));
        while (!work.isEmpty()) {
            String x = work.remove(work.size() - 1);
            if (!out.add(x)) continue;
            if (x.equals("java/lang/Object")) continue;
            Info ci = info(x);
            if (ci == null) return null;
            for (G s : ci.supers) if (s.kind == 'C') work.add(s.name);
        }
        return out;
    }

    /** Neither class is a subtype of the other, over hierarchies read in full. */
    static boolean disjoint(String a, String b) {
        if (a.equals(b) || a.equals("java/lang/Object") || b.equals("java/lang/Object")) return false;
        Set<String> sa = allSupers(a), sb = allSupers(b);
        if (sa == null || sb == null) return false;
        return !sa.contains(b) && !sb.contains(a);
    }

    /** The receiver type and the implementor's view of the owner are PROVABLY incompatible: same owner, and at
     *  some argument position both are resolved class types that are disjoint. */
    static boolean incompatible(G recvAtOwner, G implAtOwner) {
        if (recvAtOwner == null || implAtOwner == null) return false;
        if (recvAtOwner.args.size() != implAtOwner.args.size() || recvAtOwner.args.isEmpty()) return false;
        for (int k = 0; k < recvAtOwner.args.size(); k++) {
            G r = recvAtOwner.args.get(k), c = implAtOwner.args.get(k);
            if (r.kind == 'C' && c.kind == 'C' && disjoint(r.name, c.name)) return true;
        }
        return false;
    }

    static G selfType(String cls) {
        Info ci = info(cls);
        if (ci == null) return null;
        List<G> a = new ArrayList<>();
        for (String v : ci.typeParams) a.add(G.var(v));
        return G.cls(cls, a);
    }

    // ---- the receiver's declared generic type, from the program's own declarations ---------------------------
    /** Resolves what the bytecode DECLARES a value to be. Every method returns null for "cannot say". */
    static final class Recv {
        final ClassNode cn; final MethodNode mn; final Frame<SourceValue>[] fr; final InsnList insns;
        final Set<AbstractInsnNode> active = new HashSet<>();
        Recv(ClassNode cn, MethodNode mn, Frame<SourceValue>[] fr) {
            this.cn = cn; this.mn = mn; this.fr = fr; this.insns = mn.instructions;
        }

        /** The declared types of every producer of {@code v}; null if any producer is unresolved. */
        List<G> of(SourceValue v, int depth) {
            if (v == null || v.insns.isEmpty() || depth > MAX_DEPTH) return null;
            List<G> out = new ArrayList<>();
            for (AbstractInsnNode p : v.insns) {
                List<G> g = producer(p, depth);
                if (g == null) return null;
                for (G x : g) if (!out.contains(x)) out.add(x);
            }
            return out.isEmpty() ? null : out;
        }

        /** The one declared type of {@code v}, or null where there is none or several. */
        G single(SourceValue v, int depth) {
            List<G> l = of(v, depth);
            return l != null && l.size() == 1 ? l.get(0) : null;
        }

        private Frame<SourceValue> frameAt(AbstractInsnNode p) {
            int i = insns.indexOf(p);
            return i >= 0 && i < fr.length ? fr[i] : null;
        }

        private List<G> producer(AbstractInsnNode p, int depth) {
            if (!active.add(p)) return null;   // a cycle through a loop's store: unresolved
            try {
                Frame<SourceValue> f = frameAt(p);
                int op = p.getOpcode();
                if (op == Opcodes.ALOAD) {
                    int var = ((VarInsnNode) p).var;
                    G lv = lvtt(var, p);
                    if (lv != null) return List.of(lv);
                    if (f == null) return null;
                    List<G> out = new ArrayList<>();
                    int params = paramSlots();
                    if (var < params) {
                        G pt = paramType(var);
                        if (pt == null) return null;
                        out.add(pt);
                    }
                    SourceValue local = f.getLocal(var);
                    if (local.insns.isEmpty() && var >= params) return null;
                    for (AbstractInsnNode st : local.insns) {
                        if (st.getOpcode() != Opcodes.ASTORE) return null;
                        Frame<SourceValue> sf = frameAt(st);
                        if (sf == null || sf.getStackSize() == 0) return null;
                        List<G> g = of(sf.getStack(sf.getStackSize() - 1), depth + 1);
                        if (g == null) return null;
                        out.addAll(g);
                    }
                    return out;
                }
                if (op == Opcodes.DUP) {
                    if (f == null || f.getStackSize() == 0) return null;
                    return of(f.getStack(f.getStackSize() - 1), depth + 1);
                }
                if (op == Opcodes.GETFIELD || op == Opcodes.GETSTATIC) {
                    G g = field((FieldInsnNode) p, f, depth);
                    return g == null ? null : List.of(g);
                }
                if (p instanceof MethodInsnNode m && !m.name.equals("<init>")) {
                    G g = callReturn(m, f, depth);
                    return g == null ? null : List.of(g);
                }
                if (op == Opcodes.NEW) return List.of(G.cls(((TypeInsnNode) p).desc, List.of()));
                return null;   // CHECKCAST (erased), ACONST_NULL, an array load, invokedynamic, …
            } finally {
                active.remove(p);
            }
        }

        private G lvtt(int var, AbstractInsnNode at) {
            if (mn.localVariables == null) return null;
            int pos = insns.indexOf(at);
            for (LocalVariableNode lv : mn.localVariables) {
                if (lv.index != var || lv.signature == null) continue;
                int s = insns.indexOf(lv.start), e = insns.indexOf(lv.end);
                // the load sits inside the variable's scope (a load right at `start` is the first use after the store)
                if (pos >= s && pos < e) return parseOr(() -> parseField(lv.signature));
            }
            return null;
        }

        private boolean isStatic() { return (mn.access & Opcodes.ACC_STATIC) != 0; }

        private int paramSlots() {
            int n = isStatic() ? 0 : 1;
            for (Type t : Type.getArgumentTypes(mn.desc)) n += t.getSize();
            return n;
        }

        private G paramType(int slot) {
            if (!isStatic() && slot == 0) return selfType(cn.name);
            Type[] ts = Type.getArgumentTypes(mn.desc);
            int s = isStatic() ? 0 : 1;
            int idx = -1;
            for (int k = 0; k < ts.length; k++) {
                if (s == slot) { idx = k; break; }
                s += ts[k].getSize();
            }
            if (idx < 0) return null;
            if (mn.signature == null) return raw(ts[idx]);
            MethodSig ms = parseOr(() -> parseMethod(mn.signature));
            // javac leaves synthetic/implicit parameters (an inner class's outer instance, an enum's name/ordinal)
            // out of the Signature: a count that disagrees cannot be aligned, so it is unresolved
            if (ms == null || ms.params.size() != ts.length) return null;
            return ms.params.get(idx);
        }

        private G field(FieldInsnNode fi, Frame<SourceValue> f, int depth) {
            // the declaring class: the named owner or a supertype the JVM's field resolution would reach
            String decl = null; Info di = null;
            List<String> work = new ArrayList<>(List.of(fi.owner));
            Set<String> seen = new HashSet<>();
            while (!work.isEmpty() && decl == null) {
                String x = work.remove(0);
                if (!seen.add(x)) continue;
                Info ci = info(x);
                if (ci == null) return null;
                if (fi.desc.equals(ci.fieldDescs.get(fi.name))) { decl = x; di = ci; break; }
                for (G s : ci.supers) if (s.kind == 'C') work.add(s.name);
            }
            if (di == null) return null;
            String sig = di.fieldSigs.get(fi.name);
            if (sig == null) return raw(Type.getType(fi.desc));
            G t = parseOr(() -> parseField(sig));
            if (t == null) return null;
            if (fi.getOpcode() == Opcodes.GETFIELD && !di.typeParams.isEmpty() && f != null && f.getStackSize() > 0) {
                G r = single(f.getStack(f.getStackSize() - 1), depth + 1);
                G rv = r == null ? null : asSuper(r, decl);
                if (rv != null) t = subst(t, bind(di, rv));
            }
            return t;
        }

        private G callReturn(MethodInsnNode m, Frame<SourceValue> f, int depth) {
            Type rt = Type.getReturnType(m.desc);
            if (rt.getSort() != Type.OBJECT) return null;
            // the declaration the call resolves against: the owner or the nearest supertype declaring name+desc
            String decl = null; Info di = null;
            List<String> work = new ArrayList<>(List.of(m.owner));
            Set<String> seen = new HashSet<>();
            while (!work.isEmpty()) {
                String x = work.remove(0);
                if (!seen.add(x)) continue;
                Info ci = info(x);
                if (ci == null) return null;
                if (ci.methods.contains(m.name + m.desc)) { decl = x; di = ci; break; }
                for (G s : ci.supers) if (s.kind == 'C') work.add(s.name);
            }
            if (di == null) return null;
            String sig = di.methodSigs.get(m.name + m.desc);
            if (sig == null) return raw(rt);
            MethodSig ms = parseOr(() -> parseMethod(sig));
            if (ms == null) return null;
            Map<String, G> b = new HashMap<>();
            for (String v : ms.typeParams) b.put(v, G.U);   // a method's own type variable: never inferred here
            if (m.getOpcode() != Opcodes.INVOKESTATIC && !di.typeParams.isEmpty() && f != null) {
                int recvIdx = f.getStackSize() - Type.getArgumentTypes(m.desc).length - 1;
                G r = recvIdx >= 0 ? single(f.getStack(recvIdx), depth + 1) : null;
                G rv = r == null ? null : asSuper(r, decl);
                if (rv != null) for (Map.Entry<String, G> e : bind(di, rv).entrySet()) b.putIfAbsent(e.getKey(), e.getValue());
            }
            return subst(ms.ret, b);
        }
    }

    // ---- the decision ---------------------------------------------------------------------------------------
    /** The CHA targets of {@code min} (over {@code chaOwner}, a JDK type) that every contributing project subtype
     *  makes PROVABLY incompatible with the receiver's declared type. Empty when anything is unresolved. */
    static Set<String> demoted(ClassNode cn, MethodNode mn, MethodInsnNode min, String chaOwner, List<String> targets) {
        return demoted(cn, mn, min, chaOwner, targets, false);
    }

    /** {@link #demoted} for the JDK re-entry bodies decided beside the CHA answer ({@code Cha#extraReentry}). */
    static Set<String> demotedReentry(ClassNode cn, MethodNode mn, MethodInsnNode min, String chaOwner, List<String> targets) {
        return demoted(cn, mn, min, chaOwner, targets, true);
    }

    private static Set<String> demoted(ClassNode cn, MethodNode mn, MethodInsnNode min, String chaOwner,
            List<String> targets, boolean reentry) {
        try {
            return decide(cn, mn, min, chaOwner, targets, reentry);
        } catch (RuntimeException e) {
            return Set.of();   // a reader failure keeps every edge: the hedge can only ever be withheld, never forced
        }
    }

    private static Set<String> decide(ClassNode cn, MethodNode mn, MethodInsnNode min, String chaOwner,
            List<String> targets, boolean reentry) {
        if (OFF || targets.isEmpty() || !JdkSites.isJdk(chaOwner) || cn == null || !collectionOwner(chaOwner)) return Set.of();
        Info oi = info(chaOwner);
        if (oi == null || oi.typeParams.isEmpty()) return Set.of();   // a non-generic owner has nothing to compare
        Frame<SourceValue>[] fr = Candor.srcFramesOf(mn);
        int at = mn.instructions.indexOf(min);
        if (fr == null || at < 0 || fr[at] == null) return Set.of();
        Frame<SourceValue> f = fr[at];
        int recvIdx = f.getStackSize() - Type.getArgumentTypes(min.desc).length - 1;
        if (recvIdx < 0) return Set.of();
        Recv rr = new Recv(cn, mn, fr);
        List<G> recvTypes = rr.of(f.getStack(recvIdx), 0);
        if (recvTypes == null) return Set.of();
        List<G> recvAtOwner = new ArrayList<>();
        for (G r : recvTypes) {
            G a = asSuper(r, chaOwner);
            if (a == null) return Set.of();
            recvAtOwner.add(a);
        }
        // which project subtypes contribute each target (Cha#chaTargets' own walk, per subtype)
        Map<String, Set<String>> subsOf = reentry ? Cha.extraReentrySubtypes(chaOwner, min.name, min.desc)
                : Cha.chaTargetSubtypes(chaOwner, min.name, min.desc);
        Set<String> out = new LinkedHashSet<>();
        for (String t : targets) {
            Set<String> subs = subsOf.get(t);
            if (subs == null || subs.isEmpty()) continue;   // a target no subtype accounts for: keep it
            boolean all = true;
            for (String sub : subs) {
                G implAtOwner = asSuper(selfType(sub), chaOwner);
                for (G r : recvAtOwner) if (!incompatible(r, implAtOwner)) { all = false; break; }
                if (!all) break;
            }
            if (all) out.add(t);
        }
        if (DEBUG && !out.isEmpty())
            System.err.println("R1461HEDGE\t" + cn.name + "." + mn.name + mn.desc + "\t" + chaOwner + "." + min.name
                    + "\t" + recvAtOwner + "\t" + out);
        return out;
    }

    /** For tests: the receiver types the reader resolves at {@code min}, viewed as {@code owner}; null = unresolved. */
    static List<G> receiverAt(ClassNode cn, MethodNode mn, MethodInsnNode min, String owner) {
        Frame<SourceValue>[] fr = Candor.srcFramesOf(mn);
        int at = mn.instructions.indexOf(min);
        if (fr == null || at < 0 || fr[at] == null) return null;
        Frame<SourceValue> f = fr[at];
        int recvIdx = f.getStackSize() - Type.getArgumentTypes(min.desc).length - 1;
        List<G> rs = new Recv(cn, mn, fr).of(f.getStack(recvIdx), 0);
        if (rs == null) return null;
        List<G> out = new ArrayList<>();
        for (G r : rs) out.add(asSuper(r, owner));
        return out;
    }
}
