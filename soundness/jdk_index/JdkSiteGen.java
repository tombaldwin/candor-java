import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

/**
 * CALL-TARGET ROUND 2 — THE JDK SITE TABLE, DERIVED FROM THE JDK'S OWN BYTECODE ({@code jdk-sites.idx}).
 *
 * <p>Question answered, per JDK member as seen from a receiver class {@code X}: when this body runs, which OVERRIDABLE
 * members does it invoke on {@code this} (slot {@code t}) or on the value it was handed as argument {@code i} (slot
 * {@code i})? That is the set of places a JDK body re-enters user code: {@code AbstractCollection.contains} runs
 * {@code this.iterator()}; seen from {@code AbstractList} it runs {@code this.listIterator()}, the iterator's
 * {@code AbstractList.this.size()} and {@code get(int)}, and {@code o.equals}; {@code InputStream.skip} runs
 * {@code this.read(byte[],int,int)}; {@code String.valueOf(Object)} runs {@code obj.toString()}. Before this the engine
 * answered it from hand tables (SOUNDNESS R32, R1235, R1300, R1305), each a few entries of the same question.
 *
 * <p><b>The derivation.</b> An abstract interpretation of each body over ORIGINS: {@code this}, a parameter, a field
 * of {@code this}, or an object the body allocates ({@code new D(..)}, with the origins its constructor stored in its
 * fields). A virtual call on {@code this} records a hook when the member is overridable from outside the JDK (not
 * final/private/static, public or protected, on a class a user can subclass) and then FOLLOWS the default body the
 * receiver class's own chain resolves to — under a GUARD naming that member, because the followed body runs only if
 * the user did not override it (the engine checks each guard against the real receiver). A call on a parameter records
 * a hook and is NOT followed: which body runs there is the engine's question, asked over the argument's type. A call
 * on an allocated JDK object is exact and followed, its fields mapped back (the iterator over {@code this}). Static,
 * private, final and constructor calls are exact and followed with their arguments mapped. A call on a value of
 * unknown origin is followed through its declared owner's body for its ARGUMENTS only. Bounded (depth 14); a
 * recursive cycle reads the cycle's partial summary (an under-approximation, documented, never a hook invented).
 *
 * <p>Line format: {@code X.name desc} TAB hook TAB hook …; hook = {@code slot member [guard,guard…]}; slot {@code t}
 * or an argument index; a member prefixed {@code #} may be PRIVATE (a reflective hook from the residual). Only lines
 * with at least one hook are written; {@code t} hooks only for an {@code X} a user can subclass.
 *
 * <p><b>The residual</b> — what bytecode does not show, kept by hand and named here so it is a list, not an absence:
 * {@code Thread.start()} runs {@code this.run()} from native {@code start0}; {@code ObjectOutputStream.writeObject/
 * writeUnshared} run the argument's {@code writeReplace}, private {@code writeObject(ObjectOutputStream)} or
 * {@code writeExternal} reflectively. NOT covered, and named: {@code ServiceLoader} (instantiates provider classes by
 * name, no slot), {@code ObjectInputStream.readObject} (the class is chosen by the stream), finalizers, and any hook
 * reached only through a JDK FIELD the caller set earlier (a {@code PrintWriter} over a user {@code Writer}: the
 * formatting facade, SOUNDNESS R16, keeps its own rule).
 */
final class JdkSiteGen {
    private JdkSiteGen() {}

    static final int DEPTH = 14;
    static final boolean DEBUG = System.getenv("SITEGEN_DEBUG") != null;
    final Map<String, ClassNode> classes = new HashMap<>();
    final TreeMap<String, TreeSet<String>> out = new TreeMap<>();

    /** a loaded generator, for probing one summary at a time (soundness/jdk_index debugging) */
    static JdkSiteGen forDebug(List<Path> paths) {
        JdkSiteGen g = new JdkSiteGen();
        for (Path p : paths) {
            try {
                ClassNode cn = new ClassNode();
                new ClassReader(Files.readAllBytes(p)).accept(cn, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
                dropDebugBranches(cn);
                g.classes.put(cn.name, cn);
            } catch (Exception ignored) { }
        }
        return g;
    }

    static TreeMap<String, TreeSet<String>> derive(List<Path> paths) {
        JdkSiteGen g = new JdkSiteGen();
        for (Path p : paths) {
            try {
                ClassNode cn = new ClassNode();
                new ClassReader(Files.readAllBytes(p)).accept(cn, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
                dropDebugBranches(cn);
                g.classes.put(cn.name, cn);
            } catch (Exception ignored) { }
        }
        g.run();
        return g.out;
    }

    /** Diagnostic-only flags, read as their default ({@code false}): a branch taken only when the flag is set is not
     *  followed. {@code ObjectOutputStream.extendedDebugInfo} is {@code -Dsun.io.serialization.extendedDebugInfo}, off
     *  unless a user turns it on to debug a NotSerializableException; its twenty {@code if (extendedDebugInfo)} blocks
     *  push {@code obj.toString()} onto a debug stack. Followed, they made {@code writeObject(Object)} a toString sink
     *  over every Serializable in a scan and charged effects that never run under a default JVM (hibernate's
     *  {@code CollectionEntry.serialize}: fifty-seven project toString/hashCode bodies). Published 0.40.17 had no such
     *  edge either, so a user who sets the flag is not made worse off than before this table. */
    static final Set<String> DEBUG_FLAGS = Set.of("java/io/ObjectOutputStream.extendedDebugInfo");

    /** {@code getstatic FLAG; ifeq L} becomes {@code goto L} (stack-neutral): the flag-set block is unreachable. */
    static void dropDebugBranches(ClassNode cn) {
        for (MethodNode m : cn.methods) {
            if (m.instructions == null) continue;
            for (AbstractInsnNode i = m.instructions.getFirst(); i != null; i = i.getNext()) {
                if (i.getOpcode() != Opcodes.GETSTATIC) continue;
                FieldInsnNode f = (FieldInsnNode) i;
                if (!DEBUG_FLAGS.contains(f.owner + "." + f.name) || !f.desc.equals("Z")) continue;
                AbstractInsnNode n = i.getNext();
                if (n == null || n.getOpcode() != Opcodes.IFEQ) continue;
                JumpInsnNode g = new JumpInsnNode(Opcodes.GOTO, ((JumpInsnNode) n).label);
                m.instructions.set(n, g);
                AbstractInsnNode prev = i.getPrevious();
                m.instructions.remove(i);
                i = prev == null ? m.instructions.getFirst() : prev;
            }
        }
    }

    // ------------------------------------------------------------------------------------------- hierarchy helpers
    MethodNode declared(String cls, String name, String desc) {
        ClassNode c = classes.get(cls);
        if (c == null) return null;
        for (MethodNode m : c.methods) if (m.name.equals(name) && m.desc.equals(desc)) return m;
        return null;
    }
    static boolean concrete(MethodNode m) { return m != null && (m.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0; }

    /** JVM resolution of an instance (or static) member from class {@code x}: the superclass chain, then the most
     *  specific interface default. Returns the declaring class of the body that runs, or null (abstract/native/none). */
    String resolve(String x, String name, String desc) {
        for (String c = x; c != null; ) {
            ClassNode cn = classes.get(c);
            if (cn == null) return null;
            MethodNode m = declared(c, name, desc);
            if (m != null) return concrete(m) ? c : null;
            c = cn.superName;
        }
        Deque<String> q = new ArrayDeque<>(List.of(x));
        Set<String> seen = new HashSet<>();
        String found = null;
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            ClassNode cn = classes.get(c);
            if (cn == null) continue;
            MethodNode m = declared(c, name, desc);
            if (m != null && (cn.access & Opcodes.ACC_INTERFACE) != 0 && concrete(m) && (m.access & Opcodes.ACC_STATIC) == 0) {
                if (found == null || isSub(c, found)) found = c;
            }
            if (cn.superName != null) q.add(cn.superName);
            q.addAll(cn.interfaces);
        }
        return found;
    }
    /** the declaration (abstract or not) the chain from x reaches first, for the overridability test */
    MethodNode declarationFrom(String x, String name, String desc) {
        Deque<String> q = new ArrayDeque<>(List.of(x));
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            MethodNode m = declared(c, name, desc);
            if (m != null) return m;
            ClassNode cn = classes.get(c);
            if (cn == null) continue;
            if (cn.superName != null) q.add(cn.superName);
            q.addAll(cn.interfaces);
        }
        return null;
    }
    boolean isSub(String s, String t) {
        Deque<String> q = new ArrayDeque<>(List.of(s));
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            if (c.equals(t)) return true;
            ClassNode cn = classes.get(c);
            if (cn == null) continue;
            if (cn.superName != null) q.add(cn.superName);
            q.addAll(cn.interfaces);
        }
        return false;
    }
    /** A member a class OUTSIDE the JDK can override: not static/private/final, public or protected. */
    static boolean overridable(MethodNode m) {
        if (m == null) return true;   // undeclared on the chain: an interface member a subtype supplies
        if ((m.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL)) != 0) return false;
        return (m.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0 || m.name.startsWith("<");
    }
    /** a class a user can subclass: public (or protected-nested), not final, in an exported java.* / javax.* package,
     *  with an accessible constructor, or an interface */
    boolean extendable(ClassNode c) {
        if (!exported(c.name)) return false;
        if ((c.access & Opcodes.ACC_FINAL) != 0 || (c.access & Opcodes.ACC_PUBLIC) == 0) return false;
        if ((c.access & Opcodes.ACC_INTERFACE) != 0) return true;
        for (MethodNode m : c.methods)
            if (m.name.equals("<init>") && (m.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0) return true;
        return false;
    }
    static boolean exported(String n) { return n.startsWith("java/") || n.startsWith("javax/"); }

    // ------------------------------------------------------------------------------------------- origins
    /** An origin: THIS, a parameter, a field of this, or an allocation. */
    static abstract sealed class Org permits Slot, Fld, Alloc, Elem {}
    /** an ELEMENT of array parameter i ({@code Arrays.sort(a)} compares {@code a[i]}; {@code String.format} formats
     *  each vararg) — written as slot {@code i[]} */
    static final class Elem extends Org {
        final int i;
        Elem(int i) { this.i = i; }
        @Override public boolean equals(Object o) { return o instanceof Elem e && e.i == i; }
        @Override public int hashCode() { return 977 + i; }
        @Override public String toString() { return i + "[]"; }
    }
    static final class Slot extends Org {
        final int i;   // -1 = this
        Slot(int i) { this.i = i; }
        @Override public boolean equals(Object o) { return o instanceof Slot s && s.i == i; }
        @Override public int hashCode() { return 31 + i; }
        @Override public String toString() { return i < 0 ? "t" : String.valueOf(i); }
    }
    static final class Fld extends Org {
        final String f;
        Fld(String f) { this.f = f; }
        @Override public boolean equals(Object o) { return o instanceof Fld x && x.f.equals(f); }
        @Override public int hashCode() { return f.hashCode() * 7; }
    }
    /** identity-equal: one per allocation site (or per translated callee allocation at a call site) */
    static final class Alloc extends Org {
        final String cls;
        final Map<String, Set<Org>> binds = new HashMap<>();
        final Set<String> guards = new TreeSet<>();
        Alloc(String cls) { this.cls = cls; }
        /** bounded: an allocation's fields hold THIS, parameters and fields, never another allocation (a regex node
         *  graph is cyclic). The one shape this exists for — an iterator over this — needs only the first kind. */
        void bind(String f, Collection<Org> os) {
            Set<Org> cur = binds.computeIfAbsent(f, k -> new LinkedHashSet<>());
            for (Org o : os) if (!(o instanceof Alloc)) cur.add(o);
        }
    }
    static final class V implements Value {
        final int size;
        final Set<Org> orgs;
        V(int size, Set<Org> orgs) { this.size = size; this.orgs = orgs; }
        @Override public int getSize() { return size; }
        @Override public boolean equals(Object o) { return o instanceof V v && v.size == size && v.orgs.equals(orgs); }
        @Override public int hashCode() { return orgs.hashCode() + size; }
    }
    /** {@code args}: the origins of the call's arguments in the summarised body's terms, so a caller that maps the
     *  hook's slot to an object it allocated can FOLLOW the call with the right arguments (Throwable.printStackTrace
     *  hands {@code this} to a WrappedPrintStream it built) */
    record Hook(Org slot, String member, Set<String> guards, List<Set<Org>> args) {}
    record HookKey(Org slot, String member, Set<String> guards) {}
    static final class Summary {
        /** one entry per (slot, member, guards); the argument origins of every such call, unioned per position */
        final Map<HookKey, List<Set<Org>>> hookArgs = new LinkedHashMap<>();
        Iterable<Hook> hooks() {
            List<Hook> r = new ArrayList<>();
            for (var e : hookArgs.entrySet()) r.add(new Hook(e.getKey().slot(), e.getKey().member(), e.getKey().guards(), e.getValue()));
            return r;
        }
        final Set<Org> ret = new LinkedHashSet<>();
        final Map<String, Set<Org>> puts = new HashMap<>();
        /** every resolution of a call on THIS made under this summary (member -> body owner), for context reuse */
        final Map<String, String> tres = new HashMap<>();
        /** OPEN: the body (or one it follows) makes a call a user class could answer that is NOT a hook on this or an
         *  argument — on a value the summary cannot name (an iterator's element, a field the user may have set, a
         *  lambda). Then the hooks are not the whole set of user code the body can run, and the engine may only ADD
         *  them; a CLOSED summary's hooks are complete (Object.toString runs this.hashCode() and nothing else). */
        boolean open;
        String why;   // DEBUG: the first call that opened it
    }

    // ------------------------------------------------------------------------------------------- the fixpoint
    // A worklist over summary keys (receiver context | body.member): a body reads its callees' CURRENT summaries and
    // registers itself as their dependent; when a summary grows, its dependents are recomputed. No recursion, so no
    // depth bound and no cycle cut: a recursive cycle converges like any other dataflow (hooks only accumulate).
    final Map<String, Summary> memo = new HashMap<>();
    final Map<String, String[]> parts = new HashMap<>();
    final Map<String, Set<String>> dependents = new HashMap<>();
    final Map<String, String> sigs = new HashMap<>();
    final ArrayDeque<String> work = new ArrayDeque<>();
    final Set<String> queued = new HashSet<>();
    String current;
    long computations;
    static final long BUDGET = 20_000_000L;

    /** The summary of {@code body.name desc} run on a receiver of class {@code ctx}: the current value, registering the
     *  body being computed as its dependent (depth is ignored; kept for the call sites' readability). */
    Summary summary(String ctx, String body, String name, String desc, int depth) {
        String key = ctx + "|" + body + "." + name + desc;
        if (current != null && !current.equals(key)) dependents.computeIfAbsent(key, k -> new HashSet<>()).add(current);
        Summary s = memo.get(key);
        if (s == null) {
            s = new Summary();
            memo.put(key, s);
            parts.put(key, new String[] {ctx, body, name, desc});
            enqueue(key);
        }
        return s;
    }
    void drainForDebug() { drain(); }
    void enqueue(String k) { if (queued.add(k)) work.add(k); }

    void drain() {
        while (!work.isEmpty()) {
            if (++computations > BUDGET) { System.err.println("jdk-sites: BUDGET exhausted with " + work.size() + " queued (the table is written as it stands)"); return; }
            String key = work.poll();
            queued.remove(key);
            if (DEBUG && computations % 50000 == 0) {
                long sl = 0; for (String x : sigs.values()) sl += x.length();
                long dl = 0; for (Set<String> x : dependents.values()) dl += x.size();
                System.err.println("SITEGEN progress " + computations + " memo=" + memo.size() + " work=" + work.size() + " sigchars=" + sl + " deps=" + dl
                        + " heapMB=" + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1048576);
                if (sl > 300_000_000L) {
                    sigs.entrySet().stream().sorted((x, y) -> y.getValue().length() - x.getValue().length()).limit(4)
                        .forEach(e -> System.err.println("BIGSIG " + e.getKey() + " " + e.getValue().length() + " " + e.getValue().substring(0, Math.min(3000, e.getValue().length()))));
                    System.exit(3);
                }
            }
            Summary r = compute(key);
            String sg = sig(r);
            if (!sg.equals(sigs.get(key))) {
                sigs.put(key, sg);
                memo.put(key, r);
                for (String d : dependents.getOrDefault(key, Set.of())) enqueue(d);
            }
        }
    }

    Summary compute(String key) {
        String[] k = parts.get(key);
        String ctx = k[0], body = k[1], name = k[2], desc = k[3];
        String saved = current;
        current = key;
        try {
            // context reuse: the body's own-class summary applies to ctx when every call on this it made resolves the same
            if (!ctx.equals(body)) {
                Summary own = summary(body, body, name, desc, 0);
                boolean same = true;
                for (var e : own.tres.entrySet()) {
                    int sp = e.getKey().indexOf('(');
                    if (!Objects.equals(resolveOrDash(ctx, e.getKey().substring(0, sp), e.getKey().substring(sp)), e.getValue())) { same = false; break; }
                }
                if (same && sigs.containsKey(body + "|" + body + "." + name + desc)) return own;
            }
            MethodNode mn = declared(body, name, desc);
            Summary r = new Summary();
            if (mn != null && mn.instructions != null && mn.instructions.size() > 0) {
                try {
                    new Analyzer<>(new Interp(this, ctx, body, mn, r, 0)).analyze(body, mn);
                } catch (AnalyzerException e) { if (DEBUG) System.err.println("SITEGEN-AE\t" + key + "\t" + e.getMessage()); }
            }
            return r;
        } finally {
            current = saved;
        }
    }
    String resolveOrDash(String x, String n, String d) { String b = resolve(x, n, d); return b == null ? "-" : b; }

    /** a canonical text of a summary (allocations by class and bindings, never identity), to detect change */
    static String sig(Summary s) {
        StringBuilder b = new StringBuilder();
        List<String> hs = new ArrayList<>();
        for (Hook h : s.hooks()) {
            StringBuilder x = new StringBuilder(org(h.slot(), 0)).append(' ').append(h.member()).append(' ').append(new TreeSet<>(h.guards()));
            for (Set<Org> a : h.args()) x.append('|').append(orgs(a, 0));
            hs.add(x.toString());
        }
        Collections.sort(hs);
        b.append(hs).append("#").append(orgs(s.ret, 0)).append('#');
        for (var e : new TreeMap<>(s.puts).entrySet()) b.append(e.getKey()).append('=').append(orgs(e.getValue(), 0)).append(';');
        b.append('#').append(new TreeMap<>(s.tres)).append(s.open ? "#open" : "");
        return b.toString();
    }
    static String orgs(Set<Org> os, int d) {
        List<String> r = new ArrayList<>();
        for (Org o : os) r.add(org(o, d));
        Collections.sort(r);
        return r.toString();
    }
    static String org(Org o, int d) {
        if (o instanceof Slot sl) return sl.toString();
        if (o instanceof Fld f) return "f:" + f.f;
        if (o instanceof Elem e) return "e" + e.i;
        Alloc a = (Alloc) o;
        if (d > 2) return "a:" + a.cls;
        StringBuilder b = new StringBuilder("a:").append(a.cls).append(new TreeSet<>(a.guards)).append('{');
        for (var e : new TreeMap<>(a.binds).entrySet()) b.append(e.getKey()).append('=').append(orgs(e.getValue(), d + 1)).append(',');
        return b.append('}').toString();
    }

    /** The interpreter: origins through the frame; calls recorded/followed in naryOperation. */
    static final class Interp extends Interpreter<V> {
        final JdkSiteGen g; final String ctx, body; final MethodNode mn; final Summary s; final int depth;
        final boolean isStatic;
        final Map<AbstractInsnNode, Alloc> allocs = new HashMap<>();
        final Map<String, Alloc> translated = new HashMap<>();
        final Set<String> followed = new HashSet<>();   // (allocation, member, args) already followed in this body
        Interp(JdkSiteGen g, String ctx, String body, MethodNode mn, Summary s, int depth) {
            super(Opcodes.ASM9);
            this.g = g; this.ctx = ctx; this.body = body; this.mn = mn; this.s = s; this.depth = depth;
            this.isStatic = (mn.access & Opcodes.ACC_STATIC) != 0;
        }
        static V none(int size) { return new V(size, Set.of()); }
        static V of(int size, Org o) { return new V(size, Set.of(o)); }

        @Override public V newValue(Type t) {
            if (t == Type.VOID_TYPE) return null;
            return none(t == null ? 1 : t.getSize());
        }
        @Override public V newParameterValue(boolean isInstanceMethod, int local, Type type) {
            if (isInstanceMethod && local == 0) return of(1, new Slot(-1));
            int slot = isInstanceMethod ? 1 : 0, idx = 0;
            for (Type a : Type.getArgumentTypes(mn.desc)) {
                if (slot == local) return a.getSort() == Type.OBJECT || a.getSort() == Type.ARRAY ? of(a.getSize(), new Slot(idx)) : none(a.getSize());
                slot += a.getSize(); idx++;
            }
            return none(type.getSize());
        }
        @Override public V newOperation(AbstractInsnNode insn) {
            if (insn.getOpcode() == Opcodes.NEW) {
                Alloc a = allocs.computeIfAbsent(insn, k -> new Alloc(((TypeInsnNode) insn).desc));
                return of(1, a);
            }
            return switch (insn.getOpcode()) {
                case Opcodes.LCONST_0, Opcodes.LCONST_1, Opcodes.DCONST_0, Opcodes.DCONST_1 -> none(2);
                case Opcodes.LDC -> { Object c = ((LdcInsnNode) insn).cst; yield none(c instanceof Long || c instanceof Double ? 2 : 1); }
                case Opcodes.GETSTATIC -> none(Type.getType(((FieldInsnNode) insn).desc).getSize());
                default -> none(1);
            };
        }
        @Override public V copyOperation(AbstractInsnNode insn, V v) { return v; }
        @Override public V unaryOperation(AbstractInsnNode insn, V v) {
            switch (insn.getOpcode()) {
                case Opcodes.CHECKCAST: return v;
                case Opcodes.GETFIELD: {
                    FieldInsnNode fi = (FieldInsnNode) insn;
                    int size = Type.getType(fi.desc).getSize();
                    Set<Org> o = new LinkedHashSet<>();
                    for (Org x : v.orgs) {
                        if (x instanceof Slot sl && sl.i < 0) o.add(new Fld(fi.name));
                        else if (x instanceof Alloc a) o.addAll(a.binds.getOrDefault(fi.name, Set.of()));
                    }
                    return new V(size, o);
                }
                case Opcodes.PUTSTATIC: return null;
                case Opcodes.I2L: case Opcodes.I2D: case Opcodes.F2L: case Opcodes.F2D: case Opcodes.LNEG: case Opcodes.DNEG:
                    return none(2);
                case Opcodes.L2I: case Opcodes.L2F: case Opcodes.D2I: case Opcodes.D2F:
                    return none(1);
                case Opcodes.IFEQ: case Opcodes.IFNE: case Opcodes.IFLT: case Opcodes.IFGE: case Opcodes.IFGT: case Opcodes.IFLE:
                case Opcodes.TABLESWITCH: case Opcodes.LOOKUPSWITCH: case Opcodes.IRETURN: case Opcodes.LRETURN:
                case Opcodes.FRETURN: case Opcodes.DRETURN: case Opcodes.ATHROW: case Opcodes.MONITORENTER:
                case Opcodes.MONITOREXIT: case Opcodes.IFNULL: case Opcodes.IFNONNULL:
                    return null;
                case Opcodes.ARETURN: s.ret.addAll(v.orgs); return null;
                default: return none(insn.getOpcode() == Opcodes.L2D || insn.getOpcode() == Opcodes.D2L ? 2 : 1);
            }
        }
        @Override public V binaryOperation(AbstractInsnNode insn, V a, V b) {
            switch (insn.getOpcode()) {
                case Opcodes.PUTFIELD: {
                    FieldInsnNode fi = (FieldInsnNode) insn;
                    for (Org x : a.orgs) {
                        if (x instanceof Slot sl && sl.i < 0) s.puts.computeIfAbsent(fi.name, k -> new LinkedHashSet<>()).addAll(b.orgs);
                        else if (x instanceof Alloc al) al.bind(fi.name, b.orgs);
                    }
                    return null;
                }
                case Opcodes.AALOAD: {
                    Set<Org> o = new LinkedHashSet<>();
                    for (Org x : a.orgs) if (x instanceof Slot sl && sl.i >= 0) o.add(new Elem(sl.i));
                    return new V(1, o);
                }
                case Opcodes.LALOAD: case Opcodes.DALOAD: case Opcodes.LADD: case Opcodes.DADD: case Opcodes.LSUB: case Opcodes.DSUB:
                case Opcodes.LMUL: case Opcodes.DMUL: case Opcodes.LDIV: case Opcodes.DDIV: case Opcodes.LREM: case Opcodes.DREM:
                case Opcodes.LSHL: case Opcodes.LSHR: case Opcodes.LUSHR: case Opcodes.LAND: case Opcodes.LOR: case Opcodes.LXOR:
                    return none(2);
                case Opcodes.IF_ICMPEQ: case Opcodes.IF_ICMPNE: case Opcodes.IF_ICMPLT: case Opcodes.IF_ICMPGE: case Opcodes.IF_ICMPGT:
                case Opcodes.IF_ICMPLE: case Opcodes.IF_ACMPEQ: case Opcodes.IF_ACMPNE:
                    return null;
                default: return none(1);
            }
        }
        @Override public V ternaryOperation(AbstractInsnNode insn, V a, V b, V c) { return null; }
        @Override public V naryOperation(AbstractInsnNode insn, List<? extends V> values) {
            if (insn instanceof MethodInsnNode mi) return g.call(this, mi, values);
            if (insn instanceof InvokeDynamicInsnNode id) {
                Type r = Type.getReturnType(id.desc);
                // a lambda / method handle can run anything; a concat runs toString on every operand that is not a
                // String or a primitive (an Object operand may be a user value)
                if (!id.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) { s.open = true; if (s.why == null) s.why = "indy " + id.name + " in " + body + "." + mn.name; }
                else for (Type a : Type.getArgumentTypes(id.desc))
                    if (a.getSort() == Type.OBJECT && !g.finalJdk(a.getInternalName())) { s.open = true; if (s.why == null) s.why = "concat " + a + " in " + body + "." + mn.name; }
                return r == Type.VOID_TYPE ? null : none(r.getSize());
            }
            if (insn.getOpcode() == Opcodes.MULTIANEWARRAY) return none(1);
            return none(1);
        }
        @Override public void returnOperation(AbstractInsnNode insn, V value, V expected) {
            if (insn.getOpcode() == Opcodes.ARETURN && value != null) s.ret.addAll(value.orgs);
        }
        @Override public V merge(V a, V b) {
            if (a.equals(b)) return a;
            if (a.orgs.containsAll(b.orgs) && a.size == b.size) return a;
            Set<Org> u = new LinkedHashSet<>(a.orgs); u.addAll(b.orgs);
            return new V(Math.min(a.size, b.size), u);
        }
    }

    void hook(Summary s, Org slot, String member, Set<String> guards, List<Set<Org>> args) {
        if (slot instanceof Alloc) return;   // a call on an object the JDK allocated: exact, followed
        Set<String> g = Set.copyOf(guards);
        // a hook already present under a SUBSET of these guards subsumes this one; one under a superset is subsumed
        HookKey nk = new HookKey(slot, member, g);
        List<Set<Org>> cur = s.hookArgs.get(nk);
        if (cur == null) {
            List<HookKey> drop = new ArrayList<>();
            for (var e : s.hookArgs.entrySet()) {
                HookKey k = e.getKey();
                if (!k.slot().equals(slot) || !k.member().equals(member)) continue;
                if (g.containsAll(k.guards())) { cur = e.getValue(); break; }
                if (k.guards().containsAll(g)) drop.add(k);
            }
            if (cur == null) {
                cur = new ArrayList<>();
                for (HookKey k : drop) {   // keep the arguments of what it replaces
                    List<Set<Org>> old = s.hookArgs.remove(k);
                    for (int i = 0; i < old.size(); i++) { while (cur.size() <= i) cur.add(new LinkedHashSet<>()); cur.get(i).addAll(old.get(i)); }
                }
                s.hookArgs.put(nk, cur);
            }
        }
        for (int i = 0; i < args.size(); i++) {
            while (cur.size() <= i) cur.add(new LinkedHashSet<>());
            for (Org o : args.get(i)) if (!(o instanceof Alloc)) cur.get(i).add(o);   // bounded: an argument allocation is not carried
        }
    }

    /** One call instruction inside a summarised body. */
    V call(Interp in, MethodInsnNode mi, List<? extends V> values) {
        Type rt = Type.getReturnType(mi.desc);
        if (mi.owner.startsWith("[")) return rt == Type.VOID_TYPE ? null : new V(rt.getSize(), Set.of());   // an array's clone
        int rsize = rt == Type.VOID_TYPE ? 0 : rt.getSize();
        Set<Org> ret = new LinkedHashSet<>();
        boolean stat = mi.getOpcode() == Opcodes.INVOKESTATIC;
        V recv = stat ? null : values.get(0);
        List<? extends V> args = stat ? values : values.subList(1, values.size());
        String member = mi.name + mi.desc;
        Summary s = in.s;
        if (stat || mi.getOpcode() == Opcodes.INVOKESPECIAL) {
            String b = stat ? resolve(mi.owner, mi.name, mi.desc) : (mi.name.equals("<init>") ? mi.owner : resolve(mi.owner, mi.name, mi.desc));
            if (b != null && concrete(declared(b, mi.name, mi.desc))) {
                if (stat) {
                    Summary cs = summary(b, b, mi.name, mi.desc, in.depth + 1);
                    ret.addAll(apply(in, mi, cs, null, args, Set.of(), false));
                } else {
                    for (Org o : recv.orgs) {
                        if (o instanceof Slot sl && sl.i < 0) {          // super(..) / private / super.m() on this: context stays
                            Summary cs = summary(in.ctx, b, mi.name, mi.desc, in.depth + 1);
                            ret.addAll(apply(in, mi, cs, recv, args, Set.of(), true));
                        } else if (o instanceof Alloc a) {               // new D(..): its constructor binds a's fields
                            Summary cs = summary(a.cls, b, mi.name, mi.desc, in.depth + 1);
                            for (var e : cs.puts.entrySet())
                                a.bind(e.getKey(), mapAll(in, mi, e.getValue(), recv, args, a, Set.of()));
                            ret.addAll(apply(in, mi, cs, of1(a), args, Set.of(), false));
                        } else {
                            Summary cs = summary(b, b, mi.name, mi.desc, in.depth + 1);
                            ret.addAll(apply(in, mi, cs, null, args, Set.of(), false));
                        }
                    }
                    if (recv.orgs.isEmpty()) {
                        Summary cs = summary(b, b, mi.name, mi.desc, in.depth + 1);
                        ret.addAll(apply(in, mi, cs, null, args, Set.of(), false));
                    }
                }
            }
            return rsize == 0 ? null : new V(rsize, ret);
        }
        // virtual / interface
        boolean followedUnknown = false;
        for (Org o : recv.orgs) {
            if (o instanceof Slot sl && sl.i < 0) {
                String b = resolve(in.ctx, mi.name, mi.desc);
                s.tres.put(member, b == null ? "-" : b);
                MethodNode decl = declarationFrom(in.ctx, mi.name, mi.desc);
                if (decl == null) decl = declarationFrom(mi.owner, mi.name, mi.desc);
                boolean ov = userSubclassable(in.ctx) && overridable(decl) && !mi.name.startsWith("<");
                if (ov) hook(s, o, member, Set.of(), argOrgs(args));
                if (b != null) {
                    Summary cs = summary(in.ctx, b, mi.name, mi.desc, in.depth + 1);
                    for (var e : cs.tres.entrySet()) s.tres.putIfAbsent(e.getKey(), e.getValue());
                    ret.addAll(apply(in, mi, cs, recv, args, ov ? Set.of(member) : Set.of(), true));
                }
            } else if (o instanceof Slot sl) {
                MethodNode decl = declarationFrom(mi.owner, mi.name, mi.desc);
                ClassNode oc = classes.get(mi.owner);
                boolean finalOwner = oc != null && (oc.access & Opcodes.ACC_FINAL) != 0;
                // recorded even where no USER class can override it ("~": a JDK-private abstraction): a caller may map
                // the parameter to an object it allocated and follow the call there (Throwable's WrappedPrintStream)
                if (!finalOwner) hook(s, o, overridable(decl) ? member : "~" + member, Set.of(), argOrgs(args));
                if ((finalOwner || !overridable(decl)) && !followedUnknown) {   // final owner (String): the body is exact — follow its arguments
                    String b = resolve(mi.owner, mi.name, mi.desc);
                    if (b != null) { ret.addAll(apply(in, mi, summary(b, b, mi.name, mi.desc, in.depth + 1), null, args, Set.of(), false)); followedUnknown = true; }
                }
            } else if (o instanceof Elem) {
                s.open = true; if (s.why == null) s.why = "elem " + mi.owner + "." + mi.name;
                MethodNode decl = declarationFrom(mi.owner, mi.name, mi.desc);
                hook(s, o, overridable(decl) ? member : "~" + member, Set.of(), argOrgs(args));
            } else if (o instanceof Fld f) {
                if (userAnswerable(mi)) { s.open = true; if (s.why == null) s.why = "field " + f.f + " " + mi.owner + "." + mi.name + " in " + in.body + "." + in.mn.name; }   // the field may hold a user object
                hook(s, o, member, Set.of(), argOrgs(args));
                if (!followedUnknown) {
                    String b = resolve(mi.owner, mi.name, mi.desc);
                    if (b != null) { ret.addAll(apply(in, mi, summary(b, b, mi.name, mi.desc, in.depth + 1), null, args, Set.of(), false)); followedUnknown = true; }
                    // a field declared by an abstraction (TreeSet's NavigableMap m): the classes this receiver's own
                    // constructors store there (new TreeMap<>()) — each followed exactly, for its arguments
                    for (String d : fieldAllocClasses(in.ctx, f.f)) {
                        String db = resolve(d, mi.name, mi.desc);
                        if (db != null && !db.equals(b)) ret.addAll(apply(in, mi, summary(d, db, mi.name, mi.desc, in.depth + 1), null, args, Set.of(), false));
                    }
                }
            } else if (o instanceof Alloc a) {
                String b = resolve(a.cls, mi.name, mi.desc);
                if (b != null) {
                    Summary cs = summary(a.cls, b, mi.name, mi.desc, in.depth + 1);
                    ret.addAll(apply(in, mi, cs, of1(a), args, a.guards, false));
                }
            }
        }
        if (recv.orgs.isEmpty()) {
            if (userAnswerable(mi)) { s.open = true; if (s.why == null) s.why = "unknown " + mi.owner + "." + mi.name + " in " + in.body + "." + in.mn.name; }      // a value the summary cannot name, of a type a user can supply
            String b = resolve(mi.owner, mi.name, mi.desc);
            if (b != null) ret.addAll(apply(in, mi, summary(b, b, mi.name, mi.desc, in.depth + 1), null, args, Set.of(), false));
            else for (String d : closedImplementors(mi.owner, mi.name, mi.desc)) {
                // an abstraction NO user class can implement (Formatter's private FormatString): its JDK implementors
                // are the whole set, so each is followed for its arguments
                String db = resolve(d, mi.name, mi.desc);
                if (db != null) ret.addAll(apply(in, mi, summary(d, db, mi.name, mi.desc, in.depth + 1), null, args, Set.of(), false));
            }
        }
        return rsize == 0 ? null : new V(rsize, ret);
    }
    static V of1(Alloc a) { return new V(1, Set.of(a)); }

    /** Fold a callee summary into the caller: hooks mapped to the caller's origins, guards added; returns the mapped
     *  return origins. {@code thisToThis}: the callee's THIS is the caller's THIS (a call on this), so its guards and
     *  this-hooks carry over; otherwise the callee's this-hooks are dropped (an exact JDK object, or unknown). */
    Set<Org> apply(Interp in, MethodInsnNode mi, Summary cs, V recv, List<? extends V> args, Set<String> addGuards, boolean thisToThis) {
        Summary s = in.s;
        // openness travels along the receiver: a call on this, or on an object this body built. A static or exact
        // helper's own openness is about ITS values (an exception message formatted on a bounds failure), and what it
        // does with ours is already in its hooks.
        boolean onOurs = thisToThis;
        if (recv != null) for (Org o : recv.orgs) if (o instanceof Alloc) onOurs = true;
        if (cs.open && onOurs) { s.open = true; if (s.why == null) s.why = cs.why; }
        for (Hook h : cs.hooks()) {
            // a callee's guards name members of ITS receiver: ours only when its this is ours; an exact JDK receiver
            // (an allocation, an unknown value) cannot be overridden by a user, so its guards always hold
            Set<String> gs = new TreeSet<>(thisToThis ? h.guards() : Set.of()); gs.addAll(addGuards);
            if (h.slot() instanceof Slot sl && sl.i < 0) {
                if (thisToThis) hook(s, new Slot(-1), h.member(), gs, mapArgs(in, mi, h.args(), recv, args));
                continue;   // otherwise a call on an exact JDK object: followed already
            }
            Set<String> g2 = gs;
            if (recv != null && h.slot() instanceof Fld)
                for (Org r : recv.orgs) if (r instanceof Alloc a) { g2 = new TreeSet<>(g2); g2.addAll(a.guards); }
            List<Set<Org>> margs = mapArgs(in, mi, h.args(), recv, args);
            for (Org o : mapOne(in, mi, h.slot(), recv, args, thisToThis)) {
                if (o instanceof Alloc a) {
                    // the callee called a member on a value the CALLER allocated: exact here, so follow it
                    String mem = h.member().startsWith("~") ? h.member().substring(1) : h.member();
                    int sp = mem.indexOf('(');
                    String nm = mem.substring(0, sp), ds = mem.substring(sp);
                    String b = resolve(a.cls, nm, ds);
                    if (b != null && in.followed.add(System.identityHashCode(a) + ":" + h.member() + ":" + margs)) {
                        List<V> vs = new ArrayList<>();
                        for (Set<Org> x : margs) vs.add(new V(1, x));
                        apply(in, mi, summary(a.cls, b, nm, ds, in.depth + 1), of1(a), vs, g2, false);
                    }
                } else hook(s, o, h.member(), g2, margs);
            }
        }
        if (thisToThis) for (var e : cs.puts.entrySet()) s.puts.computeIfAbsent(e.getKey(), k -> new LinkedHashSet<>()).addAll(mapAll(in, mi, e.getValue(), recv, args, null, Set.of()));
        return mapAll(in, mi, cs.ret, recv, args, null, addGuards);
    }

    static List<Set<Org>> argOrgs(List<? extends V> args) {
        List<Set<Org>> r = new ArrayList<>();
        for (V v : args) r.add(v == null ? Set.of() : v.orgs);
        return r;
    }
    List<Set<Org>> mapArgs(Interp in, MethodInsnNode mi, List<Set<Org>> hargs, V recv, List<? extends V> args) {
        List<Set<Org>> r = new ArrayList<>();
        for (Set<Org> x : hargs) r.add(mapAll(in, mi, x, recv, args, null, Set.of()));
        return r;
    }
    /** a receiver class a user can subclass, so a call on its this can reach a user override */
    boolean userSubclassable(String ctx) {
        ClassNode c = classes.get(ctx);
        return c != null && extendable(c);
    }

    Set<Org> mapAll(Interp in, MethodInsnNode mi, Set<Org> os, V recv, List<? extends V> args, Alloc self, Set<String> guards) {
        Set<Org> r = new LinkedHashSet<>();
        for (Org o : os) {
            if (o instanceof Slot sl && sl.i < 0) { if (self != null) r.add(self); else if (recv != null) r.addAll(recv.orgs); }
            else if (o instanceof Alloc a) r.add(translate(in, mi, a, recv, args, guards));
            else r.addAll(mapOne(in, mi, o, recv, args, true));
        }
        return r;
    }
    /** a callee's allocation, seen at this call site: its bindings mapped to the caller's origins */
    Alloc translate(Interp in, MethodInsnNode mi, Alloc a, V recv, List<? extends V> args, Set<String> guards) {
        String k = System.identityHashCode(mi) + ":" + a.cls;     // one per class per call site
        Alloc t = in.translated.get(k);
        if (t == null) { t = new Alloc(a.cls); in.translated.put(k, t); }
        t.guards.addAll(guards); t.guards.addAll(a.guards);
        for (var e : a.binds.entrySet()) {
            Set<Org> m = new LinkedHashSet<>();
            for (Org o : e.getValue()) {
                if (o instanceof Slot sl && sl.i < 0) { if (recv != null) m.addAll(recv.orgs); }
                else if (o instanceof Alloc) { /* nested allocation: dropped (bounded) */ }
                else m.addAll(mapOne(in, mi, o, recv, args, true));
            }
            t.bind(e.getKey(), m);
        }
        return t;
    }
    /** a call a USER class could answer: the owner is an exported public non-final class or interface, the member
     *  overridable */
    boolean userAnswerable(MethodInsnNode mi) {
        ClassNode oc = classes.get(mi.owner);
        if (oc == null) return true;
        if (!exported(mi.owner) || (oc.access & Opcodes.ACC_PUBLIC) == 0 || (oc.access & Opcodes.ACC_FINAL) != 0) return false;
        return overridable(declarationFrom(mi.owner, mi.name, mi.desc));
    }
    boolean finalJdk(String t) {
        ClassNode c = classes.get(t);
        return c != null && (c.access & Opcodes.ACC_FINAL) != 0;
    }

    Map<String, List<String>> subs;
    /** the concrete JDK implementors of an abstraction that is NOT public in an exported package (so no user class can
     *  implement it), declaring or inheriting the member; empty past 16 (a bound, not a claim) */
    List<String> closedImplementors(String owner, String name, String desc) {
        ClassNode oc = classes.get(owner);
        if (oc == null || owner.startsWith("[")) return List.of();
        if (exported(owner) && (oc.access & Opcodes.ACC_PUBLIC) != 0) return List.of();
        if (subs == null) {
            subs = new HashMap<>();
            for (ClassNode c : classes.values()) {
                if (c.superName != null) subs.computeIfAbsent(c.superName, k -> new ArrayList<>()).add(c.name);
                for (String i : c.interfaces) subs.computeIfAbsent(i, k -> new ArrayList<>()).add(c.name);
            }
        }
        List<String> r = new ArrayList<>();
        Deque<String> q = new ArrayDeque<>(subs.getOrDefault(owner, List.of()));
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            q.addAll(subs.getOrDefault(c, List.of()));
            ClassNode cn = classes.get(c);
            if (cn == null || (cn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE)) != 0) continue;
            if (resolve(c, name, desc) != null) r.add(c);
            if (r.size() > 16) return List.of();
        }
        return r;
    }

    /** the classes a receiver class's constructors (declared in it or a JDK super) store into its field f */
    Set<String> fieldAllocClasses(String ctx, String f) {
        Set<String> r = new TreeSet<>();
        for (String c = ctx; c != null; ) {
            ClassNode cn = classes.get(c);
            if (cn == null) break;
            for (MethodNode m : cn.methods) {
                if (!m.name.equals("<init>")) continue;
                for (Org o : summary(ctx, c, m.name, m.desc, 0).puts.getOrDefault(f, Set.of())) if (o instanceof Alloc a) r.add(a.cls);
            }
            c = cn.superName;
        }
        return r;
    }

    Set<Org> mapOne(Interp in, MethodInsnNode mi, Org o, V recv, List<? extends V> args, boolean thisToThis) {
        if (o instanceof Elem e) {
            Set<Org> r = new LinkedHashSet<>();
            if (e.i < args.size() && args.get(e.i) != null)
                for (Org x : args.get(e.i).orgs) if (x instanceof Slot sl && sl.i >= 0) r.add(new Elem(sl.i));
            return r;
        }
        if (o instanceof Slot sl) {
            if (sl.i < 0) return recv == null ? Set.of() : recv.orgs;
            return sl.i < args.size() && args.get(sl.i) != null ? args.get(sl.i).orgs : Set.of();
        }
        if (o instanceof Fld f) {
            if (recv == null) return Set.of();
            Set<Org> r = new LinkedHashSet<>();
            for (Org x : recv.orgs) {
                if (x instanceof Slot sl && sl.i < 0 && thisToThis) r.add(f);
                else if (x instanceof Alloc a) r.addAll(a.binds.getOrDefault(f.f, Set.of()));
            }
            return r;
        }
        return Set.of();
    }

    // ------------------------------------------------------------------------------------------- driver
    void run() {
        runPass();          // requests every top key (empty at first)
        drain();
        out.clear();
        runPass();          // reads the converged summaries
        decorators();
        if (DEBUG) System.err.println("SITEGEN " + memo.size() + " summaries, " + computations + " computations");
    }

    void runPass() {
        List<String> names = new ArrayList<>(classes.keySet());
        Collections.sort(names);
        for (String x : names) {
            ClassNode c = classes.get(x);
            if (!exported(x) || (c.access & Opcodes.ACC_PUBLIC) == 0) continue;
            boolean ext = extendable(c);
            // the members a call naming X (or a user subclass of X) can reach: X's own, and the inherited ones
            Map<String, String> members = new TreeMap<>();
            Deque<String> q = new ArrayDeque<>(List.of(x));
            Set<String> seen = new HashSet<>();
            while (!q.isEmpty()) {
                String t = q.poll();
                if (!seen.add(t)) continue;
                ClassNode tn = classes.get(t);
                if (tn == null) continue;
                for (MethodNode m : tn.methods) {
                    if ((m.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) == 0) continue;
                    if (!t.equals(x) && (m.name.startsWith("<") || (m.access & Opcodes.ACC_STATIC) != 0)) continue;
                    members.putIfAbsent(m.name + m.desc, t);
                }
                if (tn.superName != null) q.add(tn.superName);
                q.addAll(tn.interfaces);
            }
            for (String md : members.keySet()) {
                int sp = md.indexOf('(');
                String name = md.substring(0, sp), desc = md.substring(sp);
                MethodNode own = declared(x, name, desc);
                String b = own != null && (own.access & Opcodes.ACC_STATIC) != 0 ? x
                        : name.equals("<init>") ? x : resolve(x, name, desc);
                if (b == null) continue;
                Summary sm = summary(x, b, name, desc, 0);
                TreeSet<String> hs = new TreeSet<>();
                for (Hook h : sm.hooks()) {
                    if (h.slot() instanceof Fld || h.member().startsWith("~")) continue;
                    if (h.slot() instanceof Elem && !(h.member().startsWith("toString(") || h.member().startsWith("compareTo(")
                            || h.member().startsWith("equals(") || h.member().startsWith("hashCode("))) continue;
                    if (h.slot() instanceof Slot sl && sl.i < 0 && (!ext || name.equals("<init>"))) continue;
                    hs.add(h.slot() + " " + h.member() + (h.guards().isEmpty() ? "" : " " + String.join(",", new TreeSet<>(h.guards()))));
                }
                residual(x, name, desc, hs);
                if (!hs.isEmpty() && sm.open) hs.add("! open");
                prune(hs);
                if (!hs.isEmpty()) out.put(x + "." + name + desc, hs);
            }
        }
    }

    // ------------------------------------------------------------------------------------------- stream decorators
    static final List<String> STREAM_BASES = List.of("java/io/InputStream", "java/io/OutputStream", "java/io/Reader", "java/io/Writer");
    String streamBase(String t) {
        for (String b : STREAM_BASES) if (isSub(t, b)) return b;
        return null;
    }
    /** The stream DECORATORS: an exported public JDK stream class with an accessible constructor taking a stream —
     *  its bodies read/write that DELEGATE, held in a field the summary does not follow (BufferedReader's {@code in},
     *  DataInputStream's {@code in}, InputStreamReader's decoder over its InputStream). Line {@code X.<delegate>} with
     *  one {@code @ base} per delegate base; and for each base, {@code B.<members>} with {@code @ member} per
     *  accessible instance member B declares — what a decorator's body can run on its delegate. */
    void decorators() {
        for (String x : new TreeSet<>(classes.keySet())) {
            ClassNode c = classes.get(x);
            if (!exported(x) || (c.access & Opcodes.ACC_PUBLIC) == 0 || (c.access & Opcodes.ACC_INTERFACE) != 0) continue;
            if (STREAM_BASES.contains(x) || streamBase(x) == null) continue;
            TreeSet<String> bs = new TreeSet<>();
            for (MethodNode m : c.methods) {
                if (!m.name.equals("<init>") || (m.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) == 0) continue;
                for (Type a : Type.getArgumentTypes(m.desc))
                    if (a.getSort() == Type.OBJECT) { String b = streamBase(a.getInternalName()); if (b != null) bs.add("@ " + b); }
            }
            if (!bs.isEmpty()) out.put(x + ".<delegate>", bs);
        }
        for (String b : STREAM_BASES) {
            ClassNode c = classes.get(b);
            if (c == null) continue;
            TreeSet<String> ms = new TreeSet<>();
            for (MethodNode m : c.methods)
                if (!m.name.startsWith("<") && (m.access & Opcodes.ACC_STATIC) == 0 && (m.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0)
                    ms.add("@ " + m.name + m.desc);
            out.put(b + ".<members>", ms);
        }
    }

    /** a hook whose guard set contains another's for the same slot and member adds nothing: drop it */
    static void prune(TreeSet<String> hs) {
        Map<String, List<Set<String>>> by = new HashMap<>();
        for (String h : hs) {
            String[] p = h.split(" ");
            by.computeIfAbsent(p[0] + " " + p[1], k -> new ArrayList<>()).add(p.length > 2 ? Set.of(p[2].split(",")) : Set.of());
        }
        hs.removeIf(h -> {
            String[] p = h.split(" ");
            if (p.length < 3) return false;
            Set<String> g = Set.of(p[2].split(","));
            for (Set<String> o : by.get(p[0] + " " + p[1])) if (!o.equals(g) && g.containsAll(o)) return true;
            return false;
        });
    }

    /** The hand residual (see the class doc): native / reflective entry the bytecode does not show. */
    void residual(String x, String name, String desc, TreeSet<String> hs) {
        if (name.equals("start") && desc.equals("()V") && isSub(x, "java/lang/Thread") && extendable(classes.get(x))) hs.add("t run()V");
        // a PrintStream formats through an OutputStreamWriter its constructor wrapped around THIS (charOut/textOut), so
        // every text member ends in this.write(byte[],int,int): a chain through fields built in the constructor, which
        // the summary does not follow (a field-held allocation's bindings are not carried) — named here instead
        if (isSub(x, "java/io/PrintStream") && extendable(classes.get(x))
                && (name.equals("print") || name.equals("println") || name.equals("append") || name.equals("format")
                    || name.equals("printf") || name.equals("write") && desc.startsWith("(Ljava/lang/String;")))
            hs.add("t write([BII)V");
        if (x.equals("java/io/ObjectOutputStream") && (name.equals("writeObject") || name.equals("writeUnshared"))
                && desc.equals("(Ljava/lang/Object;)V")) {
            hs.add("0 #writeObject(Ljava/io/ObjectOutputStream;)V");
            hs.add("0 #writeReplace()Ljava/lang/Object;");
            hs.add("0 writeExternal(Ljava/io/ObjectOutput;)V");
        }
    }
}
