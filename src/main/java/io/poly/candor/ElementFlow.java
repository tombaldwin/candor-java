package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import io.poly.candor.Interp.ProvValue;
import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

/**
 * SOUNDNESS R1166 — A COLLECTION RUNS ITS ELEMENTS' {@code equals}/{@code hashCode}.
 *
 * <p>`list.hashCode()`, `list.equals(o)`, `new HashSet<>(list)`, `r.removeAll(c)` (which runs {@code c.contains(e)},
 * i.e. {@code e.equals(..)}, and {@code e.hashCode()} when {@code c} is hashed) and `a.containsAll(b)` run the Object
 * protocol of the ELEMENTS; a set's {@code equals}/{@code removeAll} also hash the ARGUMENT's elements, and a sorted
 * collection runs neither (each executed on JDK 21). Until R1166 the only
 * thing covering that was a charge at `list.add(x)` for {@code x.equals}/{@code x.hashCode} — which `add` never runs
 * (executed: no file) and which, measured by an independent removal audit, was the sole cover for real effects in
 * exactly these shapes (`aw-lostRealHash/Eq/Set`, `both`, `useBuilt`, `lostRemoveAll`, and junit-platform-console's
 * `CommandLine$Help.excludeHiddenAndGroupOptions`, whose `OptionSpec.equals` reads the environment). This models the
 * REAL path instead, a resolution:
 *
 * <ul>
 *   <li>a CELL per collection: a local allocation, a static or instance field, a method's return, a parameter, a
 *       call-site result. Elements flow ONE WAY along `addAll`, a copying constructor or wrapper, a field store and a
 *       return — never back into a callee or a shared factory, so a `newArrayList()` used everywhere does not merge
 *       every caller's elements;</li>
 *   <li>an element's type is the added value's ({@code new T} exact, else declared), or the generic argument a
 *       field, parameter or project method's signature names (declared);</li>
 *   <li>a dispatching operation charges its method with the elements' member through the argument contract's own
 *       rules ({@link ArgContract#applyResolved}: one body, or a disclosed {@code Unknown}).</li>
 * </ul>
 *
 * <p>After the analyze loop only; reads bodies like DbHandleFlow. Residuals: elements of a map, a collection handed
 * to code outside the scan (a dependency's disclosure covers it, or nothing does), arrays.
 */
final class ElementFlow {
    private ElementFlow() {}

    static final String EQ = ArgContract.EQUALS, HASH = ArgContract.HASHCODE;
    static final boolean DEBUG = ArgContract.DEBUG;

    private static boolean isCollectionOwner(String o) {
        return o.startsWith("java/util/") && !o.startsWith("java/util/function/") && !o.startsWith("java/util/stream/")
                && !o.equals("java/util/Objects") && !o.startsWith("java/util/regex/") && !o.startsWith("java/util/concurrent/atomic/")
                && !o.startsWith("java/util/logging/");
    }
    private static boolean hashed(String o) {
        // a SORTED set/map compares (compareTo/Comparator), and an identity map uses ==/identityHashCode:
        // `new TreeSet<>(l)` runs neither equals nor hashCode on l's elements (executed)
        if (o.contains("Tree") || o.contains("Sorted") || o.contains("Navigable") || o.contains("SkipList")
                || o.contains("EnumSet") || o.contains("Identity")) return false;
        return o.contains("Set") || o.contains("HashMap") || o.contains("Hashtable") || o.equals("java/util/Map");
    }
    /** A receiver statically known to be a list: its bulk operations never hash the ARGUMENT's elements. */
    private static boolean listOwner(String o) {
        return o.endsWith("List") || o.equals("java/util/Vector") || o.equals("java/util/Stack");
    }
    private static final Set<String> ADD = Set.of("add", "addFirst", "addLast", "offer", "offerFirst", "offerLast", "push");
    private static final Set<String> WRAP = Set.of("unmodifiableList", "unmodifiableSet", "unmodifiableCollection",
            "unmodifiableSortedSet", "unmodifiableNavigableSet", "synchronizedList", "synchronizedSet",
            "synchronizedCollection", "copyOf", "checkedList", "checkedSet", "checkedCollection");

    /** cell -> element types {"type\texact"}; and src cell -> dst cells (elements of src are elements of dst). */
    private static final class Graph {
        final Map<String, Set<String>> elems = new HashMap<>();
        final Map<String, Set<String>> flow = new HashMap<>();
        final List<String[]> dispatch = new ArrayList<>();   // {caller, cell, key}
        void elem(String cell, String t, boolean exact) {
            if (cell != null && t != null) elems.computeIfAbsent(cell, k -> new HashSet<>()).add(t + "\t" + (exact ? 1 : 0));
        }
        void link(String src, String dst) { if (src != null && dst != null && !src.equals(dst)) flow.computeIfAbsent(src, k -> new HashSet<>()).add(dst); }
    }

    static void run(AnalysisContext c) {
        Graph g = new Graph();
        for (ClassNode cn : c.ALL) {
            if (!c.projectClasses.contains(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions.size() == 0 || !relevant(mn)) continue;
                try { scan(c, g, cn, mn); } catch (Throwable e) { /* an unreadable body adds nothing */ }
            }
        }
        // close the one-way flow
        boolean changed = true; int rounds = 0;
        while (changed && rounds++ < 64) {
            changed = false;
            for (var e : g.flow.entrySet()) {
                Set<String> s = g.elems.get(e.getKey());
                if (s == null || s.isEmpty()) continue;
                for (String d : e.getValue()) changed |= g.elems.computeIfAbsent(d, k -> new HashSet<>()).addAll(s);
            }
        }
        for (String[] d : g.dispatch) {
            Set<String> es = g.elems.get(d[1]);
            if (es == null) continue;
            for (String te : es) {
                int tab = te.indexOf('\t');
                String t = te.substring(0, tab);
                if (DEBUG) System.err.println("R1166ELEM\t" + d[0] + "\t" + d[2] + "\t" + t + "\t" + d[1]);
                ArgContract.applyResolved(c, d[0], d[2], t, te.endsWith("1"), false);
            }
        }
    }

    private static boolean relevant(MethodNode mn) {
        for (AbstractInsnNode in : mn.instructions)
            if (in instanceof MethodInsnNode m && isCollectionOwner(m.owner)) return true;
        return false;
    }

    private static void scan(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn) throws Exception {
        String id = Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc);
        if (!c.edges.containsKey(id)) return;
        Frame<SourceValue>[] sf = new Analyzer<>(new SourceInterpreter()).analyze(cn.name, mn);
        Frame<ProvValue>[] pf = Candor.cachedProvFrames(cn, mn);
        String self = "M:" + id;
        InsnList is = mn.instructions;
        for (int i = 0; i < is.size(); i++) {
            AbstractInsnNode in = is.get(i);
            Frame<SourceValue> f = sf[i];
            if (f == null) continue;
            int op = in.getOpcode();
            if ((op == Opcodes.PUTFIELD || op == Opcodes.PUTSTATIC) && ((FieldInsnNode) in).desc.startsWith("L")) {
                FieldInsnNode fi = (FieldInsnNode) in;
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, 0))
                    g.link(cell, "F:" + fi.owner + "." + fi.name);
                continue;
            }
            if (op == Opcodes.ARETURN) {
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, 0)) g.link(cell, "R:" + id);
                continue;
            }
            if (!(in instanceof MethodInsnNode m) || !isCollectionOwner(m.owner)) continue;
            Type[] at = Type.getArgumentTypes(m.desc);
            int n = at.length, base = f.getStackSize() - n;
            boolean inst = op != Opcodes.INVOKESTATIC;
            SourceValue recv = inst && base - 1 >= 0 ? f.getStack(base - 1) : null;
            Frame<ProvValue> p = pf == null ? null : pf[i];
            // element ADDED
            if (inst && ADD.contains(m.name) && n >= 1 && at[n - 1].getSort() == Type.OBJECT && p != null) {
                ProvValue v = Candor.callArg(p, m, n - 1);
                String t = v == null || v.nullConst ? null : ArgContract.typeOf(c, v);
                if (t != null) for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.elem(cell, t, v.newType != null);
            }
            // elements COPIED in
            if (inst && (m.name.equals("addAll") || m.name.equals("<init>")) && n >= 1 && at[n - 1].getSort() == Type.OBJECT
                    && at[n - 1].getInternalName().startsWith("java/util/")) {
                List<String> dst = cells(c, g, cn, mn, sf, recv, self, 0);
                for (String s : cells(c, g, cn, mn, sf, f.getStack(base + n - 1), self, 0)) for (String d : dst) g.link(s, d);
                if (m.name.equals("<init>") && hashed(m.owner))
                    for (String d : dst) { g.dispatch.add(new String[] {id, d, HASH}); g.dispatch.add(new String[] {id, d, EQ}); }
                if (m.name.equals("addAll") && hashed(m.owner))
                    for (String d : dst) { g.dispatch.add(new String[] {id, d, HASH}); g.dispatch.add(new String[] {id, d, EQ}); }
            }
            // DISPATCHING operations over the elements
            if (inst && m.desc.equals("()I") && m.name.equals("hashCode"))
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch.add(new String[] {id, cell, HASH});
            if (inst && m.name.equals("equals") && m.desc.equals("(Ljava/lang/Object;)Z")) {
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch.add(new String[] {id, cell, EQ});
                // a SET's equals is containsAll over the argument: the argument's elements are hashed and compared
                if (!listOwner(m.owner))
                    for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                        g.dispatch.add(new String[] {id, cell, HASH}); g.dispatch.add(new String[] {id, cell, EQ});
                    }
            }
            if (inst && (m.name.equals("removeAll") || m.name.equals("retainAll")) && n == 1) {
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) {
                    g.dispatch.add(new String[] {id, cell, EQ}); g.dispatch.add(new String[] {id, cell, HASH});
                }
                // a hashed receiver's removeAll may iterate the ARGUMENT and remove(e): its elements are hashed
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                    g.dispatch.add(new String[] {id, cell, EQ});
                    if (!listOwner(m.owner)) g.dispatch.add(new String[] {id, cell, HASH});
                }
            }
            // containsAll runs this.contains(e) for each ARGUMENT element: e.equals(..), and e.hashCode() when the
            // receiver is hashed. The receiver's own elements are only the arguments of those calls (executed).
            if (inst && m.name.equals("containsAll") && n == 1)
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                    g.dispatch.add(new String[] {id, cell, EQ});
                    if (!listOwner(m.owner)) g.dispatch.add(new String[] {id, cell, HASH});
                }
        }
    }

    /** The cells a collection-valued stack value can be, traced through locals, DUP and CHECKCAST to its producer. */
    private static List<String> cells(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            SourceValue v, String self, int depth) {
        List<String> out = new ArrayList<>();
        if (v == null || depth > 12) return out;
        for (AbstractInsnNode src : v.insns) {
            int idx = mn.instructions.indexOf(src);
            Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
            int op = src.getOpcode();
            switch (op) {
                case Opcodes.ALOAD -> {
                    int var = ((VarInsnNode) src).var;
                    if (f == null) break;
                    SourceValue lv = f.getLocal(var);
                    if (lv.insns.isEmpty()) {   // a parameter (or the receiver)
                        int p = paramOf(mn, var);
                        if (p >= 0) {
                            String cell = "P:" + self + ":" + p;
                            String e = paramElem(mn, p);
                            if (e != null) g.elem(cell, e, false);
                            out.add(cell);
                        }
                    } else {
                        for (AbstractInsnNode st : lv.insns) {
                            int si = mn.instructions.indexOf(st);
                            if (si < 0 || sf[si] == null) continue;
                            Frame<SourceValue> sfr = sf[si];
                            out.addAll(cells(c, g, cn, mn, sf, sfr.getStack(sfr.getStackSize() - 1), self, depth + 1));
                        }
                    }
                }
                case Opcodes.DUP, Opcodes.CHECKCAST -> {
                    if (f != null) out.addAll(cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, depth + 1));
                }
                case Opcodes.NEW -> out.add("L:" + self + ":" + idx);
                case Opcodes.GETSTATIC, Opcodes.GETFIELD -> {
                    FieldInsnNode fi = (FieldInsnNode) src;
                    String cell = "F:" + fi.owner + "." + fi.name;
                    String e = fieldElem(c, fi);
                    if (e != null) g.elem(cell, e, false);
                    out.add(cell);
                }
                case Opcodes.INVOKESTATIC, Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE, Opcodes.INVOKESPECIAL -> {
                    MethodInsnNode m = (MethodInsnNode) src;
                    String cell = "S:" + self + ":" + idx;
                    if (c.projectClasses.contains(m.owner)) {
                        ClassNode oc = c.byName.get(m.owner);
                        String tid = oc != null && Cha.declaresConcrete(oc, m.name, m.desc)
                                ? Cha.methodId(m.owner.replace('/', '.'), m.name, m.desc)
                                : Cha.nearestConcreteSuper(m.owner, m.name, m.desc);
                        if (tid != null) g.link("R:" + tid, cell);
                        String e = returnElem(c, m);
                        if (e != null) g.elem(cell, e, false);
                    } else if (m.owner.startsWith("java/util/") && f != null) {
                        Type[] at = Type.getArgumentTypes(m.desc);
                        int base = f.getStackSize() - at.length;
                        if (WRAP.contains(m.name) && at.length >= 1) {
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base), self, depth + 1)) g.link(s, cell);
                        } else if ((m.name.equals("of") || m.name.equals("asList")) && op == Opcodes.INVOKESTATIC) {
                            Frame<ProvValue>[] pf = Candor.cachedProvFrames(cn, mn);
                            if (pf != null && pf[idx] != null)
                                for (int k = 0; k < at.length; k++) {
                                    if (at[k].getSort() != Type.OBJECT) continue;
                                    ProvValue pv = Candor.callArg(pf[idx], m, k);
                                    String t = pv == null || pv.nullConst ? null : ArgContract.typeOf(c, pv);
                                    if (t != null) g.elem(cell, t, pv.newType != null);
                                }
                        }
                    }
                    out.add(cell);
                }
                default -> { }
            }
        }
        return out;
    }

    private static int paramOf(MethodNode mn, int var) {
        int slot = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        Type[] at = Type.getArgumentTypes(mn.desc);
        for (int p = 0; p < at.length; p++) {
            if (slot == var) return p;
            slot += at[p].getSize();
        }
        return -1;
    }

    private static String paramElem(MethodNode mn, int p) {
        return mn.signature == null ? null : firstTypeArg(mn.signature, p);
    }
    private static String returnElem(AnalysisContext c, MethodInsnNode m) {
        MethodNode t = Candor.findMethod(c.byName.get(m.owner), m.name, m.desc);
        return t == null || t.signature == null ? null : firstTypeArg(t.signature, -1);
    }
    private static String fieldElem(AnalysisContext c, FieldInsnNode fi) {
        ClassNode oc = c.byName.get(fi.owner);
        if (oc == null) return null;
        for (FieldNode fn : oc.fields)
            if (fn.name.equals(fi.name) && fn.signature != null) return firstTypeArgOfType(fn.signature);
        return null;
    }

    /** The first type argument (a class, or the bound of `? extends`) of method signature parameter {@code p} (or
     *  the return type when p < 0), when that parameter is a `java.util` collection; else null. */
    static String firstTypeArg(String sig, int p) {
        String[] out = {null};
        new SignatureReader(sig).accept(new SignatureVisitor(Opcodes.ASM9) {
            int param = -1; boolean inTarget, inRet, top; int depth;
            @Override public SignatureVisitor visitParameterType() { param++; inTarget = param == p; inRet = false; depth = 0; return this; }
            @Override public SignatureVisitor visitReturnType() { inTarget = p < 0; inRet = true; depth = 0; return this; }
            @Override public void visitClassType(String name) {
                if (!inTarget) return;
                if (depth == 0) top = name.startsWith("java/util/");
                else if (depth == 1 && top && out[0] == null) out[0] = name;
                depth++;
            }
            @Override public SignatureVisitor visitTypeArgument(char w) { return w == '-' ? new SignatureVisitor(Opcodes.ASM9) { } : this; }
            @Override public void visitEnd() { if (inTarget) depth--; }
        });
        return out[0];
    }
    static String firstTypeArgOfType(String sig) {
        String[] out = {null};
        new SignatureReader(sig).acceptType(new SignatureVisitor(Opcodes.ASM9) {
            boolean top; int depth;
            @Override public void visitClassType(String name) {
                if (depth == 0) top = name.startsWith("java/util/");
                else if (depth == 1 && top && out[0] == null) out[0] = name;
                depth++;
            }
            @Override public SignatureVisitor visitTypeArgument(char w) { return w == '-' ? new SignatureVisitor(Opcodes.ASM9) { } : this; }
            @Override public void visitEnd() { depth--; }
        });
        return out[0];
    }
}
