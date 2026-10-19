package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceValue;

/**
 * SOUNDNESS R1205 / R1217 / R1204 — WHICH {@code equals}/{@code hashCode}/{@code toString}/{@code compareTo} BODY
 * A DISPATCH RUNS, DECIDED BY WHAT PRODUCED THE RECEIVER RATHER THAN BY HOW MANY OVERRIDES THE TREE HOLDS.
 *
 * <p><b>The defect.</b> An Object-protocol dispatch on a receiver the per-method provenance cannot pin (a field, a
 * call's result) was decided by the CHA fan-out bound alone: at twelve overrides or fewer every override was edged
 * whatever the receiver could be (so {@code static Object HO = new Object(); HO.equals(k)} was charged the one
 * effectful {@code equals} in the tree — a fabrication), and past the bound none was, with no disclosure (so
 * {@code Object o = Mk.eq(1); o.hashCode()} over a factory that returns the effectful type read absent — a silent
 * under-report). Both halves executed on JDK 21 (fixtures {@code fable-v073/{narrow,wide}}, {@code javaagent-v074/f74}).
 * The same question was not asked at all where a JDK sink runs the operand's {@code toString} ({@code "" + o},
 * {@code String.valueOf(o)}, {@code sb.append(o)}, …) over an operand declared {@code Object}: there the site was
 * silent even in bound (R1217).
 *
 * <p><b>The model — a RESOLUTION.</b> The receiver's EXACT runtime classes, followed through its producers: a
 * {@code new T}, a string or class constant, a lambda, an array, a value whose static type is a final class, a field
 * whose every write the scan holds (private, final, or package-private — the closure
 * {@link Cha#foreignReassignableField} already uses for a verdict), and the return of a statically bound project
 * method. Each class is mapped to the body the JVM runs for the member: a project body (edged), a JDK body known to
 * run no user code (nothing), or UNKNOWN. A {@code Map.entry(k, v)} / {@code AbstractMap.SimpleEntry} runs its key's
 * and value's member (R1204), so those are followed as two more receivers.
 *
 * <p><b>Where the producers are not all known</b> ({@code ?} in the set): the site keeps exactly what it did before —
 * the bounded CHA in bound — and past the bound it is recorded for the Object floor's S4 class, which discloses
 * {@code Unknown} after the fixpoint only where some override it could run carries an effect the caller lacks. A JDK
 * sink's operand whose producers are not all known goes to the S5 class, in or past the bound. Both are on by default
 * ({@link ArgContract#floorClasses}).
 *
 * <p><b>Refresh.</b> The answer reads OTHER classes' bodies (a field's writers, a factory's returns), so it cannot be
 * computed during the per-class analyze (its delta would go stale when a writer changes — the R163 shape). The site
 * is recorded per class ({@link AnalysisContext#objProtoSites}) and decided here, after the loop, every run.
 */
final class ExactTypes {

    static final boolean DEBUG = System.getenv("CANDOR_R1205_DEBUG") != null;

    /** A producer this analysis cannot follow. */
    static final String TOP = "?";
    /** An array: the Object protocol is {@code Object}'s own (and {@code compareTo} on one throws). */
    static final String PURE = "=";
    /** A LambdaMetafactory proxy: {@code equals}/{@code hashCode}/{@code toString} are {@code Object}'s, but a lambda
     *  implementing {@code Comparable} runs its own body as {@code compareTo} — not followed here, so that one is TOP. */
    static final String LAMBDA = "λ";

    /** {@code "" + o} and the other JDK string sinks over an {@code Object} operand whose producers are not all known:
     *  {@code floor} (the default: the S5 floor class decides), or {@code cha} — a MEASUREMENT arm that edges every
     *  override in bound, as an explicit {@code o.toString()} does. */
    static final String SINK_TOP = Optional.ofNullable(System.getenv("CANDOR_R1217_TOP")).orElse("floor");

    /** A key/value entry built by {@code Map.entry} or an {@code AbstractMap} entry constructor. */
    record Entry(MethodNode mn, Frame<SourceValue>[] fr, SourceValue key, SourceValue value) {}

    /** The bodies a member resolves to, and the owners over which some part could not be resolved. */
    static final class Outcome {
        final Set<String> bodies = new LinkedHashSet<>();
        final Set<String> topOwners = new LinkedHashSet<>();
        boolean resolvedSome;
    }

    // ---- per-scan state (built after the analyze loop, discarded with this instance) ---------------------

    private final AnalysisContext c;
    private Map<String, List<Object[]>> fieldWrites;                       // fieldKey -> {MethodNode, insnIndex}
    private final Map<MethodNode, Set<Object>> retMemo = new IdentityHashMap<>();
    private final Map<String, Set<Object>> fieldMemo = new HashMap<>();
    private final Set<Object> inProgress = new HashSet<>();
    private static final int MAX_DEPTH = 8;

    ExactTypes(AnalysisContext c) { this.c = c; }

    // ---- recording, at analyze time --------------------------------------------------------------------

    /** Record an Object-protocol dispatch (or a JDK string sink's {@code toString} over an {@code Object}
     *  operand) for the after-loop decision. {@code stackIdx} indexes the receiver in the frame before {@code insn}. */
    static void record(String caller, MethodNode mn, AbstractInsnNode insn, int stackIdx, String owner, String name,
            String desc, String kind) {
        ctx().objProtoSites.computeIfAbsent(caller, k -> new TreeSet<>()).add(
                mn.name + "\t" + mn.desc + "\t" + mn.instructions.indexOf(insn) + "\t" + stackIdx + "\t" + owner
                        + "\t" + name + "\t" + desc + "\t" + kind);
    }

    static boolean isEntryAlloc(String t) {
        return t.equals("java/util/AbstractMap$SimpleEntry") || t.equals("java/util/AbstractMap$SimpleImmutableEntry");
    }

    /** Is this a member whose dispatch this resolves? The §4 Object protocol by name and descriptor. */
    static boolean covers(String name, String desc) { return Candor.isObjectProtocolExempt(name, desc); }

    // ---- the after-loop decision -------------------------------------------------------------------------

    /** Decide every recorded site. Runs before {@link ArgContract#resolve}, whose receiver-specialised copies read
     *  the edges this adds. */
    static void resolveSites() {
        AnalysisContext c = ctx();
        if (c.objProtoSites.isEmpty() && c.argExactSites.isEmpty()) return;
        ExactTypes x = new ExactTypes(c);
        Map<String, Object[]> byId = new HashMap<>();   // caller id -> {ClassNode, map name+desc -> MethodNode}
        Set<String> wanted = new HashSet<>(c.objProtoSites.keySet());
        wanted.addAll(c.argExactSites.keySet());
        for (ClassNode cn : c.byName.values()) {
            String dotted = cn.name.replace('/', '.');
            for (MethodNode mn : cn.methods) {
                String id = Cha.methodId(dotted, mn.name, mn.desc);
                if (!wanted.contains(id)) continue;
                Object[] e = byId.computeIfAbsent(id, k -> new Object[] {cn, new HashMap<String, MethodNode>()});
                @SuppressWarnings("unchecked") Map<String, MethodNode> m = (Map<String, MethodNode>) e[1];
                m.put(mn.name + mn.desc, mn);
            }
        }
        for (var e : c.argExactSites.entrySet()) {
            Object[] owner = byId.get(e.getKey());
            for (String site : e.getValue()) {
                String[] a = site.split("\t", -1);
                @SuppressWarnings("unchecked") MethodNode mn = owner == null ? null : ((Map<String, MethodNode>) owner[1]).get(a[0] + a[1]);
                x.resolveArg(e.getKey(), mn, Integer.parseInt(a[2]), Integer.parseInt(a[3]), Integer.parseInt(a[4]),
                        a[5].isEmpty() ? List.of() : List.of(a[5].split("\u001f")));
            }
        }
        for (var e : c.objProtoSites.entrySet()) {
            String caller = e.getKey();
            Object[] owner = byId.get(caller);
            for (String site : e.getValue()) {
                String[] a = site.split("\t", -1);
                MethodNode mn = null;
                if (owner != null) {
                    @SuppressWarnings("unchecked") Map<String, MethodNode> m = (Map<String, MethodNode>) owner[1];
                    mn = m.get(a[0] + a[1]);
                }
                x.decide(caller, mn, Integer.parseInt(a[2]), Integer.parseInt(a[3]), a[4], a[5], a[6], a[7]);
            }
        }
    }

    private void decide(String caller, MethodNode mn, int insnIdx, int stackIdx, String owner, String name, String desc,
            String kind) {
        Outcome o = new Outcome();
        Frame<SourceValue>[] fr = mn == null ? null : Candor.srcFramesOf(mn);
        Frame<SourceValue> f = fr == null || insnIdx < 0 || insnIdx >= fr.length ? null : fr[insnIdx];
        if (f == null || stackIdx < 0 || stackIdx >= f.getStackSize()) o.topOwners.add(owner);
        else member(o, values(mn, fr, f.getStack(stackIdx), 0), owner, name, desc, 0);
        Set<String> edges = c.edges.computeIfAbsent(caller, k -> new HashSet<>());
        edges.addAll(o.bodies);
        boolean sink = kind.equals("S") || kind.equals("Q");
        for (String top : o.topOwners) {
            List<String> cha = Cha.chaTargets(top, name, desc);
            boolean broad = cha.size() > Rules.CHA_FANOUT_LIMIT && !Cha.isClosedHierarchy(top);
            if (!sink) {
                // an explicit dispatch: in bound, the edges it has always had; past it, the S4 floor (not on this body's
                // own parameter, whose callers are resolved by the argument they pass — ArgContract)
                if (!broad) edges.addAll(cha);
                else if (!cha.isEmpty() && kind.equals("D")) floor(caller, top, name, desc, "S4");
            } else if (SINK_TOP.equals("cha") && !broad) {
                edges.addAll(cha);   // measurement arm only: what an explicit `o.toString()` does in bound
            } else if (!cha.isEmpty() && kind.equals("S")) {
                // a JDK sink's operand of unknown class, in or past the bound: the S5 floor (a parameter's is decided at
                // its callers, ArgContract's S3/S5 over the argument)
                floor(caller, top, name, desc, "S5");
            }
        }
        if (DEBUG)
            System.err.println("R1205SITE\t" + caller + "\t" + kind + "\t" + owner + "." + name + "\t"
                    + (o.topOwners.isEmpty() ? "RESOLVED" : o.resolvedSome ? "PARTIAL" : "TOP") + "\t" + o.bodies.size());
    }

    /** An {@code Object}-declared argument to a project callee: each exact PROJECT class its producers yield is handed
     *  to the argument contract as an exact argument type (a resolution: the callee's parameter contracts then charge
     *  that class's body). When every producer is known the S3 floor's {@code Object} witness for that argument is
     *  withdrawn — the exact types now stand where "known only as Object" stood. */
    private void resolveArg(String caller, MethodNode mn, int insnIdx, int stackIdx, int j, List<String> callees) {
        Frame<SourceValue>[] fr = mn == null ? null : Candor.srcFramesOf(mn);
        Frame<SourceValue> f = fr == null || insnIdx < 0 || insnIdx >= fr.length ? null : fr[insnIdx];
        if (f == null || stackIdx < 0 || stackIdx >= f.getStackSize() || callees.isEmpty()) return;
        Set<Object> vals = values(mn, fr, f.getStack(stackIdx), 0);
        boolean complete = true;
        Set<String> types = new LinkedHashSet<>();
        for (Object v : vals) {
            if (v instanceof Entry) { complete = false; continue; }   // an entry's contract is its components': not followed here
            String t = (String) v;
            if (t.equals(PURE) || t.equals(LAMBDA) || PURE_JDK.contains(t)) continue;
            if (t.equals(TOP) || !c.byName.containsKey(t)) { complete = false; continue; }
            types.add(t);
        }
        TreeSet<String> sites = c.argContractSites.computeIfAbsent(caller, k -> new TreeSet<>());
        for (String n : callees) {
            for (String t : types) sites.add(n + "\t" + j + "\t" + t + "\t1");
            if (complete) sites.remove(n + "\t" + j + "\tjava/lang/Object\t0");
        }
        if (DEBUG) System.err.println("R1205ARG\t" + caller + "\t" + j + "\t" + (complete ? "COMPLETE" : "PARTIAL") + "\t" + types);
    }

    /** The Object floor's S4/S5 classes (ArgContract#postFixpoint): disclosed only where an override it could run
     *  carries a concrete effect the caller lacks, and only when the class is on (the default; {@code CANDOR_R1201_FLOOR}
     *  can switch it off for measurement). */
    private void floor(String caller, String owner, String name, String desc, String cls) {
        if (!ArgContract.floor(cls)) return;
        if (DEBUG) System.err.println("R1205FLOOR\t" + cls + "\t" + caller + "\t" + owner + "." + name);
        c.argContractFloor.computeIfAbsent(caller, k -> new TreeSet<>()).add(
                (owner + "." + name + desc) + "\t" + owner + "\t" + cls);
    }

    /** Resolve {@code name+desc} over each value; anything unresolvable is a TOP over {@code topOwner}. */
    private void member(Outcome o, Set<Object> vals, String topOwner, String name, String desc, int depth) {
        for (Object v : vals) {
            if (v instanceof Entry en) {
                if (name.equals("compareTo")) continue;   // an entry is not Comparable: the call throws, nothing runs
                if (depth > MAX_DEPTH) { o.topOwners.add("java/lang/Object"); continue; }
                Set<Object> k = values(en.mn(), en.fr(), en.key(), depth + 1);
                Set<Object> w = values(en.mn(), en.fr(), en.value(), depth + 1);
                // KeyValueHolder / SimpleEntry: hashCode = key.hashCode ^ value.hashCode; equals runs key.equals then
                // value.equals; toString = key + "=" + value (each executed on JDK 21)
                member(o, k, "java/lang/Object", name, desc, depth + 1);
                member(o, w, "java/lang/Object", name, desc, depth + 1);
                continue;
            }
            String t = (String) v;
            if (t.equals(PURE) || t.equals(LAMBDA) && !name.equals("compareTo")) { o.resolvedSome = true; continue; }
            if (t.equals(LAMBDA)) { o.topOwners.add(topOwner); continue; }
            if (t.equals(TOP)) { o.topOwners.add(topOwner); continue; }
            String b = body(t, name, desc);
            if (b == null) { o.topOwners.add(topOwner); continue; }
            o.resolvedSome = true;
            if (!b.isEmpty()) o.bodies.add(b);
        }
    }

    /** JDK classes whose {@code equals}/{@code hashCode}/{@code toString}/{@code compareTo} run no user code. */
    static final Set<String> PURE_JDK = Set.of("java/lang/Object", "java/lang/String", "java/lang/Integer",
            "java/lang/Long", "java/lang/Short", "java/lang/Byte", "java/lang/Character", "java/lang/Boolean",
            "java/lang/Double", "java/lang/Float", "java/lang/Class", "java/lang/StringBuilder",
            "java/lang/StringBuffer", "java/math/BigInteger", "java/math/BigDecimal", "java/util/UUID");

    /** The body an instance of EXACTLY {@code t} runs for the member: a project method id, {@code ""} for a JDK body
     *  that runs no user code, or null when that cannot be said. */
    String body(String t, String name, String desc) {
        if (PURE_JDK.contains(t)) return "";
        if (!c.byName.containsKey(t)) return null;   // a JDK or dependency class: its body is out of sight
        // the superclass chain decides first (JVM resolution): the first project class declaring it, or the first
        // class out of sight — Object/Enum run no user code for these members; any other may override them
        String cur = t;
        while (cur != null) {
            ClassNode cn = c.byName.get(cur);
            if (cn == null) {
                if (!cur.equals("java/lang/Object") && !cur.equals("java/lang/Enum")) return null;
                if (!name.equals("compareTo")) return "";
                if (cur.equals("java/lang/Enum")) return "";
                // compareTo from an interface default: a project one is a body; otherwise it cannot be said
                String viaIface = Cha.nearestConcreteSuper(t, name, desc);
                return viaIface;
            }
            if (Cha.declaresConcrete(cn, name, desc)) return Cha.methodId(cur.replace('/', '.'), name, desc);
            cur = cn.superName;
        }
        return null;
    }

    // ---- the producers -----------------------------------------------------------------------------------

    /** The exact runtime classes a value can hold: class names, {@link #PURE}, {@link #TOP}, or {@link Entry}. */
    Set<Object> values(MethodNode mn, Frame<SourceValue>[] fr, SourceValue v, int depth) {
        Set<Object> out = new LinkedHashSet<>();
        if (fr == null || v == null || depth > MAX_DEPTH) { out.add(TOP); return out; }
        InsnList insns = mn.instructions;
        for (Object r : roots(mn, fr, insns, v)) {
            if (r == UNTRACED) { out.add(TOP); continue; }
            if (r instanceof Integer slot) { out.add(paramType(mn, slot)); continue; }
            AbstractInsnNode p = (AbstractInsnNode) r;
            int op = p.getOpcode();
            switch (op) {
                case Opcodes.NEW -> {
                    String t = ((TypeInsnNode) p).desc;
                    Entry en = t.equals("java/util/AbstractMap$SimpleEntry") || t.equals("java/util/AbstractMap$SimpleImmutableEntry")
                            ? ctorEntry(mn, fr, (TypeInsnNode) p) : null;
                    if (en != null) out.add(en);
                    else out.add(t.startsWith("java/util/AbstractMap$Simple") ? TOP : t);
                }
                case Opcodes.ACONST_NULL -> { }
                case Opcodes.ANEWARRAY, Opcodes.NEWARRAY, Opcodes.MULTIANEWARRAY -> out.add(PURE);
                case Opcodes.LDC -> {
                    Object cst = ((LdcInsnNode) p).cst;
                    if (cst instanceof String) out.add("java/lang/String");
                    else if (cst instanceof Type ty && (ty.getSort() == Type.OBJECT || ty.getSort() == Type.ARRAY)) out.add("java/lang/Class");
                    else out.add(TOP);
                }
                case Opcodes.GETSTATIC, Opcodes.GETFIELD -> out.addAll(field((FieldInsnNode) p, depth));
                case Opcodes.INVOKESTATIC, Opcodes.INVOKESPECIAL, Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE ->
                        out.addAll(call(mn, fr, (MethodInsnNode) p, depth));
                case Opcodes.INVOKEDYNAMIC -> out.add(indy((InvokeDynamicInsnNode) p));
                default -> out.add(TOP);
            }
        }
        return out;
    }

    /** A path whose producer the def-use frames do not record: an exception a handler caught (ASM gives it no
     *  instruction), or a parameter slot the body also stores to (the entry value merges away into the stores). */
    static final Object UNTRACED = new Object();

    /** {@link Candor#dbRoots}, except that a path ending in NO producer is reported ({@link #UNTRACED}) instead of
     *  dropped. dbRoots silently loses it, and here a lost path is a lost receiver class: EXECUTED on the corpus by the
     *  independent auditor — {@code catch (Exception e) { return e.toString(); }} read as "no receiver" and dropped
     *  every override's edge. */
    static Set<Object> roots(MethodNode mn, Frame<SourceValue>[] fr, InsnList insns, SourceValue v) {
        Set<Object> out = new LinkedHashSet<>();
        if (v.insns.isEmpty()) { out.add(UNTRACED); return out; }
        Deque<AbstractInsnNode> work = new ArrayDeque<>(v.insns);
        Set<AbstractInsnNode> seen = new HashSet<>();
        int paramSlots = paramSlots(mn);
        while (!work.isEmpty()) {
            AbstractInsnNode p = work.poll();
            if (!seen.add(p)) continue;
            int i = insns.indexOf(p);
            Frame<SourceValue> f = i >= 0 ? fr[i] : null;
            int op = p.getOpcode();
            if (op == Opcodes.ALOAD && f != null) {
                int var = ((VarInsnNode) p).var;
                SourceValue local = f.getLocal(var);
                if (var < paramSlots && storesTo(mn, var)) out.add(UNTRACED);   // the entry value may merge in here
                if (local.insns.isEmpty()) { out.add(var); continue; }
                work.addAll(local.insns);
            } else if ((op == Opcodes.ASTORE || op == Opcodes.DUP || op == Opcodes.CHECKCAST) && f != null
                    && f.getStackSize() > 0) {
                SourceValue top = f.getStack(f.getStackSize() - 1);
                if (top.insns.isEmpty()) out.add(UNTRACED);
                work.addAll(top.insns);
            } else if (op == Opcodes.ASTORE || op == Opcodes.DUP || op == Opcodes.CHECKCAST) {
                out.add(UNTRACED);   // unreachable code: no frame
            } else {
                out.add(p);
            }
        }
        return out;
    }

    private static int paramSlots(MethodNode mn) {
        int n = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        for (Type a : Type.getArgumentTypes(mn.desc)) n += a.getSize();
        return n;
    }

    private static boolean storesTo(MethodNode mn, int var) {
        for (AbstractInsnNode p = mn.instructions.getFirst(); p != null; p = p.getNext())
            if (p.getOpcode() == Opcodes.ASTORE && ((VarInsnNode) p).var == var) return true;
        return false;
    }

    /** A parameter (or {@code this}) at entry: exact only when its declared type is a final class. */
    private String paramType(MethodNode mn, int slot) {
        boolean stat = (mn.access & Opcodes.ACC_STATIC) != 0;
        if (!stat && slot == 0) return TOP;   // `this`: any subclass
        int s = stat ? 0 : 1;
        for (Type a : Type.getArgumentTypes(mn.desc)) {
            if (s == slot) return exactDeclared(a.getDescriptor());
            s += a.getSize();
        }
        return TOP;
    }

    /** A value whose static type is {@code desc}: exact when that is a final class, PURE for an array, else TOP. */
    String exactDeclared(String desc) {
        if (desc == null || desc.isEmpty()) return TOP;
        if (desc.charAt(0) == '[') return PURE;
        if (desc.charAt(0) != 'L') return TOP;
        String t = desc.substring(1, desc.length() - 1);
        return isFinalClass(t) ? t : TOP;
    }

    private static final Map<String, Boolean> JDK_FINAL = new java.util.concurrent.ConcurrentHashMap<>();

    boolean isFinalClass(String t) {
        ClassNode cn = c.byName.get(t);
        if (cn != null) return (cn.access & (Opcodes.ACC_FINAL)) != 0 && (cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT)) == 0;
        if (!t.startsWith("java/")) return false;   // a dependency class: its modifiers are out of sight
        return JDK_FINAL.computeIfAbsent(t, k -> {
            try {
                Class<?> k2 = Class.forName(k.replace('/', '.'), false, ClassLoader.getPlatformClassLoader());
                return java.lang.reflect.Modifier.isFinal(k2.getModifiers()) && !k2.isInterface();
            } catch (Throwable e) { return false; }
        });
    }

    private Object indy(InvokeDynamicInsnNode in) {
        String bsm = in.bsm == null ? "" : in.bsm.getOwner();
        if (bsm.equals("java/lang/invoke/LambdaMetafactory")) return LAMBDA;
        if (bsm.equals("java/lang/invoke/StringConcatFactory")) return "java/lang/String";
        return exactDeclared(Type.getReturnType(in.desc).getDescriptor());
    }

    /** A field's value: exact when its declared type is final, else the union of every write the scan holds, when
     *  the scan holds them all. */
    private Set<Object> field(FieldInsnNode fi, int depth) {
        String ex = exactDeclared(fi.desc);
        if (!ex.equals(TOP)) return Set.of(ex);
        String key = Cha.fieldKey(fi.owner, fi.name);
        Set<Object> memo = fieldMemo.get(key);
        if (memo != null) return memo;
        if (!inProgress.add(key)) return Set.of(TOP);
        Set<Object> out = new LinkedHashSet<>();
        try {
            FieldNode fn = fieldNode(key);
            if (fn == null || Cha.foreignReassignableField(key) || annotated(fn)) { out.add(TOP); return out; }
            if (fn.value instanceof String) out.add("java/lang/String");
            List<Object[]> ws = writes().getOrDefault(key, List.of());
            if (ws.isEmpty() && fn.value == null) { out.add(TOP); return out; }   // written by no code the scan holds
            for (Object[] w : ws) {
                MethodNode wm = (MethodNode) w[0];
                int i = (Integer) w[1];
                Frame<SourceValue>[] wf = Candor.srcFramesOf(wm);
                if (wf == null || wf[i] == null || wf[i].getStackSize() == 0) { out.add(TOP); continue; }
                out.addAll(values(wm, wf, wf[i].getStack(wf[i].getStackSize() - 1), depth + 1));
                if (out.contains(TOP)) break;
            }
            return out;
        } finally {
            inProgress.remove(key);
            fieldMemo.put(key, out);
        }
    }

    /** A field annotation may be an injection or a deserialisation binding: a writer the bytecode does not show. */
    private static boolean annotated(FieldNode fn) {
        return (fn.visibleAnnotations != null && !fn.visibleAnnotations.isEmpty())
                || (fn.invisibleAnnotations != null && !fn.invisibleAnnotations.isEmpty());
    }

    private FieldNode fieldNode(String key) {
        int h = key.lastIndexOf('#');
        ClassNode cn = h < 0 ? null : c.byName.get(key.substring(0, h));
        if (cn == null || cn.fields == null) return null;
        String n = key.substring(h + 1);
        for (FieldNode fn : cn.fields) if (fn.name.equals(n)) return fn;
        return null;
    }

    private Map<String, List<Object[]>> writes() {
        if (fieldWrites != null) return fieldWrites;
        fieldWrites = new HashMap<>();
        for (ClassNode cn : c.byName.values())
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                int i = 0;
                for (AbstractInsnNode p = mn.instructions.getFirst(); p != null; p = p.getNext(), i++) {
                    int op = p.getOpcode();
                    if (op != Opcodes.PUTFIELD && op != Opcodes.PUTSTATIC) continue;
                    FieldInsnNode fi = (FieldInsnNode) p;
                    if (fi.desc.charAt(0) != 'L') continue;
                    fieldWrites.computeIfAbsent(Cha.fieldKey(fi.owner, fi.name), k -> new ArrayList<>()).add(new Object[] {mn, i});
                }
            }
        return fieldWrites;
    }

    /** A call's result: exact when its declared return type is final; {@code Map.entry(k, v)}; else the union of the
     *  returns of a statically bound project body (static, private, final, a final class, or {@code super.}). */
    private Set<Object> call(MethodNode mn, Frame<SourceValue>[] fr, MethodInsnNode m, int depth) {
        if (m.name.equals("<init>")) return Set.of(TOP);
        String ex = exactDeclared(Type.getReturnType(m.desc).getDescriptor());
        if (!ex.equals(TOP)) return Set.of(ex);
        if (m.getOpcode() == Opcodes.INVOKESTATIC && m.owner.equals("java/util/Map") && m.name.equals("entry")
                && m.desc.equals("(Ljava/lang/Object;Ljava/lang/Object;)Ljava/util/Map$Entry;")) {
            Frame<SourceValue> f = fr[mn.instructions.indexOf(m)];
            if (f == null || f.getStackSize() < 2) return Set.of(TOP);
            return Set.of(new Entry(mn, fr, f.getStack(f.getStackSize() - 2), f.getStack(f.getStackSize() - 1)));
        }
        MethodNode callee = boundBody(m);
        if (callee == null) return Set.of(TOP);
        Set<Object> memo = retMemo.get(callee);
        if (memo != null) return memo;
        if (!inProgress.add(callee)) return Set.of(TOP);
        Set<Object> out = new LinkedHashSet<>();
        try {
            Frame<SourceValue>[] cf = Candor.srcFramesOf(callee);
            if (cf == null) { out.add(TOP); return out; }
            int i = 0;
            for (AbstractInsnNode p = callee.instructions.getFirst(); p != null; p = p.getNext(), i++) {
                if (p.getOpcode() != Opcodes.ARETURN) continue;
                if (cf[i] == null) continue;   // unreachable
                out.addAll(values(callee, cf, cf[i].getStack(cf[i].getStackSize() - 1), depth + 1));
                if (out.contains(TOP)) break;
            }
            return out;
        } finally {
            inProgress.remove(callee);
            retMemo.put(callee, out);
        }
    }

    /** The one project body a call lands on, or null when dispatch may choose another. */
    private MethodNode boundBody(MethodInsnNode m) {
        ClassNode oc = c.byName.get(m.owner);
        if (oc == null) return null;
        int op = m.getOpcode();
        // the declaring class: the owner, or (static / super) the nearest superclass that declares it
        String cur = m.owner;
        MethodNode found = null;
        ClassNode fc = null;
        while (cur != null) {
            ClassNode cn = c.byName.get(cur);
            if (cn == null) return null;
            MethodNode x = Candor.findMethod(cn, m.name, m.desc);
            if (x != null) { found = x; fc = cn; break; }
            if (op == Opcodes.INVOKEINTERFACE) return null;
            cur = cn.superName;
        }
        if (found == null || (found.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return null;
        if (op == Opcodes.INVOKESTATIC || op == Opcodes.INVOKESPECIAL) return found;
        boolean bound = (found.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL)) != 0
                || ((fc.access & Opcodes.ACC_FINAL) != 0 && fc == oc);
        return bound ? found : null;
    }

    /** {@code new AbstractMap.SimpleEntry<>(k, v)}: the key and value its two-argument constructor received. */
    private Entry ctorEntry(MethodNode mn, Frame<SourceValue>[] fr, TypeInsnNode alloc) {
        InsnList insns = mn.instructions;
        for (AbstractInsnNode p = alloc.getNext(); p != null; p = p.getNext()) {
            if (!(p instanceof MethodInsnNode mi) || mi.getOpcode() != Opcodes.INVOKESPECIAL || !mi.name.equals("<init>")
                    || !mi.owner.equals(alloc.desc)) continue;
            Frame<SourceValue> f = fr[insns.indexOf(mi)];
            if (f == null) continue;
            int n = Type.getArgumentTypes(mi.desc).length;
            if (f.getStackSize() < n + 1) continue;
            if (!Candor.dbRoots(fr, insns, f.getStack(f.getStackSize() - n - 1)).contains(alloc)) continue;
            if (!mi.desc.equals("(Ljava/lang/Object;Ljava/lang/Object;)V")) return null;
            return new Entry(mn, fr, f.getStack(f.getStackSize() - 2), f.getStack(f.getStackSize() - 1));
        }
        return null;
    }
}
