import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

/**
 * THE INDEPENDENT CHECKER for a call-target change (round 2; successor of round 1's ab/check_added.py, which was a
 * function-level contains-match). Shares NO engine code: it reads class files with ASM (a library), the JDK it runs on
 * through the system class loader, and report rows only as (unit hash -> concrete effects). It never reads the
 * engine's call graph, ledger or indexes. Two modes.
 *
 * <p><b>ADDED</b> ({@code CheckAdded <rows.tsv> <added.tsv> <classpath> [--seed N]}): for every unit whose concrete
 * effects grew, is there an instruction in its OWN bytecode that can run a body carrying the effect — RECEIVER-AWARE:
 * <ul>
 *   <li>PROP: the invoke's own targets (static/special exact; virtual = the instruction owner's subtypes declaring the
 *       member, and its nearest declaration up), indy handles, {@code <clinit>};</li>
 *   <li>HOOK: the invoke runs a JDK body; R = the members that body invokes (the checker's own walk over JDK bytecode,
 *       calls on this resolved on the receiver class, inner objects it builds followed, defaults of members the
 *       candidate does not declare followed); for each SLOT the site hands that body (receiver, each argument), typed
 *       by the checker's own producer typer, a subtype of the slot type declaring a member in R whose row carries the
 *       effect. Residual by hand: Thread.start -> run, ObjectOutputStream.writeObject's reflective hooks.</li>
 * </ul>
 * Seeds ({@code --seed N}), each injected alone and kept only if a BLIND checker would be fooled: EASY (no site reaches
 * the effect), UNRELATED (the effect on a class that is NOT a subtype of the slot type, declaring a reached member),
 * MEMBER (on a subtype of the slot type, but a member the JDK body never invokes). Each must come back UNEXPLAINED.
 *
 * <p><b>EDGES</b> ({@code CheckAdded --edges <edges.tsv> <classpath>}; lines caller-hash, callee-hash, kind): is the
 * edge TRUE — can some instruction in the caller run the callee (same three routes, receiver-precise: when the callee's
 * class runs its OWN body for the site's member, the JDK body never runs for it)? FALSE: the JVM never dispatches
 * there from this caller, so removing the edge removes nothing that runs. A hook explained only through an
 * {@code Object}-typed slot is reported TRUE-WEAK (any class could be the value), for a hand read.
 */
public final class CheckAdded {
    static final Map<String, ClassNode> CLS = new HashMap<>();
    static final Map<String, ClassNode> JDK = new HashMap<>();
    static final Map<String, Set<String>> ROWS = new HashMap<>();
    static final Map<String, List<String>> SUBS = new HashMap<>();
    static boolean TYPE_BLIND, MEMBER_BLIND;

    public static void main(String[] a) throws Exception {
        if (a.length > 0 && a[0].equals("--edges")) { edges(a[1], a[2]); return; }
        int seedN = 0;
        for (int i = 3; i < a.length; i++) if (a[i].equals("--seed")) seedN = Integer.parseInt(a[++i]);
        for (String l : Files.readAllLines(Path.of(a[0]))) {
            String[] p = l.split("\t", -1);
            if (p.length >= 2) ROWS.put(p[0], p[1].isEmpty() ? new HashSet<>() : new HashSet<>(Arrays.asList(p[1].split(","))));
        }
        loadAll(a[2]);
        List<String[]> added = new ArrayList<>();
        for (String l : Files.readAllLines(Path.of(a[1]))) {
            String[] p = l.split("\t", -1);
            if (p.length >= 2 && !p[1].isEmpty()) added.add(new String[] {p[0], p[1], "real", null});
        }
        if (seedN > 0) added.addAll(seeds(seedN));
        Map<String, Integer> stats = new TreeMap<>();
        for (String[] ad : added) {
            MethodNode mn = method(ad[0]);
            Set<String> gained = new TreeSet<>(Arrays.asList(ad[1].split(",")));
            if (mn == null) { stats.merge(ad[2] + " NO-BYTECODE", 1, Integer::sum); System.out.println("NO-BYTECODE\t" + ad[2] + "\t" + ad[0]); continue; }
            Map<String, String> why = new TreeMap<>();
            for (String E : gained) { String w = explainWith(owner(ad[0]), mn, E, ad[3]); if (w != null) why.put(E, w); }
            Set<String> rest = new TreeSet<>(gained); rest.removeAll(why.keySet());
            String k = ad[2].startsWith("seed") ? ad[2] : "real";
            if (rest.isEmpty()) {
                stats.merge(k + " explained", 1, Integer::sum);
                for (String w : why.values()) if (w.contains("(Object-typed slot)")) stats.merge(k + " explained-weak", 1, Integer::sum);
            } else {
                stats.merge(k + " UNEXPLAINED", 1, Integer::sum);
                System.out.println("UNEXPLAINED\t" + ad[2] + "\t" + ad[0] + "\t" + rest + "\t(explained: " + why + ")");
            }
        }
        System.out.println("STATS " + stats);
    }

    // ------------------------------------------------------------------------------------------- loading
    static void loadAll(String cp) throws IOException {
        for (String e : cp.split(":")) if (!e.isEmpty()) load(Path.of(e));
        for (ClassNode c : CLS.values()) {
            if (c.superName != null) SUBS.computeIfAbsent(c.superName, k -> new ArrayList<>()).add(c.name);
            for (String i : c.interfaces) SUBS.computeIfAbsent(i, k -> new ArrayList<>()).add(c.name);
        }
    }
    static void load(Path p) throws IOException {
        if (Files.isDirectory(p)) {
            try (var st = Files.walk(p)) {
                for (Path f : (Iterable<Path>) st::iterator)
                    if (f.toString().endsWith(".class") && !f.getFileName().toString().equals("module-info.class")) put(Files.readAllBytes(f));
            }
        } else if (p.toString().endsWith(".jar")) {
            try (ZipFile z = new ZipFile(p.toFile())) {
                for (var en = z.entries(); en.hasMoreElements(); ) {
                    ZipEntry e = en.nextElement();
                    String n = e.getName();
                    if (n.endsWith(".class") && !n.endsWith("module-info.class") && !n.startsWith("META-INF/versions/"))
                        try (InputStream in = z.getInputStream(e)) { put(in.readAllBytes()); }
                }
            }
        }
    }
    static void put(byte[] b) {
        try { ClassNode cn = new ClassNode(); new ClassReader(b).accept(cn, ClassReader.SKIP_FRAMES); CLS.putIfAbsent(cn.name, cn); }
        catch (Exception ignored) { }
    }
    static ClassNode jdk(String name) {
        if (name == null || CLS.containsKey(name) || name.startsWith("[")) return null;
        if (JDK.containsKey(name)) return JDK.get(name);
        ClassNode cn = null;
        try (InputStream in = ClassLoader.getSystemClassLoader().getResourceAsStream(name + ".class")) {
            if (in != null) { cn = new ClassNode(); new ClassReader(in.readAllBytes()).accept(cn, ClassReader.SKIP_FRAMES); }
        } catch (Exception e) { cn = null; }
        JDK.put(name, cn);
        return cn;
    }
    static ClassNode any(String name) { ClassNode c = CLS.get(name); return c != null ? c : jdk(name); }
    static boolean isJdk(String name) { return name != null && !CLS.containsKey(name) && jdk(name) != null; }
    static String owner(String hash) { int p = hash.indexOf('('); return hash.substring(0, hash.lastIndexOf('.', p)); }
    static MethodNode method(String hash) {
        int p = hash.indexOf('(');
        if (p < 0) return null;
        int dot = hash.lastIndexOf('.', p);
        ClassNode c = CLS.get(hash.substring(0, dot));
        return c == null ? null : declared(c, hash.substring(dot + 1, p), hash.substring(p));
    }
    static String hashOf(String owner, String name, String desc) { return owner + "." + name + desc; }
    static boolean carries(String owner, String name, String desc, String E) {
        Set<String> s = ROWS.get(hashOf(owner, name, desc));
        if (s != null && s.contains(E)) return true;
        // a covariant override / its bridge: the same name and parameters, another return type (one row for both)
        ClassNode c = CLS.get(owner);
        if (c == null || desc.indexOf(')') < 0) return false;
        String params = desc.substring(0, desc.indexOf(')') + 1);
        for (MethodNode m : c.methods)
            if (m.name.equals(name) && !m.desc.equals(desc) && m.desc.startsWith(params)) {
                Set<String> t = ROWS.get(hashOf(owner, m.name, m.desc));
                if (t != null && t.contains(E)) return true;
            }
        return false;
    }

    // ------------------------------------------------------------------------------------------- hierarchy
    static List<String> supersOf(String t) {
        ClassNode c = any(t);
        if (c == null) return List.of();
        List<String> out = new ArrayList<>();
        if (c.superName != null) out.add(c.superName);
        out.addAll(c.interfaces);
        return out;
    }
    static boolean isSubtype(String s, String t) {
        if (s.equals(t) || t.equals("java/lang/Object")) return true;
        Deque<String> q = new ArrayDeque<>(List.of(s)); Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) { String x = q.poll(); if (!seen.add(x)) continue; if (x.equals(t)) return true; q.addAll(supersOf(x)); }
        return false;
    }
    static Set<String> subtypes(String t) {
        Set<String> out = new LinkedHashSet<>();
        if (t.equals("java/lang/Object")) { out.addAll(CLS.keySet()); return out; }
        Deque<String> q = new ArrayDeque<>(List.of(t));
        while (!q.isEmpty()) { String x = q.poll(); if (!out.add(x)) continue; q.addAll(SUBS.getOrDefault(x, List.of())); }
        out.removeIf(x -> !CLS.containsKey(x));
        return out;
    }
    static MethodNode declared(ClassNode c, String name, String desc) {
        if (c == null) return null;
        for (MethodNode m : c.methods) if (m.name.equals(name) && m.desc.equals(desc)) return m;
        return null;
    }
    static boolean concrete(MethodNode m) { return m != null && (m.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0; }
    /** JVM resolution on runtime class t: the superclass chain, then an interface default. */
    static String resolveUp(String t, String name, String desc) {
        for (String x = t; x != null; ) {
            ClassNode c = any(x);
            if (c == null) return null;
            if (concrete(declared(c, name, desc))) return x;
            x = c.superName;
        }
        Deque<String> q = new ArrayDeque<>(List.of(t)); Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String x = q.poll(); if (!seen.add(x)) continue;
            ClassNode c = any(x); if (c == null) continue;
            if (concrete(declared(c, name, desc)) && (c.access & Opcodes.ACC_INTERFACE) != 0) return x;
            q.addAll(supersOf(x));
        }
        return null;
    }

    // ------------------------------------------------------------------------------------------- JDK reach
    static final Map<String, Set<String>> REACH = new HashMap<>();
    /** The members the JDK body {@code body.name+desc} invokes when it runs on an instance of class {@code s} (a
     *  scanned class, or null when unknown): a call whose owner is a supertype of s resolves on s — a scanned body there
     *  is recorded and NOT followed (it is the hook), a JDK body is followed; other calls through their owner; objects
     *  the body builds (an iterator over this) have all their bodies followed; bounded. */
    static Set<String> reachFor(String s, String body, String name, String desc) {
        String key = s + "|" + body + "." + name + desc;
        Set<String> memo = REACH.get(key);
        if (memo != null) return memo;
        Set<String> out = new HashSet<>();
        REACH.put(key, out);
        if (name.equals("start") && desc.equals("()V") && isSubtype(body, "java/lang/Thread")) out.add("run()V");
        if (body.equals("java/io/ObjectOutputStream") && (name.equals("writeObject") || name.equals("writeUnshared"))) {
            out.add("writeObject(Ljava/io/ObjectOutputStream;)V"); out.add("writeReplace()Ljava/lang/Object;"); out.add("writeExternal(Ljava/io/ObjectOutput;)V");
        }
        Deque<String[]> q = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        q.add(new String[] {body, name, desc, "0"});
        int nodes = 0;
        while (!q.isEmpty() && nodes < 4000) {
            String[] m = q.poll();
            int d = Integer.parseInt(m[3]);
            if (!seen.add(m[0] + "." + m[1] + m[2])) continue;
            MethodNode mn = declared(jdk(m[0]), m[1], m[2]);
            if (mn == null || mn.instructions == null) continue;
            nodes++;
            for (AbstractInsnNode in : mn.instructions) {
                if (in instanceof MethodInsnNode mi) {
                    out.add(mi.name + mi.desc);
                    if (d >= 7) continue;
                    if (s != null && mi.getOpcode() != Opcodes.INVOKESTATIC && isSubtype(s, mi.owner)) {
                        String b = resolveUp(s, mi.name, mi.desc);
                        if (b != null && CLS.containsKey(b)) continue;
                        if (b != null && jdk(b) != null) { q.add(new String[] {b, mi.name, mi.desc, String.valueOf(d + 1)}); continue; }
                    }
                    String b = resolveUp(mi.owner, mi.name, mi.desc);
                    if (b != null && jdk(b) != null) q.add(new String[] {b, mi.name, mi.desc, String.valueOf(d + 1)});
                    else if (jdk(mi.owner) != null) q.add(new String[] {mi.owner, mi.name, mi.desc, String.valueOf(d + 1)});
                } else if (in instanceof TypeInsnNode ti && ti.getOpcode() == Opcodes.NEW && d < 7) {
                    ClassNode nc = jdk(ti.desc);
                    if (nc != null && nc.name.contains("$"))
                        for (MethodNode x : nc.methods) q.add(new String[] {nc.name, x.name, x.desc, String.valueOf(d + 1)});
                } else if (in instanceof InvokeDynamicInsnNode id && d < 7) {
                    for (Object o : id.bsmArgs) if (o instanceof Handle h && jdk(h.getOwner()) != null)
                        q.add(new String[] {h.getOwner(), h.getName(), h.getDesc(), String.valueOf(d + 1)});
                }
            }
        }
        return out;
    }
    /** reach plus what the JDK DEFAULT of each reached member runs on scanned class s when s does not declare it
     *  (`new ArrayList<>(t)` runs t.toArray(), whose default AbstractCollection.toArray runs t.iterator()). */
    static Set<String> withDefaults(String s, Set<String> reach) {
        String x = s;
        while (x != null && CLS.containsKey(x)) x = CLS.get(x).superName;
        if (x == null || jdk(x) == null) return reach;
        Set<String> out = new HashSet<>(reach);
        Deque<String> q = new ArrayDeque<>(reach);
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty() && seen.size() < 400) {
            String m = q.poll();
            if (!seen.add(m)) continue;
            int lp = m.indexOf('(');
            String n = m.substring(0, lp), d = m.substring(lp);
            String own = resolveUp(s, n, d);
            if (own != null && CLS.containsKey(own)) continue;
            String b = resolveUp(x, n, d);
            if (b == null || jdk(b) == null) continue;
            for (String r : reachFor(s, b, n, d)) if (out.add(r)) q.add(r);
        }
        return out;
    }

    // ------------------------------------------------------------------------------------------- ADDED
    static String explainWith(String owner, MethodNode mn, String E, String inject) {
        boolean had = inject != null && ROWS.computeIfAbsent(inject, k -> new HashSet<>()).contains(E);
        if (inject != null) ROWS.get(inject).add(E);
        try { return explain(owner, mn, E); } finally { if (inject != null && !had) ROWS.get(inject).remove(E); }
    }
    static String explain(String owner, MethodNode mn, String E) {
        // an ABSTRACT member's row is the producer's union over its implementors (SPEC ⟨0.23⟩): explained by one of them
        if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) {
            String w = prop(Opcodes.INVOKEVIRTUAL, owner, mn.name, mn.desc, E);
            return w == null ? null : "UNION " + w;
        }
        // class initialisation: a body of a class runs only once it (and every superclass) is initialised, and an
        // invokestatic / NEW / static field touches the named class's <clinit> and its supers'
        for (String x = owner; x != null && CLS.containsKey(x); x = CLS.get(x).superName)
            if (carries(x, "<clinit>", "()V", E)) return "PROP clinit-own " + x;
        for (AbstractInsnNode in : mn.instructions) {
            String t = in instanceof MethodInsnNode mi && mi.getOpcode() == Opcodes.INVOKESTATIC ? mi.owner
                    : in instanceof FieldInsnNode fi && (fi.getOpcode() == Opcodes.GETSTATIC || fi.getOpcode() == Opcodes.PUTSTATIC) ? fi.owner
                    : in instanceof TypeInsnNode ti && ti.getOpcode() == Opcodes.NEW ? ti.desc : null;
            for (String x = t; x != null && CLS.containsKey(x); x = CLS.get(x).superName)
                if (carries(x, "<clinit>", "()V", E)) return "PROP clinit " + x;
        }
        for (AbstractInsnNode in : mn.instructions) {
            if (in instanceof MethodInsnNode mi) {
                String w = prop(mi.getOpcode(), mi.owner, mi.name, mi.desc, E);
                if (w != null) return w;
            } else if (in instanceof InvokeDynamicInsnNode id) {
                for (Object b : id.bsmArgs)
                    if (b instanceof Handle h && h.getOwner() != null) {
                        if (carries(h.getOwner(), h.getName(), h.getDesc(), E)) return "PROP indy";
                        String w = prop(h.getTag() == Opcodes.H_INVOKESTATIC ? Opcodes.INVOKESTATIC : Opcodes.INVOKEVIRTUAL, h.getOwner(), h.getName(), h.getDesc(), E);
                        if (w != null) return w + " (handle)";
                    }
            } else if (in instanceof FieldInsnNode fi && (fi.getOpcode() == Opcodes.GETSTATIC || fi.getOpcode() == Opcodes.PUTSTATIC)) {
                if (carries(fi.owner, "<clinit>", "()V", E)) return "PROP clinit";
            } else if (in instanceof TypeInsnNode ti && ti.getOpcode() == Opcodes.NEW) {
                if (carries(ti.desc, "<clinit>", "()V", E)) return "PROP clinit";
            } else if (in instanceof LdcInsnNode ld && ld.cst instanceof Handle h) {
                if (carries(h.getOwner(), h.getName(), h.getDesc(), E)) return "PROP ldc-handle";
            }
        }
        Frame<SourceValue>[] fr;
        try { fr = new Analyzer<>(new SourceInterpreter()).analyze(owner, mn); } catch (Exception e) { return null; }
        for (AbstractInsnNode in : mn.instructions) {
            Frame<SourceValue> f = fr[mn.instructions.indexOf(in)];
            if (f == null) continue;
            if (in instanceof InvokeDynamicInsnNode id) {
                String bo = id.bsm.getOwner();
                if (bo.equals("java/lang/invoke/StringConcatFactory")) {
                    Type[] ct = Type.getArgumentTypes(id.desc);
                    for (int k = 0; k < ct.length; k++) {
                        Set<String> ts = types(owner, mn, fr, f.getStack(f.getStackSize() - ct.length + k), 0);
                        String w = hookOn(ts, "java/lang/String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;", E, "concat");
                        if (w != null) return w;
                    }
                } else if (bo.equals("java/lang/runtime/ObjectMethods")) {
                    for (Object b : id.bsmArgs)
                        if (b instanceof Handle h && h.getTag() == Opcodes.H_GETFIELD && Type.getType(h.getDesc()).getSort() == Type.OBJECT) {
                            String ft = Type.getType(h.getDesc()).getInternalName();
                            for (String s : subtypes(ft))
                                for (String m : List.of("toString()Ljava/lang/String;", "hashCode()I", "equals(Ljava/lang/Object;)Z")) {
                                    int lp = m.indexOf('(');
                                    if (concrete(declared(CLS.get(s), m.substring(0, lp), m.substring(lp))) && carries(s, m.substring(0, lp), m.substring(lp), E)) return "HOOK record";
                                }
                        }
                }
                continue;
            }
            if (!(in instanceof MethodInsnNode mi)) continue;
            boolean inst = mi.getOpcode() != Opcodes.INVOKESTATIC;
            String body = mi.getOpcode() == Opcodes.INVOKESTATIC || mi.getOpcode() == Opcodes.INVOKESPECIAL
                    ? (any(mi.owner) != null ? resolveUp(mi.owner, mi.name, mi.desc) : null) : resolveUp(mi.owner, mi.name, mi.desc);
            if (body == null && !CLS.containsKey(mi.owner)) body = mi.owner;
            if (body == null || !isJdk(body)) continue;
            Type[] at = Type.getArgumentTypes(mi.desc);
            int base = f.getStackSize() - at.length - (inst ? 1 : 0);
            for (int k = inst ? -1 : 0; k < at.length; k++) {
                int idx = base + (inst ? k + 1 : k);
                if (idx < 0 || idx >= f.getStackSize()) continue;
                if (k >= 0 && at[k].getSort() != Type.OBJECT && at[k].getSort() != Type.ARRAY) continue;
                Set<String> ts = new LinkedHashSet<>(types(owner, mn, fr, f.getStack(idx), 0));
                if (k >= 0 && ts.isEmpty() && at[k].getSort() == Type.OBJECT) ts.add(at[k].getInternalName());
                if (k < 0 && mi.getOpcode() == Opcodes.INVOKESPECIAL) ts.add(owner);   // super.m(): this
                String w = hookOn(ts, body, mi.name, mi.desc, E, body + "." + mi.name + (k < 0 ? "[this]" : "[" + k + "]"));
                if (w != null) return w;
            }
        }
        return null;
    }
    static String prop(int op, String owner, String name, String desc, String E) {
        if (op == Opcodes.INVOKESTATIC || op == Opcodes.INVOKESPECIAL) {
            String b = CLS.containsKey(owner) ? resolveUp(owner, name, desc) : null;
            if (b == null) b = owner;
            return carries(b, name, desc, E) || carries(owner, name, desc, E) ? "PROP exact" : null;
        }
        String up = resolveUp(owner, name, desc);
        if (up != null && carries(up, name, desc, E)) return "PROP up";
        for (String s : subtypes(owner)) {
            if (concrete(declared(CLS.get(s), name, desc)) && carries(s, name, desc, E)) return "PROP cha";
            // a subtype whose body for the member is a JDK one (a project Multiset inheriting AbstractCollection's
            // containsAll): that JDK body's re-entered members on the subtype
            String b = resolveUp(s, name, desc);
            if (b != null && isJdk(b)) {
                Set<String> rs = withDefaults(s, reachFor(s, b, name, desc));
                for (String r : rs) {
                    int lp = r.indexOf('(');
                    String rb = resolveUp(s, r.substring(0, lp), r.substring(lp));
                    if (rb != null && CLS.containsKey(rb) && carries(rb, r.substring(0, lp), r.substring(lp), E)) return "HOOK inherited " + b + "." + name + " on " + s;
                }
            }
        }
        return null;
    }
    /** a subtype S of a slot type whose member, reached by the JDK body as it runs on S, carries E */
    static String hookOn(Set<String> types, String body, String name, String desc, String E, String site) {
        for (String t : types) {
            if (t == null) continue;
            if (t.startsWith("[")) { Type et = Type.getType(t).getElementType(); if (et.getSort() != Type.OBJECT) continue; t = et.getInternalName(); }
            for (String s : TYPE_BLIND ? CLS.keySet() : subtypes(t)) {
                Set<String> rs = withDefaults(s, reachFor(s, body, name, desc));
                for (MethodNode m : CLS.get(s).methods) {
                    if ((m.access & Opcodes.ACC_STATIC) != 0 || !concrete(m)) continue;
                    if (!MEMBER_BLIND && !rs.contains(m.name + m.desc)) continue;
                    if (carries(s, m.name, m.desc, E)) return "HOOK " + site + " -> " + s + "." + m.name + (t.equals("java/lang/Object") ? " (Object-typed slot)" : "");
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------------------------------- producer typer
    static Set<String> types(String owner, MethodNode mn, Frame<SourceValue>[] fr, SourceValue v, int depth) {
        Set<String> out = new LinkedHashSet<>();
        if (v == null || depth > 6) return out;
        for (AbstractInsnNode p : v.insns) {
            switch (p.getOpcode()) {
                case Opcodes.NEW, Opcodes.CHECKCAST -> out.add(((TypeInsnNode) p).desc);
                case Opcodes.ANEWARRAY -> out.add("[L" + ((TypeInsnNode) p).desc + ";");
                case Opcodes.GETFIELD, Opcodes.GETSTATIC -> out.add(internal(((FieldInsnNode) p).desc));
                case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE, Opcodes.INVOKESTATIC, Opcodes.INVOKESPECIAL ->
                        out.add(internal(Type.getReturnType(((MethodInsnNode) p).desc).getDescriptor()));
                case Opcodes.INVOKEDYNAMIC -> out.add(internal(Type.getReturnType(((InvokeDynamicInsnNode) p).desc).getDescriptor()));
                case Opcodes.LDC -> out.add(((LdcInsnNode) p).cst instanceof String ? "java/lang/String" : null);
                case Opcodes.AALOAD -> {
                    Frame<SourceValue> f = fr[mn.instructions.indexOf(p)];
                    if (f != null) for (String a : types(owner, mn, fr, f.getStack(f.getStackSize() - 2), depth + 1))
                        if (a != null && a.startsWith("[")) out.add(internal(a.substring(1)));
                }
                case Opcodes.DUP, Opcodes.DUP_X1, Opcodes.DUP_X2 -> {
                    Frame<SourceValue> f = fr[mn.instructions.indexOf(p)];
                    if (f != null) out.addAll(types(owner, mn, fr, f.getStack(f.getStackSize() - 1), depth + 1));
                }
                case Opcodes.ALOAD -> {
                    int var = ((VarInsnNode) p).var;
                    String lvt = null;
                    if (mn.localVariables != null)
                        for (LocalVariableNode l : mn.localVariables) {
                            int i = mn.instructions.indexOf(p), s = mn.instructions.indexOf(l.start), e = mn.instructions.indexOf(l.end);
                            if (l.index == var && i >= s - 1 && i <= e) lvt = internal(l.desc);
                        }
                    if (lvt != null) { out.add(lvt); break; }
                    Frame<SourceValue> f = fr[mn.instructions.indexOf(p)];
                    SourceValue lv = f == null ? null : f.getLocal(var);
                    if (lv == null || lv.insns.isEmpty()) {
                        if ((mn.access & Opcodes.ACC_STATIC) == 0 && var == 0) out.add(owner);
                        else {
                            int slot = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
                            for (Type t : Type.getArgumentTypes(mn.desc)) { if (slot == var) out.add(internal(t.getDescriptor())); slot += t.getSize(); }
                        }
                    } else for (AbstractInsnNode st : lv.insns) {
                        Frame<SourceValue> sf = fr[mn.instructions.indexOf(st)];
                        if (sf != null && sf.getStackSize() > 0) out.addAll(types(owner, mn, fr, sf.getStack(sf.getStackSize() - 1), depth + 1));
                    }
                }
                default -> { }
            }
        }
        out.remove(null);
        return out;
    }
    static String internal(String d) {
        if (d == null) return null;
        if (d.startsWith("L")) return d.substring(1, d.length() - 1);
        return d.startsWith("[") ? d : null;
    }

    // ------------------------------------------------------------------------------------------- seeds
    static List<String[]> seeds(int n) {
        List<String[]> out = new ArrayList<>();
        List<String> classes = new ArrayList<>(CLS.keySet());
        Collections.sort(classes);
        Collections.shuffle(classes, new Random(1441));
        int easy = 0, unrel = 0, member = 0;
        for (String cn : classes) {
            if (easy >= n && unrel >= n && member >= n) break;
            for (MethodNode mn : CLS.get(cn).methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                String h = hashOf(cn, mn.name, mn.desc);
                if (easy < n && explain(cn, mn, "Llm") == null) { out.add(new String[] {h, "Llm", "seed-EASY", null}); easy++; continue; }
                Frame<SourceValue>[] fr;
                try { fr = new Analyzer<>(new SourceInterpreter()).analyze(cn, mn); } catch (Exception e) { continue; }
                boolean done = false;
                for (AbstractInsnNode in : mn.instructions) {
                    if (done || !(in instanceof MethodInsnNode mi) || mi.getOpcode() == Opcodes.INVOKESTATIC) continue;
                    String body = resolveUp(mi.owner, mi.name, mi.desc);
                    if (body == null && !CLS.containsKey(mi.owner)) body = mi.owner;
                    if (body == null || !isJdk(body)) continue;
                    Set<String> reach = reachFor(null, body, mi.name, mi.desc);
                    if (reach.isEmpty()) continue;
                    if (unrel < n)
                        for (String u : classes) {
                            if (done) break;
                            for (MethodNode x : CLS.get(u).methods) {
                                if (!concrete(x) || (x.access & Opcodes.ACC_STATIC) != 0 || x.name.startsWith("<") || !reach.contains(x.name + x.desc)) continue;
                                String xh = hashOf(u, x.name, x.desc);
                                if (explainWith(cn, mn, "Llm", xh) != null) continue;
                                TYPE_BLIND = true; String bw = explainWith(cn, mn, "Llm", xh); TYPE_BLIND = false;
                                if (bw == null) continue;
                                out.add(new String[] {h, "Llm", "seed-UNRELATED", xh}); unrel++; done = true; break;
                            }
                        }
                    if (!done && member < n) {
                        Frame<SourceValue> f = fr[mn.instructions.indexOf(in)];
                        if (f == null) continue;
                        for (String t : types(cn, mn, fr, f.getStack(f.getStackSize() - Type.getArgumentTypes(mi.desc).length - 1), 0)) {
                            if (done || t == null || t.startsWith("[") || t.equals("java/lang/Object")) continue;
                            for (String s : subtypes(t)) {
                                if (done) break;
                                for (MethodNode x : CLS.get(s).methods) {
                                    if (!concrete(x) || (x.access & Opcodes.ACC_STATIC) != 0 || x.name.startsWith("<") || reach.contains(x.name + x.desc)) continue;
                                    String xh = hashOf(s, x.name, x.desc);
                                    if (explainWith(cn, mn, "Llm", xh) != null) continue;
                                    MEMBER_BLIND = true; String bw = explainWith(cn, mn, "Llm", xh); MEMBER_BLIND = false;
                                    if (bw == null) continue;
                                    out.add(new String[] {h, "Llm", "seed-MEMBER", xh}); member++; done = true; break;
                                }
                            }
                        }
                    }
                }
            }
        }
        System.out.println("SEEDS easy=" + easy + " unrelated=" + unrel + " member=" + member);
        return out;
    }

    // ------------------------------------------------------------------------------------------- EDGES
    static void edges(String file, String cp) throws Exception {
        loadAll(cp);
        Map<String, Integer> st = new TreeMap<>();
        for (String l : Files.readAllLines(Path.of(file))) {
            String[] p = l.split("\t", -1);
            if (p.length < 3) continue;
            String why = truth(p[0], p[1]);
            String v = why == null ? "FALSE" : why.startsWith("?") ? "UNDECIDED" : why.contains("java/lang/Object") && why.startsWith("hook") ? "TRUE-WEAK" : "TRUE";
            st.merge(p[2].split(":")[0] + " " + v, 1, Integer::sum);
            if (!v.equals("FALSE") || p[2].startsWith("seed")) System.out.println(v + "\t" + p[2] + "\t" + p[0] + "\t" + p[1] + "\t" + (why == null ? "" : why));
        }
        System.out.println("STATS " + st);
    }
    static String truth(String caller, String callee) {
        MethodNode mn = method(caller);
        if (mn == null) return "?no-caller-bytecode";
        int p = callee.indexOf('(');
        if (p < 0) return "?callee-id";
        int dot = callee.lastIndexOf('.', p);
        String cc = callee.substring(0, dot), cn = callee.substring(dot + 1, p), cd = callee.substring(p);
        if (!CLS.containsKey(cc)) return "?callee-class";
        String owner = owner(caller);
        if (cn.equals("<clinit>")) {   // a first use of the class, or of a subclass, runs it
            if (isSubtype(owner, cc)) return "clinit-own-hierarchy";
            for (AbstractInsnNode in : mn.instructions) {
                String t = in instanceof MethodInsnNode mi ? mi.owner : in instanceof FieldInsnNode fi ? fi.owner
                        : in instanceof TypeInsnNode ti && ti.getOpcode() == Opcodes.NEW ? ti.desc : null;
                if (t != null && CLS.containsKey(t) && isSubtype(t, cc)) return "clinit " + t;
            }
            return null;
        }
        Frame<SourceValue>[] fr;
        try { fr = new Analyzer<>(new SourceInterpreter()).analyze(owner, mn); } catch (Exception e) { fr = null; }
        for (AbstractInsnNode in : mn.instructions) {
            if (in instanceof MethodInsnNode mi) {
                boolean nameOk = mi.name.equals(cn) && (mi.desc.equals(cd) || bridges(cc, mi.desc, cn, cd));
                if (nameOk) {
                    if (mi.getOpcode() == Opcodes.INVOKESTATIC || mi.getOpcode() == Opcodes.INVOKESPECIAL) {
                        String b = resolveUp(mi.owner, mi.name, mi.desc);
                        if (cc.equals(b) || cc.equals(mi.owner)) return "exact " + mi.owner;
                    } else if (isSubtype(cc, mi.owner) || isSubtype(mi.owner, cc)) return "dispatch " + mi.owner + "." + mi.name;
                }
                String body = mi.getOpcode() == Opcodes.INVOKESTATIC ? mi.owner : resolveUp(mi.owner, mi.name, mi.desc);
                if (body == null && !CLS.containsKey(mi.owner)) body = mi.owner;
                // receiver-precise: the callee's class runs its OWN body for the site's member, or a JDK body its own
                // chain resolves (StringWriter.write(String), not Writer's)
                if (mi.getOpcode() == Opcodes.INVOKEVIRTUAL || mi.getOpcode() == Opcodes.INVOKEINTERFACE) {
                    if (isSubtype(cc, mi.owner)) {
                        String own = resolveUp(cc, mi.name, mi.desc);
                        if (own != null && CLS.containsKey(own)) body = null;
                        else if (own != null && isJdk(own)) body = own;
                    }
                }
                if (mi.getOpcode() == Opcodes.INVOKESPECIAL && CLS.containsKey(mi.owner) && body != null && CLS.containsKey(body)) body = null;
                if (body != null && isJdk(body) && fr != null) {
                    Frame<SourceValue> f = fr[mn.instructions.indexOf(in)];
                    if (f == null) continue;
                    Set<String> reach = withDefaults(cc, reachFor(cc, body, mi.name, mi.desc));
                    if (!reach.contains(cn + cd)) continue;
                    Type[] at = Type.getArgumentTypes(mi.desc);
                    boolean inst = mi.getOpcode() != Opcodes.INVOKESTATIC;
                    int base = f.getStackSize() - at.length - (inst ? 1 : 0);
                    for (int k = inst ? -1 : 0; k < at.length; k++) {
                        int idx = base + (inst ? k + 1 : k);
                        if (idx < 0 || idx >= f.getStackSize()) continue;
                        Set<String> ts = new HashSet<>(types(owner, mn, fr, f.getStack(idx), 0));
                        if (k >= 0 && at[k].getSort() == Type.OBJECT) ts.add(at[k].getInternalName());
                        if (k < 0) ts.add(mi.getOpcode() == Opcodes.INVOKESPECIAL ? owner : mi.owner);
                        for (String t : ts) {
                            if (t == null) continue;
                            if (t.startsWith("[")) { Type et = Type.getType(t).getElementType(); if (et.getSort() != Type.OBJECT) continue; t = et.getInternalName(); }
                            if (isSubtype(cc, t)) return "hook " + body + "." + mi.name + "[" + k + "] on " + t;
                        }
                    }
                }
            } else if (in instanceof InvokeDynamicInsnNode id) {
                for (Object b : id.bsmArgs) if (b instanceof Handle h && h.getName().equals(cn) && isSubtype(cc, h.getOwner())) return "handle";
                if (id.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory") && cn.equals("toString")) return "concat-toString";
            }
        }
        return null;
    }
    static boolean bridges(String cc, String siteDesc, String cn, String cd) {
        ClassNode c = CLS.get(cc);
        if (c == null) return false;
        for (MethodNode m : c.methods)
            if (m.name.equals(cn) && m.desc.equals(siteDesc) && (m.access & (Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC)) != 0) return true;
        return Type.getArgumentTypes(siteDesc).length == Type.getArgumentTypes(cd).length
                && siteDesc.substring(0, siteDesc.indexOf(')')).equals(cd.substring(0, cd.indexOf(')')));
    }
}
