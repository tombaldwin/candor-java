package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * CALL-TARGET ROUND 2 — THE JDK SITE TABLE, as the engine reads it ({@code jdk-sites.idx.gz}, derived from pinned JDK
 * bytecode by {@code soundness/jdk_index/JdkSiteGen.java}; see that class for the derivation and its residual).
 *
 * <p>One question, one entry point: when a JDK body runs — named by the receiver class it runs on ({@code X}) and the
 * member — which overridable members does it invoke on {@code this} (a user subclass's override runs) or on an
 * argument (the argument type's override runs)? Before this the engine kept that answer in hand tables, one per
 * spelling: SOUNDNESS R1235 ({@code Object.toString} runs {@code hashCode}; {@code Throwable.toString} runs
 * {@code getLocalizedMessage}/{@code getMessage}), R1300 ({@code printStackTrace} runs {@code toString} and
 * {@code getCause}), R32 (a provided {@code java.io} overload runs the required one), R1305 (a Throwable constructor
 * stringifies its cause). Each is now a line of the derived table, and the members no table named — the collection
 * skeletons ({@code AbstractList.contains} runs {@code get}/{@code size}), {@code Thread.start} running {@code run},
 * serialization's {@code writeObject} — are lines too (SOUNDNESS R1242, R1406).
 *
 * <p><b>What a line licenses.</b> ADDING the hooked bodies, always. A line marked OPEN (the JDK body also calls user
 * code the derivation cannot name — an iterator's elements, a field the user set) is not a complete account, so it
 * never replaces a disclosure; a CLOSED line is complete for its receiver and may resolve a site the way the R1235
 * table did ({@code Object.toString} runs exactly {@code this.hashCode()}).
 *
 * <p><b>Guards.</b> A hook derived by following a default body of another member of {@code this} names that member as a
 * GUARD: it applies only if the receiver class does not override it (then that override runs instead, and is a hook of
 * its own). This is what makes the provided-overload premise checkable per receiver: {@code InputStream.skip} re-enters
 * {@code read} only where {@code skip} itself is the JDK's (SOUNDNESS R1441) — the caller asks the table only for the
 * body that actually runs.
 */
final class JdkSites {
    private JdkSites() {}

    static final int THIS = -1;

    /** A hook: {@code slot} THIS or an argument index; {@code elem} = the ELEMENTS of that array argument;
     *  {@code anyAccess} = the member may be private (serialization's reflective hooks). */
    record Hook(int slot, boolean elem, String name, String desc, boolean anyAccess, Set<String> guards) {
        String member() { return name + desc; }
    }
    record Entry(List<Hook> hooks, boolean open) {}

    private static final class Table {
        static final Map<String, Entry> MAP = load();

        private static Map<String, Entry> load() {
            Map<String, Entry> m = new HashMap<>();
            try (var in = JdkSites.class.getResourceAsStream("/candor/jdk-sites.idx.gz")) {
                if (in == null) return m;
                try (var br = new java.io.BufferedReader(new java.io.InputStreamReader(
                        new java.util.zip.GZIPInputStream(in), java.nio.charset.StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        String[] p = line.split("\t");
                        if (p.length < 2) continue;
                        List<Hook> hs = new ArrayList<>();
                        boolean open = false;
                        for (int i = 1; i < p.length; i++) {
                            String[] h = p[i].split(" ");
                            if (h[0].equals("!")) { open = true; continue; }
                            if (h.length < 2) continue;
                            boolean elem = h[0].endsWith("[]");
                            int slot = h[0].equals("t") ? THIS : Integer.parseInt(elem ? h[0].substring(0, h[0].length() - 2) : h[0]);
                            String mem = h[1];
                            boolean any = mem.startsWith("#");
                            if (any) mem = mem.substring(1);
                            int lp = mem.indexOf('(');
                            Set<String> guards = h.length > 2 ? Set.of(h[2].split(",")) : Set.of();
                            hs.add(new Hook(slot, elem, mem.substring(0, lp), mem.substring(lp), any, guards));
                        }
                        m.put(p[0], new Entry(List.copyOf(hs), open));
                    }
                }
            } catch (java.io.IOException | RuntimeException e) {
                // a truncated table must not crash a scan: the sites it would have named stay as they were before it
            }
            return Map.copyOf(m);
        }
    }

    /** The table line for {@code x.name+desc}, or null. */
    static Entry at(String x, String name, String desc) {
        return x == null ? null : Table.MAP.get(x + "." + name + desc);
    }

    static int size() { return Table.MAP.size(); }

    /** The JDK class whose body runs for a member a PROJECT class {@code t} does not declare along its superclass chain:
     *  the first class past the project chain, when it is a JDK class (a class extending a dependency or another
     *  library class keeps the old answer — that class may override the member with a body this table does not
     *  describe). Null for a non-project {@code t}. */
    static String jdkContext(String t) {
        AnalysisContext c = ctx();
        String x = t;
        ClassNode cn = c.byName.get(x);
        if (cn == null) return null;
        for (; cn != null; cn = c.byName.get(x)) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0 || cn.superName == null) return null;
            x = cn.superName;
        }
        return isJdk(x) ? x : null;
    }

    static boolean isJdk(String x) { return x != null && (x.startsWith("java/") || x.startsWith("javax/")); }

    /** The project body that runs for {@code name+desc} on an instance of project class {@code t}: its own concrete
     *  declaration or the nearest project superclass's — never a re-entry (the table already followed the JDK's
     *  defaults), so this is the one walk a hook is resolved with. */
    static String projectBody(String t, String name, String desc) {
        ClassNode cn = ctx().byName.get(t);
        if (cn != null && Cha.declaresConcrete(cn, name, desc)) return Cha.methodId(t.replace('/', '.'), name, desc);
        return Cha.nearestConcreteSuperNoReentry(t, name, desc);
    }

    /** Every guard holds on {@code t}: no project class in its chain overrides the guarded member. */
    static boolean guardsHold(String t, Set<String> guards) {
        for (String g : guards) {
            int lp = g.indexOf('(');
            if (projectBody(t, g.substring(0, lp), g.substring(lp)) != null) return false;
        }
        return true;
    }

    /** The project bodies the JDK body of {@code name+desc} re-enters on an instance of project class {@code t} that does
     *  NOT itself declare it: each THIS hook whose guards hold, resolved on {@code t}. */
    static List<String> reentryOnThis(String t, String name, String desc) {
        List<String> out = new ArrayList<>();
        reentryOnThis(t, jdkContext(t), name, desc, out, new HashSet<>());
        if (CallTargets.DEBUG && !out.isEmpty()) System.err.println("CT\tSITE\tthis\t" + t + "." + name + desc + "\t" + out);
        return out;
    }

    /** A hooked member with no project body runs the JDK's own, which is a line of the table too: follow it on the same
     *  receiver ({@code printStackTrace} hands this to {@code println}, whose {@code toString} is
     *  {@code Throwable.toString}, which runs {@code getMessage}). */
    private static void reentryOnThis(String t, String x, String name, String desc, List<String> out, Set<String> seen) {
        if (!seen.add(name + desc)) return;
        Entry e = at(x, name, desc);
        if (e == null) return;
        for (Hook h : e.hooks()) {
            if (h.slot() != THIS || h.elem() || !guardsHold(t, h.guards())) continue;
            String b = projectBody(t, h.name(), h.desc());
            if (b != null) { if (!out.contains(b)) out.add(b); }
            else reentryOnThis(t, x, h.name(), h.desc(), out, seen);
        }
    }

    /** Whether the table's line for {@code t}'s JDK body of {@code name+desc} is CLOSED (complete) — the R1235 licence to
     *  read the re-entered bodies as the whole answer. */
    static boolean closedOnThis(String t, String name, String desc) {
        Entry e = at(jdkContext(t), name, desc);
        return e != null && !e.open();
    }

    /** Every member NAME the JDK body a call names may run on its receiver or arguments — for a reader that must not
     *  withdraw an edge such a body may take (ArgContract's specialisation). The instruction owner is the context
     *  when it is a JDK class; a project owner's JDK superclass otherwise. */
    static Set<String> hookNames(String owner, String name, String desc) {
        String x = isJdk(owner) ? owner : jdkContext(owner);
        Entry e = at(x, name, desc);
        if (e == null) return Set.of();
        Set<String> out = new HashSet<>();
        for (Hook h : e.hooks()) out.add(h.name());
        return out;
    }

    /** The argument indexes the JDK body of {@code owner.name+desc} runs {@code member} on (not array elements), in
     *  ascending order; empty when the owner is not a JDK class or the table has no such hook. */
    static int[] argsHooking(String owner, String name, String desc, String member) {
        Entry e = isJdk(owner) ? at(owner, name, desc) : null;
        if (e == null) return NO_INTS;
        TreeSet<Integer> s = new TreeSet<>();
        for (Hook h : e.hooks()) if (h.slot() >= 0 && !h.elem() && h.member().equals(member)) s.add(h.slot());
        return s.stream().mapToInt(Integer::intValue).toArray();
    }
    private static final int[] NO_INTS = new int[0];

    // ------------------------------------------------------------------------------------------- ARGUMENT hooks
    /** The Object-protocol members whose argument re-entry the protocol sinks decide (Candor#contractReentry's
     *  toString/equals/hashCode/compareTo tables and ElementFlow, with their container and allocation evidence). */
    static boolean protocol(Hook h) {
        String m = h.member();
        return m.equals("toString()Ljava/lang/String;") || m.equals("hashCode()I") || m.equals("equals(Ljava/lang/Object;)Z")
                || h.name().equals("compareTo") || h.name().equals("compare");
    }

    /** The table line for the body a call names, as the engine reads a site: the instruction owner when it is a JDK
     *  class, or a project owner's JDK superclass when no project class declares the member. */
    static Entry siteOf(AnalysisContext c, org.objectweb.asm.tree.MethodInsnNode min) {
        if (isJdk(min.owner)) return at(min.owner, min.name, min.desc);
        if (!c.byName.containsKey(min.owner) || projectBody(min.owner, min.name, min.desc) != null) return null;
        return at(jdkContext(min.owner), min.name, min.desc);
    }

    /** Apply a site's ARGUMENT hooks for every member the protocol sinks do not decide: the argument's static type
     *  names the candidates — the consumer's own overriders (in-scan bounded CHA, which also follows a subtype's JDK
     *  default through this table), a dependency's (CallTargets), or, for a reflective hook, every declarer with any
     *  access. An untyped operand ({@code Object}, unknown) or a past-bound candidate set is UNRESOLVED: nothing is
     *  added, and the site is only counted for the fallback measurement ({@link Fallback}). */
    static void argumentHooks(AnalysisContext c, String id, org.objectweb.asm.tree.MethodInsnNode min,
            org.objectweb.asm.tree.analysis.Frame<Interp.ProvValue> rf) {
        Entry e = siteOf(c, min);
        if (e == null) return;
        Fallback.site(c, id, min, e, rf);
        for (Hook h : e.hooks()) {
            if (h.slot() < 0 || h.elem() || protocol(h)) continue;
            Interp.ProvValue a = Candor.callArg(rf, min, h.slot());
            String t = a == null ? null : a.declType;
            // a value whose STATIC type is a JDK type is not resolved over that type's project implementors: the JDK body
            // got it from somewhere the static type does not narrow (`new ArrayList<>(List.of(..))` — CHA over List would
            // charge every project list's iterator to a JDK list; ArgContractR1166Test pins it). A project or
            // dependency type names the candidates; anything else is left as it was before this table
            if (t == null || t.startsWith("[") || isJdk(t)) continue;
            if (h.anyAccess()) {
                List<String> b = anyAccessTargets(t, h.name(), h.desc());
                if (!b.isEmpty()) c.edges.computeIfAbsent(id, k -> new LinkedHashSet<>()).addAll(b);
                continue;
            }
            List<String> local = Cha.chaWithReentry(t, h.name(), h.desc());
            if (!local.isEmpty() && Cha.inBound(local, t))
                c.edges.computeIfAbsent(id, k -> new LinkedHashSet<>()).addAll(local);
            if (CallTargets.outsideScan(c, t)) CallTargets.resolve(c, id, t, h.name(), h.desc(), null, CallTargets.Spelling.SINK, null);
            if (CallTargets.DEBUG) System.err.println("CT\tSITE\targ\t" + id + "\t" + min.owner + "." + min.name + min.desc + "\t" + h.slot() + " " + h.member() + "\t" + t + "\tlocal=" + local.size());
        }
    }

    // ------------------------------------------------------------------------------------------- R32's bound exemption
    /** The four java.io stream bases. NOT a site list — which members a provided overload drives is the table's — but
     *  the one PRICING exemption R32 carried: a call on a stream-typed receiver was edged to every candidate body
     *  without the CHA bound, because a stream hierarchy is routinely wider than twelve and its read/write bodies are
     *  exactly where Fs/Net live. Kept so that deleting R32's by-NAME table (which edged every `read*` override for an
     *  `in.read()`, and re-entered `read` through a `skip` the receiver overrides — R1441) does not also trade a
     *  concrete charge for a past-bound Unknown (measured on the corpus before this was kept: ~4,700 standalone rows). */
    static final Set<String> IO_STREAM_BASES = Set.of("java/io/Writer", "java/io/Reader", "java/io/InputStream", "java/io/OutputStream");

    /** The members the exemption covers, read off the table: every member of a stream base whose JDK body re-enters
     *  this (a provided overload), and every member such a body re-enters (a required one) — `read`/`write`/`append`/
     *  `skip`/`transferTo` and their overloads, as R32's name test meant, and not `close` or `available`. */
    static Set<String> streamMembers() {
        Set<String> m = STREAM_MEMBERS;
        if (m != null) return m;
        Set<String> out = new HashSet<>();
        for (var e : Table.MAP.entrySet()) {
            String k = e.getKey();
            int p = k.indexOf('('), dot = k.lastIndexOf('.', p);
            if (!streamType(k.substring(0, dot))) continue;   // a stream base or a JDK stream class (PrintStream)
            boolean thisHook = false;
            for (Hook h : e.getValue().hooks()) if (h.slot() == THIS && !h.elem()) { out.add(h.member()); thisHook = true; }
            if (thisHook) out.add(k.substring(dot + 1));
        }
        STREAM_MEMBERS = Set.copyOf(out);
        return STREAM_MEMBERS;
    }
    private static volatile Set<String> STREAM_MEMBERS;
    static boolean streamMember(String m) { return streamMembers().contains(m); }

    static boolean streamType(String t) {
        if (t == null) return false;
        if (IO_STREAM_BASES.contains(t)) return true;
        for (String s : Candor.transSupers(t)) if (IO_STREAM_BASES.contains(s)) return true;
        return false;
    }

    /** A call on an in-scan receiver whose static type is a java.io stream: for each project class that can be the
     *  receiver, the body the JVM runs for the called member — its own (or nearest project) declaration, else every
     *  body the JDK's provided overload re-enters on it (the table) — edged, unbounded (R32's exemption above). */
    static void streamReceiver(AnalysisContext c, String id, String declType, String name, String desc) {
        if (name.startsWith("<") || !streamMember(name + desc) || !streamType(declType) || CallTargets.outsideScan(c, declType)) return;
        Set<String> out = new LinkedHashSet<>();
        for (String s : c.subtypeIndex.getOrDefault(declType, List.of())) {
            ClassNode cn = c.byName.get(s);
            if (cn == null || (cn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE)) != 0) continue;
            String b = projectBody(s, name, desc);
            if (b != null) out.add(b);
            else out.addAll(reentryOnThis(s, name, desc));
        }
        if (!out.isEmpty()) c.edges.computeIfAbsent(id, k -> new LinkedHashSet<>()).addAll(out);
    }

    /** A {@code super.m()} from project method {@code id} into JDK class {@code min.owner}: the JDK body runs on this,
     *  so each THIS hook resolves on the caller's class — or a project subclass of it, which this may be — and is edged
     *  where a project body runs it and the hook's guards hold there. */
    static void superReentry(AnalysisContext c, String id, org.objectweb.asm.tree.MethodInsnNode min) {
        List<String> out = superReentryTargets(c, id, min.owner, min.name, min.desc);
        if (!out.isEmpty()) c.edges.computeIfAbsent(id, k -> new LinkedHashSet<>()).addAll(out);
    }

    /** The bodies a {@code super.m()} from {@code id} re-enters when the body that runs is JDK class {@code x}'s
     *  (a JDK owner, or a project owner whose chain reaches the JDK without declaring m): THIS hooks, resolved over the
     *  CALLER's class and its project subclasses — the runtime this — never over the instruction's owner. */
    static List<String> superReentryTargets(AnalysisContext c, String id, String x, String name, String desc) {
        String h = c.hashOf.get(id);
        if (h == null || x == null) return List.of();
        String caller = h.substring(0, h.lastIndexOf('.', h.indexOf('(')));
        if (!c.byName.containsKey(caller)) return List.of();
        Entry e = at(x, name, desc);
        if (e == null) return List.of();
        Set<String> out = new LinkedHashSet<>();
        for (String s : c.subtypeIndex.getOrDefault(caller, List.of(caller))) {
            ClassNode cn = c.byName.get(s);
            if (cn == null || (cn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE)) != 0 && !s.equals(caller)) continue;
            for (Hook hk : e.hooks()) {
                if (hk.slot() != THIS || hk.elem() || !guardsHold(s, hk.guards())) continue;
                String b = projectBody(s, hk.name(), hk.desc());
                if (b != null) out.add(b);
            }
        }
        return new ArrayList<>(out);
    }

    // ------------------------------------------------------------------------------------------- a DEPENDENCY receiver
    /** Whether dependency type {@code t} declares {@code name+desc}: TRUE from a real report row or its call-graph
     *  sidecar's member list, FALSE when the sidecar covers {@code t} and names no such member, null when no sidecar
     *  covers it (unknown). */
    static Boolean depDeclares(AnalysisContext c, String t, String name, String desc) {
        DepFn d = c.crossDeps.get(t + "." + name + desc);
        if (d != null && !d.syntheticOnly) return Boolean.TRUE;
        if (!c.depCgCoveredTypes.contains(t)) return null;
        Set<String> m = c.depDeclaredMembers.getOrDefault(t, Set.of());
        if (m.contains(name + "(" + Cha.paramTypeList(desc) + ")") || m.contains(name + "(" + Cha.paramTypeListFq(desc) + ")"))
            return Boolean.TRUE;
        // a NON-overloaded member is keyed by its bare name (the sidecar's unit id carries no descriptor): the type
        // declares exactly one member of that name. A real report row under another descriptor says which one it is
        // (LoudWriter's lone `write` is write(char[],int,int), not write(String)); with no row (a PURE body) it cannot
        // be told — UNKNOWN, and the caller keeps the re-entry (a missing fact may only widen what is reported)
        if (m.contains(name)) {
            for (String k : m) if (k.startsWith(name + "(")) return Boolean.FALSE;   // overloads, none of them this one
            Map<String, DepFn> rows = c.depMembersByName.get(t + "." + name);
            if (rows != null) for (DepFn r : rows.values()) if (!r.syntheticOnly) return Boolean.FALSE;
            return null;
        }
        return Boolean.FALSE;
    }

    /** The JDK class whose body runs for {@code name+desc} on an instance of dependency type {@code t}, walking the
     *  dependency's superclass chain from its hierarchy sidecar: null where a dependency class on the way declares the
     *  member (its body runs — the provided overload is overridden, SOUNDNESS R1441) or the chain cannot be followed.
     *  {@code unknown[0]} is set where some class on the way could not be asked (no call-graph sidecar). */
    static String depContext(AnalysisContext c, String t, String name, String desc, boolean[] unknown) {
        String x = t;
        Set<String> seen = new HashSet<>();
        while (x != null && !isJdk(x) && seen.add(x)) {
            if (c.byName.containsKey(x)) return null;
            Boolean d = depDeclares(c, x, name, desc);
            if (Boolean.TRUE.equals(d)) return null;
            if (d == null) unknown[0] = true;
            String sup = c.depSuperclass.get(x);
            if (sup == null) {
                if (c.depSplitKnown.contains(x)) return null;            // every listed supertype is an interface
                List<String> all = c.depSupers.get(x);
                sup = all == null || all.isEmpty() ? null : all.get(0);    // an older sidecar: superclass first
            }
            x = sup;
        }
        return isJdk(x) ? x : null;
    }

    /** SOUNDNESS R32, routed: a call on a DEPENDENCY-typed receiver whose body is the JDK's (a provided {@code java.io}
     *  overload, a collection skeleton member): each THIS hook of that JDK body, whose guards the dependency chain does
     *  not override, is resolved as a dispatch of the hooked member on the receiver's type ({@link CallTargets#resolve}:
     *  the nearest declaration UP and the dependency's subtypes DOWN), and the consumer's own overriders of the hooked
     *  member are edged. Where the dependency itself overrides the called member, nothing is added (R1441).
     *  @return true if anything was joined or edged */
    static boolean depReceiverReentry(AnalysisContext c, String id, String declType, String name, String desc) {
        if (declType == null || !CallTargets.outsideScan(c, declType) || name.startsWith("<")) return false;
        boolean[] unknown = {false};
        String x = depContext(c, declType, name, desc, unknown);
        Entry e = at(x, name, desc);
        if (e == null) return false;
        boolean any = false;
        for (Hook h : e.hooks()) {
            if (h.slot() != THIS || h.elem()) continue;
            boolean guarded = false;
            for (String g : h.guards()) {
                int lp = g.indexOf('(');
                if (depContext(c, declType, g.substring(0, lp), g.substring(lp), new boolean[1]) == null) { guarded = true; break; }
            }
            if (guarded) continue;
            any |= CallTargets.resolve(c, id, declType, h.name(), h.desc(), null, CallTargets.Spelling.SINK, null);
            List<String> local = Cha.chaWithReentry(declType, h.name(), h.desc());
            if (!local.isEmpty() && Cha.inBound(local, declType)) {
                c.edges.computeIfAbsent(id, k -> new LinkedHashSet<>()).addAll(local);
                any = true;
            }
        }
        if (CallTargets.DEBUG && any) System.err.println("CT\tSITE\tdep\t" + id + "\t" + declType + "." + name + desc + "\t" + x + (unknown[0] ? "\tunknown" : ""));
        return any;
    }

    /** The project classes (subtypes-or-self of {@code t}) declaring {@code name+desc} with ANY access — a reflective
     *  hook's targets (a private {@code writeObject(ObjectOutputStream)}). */
    static List<String> anyAccessTargets(String t, String name, String desc) {
        AnalysisContext c = ctx();
        List<String> out = new ArrayList<>();
        for (String s : c.subtypeIndex.getOrDefault(t, List.of())) {
            ClassNode cn = c.byName.get(s);
            if (cn == null) continue;
            for (MethodNode m : cn.methods)
                if (m.name.equals(name) && m.desc.equals(desc) && (m.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_STATIC)) == 0)
                    out.add(Cha.methodId(s.replace('/', '.'), name, desc));
        }
        return out;
    }
}
