package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import io.poly.candor.Interp.ProvValue;
import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.analysis.Frame;

/**
 * SOUNDNESS R1166 — A METHOD THAT DISPATCHES ON ITS OWN PARAMETER RUNS ITS CALLER'S OVERRIDE.
 *
 * <p><b>The silence.</b> Erasure compiles {@code <T> boolean same(T a, T b) { return a.equals(b); }} to
 * {@code invokevirtual java/lang/Object.equals}, and {@code <T> int count(Iterable<T> it)} to
 * {@code invokeinterface java/lang/Iterable.iterator}. The body that runs is the override of whatever type
 * the CALLER passes. EXECUTED on v0.40.9 with six effectful overrides (equals, hashCode, toString,
 * compareTo, Iterable.iterator, Iterator.next), each of which wrote a file:
 * <ul>
 *   <li>with the generic in a CHAINED library, all six callers were ABSENT — the library sees no
 *       implementer, and §4's Object-protocol exemption plus the κ exclusion on {@code dispatchesOn}
 *       ({@link Candor#recordDispatchedMember}) left the consumer nothing to join;</li>
 *   <li>in ONE TREE holding more than twelve overrides of the member (any real project), the four
 *       Object-protocol callers were ABSENT — the broad fan-out is dropped without a disclosure.</li>
 * </ul>
 * SPEC §4 lets an engine treat equality/hashing/formatting dispatch as resolved-pure, and that trade is kept:
 * NOTHING here hedges a dispatch it cannot resolve. It is the opposite move — where the caller's argument
 * type IS known, the override is RESOLVED, exactly as the JDK re-entry sinks already do
 * ({@code String.valueOf(w)} is charged {@code w.toString()} over the argument's type,
 * {@link Candor#contractReentry}). A method that dispatches such a member on its parameter is, to its
 * caller, a re-entry sink for that parameter.
 *
 * <p><b>Which members.</b> The §4 Object protocol (any owner, by name and descriptor) and an INTERFACE member
 * of a κ-covered JDK owner ({@code java.util.Iterator}, {@code java.lang.Iterable}, …; see {@link #isKappaOwner}) — precisely the dispatches
 * {@link Candor#recordDispatchedMember} declines to name, so the two never overlap: an abstraction a
 * dependency or the project owns keeps ⟨0.39⟩'s union, and these get the argument-typed resolution, because
 * a union over every consumer implementor of {@code Object.equals} or {@code Iterator.next} is the
 * kotlinx 87%-smear the exemption exists to avoid.
 *
 * <p><b>Across a chain, no new wire.</b> The producer names the member in {@code dispatchesOn}, in the
 * spelling every key there already uses (the owner's entry hash; the Object protocol normalised to its
 * declaring owner), on each row whose PARAMETERS reach it — the parameter-flow closure, so the consumer reads
 * it off the row it joins and walks nothing. These keys are kept out of ⟨0.39⟩'s machinery on both sides:
 * the producer does not let them seed the dispatch reach ({@code ReportWriter}), and the consumer moves them
 * into {@link AnalysisContext#depArgContract} before any admission decision reads {@code dispatchesOn}
 * ({@code Loader}), so a row carrying only these keys is not a {@code crossDeps} HIT — the R764 trap,
 * measured here before it was closed: emitted pure rows deleted 20 chained consumers' charges. The wire
 * carries no parameter index, so the chained join resolves over EVERY argument the consumer passes, still
 * subject to the one-body rule, and never wider than ⟨0.39⟩ obligation 3's union over the same key.
 *
 * <p><b>Direction.</b> Adds edges and dependency inheritance — concrete effects the override really
 * performs. It removes nothing and adds no {@code Unknown}: an argument whose type names more than one body
 * is left exactly as the callee's own dispatch answers it (see {@link #resolveByType}).
 *
 * <p><b>Residuals, stated.</b> A value the library STORES and later dispatches on (a field, a container) is
 * not a parameter receiver and is not followed; nor is the iterator an {@code Iterable.iterator} RETURNS
 * (its {@code next} runs on a derived value). A virtual project callee with a broad fan-out passes no
 * parameter flow.
 */
final class ArgContract {
    private ArgContract() {}

    static final boolean DEBUG = System.getenv("CANDOR_R1166_DEBUG") != null;

    /** Is this dispatch one the argument contract covers? See the class doc for why exactly these. */
    static boolean isContractMember(AnalysisContext c, int op, String owner, String name, String desc) {
        if (op != Opcodes.INVOKEVIRTUAL && op != Opcodes.INVOKEINTERFACE) return false;
        if (Candor.isObjectProtocolExempt(name, desc)) return true;
        return op == Opcodes.INVOKEINTERFACE && isKappaOwner(c, owner);
    }

    /** A JDK ({@code java.*}) interface — the only κ owner a KEY can name unambiguously. A κ-covered
     *  FRAMEWORK prefix ({@code com.fasterxml.jackson}, …) is κ only relative to the consumer: scanned as a
     *  project it publishes its OWN abstractions under ⟨0.39⟩, and reading those keys here would steal them
     *  from the union join (MEASURED on the chained census: jackson-databind's
     *  {@code SettableBeanProperty.deserializeAndSet} lost a consumer's {@code Clock}). The JDK is never the
     *  producer of a report this engine chains, so a {@code java/} key is ours on both sides. */
    private static boolean isKappaOwner(AnalysisContext c, String owner) {
        if (!owner.startsWith("java/") || c.projectClasses.contains(owner)) return false;
        int slash = owner.lastIndexOf('/');
        return slash > 0 && Candor.kappaCovers(owner.substring(0, slash).replace('/', '.'));
    }

    /** A {@code dispatchesOn} key this mechanism owns — read by the consumer to route the key here rather than
     *  into ⟨0.39⟩'s union. The same predicate as {@link #isContractMember}, read off the key. */
    static boolean isArgTypedKey(String key) {
        int paren = key.indexOf('(');
        int dot = paren < 0 ? -1 : key.lastIndexOf('.', paren);
        if (dot <= 0) return false;
        String owner = key.substring(0, dot), name = key.substring(dot + 1, paren), desc = key.substring(paren);
        if (Candor.isObjectProtocolExempt(name, desc)) return true;
        return isKappaOwner(ctx(), owner);
    }

    /** The key, with the Object protocol normalised to its DECLARING owner so {@code s.equals(x)} on a
     *  {@code List} and on an {@code Object} are one key, not two. */
    static String key(String owner, String name, String desc) {
        if (Candor.isObjectProtocolExempt(name, desc))
            return (name.equals("compareTo") ? "java/lang/Comparable" : "java/lang/Object") + "." + name + desc;
        return owner + "." + name + desc;
    }

    static final String TOSTRING = "java/lang/Object.toString()Ljava/lang/String;";
    static final String EQUALS = "java/lang/Object.equals(Ljava/lang/Object;)Z";
    static final String HASHCODE = "java/lang/Object.hashCode()I";
    static final String COMPARETO = "java/lang/Comparable.compareTo(Ljava/lang/Object;)I";

    // ---- analyze time: record, per method, from its OWN body only ---------------------------------------

    /** Called at every method instruction. Reads only this body's frames (RefreshBodyIndependenceTest). */
    static void site(AnalysisContext c, Candor.MethodScan s, MethodInsnNode min) {
        Frame<ProvValue>[] pf = s.provFrames;
        if (pf == null) return;
        Frame<ProvValue> f = pf[s.mn.instructions.indexOf(min)], f0 = pf[0];
        if (f == null || f0 == null) return;
        int op = min.getOpcode();
        // (1) the body dispatches a contract member on its own parameter
        if (isContractMember(c, op, min.owner, min.name, min.desc)) {
            int p = Candor.paramIndexOf(s.mn, Candor.receiverProv(f, min), f0);
            if (p >= 0) direct(c, s.id, p, key(min.owner, min.name, min.desc));
        }
        // (2) …or hands its parameter to a JDK re-entry sink — the same table Candor#contractReentry reads
        if (Candor.isToStringSink(min.owner, min.name, min.desc)
                && !(min.owner.equals("java/lang/String") && min.name.equals("format"))) {
            for (ProvValue a : Candor.callArgs(f, min)) {
                int p = Candor.paramIndexOf(s.mn, a, f0);
                if (p >= 0) direct(c, s.id, p, TOSTRING);
            }
        }
        if (Candor.isEqualsHashSink(min.owner, min.name)) {
            int p = Candor.paramIndexOf(s.mn, Candor.callArg(f, min, 0), f0);
            if (p >= 0) { direct(c, s.id, p, EQUALS); direct(c, s.id, p, HASHCODE); }
        }
        if (Candor.isCompareToSink(min.owner, min.name) && Candor.comparesArgZero(min.owner, min.name)) {
            int p = Candor.paramIndexOf(s.mn, Candor.callArg(f, min, 0), f0);
            if (p >= 0) direct(c, s.id, p, COMPARETO);
        }
        // (3) a PROJECT callee: record where each argument came from, resolved after the loop
        List<String> callees = projectCallees(c, min, f);
        if (callees.isEmpty()) return;
        Type[] at = Type.getArgumentTypes(min.desc);
        for (int j = 0; j < at.length; j++) {
            if (at[j].getSort() != Type.OBJECT) continue;
            ProvValue v = Candor.callArg(f, min, j);
            if (v == null || v.fromIndy || v.nullConst) continue;
            int p = Candor.paramIndexOf(s.mn, v, f0);
            if (p >= 0) {
                for (String n : callees)
                    c.argContractPass.computeIfAbsent(s.id, k -> new TreeSet<>()).add(p + "\t" + n + "\t" + j);
                continue;
            }
            String t = typeOf(c, v);
            if (t == null) continue;
            for (String n : callees)
                c.argContractSites.computeIfAbsent(s.id, k -> new TreeSet<>())
                        .add(n + "\t" + j + "\t" + t + "\t" + (v.newType != null ? 1 : 0));
        }
    }

    /** The type to resolve an argument over: its provable {@code new T}, else its declared type — or null when
     *  no override can exist on it (an array, or a JDK class with no project subtype, e.g. {@code String}). */
    static String typeOf(AnalysisContext c, ProvValue v) {
        String t = v.newType != null ? v.newType : v.declType;
        if (t == null || t.isEmpty() || t.charAt(0) == '[') return null;
        if (t.startsWith("java/") && !t.equals("java/lang/Object") && !c.subtypeIndex.containsKey(t)) return null;
        return t;
    }

    private static void direct(AnalysisContext c, String id, int p, String key) {
        c.argContractDirect.computeIfAbsent(id, k -> new TreeSet<>()).add(p + "\t" + key);
    }

    /** The project bodies a call can land on, for parameter flow. A broad virtual fan-out contributes none. */
    static List<String> projectCallees(AnalysisContext c, MethodInsnNode min, Frame<ProvValue> f) {
        if (!c.projectClasses.contains(min.owner)) return List.of();
        String dotted = min.owner.replace('/', '.');
        int op = min.getOpcode();
        if (op == Opcodes.INVOKESTATIC || op == Opcodes.INVOKESPECIAL) {
            ClassNode cn = c.byName.get(min.owner);
            String t = Cha.declaresConcrete(cn, min.name, min.desc) ? Cha.methodId(dotted, min.name, min.desc)
                    : Cha.nearestConcreteSuper(min.owner, min.name, min.desc);
            return t == null ? List.of() : List.of(t);
        }
        if (op != Opcodes.INVOKEVIRTUAL && op != Opcodes.INVOKEINTERFACE) return List.of();
        String mono = Interp.monomorphicReceiver(f, min);
        if (mono != null && c.byName.containsKey(mono)) {
            String t = Cha.monomorphicTarget(mono, min.name, min.desc);
            return t == null ? List.of() : List.of(t);
        }
        List<String> cha = Cha.chaTargets(min.owner, min.name, min.desc);
        return cha.size() <= Rules.CHA_FANOUT_LIMIT ? cha : List.of();
    }

    /** A call into a CHAINED dependency unit: the contract members its row publishes (already closed over its
     *  parameter flow by the producer), joined over the arguments passed here. A parameter passed on makes THIS
     *  unit publish the member in turn. Keyed by the call's own hash, the ordinary join key. */
    static void depSite(AnalysisContext c, Candor.MethodScan s, MethodInsnNode min) {
        if (s.provFrames == null || c.depArgContract.isEmpty()) return;
        List<String> keys = c.depArgContract.get(min.owner + "." + min.name + min.desc);
        if (keys == null || keys.isEmpty()) return;
        Frame<ProvValue> f = s.provFrames[s.mn.instructions.indexOf(min)], f0 = s.provFrames[0];
        if (f == null) return;
        Type[] at = Type.getArgumentTypes(min.desc);
        for (int j = 0; j < at.length; j++) {
            if (at[j].getSort() != Type.OBJECT) continue;
            ProvValue v = Candor.callArg(f, min, j);
            if (v == null || v.fromIndy || v.nullConst) continue;
            int p = Candor.paramIndexOf(s.mn, v, f0);
            if (p >= 0) {
                for (String k : keys) direct(c, s.id, p, k);
                continue;
            }
            String t = typeOf(c, v);
            if (t == null) continue;
            for (String k : keys) resolveByType(c, s.id, k, t, v.newType != null);
        }
    }

    // ---- after the analyze loop: close the parameter flow, then resolve every recorded site -------------

    static void resolve() {
        AnalysisContext c = ctx();
        if (c.argContractDirect.isEmpty()) return;
        // fn -> {"p\tkey"}: what each method's parameter p reaches, through any chain of project callees.
        Map<String, Set<String>> reach = new HashMap<>();
        for (var e : c.argContractDirect.entrySet()) reach.put(e.getKey(), new TreeSet<>(e.getValue()));
        // callee -> {"caller\tp\tj"}
        Map<String, List<String[]>> into = new HashMap<>();
        for (var e : c.argContractPass.entrySet())
            for (String x : e.getValue()) {
                String[] a = x.split("\t", 3);   // p, callee, j
                into.computeIfAbsent(a[1], k -> new ArrayList<>()).add(new String[] {e.getKey(), a[0], a[2]});
            }
        ArrayDeque<String> work = new ArrayDeque<>(reach.keySet());
        while (!work.isEmpty()) {
            String n = work.poll();
            Set<String> rn0 = reach.get(n);
            if (rn0 == null) continue;
            // A copy: a RECURSIVE method hands its parameter to itself, so the set read is the set written.
            List<String> rn = new ArrayList<>(rn0);
            for (String[] in : into.getOrDefault(n, List.of())) {
                Set<String> rc = reach.computeIfAbsent(in[0], k -> new TreeSet<>());
                boolean grew = false;
                for (String pk : rn) {
                    int tab = pk.indexOf('\t');
                    if (!pk.substring(0, tab).equals(in[2])) continue;
                    grew |= rc.add(in[1] + pk.substring(tab));
                }
                if (grew) work.add(in[0]);
            }
        }
        // PUBLISH the closure: each unit names every contract key its parameters reach, so a chained consumer
        // reads it off the row it joins and needs no walk. NOT for a member of an INTERFACE: ⟨0.23⟩'s ARM 1
        // publishes a union entry under exactly that hash, and an ordinary row emitted beside it is merged
        // into it, which withdraws the pure-only marker R919 reads (measured: 154 census rows). Named residual.
        for (var e : reach.entrySet()) {
            String owner = ownerOf(c, e.getKey());
            if (owner == null) continue;
            ClassNode cn = c.byName.get(owner);
            if (cn == null || (cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
            TreeSet<String> keys = new TreeSet<>();
            for (String pk : e.getValue()) keys.add(pk.substring(pk.indexOf('\t') + 1));
            c.argContractPub.put(e.getKey(), keys);
            if (DEBUG) for (String k : keys) System.err.println("R1166PUB\t" + e.getKey() + "\t" + k);
        }
        for (var e : c.argContractSites.entrySet()) {
            String caller = e.getKey();
            for (String x : e.getValue()) {
                String[] a = x.split("\t", 4);   // callee, j, type, exact
                Set<String> rn = reach.get(a[0]);
                if (rn == null) continue;
                for (String pk : rn) {
                    int tab = pk.indexOf('\t');
                    if (!pk.substring(0, tab).equals(a[1])) continue;
                    if (DEBUG) System.err.println("R1166SITE\t" + caller + "\t" + a[0] + "\t" + a[1] + "\t" + a[2]
                            + "\t" + pk.substring(tab + 1));
                    resolveByType(c, caller, pk.substring(tab + 1), a[2], a[3].equals("1"));
                }
            }
        }
    }

    /** Charge {@code callerId} the override of {@code key}'s member on type {@code t} — a project body as an
     *  edge, a chained dependency's as inheritance. {@code exact}: {@code t} is a provable {@code new T}. */
    static void resolveByType(AnalysisContext c, String callerId, String key, String t, boolean exact) {
        int paren = key.indexOf('(');
        int dot = paren < 0 ? -1 : key.lastIndexOf('.', paren);
        if (dot <= 0) return;
        String owner = key.substring(0, dot), name = key.substring(dot + 1, paren), desc = key.substring(paren);
        // Only a type STRICTLY MORE SPECIFIC than the member's own owner. An argument typed by the owner itself
        // (`Object`, `Map`, `Iterable`) tells the caller nothing the dispatch did not already know: in one tree
        // the callee's own CHA over that owner has already answered (narrow edges, a broad `Unknown`, or §4's
        // Object-protocol silence), and across a chain resolving it would be ⟨0.39⟩'s union over every
        // implementer of a κ owner — the smear this mechanism is scoped to avoid.
        if (t.equals(owner) || t.equals("java/lang/Object")) return;
        // …and a type that IS one: an argument at another position that merely declares a same-named method
        // must not be charged (the chained join carries no parameter index).
        if (!owner.equals("java/lang/Object") && !isSubtype(c, t, owner)) return;
        List<String> impls;
        if (exact) {
            // A provable `new T` IS that type and no subtype: a project T resolves to its one body, and an
            // EXTERNAL T (`new ArrayList<>()`, `new Exception(..)`) has no project body at all. CHA from it
            // would charge every project subclass of ArrayList on a plain list — the fabrication
            // Candor#virtualDispatch's monomorphic-receiver comment records skipping CHA to avoid.
            String m = c.byName.containsKey(t) ? Cha.monomorphicTarget(t, name, desc) : null;
            impls = m == null ? List.of() : List.of(m);
        } else {
            impls = Cha.chaTargets(t, name, desc);
            // ONE BODY OR NONE. A declared type with several overriding bodies below it is the open dispatch
            // §4 lets an engine leave unresolved, and resolving it to their CHA union is the smear that
            // exemption exists to avoid — MEASURED: with the union, 9,551 of 2.8M census rows gained a concrete
            // effect, and the sampled ones were CHA chains the program never runs (ant's `Delete.removeFiles`
            // charged `Exec` through `AnsiColorLogger` closing a declared `InputStream` that CHA read as a
            // `TarInputStream`). So a declared type resolves only where it names exactly one body; anything
            // wider keeps the answer the callee's own dispatch already gives.
            if (impls.size() > 1) {
                if (DEBUG) System.err.println("R1166WIDE\t" + callerId + "\t" + key + "\t" + t + "\t" + impls.size());
                return;
            }
        }
        if (!impls.isEmpty()) {
            c.edges.computeIfAbsent(callerId, k -> new LinkedHashSet<>()).addAll(impls);
            if (DEBUG) for (String i : impls)
                System.err.println("R1166EDGE\t" + callerId + "\t" + key + "\t" + i + "\t" + t + "\t" + (exact ? "exact" : "decl"));
            return;
        }
        DepFn d = exact ? Candor.nearestDepOverride(t, name, desc) : Candor.nearestDepFn(t, name, desc);
        if (d != null) {
            Candor.inheritDepFn(callerId, d);
            if (DEBUG) System.err.println("R1166DEP\t" + callerId + "\t" + key + "\t" + d.fn);
        }
    }

    /** The internal owner of node id {@code fn}, from the hash the report will carry for it. */
    static String ownerOf(AnalysisContext c, String fn) {
        String h = c.hashOf.get(fn);
        if (h == null) return null;
        int paren = h.indexOf('(');
        int dot = paren < 0 ? -1 : h.lastIndexOf('.', paren);
        return dot <= 0 ? null : h.substring(0, dot);
    }

    static boolean isSubtype(AnalysisContext c, String t, String owner) {
        if (Candor.transSupers(t).contains(owner)) return true;
        if (c.depSupers.isEmpty()) return false;
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> q = new ArrayDeque<>(c.depSupers.getOrDefault(t, List.of()));
        while (!q.isEmpty()) {
            String x = q.poll();
            if (!seen.add(x)) continue;
            if (x.equals(owner)) return true;
            q.addAll(Cha.depDirectSupers(x));
        }
        return false;
    }
}
