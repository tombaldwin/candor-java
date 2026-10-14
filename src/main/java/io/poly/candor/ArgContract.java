package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import io.poly.candor.Interp.ProvValue;
import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;
import org.objectweb.asm.Handle;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
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
 * measured here before it was closed: emitted pure rows deleted 20 chained consumers' charges.
 *
 * <p><b>The four properties an independent javap audit of the first cut required</b> (auditagent-r1166):
 * <ol>
 *   <li>a parameter dispatches a member only where the JDK call really runs THAT member on THAT argument —
 *       {@link Candor#equalsHashContracts} (a list {@code add} runs neither equals nor hashCode) and
 *       {@link Candor#isLoggerOwner};</li>
 *   <li>a declared type names ONE body only when every runtime type it admits is counted, Object's and the
 *       JDK's bodies included; a {@code java.*} declared type never does ({@link #bodiesFor});</li>
 *   <li>a chained join charges only an argument that can be the receiver, and where the wire cannot say
 *       which, DISCLOSES {@code Unknown} rather than charging the wrong one ({@link #depSite});</li>
 *   <li>the resolved body runs on the receiver the resolution established: the caller is edged to a
 *       specialised copy whose calls on that receiver — directly, through a bound method reference, or
 *       handed to a helper — and whose own resolutions over it are re-resolved for its type ({@link #spec}).</li>
 * </ol>
 *
 * <p><b>Direction.</b> Adds edges and dependency inheritance (a resolution), and one disclosure: the chained
 * ambiguous join. Property 1 REMOVES pre-existing over-charges of the older re-entry table.
 *
 * <p><b>Residuals, stated.</b> A value the library STORES and later dispatches on (a field, a container) is
 * not a parameter receiver and is not followed; nor is the iterator an {@code Iterable.iterator} RETURNS
 * (its {@code next} runs on a derived value). A virtual project callee with a broad fan-out passes no
 * parameter flow. CHA past the resolved body on a value that is NOT the resolved receiver (a field, another
 * parameter) is the engine's ordinary over-approximation and is not narrowed here.
 */
final class ArgContract {
    private ArgContract() {}

    static final boolean DEBUG = System.getenv("CANDOR_R1166_DEBUG") != null;
    static final boolean DEBUG_EDGES = "2".equals(System.getenv("CANDOR_R1166_DEBUG"));

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
        if (Candor.isToStringContractSink(min.owner, min.name, min.desc)
                && !(min.owner.equals("java/lang/String") && min.name.equals("format"))) {
            for (ProvValue a : Candor.callArgs(f, min)) {
                int p = Candor.paramIndexOf(s.mn, a, f0);
                if (p >= 0) direct(c, s.id, p, TOSTRING);
            }
        }
        List<String> ehc = Candor.equalsHashContracts(min.owner, min.name, min.desc);
        if (!ehc.isEmpty()) {
            ProvValue a0 = Candor.callArg(f, min, 0);
            int p = Candor.paramIndexOf(s.mn, a0, f0);
            if (p >= 0) for (String con : ehc) direct(c, s.id, p, con.equals(Candor.C_EQUALS) ? EQUALS : HASHCODE);
            else if (min.owner.equals("java/util/Objects") && a0 != null && !a0.nullConst && !a0.fromIndy) {
                // the R1166 sibling, resolved by THIS mechanism's one-body rule (not by the older re-entry CHA
                // union, which over a declared Map/Collection charged every project implementer)
                String t = typeOf(c, a0);
                if (t != null) for (String con : ehc)
                    c.argContractResolved.computeIfAbsent(s.id, x -> new TreeSet<>()).add(
                            (con.equals(Candor.C_EQUALS) ? EQUALS : HASHCODE) + "\t" + t + "\t" + (a0.newType != null ? 1 : 0));
            }
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
            // `T`: the argument is this body's own receiver, so a specialised copy of this body (spec) can
            // re-resolve it for its narrower receiver type
            boolean isThis = (s.mn.access & Opcodes.ACC_STATIC) == 0 && v == f0.getLocal(0);
            String flag = isThis ? "T" : v.newType != null ? "1" : "0";
            for (String n : callees)
                c.argContractSites.computeIfAbsent(s.id, k -> new TreeSet<>())
                        .add(n + "\t" + j + "\t" + t + "\t" + flag);
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
     *  unit publish the member in turn. Keyed by the call's own hash, the ordinary join key.
     *
     *  <p><b>Only the argument that reaches the dispatch.</b> The wire names the member, not the parameter, so
     *  for each key every argument is a CANDIDATE receiver. The join resolves only when the candidates agree —
     *  every argument whose type can run the member resolves to the same bodies — and otherwise resolves
     *  nothing (the pre-R1166 answer). Measured without this: {@code f(a,b){ a.hashCode(); }} called as
     *  {@code f(new Phash(), new Whash())} charged {@code Whash.hashCode}, which never runs. */
    static void depSite(AnalysisContext c, Candor.MethodScan s, MethodInsnNode min) {
        if (s.provFrames == null || c.depArgContract.isEmpty()) return;
        List<String> keys = c.depArgContract.get(min.owner + "." + min.name + min.desc);
        if (keys == null || keys.isEmpty()) return;
        Frame<ProvValue> f = s.provFrames[s.mn.instructions.indexOf(min)], f0 = s.provFrames[0];
        if (f == null) return;
        Type[] at = Type.getArgumentTypes(min.desc);
        for (String k : keys) {
            Res agreed = null; String aT = null; boolean aExact = false, ambiguous = false, bodyCandidate = false;
            for (int j = 0; j < at.length; j++) {
                if (at[j].getSort() != Type.OBJECT && at[j].getSort() != Type.ARRAY) continue;
                ProvValue v = Candor.callArg(f, min, j);
                if (v == null || v.nullConst) continue;
                int p = Candor.paramIndexOf(s.mn, v, f0);
                Res r;
                if (p >= 0) { direct(c, s.id, p, k); r = WIDE; }   // its runtime type is the caller's caller's
                else r = candidate(c, v, k);
                if (r == null) continue;                          // cannot be a receiver of this member
                if (r != WIDE && r != OUTSIDE) bodyCandidate = true;
                if (r == WIDE) { ambiguous = true; continue; }
                if (agreed == null) {
                    agreed = r;
                    aT = v.newType != null ? v.newType : v.declType;
                    aExact = v.newType != null;
                } else if (!agreed.equals(r)) ambiguous = true;
            }
            if (ambiguous) {
                // The member runs on ONE of these arguments and the wire does not say which. Where one of them
                // would run a body this scan or a chained report can see, that is a dispatch the engine knows
                // occurs and cannot resolve — SPEC §4's `Unknown`, not silence. Where none would, there is
                // nothing to disclose that the pre-R1166 answer did not already leave unsaid.
                if (bodyCandidate) {
                    s.dir.add(Effect.UNKNOWN);
                    int paren = k.indexOf('('), dot = k.lastIndexOf('.', paren);
                    c.unknownWhy.computeIfAbsent(s.id, x -> new TreeSet<>()).add(UnknownReason.of(
                            UnknownReason.Kind.DISPATCH, k.substring(0, dot).replace('/', '.') + "." + k.substring(dot + 1, paren)));
                }
                if (DEBUG) System.err.println("R1166AMBIG\t" + s.id + "\t" + k + "\t" + (bodyCandidate ? "disclosed" : "silent"));
                continue;
            }
            if (agreed == null || agreed == OUTSIDE) continue;
            if (agreed.dep != null) {
                Candor.inheritDepFn(s.id, agreed.dep);
                if (DEBUG) System.err.println("R1166DEP\t" + s.id + "\t" + k + "\t" + agreed.dep.fn);
            } else {
                c.argContractResolved.computeIfAbsent(s.id, x -> new TreeSet<>())
                        .add(k + "\t" + aT + "\t" + (aExact ? 1 : 0));
            }
        }
    }

    /** One argument of a chained call, as a CANDIDATE receiver of {@code key}'s member: what it would run,
     *  {@link #OUTSIDE} for a body outside the scan, {@link #WIDE} when its type does not fix one, or null
     *  when it cannot be a receiver of the member at all. A JDK-typed value counts: {@code "x".equals(w)}
     *  runs String's equals, so a String beside a project value makes the join ambiguous. */
    static Res candidate(AnalysisContext c, ProvValue v, String key) {
        if (v.fromIndy) return WIDE;
        String t = v.newType != null ? v.newType : v.declType;
        if (t == null || t.isEmpty()) return WIDE;
        int paren = key.indexOf('(');
        String owner = key.substring(0, key.lastIndexOf('.', paren));
        boolean objectMember = owner.equals("java/lang/Object");
        if (t.charAt(0) == '[') return objectMember ? OUTSIDE : null;
        if (t.equals("java/lang/Object") || t.equals(owner)) return WIDE;
        if (!objectMember && !isSubtype(c, t, owner)) return null;
        return bodiesFor(c, key, t, v.newType != null);   // exact JDK -> OUTSIDE, declared JDK/dependency -> WIDE
    }

    // ---- after the analyze loop: close the parameter flow, then resolve every recorded site -------------

    static void resolve() {
        AnalysisContext c = ctx();
        SPEC_MEMO.get().clear();
        THIS_MEMO.get().clear();
        PENDING.get().clear();
        BY_CALLER.get().clear();
        try {
            resolveSites(c);
        } finally {
            specialisePending(c);
            PENDING.get().clear();
        }
    }

    private static void resolveSites(AnalysisContext c) {
        // chained resolutions recorded by depSite, edged now so they can target the specialised body
        for (var e : c.argContractResolved.entrySet())
            for (String x : e.getValue()) {
                String[] a = x.split("\t", 3);   // key, type, exact
                applyResolved(c, e.getKey(), a[0], a[1], a[2].equals("1"), false);
            }
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
                    applyResolved(c, caller, pk.substring(tab + 1), a[2], a[3].equals("1"), a[3].equals("T"));
                }
            }
        }
    }

    /** What a contract member resolves to on an argument of type {@code t}: project bodies, or one chained
     *  dependency body. */
    static final class Res {
        final List<String> bodies; final DepFn dep;
        Res(List<String> bodies, DepFn dep) { this.bodies = bodies; this.dep = dep; }
        @Override public boolean equals(Object o) {
            return o instanceof Res r && r.bodies.equals(bodies) && r.dep == dep;
        }
        @Override public int hashCode() { return bodies.hashCode(); }
    }
    /** The type names more than one body: unresolved, and a chained join over it is ambiguous. */
    static final Res WIDE = new Res(List.of(), null);
    /** The type runs the member, but on a body outside the scan (Object's own, a JDK superclass's): nothing to
     *  charge — and, as a candidate receiver in a chained join, a disagreement with any project body. */
    static final Res OUTSIDE = new Res(List.of("<outside>"), null);

    /** {@code key}'s member on an argument of type {@code t}: null when nothing can be charged (no override,
     *  or {@code t} cannot run the member), {@link #WIDE} when {@code t} names more than one body.
     *
     *  <p><b>ONE BODY, COUNTED OVER EVERY RUNTIME TYPE.</b> A provable {@code new T} is exactly T. A DECLARED
     *  type names one body only when EVERY concrete type that can be its runtime value resolves to the same
     *  body — the declared type's own inherited one included, and a body outside the scan (Object's,
     *  a JDK superclass's) counted as a body. So a {@code java.*} declared type never qualifies (its
     *  implementations are not enumerable), nor does a dependency type. Measured before this rule: a
     *  {@code Number} from {@code Integer.valueOf} was charged a project {@code MyNum.toString}; a
     *  {@code List} from {@code Arrays.asList} a project {@code MyList.iterator}; a {@code Base} whose only
     *  project override is in {@code Sub} was charged {@code Sub.equals} on a plain {@code Base}. */
    static Res bodiesFor(AnalysisContext c, String key, String t, boolean exact) {
        int paren = key.indexOf('(');
        int dot = paren < 0 ? -1 : key.lastIndexOf('.', paren);
        if (dot <= 0) return null;
        String owner = key.substring(0, dot), name = key.substring(dot + 1, paren), desc = key.substring(paren);
        if (t.equals(owner) || t.equals("java/lang/Object")) return null;
        // …and a type that IS one: an argument that merely declares a same-named method is not a receiver.
        if (!owner.equals("java/lang/Object") && !isSubtype(c, t, owner)) return null;
        if (exact) {
            // A provable `new T` IS that type: a project T resolves to its one body; an EXTERNAL T
            // (`new ArrayList<>()`) has no project body, and CHA from it would charge every project subclass.
            String m = c.byName.containsKey(t) ? Cha.monomorphicTarget(t, name, desc) : null;
            if (m != null) return new Res(List.of(m), null);
            DepFn d = Candor.nearestDepOverride(t, name, desc);
            return d == null ? OUTSIDE : new Res(List.of(), d);
        }
        if (t.startsWith("java/") || !c.byName.containsKey(t)) return WIDE;
        Set<String> bodies = new TreeSet<>();
        boolean outside = false;
        for (String sub : c.subtypeIndex.getOrDefault(t, List.of(t))) {
            ClassNode cn = c.byName.get(sub);
            if (cn == null) { outside = true; continue; }
            if ((cn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE)) != 0) continue;
            String b = Cha.monomorphicTarget(sub, name, desc);
            if (b == null) outside = true; else bodies.add(b);
        }
        if (!Cha.samLambdaImplementors(t, name, desc).isEmpty()) outside = true;   // a lambda is a runtime type too
        if (bodies.isEmpty()) return outside ? OUTSIDE : null;
        if (bodies.size() > 1 || outside) return WIDE;
        return new Res(new ArrayList<>(bodies), null);
    }

    /** Edge {@code callerId} to what {@code key} resolves to on {@code t}, through the receiver-specialised
     *  body ({@link #spec}). After the analyze loop only. */
    static void applyResolved(AnalysisContext c, String callerId, String key, String t, boolean exact, boolean isThis) {
        Res r = bodiesFor(c, key, t, exact);
        if (r == null || r == OUTSIDE) return;
        if (r == WIDE) {
            if (DEBUG) System.err.println("R1166WIDE\t" + callerId + "\t" + key + "\t" + t);
            return;
        }
        if (r.dep != null) {
            Candor.inheritDepFn(callerId, r.dep);
            if (DEBUG) System.err.println("R1166DEP\t" + callerId + "\t" + key + "\t" + r.dep.fn);
            return;
        }
        Set<String> out = c.edges.computeIfAbsent(callerId, k -> new LinkedHashSet<>());
        for (String b : r.bodies) {
            boolean fresh = !out.contains(b);
            out.add(b);
            PENDING.get().add(new Pending(callerId, key, b, t, exact, isThis, fresh));
            if (DEBUG) System.err.println("R1166EDGE\t" + callerId + "\t" + key + "\t" + b + "\t" + t + "\t" + (exact ? "exact" : "decl"));
        }
    }

    /** A resolution edged in phase 1, to be pointed at its specialised body in phase 2 — once EVERY resolution's
     *  edge exists, because a specialised copy copies its body's edges and must not be taken before a later
     *  resolution adds one (that would be a copy missing a real edge). */
    record Pending(String caller, String key, String body, String t, boolean exact, boolean isThis, boolean fresh) {}
    private static final ThreadLocal<List<Pending>> PENDING = ThreadLocal.withInitial(ArrayList::new);
    /** caller -> body -> the resolutions that edged it: lets a specialised copy of the caller re-resolve the
     *  ones made over its OWN receiver for the copy's narrower type. */
    private static final ThreadLocal<Map<String, Map<String, List<Pending>>>> BY_CALLER = ThreadLocal.withInitial(HashMap::new);

    static void specialisePending(AnalysisContext c) {
        List<Pending> ps = PENDING.get();
        Map<String, Map<String, List<Pending>>> byCaller = BY_CALLER.get();
        for (Pending p : ps)
            byCaller.computeIfAbsent(p.caller(), k -> new HashMap<>()).computeIfAbsent(p.body(), k -> new ArrayList<>()).add(p);
        for (var e : byCaller.entrySet()) {
            Set<String> out = c.edges.get(e.getKey());
            for (var b : e.getValue().entrySet()) {
                boolean allFresh = true, allSpecialised = true;
                for (Pending p : b.getValue()) {
                    String target = spec(c, p.body(), -1, p.t(), p.exact(), 0);
                    allFresh &= p.fresh();
                    if (target.equals(p.body())) allSpecialised = false;
                    else {
                        out.add(target);
                        if (DEBUG) System.err.println("R1166EDGESPEC\t" + p.caller() + "\t" + target);
                    }
                }
                // the plain edge goes only where this mechanism alone put it and every use of it is specialised
                if (allFresh && allSpecialised) out.remove(b.getKey());
            }
        }
    }

    // ---- the receiver-specialised body --------------------------------------------------------------------

    /** SOUNDNESS R1166, property 4 — THE RESOLVED OVERRIDE RUNS ON THE RECEIVER THE RESOLUTION ESTABLISHED.
     *
     *  <p>An edge from the caller to {@code Bse.equals} for a {@code new S2()} argument is exact, but the
     *  engine's call graph is context-insensitive: inside {@code Bse.equals}, {@code this.step()} is CHA-fanned
     *  over every subclass, so the caller inherited {@code S1.step}'s write although an {@code S2} runs only
     *  {@code Bse.step} (executed: no file). The independent audit attributed most of R1166's false scoped-gate
     *  flips to exactly this — an exact new edge followed by a this-dispatch fan-out past it (guava's
     *  {@code ImmutableList.toArray → this.copyIntoArray → ImmutableSet$Indexed → Hashing.<clinit>} Clock).
     *
     *  <p>So the caller is edged to a SPECIALISED copy of the body, {@code m@T}: the body's own surfaces and its
     *  other edges are kept, and only the calls whose receiver is {@code this} are re-resolved for {@code T}
     *  (exactly, for a provable {@code new T}; over T's own subtypes, for a declared one), recursively, so a
     *  this-call inside the this-call target is specialised too. An edge is withdrawn from the copy only when
     *  its name and descriptor are reached by NO other instruction in the body — not by another receiver, not
     *  by a re-entry sink, not by an invokedynamic — so nothing the body reaches some other way is lost. The
     *  node never appears in a report: {@link #isSpecNode} ids are filtered from every output (the report rows,
     *  {@code calls}, the call-graph sidecar, the analysed set, the gate's edge view). */
    static final int SPEC_DEPTH = 8, SPEC_BUDGET = 100_000;
    // Per scan, and per THREAD: `--parallel` runs scans concurrently, each with its own context.
    private static final ThreadLocal<Map<String, String>> SPEC_MEMO = ThreadLocal.withInitial(HashMap::new);
    private static final ThreadLocal<Map<String, ThisInfo>> THIS_MEMO = ThreadLocal.withInitial(HashMap::new);

    static boolean isSpecNode(String id) { return id.indexOf('@') >= 0; }

    /** The real unit a node id stands for — itself, or the body a specialised copy was made from. */
    static String baseOf(String id) { int at = id.indexOf('@'); return at < 0 ? id : id.substring(0, at); }

    /** The calls in a body whose receiver is the BOUND value (its {@code this}, or one parameter), the calls
     *  that hand the bound value on as an argument, and the name+descriptors only those calls reach. */
    record ThisInfo(List<String[]> thisCalls, List<String[]> passes, Set<String> removableThis, Set<String> removablePass) {}

    static String spec(AnalysisContext c, String m, String t, boolean exact, int depth) {
        return spec(c, m, -1, t, exact, depth);
    }

    /** {@code m} with the value at {@code slot} ({@code -1} = {@code this}, else declared parameter index) known
     *  to be of type {@code t} (exactly, or one of its subtypes). Calls on that value are re-resolved for
     *  {@code t}; a call that hands it on as an argument is followed into a copy of the callee bound the same
     *  way — {@code Multisets.addAllImpl(this, xs)} then {@code self.add(e)} is the same receiver, measured
     *  as the path most of the remaining census smear took once `this`-calls alone were specialised. */
    static String spec(AnalysisContext c, String m, int slot, String t, boolean exact, int depth) {
        String id = m + "@" + slot + ":" + t + (exact ? "!" : "~");
        Map<String, String> specMemo = SPEC_MEMO.get();
        String memo = specMemo.get(id);
        if (memo != null) return memo;
        ThisInfo ti = thisInfo(c, m, slot);
        if (ti == null || depth > SPEC_DEPTH || specMemo.size() >= SPEC_BUDGET) {
            if (DEBUG && ti != null) System.err.println("R1166SPECCAP\t" + m + "\t" + t);
            specMemo.put(id, m);
            return m;
        }
        specMemo.put(id, id);
        copySurfaces(c, m, id);
        Set<String> base = c.edges.getOrDefault(m, Set.of());
        Set<String> e = new LinkedHashSet<>();
        Set<String> passCallees = new HashSet<>();
        for (String[] pass : ti.passes()) passCallees.add(pass[0]);
        Map<String, List<Pending>> own = slot < 0 ? BY_CALLER.get().getOrDefault(m, Map.of()) : Map.of();
        for (String x : base) {
            // a resolution this body made over its OWN receiver: re-resolved below for the copy's type
            List<Pending> ownRes = own.get(baseOf(x));
            if (ownRes != null && ownRes.stream().allMatch(p -> p.isThis() && p.fresh())) {
                for (Pending p : ownRes) {
                    Res r = bodiesFor(c, p.key(), t, exact);
                    if (r != null && r != WIDE && r != OUTSIDE && r.dep == null)
                        for (String b2 : r.bodies) if (b2.equals(p.body())) e.add(spec(c, b2, -1, t, exact, depth + 1));
                }
                continue;
            }
            String nd = nameDesc(c, baseOf(x));
            if (nd != null && ti.removableThis().contains(nd)) continue;
            // a hand-on is withdrawn only where it is re-added, as the bound copy, just below
            if (nd != null && ti.removablePass().contains(nd) && passCallees.contains(x)) continue;
            e.add(x);
        }
        // NARROWING ONLY: a bound call keeps those of the body's own edges its receiver can run, and gains none
        // the body did not already have. Where the body's dispatch was too broad to edge (and so disclosed
        // `Unknown`, copied above), the copy says the same — resolving it here would be a second, unaudited
        // resolution riding on this one.
        for (String[] call : ti.thisCalls())
            for (String tgt : thisTargets(c, call, t, exact))
                if (base.contains(tgt)) e.add(spec(c, tgt, -1, t, exact, depth + 1));
        for (String[] pass : ti.passes()) {
            String callee = pass[0]; int k = Integer.parseInt(pass[1]);
            if (base.contains(callee)) e.add(spec(c, callee, k, t, exact, depth + 1));
        }
        c.edges.put(id, e);
        if (DEBUG) System.err.println("R1166SPEC\t" + id + "\t" + e.size());
        if (DEBUG_EDGES) for (String x : e) System.err.println("R1166SPECE\t" + id + "\t" + x);
        return id;
    }

    /** The METHOD NAME a node stands for. Matched by name, not descriptor: a generic override reaches the
     *  call through a bridge whose node carries the bridge's own (or the covariant) descriptor, so a
     *  descriptor match left `EnumMultiset.add` in a copy specialised for a `HashMultiset`. Coarser in the
     *  safe direction: an edge is withdrawn only when NO other instruction in the body calls that name. */
    private static String nameDesc(AnalysisContext c, String fn) {
        String h = c.hashOf.get(fn);
        if (h == null) return null;
        int paren = h.indexOf('(');
        int dot = paren < 0 ? -1 : h.lastIndexOf('.', paren);
        return dot < 0 ? null : h.substring(dot + 1, paren);
    }

    /** The body's calls on the bound value, the calls handing it on, and the name+descriptors only those calls
     *  reach. Null when it has neither (nothing to specialise) or cannot be read. Reads the body after the
     *  analyze loop, as DbHandleFlow does; per-class analyze never sees it. */
    static ThisInfo thisInfo(AnalysisContext c, String m, int slot) {
        Map<String, ThisInfo> thisInfoMemo = THIS_MEMO.get();
        String mk = m + "#" + slot;
        if (thisInfoMemo.containsKey(mk)) return thisInfoMemo.get(mk);
        ThisInfo r = null;
        String h = c.hashOf.get(m);
        if (h != null) {
            int paren = h.indexOf('('), dot = h.lastIndexOf('.', paren);
            ClassNode cn = c.byName.get(h.substring(0, dot));
            MethodNode mn = Candor.findMethod(cn, h.substring(dot + 1, paren), h.substring(paren));
            boolean isStatic = mn != null && (mn.access & Opcodes.ACC_STATIC) != 0;
            if (mn != null && mn.instructions.size() > 0 && (slot >= 0 || !isStatic)
                    && (slot < 0 || slot < Type.getArgumentTypes(mn.desc).length)) {
                Frame<ProvValue>[] pf = Candor.cachedProvFrames(cn, mn);
                int local = slot < 0 ? 0 : Candor.paramLocalSlot(mn, slot);
                if (pf != null && pf[0] != null && local < pf[0].getLocals()) {
                    ProvValue self = pf[0].getLocal(local);
                    List<String[]> calls = new ArrayList<>(), passes = new ArrayList<>();
                    Set<String> thisKeys = new HashSet<>(), otherKeys = new HashSet<>(), otherNames = new HashSet<>();
                    Set<String> passKeys = new HashSet<>();
                    for (int i = 0; i < mn.instructions.size(); i++) {
                        AbstractInsnNode in = mn.instructions.get(i);
                        if (in instanceof InvokeDynamicInsnNode indy) {
                            // a string concat or a record's ObjectMethods re-enters the Object protocol: never
                            // withdrawn from the copy
                            otherNames.addAll(List.of("toString", "equals", "hashCode"));
                            // A method reference BOUND to the bound value — `elements.forEachEntry(self::add)` —
                            // runs that method on it: a bound call like any other (measured: guava's
                            // `Multisets.addAllImpl` reached every Multiset's `add` this way). Any other
                            // reference names a body some other value runs, and is kept.
                            Handle bound = boundMethodRef(indy, pf[i], self);
                            if (bound != null) {
                                calls.add(new String[] {String.valueOf(bound.getTag() == Opcodes.H_INVOKEINTERFACE
                                        ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL), bound.getOwner(),
                                        bound.getName(), bound.getDesc()});
                                thisKeys.add(bound.getName());
                            } else {
                                for (Object a : indy.bsmArgs) if (a instanceof Handle hd) otherNames.add(hd.getName());
                            }
                            continue;
                        }
                        if (!(in instanceof MethodInsnNode min)) continue;
                        String nd = min.name;
                        if (Candor.isToStringSink(min.owner, min.name, min.desc)) otherNames.add("toString");
                        for (String con : Candor.equalsHashContracts(min.owner, min.name, min.desc)) otherNames.add(con);
                        if (Candor.isCompareToSink(min.owner, min.name)) otherNames.add("compareTo");
                        String fc = Candor.formatterSinkCtor(min.owner, min.name, min.desc);
                        if (fc != null) otherNames.add(fc);
                        if (Candor.ioDriverContract(min.name) != null) otherNames.addAll(List.of("write", "append", "read"));
                        Frame<ProvValue> f = pf[i];
                        int op = min.getOpcode();
                        boolean onBound = f != null && self != null && op != Opcodes.INVOKESTATIC
                                && !min.name.equals("<init>") && Candor.receiverProv(f, min) == self;
                        // the bound value handed on as an argument to a project body
                        int passAt = -1;
                        if (f != null && self != null && !onBound) {
                            List<ProvValue> args = Candor.callArgs(f, min);
                            for (int k = 0; k < args.size(); k++) if (args.get(k) == self) { passAt = passAt < 0 ? k : -2; }
                        }
                        if (onBound) {
                            calls.add(new String[] {String.valueOf(op), min.owner, min.name, min.desc});
                            thisKeys.add(nd);
                        } else if (passAt >= 0 && f != null) {
                            for (String n : projectCallees(c, min, f)) passes.add(new String[] {n, String.valueOf(passAt)});
                            passKeys.add(nd);
                        } else {
                            otherKeys.add(nd);
                        }
                    }
                    if (!calls.isEmpty() || !passes.isEmpty()) {
                        Set<String> remThis = new HashSet<>(), remPass = new HashSet<>();
                        for (String k : thisKeys)
                            if (!otherKeys.contains(k) && !passKeys.contains(k) && !otherNames.contains(k)) remThis.add(k);
                        for (String k : passKeys)
                            if (!otherKeys.contains(k) && !thisKeys.contains(k) && !otherNames.contains(k)) remPass.add(k);
                        r = new ThisInfo(calls, passes, remThis, remPass);
                    }
                }
            }
        }
        thisInfoMemo.put(mk, r);
        return r;
    }

    /** The instance-method handle of a LambdaMetafactory reference whose ONE captured value is {@code self}. */
    static Handle boundMethodRef(InvokeDynamicInsnNode indy, Frame<ProvValue> f, ProvValue self) {
        if (f == null || self == null || indy.bsm == null || !indy.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory"))
            return null;
        if (indy.bsmArgs.length < 2 || !(indy.bsmArgs[1] instanceof Handle h)) return null;
        if (h.getTag() != Opcodes.H_INVOKEVIRTUAL && h.getTag() != Opcodes.H_INVOKEINTERFACE) return null;
        if (h.getName().startsWith("lambda$")) return null;
        if (Type.getArgumentTypes(indy.desc).length != 1 || f.getStackSize() < 1) return null;
        return f.getStack(f.getStackSize() - 1) == self ? h : null;
    }

    /** The bodies a call on {@code this} reaches when {@code this} is {@code t} (exactly, or one of its
     *  subtypes). A special call (private, super) names one body whatever the receiver. */
    static List<String> thisTargets(AnalysisContext c, String[] call, String t, boolean exact) {
        int op = Integer.parseInt(call[0]);
        String owner = call[1], name = call[2], desc = call[3];
        ClassNode oc = c.byName.get(owner);
        MethodNode om = Candor.findMethod(oc, name, desc);
        if (op == Opcodes.INVOKESPECIAL || om != null && (om.access & Opcodes.ACC_PRIVATE) != 0) {
            if (oc == null) return List.of();   // `super.m()` into a JDK/dependency class: no project body
            String tg = Cha.declaresConcrete(oc, name, desc) ? Cha.methodId(owner.replace('/', '.'), name, desc)
                    : Cha.nearestConcreteSuper(owner, name, desc);
            return tg == null ? List.of() : List.of(tg);
        }
        if (!c.byName.containsKey(t)) return List.of();
        if (exact) {
            String tg = Cha.monomorphicTarget(t, name, desc);
            return tg == null ? List.of() : List.of(tg);
        }
        return Cha.chaTargets(t, name, desc);
    }

    /** The specialised copy carries the body's OWN facts unchanged: its direct and inherited effects and every
     *  per-function surface the report propagates. Only edges differ. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void copySurfaces(AnalysisContext c, String from, String to) {
        EffectSet d = c.direct.get(from);
        c.direct.put(to, d == null ? EffectSet.empty() : d.copy());
        EffectSet v = c.viaCross.get(from);
        if (v != null) c.viaCross.put(to, v.copy());
        EffectSet tn = c.tainted.get(from);
        if (tn != null) c.tainted.put(to, tn.copy());
        for (Map m : List.<Map>of(c.fsDirect, c.unknownWhy, c.hostsDirect, c.cmdsDirect, c.pathsDirect,
                c.tablesDirect, c.surfaceIncomplete, c.blindDirect, c.dispatchDirect)) {
            Object x = m.get(from);
            if (x != null) m.put(to, new TreeSet((Collection) x));
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
