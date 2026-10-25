package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;
import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * CALL-TARGET RESOLUTION — ONE ENTRY POINT for "which bodies can run when a member is dispatched on a receiver whose
 * DECLARED type is outside this scan" (call-target program, round 1, 2026-10-25; FABLE-SYNTHESIS §3.3).
 *
 * <p><b>Why a class.</b> Before this, the question was answered separately at each SPELLING of the same source
 * call, and each spelling asked a different subset of the type universe:
 * <ul>
 *   <li>{@code invokevirtual java/lang/Object.toString} over a dependency-declared receiver (R1378) walked the
 *       dependency's subtypes DOWN and never the consumer's own (U2, SOUNDNESS R1413);</li>
 *   <li>{@code invokeinterface dep/I.toString} had no walk at all (SOUNDNESS R1379);</li>
 *   <li>a JDK sink formatting/hashing/comparing a dependency-typed value ({@code "v=" + t}, {@code map.put(t, v)},
 *       {@code Collections.sort(l)}) walked only UP ({@code nearestDepFn} / {@code nearestDepFnsNamed}), so a
 *       dependency SUBTYPE's override never joined (U1, SOUNDNESS R1412);</li>
 *   <li>{@code invokevirtual dep/T.toString} with more consumer overrides than the bound read pure: the past-bound
 *       floor ran only for a receiver the caller's own frame produced, never for a parameter of a dependency type
 *       (the declared half of U2).</li>
 * </ul>
 * Each spelling now calls {@link #resolve}, which asks the same three sets: UP (the nearest declaration a chained
 * report names, for the spellings that have no exact-key join of their own), the CONSUMER's own subtypes, and the
 * DEPENDENCY's subtypes ({@link Candor#depHierarchyJoin}).
 *
 * <p><b>The bound, and which rule applies past it.</b> The count is consumer overriders + dependency overriders
 * (the dependency's half is R1336's interval). The dependency's UNION is still priced on its own count (combining it
 * could only turn a union into a hedge — the removal direction); the combined count ADDS the past-bound reading.
 * Past it, the rule is the in-scan rule for the SAME spelling, so the chained answer agrees
 * with the one-tree answer: an explicit Object-protocol dispatch is decided by the S4 floor (disclosed only where
 * some override carries an effect the caller lacks — thirteen pure {@code toString}s stay pure, R919/PART 92); an
 * implicit sink keeps its in-scan reading, which edges every consumer override and applies no bound
 * ({@link Candor#reentryTargets}), so for a sink the consumer half is the caller's and only the dependency half is
 * asked here.
 *
 * <p><b>P6 (SPEC PART 30) — DEGRADING A SIDECAR MAY ONLY WIDEN A DISCLOSURE.</b> Every walk this class or
 * {@link Candor#depHierarchyJoin} / {@link Candor#depUpJoin} performs needs the dependency's hierarchy sidecar. A
 * chained report with no hierarchy sidecar beside it is therefore not counted as COVERED (Loader#loadCrossDeps: the
 * same door a stale, incomplete or judged-nothing report takes), and a walk asked from a type in such a report's
 * packages discloses {@code invisible: [pkg]} on the caller ({@link #discloseUncovered}) instead of reading pure
 * (SOUNDNESS R1377 / R1333). Before this, the answering arm made the degraded arm look worse: the more the
 * sidecar-present scan resolves, the more deleting the sidecar silently deletes.
 *
 * <p>No kill switch: the old walks are deleted. The control that licensed that ({@code CANDOR_CT=0}, byte-identical to
 * published 0.40.16 over the call-target matrix) is in the commit that introduced this class.
 */
final class CallTargets {
    private CallTargets() {}

    static final boolean DEBUG = System.getenv("CANDOR_CT_DEBUG") != null;

    /** The spelling a site was written in — decides the past-bound rule (see the class doc), nothing else. */
    enum Spelling {
        /** An explicit call whose instruction OWNER is the declared type ({@code invokevirtual dep/T.m},
         *  {@code invokeinterface dep/I.m}): crossDepJoin already joined that key and walked it UP (R868). */
        EXPLICIT,
        /** An explicit call javac spelled on a SUPERTYPE of the declared type ({@code invokevirtual
         *  java/lang/Object.toString} over a {@code dep.T} receiver, R1378): the declared type's own key is joined here. */
        RETARGET,
        /** A JDK body that runs the member on a value it was handed ({@code String.valueOf(t)}, {@code map.put(t, v)}). */
        SINK
    }

    /** Every package a P6 disclosure named this scan. */
    static Set<String> p6Packages(AnalysisContext c) {
        Set<String> out = new TreeSet<>();
        for (TreeSet<String> s : c.blindDirect.values())
            for (String p : s) if (p.startsWith(P6_MARK)) out.add(p.substring(P6_MARK.length()));
        return out;
    }

    /** The report's per-function blind sets: the κ entries kept where their package is uncovered ({@code global}
     *  minus the covered packages only P6 put there), and every P6 entry, unmarked. */
    static Map<String, TreeSet<String>> reportBlind(AnalysisContext c, Map<String, TreeSet<String>> acc, Set<String> global) {
        Set<String> p6 = p6Packages(c);
        if (p6.isEmpty()) return acc;
        Map<String, TreeSet<String>> out = new HashMap<>();
        for (var e : acc.entrySet()) {
            TreeSet<String> s = new TreeSet<>();
            for (String p : e.getValue()) {
                if (p.startsWith(P6_MARK)) s.add(p.substring(P6_MARK.length()));
                else if (global.contains(p) && !(p6.contains(p) && c.depCoveredPkgs.contains(p))) s.add(p);
            }
            out.put(e.getKey(), s);
        }
        return out;
    }

    /** Is {@code t} a type this class answers for: not a project class, and a type a chained dependency report
     *  speaks for — named by a hierarchy sidecar, or in a package a chained report names. The second half is what
     *  lets the CONSUMER half (this scan's own subtypes, which need no sidecar) run when a sidecar is missing. */
    static boolean outsideScan(AnalysisContext c, String t) {
        if (t == null || c.byName.containsKey(t) || c.projectClasses.contains(t)) return false;
        if (c.depIndexed.contains(t) || hierarchyUncovered(c, t)) return true;
        int slash = t.lastIndexOf('/');
        return slash > 0 && !t.startsWith("java/") && c.depChainedPkgs.contains(t.substring(0, slash).replace('/', '.'));
    }

    /** P6: {@code t}'s package came from a chained report whose hierarchy sidecar was absent, and no sidecar names
     *  {@code t} — so no walk from {@code t} (UP, DOWN, EXACT) can be performed. */
    static boolean hierarchyUncovered(AnalysisContext c, String t) {
        if (t == null || c.depHierUncoveredPkgs.isEmpty() || c.depIndexed.contains(t) || c.byName.containsKey(t))
            return false;
        int slash = t.lastIndexOf('/');
        return slash > 0 && c.depHierUncoveredPkgs.contains(t.substring(0, slash).replace('/', '.'));
    }

    /** Marks a P6 entry in {@code blindDirect}. The κ ledger's entries are filtered at the report by COVERAGE (a
     *  covered package's silence is a purity claim); a P6 entry names a covered package on purpose — the walk, not the
     *  key, is what could not be answered — so it rides the same accumulator (and its fixpoint, and the refresh delta)
     *  marked, and {@link ReportWriter} keeps it unfiltered. Never on the wire: the report strips it. */
    static final String P6_MARK = "\u0001";

    /** P6 — the disclosure on the no-hierarchy branch: the caller reaches a dispatch over a dependency type whose
     *  hierarchy no sidecar supplied, so the bodies it may run are out of sight. {@code invisible: [pkg]}, through the
     *  κ ledger's per-function accumulator, marked ({@link #P6_MARK}) so the coverage filter does not drop it.
     *  @return true if a disclosure was recorded */
    static boolean discloseUncovered(AnalysisContext c, String id, String t) {
        if (!hierarchyUncovered(c, t)) return false;
        String pkg = t.substring(0, t.lastIndexOf('/')).replace('/', '.');
        c.blindDirect.computeIfAbsent(id, k -> new TreeSet<>()).add(P6_MARK + pkg);
        if (DEBUG) System.err.println("CT\tP6\t" + id + "\t" + t);
        return true;
    }

    /**
     * Join into {@code id} every body that can run when {@code name+desc} is dispatched on a receiver whose declared
     * type is {@code declType}, a type outside this scan ({@link #outsideScan}).
     *
     * @param recv the receiver's EXACT dependency type where provenance proves one ({@code new T}), else null
     * @param site the call site, for an explicit Object-protocol dispatch on a parameter (the in-scan floor's
     *             receiver); null for a sink
     * @return true if anything was joined, edged or disclosed
     */
    static boolean resolve(AnalysisContext c, String id, String declType, String name, String desc, String recv,
            Spelling sp, Site site) {
        if (name.startsWith("<") || declType == null) return false;
        if (!outsideScan(c, declType)) {
            // not a dependency type (a PROJECT class extending one, typically): a sink still reads the nearest chained
            // declaration UP its supertypes — the pre-round-1 read; the consumer's own subtypes are the caller's half
            if (sp != Spelling.SINK) return false;
            DepFn up = Candor.nearestDepFn(declType, name, desc);
            Candor.inheritDepFn(id, up);
            return up != null;
        }
        boolean resolved = false;
        // UP — the nearest declaration a chained report names. An explicit call's exact-key join and R868's walk UP
        // already ran in crossDepJoin; a sink has neither, so its UP is asked here (formerly nearestDepFn at the sink).
        if (sp == Spelling.SINK) {
            DepFn up = Candor.nearestDepFn(declType, name, desc);
            Candor.inheritDepFn(id, up);
            resolved |= up != null;
        } else if (sp == Spelling.RETARGET) {
            DepFn own = c.crossDeps.get(declType + "." + name + desc);
            if (own != null && !own.walkOnly) { Candor.inheritDepFn(id, own); resolved = true; }
        }
        // P6 — no hierarchy: no DOWN, no EXACT walk can be answered. Disclose and keep the consumer half below.
        resolved |= discloseUncovered(c, id, declType);
        // CONSUMER — this scan's own overriders of the member on declType. An exact dependency receiver has none.
        List<String> local = recv != null ? List.of() : Cha.chaTargets(declType, name, desc);
        // DEPENDENCY — the dependency's own subtypes, bounded by the ONE count (consumer + dependency overriders)
        int depDeclaring = 0;
        if (c.depIndexed.contains(declType)) {
            MethodInsnNode rt = new MethodInsnNode(Opcodes.INVOKEVIRTUAL, declType, name, desc, false);
            DepFn own = c.crossDeps.get(declType + "." + name + desc);
            Snapshot before = new Snapshot(c, id);
            depDeclaring = Candor.depHierarchyJoin(c, id, rt, own, recv);
            resolved |= before.changed(c, id);
        }
        if (sp != Spelling.SINK && !local.isEmpty()) {
            boolean protocol = Candor.isObjectProtocolExempt(name, desc);
            if (local.size() + depDeclaring <= Rules.CHA_FANOUT_LIMIT || Cha.isClosedHierarchy(declType)) {
                // in bound: the in-scan resolver decides (ExactTypes) where the caller's frame produced the receiver;
                // otherwise the overriders are the candidate set, as in-scan bounded CHA edges them
                if (site == null || !site.recordExact()) c.edges.computeIfAbsent(id, k -> new LinkedHashSet<>()).addAll(local);
            } else if (protocol) {
                // past it: the S4 floor (ArgContract#objectFloor) over declType's consumer overriders
                c.argContractFloor.computeIfAbsent(id, k -> new TreeSet<>()).add(
                        declType + "." + name + desc + "\t" + declType + "\tS4");
            } else {
                c.viaCross.computeIfAbsent(id, k -> EffectSet.empty()).add(Effect.UNKNOWN);
                c.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                        .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, declType.replace('/', '.') + "." + name));
            }
            if (site != null && site.recordExact())
                ExactTypes.record(id, site.mn(), site.insn(), site.stackIdx(), declType, name, desc, site.kind());
            resolved = true;
        }
        if (DEBUG)
            System.err.println("CT\tRESOLVE\t" + sp + "\t" + id + "\t" + declType + "." + name + desc + "\tlocal="
                    + local.size() + "\tdep=" + depDeclaring + (recv != null ? "\texact=" + recv : ""));
        return resolved;
    }

    /** The dependency's subtypes of {@code owner} (transitively, from the hierarchy sidecars) and what each declares of
     *  {@code name+desc}: the overriding rows ({@code inh} excluded — it was joined by key), and the R1336 interval of
     *  declaring subtypes. Project subtypes are passed through, never counted (they are the consumer half). */
    record DepDown(List<DepFn> overrides, Set<String> seen, int declaring, int undecided) {}

    static DepDown depDown(AnalysisContext c, String owner, String name, String desc, DepFn inh, int lineState) {
        List<DepFn> overrides = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int declaring = 0, undecided = 0;
        ArrayDeque<String> q = new ArrayDeque<>(c.depSubtypes.getOrDefault(owner, List.of()));
        while (!q.isEmpty()) {
            String t = q.poll();
            if (!seen.add(t)) continue;
            q.addAll(c.depSubtypes.getOrDefault(t, List.of()));
            if (c.byName.containsKey(t)) continue;         // a project subtype: the consumer half
            DepFn d = Candor.depOverrideAt(t, name, desc);
            if (d != null) declaring++;
            else if (lineState != Integer.MIN_VALUE) {
                int a = Candor.depDeclares(c, t, owner, name, desc, lineState);
                if (a > 0) declaring++;
                else if (a < 0) undecided++;
            }
            if (d != null && d != inh && !overrides.contains(d)) overrides.add(d);
        }
        return new DepDown(overrides, seen, declaring, undecided);
    }

    /** Every dependency BODY a dispatch of {@code name+desc} on a value of declared type {@code t} can run: the nearest
     *  declaration UP and each subtype's override DOWN. For a site that DISCLOSES over candidates rather than joining
     *  them (ArgContract's WIDE sites), so its candidate set is the same set {@link #resolve} joins. */
    static List<DepFn> dependencyBodies(AnalysisContext c, String t, String name, String desc) {
        List<DepFn> out = new ArrayList<>();
        DepFn up = Candor.nearestDepFn(t, name, desc);
        if (up != null) out.add(up);
        if (c.depIndexed.contains(t))
            for (DepFn d : depDown(c, t, name, desc, up, Integer.MIN_VALUE).overrides()) if (!out.contains(d)) out.add(d);
        return out;
    }

    /** What a join added to a caller — so {@code resolved} means "joined something", never "a walk ran" (the κ
     *  disclosure at a sink is withheld on {@code resolved}). */
    private record Snapshot(int effects, int why, int edges) {
        Snapshot(AnalysisContext c, String id) {
            this(sizeOf(c.viaCross.get(id)), sizeOf(c.unknownWhy.get(id)), sizeOf(c.edges.get(id)));
        }
        boolean changed(AnalysisContext c, String id) {
            return !equals(new Snapshot(c, id));
        }
        private static int sizeOf(Object o) {
            if (o == null) return 0;
            if (o instanceof Collection<?> x) return x.size();
            if (o instanceof EffectSet e) return e.effects().size();
            return 0;
        }
    }

    /** An explicit call site, for handing the consumer half to {@link ExactTypes} (which follows the receiver's
     *  producers) when the caller's frame has it. {@code kind}: ExactTypes' D (a value) or P (a parameter). */
    record Site(MethodNode mn, org.objectweb.asm.tree.AbstractInsnNode insn, int stackIdx, String kind) {
        boolean recordExact() { return mn != null && insn != null && stackIdx >= 0; }
    }

    /** A JDK sink's by-NAME contract ({@code compareTo}, {@code append}, {@code write}, {@code read}) over a value of
     *  type {@code declType}: every descriptor the dependency publishes under that name on the type, its ancestors or
     *  its subtypes, each resolved as a member. Formerly {@link Candor#nearestDepFnsNamed} at the sink (UP only).
     *  @return true if anything was joined or disclosed */
    static boolean resolveNamed(AnalysisContext c, String id, String declType, String contract) {
        if (declType == null) return false;
        if (!outsideScan(c, declType)) {
            // not a dependency type: the nearest chained declaration UP, per descriptor (the pre-round-1 read)
            boolean any = false;
            for (DepFn d : Candor.nearestDepFnsNamed(declType, contract)) { Candor.inheritDepFn(id, d); any = true; }
            return any;
        }
        Set<String> descs = new LinkedHashSet<>();
        for (String t : Cha.resolutionOrder(declType, true))
            for (String d : Candor.depFnsNamed(t, contract).keySet())
                if (Candor.contractShapeOk(contract, d)) descs.add(d);
        ArrayDeque<String> q = new ArrayDeque<>(c.depSubtypes.getOrDefault(declType, List.of()));
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String t = q.poll();
            if (!seen.add(t)) continue;
            q.addAll(c.depSubtypes.getOrDefault(t, List.of()));
            for (String d : Candor.depFnsNamed(t, contract).keySet())
                if (Candor.contractShapeOk(contract, d)) descs.add(d);
        }
        boolean resolved = discloseUncovered(c, id, declType);
        for (String d : descs) resolved |= resolve(c, id, declType, contract, d, null, Spelling.SINK, null);
        return resolved;
    }

    /** The receiver's declared type at an explicit Object-protocol call whose OWNER the instruction names as
     *  {@code java/lang/Object} or a dependency interface: the type to resolve over, when it is outside this scan. */
    static String declTypeOf(AnalysisContext c, Interp.ProvValue rv, MethodInsnNode min) {
        String dt = rv == null ? null : rv.declType;
        if (dt == null || dt.equals("java/lang/Object") || !outsideScan(c, dt)) return null;
        return dt;
    }

    /** The receiver's stack index in the frame before {@code min}. */
    static int receiverIndex(org.objectweb.asm.tree.analysis.Frame<?> f, MethodInsnNode min) {
        return f == null ? -1 : f.getStackSize() - Type.getArgumentTypes(min.desc).length - 1;
    }
}
