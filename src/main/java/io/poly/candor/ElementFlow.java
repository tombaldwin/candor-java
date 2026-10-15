package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import io.poly.candor.Interp.ProvValue;
import java.util.*;
import org.objectweb.asm.Handle;
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
 * <p><b>SOUNDNESS R1179 — ORDERING.</b> A sort runs its elements' {@code compareTo}: {@code Collections.sort(l)},
 * {@code l.sort(null)}, {@code Arrays.sort(a)}, {@code Collections.max/min/binarySearch}, {@code stream.sorted()},
 * and inserting a collection into a SORTED one with natural ordering ({@code new TreeSet<>(l)}, {@code t.addAll(l)},
 * {@code new PriorityQueue<>(l)}, the skip lists) — each executed on JDK 21. The element type is erased inside
 * the container, so the sink cannot read it off the argument ({@link Candor#comparesArgZero}); the cell can. A
 * receiver's ORDERING is a property of the container OBJECT, so it flows along ALIAS links only (a field store, a
 * return, an unmodifiable view), never along an element copy: a {@code new TreeSet<>(cmp)} stored in a field and
 * filled elsewhere runs the comparator, not {@code compareTo}. A receiver with no known allocation is judged by its
 * static owner, and only a SORTED owner counts: a declared {@code Set}/{@code Map} needs a natural-ordered allocation
 * to reach it (POSITIVE EVIDENCE — measured on the corpus, "it may be a TreeSet" charged a {@code LinkedHashMap}
 * behind {@code unmodifiableMap}). An allocation reaches through a constructor or setter parameter that the callee
 * stores (an ALIAS summary), and a summary's receiver condition on the callee's own parameter is re-read over the
 * caller's argument at each call site, so {@code <T> void ins(Set<T> s, T a) { s.add(a); }} charges the caller
 * that passes a {@code new TreeSet<>()} and not the one that passes a {@code new HashSet<>()}.
 *
 * <p><b>PARAMETERS — a summary per method, applied at each call site.</b> A body that sorts, hashes or compares
 * the elements of its OWN collection parameter is, to its caller, a sink for the caller's elements, exactly as
 * {@link ArgContract} treats a scalar parameter: the caller is charged over ITS argument's elements, and the
 * callee keeps only what its own signature names. A parameter that reaches a FIELD passes the caller's elements
 * into that field (a field cell already merges every instance), and one that reaches the RETURN links the
 * caller's argument to that call's own result — call-site-specific, so a shared factory merges nothing.
 *
 * <p><b>SOUNDNESS R1174 — a collection handed to a CHAINED dependency.</b> The dependency may store it and compare,
 * hash or sort it later (executed); its report cannot say so (⟨0.39⟩ has no key for a JDK-owned member). The
 * argument's element types are witnessed for {@link ArgContract#postFixpoint}'s disclosure, the same one a
 * project value handed directly gets — through a parameter summary too.
 *
 * <p><b>SOUNDNESS R1184 — the residuals R1179 named.</b> A map cell's VALUES live in a twin cell ({@code |v}) that
 * travels every flow link the keys do ({@code put}'s value, {@code values()}, a {@code Map<K, V>} signature's V). An
 * ARRAY is a cell: what is STORED in it (an erased {@code T[]}, a varargs pack, a {@code toArray()}) is its element,
 * and an object-array argument takes the same summary a collection does. Past a stream's {@code map} stage the
 * elements are the function's instantiated result type. {@code collect(toCollection(TreeSet::new))} (or a capture-free
 * {@code () -> new TreeSet<>(..)}) and {@code toMap/groupingBy(.., TreeMap::new, ..)} order what they collect. A
 * SCALAR parameter a callee adds to a container — a container parameter or its return (never a field, which merges
 * every instance) — is the caller's element there, through the summary (a one-element pass, closed backwards only over pass-through callers). A
 * natural-ordering COMPARATOR ({@code Collections.reverseOrder()}, {@code Comparator.naturalOrder()}, a method
 * reference to {@code compareTo}, {@code nullsFirst/Last} over one) is natural ordering. Two members are not
 * decidable here and are DISCLOSED, never charged ({@link ArgContract#discloseCompareTo}): a dependency's container
 * returned as an interface (its allocation out of sight; a sorted static type is evidence and charges), and a
 * HashMap-backed structure's tree bins. Residuals: a comparator built by {@code Comparator.comparing(f)} (it runs
 * the KEY's compareTo); {@code flatMap}; a scalar a callee stores into its own FIELD container (a field merges every
 * instance, so it is not followed); a collection reached through a field the dependency fills; a tree bin over a
 * chained dependency's key type; a function value that is not a lambda or method reference.
 *
 * <p><b>SOUNDNESS R1183.</b> {@code TreeSet}/{@code TreeMap} key operations are charged by
 * {@link Candor#contractReentry} with the element's compareTo; the charge is applied here, and WITHHELD only where every
 * cell the receiver can be is an allocation in the same body whose comparator is a lambda or method reference (other
 * than {@code compareTo}) made in that body ({@link #CMPX}), every producer traced ({@link #traced}). A comparator
 * OBJECT ({@code new ReverseComparator()}) or one stored in a field keeps the charge: its {@code compare} may run the
 * elements' {@code compareTo} and nothing edges it from here.
 *
 * <p>After the analyze loop only; reads bodies like DbHandleFlow. A map cell's elements are its KEYS ({@code put},
 * {@code keySet()}, {@code new TreeMap<>(m)}, {@code putAll}). Over-approximations, stated: a list of one element
 * sorts without comparing; a {@code TreeSet} copied from a {@code SortedSet} reached through a declared
 * {@code Collection} builds without comparing; {@code sorted().count()} on a sized stream skips the sort (JDK 21); a
 * field merges every instance's container; a comparator-built TreeSet reached through a parameter, a public field, a
 * dependency's return or {@code Collections.reverseOrder(cmp)} keeps its charge; a hashed key of a self-Comparable
 * type is disclosed whatever its hash distribution.
 */
final class ElementFlow {
    private ElementFlow() {}

    static final String EQ = ArgContract.EQUALS, HASH = ArgContract.HASHCODE, CMP = ArgContract.COMPARETO;
    /** Not a member: the cell's elements are handed to a chained dependency (R1174). */
    static final String WITNESS = "W";
    static final String NAT = "NAT", BYCMP = "CMP", UNSORTED = "UNS";
    /** SOUNDNESS R1184 — receiver kinds beyond an allocation in sight. {@link #CMPX}: built with a comparator that is
     *  PROVABLY not natural ordering (a lambda or method reference other than {@code compareTo}, a
     *  {@code comparingInt/Long/Double}, a project comparator's {@code new}) — the only kind that may SUPPRESS a charge
     *  (R1183). {@link #SRT}: a value whose static type is a sorted container but whose comparator is not known (a
     *  dependency's or the JDK's {@code SortedSet} return) — evidence of ordering exactly as a static sorted owner is.
     *  {@link #DEP}: a dependency's return typed only as a container interface — its allocation is OUT OF SIGHT, so a
     *  key operation over it is disclosed, never charged and never silent. */
    static final String CMPX = "CMPX", SRT = "SRT", DEP = "DEP";
    /** A field cell some store into which is a value this walk cannot trace to an allocation (a parameter, a call's
     *  result, an array read): it can never be PROVEN comparator-built. Ignored by every positive test. */
    static final String UNK = "?";
    /** Not a member: the elements are KEYS of a hashed container, whose tree bins (more than eight colliding keys)
     *  run {@code compareTo} on a key class that implements {@code Comparable} of itself (R1184, disclosed). */
    static final String TB = "TB";
    /** The twin cell holding a map cell's VALUES (R1184): every flow link carries it alongside the keys. */
    static final String VALS = "|v";
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
    private static final Set<String> KEYS = Set.of("keySet", "navigableKeySet", "descendingKeySet", "sequencedKeySet");
    private static boolean mapOwner(String o) { return o.endsWith("Map") || o.equals("java/util/Hashtable") || o.equals("java/util/Properties"); }
    /** Stream stages that keep the elements (and their type). */
    private static final Set<String> STREAM_KEEP = Set.of("filter", "sorted", "distinct", "limit", "skip", "peek",
            "parallel", "sequential", "unordered", "onClose", "takeWhile", "dropWhile");
    private static final Set<String> WRAP = Set.of("unmodifiableList", "unmodifiableSet", "unmodifiableCollection",
            "unmodifiableSortedSet", "unmodifiableNavigableSet", "synchronizedList", "synchronizedSet",
            "synchronizedCollection", "copyOf", "checkedList", "checkedSet", "checkedCollection");

    /** cell -> element types {"type\texact"}; and src cell -> dst cells (elements of src are elements of dst). */
    private static final class Graph {
        final Map<String, Set<String>> elems = new HashMap<>();
        final Map<String, Set<String>> flow = new HashMap<>();
        /** src -> dst where dst IS the same container object (a store, a return, a view): ORDERING flows here. */
        final Map<String, Set<String>> alias = new HashMap<>();
        /** cell -> how the container object orders: {@link #NAT}, {@link #BYCMP} or {@link #UNSORTED}. */
        final Map<String, Set<String>> kinds = new HashMap<>();
        /** {caller, cell, key, receiver cells joined by ' ' ("" = unconditional), static receiver owner}: a CMP
         *  dispatch with receiver cells runs only where that receiver may be sorted under natural ordering. */
        final Set<List<String>> dispatch = new LinkedHashSet<>();
        /** {caller, arg cell, callee, j, the call's own result cell}. */
        final List<String[]> passes = new ArrayList<>();
        /** the call's own result cell -> arg j -> the caller's cells for it: a summary's receiver condition on the
         *  callee's parameter k is re-read over the CALLER's argument k (context, one level per application). */
        final Map<String, Map<Integer, List<String>>> siteArgs = new HashMap<>();
        boolean grew;
        /** R1183 — "id\tinsn" -> the receiver cells of a TreeSet/TreeMap key operation (Candor#contractReentry's). */
        final Map<String, String> treeRecv = new HashMap<>();
        /** The methods that may insert one of their parameters into a container that may be sorted, directly or
         *  through a project callee: the only callees a scalar argument's summary pass can matter for. */
        Set<String> qcand = Set.of();
        /** {@link #qcand}'s members' method NAMES: a body calling one may hand it a value worth a pass (R1184). */
        Set<String> qkeys = Set.of();
        void elem(String cell, String t, boolean exact) {
            if (cell != null && t != null) elems.computeIfAbsent(cell, k -> new HashSet<>()).add(t + "\t" + (exact ? 1 : 0));
        }
        void link(String src, String dst) {
            if (src != null && dst != null && !src.equals(dst)) grew |= flow.computeIfAbsent(src, k -> new HashSet<>()).add(dst);
        }
        void alias(String src, String dst) {
            link(src, dst);
            if (src != null && dst != null && !src.equals(dst)) alias.computeIfAbsent(src, k -> new HashSet<>()).add(dst);
        }
        void kind(String cell, String k) { kinds.computeIfAbsent(cell, x -> new HashSet<>()).add(k); }
        void dispatch(String caller, String cell, String key) { dispatch(caller, cell, key, "", ""); }
        void dispatch(String caller, String cell, String key, String recv, String owner) {
            grew |= dispatch.add(List.of(caller, cell, key, recv, owner));
        }
    }

    /** Whether a call ORDERS elements by their {@code compareTo} — over-inclusive, for
     *  {@link ArgContract}'s "which names does this body reach other than on its receiver". */
    static boolean ordersElements(String owner, String name, String desc) {
        if (owner.equals("java/util/Collections")) return name.equals("sort") || name.equals("max") || name.equals("min")
                || name.equals("binarySearch");
        if (owner.equals("java/util/Arrays")) return name.equals("sort") || name.equals("parallelSort") || name.equals("binarySearch");
        if (owner.equals("java/util/stream/Stream")) return name.equals("sorted");
        if (!isCollectionOwner(owner)) return false;
        if (name.equals("sort")) return true;
        return (name.equals("addAll") || name.equals("<init>")) && (Candor.sortedOwner(owner) || Candor.maySortOwner(owner));
    }

    private static boolean arrayOrdering(String name, String desc) {
        return (name.equals("sort") || name.equals("parallelSort") || name.equals("binarySearch"))
                && (desc.startsWith("([Ljava/lang/Object;") || desc.startsWith("([Ljava/lang/Comparable;"));
    }

    static void run(AnalysisContext c) {
        Graph g = new Graph();
        g.qcand = oneElementCandidates(c);
        Set<String> qk = new HashSet<>();
        for (String q : g.qcand) { int paren = q.indexOf('('); qk.add(q.substring(q.lastIndexOf('.', paren < 0 ? q.length() : paren) + 1, paren < 0 ? q.length() : paren)); }
        g.qkeys = qk;
        for (ClassNode cn : c.ALL) {
            if (!c.projectClasses.contains(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions.size() == 0 || !relevant(c, g, cn, mn)) continue;
                try { scan(c, g, cn, mn); } catch (Throwable e) { /* an unreadable body adds nothing */ }
            }
        }
        applySummaries(g);
        // ORDERING: along alias links only
        closeOver(g.alias, g.kinds, false);
        // close the one-way flow (a map's VALUES twin travels every link its keys do)
        closeOver(g.flow, g.elems, true);
        for (List<String> d : g.dispatch) {
            Set<String> es = g.elems.get(d.get(1));
            if (es == null) continue;
            String key = d.get(2);
            boolean disclose = false;
            if (key.equals(CMP) && !d.get(3).isEmpty() && !maySort(g, d.get(3), d.get(4))) {
                // R1184: a receiver whose allocation is OUT OF SIGHT (a dependency's `Set`/`Map` return) may be the
                // dependency's TreeSet: disclosed where the element's compareTo is effectful, never charged
                if (!outOfSight(g, d.get(3))) continue;
                disclose = true;
            }
            for (String te : es) {
                int tab = te.indexOf('\t');
                String t = te.substring(0, tab);
                boolean exact = te.endsWith("1");
                if (DEBUG) System.err.println((key.equals(TB) ? "R1184BIN\t" : disclose ? "R1184OOS\t" : key.equals(CMP) ? "R1179ELEM\t"
                        : key.equals(WITNESS) ? "R1174CHAIN\t" : "R1166ELEM\t") + d.get(0) + "\t" + key + "\t" + t + "\t" + d.get(1));
                if (key.equals(WITNESS)) {
                    if (c.byName.containsKey(t)) ArgContract.CHAIN_ELEMS.get().add(new String[] {d.get(0), t, exact ? "1" : "0"});
                    continue;
                }
                if (key.equals(TB)) { ArgContract.discloseCompareTo(c, d.get(0), t, exact, true); continue; }
                if (disclose) { ArgContract.discloseCompareTo(c, d.get(0), t, exact, false); continue; }
                ArgContract.applyResolved(c, d.get(0), key, t, exact, false);
            }
        }
        treeSites(c, g);
    }

    /** SOUNDNESS R1183 — Candor#contractReentry's TreeSet/TreeMap key operations, decided here because whether the
     *  receiver runs {@code compareTo} is a fact about its ALLOCATION: one PROVEN to be built with a non-natural
     *  comparator runs the comparator only (executed on JDK 21: {@code TreeSet(cmp).add/contains},
     *  {@code TreeMap(cmp).put/get/containsKey} run no {@code compareTo}). Anything short of that proof — a parameter,
     *  a dependency's return, a public field, a comparator that may be null or natural — keeps the charge it had. */
    private static void treeSites(AnalysisContext c, Graph g) {
        for (var e : c.treeKeySites.entrySet()) {
            String id = e.getKey();
            for (String x : e.getValue()) {
                String[] a = x.split("\t", 3);   // insn, kind (T = an element type, P = a parameter index), value
                String recv = g.treeRecv.get(id + "\t" + a[0]);
                if (recv != null && provenNonNatural(c, g, recv)) {
                    if (DEBUG) System.err.println("R1183SKIP\t" + id + "\t" + a[0] + "\t" + a[2] + "\t" + recv);
                    continue;
                }
                if (a[1].equals("P")) c.argContractDirect.computeIfAbsent(id, k -> new TreeSet<>()).add(a[2] + "\t" + ArgContract.COMPARETO);
                else Candor.reentryEdgeByType(id, a[2], Candor.C_COMPARETO, true);
            }
        }
    }

    /** Every cell the receiver can be is an allocation IN THIS BODY built with a provably non-natural comparator — a
     *  lambda or method reference made in this body, whose own body is therefore edged to it at creation. Not a field:
     *  a comparator lambda stored with the container is edged to the INITIALISER, not to this body, so the charge the
     *  old path made here was the only cover for whatever that comparator runs. */
    private static boolean provenNonNatural(AnalysisContext c, Graph g, String recv) {
        if (recv.isEmpty() || recv.equals("?")) return false;
        for (String r : recv.split(" ")) {
            if (!r.startsWith("L:")) return false;
            Set<String> k = g.kinds.get(r);
            if (k == null || k.isEmpty()) return false;
            for (String x : k) if (!x.equals(CMPX)) return false;
        }
        return true;
    }

    /** R1183 — every producer of the value is an allocation or a field read, through locals, DUP and CHECKCAST: no
     *  parameter, no call result, no array element. Only then do its cells say EVERYTHING it can be. */
    private static boolean traced(MethodNode mn, Frame<SourceValue>[] sf, SourceValue v, Set<SourceValue> seen) {
        if (v == null || v.insns.isEmpty()) return false;
        if (!seen.add(v)) return true;
        for (AbstractInsnNode src : v.insns) {
            int idx = mn.instructions.indexOf(src);
            Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
            switch (src.getOpcode()) {
                case Opcodes.NEW, Opcodes.GETFIELD, Opcodes.GETSTATIC -> { }
                case Opcodes.DUP, Opcodes.CHECKCAST -> { if (f == null || !traced(mn, sf, f.getStack(f.getStackSize() - 1), seen)) return false; }
                case Opcodes.ALOAD -> {
                    if (f == null) return false;
                    SourceValue lv = f.getLocal(((VarInsnNode) src).var);
                    if (lv.insns.isEmpty()) return false;   // a parameter, or the receiver
                    for (AbstractInsnNode st : lv.insns) {
                        int si = mn.instructions.indexOf(st);
                        if (si < 0 || sf[si] == null || !traced(mn, sf, sf[si].getStack(sf[si].getStackSize() - 1), seen)) return false;
                    }
                }
                default -> { return false; }
            }
        }
        return true;
    }

    private static void closeOver(Map<String, Set<String>> links, Map<String, Set<String>> vals, boolean twin) {
        boolean changed = true; int rounds = 0;
        while (changed && rounds++ < 64) {
            changed = false;
            for (var e : links.entrySet()) {
                Set<String> s = vals.get(e.getKey());
                if (s != null && !s.isEmpty())
                    for (String d : e.getValue()) changed |= vals.computeIfAbsent(d, k -> new HashSet<>()).addAll(s);
                if (!twin) continue;
                Set<String> v = vals.get(e.getKey() + VALS);
                if (v != null && !v.isEmpty())
                    for (String d : e.getValue()) changed |= vals.computeIfAbsent(d + VALS, k -> new HashSet<>()).addAll(v);
            }
        }
    }

    /** The receiver cells of a conditional dispatch; {@code "?"} — no allocation known — when it has none. */
    private static String recvKey(List<String> cells) { return cells.isEmpty() ? "?" : String.join(" ", cells); }

    /** A receiver may be sorted under natural ordering: an allocation reaching it orders naturally, or none is
     *  known and its static owner is sorted or may be. A receiver known only as comparator-ordered or unsorted
     *  does not run {@code compareTo}. */
    private static boolean maySort(Graph g, String recv, String owner) {
        for (String r : recv.split(" ")) {
            Set<String> k = g.kinds.get(r);
            // POSITIVE EVIDENCE for an interface owner: a declared `Set`/`Map`/`Collection` with no allocation in
            // sight is overwhelmingly a hashed one, and charging every such call the element's compareTo was the
            // dominant false charge measured on the corpus (a `LinkedHashMap` behind `unmodifiableMap`). A static
            // SORTED owner is evidence by itself.
            boolean none = k == null || k.isEmpty() || k.size() == 1 && k.contains(UNK);
            if (none) { if (Candor.sortedOwner(owner)) return true; }
            else if (k.contains(NAT) || k.contains(SRT)) return true;
        }
        return false;
    }

    /** R1184 — some cell of the receiver may be a dependency's container whose allocation this scan cannot see. */
    private static boolean outOfSight(Graph g, String recv) {
        for (String r : recv.split(" ")) {
            Set<String> k = g.kinds.get(r);
            if (k != null && k.contains(DEP)) return true;
        }
        return false;
    }

    /** The parameter summaries, to a fixpoint: what each method does with the elements of its parameter j —
     *  the keys dispatched on any cell of its own they reach, the fields they reach, whether they are returned
     *  — applied at every call site that passes a cell as arg j. */
    private static void applySummaries(Graph g) {
        Map<String, List<List<String>>> byCell = new HashMap<>();
        int rounds = 0;
        do {
            g.grew = false;
            byCell.clear();
            for (List<String> d : g.dispatch) byCell.computeIfAbsent(d.get(1), k -> new ArrayList<>()).add(d);
            Map<String, Object[]> memo = new HashMap<>();
            for (String[] p : new ArrayList<>(g.passes)) {
                String callee = p[2], pc = "P:M:" + callee + ":" + p[3];
                if (p[5].equals("Q")) {
                    // a scalar argument: only what the callee does with the parameter AS one element — directly, or
                    // (R1184) as an element of a container of its own that it fills with it
                    String qc = "Q" + pc.substring(1);
                    Object[] qs = memo.computeIfAbsent(qc, k -> summary(g, byCell, callee, k));
                    @SuppressWarnings("unchecked") List<List<String>> qk = (List<List<String>>) qs[0];
                    for (List<String> d : qk) g.dispatch(p[0], p[1], d.get(2), substitute(g, d.get(3), callee, p[4]), d.get(4));
                    // …and where the callee ADDS it — to a container parameter or the return, both specific to THIS call
                    // — the caller's value is an element there (`<T> void push(List<T> l, T e) { l.add(e); }`, then
                    // the caller sorts `l`). NOT to a field: a field cell merges every instance, and a generic
                    // container class's `add(E)` then poured every caller's element type into every instance —
                    // measured on stanford-corenlp, where `ClassicCounter.setCount` made `printSVMLightFormat`, which
                    // sorts an `Integer[]`, charge `IndexedWord.compareTo` (a fabrication).
                    if ((Boolean) qs[2]) g.link(p[1], p[4]);
                    @SuppressWarnings("unchecked") Set<String> qp = (Set<String>) qs[5];
                    linkParams(g, p[1], qp, -1, p[4]);
                    continue;
                }
                Object[] sum = memo.computeIfAbsent(pc, k -> summary(g, byCell, callee, k));
                @SuppressWarnings("unchecked") List<List<String>> keys = (List<List<String>>) sum[0];
                @SuppressWarnings("unchecked") Set<String> fields = (Set<String>) sum[1];
                @SuppressWarnings("unchecked") Set<String> aliasFields = (Set<String>) sum[3];
                for (List<String> d : keys) {
                    if (DEBUG) System.err.println("R1179PASS\t" + p[0] + "\t" + d.get(2) + "\t" + callee + "\t" + p[3]);
                    g.dispatch(p[0], p[1], d.get(2), substitute(g, d.get(3), callee, p[4]), d.get(4));
                }
                for (String f : fields) if (aliasFields.contains(f)) g.alias(p[1], f); else g.link(p[1], f);
                if ((Boolean) sum[4]) g.alias(p[1], p[4]);
                else if ((Boolean) sum[2]) g.link(p[1], p[4]);
                // R1184: a parameter's elements copied into ANOTHER parameter (`copy(a, b) { b.addAll(a); }`)
                @SuppressWarnings("unchecked") Set<String> ps = (Set<String>) sum[5];
                linkParams(g, p[1], ps, Integer.parseInt(p[3]), p[4]);
                // …and what it does with a map parameter's VALUES (`m.values()` sorted, copied out, returned)
                Object[] vs = memo.computeIfAbsent(pc + VALS, k -> summary(g, byCell, callee, k));
                @SuppressWarnings("unchecked") List<List<String>> vk = (List<List<String>>) vs[0];
                for (List<String> d : vk) g.dispatch(p[0], p[1] + VALS, d.get(2), substitute(g, d.get(3), callee, p[4]), d.get(4));
                @SuppressWarnings("unchecked") Set<String> vf = (Set<String>) vs[1];
                for (String f : vf) g.link(p[1] + VALS, f);
                if ((Boolean) vs[2]) g.link(p[1] + VALS, p[4]);
                @SuppressWarnings("unchecked") Set<String> vp = (Set<String>) vs[5];
                linkParams(g, p[1] + VALS, vp, -1, p[4]);
            }
        } while (g.grew && rounds++ < 32);
    }

    /** The caller's cells for each callee parameter {@code k} the value reaches: one-way element flow, at this site. */
    private static void linkParams(Graph g, String src, Set<String> params, int self, String site) {
        if (params.isEmpty()) return;
        Map<Integer, List<String>> args = g.siteArgs.getOrDefault(site, Map.of());
        for (String x : params) {
            String twin = x.endsWith(VALS) ? VALS : "";
            int k;
            try { k = Integer.parseInt(twin.isEmpty() ? x : x.substring(0, x.length() - VALS.length())); }
            catch (NumberFormatException e) { continue; }
            if (k == self && twin.isEmpty()) continue;
            for (String a : args.getOrDefault(k, List.of())) g.link(src, a + twin);
        }
    }

    /** A receiver condition read in the callee, re-read at one call site: the callee's own parameter k stands for
     *  the caller's argument k there. */
    private static String substitute(Graph g, String recv, String callee, String site) {
        if (recv.isEmpty()) return recv;
        String pfx = "P:M:" + callee + ":";
        if (!recv.contains(pfx)) return recv;
        Map<Integer, List<String>> args = g.siteArgs.getOrDefault(site, Map.of());
        List<String> out = new ArrayList<>();
        for (String r : recv.split(" ")) {
            if (!r.startsWith(pfx)) { out.add(r); continue; }
            List<String> a = args.get(Integer.parseInt(r.substring(pfx.length())));
            if (a == null || a.isEmpty()) out.add("?"); else out.addAll(a);
        }
        return String.join(" ", out);
    }

    /** The internal name of the class declaring node {@code id} ({@code a.b.C.m(..)} -> {@code a/b/C}). */
    private static String classOf(String id) {
        int paren = id.indexOf('(');
        String head = paren < 0 ? id : id.substring(0, paren);
        int dot = head.lastIndexOf('.');
        return dot < 0 ? "" : head.substring(0, dot).replace('.', '/');
    }

    private static Object[] summary(Graph g, Map<String, List<List<String>>> byCell, String callee, String pc) {
        String own = "M:" + callee + ":", ret = "R:" + callee;
        // a parameter reaches a field the summary carries only when it is the callee's OWN class's field (a
        // constructor or setter storing its argument): measured on the corpus, a summary that also carried a field
        // reached through ANOTHER class's callee grew transitively until every `ImmutableSet.copyOf` caller's
        // elements sat in guava's `ImmutableEnumSet.delegate`, whose runtime elements are enums only.
        String ownField = "F:" + classOf(callee) + ".";
        List<List<String>> keys = new ArrayList<>();
        Set<String> fields = new HashSet<>();
        boolean returns = false;
        Set<String> params = new TreeSet<>();
        String ownParam = "P:" + own;
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> work = new ArrayDeque<>(List.of(pc));
        while (!work.isEmpty()) {
            String x = work.poll();
            if (!seen.add(x)) continue;
            for (List<String> d : byCell.getOrDefault(x, List.of())) if (d.get(0).equals(callee)) keys.add(d);
            for (String y : g.flow.getOrDefault(x, Set.of())) {
                if (y.startsWith("F:")) { if (y.startsWith(ownField)) fields.add(y); }
                else if (y.equals(ret)) returns = true;
                else if (y.indexOf(own) == 2) {   // L:/S:/P:/A: cells of the callee itself
                    work.add(y);
                    // R1184: one of the callee's own container PARAMETERS — the caller's argument there
                    if (y.startsWith(ownParam)) params.add(y.substring(ownParam.length()));   // "k", or "k|v" (its values)
                }
            }
        }
        // the same container OBJECT (not a copy of its elements) reaching a field or the return: its ordering goes too
        Set<String> aliasFields = new HashSet<>(); boolean aliasRet = false;
        Set<String> aseen = new HashSet<>();
        ArrayDeque<String> aw = new ArrayDeque<>(List.of(pc));
        while (!aw.isEmpty()) {
            String x = aw.poll();
            if (!aseen.add(x)) continue;
            for (String y : g.alias.getOrDefault(x, Set.of())) {
                if (y.startsWith("F:")) { if (y.startsWith(ownField)) aliasFields.add(y); }
                else if (y.equals(ret)) aliasRet = true;
                else if (y.indexOf(own) == 2) aw.add(y);
            }
        }
        return new Object[] {keys, fields, returns, aliasFields, aliasRet, params};
    }

    /** See {@link Graph#qcand}: the bodies with a one-element key operation on a container that may be sorted, closed
     *  backwards over the call graph. Computed before the scan so a scalar argument records a summary pass only where
     *  one can apply — every object argument of every project call was the scan's largest allocation (measured). */
    private static Set<String> oneElementCandidates(AnalysisContext c) {
        Set<String> out = new HashSet<>();
        // R1184: the bodies that ADD one of their parameters to a container, closed backwards only through callers
        // that hand one of THEIR parameters on to such a body (a pass-through) — the caller that passes its own
        // value needs a pass recorded, not membership. Kept apart from the ordering candidates, whose closure is
        // over every caller: an "adds its parameter" body is everywhere, and closing it over every caller made
        // this filter filter nothing.
        Set<String> adders = new HashSet<>(), adderKeys = new HashSet<>();
        for (ClassNode cn : c.ALL) {
            if (!c.projectClasses.contains(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                boolean ord = false, add = false;
                for (AbstractInsnNode in : mn.instructions) {
                    if (!(in instanceof MethodInsnNode m) || m.getOpcode() == Opcodes.INVOKESTATIC) continue;
                    if (!Candor.isCompareToSink(m.owner, m.name) && Candor.mayCompareArg0(m.owner, m.name, m.desc, null)) ord = true;
                    if (addsParam(mn, m)) add = true;
                    if (ord && add) break;
                }
                String id = Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc);
                if (ord) out.add(id);
                if (add) { adders.add(id); adderKeys.add(mn.name + mn.desc); }
            }
        }
        Map<String, List<String>> callers = new HashMap<>();
        for (var e : c.edges.entrySet()) for (String y : e.getValue()) callers.computeIfAbsent(y, k -> new ArrayList<>()).add(e.getKey());
        ArrayDeque<String> work = new ArrayDeque<>(out);
        while (!work.isEmpty()) for (String x : callers.getOrDefault(work.poll(), List.of())) if (out.add(x)) work.add(x);
        boolean grew = !adders.isEmpty(); int rounds = 0;
        while (grew && rounds++ < 16) {
            grew = false;
            for (ClassNode cn : c.ALL) {
                if (!c.projectClasses.contains(cn.name)) continue;
                for (MethodNode mn : cn.methods) {
                    if (adderKeys.contains(mn.name + mn.desc) && adders.contains(Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc))) continue;
                    for (AbstractInsnNode in : mn.instructions)
                        if (in instanceof MethodInsnNode m && c.projectClasses.contains(m.owner) && adderKeys.contains(m.name + m.desc)
                                && passesParam(mn, m)) {
                            String id = Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc);
                            if (adders.add(id)) { adderKeys.add(mn.name + mn.desc); grew = true; }
                            break;
                        }
                }
            }
        }
        out.addAll(adders);
        return out;
    }

    /** One of the call's argument producers (the real instructions just before it, one per argument) loads a
     *  reference parameter of the body. Syntactic, a candidate filter only. */
    private static boolean passesParam(MethodNode mn, MethodInsnNode m) {
        int n = Type.getArgumentTypes(m.desc).length;
        AbstractInsnNode prev = m;
        for (int k = 0; k < n + 2 && prev != null; k++) {
            prev = prev.getPrevious();
            while (prev != null && prev.getOpcode() < 0) prev = prev.getPrevious();
            if (prev instanceof VarInsnNode v && v.getOpcode() == Opcodes.ALOAD && paramOf(mn, v.var) >= 0) return true;
            if (prev instanceof MethodInsnNode || prev instanceof JumpInsnNode) return false;
        }
        return false;
    }

    /** R1184 — a collection insertion whose inserted value is loaded straight from one of the body's own reference
     *  parameters (not {@code this}): the body hands its caller's value into a container. Syntactic, a candidate
     *  filter only; the scan decides. */
    private static boolean addsParam(MethodNode mn, MethodInsnNode m) {
        if (!isCollectionOwner(m.owner)) return false;
        Type[] at = Type.getArgumentTypes(m.desc);
        boolean add = ADD.contains(m.name) && at.length >= 1, put = PUTS.contains(m.name) && at.length == 2 && mapOwner(m.owner);
        if (!add && !put) return false;
        AbstractInsnNode prev = m;
        for (int k = 0; k < (put ? 2 : 1); k++) {   // the value, and for a put its KEY under it
            prev = prev.getPrevious();
            while (prev != null && prev.getOpcode() < 0) prev = prev.getPrevious();
            if (prev == null) return false;
            if (prev instanceof VarInsnNode v && v.getOpcode() == Opcodes.ALOAD && paramOf(mn, v.var) >= 0) return true;
        }
        return false;
    }
    private static final Set<String> PUTS = Set.of("put", "putIfAbsent", "replace");

    private static boolean relevant(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn) {
        for (AbstractInsnNode in : mn.instructions)
            if (in instanceof MethodInsnNode m && (isCollectionOwner(m.owner) || m.owner.equals("java/util/Collections")
                    || m.owner.equals("java/util/Arrays") || m.owner.equals("java/util/stream/Stream"))) return true;
        // a method handing a value to a chained dependency (R1174), or a collection-typed parameter to a project
        // callee (a summary): neither needs a java.util call of its own
        String id = Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc);
        if (c.argContractChainArgs.containsKey(id)) return true;
        // a body that only STORES or RETURNS a collection (a constructor taking one) carries it to a field or caller
        if (mn.desc.contains("Ljava/util/")) return true;
        for (AbstractInsnNode in : mn.instructions)
            if (in instanceof FieldInsnNode fi && fi.desc.startsWith("Ljava/util/")) return true;
        for (AbstractInsnNode in : mn.instructions)
            if (in instanceof MethodInsnNode m && c.projectClasses.contains(m.owner)
                    && (m.desc.contains("Ljava/util/") || m.desc.contains("[L") || g.qkeys.contains(m.name))) return true;
        return false;
    }

    private static void scan(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn) throws Exception {
        String id = Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc);
        if (!c.edges.containsKey(id)) return;
        Frame<SourceValue>[] sf = new Analyzer<>(new SourceInterpreter()).analyze(cn.name, mn);
        CELLS_MEMO.get().clear();
        Frame<ProvValue>[] pf = Candor.cachedProvFrames(cn, mn);
        String self = "M:" + id;
        InsnList is = mn.instructions;
        // R1174: where this body hands a value to a CHAINED dependency (ArgContract#chainWitness recorded it)
        Map<Integer, Set<Integer>> chainAt = new HashMap<>();
        for (String x : c.argContractChainArgs.getOrDefault(id, new TreeSet<>())) {
            int tab = x.indexOf('\t');
            chainAt.computeIfAbsent(Integer.parseInt(x.substring(0, tab)), k -> new HashSet<>()).add(Integer.parseInt(x.substring(tab + 1)));
        }
        for (int i = 0; i < is.size(); i++) {
            AbstractInsnNode in = is.get(i);
            Frame<SourceValue> f = sf[i];
            if (f == null) continue;
            int op = in.getOpcode();
            if ((op == Opcodes.PUTFIELD || op == Opcodes.PUTSTATIC)
                    && (((FieldInsnNode) in).desc.startsWith("L") || ((FieldInsnNode) in).desc.startsWith("[L"))) {
                FieldInsnNode fi = (FieldInsnNode) in;
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, 0))
                    g.alias(cell, "F:" + fi.owner + "." + fi.name);
                // R1183: a store of a value not traced to an allocation means this field is never PROVEN anything
                if (!traced(mn, sf, f.getStack(f.getStackSize() - 1), Collections.newSetFromMap(new IdentityHashMap<>())))
                    g.kind("F:" + fi.owner + "." + fi.name, UNK);
                continue;
            }
            if (op == Opcodes.ARETURN) {
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, 0)) g.alias(cell, "R:" + id);
                continue;
            }
            // R1184: a value stored into an ARRAY is one of its elements (`T[]` erases to `Object[]`, so the array's
            // own declared component says nothing; the stored value's type does)
            if (op == Opcodes.AASTORE && f.getStackSize() >= 3 && pf != null && pf[i] != null) {
                ProvValue v = pf[i].getStack(pf[i].getStackSize() - 1);
                String t = v == null || v.nullConst || v.fromIndy ? null : ArgContract.typeOf(c, v);
                if (t != null && !t.equals("java/lang/Object"))
                    for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 3), self, 0)) g.elem(cell, t, v.newType != null);
                continue;
            }
            if (!(in instanceof MethodInsnNode m)) continue;
            Type[] at = Type.getArgumentTypes(m.desc);
            int n = at.length, base = f.getStackSize() - n;
            boolean inst = op != Opcodes.INVOKESTATIC;
            SourceValue recv = inst && base - 1 >= 0 ? f.getStack(base - 1) : null;
            Frame<ProvValue> p = pf == null ? null : pf[i];
            // R1174: a collection handed to a chained dependency — its elements are witnessed
            Set<Integer> chained = chainAt.get(i);
            if (chained != null)
                for (int j : chained)
                    if (j < n) for (String cell : cells(c, g, cn, mn, sf, f.getStack(base + j), self, 0)) g.dispatch(id, cell, WITNESS);
            // a PROJECT callee: its parameter summary is applied here (applySummaries)
            if (c.projectClasses.contains(m.owner) && p != null) {
                List<String> callees = null;
                String site = "S:" + self + ":" + i;
                for (int j = 0; j < n; j++) {
                    // R1184: an object ARRAY argument is a container too (`<T> void sa(T[] a) { Arrays.sort(a); }`)
                    boolean arr = at[j].getSort() == Type.ARRAY && at[j].getDimensions() == 1 && at[j].getElementType().getSort() == Type.OBJECT;
                    if (at[j].getSort() != Type.OBJECT && !arr) continue;
                    if (callees == null) callees = ArgContract.projectCallees(c, m, p);
                    if (callees.isEmpty()) break;
                    List<String> argCells = cells(c, g, cn, mn, sf, f.getStack(base + j), self, 0);
                    g.siteArgs.computeIfAbsent(site, k -> new HashMap<>()).put(j, argCells);
                    for (String cell : argCells)
                        for (String callee : callees) g.passes.add(new String[] {id, cell, callee, String.valueOf(j), site, ""});
                    if (arr) continue;
                    // a SCALAR argument the callee may insert into a sorted container: its own type, as ONE element.
                    // Kept apart from the cells above: it answers only the callee's Q (one-element) dispatches — the
                    // value is not a container, and reading it as one charged a project Set's OWN equals as if it
                    // were an element's (geode's CopyOnWriteHashSet, measured).
                    ProvValue v = Candor.callArg(p, m, j);
                    int pj = v == null || pf[0] == null ? -1 : Candor.paramIndexOf(mn, v, pf[0]);
                    String t = v == null || v.nullConst || v.fromIndy ? null : ArgContract.typeOf(c, v);
                    if (pj >= 0) {
                        // this body's own parameter handed on: the callee's one-element use is this body's, for ITS callers
                        for (String callee : callees)
                            if (g.qcand.contains(callee)) g.passes.add(new String[] {id, "Q:" + self + ":" + pj, callee, String.valueOf(j), site, "Q"});
                    } else if (t != null && c.byName.containsKey(t)) {
                        String vc = "V:" + self + ":" + i + ":" + j;
                        boolean any = false;
                        for (String callee : callees)
                            if (g.qcand.contains(callee)) { g.passes.add(new String[] {id, vc, callee, String.valueOf(j), site, "Q"}); any = true; }
                        if (any) g.elem(vc, t, v.newType != null);
                    }
                }
                continue;
            }
            // R1179: ORDERING over the elements of a container argument or receiver
            ordering(c, g, cn, mn, sf, f, p, m, at, base, recv, self, id, i);
            if (!isCollectionOwner(m.owner)) continue;
            // R1183: a TreeSet/TreeMap key operation (Candor#contractReentry charges it): its receiver's cells
            if (inst && treeKeyOp(m.owner, m.name))
                g.treeRecv.put(id + "\t" + i, traced(mn, sf, recv, Collections.newSetFromMap(new IdentityHashMap<>()))
                        ? recvKey(cells(c, g, cn, mn, sf, recv, self, 0)) : "?");
            // R1179: ONE element inserted into, or looked up in, a container that may be sorted — the declared
            // `Set`/`Map`, a priority queue, a skip list — runs that element's compareTo. Decided here rather than at
            // the call because the receiver's ORDERING is a cell fact: a `new TreeSet<>(cmp)` runs the comparator.
            // (`TreeSet.add`/`TreeMap.put` keep their own older path, Candor#contractReentry.)
            if (inst && p != null && n >= 1 && !Candor.isCompareToSink(m.owner, m.name)) {
                ProvValue rv = Candor.receiverProv(p, m);
                if (Candor.mayCompareArg0(m.owner, m.name, m.desc, rv == null ? null : rv.newType)) {
                    ProvValue v = Candor.callArg(p, m, 0);
                    int pi = pf[0] == null ? -1 : Candor.paramIndexOf(mn, v, pf[0]);
                    String rk = recvKey(cells(c, g, cn, mn, sf, recv, self, 0));
                    if (pi >= 0) {
                        // the element is this body's own PARAMETER: its caller's argument, through the summary
                        g.dispatch(id, "Q:" + self + ":" + pi, CMP, rk, m.owner);
                    } else {
                        String t = v == null || v.nullConst ? null : ArgContract.typeOf(c, v);
                        if (t != null) {
                            String cell = "V:" + self + ":" + i;
                            g.elem(cell, t, v.newType != null);
                            g.dispatch(id, cell, CMP, rk, m.owner);
                        }
                    }
                }
            }
            // the ORDERING of a container object, at its allocation
            if (m.name.equals("<init>") && inst) {
                String k = allocKind(m, p, mn, sf, f, base);
                if (k != null) for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.kind(cell, k);
            }
            // element ADDED
            if (inst && ADD.contains(m.name) && n >= 1 && at[n - 1].getSort() == Type.OBJECT && p != null)
                element(c, g, cn, mn, sf, pf, p, m, n - 1, recv, self, "");
            // a map's KEY put (a map cell's elements are its keys, as a declared `Map<K, V>` already reads them), and
            // (R1184) its VALUE, into the map cell's values twin
            if (inst && PUTS.contains(m.name) && n == 2 && mapOwner(m.owner) && at[0].getSort() == Type.OBJECT && p != null) {
                element(c, g, cn, mn, sf, pf, p, m, 0, recv, self, "");
                if (at[1].getSort() == Type.OBJECT) element(c, g, cn, mn, sf, pf, p, m, 1, recv, self, VALS);
            }
            // elements COPIED in
            if (inst && (m.name.equals("addAll") || m.name.equals("putAll") || m.name.equals("<init>")) && n >= 1 && at[n - 1].getSort() == Type.OBJECT
                    && at[n - 1].getInternalName().startsWith("java/util/")) {
                List<String> dst = cells(c, g, cn, mn, sf, recv, self, 0);
                for (String s : cells(c, g, cn, mn, sf, f.getStack(base + n - 1), self, 0)) for (String d : dst) g.link(s, d);
                if (m.name.equals("<init>") && hashed(m.owner))
                    for (String d : dst) { g.dispatch(id, d, HASH); g.dispatch(id, d, EQ); treeBin(g, id, d, m.owner); }
                if ((m.name.equals("addAll") || m.name.equals("putAll")) && hashed(m.owner))
                    for (String d : dst) { g.dispatch(id, d, HASH); g.dispatch(id, d, EQ); treeBin(g, id, d, m.owner); }
                // R1179: a SORTED container built from, or filled with, a collection compares the incoming elements
                // under natural ordering; a copy of a SortedSet/SortedMap/PriorityQueue keeps ITS ordering and
                // builds without comparing (TreeSet(SortedSet), executed: no compareTo)
                if (m.name.equals("<init>") && Candor.sortedOwner(m.owner) && NAT.equals(allocKind(m, p, mn, sf, f, base)))
                    for (String d : dst) g.dispatch(id, d, CMP);
                if ((m.name.equals("addAll") || m.name.equals("putAll")) && (Candor.sortedOwner(m.owner) || Candor.maySortOwner(m.owner))) {
                    String rc = recvKey(dst);
                    for (String src : cells(c, g, cn, mn, sf, f.getStack(base + n - 1), self, 0)) g.dispatch(id, src, CMP, rc, m.owner);
                }
            }
            // DISPATCHING operations over the elements
            if (inst && m.desc.equals("()I") && m.name.equals("hashCode"))
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, HASH);
            if (inst && m.name.equals("equals") && m.desc.equals("(Ljava/lang/Object;)Z")) {
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, EQ);
                // a SET's equals is containsAll over the argument: the argument's elements are hashed and compared
                if (!listOwner(m.owner))
                    for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                        g.dispatch(id, cell, HASH); g.dispatch(id, cell, EQ); treeBin(g, id, cell, m.owner);
                    }
            }
            if (inst && (m.name.equals("removeAll") || m.name.equals("retainAll")) && n == 1) {
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) {
                    g.dispatch(id, cell, EQ); g.dispatch(id, cell, HASH); treeBin(g, id, cell, m.owner);
                }
                // a hashed receiver's removeAll may iterate the ARGUMENT and remove(e): its elements are hashed
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                    g.dispatch(id, cell, EQ);
                    if (!listOwner(m.owner)) { g.dispatch(id, cell, HASH); treeBin(g, id, cell, m.owner); }
                }
            }
            // containsAll runs this.contains(e) for each ARGUMENT element: e.equals(..), and e.hashCode() when the
            // receiver is hashed. The receiver's own elements are only the arguments of those calls (executed).
            if (inst && m.name.equals("containsAll") && n == 1)
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                    g.dispatch(id, cell, EQ);
                    if (!listOwner(m.owner)) { g.dispatch(id, cell, HASH); treeBin(g, id, cell, m.owner); }
                }
        }
    }

    /** R1184 — a hashed LOOKUP or insertion over a cell's elements: a HashMap-backed structure's tree bin runs their
     *  {@code compareTo} (executed: HashMap/HashSet/LinkedHashMap/ConcurrentHashMap, 11+ colliding keys; Hashtable
     *  never treeifies). Disclosed, see {@link ArgContract#discloseCompareTo}. */
    private static void treeBin(Graph g, String id, String cell, String owner) {
        if (owner.equals("java/util/Hashtable") || owner.equals("java/util/Properties") || owner.equals("java/util/WeakHashMap")
                || owner.contains("Identity") || owner.contains("Tree") || owner.contains("Sorted") || owner.contains("Navigable")
                || owner.contains("SkipList") || owner.contains("Enum") || listOwner(owner)) return;
        g.dispatch(id, cell, TB);
    }

    /** {@link Candor#isCompareToSink}'s TreeSet/TreeMap key operations — the ones R1183 decides by the receiver. */
    static boolean treeKeyOp(String owner, String name) {
        return (owner.equals("java/util/TreeSet") || owner.equals("java/util/TreeMap")) && Candor.isCompareToSink(owner, name);
    }

    /** One element (argument {@code j}) into the receiver's cells (or their {@code twin}): its own type, and (R1184) when
     *  it is this body's own PARAMETER, a flow from that parameter's one-element cell, so a caller's value reaches the
     *  caller's container through this body's summary. */
    private static void element(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            Frame<ProvValue>[] pf, Frame<ProvValue> p, MethodInsnNode m, int j, SourceValue recv, String self, String twin) {
        ProvValue v = Candor.callArg(p, m, j);
        if (v == null || v.nullConst) return;
        List<String> dst = cells(c, g, cn, mn, sf, recv, self, 0);
        String t = ArgContract.typeOf(c, v);
        if (t != null) for (String cell : dst) g.elem(cell + twin, t, v.newType != null);
        int pi = pf[0] == null ? -1 : Candor.paramIndexOf(mn, v, pf[0]);
        if (pi >= 0) for (String cell : dst) g.link("Q:" + self + ":" + pi, cell + twin);
    }

    /** How a collection allocation orders: natural ({@link #NAT}), by a comparator ({@link #BYCMP}), unsorted, or
     *  null when it keeps a source's ordering ({@code new TreeSet<>(SortedSet)}) and so is not known here. */
    static String allocKind(MethodInsnNode m, Frame<ProvValue> p, MethodNode mn, Frame<SourceValue>[] sf, Frame<SourceValue> f, int base) {
        if (!Candor.sortedOwner(m.owner)) return UNSORTED;
        Type[] at = Type.getArgumentTypes(m.desc);
        for (int k = 0; k < at.length; k++) {
            if (at[k].getSort() != Type.OBJECT) continue;
            String a = at[k].getInternalName();
            if (a.equals("java/util/Comparator")) {
                ProvValue v = p == null ? null : Candor.callArg(p, m, k);
                if (v != null && v.nullConst) return NAT;
                return f == null ? BYCMP : comparatorKind(mn, sf, f.getStack(base + k), Collections.newSetFromMap(new IdentityHashMap<>()));
            }
            if (a.equals("java/util/SortedSet") || a.equals("java/util/SortedMap") || a.equals("java/util/PriorityQueue")
                    || a.equals("java/util/concurrent/PriorityBlockingQueue")) return null;
        }
        return NAT;
    }

    /** SOUNDNESS R1184 — what a comparator VALUE orders by, read off its producers. {@link #NAT}: it may be natural
     *  ordering — {@code null}, {@code Collections.reverseOrder()}, {@code Comparator.naturalOrder()/reverseOrder()},
     *  a {@code nullsFirst/Last} over one of those, a method reference to {@code compareTo} (each runs the elements'
     *  {@code compareTo}, executed on JDK 21). {@link #CMPX}: provably not — a lambda or another method reference, a
     *  {@code comparingInt/Long/Double} over one. Anything else — a {@code new} comparator object included — is
     *  {@link #BYCMP} (unknown). A union: NAT wins,
     *  CMPX only when every producer is one. */
    static String comparatorKind(MethodNode mn, Frame<SourceValue>[] sf, SourceValue v, Set<SourceValue> seen) {
        if (v == null || v.insns.isEmpty() || !seen.add(v)) return BYCMP;
        boolean allX = true;
        for (AbstractInsnNode src : v.insns) {
            String k = BYCMP;
            int idx = mn.instructions.indexOf(src);
            Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
            switch (src.getOpcode()) {
                case Opcodes.ACONST_NULL -> k = NAT;
                // a `new SomeComparator()`: its compare may itself run the elements' compareTo (unboundid's
                // ReverseComparator does, measured), and nothing edges its body from the container's users — unknown
                case Opcodes.INVOKEDYNAMIC -> {
                    InvokeDynamicInsnNode d = (InvokeDynamicInsnNode) src;
                    Handle h = d.bsmArgs.length >= 2 && d.bsmArgs[1] instanceof Handle hh ? hh : null;
                    k = h == null ? BYCMP : h.getName().equals("compareTo") ? NAT : CMPX;
                }
                case Opcodes.INVOKESTATIC -> {
                    MethodInsnNode mi = (MethodInsnNode) src;
                    boolean cmpOwner = mi.owner.equals("java/util/Comparator") || mi.owner.equals("java/util/Collections")
                            || mi.owner.equals("java/util/Map$Entry");
                    if (cmpOwner && (mi.name.equals("naturalOrder") || mi.name.equals("reverseOrder") && mi.desc.startsWith("()")))
                        k = NAT;
                    else if (mi.owner.equals("java/util/Comparator") && (mi.name.equals("comparingInt") || mi.name.equals("comparingLong")
                            || mi.name.equals("comparingDouble")) && f != null) {
                        // a primitive key: never a compareTo — when the key function is a lambda made HERE (edged here)
                        String kk = comparatorKind(mn, sf, f.getStack(f.getStackSize() - 1), seen);
                        k = kk.equals(CMPX) ? CMPX : BYCMP;
                    }
                    else if (mi.owner.equals("java/util/Comparator") && (mi.name.equals("nullsFirst") || mi.name.equals("nullsLast")) && f != null)
                        k = comparatorKind(mn, sf, f.getStack(f.getStackSize() - 1), seen);
                }
                case Opcodes.CHECKCAST, Opcodes.DUP -> { if (f != null) k = comparatorKind(mn, sf, f.getStack(f.getStackSize() - 1), seen); }
                case Opcodes.ALOAD -> {
                    if (f == null) break;
                    SourceValue lv = f.getLocal(((VarInsnNode) src).var);
                    if (lv.insns.isEmpty()) break;   // a parameter: unknown
                    boolean x = true, nat = false;
                    for (AbstractInsnNode st : lv.insns) {
                        int si = mn.instructions.indexOf(st);
                        String sk = si >= 0 && sf[si] != null ? comparatorKind(mn, sf, sf[si].getStack(sf[si].getStackSize() - 1), seen) : BYCMP;
                        nat |= sk.equals(NAT); x &= sk.equals(CMPX);
                    }
                    k = nat ? NAT : x ? CMPX : BYCMP;
                }
                default -> { }
            }
            if (k.equals(NAT)) return NAT;
            allX &= k.equals(CMPX);
        }
        return allX ? CMPX : BYCMP;
    }

    /** Whether the comparator argument {@code k} of {@code m} is the null constant (natural ordering). */
    private static boolean nullCmp(Frame<ProvValue> p, MethodInsnNode m, int k) {
        ProvValue v = p == null ? null : Candor.callArg(p, m, k);
        return v != null && v.nullConst;
    }
    private static int cmpArg(Type[] at) {
        for (int k = 0; k < at.length; k++) if (at[k].getSort() == Type.OBJECT && at[k].getInternalName().equals("java/util/Comparator")) return k;
        return -1;
    }

    /** SOUNDNESS R1179 — the ordering operations over a container's or an array's elements. */
    private static void ordering(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            Frame<SourceValue> f, Frame<ProvValue> p, MethodInsnNode m, Type[] at, int base, SourceValue recv,
            String self, String id, int i) throws Exception {
        int n = at.length, ck = cmpArg(at);
        // R1184: a natural-ordering comparator (`Collections.reverseOrder()`, `Comparator.naturalOrder()`, …) is
        // natural ordering too
        boolean natural = ck < 0 || nullCmp(p, m, ck)
                || NAT.equals(comparatorKind(mn, sf, f.getStack(base + ck), Collections.newSetFromMap(new IdentityHashMap<>())));
        if (!natural) return;
        String o = m.owner, name = m.name;
        if (o.equals("java/util/Collections")) {
            boolean first = n >= 1 && at[0].getSort() == Type.OBJECT && at[0].getInternalName().startsWith("java/util/");
            if (first && (name.equals("sort") || name.equals("max") || name.equals("min") || name.equals("binarySearch")))
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) g.dispatch(id, cell, CMP);
            return;
        }
        if (o.equals("java/util/Arrays")) {
            if (!arrayOrdering(name, m.desc)) return;
            // the array's DECLARED component type, read off whatever produced it (the provenance frames type
            // objects only, an array is a bare reference there)
            Set<String> comps = new HashSet<>();
            arrayComponents(mn, sf, f.getStack(base), comps, 0);
            String cell = "A:" + self + ":" + i;
            for (String comp : comps) g.elem(cell, comp, false);
            if (!comps.isEmpty()) g.dispatch(id, cell, CMP);
            // R1184: …and the array's own cells, whose elements are what was STORED in it (an erased `T[]` parameter,
            // a `toArray()`, a varargs pack) — through a summary for a parameter
            for (String ac : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) g.dispatch(id, ac, CMP);
            return;
        }
        if (o.equals("java/util/stream/Stream")) {
            // R1184: a collector that builds a naturally-ordered container compares every element it collects
            if (name.equals("collect") && n == 1 && recv != null) {
                if (NAT.equals(collectorKind(c, cn, mn, sf, f.getStack(base))))
                    for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, CMP);
                // …and a map collector with a naturally-ordered map factory compares the KEYS its key function makes
                String kt = sortedMapCollectorKey(c, cn, mn, sf, f.getStack(base));
                if (kt != null) {
                    String cell = "V:" + self + ":" + i;
                    g.elem(cell, kt, false);
                    g.dispatch(id, cell, CMP);
                }
            }
            if (name.equals("sorted") && n <= 1 && recv != null)
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, CMP);
            if ((name.equals("max") || name.equals("min")) && n == 1 && recv != null)
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, CMP);
            return;
        }
        // `list.sort(null)`: natural ordering on the receiver's own elements
        if (isCollectionOwner(o) && name.equals("sort") && n == 1 && ck == 0 && recv != null)
            for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, CMP);
    }

    /** The component types a one-dimensional object array on the stack is declared with, by its producers. */
    private static void arrayComponents(MethodNode mn, Frame<SourceValue>[] sf, SourceValue v, Set<String> out, int depth) {
        arrayComponents(mn, sf, v, out, Collections.newSetFromMap(new IdentityHashMap<>()));
    }
    private static void arrayComponents(MethodNode mn, Frame<SourceValue>[] sf, SourceValue v, Set<String> out, Set<SourceValue> seen) {
        if (v == null || !seen.add(v)) return;
        for (AbstractInsnNode src : v.insns) {
            int idx = mn.instructions.indexOf(src);
            Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
            String desc = null;
            switch (src.getOpcode()) {
                case Opcodes.ANEWARRAY -> { String t = ((TypeInsnNode) src).desc; if (!t.startsWith("[")) out.add(t); }
                case Opcodes.CHECKCAST -> desc = ((TypeInsnNode) src).desc;
                case Opcodes.GETFIELD, Opcodes.GETSTATIC -> desc = ((FieldInsnNode) src).desc;
                case Opcodes.INVOKESTATIC, Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE, Opcodes.INVOKESPECIAL ->
                        desc = Type.getReturnType(((MethodInsnNode) src).desc).getDescriptor();
                case Opcodes.DUP -> { if (f != null) arrayComponents(mn, sf, f.getStack(f.getStackSize() - 1), out, seen); }
                case Opcodes.ALOAD -> {
                    if (f == null) break;
                    int var = ((VarInsnNode) src).var;
                    SourceValue lv = f.getLocal(var);
                    if (lv.insns.isEmpty()) {
                        int p = paramOf(mn, var);
                        if (p >= 0) desc = Type.getArgumentTypes(mn.desc)[p].getDescriptor();
                    } else for (AbstractInsnNode st : lv.insns) {
                        int si = mn.instructions.indexOf(st);
                        if (si >= 0 && sf[si] != null) arrayComponents(mn, sf, sf[si].getStack(sf[si].getStackSize() - 1), out, seen);
                    }
                }
                default -> { }
            }
            if (desc != null && desc.startsWith("[L")) out.add(desc.substring(2, desc.length() - 1));
        }
    }

    /** The cells a collection-valued stack value can be, traced through locals, DUP and CHECKCAST to its producer. */
    /** Per scanned body: a value's cells, a union over its producers, computed once per value with each producer
     *  visited once. Before this the walk through locals re-derived the same producers along every path (to depth
     *  12) — exponential in a body with many stores to one local, and measured running a scala-compiler scan out of a
     *  3 GB heap once chained calls made most of its bodies relevant. A union is order-independent, so a visited set
     *  loses nothing a path-by-path walk would have found. */
    private static final ThreadLocal<IdentityHashMap<SourceValue, List<String>>> CELLS_MEMO =
            ThreadLocal.withInitial(IdentityHashMap::new);

    /** A value's cells (memoized for the body being scanned). {@code depth} is kept for the call sites' shape only. */
    private static List<String> cells(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            SourceValue v, String self, int depth) {
        if (v == null) return new ArrayList<>();
        List<String> done = CELLS_MEMO.get().get(v);
        if (done != null) return new ArrayList<>(done);
        Set<SourceValue> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        CELLS_MEMO.get().put(v, List.of());   // in progress: a wrapper's operand that loops back to it adds nothing new
        List<String> res = new ArrayList<>(new LinkedHashSet<>(walk(c, g, cn, mn, sf, v, self, seen)));
        CELLS_MEMO.get().put(v, res);
        return new ArrayList<>(res);
    }

    private static List<String> walk(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            SourceValue v, String self, Set<SourceValue> seen) {
        if (v == null || !seen.add(v)) return new ArrayList<>();
        return cells0(c, g, cn, mn, sf, v, self, seen);
    }

    private static List<String> cells0(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            SourceValue v, String self, Set<SourceValue> seen) {
        List<String> out = new ArrayList<>();
        int depth = 0;
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
                            String ve = mn.signature == null ? null : mapValueArg(mn.signature, p);
                            if (ve != null) g.elem(cell + VALS, ve, false);
                            out.add(cell);
                        }
                    } else {
                        for (AbstractInsnNode st : lv.insns) {
                            int si = mn.instructions.indexOf(st);
                            if (si < 0 || sf[si] == null) continue;
                            Frame<SourceValue> sfr = sf[si];
                            out.addAll(walk(c, g, cn, mn, sf, sfr.getStack(sfr.getStackSize() - 1), self, seen));
                        }
                    }
                }
                case Opcodes.DUP, Opcodes.CHECKCAST -> {
                    if (f != null) out.addAll(walk(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, seen));
                }
                case Opcodes.NEW -> out.add("L:" + self + ":" + idx);
                case Opcodes.ANEWARRAY -> {
                    // R1184: an array allocation is a container cell; its declared component is an element type
                    String cell = "L:" + self + ":" + idx;
                    String comp = ((TypeInsnNode) src).desc;
                    if (!comp.startsWith("[") && c.byName.containsKey(comp)) g.elem(cell, comp, false);
                    out.add(cell);
                }
                case Opcodes.GETSTATIC, Opcodes.GETFIELD -> {
                    FieldInsnNode fi = (FieldInsnNode) src;
                    String cell = "F:" + fi.owner + "." + fi.name;
                    String e = fieldElem(c, fi);
                    if (e != null) g.elem(cell, e, false);
                    String ve = fieldValueElem(c, fi);
                    if (ve != null) g.elem(cell + VALS, ve, false);
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
                        if (tid != null) g.alias("R:" + tid, cell);
                        MethodNode tm = Candor.findMethod(c.byName.get(m.owner), m.name, m.desc);
                        String e = tm == null || tm.signature == null ? null : firstTypeArg(tm.signature, -1);
                        if (e != null) g.elem(cell, e, false);
                        String ve = tm == null || tm.signature == null ? null : mapValueArg(tm.signature, -1);
                        if (ve != null) g.elem(cell + VALS, ve, false);
                    } else if (!jdkOwner(m.owner)) {
                        // R1184: a DEPENDENCY's return — its allocation is out of sight. Its static type is all there is:
                        // a sorted type orders (as a static sorted owner does), a container interface MAY, a concrete
                        // JDK container type does not
                        String k = returnKind(Type.getReturnType(m.desc));
                        if (k != null) g.kind(cell, k.equals(SRT) || k.equals(UNSORTED) ? k : DEP);
                    } else if (m.owner.startsWith("java/util/") && f != null) {
                        Type[] at = Type.getArgumentTypes(m.desc);
                        int base = f.getStackSize() - at.length;
                        // R1184: a JDK call whose static return type is SORTED (a view, a synchronized wrapper, an empty
                        // sorted set): evidence of ordering, exactly as a static sorted owner is
                        if ("SRT".equals(returnKind(Type.getReturnType(m.desc)))) g.kind(cell, SRT);
                        if (m.name.equals("values") && at.length == 0 && base >= 1 && mapOwner(m.owner)) {
                            // R1184: a map's values() holds its VALUES
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s + VALS, cell);
                        } else if (m.name.equals("toArray") && base >= 1 && op != Opcodes.INVOKESTATIC) {
                            // R1184: a collection's toArray() holds its elements
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s, cell);
                        } else if ((m.name.equals("asList") || m.name.equals("stream") || m.name.equals("of")) && op == Opcodes.INVOKESTATIC
                                && at.length == 1 && at[0].getSort() == Type.ARRAY) {
                            // R1184: a list, or a stream, over an array holds the array's elements
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base), self, depth + 1)) g.link(s, cell);
                        } else if (m.name.equals("collect") && m.owner.equals("java/util/stream/Stream") && at.length == 1 && base >= 1) {
                            // R1184: `collect(toCollection(TreeSet::new))` — the result holds the stream's elements, ordered
                            // as the supplier's allocation orders
                            String k = collectorKind(c, cn, mn, sf, f.getStack(base));
                            if (k != null) {
                                for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s, cell);
                                g.kind(cell, k);
                            }
                        } else if ((m.name.equals("map") && m.owner.equals("java/util/stream/Stream")
                                || m.name.equals("mapToObj") && m.owner.startsWith("java/util/stream/")) && at.length == 1) {
                            // R1184: past a mapping stage the elements are the FUNCTION's results: a lambda's or a method
                            // reference's instantiated return type (a constructor reference's is exact)
                            String[] rt = functionResult(c, mn, sf, f.getStack(base));
                            if (rt != null) g.elem(cell, rt[0], rt[1] != null);
                        } else if (WRAP.contains(m.name) && at.length >= 1) {
                            // a view is the same object (its ordering too); `copyOf` is a new, unsorted one
                            boolean view = !m.name.equals("copyOf");
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base), self, depth + 1))
                                if (view) g.alias(s, cell); else g.link(s, cell);
                        } else if (KEYS.contains(m.name) && at.length == 0 && base >= 1 && mapOwner(m.owner)) {
                            // a map's key set holds its keys
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s, cell);
                        } else if ((m.name.equals("stream") || m.name.equals("parallelStream")) && at.length == 0 && base >= 1) {
                            // R1179: a stream over the collection carries its elements to `sorted()`
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s, cell);
                        } else if (m.owner.equals("java/util/stream/Stream") && STREAM_KEEP.contains(m.name) && base >= 1) {
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s, cell);
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

    /** Not a dependency: the JDK's own packages. */
    private static boolean jdkOwner(String o) {
        return o.startsWith("java/") || o.startsWith("javax/") || o.startsWith("jdk/") || o.startsWith("sun/") || o.startsWith("com/sun/");
    }

    /** R1184 — how a container of this STATIC type orders, when nothing else is known: {@link #SRT} sorted,
     *  {@link #DEP} a container interface that may be sorted, {@link #UNSORTED} a concrete JDK container, else null. */
    private static String returnKind(Type rt) {
        if (rt.getSort() != Type.OBJECT) return null;
        String n = rt.getInternalName();
        if (Candor.sortedOwner(n)) return SRT;
        if (Candor.maySortOwner(n)) return DEP;
        return isCollectionOwner(n) ? UNSORTED : null;
    }

    /** The producer instructions of a value, through locals, DUP and CHECKCAST (the stack values ASM recorded). */
    private static List<AbstractInsnNode> producers(MethodNode mn, Frame<SourceValue>[] sf, SourceValue v) {
        List<AbstractInsnNode> out = new ArrayList<>();
        Set<SourceValue> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        ArrayDeque<SourceValue> work = new ArrayDeque<>();
        if (v != null) work.add(v);
        while (!work.isEmpty() && out.size() < 16) {
            SourceValue x = work.poll();
            if (!seen.add(x)) continue;
            for (AbstractInsnNode src : x.insns) {
                int idx = mn.instructions.indexOf(src);
                Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
                int op = src.getOpcode();
                if ((op == Opcodes.DUP || op == Opcodes.CHECKCAST) && f != null) work.add(f.getStack(f.getStackSize() - 1));
                else if (op == Opcodes.ALOAD && f != null) {
                    SourceValue lv = f.getLocal(((VarInsnNode) src).var);
                    if (lv.insns.isEmpty()) out.add(src);
                    for (AbstractInsnNode st : lv.insns) {
                        int si = mn.instructions.indexOf(st);
                        if (si >= 0 && sf[si] != null) work.add(sf[si].getStack(sf[si].getStackSize() - 1));
                    }
                } else out.add(src);
            }
        }
        return out;
    }

    /** R1184 — the result type of a FUNCTION value made by a lambda or method reference: the instantiated method type's
     *  return, when it is a project class; {@code [type, "exact"]} for a constructor reference, else {@code [type, null]}.
     *  Null when any producer is something else (a field, a parameter): nothing is assumed. */
    private static String[] functionResult(AnalysisContext c, MethodNode mn, Frame<SourceValue>[] sf, SourceValue v) {
        String[] res = null;
        for (AbstractInsnNode src : producers(mn, sf, v)) {
            if (!(src instanceof InvokeDynamicInsnNode d) || d.bsmArgs.length < 3 || !(d.bsmArgs[2] instanceof Type mt)
                    || mt.getSort() != Type.METHOD) return null;
            Type rt = mt.getReturnType();
            if (rt.getSort() != Type.OBJECT || !c.byName.containsKey(rt.getInternalName())) return null;
            Handle h = d.bsmArgs[1] instanceof Handle hh ? hh : null;
            boolean exact = h != null && h.getTag() == Opcodes.H_NEWINVOKESPECIAL && h.getOwner().equals(rt.getInternalName());
            String[] r = {rt.getInternalName(), exact ? "exact" : null};
            if (res != null && !res[0].equals(r[0])) return null;
            res = r;
        }
        return res;
    }

    /** R1184 — how the container a {@code Collector} builds orders: {@code Collectors.toCollection(supplier)} by the
     *  supplier's allocation (a constructor reference, or a capture-free lambda that returns one {@code new}), the
     *  list/set collectors {@link #UNSORTED}; null when unknown. */
    static String collectorKind(AnalysisContext c, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf, SourceValue v) {
        String kind = null;
        for (AbstractInsnNode src : producers(mn, sf, v)) {
            if (!(src instanceof MethodInsnNode m) || !m.owner.equals("java/util/stream/Collectors")) return null;
            String k;
            if (m.name.equals("toList") || m.name.equals("toSet") || m.name.equals("toUnmodifiableList")
                    || m.name.equals("toUnmodifiableSet")) k = UNSORTED;
            else if (m.name.equals("toCollection")) {
                int idx = mn.instructions.indexOf(m);
                Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
                k = f == null ? null : supplierKind(c, cn, mn, sf, f.getStack(f.getStackSize() - 1));
            } else return null;
            if (k == null) return null;
            if (kind != null && !kind.equals(k)) return null;
            kind = k;
        }
        return kind;
    }

    /** R1184 — {@code Collectors.toMap(k, v, merge, TreeMap::new)} / {@code groupingBy(k, TreeMap::new, d)} (and the
     *  concurrent skip-list spellings): the key function's result type when the map factory orders naturally. */
    private static String sortedMapCollectorKey(AnalysisContext c, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf, SourceValue v) {
        String key = null;
        for (AbstractInsnNode src : producers(mn, sf, v)) {
            if (!(src instanceof MethodInsnNode m) || !m.owner.equals("java/util/stream/Collectors")) return null;
            Type[] at = Type.getArgumentTypes(m.desc);
            int fn, sup;
            if ((m.name.equals("toMap") || m.name.equals("toConcurrentMap")) && at.length == 4) { fn = 0; sup = 3; }
            else if ((m.name.equals("groupingBy") || m.name.equals("groupingByConcurrent")) && at.length == 3) { fn = 0; sup = 1; }
            else return null;
            int idx = mn.instructions.indexOf(m);
            Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
            if (f == null) return null;
            int base = f.getStackSize() - at.length;
            if (!NAT.equals(supplierKind(c, cn, mn, sf, f.getStack(base + sup)))) return null;
            String[] r = functionResult(c, mn, sf, f.getStack(base + fn));
            if (r == null) return null;
            if (key != null && !key.equals(r[0])) return null;
            key = r[0];
        }
        return key;
    }

    /** The ordering of the container a {@code Supplier} value allocates (see {@link #collectorKind}). */
    static String supplierKind(AnalysisContext c, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf, SourceValue v) {
        String kind = null;
        for (AbstractInsnNode src : producers(mn, sf, v)) {
            if (!(src instanceof InvokeDynamicInsnNode d) || d.bsmArgs.length < 2 || !(d.bsmArgs[1] instanceof Handle h)) return null;
            String k = null;
            if (h.getTag() == Opcodes.H_NEWINVOKESPECIAL && h.getDesc().equals("()V"))
                k = Candor.sortedOwner(h.getOwner()) ? NAT : isCollectionOwner(h.getOwner()) ? UNSORTED : null;
            else if (h.getOwner().equals(cn.name) && h.getDesc().startsWith("()") && d.desc.startsWith("()")) {
                // a capture-free lambda in this class: `() -> new TreeSet<>(…)`, its one allocation returned
                MethodNode lm = Candor.findMethod(cn, h.getName(), h.getDesc());
                if (lm != null) k = lambdaAllocKind(cn, lm);
            }
            if (k == null) return null;
            if (kind != null && !kind.equals(k)) return null;
            kind = k;
        }
        return kind;
    }

    private static String lambdaAllocKind(ClassNode cn, MethodNode lm) {
        try {
            Frame<SourceValue>[] lsf = new Analyzer<>(new SourceInterpreter()).analyze(cn.name, lm);
            Frame<ProvValue>[] lpf = Candor.cachedProvFrames(cn, lm);
            String kind = null;
            for (int i = 0; i < lm.instructions.size(); i++) {
                AbstractInsnNode in = lm.instructions.get(i);
                if (in.getOpcode() != Opcodes.ARETURN || lsf[i] == null) continue;
                for (AbstractInsnNode src : producers(lm, lsf, lsf[i].getStack(lsf[i].getStackSize() - 1))) {
                    if (src.getOpcode() != Opcodes.NEW) return null;
                    // its constructor call: the INVOKESPECIAL <init> on this NEW's type that follows it
                    String t = ((TypeInsnNode) src).desc;
                    String k = null;
                    for (AbstractInsnNode x = src.getNext(); x != null; x = x.getNext())
                        if (x instanceof MethodInsnNode mi && mi.getOpcode() == Opcodes.INVOKESPECIAL && mi.name.equals("<init>") && mi.owner.equals(t)) {
                            int xi = lm.instructions.indexOf(x);
                            Frame<SourceValue> xf = lsf[xi];
                            if (xf == null) return null;
                            int base = xf.getStackSize() - Type.getArgumentTypes(mi.desc).length;
                            k = Candor.sortedOwner(t) ? allocKind(mi, lpf == null ? null : lpf[xi], lm, lsf, xf, base)
                                    : isCollectionOwner(t) ? UNSORTED : null;
                            break;
                        }
                    if (k == null) return null;
                    if (kind != null && !kind.equals(k)) return null;
                    kind = k;
                }
            }
            return kind;
        } catch (Exception e) {
            return null;
        }
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
    /** R1184 — a {@code Map<K, V>} field's V. */
    private static String fieldValueElem(AnalysisContext c, FieldInsnNode fi) {
        ClassNode oc = c.byName.get(fi.owner);
        if (oc == null) return null;
        for (FieldNode fn : oc.fields)
            if (fn.name.equals(fi.name) && fn.signature != null) return typeArgOfType(fn.signature, 1, true);
        return null;
    }
    /** R1184 — a method signature's parameter {@code p} (or the return, p < 0) {@code Map<K, V>}'s V. */
    static String mapValueArg(String sig, int p) {
        String[] out = {null};
        new SignatureReader(sig).accept(new SignatureVisitor(Opcodes.ASM9) {
            int param = -1; boolean inTarget, top; int depth, nth;
            @Override public SignatureVisitor visitParameterType() { param++; inTarget = param == p; depth = 0; nth = 0; return this; }
            @Override public SignatureVisitor visitReturnType() { inTarget = p < 0; depth = 0; nth = 0; return this; }
            @Override public void visitClassType(String name) {
                if (!inTarget) return;
                if (depth == 0) top = name.startsWith("java/util/") && mapOwner(name);
                else if (depth == 1 && top && nth == 2 && out[0] == null) out[0] = name;
                depth++;
            }
            @Override public SignatureVisitor visitTypeArgument(char w) {
                if (inTarget && depth == 1) nth++;
                return w == '-' ? new SignatureVisitor(Opcodes.ASM9) { } : this;
            }
            @Override public void visitTypeArgument() { if (inTarget && depth == 1) nth++; }
            @Override public void visitEnd() { if (inTarget) depth--; }
        });
        return out[0];
    }
    static String typeArgOfType(String sig, int n, boolean mapOnly) {
        String[] out = {null};
        new SignatureReader(sig).acceptType(new SignatureVisitor(Opcodes.ASM9) {
            boolean top; int depth, nth;
            @Override public void visitClassType(String name) {
                if (depth == 0) top = name.startsWith("java/util/") && (!mapOnly || mapOwner(name));
                else if (depth == 1 && top && nth == n + 1 && out[0] == null) out[0] = name;
                depth++;
            }
            @Override public SignatureVisitor visitTypeArgument(char w) {
                if (depth == 1) nth++;
                return w == '-' ? new SignatureVisitor(Opcodes.ASM9) { } : this;
            }
            @Override public void visitTypeArgument() { if (depth == 1) nth++; }
            @Override public void visitEnd() { depth--; }
        });
        return out[0];
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
