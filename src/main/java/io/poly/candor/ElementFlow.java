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
 * <p>After the analyze loop only; reads bodies like DbHandleFlow. A map cell's elements are its KEYS ({@code put},
 * {@code keySet()}, {@code new TreeMap<>(m)}, {@code putAll}). Residuals: a map's values, an array that is not of a
 * project element type ({@code T[]} erases to {@code Object[]}), a stream past a mapping stage, a collector building
 * a sorted set, a scalar parameter added to a LIST and sorted by the caller, a declared {@code Set}/{@code Map} whose
 * allocation is out of sight (a dependency's return), and HashMap's tree bins (a bucket of more than eight colliding
 * {@code Comparable} keys runs {@code compareTo}; never modelled). Over-approximations, stated: a list of one
 * element sorts without comparing; a {@code TreeSet} copied from a {@code SortedSet} reached through a declared
 * {@code Collection} builds without comparing; a field merges every instance's container.
 */
final class ElementFlow {
    private ElementFlow() {}

    static final String EQ = ArgContract.EQUALS, HASH = ArgContract.HASHCODE, CMP = ArgContract.COMPARETO;
    /** Not a member: the cell's elements are handed to a chained dependency (R1174). */
    static final String WITNESS = "W";
    static final String NAT = "NAT", BYCMP = "CMP", UNSORTED = "UNS";
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
        /** The methods that may insert one of their parameters into a container that may be sorted, directly or
         *  through a project callee: the only callees a scalar argument's summary pass can matter for. */
        Set<String> qcand = Set.of();
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
        for (ClassNode cn : c.ALL) {
            if (!c.projectClasses.contains(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions.size() == 0 || !relevant(c, cn, mn)) continue;
                try { scan(c, g, cn, mn); } catch (Throwable e) { /* an unreadable body adds nothing */ }
            }
        }
        applySummaries(g);
        // ORDERING: along alias links only
        closeOver(g.alias, g.kinds);
        // close the one-way flow
        closeOver(g.flow, g.elems);
        for (List<String> d : g.dispatch) {
            Set<String> es = g.elems.get(d.get(1));
            if (es == null) continue;
            String key = d.get(2);
            if (key.equals(CMP) && !d.get(3).isEmpty() && !maySort(g, d.get(3), d.get(4))) continue;
            for (String te : es) {
                int tab = te.indexOf('\t');
                String t = te.substring(0, tab);
                if (DEBUG) System.err.println((key.equals(CMP) ? "R1179ELEM\t" : key.equals(WITNESS) ? "R1174CHAIN\t" : "R1166ELEM\t")
                        + d.get(0) + "\t" + key + "\t" + t + "\t" + d.get(1));
                if (key.equals(WITNESS)) {
                    if (c.byName.containsKey(t)) ArgContract.CHAIN_ELEMS.get().add(new String[] {d.get(0), t, te.endsWith("1") ? "1" : "0"});
                    continue;
                }
                ArgContract.applyResolved(c, d.get(0), key, t, te.endsWith("1"), false);
            }
        }
    }

    private static void closeOver(Map<String, Set<String>> links, Map<String, Set<String>> vals) {
        boolean changed = true; int rounds = 0;
        while (changed && rounds++ < 64) {
            changed = false;
            for (var e : links.entrySet()) {
                Set<String> s = vals.get(e.getKey());
                if (s == null || s.isEmpty()) continue;
                for (String d : e.getValue()) changed |= vals.computeIfAbsent(d, k -> new HashSet<>()).addAll(s);
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
            if (k == null || k.isEmpty()) { if (Candor.sortedOwner(owner)) return true; }
            else if (k.contains(NAT)) return true;
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
                    // a scalar argument: only what the callee does with the parameter AS one element
                    for (List<String> d : byCell.getOrDefault("Q" + pc.substring(1), List.of()))
                        if (d.get(0).equals(callee)) g.dispatch(p[0], p[1], d.get(2), substitute(g, d.get(3), callee, p[4]), d.get(4));
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
            }
        } while (g.grew && rounds++ < 32);
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
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> work = new ArrayDeque<>(List.of(pc));
        while (!work.isEmpty()) {
            String x = work.poll();
            if (!seen.add(x)) continue;
            for (List<String> d : byCell.getOrDefault(x, List.of())) if (d.get(0).equals(callee)) keys.add(d);
            for (String y : g.flow.getOrDefault(x, Set.of())) {
                if (y.startsWith("F:")) { if (y.startsWith(ownField)) fields.add(y); }
                else if (y.equals(ret)) returns = true;
                else if (y.indexOf(own) == 2) work.add(y);   // L:/S:/P:/A: cells of the callee itself
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
        return new Object[] {keys, fields, returns, aliasFields, aliasRet};
    }

    /** See {@link Graph#qcand}: the bodies with a one-element key operation on a container that may be sorted, closed
     *  backwards over the call graph. Computed before the scan so a scalar argument records a summary pass only where
     *  one can apply — every object argument of every project call was the scan's largest allocation (measured). */
    private static Set<String> oneElementCandidates(AnalysisContext c) {
        Set<String> out = new HashSet<>();
        for (ClassNode cn : c.ALL) {
            if (!c.projectClasses.contains(cn.name)) continue;
            for (MethodNode mn : cn.methods)
                for (AbstractInsnNode in : mn.instructions)
                    if (in instanceof MethodInsnNode m && m.getOpcode() != Opcodes.INVOKESTATIC
                            && !Candor.isCompareToSink(m.owner, m.name) && Candor.mayCompareArg0(m.owner, m.name, m.desc, null)) {
                        out.add(Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc));
                        break;
                    }
        }
        Map<String, List<String>> callers = new HashMap<>();
        for (var e : c.edges.entrySet()) for (String y : e.getValue()) callers.computeIfAbsent(y, k -> new ArrayList<>()).add(e.getKey());
        ArrayDeque<String> work = new ArrayDeque<>(out);
        while (!work.isEmpty()) for (String x : callers.getOrDefault(work.poll(), List.of())) if (out.add(x)) work.add(x);
        return out;
    }

    private static boolean relevant(AnalysisContext c, ClassNode cn, MethodNode mn) {
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
            if (in instanceof MethodInsnNode m && c.projectClasses.contains(m.owner) && m.desc.contains("Ljava/util/")) return true;
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
            if ((op == Opcodes.PUTFIELD || op == Opcodes.PUTSTATIC) && ((FieldInsnNode) in).desc.startsWith("L")) {
                FieldInsnNode fi = (FieldInsnNode) in;
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, 0))
                    g.alias(cell, "F:" + fi.owner + "." + fi.name);
                continue;
            }
            if (op == Opcodes.ARETURN) {
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, 0)) g.alias(cell, "R:" + id);
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
                    if (at[j].getSort() != Type.OBJECT) continue;
                    if (callees == null) callees = ArgContract.projectCallees(c, m, p);
                    if (callees.isEmpty()) break;
                    List<String> argCells = cells(c, g, cn, mn, sf, f.getStack(base + j), self, 0);
                    g.siteArgs.computeIfAbsent(site, k -> new HashMap<>()).put(j, argCells);
                    for (String cell : argCells)
                        for (String callee : callees) g.passes.add(new String[] {id, cell, callee, String.valueOf(j), site, ""});
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
                String k = allocKind(m, p);
                if (k != null) for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.kind(cell, k);
            }
            // element ADDED
            if (inst && ADD.contains(m.name) && n >= 1 && at[n - 1].getSort() == Type.OBJECT && p != null) {
                ProvValue v = Candor.callArg(p, m, n - 1);
                String t = v == null || v.nullConst ? null : ArgContract.typeOf(c, v);
                if (t != null) for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.elem(cell, t, v.newType != null);
            }
            // a map's KEY put (a map cell's elements are its keys, as a declared `Map<K, V>` already reads them)
            if (inst && (m.name.equals("put") || m.name.equals("putIfAbsent")) && n == 2 && mapOwner(m.owner)
                    && at[0].getSort() == Type.OBJECT && p != null) {
                ProvValue v = Candor.callArg(p, m, 0);
                String t = v == null || v.nullConst ? null : ArgContract.typeOf(c, v);
                if (t != null) for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.elem(cell, t, v.newType != null);
            }
            // elements COPIED in
            if (inst && (m.name.equals("addAll") || m.name.equals("putAll") || m.name.equals("<init>")) && n >= 1 && at[n - 1].getSort() == Type.OBJECT
                    && at[n - 1].getInternalName().startsWith("java/util/")) {
                List<String> dst = cells(c, g, cn, mn, sf, recv, self, 0);
                for (String s : cells(c, g, cn, mn, sf, f.getStack(base + n - 1), self, 0)) for (String d : dst) g.link(s, d);
                if (m.name.equals("<init>") && hashed(m.owner))
                    for (String d : dst) { g.dispatch(id, d, HASH); g.dispatch(id, d, EQ); }
                if ((m.name.equals("addAll") || m.name.equals("putAll")) && hashed(m.owner))
                    for (String d : dst) { g.dispatch(id, d, HASH); g.dispatch(id, d, EQ); }
                // R1179: a SORTED container built from, or filled with, a collection compares the incoming elements
                // under natural ordering; a copy of a SortedSet/SortedMap/PriorityQueue keeps ITS ordering and
                // builds without comparing (TreeSet(SortedSet), executed: no compareTo)
                if (m.name.equals("<init>") && Candor.sortedOwner(m.owner) && NAT.equals(allocKind(m, p)))
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
                        g.dispatch(id, cell, HASH); g.dispatch(id, cell, EQ);
                    }
            }
            if (inst && (m.name.equals("removeAll") || m.name.equals("retainAll")) && n == 1) {
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) {
                    g.dispatch(id, cell, EQ); g.dispatch(id, cell, HASH);
                }
                // a hashed receiver's removeAll may iterate the ARGUMENT and remove(e): its elements are hashed
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                    g.dispatch(id, cell, EQ);
                    if (!listOwner(m.owner)) g.dispatch(id, cell, HASH);
                }
            }
            // containsAll runs this.contains(e) for each ARGUMENT element: e.equals(..), and e.hashCode() when the
            // receiver is hashed. The receiver's own elements are only the arguments of those calls (executed).
            if (inst && m.name.equals("containsAll") && n == 1)
                for (String cell : cells(c, g, cn, mn, sf, f.getStack(base), self, 0)) {
                    g.dispatch(id, cell, EQ);
                    if (!listOwner(m.owner)) g.dispatch(id, cell, HASH);
                }
        }
    }

    /** How a collection allocation orders: natural ({@link #NAT}), by a comparator ({@link #BYCMP}), unsorted, or
     *  null when it keeps a source's ordering ({@code new TreeSet<>(SortedSet)}) and so is not known here. */
    static String allocKind(MethodInsnNode m, Frame<ProvValue> p) {
        if (!Candor.sortedOwner(m.owner)) return UNSORTED;
        Type[] at = Type.getArgumentTypes(m.desc);
        for (int k = 0; k < at.length; k++) {
            if (at[k].getSort() != Type.OBJECT) continue;
            String a = at[k].getInternalName();
            if (a.equals("java/util/Comparator")) {
                ProvValue v = p == null ? null : Candor.callArg(p, m, k);
                return v != null && v.nullConst ? NAT : BYCMP;
            }
            if (a.equals("java/util/SortedSet") || a.equals("java/util/SortedMap") || a.equals("java/util/PriorityQueue")
                    || a.equals("java/util/concurrent/PriorityBlockingQueue")) return null;
        }
        return NAT;
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
        boolean natural = ck < 0 || nullCmp(p, m, ck);
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
            return;
        }
        if (o.equals("java/util/stream/Stream")) {
            if (name.equals("sorted") && n == 0 && recv != null)
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
                        if (tid != null) g.alias("R:" + tid, cell);
                        String e = returnElem(c, m);
                        if (e != null) g.elem(cell, e, false);
                    } else if (m.owner.startsWith("java/util/") && f != null) {
                        Type[] at = Type.getArgumentTypes(m.desc);
                        int base = f.getStackSize() - at.length;
                        if (WRAP.contains(m.name) && at.length >= 1) {
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
