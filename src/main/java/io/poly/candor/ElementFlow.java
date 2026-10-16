package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;

import io.poly.candor.Interp.ProvValue;
import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;
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
 * HashMap-backed structure's tree bins (a chained dependency's key type too, R1191, read off its hierarchy sidecar).
 * Residuals: {@code flatMap}; a scalar a callee stores into its own FIELD container (a field merges every instance, so
 * it is not followed); a collection reached through a field the dependency fills; a function value that is not a
 * lambda or method reference.
 *
 * <p><b>SOUNDNESS R1188/R1189 — what a COMPARATOR runs.</b> A {@code Comparator.comparing(f)} (and
 * {@code thenComparing(f)}, {@code comparing(f, naturalOrder())}, {@code reversed()}/{@code nullsFirst} over one) runs the
 * KEY's {@code compareTo}; a comparator OBJECT ({@code new RevCmp()}) runs its own {@code compare}. Both are facts of
 * the comparator VALUE ({@link Graph#cmpk}), carried along the alias links (a field, a return), into a sorted container
 * built with it, through a composing combinator, and to a callee's comparator or container parameter as a per-call
 * SUMMARY (never merged into the callee). They are charged only where the comparator RUNS — an ordering call handed it,
 * or a key operation / {@code addAll} on a container that holds it — each executed on JDK 21. A comparator made and never
 * used charges nothing. Residuals: {@code Map.Entry.comparingByKey/Value()} (the key is the entry's; the sort site's
 * {@code callback:} disclosure stays); a key function that is not a lambda or method reference; a comparator whose
 * value comes from a dependency's return or a field no store in the scan traces.
 *
 * <p><b>SOUNDNESS R1195 — the residuals R1184/R1188/R1189 named, each executed on JDK 21.</b> A stream with no
 * collection behind it ({@code Stream.iterate/generate/concat}, a {@code Stream.Builder}, {@code StreamSupport} over a
 * spliterator) holds its seed's and its functions' result types. A {@code flatMap} stage holds the elements of the
 * streams its function returns: a lambda's return cell flows to it, and its element parameter is bound to the incoming
 * elements' OWN elements, a twin cell ({@link #NEST}) that a {@code Collection<Collection<E>>} signature or an
 * {@code outer.add(inner)} fills. A COMPARATOR's naturalness is a fact of its value ({@link #CNAT}), carried through a
 * return, a field and a combinator to the container built with it, which then orders naturally (charged); a comparator
 * out of sight ({@link #CDEP}: a dependency's return or field, a project field nothing in the scan stores) makes the
 * container's key operations DISCLOSE {@code callback:java.util.Comparator.compare}, as {@code l.sort(depCmp)} already
 * does, and with a comparator PARAMETER ({@link #CPAR}) the elements' {@code compareTo} is disclosed, never charged. A
 * container in a FIELD is modelled per RECEIVER — a field twin {@code <cell>#<owner.field>} beside the global field cell
 * — so {@code b.put(x); b.order();} charges the caller with {@code x}'s compareTo and a second instance of the same class
 * never sees it (the instance merge is what smeared stanford-corenlp under R1184); a static field is one object and
 * takes a scalar directly. A callee's own EXACT insertions into a container its caller handed it (or into a field of
 * one) flow BACK to the caller's argument ({@link Graph#back}); a declared type never does. Residuals: a field of a
 * field (one twin level; deeper falls back to the merging field cell); {@code equals}/{@code hashCode} through a callee's
 * field twin (only {@code compareTo} summaries are applied); a callee's non-exact insertion; a comparator a caller
 * outside the scan hands to a parameter.
 *
 * <p><b>SOUNDNESS R1198 — the residuals R1195 named, each executed on JDK 21.</b> A field twin is a PATH of up to
 * {@link #MAX_TWIN} fields ({@code <o>#Outer.bag#Bag.items}): an object held in a field keeps its containers per
 * receiver. No twin is taken on an INSTANCE field's global {@code F:} cell — that cell is every object's field, and a twin
 * on it charged {@code b.bag.order()} with another instance's elements (R1195's model did, on main only); a static field
 * keeps its twins. A twin summary applies EVERY key ({@code equals}/{@code hashCode} too). A callee's own inserts flow
 * back to its caller whatever their precision ({@code "type\t2"}, {@link Graph#elemV}); a declared signature type and a
 * parameter's declared type never do. Two cells that are the same OBJECT at one site — a getter's result, an argument a
 * callee stores into another argument's field — share their field twins ({@link #pairTwins}). A comparator CAPTURED by a
 * {@code toCollection} supplier lambda orders the collected container ({@link #capturedComparatorCollect}). A comparator
 * PARAMETER whose caller is outside the scan was already disclosed (premise correction). Residuals: an element declared
 * as a JDK interface ({@code Comparable}) names no body, in either direction; an alias through a callee's return cell or
 * an instance field's global cell is not paired (both are shared by every caller or instance).
 *
 * <p><b>SOUNDNESS R1199 — A FLOOR, NOT A SEVENTH SPECIAL CASE.</b> R1174 to R1198 built the element set of a sorted cell
 * positively, by tracing inserts and pairing aliases, and each row's residual was a shape the tracing missed: an empty
 * or uninformative set read as "nothing runs". The floor: an ordering site a body makes ITSELF whose element set does not
 * bound what it orders — nothing traced, or a value known only as {@code Object}/{@code Comparable} (a signature's bound,
 * an insert's static type, a scalar parameter so declared) — is a {@code Comparable.compareTo} dispatch, DISCLOSED after
 * the fixpoint where some project implementor carries a concrete effect the body does not already report (reason
 * {@code dispatch:java.lang.Comparable.compareTo}); callers inherit it along the call edge. Field TWIN cells are skipped:
 * the read that yields a twin yields the field's global cell too, which is the bound. The pairing model stays, as
 * PRECISION (an exact type is charged, not disclosed); soundness for an untraced set no longer depends on it. Two
 * resolutions ride beside the floor: a callee that RETURNS its container argument is one object with it at that site, so
 * the caller's inserts into the result flow back ({@link Graph#siteBack}; never into a shared return cell or an instance
 * field's global cell); and a generic project method's container return is instantiated by its receiver's static type
 * ({@code Set<V> getAllVertices()} on a {@code DirectedMultiGraph<SceneGraphNode, ..>} field). Residual: the
 * {@code equals}/{@code hashCode} twin (an element known only as {@code Object} hashed, or a container aliased through a
 * callee's return and hashed) is silent and not floored here — its population is every hashed {@code Object}.
 *
 * <p><b>SOUNDNESS R1183.</b> {@code TreeSet}/{@code TreeMap} key operations are charged by
 * {@link Candor#contractReentry} with the element's compareTo; the charge is applied here, and WITHHELD only where every
 * cell the receiver can be is an allocation in the same body whose comparator is a lambda or method reference (other
 * than {@code compareTo}) made in that body ({@link #CMPX}), every producer traced ({@link #traced}). A comparator
 * OBJECT ({@code new ReverseComparator()}) or one stored in a field keeps the charge: its {@code compare} may run the
 * elements' {@code compareTo}. (Since R1189 the object's {@code compare} is ALSO edged where it reaches the receiver;
 * the element charge is not narrowed by that — narrowing it would be a removal, priced on its own.)
 *
 * <p>After the analyze loop only; reads bodies like DbHandleFlow. A map cell's elements are its KEYS ({@code put},
 * {@code keySet()}, {@code new TreeMap<>(m)}, {@code putAll}). Over-approximations, stated: a list of one element
 * sorts without comparing; a {@code TreeSet} copied from a {@code SortedSet} reached through a declared
 * {@code Collection} builds without comparing; {@code sorted().count()} on a sized stream skips the sort on JDK 9+ (R1190 — KEPT: it compares on JDK 8, executed); a
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
    /** SOUNDNESS R1195 — the twin cell holding the ELEMENTS OF a cell's elements (a {@code List<List<E>>}'s E), read by
     *  a {@code flatMap} stage; it travels every flow link, as {@link #VALS} does. */
    static final String NEST = "|e";
    private static final String[] TWINS = {VALS, NEST};
    /** SOUNDNESS R1198 — the deepest field path a per-receiver twin follows ({@code o.a.b.items} is three). */
    static final int MAX_TWIN = 3;
    /** SOUNDNESS R1195 — comparator facts ({@link Graph#cmpk}) beyond R1188/R1189's: {@link #CNAT} the comparator is
     *  natural ordering (it runs the ELEMENTS' {@code compareTo}) however far it travelled — a project method's return,
     *  a field, a combinator over one; {@link #CDEP} its value is OUT OF SIGHT (a dependency's return or field, or a
     *  project field no store in the scan writes), so neither what it runs nor whether it is natural is known;
     *  {@link #CPAR} it is a method's own comparator PARAMETER (a caller outside the scan may pass natural ordering). */
    static final String CNAT = "N", CDEP = "UD", CPAR = "UP";
    private static final String CMP_DESC = "Ljava/util/Comparator;";
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
        /** SOUNDNESS R1198 — an element a body INSERTED (a value's own static type, not a type a signature declares):
         *  {@code "type\t2"} when not exact. Read as non-exact everywhere; only {@link #backFlow} tells it from a
         *  declared {@code "type\t0"}, because a callee's insert reaches its caller's container and a callee's
         *  signature does not. {@code Object} says nothing and stays declared. */
        void elemV(String cell, String t, boolean exact) {
            if (cell == null || t == null) return;
            elems.computeIfAbsent(cell, k -> new HashSet<>()).add(t + "\t" + (exact ? 1 : t.equals("java/lang/Object") ? 0 : 2));
        }
        void link(String src, String dst) {
            if (src != null && dst != null && !src.equals(dst)) grew |= flow.computeIfAbsent(src, k -> new HashSet<>()).add(dst);
        }
        void alias(String src, String dst) {
            link(src, dst);
            if (src != null && dst != null && !src.equals(dst)) alias.computeIfAbsent(src, k -> new HashSet<>()).add(dst);
        }
        void kind(String cell, String k) { kinds.computeIfAbsent(cell, x -> new HashSet<>()).add(k); }
        /** R1195 — the twin of {@code base} for the field {@code fkey} ({@code fkey} may itself be a path
         *  {@code a#b}). SOUNDNESS R1198: a PATH of up to {@link #MAX_TWIN} fields, so an object held in a field of an
         *  object keeps its own containers per receiver ({@code o.bag.items}: {@code <o>#Outer.bag#Bag.items}). Null on
         *  an INSTANCE field's global {@code F:} cell: that cell stands for the field of EVERY object of the class, so a
         *  twin on it pours every instance's elements into every other's (measured: {@code a.bag.put(eff); b.bag.order()}
         *  charged {@code b}'s sort with {@code a}'s element) — the merge the per-receiver model exists to avoid. A static
         *  field is one object and keeps its twins. */
        String twin(String base, String fkey) {
            if (base == null || fkey == null || base.indexOf('|') >= 0 || base.equals("?")) return null;
            int h = base.indexOf('#');
            String root = h < 0 ? base : base.substring(0, h);
            if (root.startsWith("F:") && !statics.contains(root)) return null;
            String path = (h < 0 ? "" : base.substring(h)) + "#" + fkey;
            int depth = 0;
            for (int k = 0; k < path.length(); k++) if (path.charAt(k) == '#') depth++;
            if (depth > MAX_TWIN) return null;
            if (root.startsWith("P:")) twins.computeIfAbsent(root, x -> new TreeSet<>()).add(path);
            return root + path;
        }
        /** SOUNDNESS R1199 — a one-element cell ({@code Q:}, a body's own scalar parameter) -> the parameter's erased
         *  declared type: the only bound on it this body has. */
        final Map<String, String> qDecl = new HashMap<>();
        /** SOUNDNESS R1198 — cells that are one OBJECT at one site (see {@link #pairTwins}). */
        final Set<List<String>> pairs = new LinkedHashSet<>();
        void pair(String a, String b) {
            if (a == null || b == null || a.equals(b) || a.indexOf('|') >= 0 || b.indexOf('|') >= 0) return;
            if (a.startsWith("R:") || b.startsWith("R:") || a.startsWith("Q:") || b.startsWith("Q:") || a.startsWith("V:") || b.startsWith("V:")) return;
            if (a.startsWith("F:") && !statics.contains(a.indexOf('#') < 0 ? a : a.substring(0, a.indexOf('#')))) return;
            if (b.startsWith("F:") && !statics.contains(b.indexOf('#') < 0 ? b : b.substring(0, b.indexOf('#')))) return;
            pairs.add(List.of(a, b));
        }
        /** SOUNDNESS R1199 — the callee RETURNS the argument object itself ({@code List<T> id(List<T> l) { return l; }}):
         *  at this site the call's result and the caller's argument are ONE container, so what the caller inserts into
         *  the result is in its argument too. Elements flow back from the site's own result cell only into a cell
         *  specific to this caller (never a callee's shared return cell, a scalar's, or an instance field's global
         *  cell, which would hand this site's elements to every other caller or instance). */
        void siteBack(String site, String arg) {
            if (site == null || arg == null || site.equals(arg) || arg.indexOf('|') >= 0) return;
            if (arg.startsWith("R:") || arg.startsWith("Q:") || arg.startsWith("V:") || arg.equals(UNK)) return;
            if (arg.startsWith("F:") && !statics.contains(arg.indexOf('#') < 0 ? arg : arg.substring(0, arg.indexOf('#')))) return;
            if (DEBUG) System.err.println("R1199SITEBACK\t" + site + "\t" + arg);
            link(site, arg);
        }
        void back(String src, String dst) {
            if (src != null && dst != null && !src.equals(dst)) back.computeIfAbsent(src, x -> new HashSet<>()).add(dst);
        }
        /** SOUNDNESS R1188/R1189 — what a COMPARATOR value runs, per cell: {@code "K:<type>\t<exact>"} (a
         *  {@code Comparator.comparing(f)} family member runs the KEY's {@code compareTo}) and {@code "C:<class>"} (a
         *  comparator OBJECT, whose {@code compare} runs). Kept apart from {@link #kinds}: these never decide whether a
         *  receiver is naturally ordered, they only say which bodies its comparator runs. */
        final Map<String, Set<String>> cmpk = new HashMap<>();
        /** src -> dst: dst's comparator includes src's (a container built with a comparator, a composed comparator, a
         *  comparator argument bound to a callee's parameter). Comparator facts flow here and along {@link #alias}. */
        final Map<String, Set<String>> cmpl = new HashMap<>();
        /** {caller, cells}: a site that RUNS the comparator of those cells — an ordering call handed it, or a key
         *  operation on a container built with it. */
        final Set<List<String>> cmpSites = new LinkedHashSet<>();
        void cmpk(String cell, String k) { if (cell != null) cmpk.computeIfAbsent(cell, x -> new HashSet<>()).add(k); }
        void cmpLink(String src, String dst) {
            if (src != null && dst != null && !src.equals(dst)) cmpl.computeIfAbsent(src, x -> new HashSet<>()).add(dst);
        }
        /** SOUNDNESS R1195 — FIELD TWINS: {@code <cell>#<owner.field>} is the container held in field {@code field} of
         *  the OBJECT {@code cell} stands for — per receiver, never merged across instances (a global {@code F:} cell
         *  does that). Indexed by base cell for a {@code P:} base, the twins a summary carries back to the caller. */
        final Map<String, Set<String>> twins = new HashMap<>();
        /** R1195 — BACK-FLOW, callee -> caller: what a callee itself inserted into a container its caller handed it
         *  (a parameter, or a field of one, or of the receiver). EXACT element types only (a {@code new T} the callee
         *  made): a callee's declared parameter type and every other caller's values never travel this way. */
        final Map<String, Set<String>> back = new HashMap<>();
        /** R1195 — static field cells: one object each, so a scalar a callee stores into one is the field's element. */
        final Set<String> statics = new HashSet<>();
        final Map<String, Boolean> fieldClassMemo = new HashMap<>();
        /** R1195 — project comparator FIELDS read ({@code F:} cell -> declaring owner.name) and written in the scan. */
        final Map<String, String> cmpFieldReads = new HashMap<>();
        final Set<String> fieldStores = new HashSet<>();
        /** {caller, arg cells, callee, j}: a comparator handed to a project callee's parameter j. */
        final Set<List<String>> cmpPasses = new LinkedHashSet<>();
        void cmpSite(String caller, List<String> cells) { if (!cells.isEmpty()) cmpSites.add(List.of(caller, String.join(" ", cells))); }
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
        // R1199: the ordering sites each body makes ITSELF (a summary's copy at a caller is not one: the callee's own
        // disclosure reaches its callers along the call edge, as every other effect of the callee does)
        Set<List<String>> own = new HashSet<>(g.dispatch);
        applySummaries(g);
        pairTwins(g);
        comparatorKinds(c, g);
        // ORDERING: along alias links only
        closeOver(g.alias, g.kinds, false);
        // close the one-way flow (a map's VALUES twin travels every link its keys do)
        closeOver(g.flow, g.elems, true);
        backFlow(g);
        for (List<String> d : g.dispatch) {
            Set<String> es = g.elems.get(d.get(1));
            String key = d.get(2);
            if (es == null && !key.equals(CMP)) continue;
            boolean disclose = false;
            if (key.equals(CMP) && !d.get(3).isEmpty() && !maySort(g, d.get(3), d.get(4))) {
                // R1184: a receiver whose allocation is OUT OF SIGHT (a dependency's `Set`/`Map` return) may be the
                // dependency's TreeSet: disclosed where the element's compareTo is effectful, never charged
                if (!outOfSight(g, d.get(3))) continue;
                disclose = true;
            }
            if (key.equals(CMP) && own.contains(d) && d.get(1).indexOf('#') < 0 && untraced(d.get(1).startsWith("Q:") ? qBound(g, d.get(1)) : es)) {
                // SOUNDNESS R1199 — the elements this site ORDERS name no body: none traced, or only Object/Comparable.
                // They are Comparable (the sort casts them), so their compareTo is a Comparable dispatch, resolved by
                // ArgContract's own rule for a java.* declared type: disclosed where some implementor carries a
                // concrete effect the caller does not already report, never charged and never silent. Only a site the body
                // makes itself (a caller inherits it along the call edge), and not on a field TWIN: the read that gives a
                // twin gives the field's global cell too, which holds every insert in the scan and the declared bound of
                // every parameter stored there, so it is the bound; a twin is a per-receiver summary for callers.
                if (DEBUG) System.err.println("R1199UNTRACED\t" + d.get(0) + "\t" + d.get(1) + "\t" + (es == null ? "-" : String.join(",", es)));
                ArgContract.discloseComparable(d.get(0));
                if (es == null) continue;
            }
            if (es == null) continue;
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
        comparatorSites(c, g);
    }

    /** SOUNDNESS R1188/R1189 — the bodies a comparator runs, charged where it RUNS: an ordering call handed the
     *  comparator, or a key operation on a container built with it (positive evidence: the comparator fact reached
     *  that receiver or argument along an alias, a field, a return or a comparator parameter). A
     *  {@code Comparator.comparing(f)} runs {@code f}'s result's {@code compareTo}, resolved as an element's is; a
     *  comparator OBJECT runs its own {@code compare} (executed on JDK 21: {@code new TreeSet<>(new RevCmp())}
     *  then {@code add}/{@code addAll}, a {@code PriorityQueue}, a skip list). */
    private static void comparatorSites(AnalysisContext c, Graph g) {
        if (g.cmpSites.isEmpty() || g.cmpk.isEmpty()) return;
        Map<String, Set<String>> links = comparatorLinks(g);
        closeOver(links, g.cmpk, false);
        // a callee's comparator PARAMETER runs when it reaches one of the callee's own sites, or is handed on to a
        // parameter that runs (to a fixpoint); each call passing a comparator there runs the CALLER's comparator
        Map<String, Set<String>> sitesBy = new HashMap<>();
        for (List<String> s : g.cmpSites) sitesBy.computeIfAbsent(s.get(0), k -> new HashSet<>()).addAll(Arrays.asList(s.get(1).split(" ")));
        Set<String> runs = new HashSet<>();
        Map<String, Set<String>> reachMemo = new HashMap<>();
        boolean grew = true; int rounds = 0;
        while (grew && rounds++ < 16) {
            grew = false;
            for (List<String> p : g.cmpPasses) {
                String pc = "P:M:" + p.get(2) + ":" + p.get(3);
                if (runs.contains(pc)) continue;
                Set<String> reach = reachMemo.computeIfAbsent(pc, k -> reach(links, k));
                boolean r = false;
                for (String x : sitesBy.getOrDefault(p.get(2), Set.of())) if (reach.contains(x)) { r = true; break; }
                if (!r) for (List<String> q : g.cmpPasses)
                    if (q.get(0).equals(p.get(2)) && runs.contains("P:M:" + q.get(2) + ":" + q.get(3)))
                        for (String a : q.get(1).split(" ")) if (reach.contains(a)) { r = true; break; }
                if (r) { runs.add(pc); grew = true; }
            }
        }
        for (List<String> p : g.cmpPasses)
            if (runs.contains("P:M:" + p.get(2) + ":" + p.get(3))) g.cmpSites.add(List.of(p.get(0), p.get(1)));
        for (List<String> s : g.cmpSites) {
            String id = s.get(0);
            Set<String> ks = new TreeSet<>();
            for (String cell : s.get(1).split(" ")) ks.addAll(g.cmpk.getOrDefault(cell, Set.of()));
            for (String k : ks) {
                if (DEBUG) System.err.println("R1188SITE\t" + id + "\t" + k);
                if (k.equals(CDEP)) {
                    // R1195: a comparator OUT OF SIGHT runs here — what its compare does is not known: disclosed as an
                    // ordering call handed an unresolved comparator already is (`l.sort(depCmp)`)
                    if (DEBUG) System.err.println("R1195CDEP\t" + id);
                    c.direct.computeIfAbsent(id, x -> EffectSet.empty()).add(Effect.UNKNOWN);
                    c.unknownWhy.computeIfAbsent(id, x -> new TreeSet<>()).add(UnknownReason.parse("callback:java.util.Comparator.compare"));
                } else if (k.startsWith("K:")) {
                    int tab = k.indexOf('\t');
                    String t = k.substring(2, tab);
                    boolean exact = k.endsWith("\t1");
                    if (c.byName.containsKey(t)) ArgContract.applyResolved(c, id, CMP, t, exact, false);
                    else Candor.reentryEdgeByType(id, t, Candor.C_COMPARETO, true);   // a chained dependency's key type
                } else if (k.startsWith("C:")) {
                    String cls = k.substring(2);
                    if (c.byName.containsKey(cls)) {
                        String b = ArgContract.jvmTarget(c, cls, "compare", "(Ljava/lang/Object;Ljava/lang/Object;)I");
                        Set<String> out = c.edges.get(id);
                        if (out == null) continue;
                        if (b != null) out.add(b); else out.addAll(Candor.functionalSamSurface(cls));
                    } else for (DepFn d : Candor.depFnsInvokedByHandoff(cls, Set.of("compare"))) Candor.inheritDepFn(id, d);
                }
            }
        }
    }

    /** SOUNDNESS R1195 — what a container's COMPARATOR says about its ordering, wherever the comparator came from. The
     *  comparator facts are closed along the alias and comparator links first (a project method's return, a field, a
     *  combinator, the container built with it), then: a container whose comparator may be natural ordering
     *  ({@link #CNAT}) orders NATURALLY ({@link #NAT}, positive evidence, charged); one whose comparator is out of sight
     *  or a parameter is treated as a container out of sight ({@link #DEP}: its elements' compareTo DISCLOSED where it is
     *  effectful, never charged). Executed on JDK 21: a {@code PriorityQueue}/{@code TreeSet}/skip list built with a
     *  {@code naturalOrder()} returned by a method or read from a field runs the elements' {@code compareTo}. */
    private static void comparatorKinds(AnalysisContext c, Graph g) {
        // a project comparator field that no store in this scan writes (injected, reflective) is out of sight
        for (var e : g.cmpFieldReads.entrySet()) if (!g.fieldStores.contains(e.getValue())) g.cmpk(e.getKey(), CDEP);
        if (g.cmpk.isEmpty()) return;
        closeOver(comparatorLinks(g), g.cmpk, false);
        for (var e : g.cmpk.entrySet()) {
            Set<String> k = e.getValue();
            if (k.contains(CNAT)) g.kind(e.getKey(), NAT);
            if (k.contains(CDEP) || k.contains(CPAR)) g.kind(e.getKey(), DEP);
            if (DEBUG && (k.contains(CNAT) || k.contains(CDEP) || k.contains(CPAR)) && e.getKey().startsWith("L:"))
                System.err.println("R1195CKIND\t" + e.getKey() + "\t" + k);
        }
    }
    private static Map<String, Set<String>> comparatorLinks(Graph g) {
        Map<String, Set<String>> links = new HashMap<>();
        for (var e : g.alias.entrySet()) links.computeIfAbsent(e.getKey(), k -> new HashSet<>()).addAll(e.getValue());
        for (var e : g.cmpl.entrySet()) links.computeIfAbsent(e.getKey(), k -> new HashSet<>()).addAll(e.getValue());
        return links;
    }
    /** SOUNDNESS R1195 — close the BACK-FLOW links ({@link Graph#back}) with the forward flow: only EXACT element types
     *  (a {@code new T}) travel back to the caller, so a callee's declared parameter type (a {@code List<Comparable>})
     *  is never poured into every caller's container. */
    private static void backFlow(Graph g) {
        if (g.back.isEmpty()) return;
        boolean changed = true; int rounds = 0;
        while (changed && rounds++ < 16) {
            changed = false;
            for (var e : g.back.entrySet()) {
                Set<String> s = g.elems.get(e.getKey());
                if (s == null || s.isEmpty()) continue;
                List<String> ex = new ArrayList<>();
                for (String t : s) if (t.endsWith("\t1") || t.endsWith("\t2")) ex.add(t);
                if (ex.isEmpty()) continue;
                for (String d : e.getValue()) {
                    boolean a = g.elems.computeIfAbsent(d, k -> new HashSet<>()).addAll(ex);
                    if (a && DEBUG) System.err.println("R1195BACK\t" + e.getKey() + "\t" + d + "\t" + ex);
                    if (a && DEBUG && ex.stream().anyMatch(t -> t.endsWith("\t2"))) System.err.println("R1198BACK\t" + e.getKey() + "\t" + d);
                    changed |= a;
                }
            }
            if (changed) closeOver(g.flow, g.elems, true);
        }
    }

    /** R1195 — a container-typed field: the only ones given per-receiver twins. */
    private static boolean containerField(String desc) { return desc.startsWith("Ljava/util/") || desc.startsWith("[L"); }
    /** R1195 — whether project class {@code cls} (or a superclass) declares a container field: a receiver pass to one
     *  of its methods can matter only then. SOUNDNESS R1198: or an instance field holding a project object that does,
     *  up to {@link #MAX_TWIN} fields deep (an {@code Outer} whose {@code bag} holds the list). */
    private static boolean fieldClass(AnalysisContext c, Graph g, String cls) {
        Boolean m = g.fieldClassMemo.get(cls);
        if (m != null) return m;
        boolean r = fieldClass(c, cls, 1, new HashSet<>());
        g.fieldClassMemo.put(cls, r);
        return r;
    }
    private static boolean fieldClass(AnalysisContext c, String cls, int depth, Set<String> seen) {
        if (!seen.add(cls)) return false;
        for (String o = cls; o != null; ) {
            ClassNode cn = c.byName.get(o);
            if (cn == null) break;
            for (FieldNode fn : cn.fields) {
                if ((fn.access & Opcodes.ACC_STATIC) != 0) continue;
                if (containerField(fn.desc)) return true;
                if (depth < MAX_TWIN && fn.desc.startsWith("L") && fn.desc.endsWith(";")) {
                    String t = fn.desc.substring(1, fn.desc.length() - 1);
                    if (c.projectClasses.contains(t) && fieldClass(c, t, depth + 1, seen)) return true;
                }
            }
            o = cn.superName;
        }
        return false;
    }
    /** R1198 — a field given per-receiver twins: a container, or a project object whose class holds one. */
    private static boolean twinField(AnalysisContext c, Graph g, String desc) {
        if (containerField(desc)) return true;
        if (!desc.startsWith("L") || !desc.endsWith(";")) return false;
        String t = desc.substring(1, desc.length() - 1);
        return c.projectClasses.contains(t) && fieldClass(c, g, t);
    }
    /** R1195 — the cells of an OBJECT reference: {@link #cells}, plus this body's own receiver ({@code P:..:-1}) when
     *  the reference is {@code this}. Used only for a field access and a project call's receiver. */
    private static List<String> objCells(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            SourceValue v, String self) {
        List<String> out = cells(c, g, cn, mn, sf, v, self, 0);
        if (v != null && (mn.access & Opcodes.ACC_STATIC) == 0 && !v.insns.isEmpty()) {
            boolean me = true;
            for (AbstractInsnNode src : v.insns) {
                int idx = mn.instructions.indexOf(src);
                Frame<SourceValue> f = idx >= 0 ? sf[idx] : null;
                if (!(src instanceof VarInsnNode vi) || vi.getOpcode() != Opcodes.ALOAD || vi.var != 0 || f == null
                        || !f.getLocal(0).insns.isEmpty()) { me = false; break; }
            }
            if (me) out.add("P:" + self + ":-1");
        }
        return out;
    }

    /** R1195 — a field's DECLARING class (a read or store may name a subclass). */
    private static String declaringField(AnalysisContext c, String owner, String name) {
        for (String o = owner; o != null; ) {
            ClassNode cn = c.byName.get(o);
            if (cn == null) return owner + "." + name;
            for (FieldNode fn : cn.fields) if (fn.name.equals(name)) return o + "." + name;
            o = cn.superName;
        }
        return owner + "." + name;
    }

    /** The cells reachable from {@code start} (itself included) along {@code links}. */
    private static Set<String> reach(Map<String, Set<String>> links, String start) {
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> work = new ArrayDeque<>(List.of(start));
        while (!work.isEmpty()) { String x = work.poll(); if (seen.add(x)) work.addAll(links.getOrDefault(x, Set.of())); }
        return seen;
    }

    /** R1188 — a {@code Comparator.comparing}-family call's comparator facts, onto its result cell: the key's
     *  {@code compareTo} where the key comparator is natural (none, {@code naturalOrder()}, ...), the given comparator's
     *  facts otherwise, and the receiver's for an instance combinator ({@code thenComparing}, {@code reversed}). */
    private static void comparatorCall(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            Frame<SourceValue> f, MethodInsnNode m, Type[] at, int base, String cell, String self, int depth) {
        boolean cmpOwner = m.owner.equals("java/util/Comparator");
        boolean rev = m.owner.equals("java/util/Collections") && m.name.equals("reverseOrder") && at.length == 1;
        if (!cmpOwner && !rev) return;
        if (m.getOpcode() != Opcodes.INVOKESTATIC && base >= 1)
            for (String r : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.cmpLink(r, cell);
        int fn = -1, cmp = -1;
        for (int k = 0; k < at.length; k++) {
            if (at[k].getSort() != Type.OBJECT) continue;
            if (at[k].getInternalName().equals("java/util/function/Function")) fn = k;
            else if (at[k].getInternalName().equals("java/util/Comparator")) cmp = k;
        }
        boolean keyed = fn >= 0 && (m.name.equals("comparing") || m.name.equals("thenComparing"));
        boolean natural = cmp < 0 || NAT.equals(comparatorKind(mn, sf, f.getStack(base + cmp), Collections.newSetFromMap(new IdentityHashMap<>())));
        if (keyed && natural) {
            String[] kt = keyResult(c, mn, sf, f.getStack(base + fn));
            if (kt != null) g.cmpk(cell, "K:" + kt[0] + "\t" + (kt[1] != null ? 1 : 0));
        }
        // a comparator argument the result runs: `comparing(f, new RevCmp())`, `thenComparing(other)`, `nullsFirst(c)`,
        // `reverseOrder(c)` — never a natural one, whose key is the ELEMENT (not known here)
        if (cmp >= 0 && !(keyed && natural))
            for (String a : cells(c, g, cn, mn, sf, f.getStack(base + cmp), self, depth + 1)) g.cmpLink(a, cell);
    }

    /** R1188 — {@link #functionResult}, but for a KEY: a project class or a chained dependency's (never the JDK's,
     *  whose {@code compareTo} on {@code String}/boxes is pure). */
    private static String[] keyResult(AnalysisContext c, MethodNode mn, Frame<SourceValue>[] sf, SourceValue v) {
        String[] res = null;
        for (AbstractInsnNode src : producers(mn, sf, v)) {
            if (!(src instanceof InvokeDynamicInsnNode d) || d.bsmArgs.length < 3 || !(d.bsmArgs[2] instanceof Type mt)
                    || mt.getSort() != Type.METHOD) return null;
            Type rt = mt.getReturnType();
            if (rt.getSort() != Type.OBJECT || jdkOwner(rt.getInternalName())) return null;
            Handle h = d.bsmArgs[1] instanceof Handle hh ? hh : null;
            boolean exact = h != null && h.getTag() == Opcodes.H_NEWINVOKESPECIAL && h.getOwner().equals(rt.getInternalName());
            String[] r = {rt.getInternalName(), exact ? "exact" : null};
            if (res != null && !res[0].equals(r[0])) return null;
            res = r;
        }
        return res;
    }

    /** R1189 — a class whose instances are comparators: a project class, or a chained dependency's, that implements
     *  {@code java.util.Comparator}. */
    private static boolean comparatorClass(AnalysisContext c, String t) {
        if (jdkOwner(t)) return false;
        if (c.byName.containsKey(t)) return Candor.transSupers(t).contains("java/util/Comparator");
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> work = new ArrayDeque<>(List.of(t));
        while (!work.isEmpty()) {
            String x = work.poll();
            if (!seen.add(x)) continue;
            for (String s : c.depSupers.getOrDefault(x, List.of())) {
                if (s.equals("java/util/Comparator")) return true;
                work.add(s);
            }
        }
        return false;
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
                for (String sfx : TWINS) {
                    Set<String> v = vals.get(e.getKey() + sfx);
                    if (v != null && !v.isEmpty())
                        for (String d : e.getValue()) changed |= vals.computeIfAbsent(d + sfx, k -> new HashSet<>()).addAll(v);
                }
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

    /** SOUNDNESS R1199 — an element set that does not bound what this site orders: empty (nothing traced), or holding a
     *  value known only as {@code Object} or {@code Comparable} — a signature's bound or an insert's static type, which
     *  admits ANY Comparable, so an exact type beside it is one member, not the set. {@link ArgContract#bodiesFor}
     *  answers both with nothing (neither IS a body), which left such a site silent. */
    private static Set<String> qBound(Graph g, String q) {
        String t = g.qDecl.get(q);
        return t == null ? null : Set.of(t + "\t0");
    }
    private static boolean untraced(Set<String> es) {
        if (es == null || es.isEmpty()) return true;
        for (String te : es) {
            int tab = te.indexOf('\t');
            String t = te.substring(0, tab);
            if ((t.equals("java/lang/Object") || t.equals("java/lang/Comparable")) && !te.endsWith("\t1")) return true;
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
                    linkParams(g, p[1], qp, Integer.MIN_VALUE, p[4]);
                    // R1195: a STATIC field is one object — the scalar is its element (`Reg.add(o) { ALL.add(o); }`)
                    @SuppressWarnings("unchecked") Set<String> qf = (Set<String>) qs[6];
                    for (String sf2 : qf) { if (DEBUG) System.err.println("R1195QSTATIC\t" + p[0] + "\t" + sf2); g.link(p[1], sf2); }
                    continue;
                }
                // R1195: what the callee does with the containers in the FIELDS of this argument (or receiver), and what
                // it itself put there or into the argument (back-flow, exact types only)
                for (String tw : new ArrayList<>(g.twins.getOrDefault(pc, Set.of()))) {
                    // R1198: the caller's cell may itself be a twin (an object in a field), up to MAX_TWIN fields deep
                    String a = g.twin(p[1], tw.substring(1));
                    if (a == null) continue;
                    g.back(pc + tw, a);
                    Object[] ts = memo.computeIfAbsent(pc + tw, k -> summary(g, byCell, callee, k));
                    @SuppressWarnings("unchecked") List<List<String>> tk = (List<List<String>>) ts[0];
                    // R1198: every key, not only compareTo — a callee hashing or comparing for equality the container in
                    // a field of the object its caller handed it runs the CALLER's elements' equals/hashCode
                    for (List<String> d : tk) {
                        if (DEBUG) System.err.println("R1195TWIN\t" + p[0] + "\t" + callee + "\t" + a + "\t" + d.get(2));
                        // R1198 reach: a key other than compareTo, or a field PATH (a field of a field)
                        if (DEBUG && (!d.get(2).equals(CMP) || a.indexOf('#') != a.lastIndexOf('#')))
                            System.err.println("R1198TWIN\t" + p[0] + "\t" + callee + "\t" + a + "\t" + d.get(2));
                        g.dispatch(p[0], a, d.get(2), substitute(g, d.get(3), callee, p[4]), d.get(4));
                    }
                    if ((Boolean) ts[4]) { g.alias(a, p[4]); g.pair(a, p[4]); } else if ((Boolean) ts[2]) g.link(a, p[4]);
                    @SuppressWarnings("unchecked") Set<String> tap = (Set<String>) ts[7];
                    pairParams(g, a, tap, p[4]);
                    @SuppressWarnings("unchecked") Set<String> tp = (Set<String>) ts[5];
                    linkParams(g, a, tp, Integer.MIN_VALUE, p[4]);
                }
                if (p[3].equals("-1")) continue;
                g.back(pc, p[1]);
                Object[] sum = memo.computeIfAbsent(pc, k -> summary(g, byCell, callee, k));
                @SuppressWarnings("unchecked") List<List<String>> keys = (List<List<String>>) sum[0];
                @SuppressWarnings("unchecked") Set<String> fields = (Set<String>) sum[1];
                @SuppressWarnings("unchecked") Set<String> aliasFields = (Set<String>) sum[3];
                for (List<String> d : keys) {
                    if (DEBUG) System.err.println("R1179PASS\t" + p[0] + "\t" + d.get(2) + "\t" + callee + "\t" + p[3]);
                    g.dispatch(p[0], p[1], d.get(2), substitute(g, d.get(3), callee, p[4]), d.get(4));
                }
                for (String f : fields) if (aliasFields.contains(f)) g.alias(p[1], f); else g.link(p[1], f);
                @SuppressWarnings("unchecked") Set<String> sap = (Set<String>) sum[7];
                pairParams(g, p[1], sap, p[4]);
                if ((Boolean) sum[4]) { g.alias(p[1], p[4]); g.pair(p[1], p[4]); g.siteBack(p[4], p[1]); }
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
                linkParams(g, p[1] + VALS, vp, Integer.MIN_VALUE, p[4]);
            }
        } while (g.grew && rounds++ < 32);
    }

    /** SOUNDNESS R1198 — the callee stored the argument OBJECT itself (not a copy) into a field of another argument or
     *  of its receiver ({@code Outer3(Bag b) { bag = b; }}): at this site the caller's cell and that field twin are one
     *  object. */
    private static void pairParams(Graph g, String src, Set<String> params, String site) {
        if (params.isEmpty()) return;
        Map<Integer, List<String>> args = g.siteArgs.getOrDefault(site, Map.of());
        for (String x : params) {
            int h = x.indexOf('#');
            if (h <= 0) continue;
            int k;
            try { k = Integer.parseInt(x.substring(0, h)); } catch (NumberFormatException e) { continue; }
            for (String a : args.getOrDefault(k, List.of())) {
                String tw = g.twin(a, x.substring(h + 1));
                if (tw != null) g.pair(src, tw);
            }
        }
    }

    /** SOUNDNESS R1198 — two cells that are the SAME object ({@link Graph#pairs}) have the same fields: every field twin
     *  either has is linked both ways to the other's, to a fixpoint (a pair can be a twin of another pair). Only cells
     *  specific to one receiver or one call site are ever paired — a getter's result at one call, a constructor's
     *  argument at one call — never a callee's return cell or an instance field's global cell, so no two objects meet. */
    private static void pairTwins(Graph g) {
        if (g.pairs.isEmpty()) return;
        for (int round = 0; round < 8; round++) {
            Map<String, Set<String>> idx = new HashMap<>();
            java.util.function.Consumer<String> add = cell -> {
                if (cell == null) return;
                for (int h = cell.indexOf('#'); h > 0; h = cell.indexOf('#', h + 1))
                    idx.computeIfAbsent(cell.substring(0, h), x -> new HashSet<>()).add(cell.substring(h));
            };
            for (String k : g.elems.keySet()) add.accept(k);
            for (var e : g.flow.entrySet()) { add.accept(e.getKey()); e.getValue().forEach(add); }
            for (List<String> d : g.dispatch) { add.accept(d.get(1)); for (String r : d.get(3).split(" ")) add.accept(r); }
            for (List<String> cs : g.cmpSites) for (String r : cs.get(1).split(" ")) add.accept(r);
            boolean grew = false;
            for (List<String> pr : new ArrayList<>(g.pairs)) {
                String x = pr.get(0), y = pr.get(1);
                Set<String> sfx = new HashSet<>(idx.getOrDefault(x, Set.of()));
                sfx.addAll(idx.getOrDefault(y, Set.of()));
                for (String sf : sfx) {
                    String xs = g.twin(x, sf.substring(1)), ys = g.twin(y, sf.substring(1));
                    if (xs == null || ys == null) continue;
                    if (DEBUG) System.err.println("R1198PAIR\t" + xs + "\t" + ys);
                    grew |= g.flow.computeIfAbsent(xs, k -> new HashSet<>()).add(ys);
                    grew |= g.flow.computeIfAbsent(ys, k -> new HashSet<>()).add(xs);
                    g.alias.computeIfAbsent(xs, k -> new HashSet<>()).add(ys);
                    g.alias.computeIfAbsent(ys, k -> new HashSet<>()).add(xs);
                    g.pair(xs, ys);
                }
            }
            if (!grew) return;
        }
    }

    /** The caller's cells for each callee parameter {@code k} the value reaches: one-way element flow, at this site. */
    private static void linkParams(Graph g, String src, Set<String> params, int self, String site) {
        if (params.isEmpty()) return;
        Map<Integer, List<String>> args = g.siteArgs.getOrDefault(site, Map.of());
        for (String x : params) {
            int cut = 0;
            while (cut < x.length() && (Character.isDigit(x.charAt(cut)) || cut == 0 && x.charAt(0) == '-')) cut++;
            String twin = x.substring(cut);
            int k;
            try { k = Integer.parseInt(x.substring(0, cut)); }
            catch (NumberFormatException e) { continue; }
            if (k == self && twin.isEmpty()) continue;
            if (!twin.isEmpty() && !twin.equals(VALS) && !twin.startsWith("#")) continue;
            for (String a : args.getOrDefault(k, List.of())) {
                if (twin.startsWith("#")) {
                    String tw = g.twin(a, twin.substring(1));
                    if (tw != null) g.link(src, tw);
                } else g.link(src, a + twin);
            }
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
            String rest = r.substring(pfx.length());
            int hash = rest.indexOf('#');
            List<String> a;
            try { a = args.get(Integer.parseInt(hash < 0 ? rest : rest.substring(0, hash))); }
            catch (NumberFormatException e) { out.add("?"); continue; }
            if (a == null || a.isEmpty()) { out.add("?"); continue; }
            if (hash < 0) { out.addAll(a); continue; }
            for (String x : a) { String tw = g.twin(x, rest.substring(hash + 1)); out.add(tw == null ? "?" : tw); }
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
        Set<String> fields = new HashSet<>(), staticFields = new HashSet<>();
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
                if (y.startsWith("F:")) { if (y.startsWith(ownField)) fields.add(y); if (g.statics.contains(y)) staticFields.add(y); }
                else if (y.equals(ret)) returns = true;
                else if (y.indexOf(own) == 2) {   // L:/S:/P:/A: cells of the callee itself
                    work.add(y);
                    // R1184: one of the callee's own container PARAMETERS — the caller's argument there
                    if (y.startsWith(ownParam)) params.add(y.substring(ownParam.length()));   // "k", or "k|v" (its values)
                }
            }
        }
        // the same container OBJECT (not a copy of its elements) reaching a field or the return: its ordering goes too
        Set<String> aliasFields = new HashSet<>(), aliasParams = new TreeSet<>(); boolean aliasRet = false;
        Set<String> aseen = new HashSet<>();
        ArrayDeque<String> aw = new ArrayDeque<>(List.of(pc));
        while (!aw.isEmpty()) {
            String x = aw.poll();
            if (!aseen.add(x)) continue;
            for (String y : g.alias.getOrDefault(x, Set.of())) {
                if (y.startsWith("F:")) { if (y.startsWith(ownField)) aliasFields.add(y); }
                else if (y.equals(ret)) aliasRet = true;
                else if (y.indexOf(own) == 2) {
                    aw.add(y);
                    // R1198: the SAME object stored into a field of another parameter (or of the receiver)
                    if (y.startsWith(ownParam) && y.indexOf('#') > 0) aliasParams.add(y.substring(ownParam.length()));
                }
            }
        }
        return new Object[] {keys, fields, returns, aliasFields, aliasRet, params, staticFields, aliasParams};
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
        // R1198: a body that reads or stores an object holding containers (a getter, a constructor storing one)
        for (AbstractInsnNode in : mn.instructions)
            if (in instanceof FieldInsnNode fi && (fi.getOpcode() == Opcodes.GETFIELD || fi.getOpcode() == Opcodes.PUTFIELD)
                    && twinField(c, g, fi.desc)) return true;
        for (AbstractInsnNode in : mn.instructions)
            if (in instanceof MethodInsnNode m && c.projectClasses.contains(m.owner)
                    && (m.desc.contains("Ljava/util/") || m.desc.contains("[L") || g.qkeys.contains(m.name))) return true;
        // R1195: an object whose class holds container fields, handed on or called — its field twins travel
        for (AbstractInsnNode in : mn.instructions)
            if (in instanceof MethodInsnNode m && c.projectClasses.contains(m.owner)) {
                if (m.getOpcode() != Opcodes.INVOKESTATIC && fieldClass(c, g, m.owner)) return true;
                for (Type t : Type.getArgumentTypes(m.desc))
                    if (t.getSort() == Type.OBJECT && c.projectClasses.contains(t.getInternalName()) && fieldClass(c, g, t.getInternalName())) return true;
            }
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
                if (fi.desc.equals(CMP_DESC)) g.fieldStores.add(declaringField(c, fi.owner, fi.name));
                if (op == Opcodes.PUTSTATIC) g.statics.add("F:" + fi.owner + "." + fi.name);
                List<String> stored = cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self, 0);
                for (String cell : stored) g.alias(cell, "F:" + fi.owner + "." + fi.name);
                // R1195: …and into the field of THIS object (its twin), per receiver
                if (op == Opcodes.PUTFIELD && twinField(c, g, fi.desc) && f.getStackSize() >= 2) {
                    String fk = declaringField(c, fi.owner, fi.name);
                    for (String r : objCells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 2), self)) {
                        String tw = g.twin(r, fk);
                        if (tw != null) for (String cell : stored) g.alias(cell, tw);
                    }
                }
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
                if (t != null && !t.equals("java/lang/Object")) {
                    boolean par = pf[0] != null && Candor.paramIndexOf(mn, v, pf[0]) >= 0;
                    for (String cell : cells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 3), self, 0))
                        if (par) g.elem(cell, t, false); else g.elemV(cell, t, v.newType != null);
                }
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
                // R1195: the RECEIVER of an instance call to a class holding container fields — its field twins are
                // the caller's, through the callee's summary (per receiver)
                if (inst && recv != null && fieldClass(c, g, m.owner)) {
                    callees = ArgContract.projectCallees(c, m, p);
                    List<String> rc = objCells(c, g, cn, mn, sf, recv, self);
                    if (!callees.isEmpty() && !rc.isEmpty()) {
                        g.siteArgs.computeIfAbsent(site, k -> new HashMap<>()).put(-1, rc);
                        for (String cell : rc) for (String callee : callees) g.passes.add(new String[] {id, cell, callee, "-1", site, ""});
                    }
                }
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
                    // R1189: a COMPARATOR the callee runs (`fill(Comparator c) { new TreeSet<>(c).add(..) }`), or a container
                    // built with one that the callee fills (`put2(TreeSet t) { t.add(..) }`), runs at THIS call with THIS
                    // caller's comparator — a summary, never a merge of every caller's
                    String an = at[j].getInternalName();
                    if ((an.startsWith("java/util/") || an.equals("java/lang/Object") || an.equals("java/lang/Iterable")) && !argCells.isEmpty())
                        for (String callee : callees) g.cmpPasses.add(List.of(id, String.join(" ", argCells), callee, String.valueOf(j)));
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
                        if (any) g.elemV(vc, t, v.newType != null);
                    }
                }
                continue;
            }
            // R1179: ORDERING over the elements of a container argument or receiver
            ordering(c, g, cn, mn, sf, f, p, m, at, base, recv, self, id, i);
            if (!isCollectionOwner(m.owner)) continue;
            // R1183: a TreeSet/TreeMap key operation (Candor#contractReentry charges it): its receiver's cells
            if (inst && treeKeyOp(m.owner, m.name)) {
                g.treeRecv.put(id + "\t" + i, traced(mn, sf, recv, Collections.newSetFromMap(new IdentityHashMap<>()))
                        ? recvKey(cells(c, g, cn, mn, sf, recv, self, 0)) : "?");
                g.cmpSite(id, cells(c, g, cn, mn, sf, recv, self, 0));   // R1189: the receiver's comparator runs
            }
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
                    g.cmpSite(id, cells(c, g, cn, mn, sf, recv, self, 0));   // R1189: the receiver's comparator runs
                    if (pi >= 0) {
                        // the element is this body's own PARAMETER: its caller's argument, through the summary
                        g.dispatch(id, "Q:" + self + ":" + pi, CMP, rk, m.owner);
                        // R1199: what the parameter is declared as (erased: a type variable is its bound)
                        Type pt = Type.getArgumentTypes(mn.desc)[pi];
                        g.qDecl.put("Q:" + self + ":" + pi, pt.getSort() == Type.OBJECT ? pt.getInternalName() : pt.getDescriptor());
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
                // R1188/R1189: a sorted container built with a comparator runs THAT comparator on every key operation
                int ck = cmpArg(at);
                if (ck >= 0 && Candor.sortedOwner(m.owner))
                    for (String cc : cells(c, g, cn, mn, sf, f.getStack(base + ck), self, 0))
                        for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.cmpLink(cc, cell);
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
                    g.cmpSite(id, dst);   // R1189: the receiver's comparator runs on every incoming element
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
        int pi = pf[0] == null ? -1 : Candor.paramIndexOf(mn, v, pf[0]);
        // R1198: the body's own value is an insert (it travels back to a caller that handed the container in); a
        // PARAMETER's declared type is not — its caller's own value reaches through the Q link below, exactly
        if (t != null) for (String cell : dst) { if (pi >= 0) g.elem(cell + twin, t, v.newType != null); else g.elemV(cell + twin, t, v.newType != null); }
        if (pi >= 0) for (String cell : dst) g.link("Q:" + self + ":" + pi, cell + twin);
        // R1195: a CONTAINER added as one element — its elements are the receiver's elements' elements (NEST)
        if (t == null || t.startsWith("java/util/")) {
            int idx = mn.instructions.indexOf(m);
            Frame<SourceValue> fr = idx >= 0 ? sf[idx] : null;
            int n = Type.getArgumentTypes(m.desc).length;
            if (fr != null && fr.getStackSize() >= n)
                for (String a : cells(c, g, cn, mn, sf, fr.getStack(fr.getStackSize() - n + j), self, 0))
                    for (String cell : dst) g.link(a, cell + twin + NEST);
        }
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
        String o = m.owner, name = m.name;
        // R1188/R1189: an ordering call handed a comparator runs it (a `new` comparator object here is already edged by
        // Candor#namedFunctionalToHof; one reaching through a field, a parameter or a combinator is not)
        if (ck >= 0 && !nullCmp(p, m, ck) && sortsWith(o, name))
            g.cmpSite(id, cells(c, g, cn, mn, sf, f.getStack(base + ck), self, 0));
        if (!natural) return;
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
                String ckind = collectorKind(c, cn, mn, sf, f.getStack(base));
                if (NAT.equals(ckind))
                    for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, CMP);
                else if (ckind == null) capturedComparatorCollect(c, g, cn, mn, sf, f.getStack(base), recv, self, id, i);
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

    /** SOUNDNESS R1198 — {@code collect(toCollection(() -> new TreeSet<>(cmp)))} with {@code cmp} CAPTURED by the
     *  supplier lambda: the collected container is built with the CAPTURED comparator, so it orders as that value does
     *  (executed on JDK 21: a captured {@code naturalOrder()} runs the elements' {@code compareTo}; a captured
     *  comparator PARAMETER runs whatever its caller handed in). The container is a synthetic cell at this call: its
     *  comparator is the captured value's cells (so its facts — natural, out of sight, a parameter, an object — reach it
     *  as for any built container), its base kind the captured value's own {@link #comparatorKind}, and every stream
     *  element is a CMP dispatch conditioned on it — charged where natural, disclosed where out of sight, nothing where
     *  provably not natural. Only a lambda in this class whose every return is one {@code new} of a sorted container
     *  built with a comparator loaded from a captured parameter is read; anything else adds nothing, as before. */
    private static void capturedComparatorCollect(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            SourceValue collector, SourceValue recv, String self, String id, int i) {
        for (AbstractInsnNode src : producers(mn, sf, collector)) {
            if (!(src instanceof MethodInsnNode m) || !m.owner.equals("java/util/stream/Collectors") || !m.name.equals("toCollection")) continue;
            int mi = mn.instructions.indexOf(m);
            Frame<SourceValue> mf = mi >= 0 ? sf[mi] : null;
            if (mf == null || mf.getStackSize() < 1) continue;
            for (AbstractInsnNode sup : producers(mn, sf, mf.getStack(mf.getStackSize() - 1))) {
                if (!(sup instanceof InvokeDynamicInsnNode d) || d.bsmArgs.length < 2 || !(d.bsmArgs[1] instanceof Handle h)
                        || !h.getOwner().equals(cn.name) || !h.getName().startsWith("lambda$")) continue;
                int ncap = Type.getArgumentTypes(d.desc).length;
                if (ncap == 0) continue;
                MethodNode lm = Candor.findMethod(cn, h.getName(), h.getDesc());
                if (lm == null) continue;
                String[] built = capturedSortedAlloc(cn, lm);   // {owner, lambda parameter index of the comparator}
                if (built == null) continue;
                boolean stat = h.getTag() == Opcodes.H_INVOKESTATIC;
                int capIdx = Integer.parseInt(built[1]) + (stat ? 0 : 1);   // an instance lambda captures `this` first
                int di = mn.instructions.indexOf(d);
                Frame<SourceValue> df = di >= 0 ? sf[di] : null;
                if (df == null || capIdx < 0 || capIdx >= ncap || df.getStackSize() < ncap) continue;
                SourceValue cv = df.getStack(df.getStackSize() - ncap + capIdx);
                String synth = "L:" + self + ":" + i;
                g.kind(synth, comparatorKind(mn, sf, cv, Collections.newSetFromMap(new IdentityHashMap<>())));
                for (String cc : cells(c, g, cn, mn, sf, cv, self, 0)) g.cmpLink(cc, synth);
                g.cmpSite(id, List.of(synth));
                if (DEBUG) System.err.println("R1198CAPCMP\t" + id + "\t" + built[0] + "\t" + synth);
                for (String cell : cells(c, g, cn, mn, sf, recv, self, 0)) g.dispatch(id, cell, CMP, synth, built[0]);
            }
        }
    }

    /** R1198 — a supplier lambda's one allocation: every ARETURN returns a {@code new} of a SORTED container whose
     *  comparator argument is loaded straight from one of the lambda's own parameters (a captured value). */
    private static String[] capturedSortedAlloc(ClassNode cn, MethodNode lm) {
        try {
            Frame<SourceValue>[] lsf = new Analyzer<>(new SourceInterpreter()).analyze(cn.name, lm);
            String[] res = null;
            for (int k = 0; k < lm.instructions.size(); k++) {
                AbstractInsnNode in = lm.instructions.get(k);
                if (in.getOpcode() != Opcodes.ARETURN || lsf[k] == null) continue;
                for (AbstractInsnNode src : producers(lm, lsf, lsf[k].getStack(lsf[k].getStackSize() - 1))) {
                    if (src.getOpcode() != Opcodes.NEW) return null;
                    String t = ((TypeInsnNode) src).desc;
                    if (!Candor.sortedOwner(t)) return null;
                    String[] r = null;
                    for (AbstractInsnNode x = src.getNext(); x != null; x = x.getNext())
                        if (x instanceof MethodInsnNode mi && mi.getOpcode() == Opcodes.INVOKESPECIAL && mi.name.equals("<init>") && mi.owner.equals(t)) {
                            int xi = lm.instructions.indexOf(x);
                            Frame<SourceValue> xf = lsf[xi];
                            Type[] at = Type.getArgumentTypes(mi.desc);
                            int ck = cmpArg(at);
                            if (xf == null || ck < 0) return null;
                            SourceValue cv = xf.getStack(xf.getStackSize() - at.length + ck);
                            for (AbstractInsnNode p : producers(lm, lsf, cv)) {
                                if (!(p instanceof VarInsnNode v) || v.getOpcode() != Opcodes.ALOAD) return null;
                                int pi = paramOf(lm, v.var);
                                if (pi < 0) return null;
                                if (r != null && !r[1].equals(String.valueOf(pi))) return null;
                                r = new String[] {t, String.valueOf(pi)};
                            }
                            break;
                        }
                    if (r == null) return null;
                    if (res != null && !Arrays.equals(res, r)) return null;
                    res = r;
                }
            }
            return res;
        } catch (Exception e) {
            return null;
        }
    }

    /** R1188 — an ordering call that runs the comparator it is handed, synchronously. */
    private static boolean sortsWith(String o, String name) {
        if (o.equals("java/util/Collections")) return name.equals("sort") || name.equals("max") || name.equals("min") || name.equals("binarySearch");
        if (o.equals("java/util/Arrays")) return name.equals("sort") || name.equals("parallelSort") || name.equals("binarySearch");
        if (o.equals("java/util/stream/Stream")) return name.equals("sorted") || name.equals("max") || name.equals("min");
        return isCollectionOwner(o) && name.equals("sort");
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
                            if (mn.signature != null) nestedElems(g, cell, methodTypeTree(mn.signature, p));
                            if (Type.getArgumentTypes(mn.desc)[p].getDescriptor().equals(CMP_DESC)) g.cmpk(cell, CPAR);
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
                case Opcodes.NEW -> {
                    out.add("L:" + self + ":" + idx);
                    // R1189: a comparator OBJECT runs its own compare wherever the comparator runs
                    String t = ((TypeInsnNode) src).desc;
                    if (comparatorClass(c, t)) g.cmpk("L:" + self + ":" + idx, "C:" + t);
                }
                case Opcodes.INVOKEDYNAMIC -> {
                    // R1195: `T::compareTo` as a Comparator value — natural ordering, wherever it is stored
                    InvokeDynamicInsnNode d = (InvokeDynamicInsnNode) src;
                    if (d.desc.endsWith(")" + CMP_DESC) && d.bsmArgs.length >= 2 && d.bsmArgs[1] instanceof Handle h
                            && h.getName().equals("compareTo")) {
                        String cell = "L:" + self + ":" + idx;
                        g.cmpk(cell, CNAT);
                        out.add(cell);
                    }
                }
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
                    if (op == Opcodes.GETSTATIC) g.statics.add(cell);
                    // R1195: the container in the field of THIS object, per receiver (beside the global field cell)
                    if (op == Opcodes.GETFIELD && twinField(c, g, fi.desc) && f != null && f.getStackSize() >= 1) {
                        String fk = declaringField(c, fi.owner, fi.name);
                        for (String r : objCells(c, g, cn, mn, sf, f.getStack(f.getStackSize() - 1), self)) {
                            String tw = g.twin(r, fk);
                            if (tw != null) out.add(tw);
                        }
                    }
                    String e = fieldElem(c, fi);
                    if (e != null) g.elem(cell, e, false);
                    String ve = fieldValueElem(c, fi);
                    if (ve != null) g.elem(cell + VALS, ve, false);
                    String fs = fieldSig(c, fi);
                    if (fs != null) nestedElems(g, cell, fieldTypeTree(fs));
                    if (fi.desc.equals(CMP_DESC) && !jdkOwner(fi.owner)) {
                        if (c.projectClasses.contains(fi.owner)) g.cmpFieldReads.put(cell, declaringField(c, fi.owner, fi.name));
                        else g.cmpk(cell, CDEP);   // a dependency's comparator field
                    }
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
                        // SOUNDNESS R1199: `Set<V> all()` on a receiver whose static type is `Graph2<Eff>` holds Eff
                        if (e == null && tm != null && op != Opcodes.INVOKESTATIC && f != null)
                            e = instantiatedReturnElem(c, mn, f, m, tm);
                        if (e != null) g.elem(cell, e, false);
                        String ve = tm == null || tm.signature == null ? null : mapValueArg(tm.signature, -1);
                        if (ve != null) g.elem(cell + VALS, ve, false);
                        if (tm != null && tm.signature != null) nestedElems(g, cell, methodTypeTree(tm.signature, -1));
                    } else if (!jdkOwner(m.owner)) {
                        // R1184: a DEPENDENCY's return — its allocation is out of sight. Its static type is all there is:
                        // a sorted type orders (as a static sorted owner does), a container interface MAY, a concrete
                        // JDK container type does not
                        String k = returnKind(Type.getReturnType(m.desc));
                        if (k != null) g.kind(cell, k.equals(SRT) || k.equals(UNSORTED) ? k : DEP);
                        // R1195: a dependency's COMPARATOR — out of sight
                        if (Type.getReturnType(m.desc).getDescriptor().equals(CMP_DESC)) g.cmpk(cell, CDEP);
                    } else if (m.owner.startsWith("java/util/") && f != null) {
                        Type[] at = Type.getArgumentTypes(m.desc);
                        int base = f.getStackSize() - at.length;
                        // R1184: a JDK call whose static return type is SORTED (a view, a synchronized wrapper, an empty
                        // sorted set): evidence of ordering, exactly as a static sorted owner is
                        if ("SRT".equals(returnKind(Type.getReturnType(m.desc)))) g.kind(cell, SRT);
                        // R1188: a comparator made by a `Comparator.comparing` family member
                        if (m.desc.endsWith(")Ljava/util/Comparator;")) {
                            comparatorCall(c, g, cn, mn, sf, f, m, at, base, cell, self, depth);
                            // R1195: natural ordering made here — a fact of the VALUE, so it survives a return or a field
                            if (op == Opcodes.INVOKESTATIC && m.desc.startsWith("()") && (m.name.equals("naturalOrder") || m.name.equals("reverseOrder"))
                                    && (m.owner.equals("java/util/Comparator") || m.owner.equals("java/util/Collections")))
                                g.cmpk(cell, CNAT);
                        }
                        if (m.owner.equals("java/util/stream/Stream") && op == Opcodes.INVOKESTATIC
                                && (m.name.equals("iterate") || m.name.equals("generate") || m.name.equals("concat"))) {
                            // R1195: a stream with NO collection behind it — `iterate(seed, [hasNext,] next)`, `generate(s)`,
                            // `concat(a, b)` — holds what its seed and functions make, or its operands' elements
                            streamSource(c, g, cn, mn, sf, f, m, at, base, cell, self, depth, idx);
                        } else if (m.owner.equals("java/util/stream/StreamSupport") && m.name.equals("stream") && at.length == 2
                                && at[0].getSort() == Type.OBJECT && at[0].getInternalName().equals("java/util/Spliterator")) {
                            // R1195: `StreamSupport.stream(c.spliterator(), par)` streams the spliterator's elements
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base), self, depth + 1)) g.link(s, cell);
                        } else if (m.owner.equals("java/util/stream/Stream$Builder") && base >= 1
                                && (m.name.equals("add") && at.length == 1 || m.name.equals("build") && at.length == 0)) {
                            // R1195: `Stream.builder().add(x)…build()` — the builder is the same object along the chain
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s, cell);
                            if (at.length == 1) streamElem(c, g, cn, mn, idx, m, 0, cell);
                        } else if (m.name.equals("flatMap") && m.owner.equals("java/util/stream/Stream") && at.length == 1 && base >= 1) {
                            // R1195: past a flatMap stage the elements are those of the streams the FUNCTION returns
                            flatMapStage(c, g, cn, mn, sf, f.getStack(base), f.getStack(base - 1), cell, self, depth);
                        } else if (m.name.equals("values") && at.length == 0 && base >= 1 && mapOwner(m.owner)) {
                            // R1184: a map's values() holds its VALUES
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s + VALS, cell);
                        } else if (m.name.equals("toArray") && base >= 1 && op != Opcodes.INVOKESTATIC) {
                            // R1184: a collection's toArray() holds its elements
                            for (String s : cells(c, g, cn, mn, sf, f.getStack(base - 1), self, depth + 1)) g.link(s, cell);
                        } else if ((m.name.equals("asList") || m.name.equals("stream") || m.name.equals("of")) && op == Opcodes.INVOKESTATIC
                                && (at.length == 1 || at.length == 3 && m.name.equals("stream")) && at[0].getSort() == Type.ARRAY) {
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
                        } else if ((m.name.equals("stream") || m.name.equals("parallelStream") || m.name.equals("spliterator"))
                                && at.length == 0 && base >= 1) {
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
                                    if (t == null) continue;
                                    if (pf[0] != null && Candor.paramIndexOf(mn, pv, pf[0]) >= 0) g.elem(cell, t, false);
                                    else g.elemV(cell, t, pv.newType != null);
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

    /** SOUNDNESS R1195 — a stream source with no collection behind it: {@code concat}'s operands' elements; for
     *  {@code iterate} the seed's type, and for {@code iterate}/{@code generate} the result type of the function that
     *  makes each next element (a lambda or method reference; nothing is assumed otherwise). Executed on JDK 21:
     *  {@code iterate(..).sorted()} and {@code generate(..).limit(n).sorted()} run the elements' {@code compareTo}. */
    private static void streamSource(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            Frame<SourceValue> f, MethodInsnNode m, Type[] at, int base, String cell, String self, int depth, int idx) {
        if (m.name.equals("concat")) {
            for (int k = 0; k < at.length; k++)
                for (String s : cells(c, g, cn, mn, sf, f.getStack(base + k), self, depth + 1)) g.link(s, cell);
            return;
        }
        if (at.length == 0) return;
        if (DEBUG) System.err.println("R1195SRC\t" + self + "\t" + m.name);
        if (m.name.equals("iterate") && at.length >= 2) streamElem(c, g, cn, mn, idx, m, 0, cell);
        String[] rt = functionResult(c, mn, sf, f.getStack(base + at.length - 1));
        if (rt != null) g.elem(cell, rt[0], rt[1] != null);
    }

    /** R1195 — argument {@code j} of call {@code m} (at instruction {@code idx}) is one element of {@code cell}. */
    private static void streamElem(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, int idx, MethodInsnNode m, int j, String cell) {
        Frame<ProvValue>[] pf = Candor.cachedProvFrames(cn, mn);
        if (pf == null || pf[idx] == null) return;
        ProvValue v = Candor.callArg(pf[idx], m, j);
        String t = v == null || v.nullConst || v.fromIndy ? null : ArgContract.typeOf(c, v);
        if (t == null) return;
        if (pf[0] != null && Candor.paramIndexOf(mn, v, pf[0]) >= 0) g.elem(cell, t, false);
        else g.elemV(cell, t, v.newType != null);
    }

    /** SOUNDNESS R1195 — a {@code flatMap} stage's elements: those of the stream its FUNCTION returns. A lambda or a
     *  project method reference returns into its own return cell, which flows here; its element parameter (the one
     *  after the captured values) is bound to the incoming elements' OWN elements ({@link #NEST}), so
     *  {@code l -> l.stream()} carries a {@code List<List<E>>}'s E. {@code List::stream}/{@code Collection::stream}/
     *  {@code Arrays::stream} carry the incoming elements' elements directly. Any other function value adds nothing. */
    private static void flatMapStage(AnalysisContext c, Graph g, ClassNode cn, MethodNode mn, Frame<SourceValue>[] sf,
            SourceValue fn, SourceValue recvV, String cell, String self, int depth) {
        List<String> recv = cells(c, g, cn, mn, sf, recvV, self, depth + 1);
        for (AbstractInsnNode src : producers(mn, sf, fn)) {
            if (!(src instanceof InvokeDynamicInsnNode d) || d.bsmArgs.length < 2 || !(d.bsmArgs[1] instanceof Handle h)) continue;
            int ncap = Type.getArgumentTypes(d.desc).length;
            if (c.projectClasses.contains(h.getOwner())) {
                String tid = Cha.methodId(h.getOwner().replace('/', '.'), h.getName(), h.getDesc());
                if (DEBUG) System.err.println("R1195FLAT\t" + self + "\t" + tid);
                g.link("R:" + tid, cell);
                // a static body takes the element after its captured values; an instance body (a bound reference, or a
                // lambda capturing `this`) has its receiver among them; an UNBOUND reference's element is its
                // receiver, whose own elements are not a parameter here
                boolean stat = h.getTag() == Opcodes.H_INVOKESTATIC;
                // only a synthetic lambda body: a NAMED method's parameter is also every direct caller's, and binding
                // this stream's elements to it would hand them back to those callers
                if (!stat && ncap == 0 || !h.getName().startsWith("lambda$")) continue;
                int ep = stat ? ncap : ncap - 1;
                if (ep >= 0 && ep < Type.getArgumentTypes(h.getDesc()).length)
                    for (String r : recv) g.link(r + NEST, "P:M:" + tid + ":" + ep);
            } else if (ncap == 0 && h.getName().equals("stream") && h.getOwner().startsWith("java/util/")) {
                for (String r : recv) g.link(r + NEST, cell);
            }
        }
    }

    /** R1195 — a declared generic type as a tree (a type variable, a wildcard or an array is null). */
    private static final class GT {
        final String name; final List<GT> args = new ArrayList<>();
        GT(String n) { name = n; }
    }
    private static final class TreeBuilder extends SignatureVisitor {
        final java.util.function.Consumer<GT> sink; GT cur;
        TreeBuilder(java.util.function.Consumer<GT> sink) { super(Opcodes.ASM9); this.sink = sink; }
        @Override public void visitClassType(String name) { cur = new GT(name); sink.accept(cur); }
        @Override public void visitInnerClassType(String name) { if (cur != null) cur.args.clear(); }
        @Override public void visitTypeVariable(String name) { sink.accept(null); }
        @Override public SignatureVisitor visitArrayType() { return new TreeBuilder(x -> sink.accept(null)); }
        @Override public void visitTypeArgument() { if (cur != null) cur.args.add(null); }
        @Override public SignatureVisitor visitTypeArgument(char w) {
            GT parent = cur;
            if (parent == null) return new SignatureVisitor(Opcodes.ASM9) { };
            if (w == '-') { parent.args.add(null); return new SignatureVisitor(Opcodes.ASM9) { }; }
            return new TreeBuilder(parent.args::add);
        }
    }
    /** A method signature's parameter {@code p} (the return for p < 0), as a tree; null when it is not a class type. */
    private static GT methodTypeTree(String sig, int p) {
        GT[] out = {null};
        try {
            new SignatureReader(sig).accept(new SignatureVisitor(Opcodes.ASM9) {
                int param = -1;
                @Override public SignatureVisitor visitParameterType() {
                    param++;
                    return param == p ? new TreeBuilder(x -> out[0] = x) : new SignatureVisitor(Opcodes.ASM9) { };
                }
                @Override public SignatureVisitor visitReturnType() {
                    return p < 0 ? new TreeBuilder(x -> out[0] = x) : new SignatureVisitor(Opcodes.ASM9) { };
                }
                @Override public SignatureVisitor visitClassBound() { return new SignatureVisitor(Opcodes.ASM9) { }; }
                @Override public SignatureVisitor visitInterfaceBound() { return new SignatureVisitor(Opcodes.ASM9) { }; }
                @Override public SignatureVisitor visitExceptionType() { return new SignatureVisitor(Opcodes.ASM9) { }; }
            });
        } catch (RuntimeException e) { return null; }
        return out[0];
    }
    private static GT fieldTypeTree(String sig) {
        GT[] out = {null};
        try { new SignatureReader(sig).acceptType(new TreeBuilder(x -> out[0] = x)); } catch (RuntimeException e) { return null; }
        return out[0];
    }
    private static boolean seqContainer(GT t) {
        return t != null && t.name.startsWith("java/util/") && isCollectionOwner(t.name) && !mapOwner(t.name);
    }
    /** R1195 — a declared {@code Collection<Collection<E>>}'s E onto {@code cell}{@link #NEST}, and a
     *  {@code Map<K, Collection<E>>}'s E onto {@code cell}{@link #VALS}{@link #NEST}. */
    private static void nestedElems(Graph g, String cell, GT t) {
        if (t == null || t.args.isEmpty() || !t.name.startsWith("java/util/")) return;
        GT inner = mapOwner(t.name) ? (t.args.size() == 2 ? t.args.get(1) : null) : seqContainer(t) ? t.args.get(0) : null;
        if (!seqContainer(inner) || inner.args.isEmpty() || inner.args.get(0) == null) return;
        String e = inner.args.get(0).name;
        if (e.startsWith("java/util/")) return;
        g.elem(cell + (mapOwner(t.name) ? VALS : "") + NEST, e, false);
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

    /** SOUNDNESS R1199 — the element type a GENERIC project method's container return holds, instantiated by its
     *  receiver's static type: {@code Set<V> getAllVertices()} on a {@code DirectedMultiGraph<SceneGraphNode, ..>}
     *  field holds {@code SceneGraphNode} (declared). The receiver's type comes from a field's, a parameter's or a
     *  local's generic signature; every source of the receiver must agree on the argument, and the class it names must
     *  be the one declaring the method (a subclass may rename or fix its parameters). Else null. */
    private static String instantiatedReturnElem(AnalysisContext c, MethodNode mn, Frame<SourceValue> f, MethodInsnNode m, MethodNode tm) {
        // never let a malformed or absent signature throw: the caller's catch would drop the WHOLE body's scan
        try {
            return instantiatedReturnElem0(c, mn, f, m, tm);
        } catch (RuntimeException e) {
            return null;
        }
    }
    private static String instantiatedReturnElem0(AnalysisContext c, MethodNode mn, Frame<SourceValue> f, MethodInsnNode m, MethodNode tm) {
        if (tm.signature == null) return null;
        String tv = returnTypeVar(tm.signature);
        ClassNode oc = c.byName.get(m.owner);
        if (tv == null || oc == null || oc.signature == null || !oc.methods.contains(tm)) return null;
        int k = formalIndex(oc.signature, tv);
        int nargs = Type.getArgumentTypes(m.desc).length;
        int at = f.getStackSize() - nargs - 1;
        if (k < 0 || at < 0) return null;
        String out = null;
        for (AbstractInsnNode src : f.getStack(at).insns) {
            String sig = staticSig(c, mn, src);
            String a = sig == null ? null : typeArgOf(sig, m.owner, k);
            if (a == null || out != null && !out.equals(a)) return null;
            out = a;
        }
        return out;
    }
    /** The generic signature of the value {@code src} pushes: a field's, a parameter's, or a local's (its LVTT entry). */
    private static String staticSig(AnalysisContext c, MethodNode mn, AbstractInsnNode src) {
        if (src instanceof FieldInsnNode fi && (src.getOpcode() == Opcodes.GETFIELD || src.getOpcode() == Opcodes.GETSTATIC))
            return fieldSig(c, fi);
        if (src instanceof VarInsnNode vi && src.getOpcode() == Opcodes.ALOAD && mn.localVariables != null) {
            int idx = mn.instructions.indexOf(src);
            for (LocalVariableNode lv : mn.localVariables)
                if (lv.index == vi.var && lv.signature != null && mn.instructions.indexOf(lv.start) <= idx && idx < mn.instructions.indexOf(lv.end))
                    return lv.signature;
        }
        return null;
    }
    /** The type variable a method signature's return container takes as its FIRST type argument ({@code Set<V>}). */
    private static String returnTypeVar(String sig) {
        String[] out = {null};
        new SignatureReader(sig).accept(new SignatureVisitor(Opcodes.ASM9) {
            boolean inRet, top; int depth;
            @Override public SignatureVisitor visitParameterType() { inRet = false; return new SignatureVisitor(Opcodes.ASM9) { }; }
            @Override public SignatureVisitor visitExceptionType() { inRet = false; return new SignatureVisitor(Opcodes.ASM9) { }; }
            @Override public SignatureVisitor visitReturnType() { inRet = true; depth = 0; return this; }
            @Override public void visitClassType(String name) {
                if (!inRet) return;
                if (depth == 0) top = name.startsWith("java/util/");
                depth++;
            }
            @Override public void visitTypeVariable(String name) { if (inRet && depth == 1 && top && out[0] == null) out[0] = name; }
            @Override public SignatureVisitor visitTypeArgument(char w) { return w == '=' || w == '+' ? this : new SignatureVisitor(Opcodes.ASM9) { }; }
            @Override public void visitEnd() { if (inRet) depth--; }
        });
        return out[0];
    }
    /** The position of formal type parameter {@code tv} in a class signature, or -1. */
    private static int formalIndex(String classSig, String tv) {
        List<String> names = new ArrayList<>();
        new SignatureReader(classSig).accept(new SignatureVisitor(Opcodes.ASM9) {
            @Override public void visitFormalTypeParameter(String name) { names.add(name); }
        });
        return names.indexOf(tv);
    }
    /** The k-th type argument of a type signature whose raw class is {@code owner}, when it is a class (exact match on
     *  the raw class; a wildcard {@code ? extends T} gives its bound T). Else null. */
    private static String typeArgOf(String typeSig, String owner, int k) {
        String[] out = {null};
        boolean[] ok = {false};
        try {
            new SignatureReader(typeSig).acceptType(new SignatureVisitor(Opcodes.ASM9) {
                int depth, nth;
                @Override public void visitClassType(String name) {
                    if (depth == 0) ok[0] = name.equals(owner);
                    else if (depth == 1 && ok[0] && nth == k + 1 && out[0] == null) out[0] = name;
                    depth++;
                }
                @Override public void visitInnerClassType(String name) { if (depth == 1) ok[0] = false; }
                @Override public SignatureVisitor visitTypeArgument(char w) {
                    if (depth == 1) nth++;
                    return w == '-' ? new SignatureVisitor(Opcodes.ASM9) { } : this;
                }
                @Override public void visitTypeArgument() { if (depth == 1) nth++; }
                @Override public void visitEnd() { depth--; }
            });
        } catch (RuntimeException e) {
            return null;
        }
        return out[0];
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
    private static String fieldSig(AnalysisContext c, FieldInsnNode fi) {
        ClassNode oc = c.byName.get(fi.owner);
        if (oc == null) return null;
        for (FieldNode fn : oc.fields) if (fn.name.equals(fi.name)) return fn.signature;
        return null;
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
