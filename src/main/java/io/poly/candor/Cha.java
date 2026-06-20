package io.poly.candor;

import java.util.*;
import java.util.stream.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;

/** CHA / dispatch resolution. The bounded-CHA closed-hierarchy carve-out (enum + fully-closed-visible
 *  sealed families: isClosedHierarchy/isFullyClosedSealed/sealedHasUnseenPermit + the two private
 *  closure walks) and the dispatch-resolution band (externalSupers/buildSubtypeIndex/chaTargets/
 *  monomorphicTarget/nearestConcreteSuper + node-id methodId/paramTypeList family + declaresConcrete).
 *  EXTRACTED verbatim from Candor.java (refactor P4); reads shared state via the static import. See
 *  REFACTOR_PLAN.md + SEALED_CHA_PLAN.md. */
final class Cha {
    /** A PROVABLY-CLOSED dispatch owner: an enum. An enum cannot be extended (the JVM forbids it),
     *  so its only subtypes are its own constant bodies — synthetic subclasses compiled into the same
     *  class file, ALL of which `chaTargets` already enumerates. A dispatch over it therefore resolves
     *  EXACTLY to that finite, fully-visible set, and resolving all of them is sound even past
     *  CHA_FANOUT_LIMIT. This is NOT the open-hierarchy smear the bound guards against: an open abstract
     *  class or interface (scala-library's hundreds of collection impls; a DI-wired strategy) may have an
     *  external/unseen subtype, so its broad fan-out stays honest Unknown — but a closed enum has none.
     *  The high-value case is the enum STATE MACHINE with per-constant method bodies (jsoup
     *  HtmlTreeBuilderState/TokeniserState: 26/68 constants, a mutually-recursive cluster the >12 drop
     *  turned into a CIRCULAR Unknown that smeared ~600 functions; the true effect-union is pure). */
    static boolean isClosedEnumOwner(String internal) {
        ClassNode cn = ctx.byName.get(internal);
        return cn != null && ((cn.access & Opcodes.ACC_ENUM) != 0 || "java/lang/Enum".equals(cn.superName));
    }

    /** A dispatch owner whose implementor set is PROVABLY COMPLETE + finite + fully visible — so resolving
     *  ALL of `chaTargets` past CHA_FANOUT_LIMIT is sound + EXACT (no open-hierarchy smear). Two cases:
     *  (1) a closed ENUM (constants are the whole target set), or (2) a fully-closed, fully-visible SEALED
     *  type (Java 17+ — its `permits` list is the complete subtype set). The sealed case generalizes the enum
     *  carve-out to the modern sealed+record ADT pattern. See SEALED_CHA_PLAN.md. */
    static boolean isClosedHierarchy(String internal) {
        return isClosedEnumOwner(internal) || isFullyClosedSealed(internal);
    }

    /** True iff {@code internal} is a SEALED type whose ENTIRE transitive permitted-subtype closure is (a)
     *  fully VISIBLE (every permit in `byName` — else candor can't analyze its effect → silent-pure) and (b)
     *  fully CLOSED (every permit is `final`/record OR itself a closed sealed type — a `non-sealed` permit
     *  re-opens the hierarchy to unseen external subtypes). Either gate failing → false → the dispatch stays
     *  bounded (honest Unknown). Memoized + cycle-guarded (a sealed cycle is impossible in valid bytecode but
     *  cheap to guard against malformed input). */
    static boolean isFullyClosedSealed(String internal) {
        Boolean memo = ctx.sealedClosedMemo.get(internal);
        if (memo != null) return memo;
        ClassNode cn = ctx.byName.get(internal);
        boolean r = cn != null && cn.permittedSubclasses != null && !cn.permittedSubclasses.isEmpty()
                && closedAndVisible(internal, new HashSet<>());
        ctx.sealedClosedMemo.put(internal, r);
        return r;
    }

    /** True iff {@code internal} is a SEALED type whose transitive permit-closure includes a subtype absent
     *  from `byName`. Then candor KNOWS (from the `permits` attribute) a specific subtype exists that it
     *  cannot analyze → a dispatch over it is PROVABLY incomplete and must disclose Unknown, EVEN ON THE
     *  NARROW path (where the visible subset would otherwise read complete and silent-pure). This is the
     *  provable-incompleteness case, distinct from an OPEN hierarchy (where an external subtype MIGHT exist
     *  but candor can't prove it — the accepted bounded-CHA tradeoff). Fixes a pre-existing silent-pure the
     *  sealed-CHA review surfaced. */
    static boolean sealedHasUnseenPermit(String internal) {
        Boolean memo = ctx.sealedUnseenMemo.get(internal);
        if (memo != null) return memo;
        ClassNode cn = ctx.byName.get(internal);
        boolean r = cn != null && cn.permittedSubclasses != null && !cn.permittedSubclasses.isEmpty()
                && permitClosureHasUnseen(internal, new HashSet<>());
        ctx.sealedUnseenMemo.put(internal, r);
        return r;
    }

    private static boolean permitClosureHasUnseen(String internal, Set<String> seen) {
        if (!seen.add(internal)) return false;
        ClassNode cn = ctx.byName.get(internal);
        if (cn == null) return true;                                  // this permit itself is off-classpath
        if (cn.permittedSubclasses == null) return false;            // a visible leaf
        for (String p : cn.permittedSubclasses)
            if (!ctx.byName.containsKey(p) || permitClosureHasUnseen(p, seen)) return true;
        return false;
    }

    /** Walk a sealed type's permitted-subtype closure, requiring every permit be visible (in byName) AND
     *  closed (final/record, or a sealed type that is itself closedAndVisible). `seen` guards cycles. */
    private static boolean closedAndVisible(String internal, Set<String> seen) {
        if (!seen.add(internal)) return true;   // already on the walk path (cycle) — don't re-fail it
        ClassNode cn = ctx.byName.get(internal);
        if (cn == null) return false;           // gate 2: an unseen type can't be analyzed
        if (cn.permittedSubclasses == null || cn.permittedSubclasses.isEmpty())
            // a leaf: must be final (incl. records, which are ACC_FINAL) — else it is `non-sealed` (open).
            return (cn.access & Opcodes.ACC_FINAL) != 0;
        for (String p : cn.permittedSubclasses) {
            if (!ctx.byName.containsKey(p)) return false;        // gate 2: a permit not on the classpath
            if (!closedAndVisible(p, seen)) return false;    // gate 1+2 recursively
        }
        return true;
    }

    static boolean isChaExemptMethod(String owner, String name, String desc) {
        // Object protocol — conventionally pure (formatting / equality / hashing / ordering).
        if (isObjectProtocolExempt(name, desc)) return true;
        // Function-interface invocation: Kotlin FunctionN.invoke; Scala FunctionN/PartialFunction.apply
        // + the java8 JFunction SAM bridges; Groovy Closure.call/doCall.
        if (owner.startsWith("kotlin/jvm/functions/") && name.equals("invoke")) return true;
        if ((owner.startsWith("scala/Function") || owner.equals("scala/PartialFunction")
                || owner.startsWith("scala/runtime/java8/JFunction")) && name.equals("apply")) return true;
        if (owner.equals("groovy/lang/Closure") && (name.equals("call") || name.equals("doCall"))) return true;
        // NB: java.lang.Runnable.run / java.util.concurrent.Callable.call are NOT exempt. They can be
        // NAMED project classes (not just lambdas), and an unpinned `r.run()` over them was silently pure
        // (the §7.13 fuzzer's task_unpinned form caught it). They now go through normal bounded CHA —
        // narrow → fan out to the actual impls, broad → Unknown — like any other interface dispatch. A
        // lambda's own effect is still captured at its creation site (closure attribution), so this only
        // adds the sound over-approximation for genuinely-unresolvable task receivers. The Kotlin/Scala/
        // Groovy FUNCTION-object dispatch above stays exempt: there the impls are lambda classes whose
        // effect IS captured at creation, and fanning out smears (the documented FunctionN.invoke case).
        return false;
    }

    /** Direct supertypes (internal names) of an EXTERNAL class, read off candor's runtime classpath via
     *  ASM. JDK classes (java/util/ArrayList → AbstractList → List/Collection) resolve; the SCANNED
     *  project's own third-party deps are not on candor's classpath, so they fail to load and yield nothing
     *  — the same sound under-approximation as before (never fabrication). Never throws. Cached per name. */
    static List<String> externalSupers(String internal) {
        List<String> cached = ctx.externalSupersCache.get(internal);
        if (cached != null) return cached;
        List<String> out = new ArrayList<>();
        try {
            ClassReader cr = new ClassReader(internal);
            if (cr.getSuperName() != null) out.add(cr.getSuperName());
            for (String i : cr.getInterfaces()) out.add(i);
        } catch (Throwable t) { /* not on candor's classpath / unreadable → no supers (sound) */ }
        ctx.externalSupersCache.put(internal, out);
        return out;
    }

    /** Build the reverse-subtype index ONCE: owner -> loaded classes that are owner-or-a-subtype, in
     *  `ALL` order. For each loaded class `c` we record `c.name` against itself and against every
     *  transitive supertype of `c.name` — the exact inverse of chaTargets()'s old per-class predicate
     *  `c.name == owner || transSupers(c.name).contains(owner)`. Iterating `classes` (== `ALL`) in
     *  order makes every owner's candidate list identical, element-for-element AND in the same order,
     *  to the old ALL-scan that filtered by that predicate. Reuses the memoized transSupers. */
    static void buildSubtypeIndex(List<ClassNode> classes) {
        for (ClassNode c : classes) {
            // self: the `c.name == owner` arm. (No dedupe needed — a class appears once in `classes`,
            // and `c.name ∉ transSupers(c.name)` for a well-formed acyclic chain; transSupers seeds the
            // cache before recursing so a self-cycle can't add c.name to its own super set.)
            ctx.subtypeIndex.computeIfAbsent(c.name, k -> new ArrayList<>()).add(c.name);
            // every transitive supertype: the `transSupers(c.name).contains(owner)` arm.
            for (String sup : transSupers(c.name))
                ctx.subtypeIndex.computeIfAbsent(sup, k -> new ArrayList<>()).add(c.name);
        }
    }

    /** CHA: project subtypes-or-self of `owner` that provide a concrete (name,desc) impl. */
    static List<String> chaTargets(String owner, String name, String desc) {
        Set<String> out = new LinkedHashSet<>();
        // O(subtypes-of-owner) via the precomputed reverse index instead of scanning ALL classes. The
        // candidate set + its order are identical to the old `for (ClassNode c : ALL) if (c.name==owner
        // || transSupers(c.name).contains(owner))` filter (see buildSubtypeIndex), so `out` — and thus
        // cha.size(), the ≤CHA_FANOUT_LIMIT cap, the Unknown-on-overflow, and the edge set — are byte-
        // for-byte unchanged.
        for (String cName : ctx.subtypeIndex.getOrDefault(owner, List.of())) {
            ClassNode c = ctx.byName.get(cName);
            if (declaresConcrete(c, name, desc)) {
                out.add(methodId(c.name.replace('/', '.'), name, desc));
            } else {
                // c is owner-or-a-subtype that INHERITS the impl from its OWN superchain — a concrete
                // GRANDPARENT (the ubiquitous `Foo` / `Foo$AbstractBase` library pattern, where the impl
                // lives in a shared base like `FilterableList$AbstractBase`). The receiver-type-only and
                // owner-superchain checks both miss it, because the impl is reached by going DOWN from
                // owner to c then UP c's chain. Resolve it so the dispatch isn't a false Unknown. (Found
                // by the gradle-cache sweep: byte-buddy `MethodList.filter`/`getOnly` were 600+ false
                // Unknowns inside byte-buddy's own jar — pure methods, so precision, not soundness.)
                String impl = nearestConcreteSuper(c.name, name, desc);
                if (impl != null) out.add(impl);
            }
        }
        // owner itself inherits a concrete from a SUPER (a default on a super-interface) with no subtype
        // contributing — the original single-receiver inherited-concrete case.
        if (out.isEmpty()) {
            String impl = nearestConcreteSuper(owner, name, desc);
            if (impl != null) out.add(impl);
        }
        return new ArrayList<>(out);
    }

    /** The single method a dispatch on a PROVABLY-`new recv` receiver actually invokes: `recv` itself if it
     *  declares a concrete `(name,desc)`, else `recv`'s nearest concrete superclass that does — exactly how
     *  the JVM resolves virtual dispatch on a known concrete type. Used to NARROW an invokevirtual on a
     *  monomorphic receiver, replacing the CHA sibling fan-out with the one real target. Returns null only
     *  if no concrete impl is visible in `recv`'s own chain (then the caller keeps the CHA — sound). */
    static String monomorphicTarget(String recv, String name, String desc) {
        ClassNode c = ctx.byName.get(recv);
        if (c != null && declaresConcrete(c, name, desc))
            return methodId(recv.replace('/', '.'), name, desc);
        return nearestConcreteSuper(recv, name, desc);
    }

    /** The concrete `(name, desc)` declaration `internal` would invoke via inheritance: the first one
     *  found walking its supertype chain (excludes `internal` itself — the caller checks that). */
    static String nearestConcreteSuper(String internal, String name, String desc) {
        for (String sup : transSupers(internal)) {
            ClassNode c = ctx.byName.get(sup);
            if (c != null && declaresConcrete(c, name, desc)) return methodId(sup.replace('/', '.'), name, desc);
        }
        return null;
    }

    /** The node/edge id for a project method. UNIQUE name in its class → bare `class.method` (so every
     *  non-overloaded method, including every conformance fixture matched by leaf name, is unchanged).
     *  OVERLOADED name (>1 descriptor under `class.method`) → a stable per-overload suffix derived from
     *  the descriptor's param types (`HmacUtils.hmac(byte[])`), so a pure overload no longer unions an
     *  effectful sibling's effect. Keyed by the DECLARING class so the node-build site (the method's own
     *  class) and every edge site (call-site `owner`/CHA-resolved class) agree on the same id. A
     *  desc/owner candor can't see (a non-project owner, an unknown descriptor) falls back to the bare
     *  name — harmless, since those never key a project node. */
    static String methodId(String dottedClass, String name, String desc) {
        Set<String> descs = ctx.overloadDescs.get(dottedClass + "." + name);
        // Bare name unless this is a genuine overload with a parseable METHOD descriptor. The `(` guard is
        // defence-in-depth: a non-method descriptor (a field handle that slipped a caller's guard) must
        // never reach Type.getArgumentTypes, which overruns and crashes the scan on anything without `()`.
        if (descs == null || descs.size() <= 1 || desc == null || !desc.startsWith("("))
            return dottedClass + "." + name;
        String suffix = paramTypeList(desc);
        // Simple param names CAN collide across overloads whose param types share a SIMPLE name from
        // different packages (`f(a.User)` vs `f(b.User)` both → "User") — Java forbids same-ERASED-descriptor
        // overloads, not same-simple-name ones. Two overloads sharing a node id UNION their effects →
        // fabrication on the pure sibling (and every caller of it). When the readable suffix is ambiguous,
        // fall back to FULLY-QUALIFIED param names (unique per descriptor); the common non-colliding case
        // keeps the short, readable form.
        boolean ambiguous = descs.stream()
                .filter(d -> d != null && d.startsWith("(") && !d.equals(desc))
                .anyMatch(d -> paramTypeList(d).equals(suffix));
        return dottedClass + "." + name + "(" + (ambiguous ? paramTypeListFq(desc) : suffix) + ")";
    }

    /** Like {@link #paramTypeList} but with FULLY-QUALIFIED object names — the collision-free disambiguator
     *  used only when simple names clash across a class's overloads. */
    static String paramTypeListFq(String desc) {
        StringBuilder sb = new StringBuilder();
        try {
            for (Type t : Type.getArgumentTypes(desc)) {     // fail soft on a malformed descriptor (see paramTypeList)
                if (sb.length() > 0) sb.append(',');
                sb.append(fqTypeName(t));
            }
        } catch (Throwable t) { return ""; }
        return sb.toString();
    }

    static String fqTypeName(Type t) {
        if (t.getSort() == Type.ARRAY) return fqTypeName(t.getElementType()) + "[]".repeat(t.getDimensions());
        return t.getClassName(); // OBJECT → fully-qualified (a.User); primitive → int/long/...
    }

    /** A method descriptor's argument types as a readable, comma-separated list of source-form names
     *  (`(MessageDigest,byte[])` -> `MessageDigest,byte[]`) — the human-facing overload disambiguator.
     *  Stable per descriptor and collision-free across a class's overloads (Java forbids two overloads
     *  with the same erased parameter types). */
    static String paramTypeList(String desc) {
        StringBuilder sb = new StringBuilder();
        // Type.getArgumentTypes validates the descriptor lazily and THROWS on a malformed one (e.g. a
        // missing `;` — ASM stores the raw UTF8 and doesn't check at parse time). Fail soft: a bad
        // descriptor yields an empty suffix rather than aborting the scan (the per-class guard in runScan
        // also catches it, but keeping methodId total is cheaper and keeps the id stable-ish).
        try {
            for (Type t : Type.getArgumentTypes(desc)) {
                if (sb.length() > 0) sb.append(',');
                sb.append(shortTypeName(t));
            }
        } catch (Throwable t) { return ""; }
        return sb.toString();
    }

    /** A Type as its short source name: `byte[]`, `MessageDigest` (simple name for objects, so the
     *  suffix stays readable), `int`, etc. */
    static String shortTypeName(Type t) {
        if (t.getSort() == Type.ARRAY)
            return shortTypeName(t.getElementType()) + "[]".repeat(t.getDimensions());
        if (t.getSort() == Type.OBJECT) {
            String cn = t.getClassName();
            int dot = cn.lastIndexOf('.');
            return dot >= 0 ? cn.substring(dot + 1) : cn;
        }
        return t.getClassName(); // primitives: int, long, byte, ...
    }

    static boolean declaresConcrete(ClassNode c, String name, String desc) {
        for (MethodNode mn : c.methods)
            if (mn.name.equals(name) && mn.desc.equals(desc) && (mn.access & Opcodes.ACC_ABSTRACT) == 0)
                return true;
        return false;
    }

    static boolean isProjectIfaceOrAbstract(String internal) {
        ClassNode cn = ctx.byName.get(internal);
        return cn != null && (cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT)) != 0;
    }

    /** Does the PROJECT itself declare `(name, desc)` somewhere in `owner`'s own hierarchy (owner or a
     *  project supertype)? Distinguishes a genuine project abstraction whose impl is missing (→ honest
     *  Unknown) from a framework method merely INHERITED by a project type, which resolves to a
     *  superclass candor never loaded and is just an ordinary external call. byName holds only project
     *  classes, so a framework-only method (declared solely in an unloaded superclass) returns false. */
    static boolean projectDeclaresMethod(String owner, String name, String desc) {
        Set<String> types = new HashSet<>(transSupers(owner));
        types.add(owner);
        for (String t : types) {
            ClassNode c = ctx.byName.get(t);
            if (c == null) continue; // framework supertype — not a project declaration
            for (MethodNode mn : c.methods)
                if (mn.name.equals(name) && mn.desc.equals(desc)) return true;
        }
        return false;
    }
}
