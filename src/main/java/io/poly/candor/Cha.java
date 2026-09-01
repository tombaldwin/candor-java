package io.poly.candor;

import java.util.*;
import java.util.stream.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Frame;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Interp.*;

/** CHA / dispatch resolution. The bounded-CHA closed-hierarchy carve-out (enum + fully-closed-visible
 *  sealed families: isClosedHierarchy/isFullyClosedSealed/sealedHasUnseenPermit + the two private
 *  closure walks) and the dispatch-resolution band (externalSupers/buildSubtypeIndex/chaTargets/
 *  monomorphicTarget/nearestConcreteSuper + node-id methodId/paramTypeList family + declaresConcrete).
 *  EXTRACTED verbatim from Candor.java (refactor P4); reads shared state via the static import. See
 *  REFACTOR_PLAN.md + SEALED_CHA_PLAN.md. */
public final class Cha { // public only so the verify -javaagent can reuse the overload-disambiguating methodId; all other members stay package-private
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
        ClassNode cn = ctx().byName.get(internal);
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
        Boolean memo = ctx().sealedClosedMemo.get(internal);
        if (memo != null) return memo;
        ClassNode cn = ctx().byName.get(internal);
        boolean r = cn != null && cn.permittedSubclasses != null && !cn.permittedSubclasses.isEmpty()
                && closedAndVisible(internal, new HashSet<>());
        ctx().sealedClosedMemo.put(internal, r);
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
        Boolean memo = ctx().sealedUnseenMemo.get(internal);
        if (memo != null) return memo;
        ClassNode cn = ctx().byName.get(internal);
        boolean r = cn != null && cn.permittedSubclasses != null && !cn.permittedSubclasses.isEmpty()
                && permitClosureHasUnseen(internal, new HashSet<>());
        ctx().sealedUnseenMemo.put(internal, r);
        return r;
    }

    private static boolean permitClosureHasUnseen(String internal, Set<String> seen) {
        if (!seen.add(internal)) return false;
        ClassNode cn = ctx().byName.get(internal);
        if (cn == null) return true;                                  // this permit itself is off-classpath
        if (cn.permittedSubclasses == null) return false;            // a visible leaf
        for (String p : cn.permittedSubclasses)
            if (!ctx().byName.containsKey(p) || permitClosureHasUnseen(p, seen)) return true;
        return false;
    }

    /** Walk a sealed type's permitted-subtype closure, requiring every permit be visible (in byName) AND
     *  closed (final/record, or a sealed type that is itself closedAndVisible). `seen` guards cycles. */
    private static boolean closedAndVisible(String internal, Set<String> seen) {
        if (!seen.add(internal)) return true;   // already on the walk path (cycle) — don't re-fail it
        ClassNode cn = ctx().byName.get(internal);
        if (cn == null) return false;           // gate 2: an unseen type can't be analyzed
        if (cn.permittedSubclasses == null || cn.permittedSubclasses.isEmpty())
            // a leaf: must be final (incl. records, which are ACC_FINAL) — else it is `non-sealed` (open).
            return (cn.access & Opcodes.ACC_FINAL) != 0;
        for (String p : cn.permittedSubclasses) {
            if (!ctx().byName.containsKey(p)) return false;        // gate 2: a permit not on the classpath
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

    /** Direct supertypes of `internal`, ALSO consulting a chained dependency's own published hierarchy
     *  ({@link Loader#loadDepHierarchy}) — the dep-facing analogue of {@link #externalSupers}.
     *
     *  <p><b>Why this is a separate entry point rather than a line inside {@code externalSupers}.</b> That
     *  chokepoint feeds {@link #buildSubtypeIndex}, and widening it there is NOT additive in the direction
     *  that matters. A project class `P extends DepBase`, where `DepBase implements Runnable` in the
     *  dependency, would newly land in `subtypeIndex[Runnable]`; a `r.run()` site on a `Runnable`-typed
     *  receiver would then find a non-empty CHA and take the resolved-narrow path — and the JDK-functional-SAM
     *  gate that raises the honest `callback:` Unknown fires only on an EMPTY target set. So a call whose real
     *  receiver is a lambda or one of the dependency's OWN implementers would go from a disclosed Unknown to
     *  a confident purity claim: a silent under-report manufactured by a change whose whole argument was that
     *  it only adds knowledge. (The same posture already applies to a class implementing `Runnable`
     *  DIRECTLY — that is pre-existing and separately argued; it is not a licence to extend its reach
     *  silently as a side effect of reading a sidecar.)
     *
     *  <p>So the hierarchy answers questions ABOUT DEPENDENCY TYPES — is this dep type a `java.io` stream,
     *  what does it inherit from its own supers — at the two dep-facing walks, and does not enter the
     *  project's subtype index. Widening those two is additive: they can only find MORE dependency bodies
     *  to inherit.
     *
     *  <p><b>NOW MEASURED, so nobody has to re-derive it — and BOTH numbers matter.</b> The paragraph above
     *  was an argument; a shadow subtype index built from the sidecar and compared against the real one at
     *  every polymorphic dispatch site, over seven chained real jar pairs (68 539 sites), makes it a
     *  measurement. 737 sites go empty-CHA -> non-empty; at report level that is 113 gains and <b>8
     *  LOSSES</b> — 7 functions lose a disclosed {@code Unknown} and one loses a concrete {@code Net}.
     *  httpclient's {@code IdleConnectionHandler.closeExpiredConnections} and three siblings go from
     *  {@code ['Unknown']} to a confident purity claim on a method that closes network connections: the
     *  project's connection adapters get filed under {@code HttpConnection}, the CHA stops being empty, and
     *  the target set that replaces the disclosure is not the true one, because httpcore's OWN implementers
     *  are outside the scan. A partial answer wearing a complete one's clothes.
     *
     *  <p><b>The hazard is real; the GATE named above is not the one that fired.</b> Instrumented per site,
     *  the JDK-functional-SAM `callback:` branch this paragraph reasons about suppressed <b>zero</b> across
     *  the seven pairs, as did the missing-project-impl branch. What suppressed was half 1
     *  ({@link Candor#untypedDepReceiver}), whose conjunct 4 is the same "the project CHA is empty" test.
     *  The argument generalises and the illustration did not; the property to protect is <i>every</i>
     *  Unknown branch conditioned on an empty target set, not the one that was easiest to picture.
     *
     *  <p><b>And it does not buy what it is usually reached for.</b> The abstract-dep-CLASS row was the
     *  standing argument for widening here, and widening cannot close it: {@link #buildSubtypeIndex} files
     *  PROJECT {@code ClassNode}s and {@link #chaTargets} needs one to test {@link #declaresConcrete}, so a
     *  DEPENDENCY's implementer never enters the index however wide the hierarchy gets — the two-tree
     *  fixture is exit 0 in that arm too. That row is closed producer-side instead, by
     *  {@code ReportWriter.appendInterfaceUnions}' ACC_ABSTRACT arm.
     *
     *  <p><b>One ordering fact worth knowing before trusting the hazard is dormant.</b> As a literal
     *  one-liner inside {@code externalSupers} the widening is INERT today, because {@code runScan} builds
     *  the subtype index BEFORE {@code loadCrossDeps} populates {@code depSupers}. The first measurement
     *  arm reported byte-identical zero cost for exactly that reason, and it pointed the flattering way.
     *  So the numbers above are from an arm with the load hoisted — and a future reordering of
     *  {@code runScan} would arm the hazard silently. {@code CrossScanBoundaryTest}'s assertion that
     *  {@code externalSupers} on a sidecar type still returns empty is the guard that survives either
     *  order; keep it. */
    static List<String> depDirectSupers(String internal) {
        List<String> dep = ctx().depSupers.get(internal);
        if (dep != null) {
            if (System.getenv("CANDOR_DEPHIER_DEBUG") != null)
                System.err.println("DEPHIER hit " + internal + " -> " + dep);
            return dep;
        }
        return externalSupers(internal);
    }

    /** An external type's direct supertypes, kept SPLIT the way JVM method resolution needs them:
     *  {@code superClass} (null only for {@code java/lang/Object}, which has none) and the directly
     *  implemented {@code interfaces}. {@code all} is the flattened superclass-then-interfaces view
     *  {@link #externalSupers} has always returned, precomputed so the hot path allocates nothing. */
    record ExtSupers(String superClass, List<String> interfaces, List<String> all) {
        static ExtSupers of(String superClass, List<String> interfaces) {
            List<String> all = new ArrayList<>();
            if (superClass != null) all.add(superClass);
            all.addAll(interfaces);
            return new ExtSupers(superClass, List.copyOf(interfaces), List.copyOf(all));
        }
        static final ExtSupers NONE = of(null, List.of());
    }

    /** Direct supertypes (internal names) of an EXTERNAL class, read off candor's runtime classpath via
     *  ASM. JDK classes (java/util/ArrayList → AbstractList → List/Collection) resolve; the SCANNED
     *  project's own third-party deps are not on candor's classpath, so they fail to load and yield nothing
     *  — the same sound under-approximation as before (never fabrication). Never throws. Cached per name. */
    static List<String> externalSupers(String internal) {
        return externalSupersSplit(internal).all();
    }

    /** {@link #externalSupers}, with the superclass still distinguishable from the interfaces — the one
     *  fact JVM method resolution turns on and the flattened list throws away. Cached per name. */
    static ExtSupers externalSupersSplit(String internal) {
        ExtSupers cached = ctx().externalSupersCache.get(internal);
        if (cached != null) return cached;
        // DELIBERATELY NOT consulting the chained dependency's hierarchy here — see {@link #depDirectSupers}
        // for where it IS consulted and why this chokepoint is the wrong one.
        ExtSupers out = ExtSupers.NONE;
        try {
            ClassReader cr = new ClassReader(internal);
            out = ExtSupers.of(cr.getSuperName(), List.of(cr.getInterfaces()));
        } catch (Throwable t) {
            // Can't read the .class bytes off the classpath. On the JVM this means a class not on
            // candor's classpath (e.g. a project's third-party dep) → no supers (sound under-approx). In a
            // GraalVM NATIVE IMAGE there are no .class files at all, so even JDK classes land here — fall
            // back to the build-time JDK supertype index so JDK hierarchies still resolve (native == jar).
            // Gate to NATIVE only: on the JVM the only behavior is ClassReader-or-empty (host-independent,
            // and the ~270KB index is never loaded); the index can't make the JVM's output host-dependent.
            //
            // The index is written as `superName interface…` by the SAME ClassReader (build.gradle.kts
            // `generateJdkSupertypes`), and `superName` is null only for `java/lang/Object` — whose entry
            // is then empty and never written. So a present entry's head IS the superclass, and native
            // splits identically to the JVM rather than degrading to "kind unknown".
            if (IN_NATIVE_IMAGE) {
                List<String> idx = JdkSupers.MAP.get(internal);
                if (idx != null && !idx.isEmpty())
                    out = ExtSupers.of(idx.get(0), idx.subList(1, idx.size()));
            }
        }
        ctx().externalSupersCache.put(internal, out);
        return out;
    }

    /** Every supertype of {@code start}, {@code start} ITSELF FIRST, in JVM METHOD-RESOLUTION ORDER: the
     *  whole SUPERCLASS CHAIN before any interface, then interfaces breadth-first. {@code java/lang/Object}
     *  is excluded — no walk here has anything to read from it.
     *
     *  <p><b>THE DEFECT THIS EXISTS TO PREVENT, and it was live at four sites.</b> Each of those walks
     *  polled ONE queue seeded from a list that flattened "superclass" and "interfaces" together, so the
     *  traversal interleaved the two BY DEPTH and a nearer interface {@code default} settled a descriptor
     *  before the superclass body was reached. Java resolution does not work that way — JLS 15.12.2.5 /
     *  8.4.8: a concrete method inherited from a superclass beats an interface {@code default} AT ANY
     *  DEPTH. Given
     *  <pre>
     *    class Root { public void write(byte[] b) { … writes a file … } }
     *    class Mid extends Root {}
     *    interface Trace { default void write(byte[] b) {} }        // pure
     *    class Half extends Mid implements Trace {}
     *  </pre>
     *  a depth-ordered walk from {@code Half} visits {Mid, Trace}; {@code Mid} declares no {@code write},
     *  {@code Trace} does, the descriptor is settled, and {@code Root.write} at depth 2 is skipped as
     *  already decided. The JVM runs {@code Root.write}. The caller was reported with NO {@code Fs} — a
     *  silent under-report — while simultaneously being charged {@code Trace}'s empty effects.
     *
     *  <p>{@code useDepHierarchy} decides whether a type candor's classpath cannot load falls back to a
     *  CHAINED DEPENDENCY's published hierarchy ({@link #depDirectSupers}) — true for the dep-facing walks,
     *  false for the project-facing ones. See that method for why the two are deliberately separate.
     *
     *  <p><b>THE DEPENDENCY'S OWN CHAIN, and the residual that closed it.</b> The consumer's OWN classes
     *  state their superclass and their interfaces separately, so a project class extending a dep class and
     *  implementing a dep interface always resolved exactly. What stayed depth-ordered was a chain lying
     *  ENTIRELY inside the dependency — a dep interface {@code default} shadowing a dep superclass body two
     *  hops up — because {@code ReportWriter#writeHierarchy} wrote a sorted {@code TreeSet} that threw the
     *  kinds away. It now also writes {@link ReportWriter#SUPERCLASS_KEY}, a sibling key in the reserved
     *  {@code @} metadata namespace whose value is a FLAT ARRAY of {@code [type, superclass]} pairs — an
     *  array precisely so that EVERY value in the sidecar is one and a strictly typed reader (candor-rust's,
     *  which models the whole file as {@code BTreeMap<String, Vec<String>>}) still parses it. A consumer
     *  that does not know the key sees one phantom entry it never looks up, so the rung needs no version
     *  gate on either side; see {@code SUPERCLASS_KEY} for the reader survey that produced that shape.
     *
     *  <p><b>What happens where the split is STILL not knowable</b> — a sidecar written before that marker,
     *  or by an engine that writes none. Those types are walked in whichever phase the walk is already in,
     *  which is precisely the behaviour all four walks had before, so an unknown region is never made worse
     *  while every marked, project and classpath region becomes exact. The fallback is that behaviour and
     *  not a reading of the list, deliberately: taking an unmarked list as all-INTERFACES would push a real
     *  superclass BELOW an interface and manufacture the very under-report this ordering exists to close.
     *  {@code CrossScanBoundaryTest}'s {@code anUnmarkedHierarchySidecarKeepsEXACTLYTodaysDepthOrderedAnswer}
     *  is that assertion, verified to catch by mutation.
     *
     *  <p>The other mis-reading — forcing an unmarked list into the CLASS phase — is NOT observable, and
     *  saying so is worth more than implying a symmetry that does not hold. It differs from this branch only
     *  for a kind-unknown type polled from the INTERFACE queue, whose supertypes are necessarily interfaces;
     *  promoting them would visit them before the remaining interfaces, and for that to change an answer two
     *  unrelated interfaces would have to supply the same method — which javac rejects outright. A type
     *  reached THROUGH an interface stays in the interface phase whatever its own split says, because a
     *  class is never a supertype of an interface. */
    static List<String> resolutionOrder(String start, boolean useDepHierarchy) {
        if (start == null) return List.of();
        AnalysisContext c = ctx();
        String key = (useDepHierarchy ? "D\t" : "P\t") + start;
        List<String> memo = c.resolutionOrderCache.get(key);
        if (memo != null) return memo;
        List<String> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> classQ = new ArrayDeque<>();
        ArrayDeque<String> ifaceQ = new ArrayDeque<>();
        classQ.add(start);
        while (!classQ.isEmpty() || !ifaceQ.isEmpty()) {
            // The class phase runs to EXHAUSTION before the interface phase is entered — that ordering IS
            // the JLS rule. (Both queues grow as the walk proceeds; a superclass found while draining the
            // interface queue cannot exist, so this stays a two-phase drain and not an alternation.)
            boolean inClassPhase = !classQ.isEmpty();
            String t = (inClassPhase ? classQ : ifaceQ).poll();
            if (t == null || t.equals("java/lang/Object") || !seen.add(t)) continue;
            out.add(t);
            ClassNode cn = c.byName.get(t);
            String sup;
            List<String> ifaces;
            if (cn != null) {
                // A project ClassNode: ASM gives an INTERFACE `superName = java/lang/Object`, which the
                // Object skip above drops — so the same two fields split classes and interfaces alike and
                // no ACC_INTERFACE test is needed.
                sup = cn.superName;
                ifaces = cn.interfaces == null ? List.of() : cn.interfaces;
            } else {
                List<String> dep = useDepHierarchy ? c.depSupers.get(t) : null;
                if (dep != null) {
                    if (!c.depSplitKnown.contains(t)) {
                        // KIND UNKNOWN — a sidecar written before the `@superclass` marker. Walk them in
                        // whichever phase we are already in, which is exactly what shipped. Demoting them
                        // to the interface phase would push a real superclass BELOW an interface and
                        // manufacture the under-report this ordering exists to close (see the class doc for
                        // why the other mis-reading is not observable, rather than claiming a symmetry).
                        (inClassPhase ? classQ : ifaceQ).addAll(dep);
                        continue;
                    }
                    // KIND KNOWN: the sidecar says which entry is the superclass, so the JLS rule applies
                    // to a chain lying ENTIRELY inside the dependency too. No entry means the superclass is
                    // java/lang/Object and every listed supertype is an interface — a fact the writer
                    // records by omission, not a default.
                    sup = c.depSuperclass.get(t);
                    List<String> di = new ArrayList<>(dep.size());
                    for (String s : dep) if (!s.equals(sup)) di.add(s);
                    ifaces = di;
                    // fall through to the shared enqueue below, which keeps a type reached THROUGH an
                    // interface in the interface phase whatever its own split says.
                } else {
                    ExtSupers e = externalSupersSplit(t);
                    sup = e.superClass();
                    ifaces = e.interfaces();
                }
            }
            if (sup != null) (inClassPhase ? classQ : ifaceQ).add(sup);
            ifaceQ.addAll(ifaces);
        }
        List<String> result = List.copyOf(out);
        c.resolutionOrderCache.put(key, result);
        return result;
    }

    /** True iff running as a GraalVM native image. The {@code org.graalvm.nativeimage.imagecode} property
     *  is {@code "buildtime"}/{@code "runtime"} in an image and absent on a normal JVM — read directly so
     *  no graal-sdk dependency is needed. Gates the JDK supertype-index fallback to native only. */
    private static final boolean IN_NATIVE_IMAGE =
            System.getProperty("org.graalvm.nativeimage.imagecode") != null;

    /** The build-time JDK class -> direct super + interfaces index (gzipped resource), loaded once on
     *  first use (lazily, via class-init). Process-global + immutable — it's the constant JDK hierarchy,
     *  not per-scan state. Consulted ONLY in a native image (see {@link #IN_NATIVE_IMAGE}); on the JVM
     *  {@link #externalSupers} reads JDK classes via {@code ClassReader}, so this class is never loaded. */
    private static final class JdkSupers {
        static final Map<String, List<String>> MAP = load();

        private static Map<String, List<String>> load() {
            Map<String, List<String>> m = new HashMap<>();
            try (var in = Cha.class.getResourceAsStream("/candor/jdk-supertypes.idx.gz")) {
                if (in == null) return m;   // index not bundled (older build) → JVM path is unaffected
                try (var br = new java.io.BufferedReader(new java.io.InputStreamReader(
                        new java.util.zip.GZIPInputStream(in), java.nio.charset.StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        int sp = line.indexOf(' ');
                        if (sp < 0) continue;
                        m.put(line.substring(0, sp), List.of(line.substring(sp + 1).split(" ")));
                    }
                }
            } catch (java.io.IOException e) {
                // a corrupt/truncated index must not crash a scan — degrade to no-supers (the JVM path is
                // unaffected since it uses ClassReader; native loses JDK resolution but stays sound).
            }
            return m;
        }
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
            ctx().subtypeIndex.computeIfAbsent(c.name, k -> new ArrayList<>()).add(c.name);
            // every transitive supertype: the `transSupers(c.name).contains(owner)` arm.
            for (String sup : transSupers(c.name))
                ctx().subtypeIndex.computeIfAbsent(sup, k -> new ArrayList<>()).add(c.name);
        }
    }

    /** The (owner,name) key a field access should be recorded/looked-up under for
     *  {@link #collectFieldLambdaBindings}/{@link #fieldBoundImplementors}, NORMALIZED to the class that
     *  actually DECLARES the field — never the literal `owner` a PUTFIELD/GETFIELD/PUTSTATIC/GETSTATIC
     *  instruction names in its constant-pool entry, which javac frequently spells as the ACCESSING site's
     *  class instead: a `this.task` read inside a subclass whose field is inherited from a base names the
     *  SUBCLASS as owner even though the base's own write to the identical storage names the BASE; a static
     *  field read through a subtype reference (`Impl.CONST` where `CONST` is declared on an interface
     *  `Impl` implements) names the SUBTYPE; `super.field` names the syntactic superclass, which already
     *  happens to agree with the declaring class today but is not guaranteed to for a deeper chain. All of
     *  these are the SAME runtime storage location and MUST collapse to the same key on both the write side
     *  and the read side, or a binding proven clean at the write's key silently never matches the read's.
     *
     *  <p>Reuses {@link #resolutionOrder} — project method-resolution order, `owner` first, already
     *  handling the dep-hierarchy fallback for a field inherited across a chained dependency — rather than
     *  a second hand-rolled walk (the family's "ask the authority" rule: {@link #buildSubtypeIndex}/
     *  {@link #chaTargets} already trust it for methods, and field-vs-method resolution order agrees for
     *  the single-field-name case javac accepts — an ambiguous inherited field name is a compile error, so
     *  there is never a second candidate to choose between). The first type in that order whose own
     *  `ClassNode.fields` declares `name` IS the field's home; `owner` itself is visited first, so a
     *  same-class field (the common case) still resolves to itself with zero extra work.
     *
     *  <p><b>Falls back to the literal `owner` unchanged</b> when no class in the visible chain declares the
     *  field — the declaring class is off-classpath (a JDK/third-party field), or this walk simply cannot
     *  place it. That is the CONSERVATIVE direction: the two sides then key exactly as they did before this
     *  normalization existed, so the binding can still miss (falls through to the pre-existing CHA/Unknown
     *  behaviour) but never MERGES two accesses that do not, in fact, share storage. */
    static String fieldKey(String owner, String name) {
        for (String t : resolutionOrder(owner, false)) {
            ClassNode cn = ctx().byName.get(t);
            if (cn == null || cn.fields == null) continue;
            for (FieldNode fn : cn.fields)
                if (fn.name.equals(name)) return t + "#" + name;
        }
        return owner + "#" + name;
    }

    /** ⟨0.35⟩ SPEC §4 "A NON-EMPTY CANDIDATE SET IS NOT A COMPLETE ONE" — binds a functional-interface-
     *  typed FIELD to the LambdaMetafactory implementor(s) stored into it, so a dispatch through that
     *  field (`this.task = () -> s.write(); … task.run();`) resolves to the real body instead of falling
     *  silently pure the moment some UNRELATED class also implements the interface.
     *
     *  <p><b>Why this is keyed by FIELD, not by (interface, SAM) globally.</b> A first version of this fix
     *  registered every lambda/method-ref project-wide under (owner,name,desc) and unioned it straight
     *  into {@link #chaTargets}. It closed PART 87 but broke FOUR existing
     *  {@code PrivateFunctionalParamForwardingTest} cases: a private sink's sole functional PARAM is
     *  already resolved precisely by enumerating that (closed, nestmate-only) method's own call sites —
     *  {@code Candor.forwardable}/{@code fwdSinkPending} — and bails to honest Unknown the moment ANY call
     *  site passes an opaque value. A global per-interface union made {@code chaTargets} non-empty the
     *  instant ANY lambda anywhere in the project targeted that interface, which skipped the forwarding
     *  gate entirely (it only runs on an EMPTY candidate set) and silently dropped the opaque call site's
     *  Unknown — the exact cardinal-sin direction this project measures for fabrication-shaped fixes. A
     *  FIELD is a narrower, provable unit: {@code this.task}'s only possible runtime values are whatever
     *  was ever written to it, so completing THAT receiver from THAT field's own write-set cannot leak an
     *  unrelated field's or an unrelated call site's value the way a project-wide interface union can.
     *
     *  <p><b>How — CONTROL-FLOW-AWARE, not linear-adjacency (⟨0.35⟩ hardening, PART 87 vein).</b> An
     *  earlier version of this pass looked only at the single bytecode instruction immediately preceding
     *  the PUTFIELD/PUTSTATIC (skipping labels/line-numbers/frames) — a LINEAR lookback answering a
     *  CONTROL-FLOW question, and wrong whenever the stored value has more than one producer. The
     *  idiom {@code this.x = supplied != null ? supplied : defaultLambda;} (the default-or-caller-
     *  supplied-callback pattern — AWS SDK, HttpCore5, Spring Data Redis, Netflix Eureka all ship it)
     *  compiles to ONE putfield fed by TWO control-flow predecessors merging: javac places the default
     *  branch's lambda immediately before the putfield, so the linear check saw only the default and
     *  called the field cleanly bound — treating an arbitrary externally-supplied callback as if it could
     *  only ever be the safe default. That is the exact inverse of this method's own TAINT contract below.
     *
     *  <p>The fix reuses the engine's existing whole-method dataflow ({@link Interp.ProvInterpreter} via
     *  {@link Candor#cachedProvFrames}) rather than hand-rolling a second, weaker analysis over the same
     *  question ASM's frame MERGE already answers soundly elsewhere ({@link Interp#monomorphicReceiver}) —
     *  the family's "ask the authority, don't reimplement it" rule. One pass over every PUTFIELD/PUTSTATIC:
     *  the value about to be stored is the top of the {@code Frame<ProvValue>} recorded for that
     *  instruction — the frame ASM's {@code Analyzer} computes as the MERGE, over EVERY incoming
     *  control-flow edge, of whatever value reaches this program point, not merely whatever instruction is
     *  physically adjacent to it. {@code ProvInterpreter#merge} already collapses {@code lambdaTarget} to
     *  null the instant two incoming paths disagree (a lambda vs. a param, or two different lambdas), so a
     *  ternary/if-else whose arms push different producers is seen as what it is — taint, not a clean bind
     *  — while a single-producer write (the overwhelming common case) reads identically to the old check.
     *  {@code lambdaTarget} is set only when the producer is an INVOKEDYNAMIC(LambdaMetafactory) resolving
     *  to a PROJECT method ({@link Candor#indyLambdaTarget}, reused verbatim there too — covers an inline
     *  lambda's synthetic body, an unbound/bound method reference's real target, and a constructor
     *  reference's {@code <init>} identically). A method with no field writes never pays for the analyzer
     *  (computed lazily, first PUTFIELD/PUTSTATIC only); an unanalyzable method (native/abstract/bodiless,
     *  or a genuine {@code AnalyzerException} on malformed bytecode) taints every field it writes — sound:
     *  no binding is ever claimed without the dataflow proving it. {@link Candor#cachedProvFrames} shares
     *  its memo with the Phase-2 stream-origin pre-pass that runs right after this one, so a method touched
     *  by both pays for the analyzer once, not twice. Record each producer's key under {@link #fieldKey} —
     *  the SAME normalized key {@link Interp.ProvValue#fieldOrigin} carries for BOTH a GETFIELD and a
     *  GETSTATIC read (see {@code Interp.ProvInterpreter#unaryOperation}/{@code newOperation}), so the
     *  dispatch-site lookup is a direct map hit regardless of which class's bytecode the write and the read
     *  instructions each name as `owner` — see {@link #fieldKey}'s doc for why those two can legitimately
     *  disagree.
     *
     *  <p><b>Known, accepted precision loss (sound direction only).</b> A single putfield fed by a merge of
     *  TWO DIFFERENT clean project lambdas (`this.x = cond ? lambdaA : lambdaB;`, both recognisable) now
     *  taints rather than unions — {@code merge} cannot tell "two disagreeing clean lambdas" apart from
     *  "a clean lambda vs. an opaque value" from the merged value alone, and guessing wrong in the union
     *  direction risks exactly the fabrication this pass exists to prevent. This falls through to the
     *  pre-existing CHA/Unknown path, same as any other tainted field — under-precision, never fabrication.
     *  A field written from TWO DIFFERENT SITES (two constructors, or a constructor and a setter, each its
     *  own single-producer putfield) is unaffected and still unions both — see
     *  {@code fieldWrittenThroughSetterAndConstructorCompletesEvenWithUnrelatedImplementor}.
     *
     *  <p><b>TAINT, not silence, on an opaque write.</b> If ANY assignment to a field — anywhere in the
     *  project — is NOT a recognisable project lambda/method-ref (a parameter, a null, an external
     *  factory's return value, a second field's value…), the field is EXCLUDED from binding entirely,
     *  even if every OTHER assignment to it was clean: `this.task = external(); … this.task = () -> ...;`
     *  must not complete as if only the lambda could ever be there. An unbound field simply falls through
     *  to the engine's pre-existing behaviour (CHA/Unknown), unaffected by this pass — under-precision,
     *  never fabrication. A field assigned the SAME interface from TWO clean sites (two constructors, or
     *  two lambdas in one) unions both — correct: either could be the runtime value.
     *
     *  <p><b>Not registered, by construction (sound under-approximation):</b> a method reference to a
     *  method OUTSIDE the project (indyLambdaTarget's existing project-only filter) taints nothing by
     *  itself here — a field written ONLY via such calls degrades to "not recognised as a lambda", so it
     *  is simply never bound (falls through), same as any other opaque write.
     *
     *  <p><b>STATIC fields and INHERITED fields are now first-class, not a scope decision.</b> An earlier
     *  version of this doc called a static-only field binding "inert" because GETSTATIC only captured
     *  `declType`, never `fieldOrigin` — that was measured wrong: a static field's OWN class re-reading its
     *  own write is the ORDINARY case (`private static Runnable task; … task = () -> s.write(); … task.run();`
     *  in one class), and it silently dropped the effect just as completely as the instance-field shape this
     *  method was written to fix. {@code Interp.ProvInterpreter#newOperation} now tags a GETSTATIC's result
     *  with `fieldOrigin` the same way `unaryOperation` already tagged GETFIELD. Separately, {@link #fieldKey}
     *  normalizes both this write-side key and the read-side key to the DECLARING class, closing the
     *  inherited-field mismatch (a base class's write and a subclass's inherited read/write name DIFFERENT
     *  classes as `owner` in their own bytecode — see that method's doc for the full enumeration, including
     *  the reverse direction and interface constants read through an implementing subtype). */
    static void collectFieldLambdaBindings(List<ClassNode> classes) {
        Set<String> tainted = new HashSet<>();
        Map<String, List<String>> bindings = new HashMap<>();
        for (ClassNode cn : classes) {
            for (MethodNode mn : cn.methods) {
                AbstractInsnNode[] insns = mn.instructions.toArray();
                Frame<ProvValue>[] pf = null;      // computed lazily — only methods that write a field pay
                boolean pfAttempted = false;        // for the analyzer; null pf after an attempt means
                for (int i = 0; i < insns.length; i++) {   // unanalyzable, not "not yet computed"
                    if (!(insns[i] instanceof FieldInsnNode fi)) continue;
                    if (fi.getOpcode() != Opcodes.PUTFIELD && fi.getOpcode() != Opcodes.PUTSTATIC) continue;
                    String key = fieldKey(fi.owner, fi.name);
                    if (!pfAttempted) { pf = cachedProvFrames(cn, mn); pfAttempted = true; }
                    String impl = null;
                    if (pf != null) {
                        Frame<ProvValue> f = pf[i];   // the merged frame reaching THIS putfield, over every
                        if (f != null && f.getStackSize() > 0) {   // incoming control-flow edge — not just
                            ProvValue v = f.getStack(f.getStackSize() - 1);   // the physically preceding insn
                            if (v != null) impl = v.lambdaTarget;   // null unless EVERY reaching path agrees
                        }                                           // on the identical project lambda/ctor-ref
                    }
                    if (impl != null) bindings.computeIfAbsent(key, k -> new ArrayList<>()).add(impl);
                    else tainted.add(key);   // conservative: an unrecognised OR merge-disagreeing write
                }                             // voids the WHOLE field
            }
        }
        for (String t : tainted) bindings.remove(t);
        ctx().fieldLambdaBindings.putAll(bindings);
    }

    /** The bound implementor(s) of the receiver `min` dispatches on, if it is a GETFIELD read of a field
     *  {@link #collectFieldLambdaBindings} proved is written ONLY by project lambdas/method-refs — or null
     *  (not a field receiver, or that field carries at least one unrecognised write and was never bound).
     *  Mirrors {@link Interp#monomorphicReceiver}'s stack-slot arithmetic exactly (the receiver sits below
     *  the call's argument slots), reading {@code fieldOrigin} instead of {@code newType}. */
    static List<String> fieldBoundImplementors(Frame<ProvValue> f, MethodInsnNode min) {
        if (f == null) return null;
        int argSlots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) argSlots += a.getSize();
        int top = f.getStackSize();
        int recvIdx = top - 1 - argSlots;
        if (recvIdx < 0) return null;
        ProvValue rv = f.getStack(recvIdx);
        if (rv == null || rv.fieldOrigin == null) return null;
        return ctx().fieldLambdaBindings.get(rv.fieldOrigin);
    }

    /** CHA: project subtypes-or-self of `owner` that provide a concrete (name,desc) impl. */
    static List<String> chaTargets(String owner, String name, String desc) {
        AnalysisContext c = ctx();   // hoist the ThreadLocal lookup out of the per-subtype loop below
        // Memoize: chaTargets is pure over the fixed post-load hierarchy, and the same (owner,name,desc)
        // recurs across every call site that dispatches this method on this declared type. `name` never
        // contains '(' and `desc` always begins with it, so `name+desc` is an unambiguous join; '\t'
        // separates the owner (neither internal names nor descriptors contain a tab).
        String key = owner + '\t' + name + desc;
        List<String> memo = c.chaTargetsCache.get(key);
        if (memo != null) return memo;
        Set<String> out = new LinkedHashSet<>();
        // O(subtypes-of-owner) via the precomputed reverse index instead of scanning ALL classes. The
        // candidate set + its order are identical to the old `for (ClassNode c : ALL) if (c.name==owner
        // || transSupers(c.name).contains(owner))` filter (see buildSubtypeIndex), so `out` — and thus
        // cha.size(), the ≤CHA_FANOUT_LIMIT cap, the Unknown-on-overflow, and the edge set — are byte-
        // for-byte unchanged.
        for (String cName : c.subtypeIndex.getOrDefault(owner, List.of())) {
            ClassNode cn = c.byName.get(cName);
            if (declaresConcrete(cn, name, desc)) {
                out.add(methodId(cn.name.replace('/', '.'), name, desc));
            } else {
                // c is owner-or-a-subtype that INHERITS the impl from its OWN superchain — a concrete
                // GRANDPARENT (the ubiquitous `Foo` / `Foo$AbstractBase` library pattern, where the impl
                // lives in a shared base like `FilterableList$AbstractBase`). The receiver-type-only and
                // owner-superchain checks both miss it, because the impl is reached by going DOWN from
                // owner to c then UP c's chain. Resolve it so the dispatch isn't a false Unknown. (Found
                // by the gradle-cache sweep: byte-buddy `MethodList.filter`/`getOnly` were 600+ false
                // Unknowns inside byte-buddy's own jar — pure methods, so precision, not soundness.)
                String impl = nearestConcreteSuper(cn.name, name, desc);
                if (impl != null) out.add(impl);
            }
        }
        // owner itself inherits a concrete from a SUPER (a default on a super-interface) with no subtype
        // contributing — the original single-receiver inherited-concrete case.
        if (out.isEmpty()) {
            String impl = nearestConcreteSuper(owner, name, desc);
            if (impl != null) out.add(impl);
        }
        // ⟨0.35⟩ SPEC §4's lambda/method-ref completion does NOT live here — see
        // collectFieldLambdaBindings's doc for why a project-wide union at this chokepoint is unsound
        // (it broke the private functional-param forwarding tests) and fieldBoundImplementors for the
        // narrower, field-scoped mechanism virtualDispatch consults instead, before it ever reaches CHA.
        List<String> result = List.copyOf(out);   // immutable → safe to share across call sites
        c.chaTargetsCache.put(key, result);
        return result;
    }

    /** The single method a dispatch on a PROVABLY-`new recv` receiver actually invokes: `recv` itself if it
     *  declares a concrete `(name,desc)`, else `recv`'s nearest concrete superclass that does — exactly how
     *  the JVM resolves virtual dispatch on a known concrete type. Used to NARROW an invokevirtual on a
     *  monomorphic receiver, replacing the CHA sibling fan-out with the one real target. Returns null only
     *  if no concrete impl is visible in `recv`'s own chain (then the caller keeps the CHA — sound). */
    static String monomorphicTarget(String recv, String name, String desc) {
        ClassNode c = ctx().byName.get(recv);
        if (c != null && declaresConcrete(c, name, desc))
            return methodId(recv.replace('/', '.'), name, desc);
        return nearestConcreteSuper(recv, name, desc);
    }

    /** The concrete `(name, desc)` declaration `internal` would invoke via inheritance: the first one
     *  found walking its supertype chain in JVM RESOLUTION ORDER (excludes `internal` itself — the caller
     *  checks that).
     *
     *  <p>This walked {@link Candor#transSupers} — a {@code HashSet} — and returned the first
     *  {@code declaresConcrete} hit in HASH order, so it had no notion of the class chain at all. With a
     *  superclass body and an interface {@code default} both declaring the descriptor, which one it named
     *  was arbitrary: `class Half extends Mid implements Trace` where `Mid extends Root` and both
     *  `Root.go()` and `Trace.go()` are concrete resolved to {@code Trace.go} and `h.go()` read PURE,
     *  though the JVM runs {@code Root.go}. {@link #resolutionOrder} is the fix and the shared walk. */
    static String nearestConcreteSuper(String internal, String name, String desc) {
        AnalysisContext cx = ctx();   // hoist the ThreadLocal lookup out of the per-super loop
        List<String> order = resolutionOrder(internal, false);
        for (int i = 1; i < order.size(); i++) {          // index 0 is `internal` itself
            String sup = order.get(i);
            ClassNode c = cx.byName.get(sup);
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
        return methodId(dottedClass, name, desc, ctx().overloadDescs.get(dottedClass + "." + name));
    }

    /** Overload-disambiguating node id from an EXPLICIT descriptor set (the set of distinct JVM descriptors
     *  declared under {@code dottedClass.name}). The 3-arg form reads that set from the scan's overload index;
     *  the DYNAMIC HONESTY ORACLE's -javaagent has no scan context, so it collects the set per-class from the
     *  bytecode and calls this 4-arg form — so agent attribution keys MATCH the report's fn quals for
     *  overloaded methods (else an overloaded effectful method never matches its report entry and reads as a
     *  false cardinal-sin VIOLATION). PUBLIC + ctx-free for cross-package (io.poly.candor.verify) reuse. */
    public static String methodId(String dottedClass, String name, String desc, Set<String> descs) {
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
        ClassNode cn = ctx().byName.get(internal);
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
            ClassNode c = ctx().byName.get(t);
            if (c == null) continue; // framework supertype — not a project declaration
            for (MethodNode mn : c.methods)
                if (mn.name.equals(name) && mn.desc.equals(desc)) return true;
        }
        return false;
    }
}
