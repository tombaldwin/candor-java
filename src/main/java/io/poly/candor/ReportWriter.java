package io.poly.candor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import com.google.gson.*;
import org.objectweb.asm.tree.*;
import io.poly.candor.model.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Literals.*;
import static io.poly.candor.Cha.*;

/** Report output — builds the typed {@link io.poly.candor.model.Report} (one {@link Effector} per unit)
 *  and serializes it via {@link ReportJson}; plus the callgraph/hierarchy sidecars, the atomic writer,
 *  the Unknown-source stderr breakdown, and the build-id provenance. Reads the analysis result state via
 *  the static imports. (Was {@code Report} before the domain-model work freed that name for the model
 *  envelope record.) See candor-spec/MODEL.md. */
final class ReportWriter {
    /** Write the full report set for one scan — the JSON report (+ its §5 conformance), then the callgraph
     *  and hierarchy sidecars — all reading the CURRENT thread's context. {@code cc} may be null (computed
     *  if so; {@link Candor#main} passes the one it already built when {@code --json}+gate share it). The
     *  single shared sequence used by the normal scan, selftest-reentrant, and {@code --parallel}, so the
     *  three can't drift (the three were previously copy-pasted). */
    static void writeReport(Map<String, EffectSet> inferred, String out, ClassConformance cc) throws IOException {
        if (cc != null) writeJson(inferred, out, cc); else writeJson(inferred, out);
        // The "-" sentinel is the --json-stdout pipe form: report ENVELOPE only, NO sidecars (matching
        // the Rust reference) — there's nowhere on stdout to put a second/third document, and a piped
        // `| jq .` wants exactly one. The callgraph/hierarchy are a file-mode affordance for queries.
        if ("-".equals(out)) return;
        writeCallgraph(out);
        writeHierarchy(out);
    }

    static void writeJson(Map<String, EffectSet> inferred, String out) throws IOException {
        writeJson(inferred, out, classConformance(inferred));
    }

    /** As {@link #writeJson(Map, String)} but reusing a precomputed {@link ClassConformance}. The report
     *  needs the all-classes form; {@link Candor#main} computes it once and shares it with the gate so the
     *  two-pass class/method/field walk isn't repeated on a {@code --json} + {@code CANDOR_STRICT} run. */
    static void writeJson(Map<String, EffectSet> inferred, String out, ClassConformance cc) throws IOException {
        // Per-class conformance (candor-spec §5), computed the ONE shared way (see classConformance):
        // declared = effects the class's injected dependency types can supply; performed = union over
        // its methods. We attach declared/undeclared/overdeclared to each method entry so an agent can
        // consume conformance from the JSON, not just the AS-EFF diagnostics.
        Map<String, EffectSet> performed = cc.performed();
        Map<String, EffectSet> declaredByClass = cc.declared();
        Map<String, String> fnToClass = cc.fnToClass();

        Map<String, TreeSet<String>> fsAcc = fsFixpoint();
        Map<String, TreeSet<String>> hostsAcc = literalFixpoint(ctx().hostsDirect);
        Map<String, TreeSet<String>> cmdsAcc = literalFixpoint(ctx().cmdsDirect);
        Map<String, TreeSet<String>> pathsAcc = literalFixpoint(ctx().pathsDirect);
        Map<String, TreeSet<String>> tablesAcc = literalFixpoint(ctx().tablesDirect);
        // Per-method BLIND SPOTS (honesty disclosure): the external packages a method transitively reaches
        // where the classifier was floored AND κ never classified the package ANYWHERE (a genuine blind spot,
        // not a known-pure stdlib op). Propagated along the call graph like the literal surfaces, then
        // intersected with the global-blind set — so `inferred` is never an unqualified claim: a `pure`
        // method that reaches an unanalyzable package carries it in `invisible`.
        // ⟨0.15 staged⟩ read from the ONE shared ledger (Candor.kappaUncovered) that also feeds the stderr
        // line, the envelope `coverage` field below, and the --gate-json advisory — same names everywhere.
        List<Map.Entry<String, Integer>> uncovered = Candor.kappaUncovered();
        Set<String> globalBlind = uncovered.stream().map(Map.Entry::getKey).collect(Collectors.toSet());
        Map<String, TreeSet<String>> blindAcc = literalFixpoint(ctx().blindDirect);
        // ⟨0.20⟩ Net destination-class: transitive masked-surface markers, so a fn whose Net surface is
        // structurally incomplete (AS-EFF-008) fails closed to `unknown-host` even if its VISIBLE hosts are
        // all telemetry/partner — a benign visible host must not certify a fn that also reaches an invisible one.
        Map<String, TreeSet<String>> incompleteAcc = literalFixpoint(ctx().surfaceIncomplete);
        List<Effector> effectors = new ArrayList<>();
        inferred.entrySet().stream()
                // Keep a method if it has effects, is an entry point, has a BLIND SPOT (an unanalyzable
                // reach — so the honesty disclosure survives even on a `pure`-looking method), OR its class
                // declares a capability (an injects-but-never-uses class stays visible, overdeclared /
                // AS-EFF-002).
                .filter(e -> {
                    if (!e.getValue().isEmpty() || ctx().entryPoints.contains(e.getKey())) return true;
                    if (blindAcc.getOrDefault(e.getKey(), new TreeSet<>()).stream().anyMatch(globalBlind::contains))
                        return true;
                    String dc = fnToClass.get(e.getKey());
                    return dc != null && !declaredByClass.getOrDefault(dc, EffectSet.empty()).isEmpty();
                })
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> {
                    String fn = e.getKey();
                    EffectSet inf = e.getValue();
                    String dc = fnToClass.get(fn);
                    EffectSet declared = dc == null ? EffectSet.empty()
                            : declaredByClass.getOrDefault(dc, EffectSet.empty());
                    EffectSet perf = dc == null ? EffectSet.empty()
                            : performed.getOrDefault(dc, EffectSet.empty());
                    // undeclared = inferred − declared (the AS-EFF-001 surface; Unknown excluded,
                    // it's handled by AS-EFF-003). overdeclared = class declares but never performs.
                    EffectSet undeclared = inf.minus(declared).without(Effect.UNKNOWN);
                    EffectSet overdeclared = declared.minus(perf);
                    // HONESTY: the external packages this method transitively reaches that candor could NOT
                    // analyse (κ floored them, never classified anywhere) — effects through them are NOT in
                    // `inferred`. So `inferred` is never read as a completeness claim. Omitted when none.
                    List<String> invisible = blindAcc.getOrDefault(fn, new TreeSet<>()).stream()
                            .filter(globalBlind::contains).sorted().collect(Collectors.toList());
                    // Effect-relevant local call graph (SPEC §2 `calls`): the EFFECTFUL local callees,
                    // so a consumer can answer "who calls X?" from the report without re-analysis.
                    List<String> calls = ctx().edges.getOrDefault(fn, Set.of()).stream()
                            .filter(c -> {
                                EffectSet ce = inferred.get(c);
                                return ce != null && !ce.isEmpty();
                            })
                            .sorted().collect(Collectors.toList());
                    // Fs read/write detail (SPEC §2 `fs`): the access kind, when known AND complete.
                    // Empty when unknown, when the fn performs no Fs, or when reached cross-jar (FS_UNKNOWN).
                    List<String> fsKinds = List.of();
                    TreeSet<String> fk = fsAcc.get(fn);
                    if (inf.contains(Effect.FS) && fk != null && !fk.contains(FS_UNKNOWN))
                        fsKinds = fk.stream().filter(x -> !x.equals(FS_UNKNOWN)).sorted()
                                .collect(Collectors.toList());
                    // Literal Net/Exec/Fs/Db surfaces statically visible from this method (SPEC §2). Empty
                    // when none are visible (a runtime-computed value, or the effect absent).
                    TreeSet<String> hk = hostsAcc.get(fn);
                    List<String> hosts = inf.contains(Effect.NET) && hk != null && !hk.isEmpty()
                            ? new ArrayList<>(hk) : List.of();
                    TreeSet<String> ck = cmdsAcc.get(fn);
                    List<String> cmds = inf.contains(Effect.EXEC) && ck != null && !ck.isEmpty()
                            ? new ArrayList<>(ck) : List.of();
                    TreeSet<String> pk = pathsAcc.get(fn);
                    List<String> paths = inf.contains(Effect.FS) && pk != null && !pk.isEmpty()
                            ? new ArrayList<>(pk) : List.of();
                    TreeSet<String> tk = tablesAcc.get(fn);
                    List<String> tables = inf.contains(Effect.DB) && tk != null && !tk.isEmpty()
                            ? new ArrayList<>(tk) : List.of();
                    // ⟨0.20⟩ Net destination-class (SPEC §1): the destination classes present in this fn's
                    // (transitive) Net surface. `known-telemetry`/`known-partner` come from an EXACT host-
                    // literal match (Literals.netDestClass); a masked Net surface OR a Net with NO visible host
                    // (runtime-computed endpoint) fails closed to `unknown-host` — candor never guesses a host
                    // onto a safe class. Omitted when the fn has no Net.
                    List<String> netClass = List.of();
                    if (inf.contains(Effect.NET)) {
                        TreeSet<String> classes = new TreeSet<>();
                        if (hk != null) for (String h : hk) classes.add(Literals.netDestClass(h, ctx().netPartners));
                        TreeSet<String> inc = incompleteAcc.get(fn);
                        boolean masked = inc != null && inc.contains("Net");
                        if (masked || hk == null || hk.isEmpty()) classes.add("unknown-host");
                        netClass = new ArrayList<>(classes);
                    }
                    // Why Unknown was emitted HERE (not inherited): native:/reflect:/dispatch:/… tags.
                    TreeSet<UnknownReason> uw = ctx().unknownWhy.get(fn);
                    List<UnknownReason> reasons = uw == null ? List.of() : new ArrayList<>(uw);
                    // spec ⟨0.5⟩ unitKind: a static initializer is a UNIT, not a method anyone calls.
                    EffectorKind kind = fn.endsWith(".<clinit>") ? EffectorKind.INITIALIZER : EffectorKind.FUNCTION;
                    effectors.add(new Effector(
                            fn,
                            ctx().loc.getOrDefault(fn, "?"),
                            inf,
                            invisible,
                            ctx().direct.getOrDefault(fn, EffectSet.empty()),
                            declared,
                            undeclared,
                            overdeclared,
                            ctx().entryPoints.contains(fn),
                            inf.hasUnknown(), // trust contract (SPEC §4)
                            kind,
                            reasons,
                            ctx().hashOf.getOrDefault(fn, ""), // cross-jar join key (SPEC §2)
                            calls,
                            fsKinds, hosts, cmds, paths, tables, netClass));
                });
        // ⟨0.23, gated⟩ the synthetic INTERFACE-UNION entries. Appended last so the ordinary entries above
        // are untouched; a no-op unless CANDOR_WORKSPACE_CHAIN is set.
        appendInterfaceUnions(effectors, inferred, blindAcc, globalBlind,
                hostsAcc, cmdsAcc, pathsAcc, tablesAcc, incompleteAcc);
        // v0.2 self-describing envelope (candor-spec §2): a provenance header + the entries. Readers
        // still accept the legacy v0.1 bare array (see loadBaseline) during migration.
        String[] prov = provenance();
        // The packages this report COVERS — exact, from the analyzed class names. Lets a consumer
        // chaining this report register coverage even when `functions` is empty (SPEC §2 rule 3).
        TreeSet<String> pkgs = new TreeSet<>();
        for (ClassNode cn : ctx().ALL) {
            int slash = cn.name.lastIndexOf('/');
            if (slash > 0) pkgs.add(cn.name.substring(0, slash).replace('/', '.'));
        }
        // ⟨0.15 staged⟩ the `coverage` envelope field: the κ ledger as data — same entries and counts as
        // the stderr disclosure. null when fully covered → ReportJson omits the key entirely, keeping a
        // fully-covered report byte-identical to a pre-⟨0.15⟩ one.
        Coverage coverage = uncovered.isEmpty() ? null
                : new Coverage(uncovered.stream()
                        .map(e -> new Coverage.Uncovered(e.getKey(), e.getValue()))
                        .collect(Collectors.toList()));
        // ⟨0.21⟩ COMPLETENESS MANIFEST: the analyzed universe = every method candor formed a judgment for =
        // the §2.2 callgraph node set (ctx().edges keys, pure leaves included — NOT the effectful-only
        // `functions` array). count lets a bare-envelope consumer compute the pure count (count − |functions|)
        // and tell analyzed-pure from never-seen; digest fingerprints the set for same-engine re-scan agreement.
        java.util.TreeSet<String> analyzedQuals = new java.util.TreeSet<>(ctx().edges.keySet());
        Report.Analyzed analyzed = new Report.Analyzed(analyzedQuals.size(), fnv1aHex(analyzedQuals));
        List<Report.UnanalyzedUnit> unanalyzed = ctx().unanalyzed.entrySet().stream()
                .map(e -> new Report.UnanalyzedUnit(e.getKey(), e.getValue())).collect(Collectors.toList());
        Report report = new Report(
                new Provenance(prov[0], prov[1], SPEC_VERSION), // §2.1 — contract version distinct from build id
                new ArrayList<>(pkgs),
                coverage,
                analyzed,
                unanalyzed,
                effectors);
        // "-" is the --json-stdout pipe form: emit the report JSON to stdout (pure — `| jq .` parses it)
        // rather than writing a file. The progress line stays on stderr so stdout carries ONLY the report.
        if ("-".equals(out)) {
            System.out.println(ReportJson.serialize(report));
            System.err.println("candor-java: wrote " + effectors.size() + " entries (@" + prov[0] + ") to stdout");
        } else {
            writeAtomic(Path.of(out), ReportJson.serialize(report));
            System.err.println("candor-java: wrote " + effectors.size() + " entries (@" + prov[0] + ") to " + out);
        }
        reportUnknownSources();
    }

    /** ⟨0.23⟩ Is the workspace-chain rung ON? PRESENCE of {@code CANDOR_WORKSPACE_CHAIN} in the environment,
     *  matching candor-scan (`env::var_os(..).is_some()`) and candor-swift. A package-private field rather
     *  than a direct read so an in-process test can drive both arms; {@link #workspaceChainOverride} is null
     *  in every production path, so the env var is the only thing that turns the rung on. */
    static Boolean workspaceChainOverride = null;

    static boolean workspaceChain() {
        return workspaceChainOverride != null ? workspaceChainOverride
                : System.getenv("CANDOR_WORKSPACE_CHAIN") != null;
    }

    /**
     * ⟨0.23, gated on {@code CANDOR_WORKSPACE_CHAIN}⟩ INTERFACE-CHA UNION ENTRIES — candor-java joining the
     * rung candor-scan / candor-ts / candor-swift already ship (SPEC §2, WORKSPACE-CHAINING-DESIGN.md,
     * conformance PART 18).
     *
     * <p>A consumer that calls {@code s.save()} on a value typed by an interface declared HERE compiles to
     * INVOKEINTERFACE with THIS package's interface as the static owner, so it keys the chain lookup on
     * {@code lib/Store.save(…)} — a declaration with no body, hashed under no entry. candor-java was marked
     * N/A for PART 18 because "whole-classpath bytecode resolves cross-module dispatch natively", which is
     * true of an UNCHAINED whole-classpath scan and false across the scan boundary, where the implementer is
     * in the other tree (candor-spec DEP-RECEIVER-TYPING-DESIGN.md, "Which engine needs WHICH field").
     *
     * <p>The consumer side needed no change at all: this engine keys report entries by
     * {@code owner.name+desc}, which is exactly the key {@code crossDepJoin} forms for an INVOKEINTERFACE
     * site — so a union entry lands where the join already looks. Only the PRODUCER was missing.
     *
     * <p>Emitted per interface method, with effects = the union over {@link Cha#chaTargets} — the very CHA
     * universe in-scan dispatch uses, so the union can only name bodies this scan actually analysed. Bounds,
     * each pinned by a test in {@code InterfaceUnionTest} and each verified to CATCH by mutation:
     * <ul>
     *   <li>Union EMPTY (no implementer at all, or every implementer pure, and nothing invisible) → no entry:
     *       a dep report omits its pure functions, and that silence IS the purity claim (§2 rule 3). This is
     *       also what makes "an interface nothing implements publishes nothing" fall out — {@code chaTargets}
     *       returns nothing to union.
     *   <li>A REAL entry already claims the hash (an effectful {@code default} method) → the union is MERGED
     *       INTO IT, never skipped and never replaced. Skipping was a SILENT UNDER-REPORT — the cardinal sin
     *       — and it shipped: {@code interface Store { default void save(String s){ log(s); } }} publishes
     *       {@code ["Log"]} under the very hash a consumer's INVOKEINTERFACE keys on, so an
     *       {@code S3Store implements Store} that overrides it with an HTTP call was never charged to
     *       anyone and {@code deny Net} passed on code that makes an HTTP call. Publishing under a hash is
     *       answering "what can running this member do", and IN-SCAN the same {@code iface.save()} is
     *       already charged the whole CHA union — so the boundary answer must be the union too, or the
     *       engine contradicts itself across the scan boundary. The merge WIDENS only: {@code inferred},
     *       {@code invisible}, the literal surfaces and {@code netClass} take the union; {@code loc},
     *       {@code direct}, {@code declared}/{@code undeclared}/{@code overdeclared} and {@code calls}
     *       still describe the analysed BODY (they are assertions about that body, not about the dispatch),
     *       and the entry stays UNMARKED — it is a real analysed unit, counted in ⟨0.21⟩ {@code analyzed},
     *       and marking it would make a consumer subtract it twice. {@code fs} is DROPPED when another
     *       implementer contributes {@code Fs}: the field means "kind known and complete", and the union
     *       does not carry kinds, so keeping the default body's {@code ["read"]} would claim completeness
     *       for a write it never saw.
     *   <li>{@code static} / {@code private} / synthetic / {@code <clinit>} interface members are skipped.
     *       Not cosmetic: a PURE {@code static} interface method has no real entry to claim its hash, and an
     *       implementer that happens to declare the same {@code name+desc} as an INSTANCE method would be
     *       unioned onto it — charging a consumer's INVOKESTATIC the effects of a body it never runs.
     * </ul>
     *
     * <p>An "at least one local subtype" guard was written here first and then REMOVED: measured across
     * twelve real jars it changed not one entry, and the single shape where it did fire — an interface that
     * re-abstracts a method whose only body is a super-interface {@code default} — is a genuinely runnable
     * local body that an external implementer inherits, so suppressing it was an under-report, not a bound.
     *
     * <p>Sound over-approximation, in the same sense as in-scan bounded CHA: a consumer holding the PURE
     * implementer is charged the effectful sibling's effect, because nothing types the receiver more
     * precisely. What it replaces is not silence — half 1 ({@link Candor#untypedDepReceiver}) already
     * discloses {@code Unknown[dispatch:…]} at that site — so the rung's effect on a chained consumer is
     * {@code Unknown} → the precise union.
     *
     * <p>Two things a union entry deliberately does NOT carry. The literal surfaces it DOES carry
     * ({@code hosts}/{@code cmds}/{@code paths}/{@code tables}/{@code netClass}) are exactly the ones
     * {@code crossDepJoin} inherits, so the join is as informative through a union as through a real entry;
     * {@code fs} (the read/write kind) is not among them and is omitted rather than half-published. And a
     * union entry is NOT in ⟨0.21⟩ {@code analyzed} — it is not a unit anyone analysed — so under this flag
     * {@code analyzed.count − |functions|} undercounts the pure set by the number of marked entries. That
     * is what the marker is for; a consumer computing the pure count subtracts them.
     */
    private static void appendInterfaceUnions(List<Effector> effectors, Map<String, EffectSet> inferred,
            Map<String, TreeSet<String>> blindAcc, Set<String> globalBlind,
            Map<String, TreeSet<String>> hostsAcc, Map<String, TreeSet<String>> cmdsAcc,
            Map<String, TreeSet<String>> pathsAcc, Map<String, TreeSet<String>> tablesAcc,
            Map<String, TreeSet<String>> incompleteAcc) {
        if (!workspaceChain()) return;
        // The REAL entry claiming each hash, by index — the union MERGES into it (see the `default`-method
        // bullet above); `putIfAbsent` keeps the first, so the merge target is stable.
        Map<String, Integer> claimedAt = new HashMap<>();
        for (int i = 0; i < effectors.size(); i++) claimedAt.putIfAbsent(effectors.get(i).hash(), i);
        Set<String> published = new HashSet<>();            // one entry per hash, whatever ALL contains
        List<Effector> unions = new ArrayList<>();
        int merged = 0;
        for (ClassNode cn : ctx().ALL) {
            if ((cn.access & org.objectweb.asm.Opcodes.ACC_INTERFACE) == 0) continue;
            for (MethodNode mn : cn.methods) {
                if ((mn.access & (org.objectweb.asm.Opcodes.ACC_STATIC | org.objectweb.asm.Opcodes.ACC_PRIVATE
                        | org.objectweb.asm.Opcodes.ACC_SYNTHETIC)) != 0) continue;
                if (mn.name.startsWith("<")) continue;
                String hash = cn.name + "." + mn.name + mn.desc;   // the exact key crossDepJoin forms
                if (!published.add(hash)) continue;
                Integer at = claimedAt.get(hash);
                Effector real = at == null ? null : effectors.get(at);
                List<String> impls = chaTargets(cn.name, mn.name, mn.desc);
                // BOUNDED CHA, the same bound every IN-SCAN dispatch site applies (Candor: `broad =
                // cha.size() > CHA_FANOUT_LIMIT && !isClosedHierarchy(owner)`). Past the limit an OPEN
                // hierarchy may have a subtype candor never saw, so its visible union is an open-world
                // guess, and publishing it is a FABRICATION at the far end: a consumer holding the one
                // pure implementer reads {Rand, Net, Fs} and fails `deny Net`. Only the consumer breaks,
                // which is why nothing local caught it — the producing scan's own gate reads `inferred`,
                // never the report it writes. A PROVABLY-closed hierarchy (a sealed family's `permits`
                // list is the whole subtype set) is exempt exactly as in-scan: its union is exact.
                // The in-scan formula's THIRD term, `closedWorldResolvable`, is deliberately NOT copied:
                // CANDOR_CLOSED_WORLD asserts the scanned classes are the whole world, and that assertion
                // is exactly what publishing for a CHAINED consumer contradicts — the consumer's own
                // implementers are, by construction, outside this scan.
                boolean broad = impls.size() > Rules.CHA_FANOUT_LIMIT && !isClosedHierarchy(cn.name);
                EffectSet inf = EffectSet.empty();
                // What the OTHER implementers contribute — the interface's own `default` body is one of
                // `chaTargets`' targets, and only the rest is news to a claimed entry.
                EffectSet fromOthers = EffectSet.empty();
                TreeSet<String> inv = new TreeSet<>(), hosts = new TreeSet<>(), cmds = new TreeSet<>(),
                        paths = new TreeSet<>(), tables = new TreeSet<>();
                boolean masked = false;
                // UNKNOWN, not silence. Dropping the broad union and publishing nothing would be the other
                // half of the same defect: a dep report omits its pure functions, so an absent entry IS a
                // purity claim (§2 rule 3), and twelve pure implementers do not make the thirteenth pure.
                // Unknown is what is true of candor's state, it is what the in-scan site reports, and it
                // carries its reason so a `deny E Unknown[dispatch]` still bites.
                List<UnknownReason> why = List.of();
                if (broad) {
                    inf.add(Effect.UNKNOWN);
                    why = List.of(UnknownReason.of(UnknownReason.Kind.DISPATCH,
                            cn.name.replace('/', '.') + "." + mn.name));
                }
                for (String impl : broad ? List.<String>of() : impls) {
                    EffectSet ie = inferred.get(impl);
                    if (ie != null) {
                        inf.addAll(ie);
                        if (real == null || !impl.equals(real.fn())) fromOthers.addAll(ie);
                    }
                    inv.addAll(blindAcc.getOrDefault(impl, new TreeSet<>()).stream()
                            .filter(globalBlind::contains).collect(Collectors.toList()));
                    hosts.addAll(hostsAcc.getOrDefault(impl, new TreeSet<>()));
                    cmds.addAll(cmdsAcc.getOrDefault(impl, new TreeSet<>()));
                    paths.addAll(pathsAcc.getOrDefault(impl, new TreeSet<>()));
                    tables.addAll(tablesAcc.getOrDefault(impl, new TreeSet<>()));
                    masked |= incompleteAcc.getOrDefault(impl, new TreeSet<>()).contains("Net");
                }
                if (inf.isEmpty() && inv.isEmpty()) continue;      // pure across every implementer
                List<String> netClass = List.of();
                if (inf.contains(Effect.NET)) {
                    TreeSet<String> classes = new TreeSet<>();
                    for (String h : hosts) classes.add(Literals.netDestClass(h, ctx().netPartners));
                    if (masked || hosts.isEmpty()) classes.add("unknown-host");
                    netClass = new ArrayList<>(classes);
                }
                if (real != null) {
                    Effector wide = mergeUnionInto(real, inf, fromOthers, inv, hosts, cmds, paths, tables,
                            netClass, why);
                    if (wide != real) { effectors.set(at, wide); merged++; }
                    continue;
                }
                unions.add(new Effector(
                        cn.name.replace('/', '.') + "." + mn.name, "", inf, new ArrayList<>(inv),
                        EffectSet.empty(), EffectSet.empty(), EffectSet.empty(), EffectSet.empty(),
                        false, inf.hasUnknown(), EffectorKind.FUNCTION, why, hash, List.of(),
                        List.of(),
                        inf.contains(Effect.NET) ? new ArrayList<>(hosts) : List.of(),
                        inf.contains(Effect.EXEC) ? new ArrayList<>(cmds) : List.of(),
                        inf.contains(Effect.FS) ? new ArrayList<>(paths) : List.of(),
                        inf.contains(Effect.DB) ? new ArrayList<>(tables) : List.of(),
                        netClass, true));
            }
        }
        if (unions.isEmpty() && merged == 0) return;
        unions.sort(Comparator.comparing(Effector::hash));
        effectors.addAll(unions);
        System.err.println("candor-java: emitted " + unions.size()
                + " interface-CHA union entries, merged " + merged + " into a claimed hash (workspace chain)");
    }

    /**
     * WIDEN the real entry that already claims an interface method's hash with the dispatch union over its
     * implementers — the merge half of {@link #appendInterfaceUnions}. Returns {@code real} UNCHANGED when
     * the union adds nothing, so a claimed hash with only pure implementers is byte-identical to the
     * unflagged report (the second fixture); otherwise a copy with the widened fields.
     *
     * <p>WIDEN ONLY, never veto and never replace: every field is a union with what the analysed body
     * already reported. The body's own assertions — {@code loc}, {@code direct}, {@code declared},
     * {@code undeclared}, {@code overdeclared}, {@code calls} — are left alone; they describe the code at
     * {@code loc}, not the dispatch, and widening them would manufacture an AS-EFF-001 violation on a class
     * for an effect a DIFFERENT class performs. The entry also stays unmarked (see the bullet).
     */
    private static Effector mergeUnionInto(Effector real, EffectSet inf, EffectSet fromOthers,
            TreeSet<String> inv, TreeSet<String> hosts, TreeSet<String> cmds, TreeSet<String> paths,
            TreeSet<String> tables, List<String> netClass, List<UnknownReason> why) {
        EffectSet wide = real.inferred().join(inf);
        TreeSet<UnknownReason> whyW = new TreeSet<>(real.unknownWhy()); whyW.addAll(why);
        TreeSet<String> invW = new TreeSet<>(real.invisible()); invW.addAll(inv);
        TreeSet<String> hostsW = new TreeSet<>(real.hosts()); hostsW.addAll(hosts);
        TreeSet<String> cmdsW = new TreeSet<>(real.cmds()); cmdsW.addAll(cmds);
        TreeSet<String> pathsW = new TreeSet<>(real.paths()); pathsW.addAll(paths);
        TreeSet<String> tablesW = new TreeSet<>(real.tables()); tablesW.addAll(tables);
        TreeSet<String> netW = new TreeSet<>(real.netClass()); netW.addAll(netClass);
        // `fs` means "the access kind, known AND complete" (see the fsKinds branch above). The union carries
        // no kinds, so once ANOTHER implementer contributes Fs the body's own kinds stop being the whole
        // story — drop the field rather than half-publish it (empty = unknown = the gate fails closed).
        List<String> fsW = fromOthers.contains(Effect.FS) ? List.of() : real.fs();
        boolean unchanged = wide.equals(real.inferred())
                && invW.size() == real.invisible().size() && hostsW.size() == real.hosts().size()
                && cmdsW.size() == real.cmds().size() && pathsW.size() == real.paths().size()
                && tablesW.size() == real.tables().size() && netW.size() == real.netClass().size()
                && fsW.equals(real.fs()) && whyW.size() == real.unknownWhy().size();
        if (unchanged) return real;
        boolean hasNet = wide.contains(Effect.NET);
        return new Effector(real.fn(), real.loc(), wide, new ArrayList<>(invW), real.direct(),
                real.declared(), real.undeclared(), real.overdeclared(), real.entryPoint(),
                wide.hasUnknown(), real.kind(), new ArrayList<>(whyW), real.hash(), real.calls(), fsW,
                hasNet ? new ArrayList<>(hostsW) : real.hosts(),
                wide.contains(Effect.EXEC) ? new ArrayList<>(cmdsW) : real.cmds(),
                wide.contains(Effect.FS) ? new ArrayList<>(pathsW) : real.paths(),
                wide.contains(Effect.DB) ? new ArrayList<>(tablesW) : real.tables(),
                hasNet ? new ArrayList<>(netW) : real.netClass(),
                real.interfaceUnion());
    }

    /** ⟨0.21⟩ An opaque, within-engine-stable fingerprint of a sorted qual set — FNV-1a 64-bit over the
     *  newline-joined UTF-8 quals, lowercase hex. Dependency-free + deterministic: it changes iff the set
     *  changes, so a same-engine re-scan of unchanged input agrees. NOT cryptographic and NOT cross-engine
     *  comparable (qualifiers differ `::` vs `.`) — a completeness-manifest re-scan check, not a security hash. */
    static String fnv1aHex(Iterable<String> sortedQuals) {
        long h = 0xcbf29ce484222325L; // FNV offset basis
        for (String q : sortedQuals) {
            for (byte b : q.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
                h ^= (b & 0xff);
                h *= 0x100000001b3L; // FNV prime
            }
            h ^= '\n';
            h *= 0x100000001b3L;
        }
        return String.format("%016x", h);
    }

    /** The FULL call graph (every project method -> its callees, including pure ones), written beside the
     *  report as `<out-minus-.json>.callgraph.json`. The report omits pure functions, so without this a
     *  `callers` query can't answer the PRE-EDIT blast-radius question ("who would be affected if I add an
     *  effect to this pure function?") — the most natural thing an agent asks. Mirrors candor-scan's
     *  callgraph sidecar so both engines answer it identically (candor-spec §2). */
    static void writeCallgraph(String out) throws IOException {
        String cgOut = out.endsWith(".json") ? out.substring(0, out.length() - 5) + ".callgraph.json"
                                             : out + ".callgraph.json";
        Map<String, List<String>> cg = new TreeMap<>();
        // SPEC §2.2: EVERY analyzed method is a key — a LEAF with no project callees gets an empty
        // list (was skipped, which made an uncalled leaf invisible to whatif/callers and conflated
        // "no callers" with "no such function"; mirrors the same fix in candor-scan + the lint).
        for (var e : ctx().edges.entrySet()) {
            cg.put(e.getKey(), new ArrayList<>(new TreeSet<>(e.getValue())));
        }
        writeAtomic(Path.of(cgOut), ReportJson.pretty(cg));
    }

    /** Write the type-hierarchy sidecar (`<report-stem>.hierarchy.json`) ⟨0.7⟩: each PROJECT type →
     *  its direct supertypes + implemented interfaces (dotted; project AND external supers kept, so a
     *  a `dispatch:` over an external-owner interface still resolves). A SEPARATE sidecar — not a key
     *  in the §2.2 call-graph sidecar, whose every top-level key is a function — and compact (O(classes),
     *  one short list each), so the precise dispatch-frontier query can resolve "is R an override of
     *  OWNER.M?" by name + subtype WITHOUT the engine storing the exploded candidate edges bounded-CHA
     *  drops (which would re-encode the very flood it prevents). `java/lang/Object` is omitted as noise. */
    static void writeHierarchy(String out) throws IOException {
        String hOut = out.endsWith(".json") ? out.substring(0, out.length() - 5) + ".hierarchy.json"
                                            : out + ".hierarchy.json";
        Map<String, List<String>> h = new TreeMap<>();
        for (ClassNode cn : ctx().ALL) {
            if (!ctx().projectClasses.contains(cn.name)) continue; // key on the project types we resolve overrides for
            TreeSet<String> sup = new TreeSet<>();
            if (cn.superName != null && !cn.superName.equals("java/lang/Object")) sup.add(cn.superName.replace('/', '.'));
            if (cn.interfaces != null) for (String i : cn.interfaces) sup.add(i.replace('/', '.'));
            if (!sup.isEmpty()) h.put(cn.name.replace('/', '.'), new ArrayList<>(sup));
        }
        writeAtomic(Path.of(hOut), ReportJson.pretty(h));
    }

    /** Write a report file ATOMICALLY: serialize to a sibling temp file, then move it into place. A
     *  concurrent reader (a cross-engine candor-query merging this report) must never observe a
     *  half-written file — the same write invariant the Rust and TS backends hold. Tries an atomic
     *  move first; falls back to a plain replacing move on a filesystem that can't do ATOMIC_MOVE
     *  (e.g. across a tmp boundary), which still beats an in-place truncate+write. On ANY failure
     *  (disk full mid-write, both moves rejected) the temp is removed so a failed run never leaves an
     *  accumulating `<name>.json<rnd>.tmp` residue beside the report. */
    static void writeAtomic(Path path, String contents) throws IOException {
        Path dir = path.toAbsolutePath().getParent();
        Path tmp = Files.createTempFile(dir, path.getFileName().toString(), ".tmp");
        boolean moved = false;
        try {
            Files.writeString(tmp, contents);
            try {
                Files.move(tmp, path, java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
        } finally {
            if (!moved) Files.deleteIfExists(tmp);
        }
    }

    /** Human-readable breakdown of WHERE direct Unknowns come from, bucketed into the irreducible
     *  (reflection, native) vs the improvable (unresolved dispatch — a project iface/abstract whose
     *  impl wasn't on the analyzed classpath). Printed to stderr so a maintainer can see which
     *  opacity is worth chasing (widen the classpath) vs accept (honest Unknown, SPEC §4). */
    static void reportUnknownSources() {
        if (ctx().unknownWhy.isEmpty()) return;
        var byCategory = new java.util.TreeMap<String, Integer>();   // native|reflect|dispatch -> count
        var byTarget = new java.util.TreeMap<String, Integer>();     // specific owner/method -> count
        for (TreeSet<UnknownReason> reasons : ctx().unknownWhy.values())
            for (UnknownReason r : reasons) {
                byCategory.merge(r.prefix(), 1, Integer::sum);
                byTarget.merge(r.format(), 1, Integer::sum);
            }
        System.err.println("\ncandor-java: Unknown sources (direct) — " + ctx().unknownWhy.size() + " methods");
        byCategory.forEach((c, n) -> System.err.println(String.format("  %-9s %4d", c, n)));
        System.err.println("  top targets (dispatch: = improvable by widening the analyzed classpath):");
        byTarget.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(12)
                .forEach(e -> System.err.println(String.format("    %4d  %s", e.getValue(), e.getKey())));
    }

    /** Engine provenance for the v0.2 envelope (candor-spec §2.1): the build id + toolchain baked into
     *  a resource at build time, so the report reflects the BINARY that ran rather than the source
     *  tree. Falls back to "unknown" / the running JDK when the resource is absent. */
    static String[] provenance() {
        String version = "unknown";
        String toolchain = "jvm-" + System.getProperty("java.version", "?");
        try (var in = Candor.class.getResourceAsStream("/candor/build-info.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                version = p.getProperty("version", version);
                toolchain = p.getProperty("toolchain", toolchain);
            }
        } catch (IOException ignored) {
            // best-effort provenance: a missing/unreadable build-info resource falls back to the defaults
        }
        return new String[] {version, toolchain};
    }

    /** The clean RELEASE semver (e.g. "0.5.0") — the crate-semver axis that GitHub releases tag and the
     *  `-all.jar` filename carry, distinct from {@link #provenance()}'s git-hash build id. Baked into
     *  build-info.properties as `release` by the Gradle build; falls back to "unknown" if absent. */
    static String release() {
        try (var in = Candor.class.getResourceAsStream("/candor/build-info.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                return p.getProperty("release", "unknown");
            }
        } catch (IOException ignored) {
            // best-effort: an unreadable build-info resource falls back to "unknown"
        }
        return "unknown";
    }
}
