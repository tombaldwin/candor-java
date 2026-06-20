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
    static void writeJson(Map<String, EffectSet> inferred, String out) throws IOException {
        // Per-class conformance (same model as checkConformance, SPEC §5): declared = effects
        // the class's injected dependency types can supply; performed = union over its methods.
        // We attach declared/undeclared/overdeclared to each method entry so an agent can
        // consume conformance from the JSON, not just the AS-EFF diagnostics. The unit of
        // declaration in the DI idiom is the class, projected onto each of its methods.
        Map<String, TreeSet<String>> performed = new HashMap<>();
        Map<String, String> fnToClass = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> p = performed.computeIfAbsent(dc, k -> new TreeSet<>());
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                String fn = methodId(dc, mn.name, mn.desc);
                fnToClass.put(fn, dc);
                var inf = inferred.get(fn);
                if (inf != null) p.addAll(inf.toNames());
            }
        }
        Map<String, TreeSet<String>> declaredByClass = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> declared = new TreeSet<>();
            if (cn.fields != null)
                for (FieldNode f : cn.fields) {
                    String t = fieldTypeInternal(f.desc);
                    if (t != null) declared.addAll(typeEffects(t, performed));
                }
            declaredByClass.put(dc, declared);
        }

        Map<String, TreeSet<String>> fsAcc = fsFixpoint();
        Map<String, TreeSet<String>> hostsAcc = literalFixpoint(hostsDirect);
        Map<String, TreeSet<String>> cmdsAcc = literalFixpoint(cmdsDirect);
        Map<String, TreeSet<String>> pathsAcc = literalFixpoint(pathsDirect);
        Map<String, TreeSet<String>> tablesAcc = literalFixpoint(tablesDirect);
        // Per-method BLIND SPOTS (honesty disclosure): the external packages a method transitively reaches
        // where the classifier was floored AND κ never classified the package ANYWHERE (a genuine blind spot,
        // not a known-pure stdlib op). Propagated along the call graph like the literal surfaces, then
        // intersected with the global-blind set — so `inferred` is never an unqualified claim: a `pure`
        // method that reaches an unanalyzable package carries it in `invisible`.
        Set<String> globalBlind = kappaSeen.keySet().stream()
                .filter(p -> !kappaClassified.contains(p) && !depCoveredPkgs.contains(p))
                .collect(Collectors.toSet());
        Map<String, TreeSet<String>> blindAcc = literalFixpoint(blindDirect);
        List<Effector> effectors = new ArrayList<>();
        inferred.entrySet().stream()
                // Keep a method if it has effects, is an entry point, has a BLIND SPOT (an unanalyzable
                // reach — so the honesty disclosure survives even on a `pure`-looking method), OR its class
                // declares a capability (an injects-but-never-uses class stays visible, overdeclared /
                // AS-EFF-002).
                .filter(e -> {
                    if (!e.getValue().isEmpty() || entryPoints.contains(e.getKey())) return true;
                    if (blindAcc.getOrDefault(e.getKey(), new TreeSet<>()).stream().anyMatch(globalBlind::contains))
                        return true;
                    String dc = fnToClass.get(e.getKey());
                    return dc != null && !declaredByClass.getOrDefault(dc, new TreeSet<>()).isEmpty();
                })
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> {
                    String fn = e.getKey();
                    EffectSet inf = e.getValue();
                    String dc = fnToClass.get(fn);
                    TreeSet<String> declared = dc == null ? new TreeSet<>()
                            : declaredByClass.getOrDefault(dc, new TreeSet<>());
                    TreeSet<String> perf = dc == null ? new TreeSet<>()
                            : performed.getOrDefault(dc, new TreeSet<>());
                    // undeclared = inferred − declared (the AS-EFF-001 surface; Unknown excluded,
                    // it's handled by AS-EFF-003). overdeclared = class declares but never performs.
                    List<String> undeclared = inf.toNames().stream()
                            .filter(x -> !x.equals("Unknown") && !declared.contains(x))
                            .sorted().collect(Collectors.toList());
                    List<String> overdeclared = declared.stream()
                            .filter(x -> !perf.contains(x)).sorted().collect(Collectors.toList());
                    // HONESTY: the external packages this method transitively reaches that candor could NOT
                    // analyse (κ floored them, never classified anywhere) — effects through them are NOT in
                    // `inferred`. So `inferred` is never read as a completeness claim. Omitted when none.
                    List<String> invisible = blindAcc.getOrDefault(fn, new TreeSet<>()).stream()
                            .filter(globalBlind::contains).sorted().collect(Collectors.toList());
                    // Effect-relevant local call graph (SPEC §2 `calls`): the EFFECTFUL local callees,
                    // so a consumer can answer "who calls X?" from the report without re-analysis.
                    List<String> calls = edges.getOrDefault(fn, Set.of()).stream()
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
                    // Why Unknown was emitted HERE (not inherited): native:/reflect:/dispatch:/… tags.
                    TreeSet<UnknownReason> uw = unknownWhy.get(fn);
                    List<UnknownReason> reasons = uw == null ? List.of() : new ArrayList<>(uw);
                    // spec ⟨0.5⟩ unitKind: a static initializer is a UNIT, not a method anyone calls.
                    EffectorKind kind = fn.endsWith(".<clinit>") ? EffectorKind.INITIALIZER : EffectorKind.FUNCTION;
                    effectors.add(new Effector(
                            fn,
                            loc.getOrDefault(fn, "?"),
                            inf,
                            invisible,
                            direct.getOrDefault(fn, EffectSet.empty()),
                            EffectSet.ofNames(declared),
                            EffectSet.ofNames(undeclared),
                            EffectSet.ofNames(overdeclared),
                            entryPoints.contains(fn),
                            inf.hasUnknown(), // trust contract (SPEC §4)
                            kind,
                            reasons,
                            hashOf.getOrDefault(fn, ""), // cross-jar join key (SPEC §2)
                            calls,
                            fsKinds, hosts, cmds, paths, tables));
                });
        // v0.2 self-describing envelope (candor-spec §2): a provenance header + the entries. Readers
        // still accept the legacy v0.1 bare array (see loadBaseline) during migration.
        String[] prov = provenance();
        // The packages this report COVERS — exact, from the analyzed class names. Lets a consumer
        // chaining this report register coverage even when `functions` is empty (SPEC §2 rule 3).
        TreeSet<String> pkgs = new TreeSet<>();
        for (ClassNode cn : ALL) {
            int slash = cn.name.lastIndexOf('/');
            if (slash > 0) pkgs.add(cn.name.substring(0, slash).replace('/', '.'));
        }
        Report report = new Report(
                new Provenance(prov[0], prov[1], SPEC_VERSION), // §2.1 — contract version distinct from build id
                new ArrayList<>(pkgs),
                effectors);
        writeAtomic(Path.of(out), ReportJson.serialize(report));
        System.err.println("candor-java: wrote " + effectors.size() + " entries (@" + prov[0] + ") to " + out);
        reportUnknownSources();
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
        for (var e : edges.entrySet()) {
            cg.put(e.getKey(), new ArrayList<>(new TreeSet<>(e.getValue())));
        }
        writeAtomic(Path.of(cgOut), new GsonBuilder().setPrettyPrinting().create().toJson(cg));
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
        for (ClassNode cn : ALL) {
            if (!projectClasses.contains(cn.name)) continue; // key on the project types we resolve overrides for
            TreeSet<String> sup = new TreeSet<>();
            if (cn.superName != null && !cn.superName.equals("java/lang/Object")) sup.add(cn.superName.replace('/', '.'));
            if (cn.interfaces != null) for (String i : cn.interfaces) sup.add(i.replace('/', '.'));
            if (!sup.isEmpty()) h.put(cn.name.replace('/', '.'), new ArrayList<>(sup));
        }
        writeAtomic(Path.of(hOut), new GsonBuilder().setPrettyPrinting().create().toJson(h));
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
        if (unknownWhy.isEmpty()) return;
        var byCategory = new java.util.TreeMap<String, Integer>();   // native|reflect|dispatch -> count
        var byTarget = new java.util.TreeMap<String, Integer>();     // specific owner/method -> count
        for (TreeSet<UnknownReason> reasons : unknownWhy.values())
            for (UnknownReason r : reasons) {
                byCategory.merge(r.prefix(), 1, Integer::sum);
                byTarget.merge(r.format(), 1, Integer::sum);
            }
        System.err.println("\ncandor-java: Unknown sources (direct) — " + unknownWhy.size() + " methods");
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
        }
        return "unknown";
    }
}
