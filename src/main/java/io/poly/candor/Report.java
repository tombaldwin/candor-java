package io.poly.candor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import com.google.gson.*;
import org.objectweb.asm.tree.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Literals.*;
import static io.poly.candor.Cha.*;

/** Report output — writeJson/writeCallgraph/writeHierarchy/writeAtomic + reportUnknownSources +
 *  provenance/release (the build-id header). EXTRACTED from Candor.java (refactor P5-Report); reads the
 *  analysis result state via the static import. See REFACTOR_PLAN.md. */
final class Report {
    static void writeJson(Map<String, TreeSet<String>> inferred, String out) throws IOException {
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
                if (inf != null) p.addAll(inf);
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
        List<Map<String, Object>> entries = new ArrayList<>();
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
                    TreeSet<String> inf = e.getValue();
                    String dc = fnToClass.get(fn);
                    TreeSet<String> declared = dc == null ? new TreeSet<>()
                            : declaredByClass.getOrDefault(dc, new TreeSet<>());
                    TreeSet<String> perf = dc == null ? new TreeSet<>()
                            : performed.getOrDefault(dc, new TreeSet<>());
                    // undeclared = inferred − declared (the AS-EFF-001 surface; Unknown excluded,
                    // it's handled by AS-EFF-003). overdeclared = class declares but never performs.
                    List<String> undeclared = inf.stream()
                            .filter(x -> !x.equals("Unknown") && !declared.contains(x))
                            .sorted().collect(Collectors.toList());
                    List<String> overdeclared = declared.stream()
                            .filter(x -> !perf.contains(x)).sorted().collect(Collectors.toList());
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("fn", fn);
                    m.put("loc", loc.getOrDefault(fn, "?"));
                    m.put("inferred", new ArrayList<>(inf));
                    // HONESTY: the external packages this method transitively reaches that candor could NOT
                    // analyse (κ floored them, never classified anywhere) — effects through them are NOT in
                    // `inferred`. So `inferred` is never read as a completeness claim: a `pure` method that
                    // calls into one of these is disclosed, not silently certified. Omitted when none.
                    List<String> invisible = blindAcc.getOrDefault(fn, new TreeSet<>()).stream()
                            .filter(globalBlind::contains).sorted().collect(Collectors.toList());
                    if (!invisible.isEmpty()) m.put("invisible", invisible);
                    m.put("direct", new ArrayList<>(direct.getOrDefault(fn, new TreeSet<>())));
                    m.put("declared", new ArrayList<>(declared));
                    m.put("undeclared", undeclared);
                    m.put("overdeclared", overdeclared);
                    m.put("entryPoint", entryPoints.contains(fn));
                    m.put("unresolved", inf.contains("Unknown")); // trust contract (SPEC §4)
                    // spec ⟨0.5⟩ unitKind: a static initializer is a UNIT, not a method anyone
                    // calls — name it so consumers render it sensibly. Absent = ordinary function.
                    if (fn.endsWith(".<clinit>")) m.put("unitKind", "initializer");
                    // Why Unknown was emitted HERE (not inherited): native:/reflect:/dispatch: tags,
                    // so a reader can see which opacity is improvable (a missing-impl dispatch) vs
                    // irreducible (reflection, native). Omitted when this fn introduces no Unknown.
                    TreeSet<String> uw = unknownWhy.get(fn);
                    if (uw != null && !uw.isEmpty()) m.put("unknownWhy", new ArrayList<>(uw));
                    m.put("hash", hashOf.getOrDefault(fn, "")); // cross-jar join key (SPEC §2)
                    // Effect-relevant local call graph (SPEC §2 `calls`): the EFFECTFUL local callees,
                    // so a consumer can answer "who calls X?" from the report without re-analysis.
                    // Omitted when empty.
                    List<String> calls = edges.getOrDefault(fn, Set.of()).stream()
                            .filter(c -> {
                                TreeSet<String> ce = inferred.get(c);
                                return ce != null && !ce.isEmpty();
                            })
                            .sorted().collect(Collectors.toList());
                    if (!calls.isEmpty()) m.put("calls", calls);
                    // Fs read/write detail (SPEC §2 `fs`): the access kind, when known AND complete.
                    // Empty when unknown, when the fn performs no Fs, or when reached cross-jar
                    // (FS_UNKNOWN) — never a misleading partial. Omitted when empty.
                    TreeSet<String> fk = fsAcc.get(fn);
                    if (inf.contains("Fs") && fk != null && !fk.contains(FS_UNKNOWN)) {
                        List<String> kinds = fk.stream().filter(x -> !x.equals(FS_UNKNOWN)).sorted()
                                .collect(Collectors.toList());
                        if (!kinds.isEmpty()) m.put("fs", kinds);
                    }
                    // Literal Net/Exec/Fs surfaces statically visible from this method (SPEC §2
                    // `hosts`/`cmds`/`paths`): the decidable subset of who it talks to / what it runs /
                    // what it touches, feeding the AS-EFF-008 allowlist. Omitted when none are visible (a
                    // runtime-computed value, or the effect absent) — never a completeness claim.
                    TreeSet<String> hk = hostsAcc.get(fn);
                    if (inf.contains("Net") && hk != null && !hk.isEmpty())
                        m.put("hosts", new ArrayList<>(hk));
                    TreeSet<String> ck = cmdsAcc.get(fn);
                    if (inf.contains("Exec") && ck != null && !ck.isEmpty())
                        m.put("cmds", new ArrayList<>(ck));
                    TreeSet<String> pk = pathsAcc.get(fn);
                    if (inf.contains("Fs") && pk != null && !pk.isEmpty())
                        m.put("paths", new ArrayList<>(pk));
                    TreeSet<String> tk = tablesAcc.get(fn);
                    if (inf.contains("Db") && tk != null && !tk.isEmpty())
                        m.put("tables", new ArrayList<>(tk));
                    entries.add(m);
                });
        // v0.2 self-describing envelope (candor-spec §2): a provenance header + the function entries.
        // Readers still accept the legacy v0.1 bare array (see loadBaseline) during migration.
        String[] prov = provenance();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("version", prov[0]);
        header.put("toolchain", prov[1]);
        header.put("spec", SPEC_VERSION); // candor-spec contract version (§2.1), distinct from the build id
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("candor", header);
        // The packages this report COVERS — exact, from the analyzed class names. Lets a consumer
        // chaining this report register coverage even when `functions` is empty (an all-pure
        // dep's report is its purity claim, SPEC §2 rule 3 — the empty-report coverage fix).
        TreeSet<String> pkgs = new TreeSet<>();
        for (ClassNode cn : ALL) {
            int slash = cn.name.lastIndexOf('/');
            if (slash > 0) pkgs.add(cn.name.substring(0, slash).replace('/', '.'));
        }
        envelope.put("packages", pkgs);
        envelope.put("functions", entries);
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(envelope);
        writeAtomic(Path.of(out), json);
        System.err.println("candor-java: wrote " + entries.size() + " entries (@" + prov[0] + ") to " + out);
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
        for (TreeSet<String> reasons : unknownWhy.values())
            for (String r : reasons) {
                String cat = r.substring(0, r.indexOf(':'));
                byCategory.merge(cat, 1, Integer::sum);
                byTarget.merge(r, 1, Integer::sum);
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
