package io.poly.candor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import io.poly.candor.model.*;
import com.google.gson.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.Rules.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Cha.*;
import static io.poly.candor.Literals.*;
import static io.poly.candor.Policy.*;

/** Class loading + project indexing: read the scan target into ClassNodes (load/collectClasses),
 *  derive the Spring stereotype/repository type set (computeSpringTypes), and ingest CANDOR_DEPS
 *  cross-dependency effect reports (loadCrossDeps, candor-spec §2). EXTRACTED verbatim from
 *  Candor.java (refactor P5-Loader); re-exposed to Candor as bare names via
 *  `import static io.poly.candor.Loader.*`; reads shared state via the static imports. See
 *  REFACTOR_PLAN.md. */
final class Loader {
    static List<ClassNode> load(Path root) throws IOException {
        List<ClassNode> out = new ArrayList<>();
        // A `.jar`/`.zip` is an ARCHIVE, not a directory: `Files.walk` over it yields only the archive
        // file itself (no `.class` entries), so the loader silently returned ZERO classes from a jar —
        // despite the usage advertising `<dir-or-jar-of-classes>`. Mount it as a zip filesystem and walk
        // its entries, so analysing a built jar / a dependency actually works.
        String name = root.toString().toLowerCase(Locale.ROOT);
        if (Files.isRegularFile(root) && (name.endsWith(".jar") || name.endsWith(".zip"))) {
            try (FileSystem fs = FileSystems.newFileSystem(root)) {
                for (Path r : fs.getRootDirectories()) collectClasses(r, out);
            }
        } else {
            collectClasses(root, out);
        }
        return out;
    }

    static void collectClasses(Path root, List<ClassNode> out) throws IOException {
        int[] skipped = {0};
        String[] firstErr = {null};
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class"))::iterator) {
                // A MULTI-RELEASE jar ships version-specific overrides under META-INF/versions/<N>/; analyse
                // the BASE classes (the runtime picks the override; the base is the portable surface) and
                // skip the versioned copies — they are duplicates of the same class, and the newest ones may
                // be a bytecode version even a current ASM can't read.
                if (p.toString().replace('\\', '/').contains("/META-INF/versions/")) continue;
                // TOLERATE a class ASM can't parse (a future-major-version class, a corrupt entry): skip it
                // and DISCLOSE the count, never ABORT the whole scan on one bad class (the old behaviour —
                // one Java-25 entry in a multi-release jar threw IllegalArgumentException and killed the run).
                try {
                    ClassNode cn = new ClassNode();
                    new ClassReader(Files.readAllBytes(p)).accept(cn, 0);
                    out.add(cn);
                } catch (Exception | LinkageError e) {
                    skipped[0]++;
                    if (firstErr[0] == null) firstErr[0] = p.getFileName() + ": " + e.getMessage();
                    // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): record the un-analyzable class so the report + the
                    // gate verdict disclose it to a MACHINE (not just the stderr line below) — its effects are
                    // invisible, so a green gate over it would be a false-pure. path → reason.
                    ctx().unanalyzed.put(p.toString(), "class file failed to parse: "
                            + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
                }
            }
        }
        if (skipped[0] > 0) {
            System.err.println("candor-java: skipped " + skipped[0] + " unparseable class file(s) — their effects are"
                + " INVISIBLE, not analysed (e.g. " + firstErr[0] + "). A newer bytecode version may need an ASM bump.");
        }
    }

    /** Identify Spring Data repositories (effect: Db) and @FeignClient interfaces (Net). */
    static void computeSpringTypes(List<ClassNode> classes) {
        for (ClassNode cn : classes) {
            if (annoPresent(cn.visibleAnnotations, FEIGN)) ctx().feignTypes.add(cn.name);
            else if (isHttpClientType(cn)) ctx().httpClientTypes.add(cn.name);  // Retrofit/Micronaut/MP/Spring HTTP clients -> Net
        }
        // JPA entity tables: the literal @Table(name="…") (javax or jakarta persistence).
        for (ClassNode cn : classes) {
            if (cn.visibleAnnotations == null) continue;
            for (AnnotationNode a : cn.visibleAnnotations) {
                if (a.desc == null || !a.desc.contains("persistence/Table") || a.values == null) continue;
                for (int i = 0; i + 1 < a.values.size(); i += 2)
                    if ("name".equals(a.values.get(i)) && a.values.get(i + 1) instanceof String t && !t.isBlank())
                        ctx().entityTables.put(cn.name, t);
            }
        }
        boolean changed = true;
        while (changed) {
            changed = false;
            for (ClassNode cn : classes) {
                if (ctx().repoTypes.contains(cn.name) || cn.interfaces == null) continue;
                for (String itf : cn.interfaces) {
                    if (REPO_MARKERS.contains(itf) || ctx().repoTypes.contains(itf)
                            || isSpringDataRepoBase(itf) || isJakartaDataRepoBase(itf)
                            || isPanacheRepoBase(itf) || isMicronautDataRepoBase(itf)) {
                        ctx().repoTypes.add(cn.name);
                        changed = true;
                        break;
                    }
                }
            }
        }
        // A repository's entity is its FIRST generic argument (`extends CrudRepository<User, Long>`):
        // read it from the interface's generic signature and join with the entity's declared table.
        for (ClassNode cn : classes) {
            if (!ctx().repoTypes.contains(cn.name) || cn.signature == null) continue;
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("<L([^;<]+);").matcher(cn.signature);
            if (m.find()) {
                String table = ctx().entityTables.get(m.group(1));
                if (table != null) ctx().repoTables.put(cn.name, table);
            }
        }
    }

    /** Load dependency reports named by CANDOR_DEPS (a path list — space/colon/comma-separated; a
     *  directory is scanned for *.json) into a `method-ref hash -> inferred effects` map, so a call
     *  into an already-analyzed dependency inherits its effects (candor-spec §2). Version-aware trust
     *  (§2.1): effects from a report produced by a DIFFERENT engine version are downgraded to Unknown
     *  rather than silently trusted. Legacy-v0.1 (no hash) entries are skipped.
     *
     *  <p><b>Fail-closed (the CANDOR_CONFIG posture):</b> CANDOR_DEPS is a configured effect SOURCE —
     *  a token that resolves to no readable file (a typo'd path), an unwalkable deps directory, or an
     *  unreadable/unparseable dep report FAILS the run (exit 2). Silently skipping any of these made
     *  every call into that dep read PURE — the §2.1 "corrupt report ≠ pure" care taken inside the
     *  parser, undone one level up. */
    /** The `<report>.hierarchy.json` sidecar path for a report file, or null if `f` is not a report name.
     *  Mirrors {@link ReportWriter#writeHierarchy}'s naming exactly — one producer, one consumer, one rule. */
    static Path hierarchySidecarOf(Path f) {
        String n = f.getFileName().toString();
        if (!n.endsWith(".json") || n.endsWith(".hierarchy.json")) return null;
        return f.resolveSibling(n.substring(0, n.length() - 5) + ".hierarchy.json");
    }

    /** Read a chained dependency's class hierarchy from the sidecar {@link ReportWriter#writeHierarchy}
     *  writes beside EVERY report — `{"a.b.C": ["a.b.Base", "a.b.Iface"], …}`, dotted, direct supers only.
     *
     *  <p>WHY THIS EXISTS. A dependency's classes are not on candor's classpath, so {@link Cha#externalSupers}
     *  reads nothing for them and every question about a dep type's supertypes answered "no supers". That is
     *  a sound under-approximation and it is also the exact blocker under three open rows: the receiver-driven
     *  `w.write(..)` / `r.read(..)` reentry (proving the receiver IS a `java.io` stream needs its ancestry),
     *  dispatch through a dep's abstract CLASS, and swift's protocol-typed-parameter row one repo over. The
     *  information was already on disk beside every report and nothing read it.
     *
     *  <p>NOT VERSION-GATED, and the reason is that it carries no effect claim. §2.1 downgrades a
     *  different-version report's EFFECTS to Unknown because a different classifier produced them; a list of
     *  direct supertypes is a structural fact of the compiled bytecode, and it can only ROUTE a lookup — the
     *  entry it routes to is still version-gated and still downgraded. A stale hierarchy therefore reaches a
     *  stale entry and yields Unknown, which is the disclosure direction.
     *
     *  <p>Fail-closed like the report parser above: a sidecar that is PRESENT and unparsable fails the run.
     *  Absent is the ordinary case (candor-ts and pre-sidecar reports have none) and simply leaves the map
     *  empty — the behaviour every scan had before this. */
    static void loadDepHierarchy(Path f) {
        try {
            JsonElement root = JsonParser.parseString(Files.readString(f));
            if (!root.isJsonObject()) return;                    // an unexpected shape names no supertype
            for (var e : root.getAsJsonObject().entrySet()) {
                if (!e.getValue().isJsonArray()) continue;
                List<String> sup = new ArrayList<>();
                for (JsonElement x : e.getValue().getAsJsonArray())
                    if (x.isJsonPrimitive()) sup.add(x.getAsString().replace('.', '/'));
                if (!sup.isEmpty()) ctx().depSupers.putIfAbsent(e.getKey().replace('.', '/'), sup);
            }
            // INSTRUMENT THE PRECONDITION, not the output. A diff cannot show that a mechanism never fired
            // (a sidecar that loads zero types looks exactly like one that loads thousands and is never
            // consulted); `Cha.externalSupers` prints the other half, the hits.
            if (System.getenv("CANDOR_DEPHIER_DEBUG") != null)
                System.err.println("DEPHIER load " + f + ": " + ctx().depSupers.size() + " types known");
        } catch (Exception e) {
            System.err.println("candor: CANDOR_DEPS hierarchy sidecar " + f + " is unreadable ("
                    + e.getMessage() + ") — failing (exit 2), a configured dep must not silently read pure");
            System.exit(2);
        }
    }

    /** The package name(s) a dep report's ENVELOPE names. Accepts BOTH the spec's singular
     *  {@code "package": "<name>"} (what candor-report and candor-ts emit) AND this engine's own plural
     *  {@code packages[]} — reading only the array meant an all-pure spec-form report was ignored and its
     *  package falsely named a blind spot. One reader, so the trust-gated and the ungated registration
     *  below can never disagree about WHICH packages a report is about, only about what that licenses. */
    static List<String> reportPackages(JsonObject obj) {
        if (obj == null) return List.of();
        List<String> out = new ArrayList<>();
        if (obj.has("package") && obj.get("package").isJsonPrimitive())
            out.add(obj.get("package").getAsString());
        if (obj.has("packages") && obj.get("packages").isJsonArray())
            for (JsonElement x : obj.getAsJsonArray("packages"))
                if (x.isJsonPrimitive()) out.add(x.getAsString());
        return out;
    }

    /** The package a report ENTRY's hash names, or null if the hash names none — the fallback for reports
     *  with no envelope package field. The spec join key is {@code pkg#qual} (Rust/TS), so take what is
     *  before {@code #}; this engine's own hash is the slash-form {@code owner/Class.method(desc)}, so fall
     *  back to the last {@code /}. */
    static String entryPackage(String hash) {
        int hashSep = hash.indexOf('#');
        if (hashSep > 0) return hash.substring(0, hashSep);
        int slash = hash.lastIndexOf('/');
        return slash > 0 ? hash.substring(0, slash).replace('/', '.') : null;
    }

    static void loadCrossDeps(String spec, String ownVersion) {
        if (spec == null || spec.isBlank()) return;
        for (String tok : spec.split("[\\s:,]+")) {
            if (tok.isBlank()) continue;
            Path p = Path.of(tok);
            List<Path> files = new ArrayList<>();
            try {
                if (Files.isDirectory(p)) {
                    try (var s = Files.walk(p)) {
                        s.filter(f -> f.toString().endsWith(".json")).forEach(files::add);
                    }
                } else if (Files.isRegularFile(p)) {
                    files.add(p);
                    // A token naming the report FILE directly (what `.candor/config`'s `deps` key usually
                    // holds) never walks a directory, so the sidecar beside it would never be seen. Add it
                    // explicitly; absent is the ordinary case and simply leaves the hierarchy empty.
                    Path sib = hierarchySidecarOf(p);
                    if (sib != null && Files.isRegularFile(sib)) files.add(sib);
                } else {
                    System.err.println("candor: CANDOR_DEPS names " + p + " but it is not a readable file or"
                            + " directory — failing (exit 2), a configured dep must not silently read pure");
                    System.exit(2);
                }
            } catch (IOException e) {
                System.err.println("candor: CANDOR_DEPS cannot read " + p + " (" + e.getMessage()
                        + ") — failing (exit 2), a configured dep must not silently read pure");
                System.exit(2);
            }
            for (Path f : files) {
                if (f.getFileName().toString().endsWith(".hierarchy.json")) {
                    loadDepHierarchy(f);
                    continue;                      // a hierarchy sidecar carries no `functions` and no effects
                }
                try {
                    JsonElement root = JsonParser.parseString(Files.readString(f));
                    JsonObject obj = root.isJsonObject() ? root.getAsJsonObject() : null;
                    // isJsonArray-gated reads (not getAsJsonArray, which THROWS on a non-array `functions`).
                    // A throw here was caught by the per-FILE catch below and abandoned the WHOLE report — so
                    // a single malformed field made every caller of the dep read PURE instead of the §2.1
                    // Unknown. Be resilient field-by-field and downgrade to Unknown, never silently drop.
                    JsonArray fns = obj != null && obj.has("functions") && obj.get("functions").isJsonArray()
                            ? obj.getAsJsonArray("functions")
                            : (root.isJsonArray() ? root.getAsJsonArray() : null);
                    if (fns == null) continue;
                    String depVer = null;
                    if (obj != null && obj.has("candor") && obj.get("candor").isJsonObject()) {
                        JsonElement v = obj.getAsJsonObject("candor").get("version");
                        if (v != null && v.isJsonPrimitive()) depVer = v.getAsString(); // JsonNull → null → stale
                    }
                    // A report whose version can't be VERIFIED is not trusted (§2.1) — a missing
                    // header is as untrustworthy as a mismatched one (the Rust engine's rule;
                    // /code-review found the engines split three ways on versionless reports).
                    boolean stale = depVer == null || !depVer.equals(ownVersion);
                    // §2.1 TRUST IS ONE DECISION, NOT TWO. A stale report's EFFECTS are downgraded to
                    // Unknown below — the engine refuses to believe what it says. Registering its packages
                    // as COVERED believes it about everything it does NOT say: coverage is what silences
                    // the κ ledger's `invisible: [pkg]` disclosure, so every key this report omits then
                    // reads as a confident purity claim (absent from `functions` while counted in ⟨0.21⟩
                    // `analyzed`) on the authority of a report we had just declined to trust. Measured:
                    // `app.S.go` calling an unmentioned dep method vanished from the report entirely,
                    // identical to the FRESH arm and unlike the honest unchained arm. Coverage is claimed
                    // ONLY from a report whose producing build verifies. See StaleDepTrustTest — the
                    // FRESH arm is the case that must still work, and it is asserted beside this one.
                    //
                    // BUT COVERAGE AND CHAINED-NESS ARE TWO QUESTIONS, and collapsing them was wrong in the
                    // other direction — standing-bar item 0 in its exact shape. {@link
                    // Candor#untypedDepReceiver}'s conjunct 3 reads "is this dependency chained?" purely as
                    // an anti-flood test: it discloses ONLY where the κ ledger correctly falls silent.
                    // Routing it through the trust-gated set cost 2 disclosed Unknowns on logback-classic
                    // (`ContextInitializer.printConfiguratorOrder` ['Unknown'] -> [], an entry reduced to an
                    // empty purity claim) with NOTHING to replace them, because `ch.qos.logback` is a
                    // κ-CURATED-covered prefix and `invisible` is never emitted for it either way. So the
                    // chained-ness fact keeps its own, ungated set. `depCoveredPkgs` = whose silence we
                    // trust; `depChainedPkgs` = for whom a report was configured.
                    ctx().depChainedPkgs.addAll(reportPackages(obj));
                    if (stale) {
                        System.err.println("candor: CANDOR_DEPS report " + f + " was produced by build '"
                                + depVer + "', not this one ('" + ownVersion + "') — its effects are"
                                + " downgraded to Unknown (§2.1) and its packages are NOT counted as"
                                + " covered. Re-run the dependency's scan with this build to trust it.");
                    }
                    // File-level coverage: the producer's own package name(s) register the report's
                    // packages as COVERED even when `functions` is empty — an all-pure dep's empty
                    // report is its purity claim (SPEC §2 rule 3; the serde_json lesson). Accept BOTH
                    // the spec's singular `"package": "<name>"` (what candor-report and candor-ts
                    // emit) AND this engine's own plural `packages[]` — reading only the array meant an
                    // all-pure spec-form report was ignored and its package falsely named a blind spot.
                    if (!stale) ctx().depCoveredPkgs.addAll(reportPackages(obj));
                    for (JsonElement el : fns) {
                        if (!el.isJsonObject()) continue;                 // a non-object entry → skip (not pure-able)
                        JsonObject m = el.getAsJsonObject();
                        if (!m.has("hash") || !m.get("hash").isJsonPrimitive()) continue; // v0.1 / no cross-jar id
                        String h = m.get("hash").getAsString();
                        if (h.isBlank()) continue;
                        DepFn de = new DepFn();
                        if (stale) {
                            de.effects.add(Effect.UNKNOWN);
                        } else {
                            // `inferred` present but MALFORMED (JsonNull / a string / an object, or a
                            // non-string element) is an untrustworthy claim → Unknown, never silently dropped
                            // (the §2.1 contract: a corrupt same-version report ≠ pure). A clean array of
                            // strings reads its effects; a genuinely ABSENT inferred field stays pure.
                            if (m.has("inferred") && m.get("inferred").isJsonArray()) {
                                for (JsonElement x : m.getAsJsonArray("inferred"))
                                    if (x.isJsonPrimitive()) {
                                        Effect e = Effect.fromSpecName(x.getAsString());
                                        de.effects.add(e != null ? e : Effect.UNKNOWN); // foreign name → Unknown, never dropped
                                    } else de.effects.add(Effect.UNKNOWN);
                            } else if (m.has("inferred") && !m.get("inferred").isJsonNull()) {
                                de.effects.add(Effect.UNKNOWN);
                            } else if (m.has("inferred")) {
                                de.effects.add(Effect.UNKNOWN); // inferred: null → untrusted
                            }
                            for (var pair : List.of(Map.entry("hosts", de.hosts), Map.entry("cmds", de.cmds),
                                    Map.entry("paths", de.paths), Map.entry("tables", de.tables),
                                    Map.entry("netClass", de.netClass),
                                    Map.entry("unknownWhy", de.unknownWhy)))
                                if (m.has(pair.getKey()) && m.get(pair.getKey()).isJsonArray())
                                    for (JsonElement x : m.getAsJsonArray(pair.getKey()))
                                        pair.getValue().add(x.getAsString());
                        }
                        if (!de.effects.isEmpty()) ctx().crossDeps.put(h, de);
                        // Entry-level coverage fallback (reports with no package field): the hash's
                        // package prefix gives the EXACT package. The spec join key is `pkg#qual`
                        // (Rust/TS) — take what's before `#`; this engine's own hash is the
                        // slash-form `owner/Class.method(desc)`, so fall back to the last `/`.
                        // The COVERAGE half is gated on trust for the same reason as the file-level
                        // registration above (an untrusted report's entry names a package, it does not
                        // vouch for it); the CHAINED-NESS half is not, for the reason recorded there.
                        String pkg = entryPackage(h);
                        if (pkg == null) continue;
                        ctx().depChainedPkgs.add(pkg);
                        if (!stale) ctx().depCoveredPkgs.add(pkg);
                    }
                } catch (Exception ex) {
                    // FAIL-CLOSED: an unreadable/unparseable dep report swallowed here meant every call
                    // into that dep read pure (the field-level care above never ran). A corrupt configured
                    // report is a misconfiguration, not background noise — exit 2, like CANDOR_CONFIG.
                    System.err.println("candor: CANDOR_DEPS report " + f + " is unreadable or not valid JSON ("
                            + ex.getMessage() + ") — failing (exit 2), a corrupt dep report must not read pure");
                    System.exit(2);
                }
            }
        }
    }
}
