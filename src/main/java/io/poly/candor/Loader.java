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
        for (ClassNode cn : classes) if (annoPresent(cn.visibleAnnotations, FEIGN)) ctx().feignTypes.add(cn.name);
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
     *  rather than silently trusted. Unreadable/legacy-v0.1 (no hash) entries are skipped. */
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
                }
            } catch (IOException e) {
                continue;
            }
            for (Path f : files) {
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
                    // File-level coverage: the producer's own package name(s) register the report's
                    // packages as COVERED even when `functions` is empty — an all-pure dep's empty
                    // report is its purity claim (SPEC §2 rule 3; the serde_json lesson). Accept BOTH
                    // the spec's singular `"package": "<name>"` (what candor-report and candor-ts
                    // emit) AND this engine's own plural `packages[]` — reading only the array meant an
                    // all-pure spec-form report was ignored and its package falsely named a blind spot.
                    if (obj != null) {
                        if (obj.has("package") && obj.get("package").isJsonPrimitive())
                            ctx().depCoveredPkgs.add(obj.get("package").getAsString());
                        if (obj.has("packages") && obj.get("packages").isJsonArray())
                            for (JsonElement x : obj.getAsJsonArray("packages"))
                                ctx().depCoveredPkgs.add(x.getAsString());
                    }
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
                                    Map.entry("paths", de.paths), Map.entry("tables", de.tables)))
                                if (m.has(pair.getKey()) && m.get(pair.getKey()).isJsonArray())
                                    for (JsonElement x : m.getAsJsonArray(pair.getKey()))
                                        pair.getValue().add(x.getAsString());
                        }
                        if (!de.effects.isEmpty()) ctx().crossDeps.put(h, de);
                        // Entry-level coverage fallback (reports with no package field): the hash's
                        // package prefix gives the EXACT package. The spec join key is `pkg#qual`
                        // (Rust/TS) — take what's before `#`; this engine's own hash is the
                        // slash-form `owner/Class.method(desc)`, so fall back to the last `/`.
                        int hashSep = h.indexOf('#');
                        if (hashSep > 0) {
                            ctx().depCoveredPkgs.add(h.substring(0, hashSep));
                        } else {
                            int slash = h.lastIndexOf('/');
                            if (slash > 0) ctx().depCoveredPkgs.add(h.substring(0, slash).replace('/', '.'));
                        }
                    }
                } catch (Exception ex) {
                    // skip unreadable / unparseable dependency reports (like the Rust impl)
                }
            }
        }
    }
}
