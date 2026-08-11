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
    /** ⟨0.24⟩ SPEC §2.2's RESERVED trailing segments, family-wide: a file whose LAST dotted segment before
     *  `.json` is one of these is a SIDECAR, never a report. Stated in the spec because the engines were
     *  already drifting — java carved out two of these, candor-ts six — and cross-engine reading is not
     *  hypothetical (the conformance frontier differential has one engine produce and another consume). */
    private static final Set<String> RESERVED_SIDECAR_SEGMENTS =
            Set.of("callgraph", "hierarchy", "calibrated", "layerreach", "locs", "gate");

    /**
     * ⟨0.28⟩ The reserved segments that name A REPORT'S OWN §2.2 SIDECARS — the set
     * {@link Candor#removeArmedReportSidecars} deletes when it arms that report. DERIVED from the one
     * list above rather than restated, because a second copy is a copy that drifts (which is what
     * {@code SourceHygieneTest.theReservedSidecarSegmentsAreListedExactlyOnce} counts, and it caught
     * this method's first draft doing exactly that).
     *
     * <p><b>{@code gate} is excluded, and that exclusion is the whole content of this method.</b> The
     * other five are DERIVED FROM the report and carry no provenance of their own, which is why §2.2
     * says to read them together with it and why arming the report has to take them along. A
     * {@code <stem>.gate.json} is not that: it is the VERDICT SINK's document, with its own
     * operator-named flag, its own ⟨0.27⟩ arming and its own fail-closed shape. Deleting it here would
     * be the report sink destroying the verdict sink's document beside it — the harm §3.3.1 records as
     * MEASURED ("a three-suffix carve-out overwrote … {@code <prefix>.gate.json}, a gate verdict") — and
     * it would fail OPEN in the way {@link Candor#writeRefusedGateJson} explicitly refuses to: a CI
     * wrapper that reads a missing verdict as "nothing to report" goes green. The deletion argument for
     * the five turns on NO consumer treating their absence as a claim; for a verdict, absence is
     * precisely the claim that gets misread. (candor-rust's reference lists five literals and does not
     * say why; this engine's canonical list has six, so the reason has to be written down.)
     */
    static java.util.List<String> reportSidecarSegments() {
        var segs = new java.util.ArrayList<>(RESERVED_SIDECAR_SEGMENTS);
        segs.remove("gate");
        java.util.Collections.sort(segs);   // deterministic, so a failure's stderr is stable across runs
        return segs;
    }

    /**
     * Is this file name a SIDECAR rather than a report? The ONE rule, for every locator glob in this engine
     * — {@link Query#prefixHits}, {@link Query#quietPrefixMatches} and the CANDOR_DEPS directory walk all
     * ask here, because two lists that can drift apart is exactly how this started.
     *
     * <p><b>It is a DENYLIST over the reserved segment, and must stay one.</b> The inversion — accept only
     * the `<type>` values this engine knows — is an ALLOWLIST, and a report whose type segment an
     * implementer failed to anticipate would become silently invisible to every query: a false all-clear.
     * A denylist can only be INCOMPLETE, and incompleteness here is LOUD — an unregistered suffix falls
     * back into the candidate set and the locator discloses the ambiguity on every query. Noise, never a
     * swallowed report.
     *
     * <p>The reserved word is reserved in the SIDECAR SEGMENT POSITION, not banned from the name: the test
     * is the LAST segment, so `report.hierarchy.jvm.json` — a crate legitimately named `hierarchy` — still
     * resolves, because there the word sits in the `<crate>` position. Segment COUNT is deliberately not
     * the discriminator: sidecar names are per-engine, so counting excludes this engine's own 3-segment
     * sidecars and not a 2-segment one from another producer. The `encountered-*` family matches in any
     * position, as candor-ts has it — a crate named `encountered-<something>` is not a real shape, and
     * agreeing with the sibling engine on a shared convention is worth more than the last inch of width.
     */
    static boolean isSidecarName(String name) {
        if (name.contains(".encountered-")) return true;
        if (!name.endsWith(".json")) return false;
        String stem = name.substring(0, name.length() - ".json".length());
        int dot = stem.lastIndexOf('.');
        return dot >= 0 && RESERVED_SIDECAR_SEGMENTS.contains(stem.substring(dot + 1));
    }

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
            // ⟨the superclass split⟩ Read the marker FIRST — JSON object order is not a contract, so a
            // class key may arrive before it. Its ABSENCE is the old sidecar shape and means the kinds are
            // unknown, which is exactly what every consumer assumed before this key existed; reading an
            // unmarked list as all-interfaces or all-classes would be a guess, and both guesses are wrong
            // in a direction this vein has already paid for.
            Map<String, String> split =
                    readSuperclassMarker(root.getAsJsonObject().get(ReportWriter.SUPERCLASS_KEY));
            for (var e : root.getAsJsonObject().entrySet()) {
                // `@` is the RESERVED METADATA NAMESPACE (SPEC §2.2). The marker's value is now an array
                // like every other value in the file — which is what keeps a strictly typed reader working
                // — so the shape no longer tells them apart and the name has to. A key starting `@` is
                // never a type: javac cannot produce one, and treating a metadata key as a type would put a
                // phantom entry in `depSupers` for every future extension.
                if (e.getKey().startsWith("@")) continue;
                if (!e.getValue().isJsonArray()) continue;       // any other non-array value is metadata too
                List<String> sup = new ArrayList<>();
                for (JsonElement x : e.getValue().getAsJsonArray())
                    if (x.isJsonPrimitive()) sup.add(x.getAsString().replace('.', '/'));
                if (sup.isEmpty()) continue;
                String internal = e.getKey().replace('.', '/');
                // The split must come from the SAME sidecar as the list, or a later report's kinds would be
                // applied to an earlier one's supertypes — `putIfAbsent` keeps the first, so gate on it.
                if (ctx().depSupers.putIfAbsent(internal, sup) == null && split != null) {
                    ctx().depSplitKnown.add(internal);
                    String s = split.get(e.getKey());
                    // Absent = the superclass is java/lang/Object (or this is an interface): every listed
                    // supertype is an interface. The writer omits it for exactly that case.
                    if (s != null) ctx().depSuperclass.put(internal, s.replace('.', '/'));
                }
            }
            // INSTRUMENT THE PRECONDITION, not the output. A diff cannot show that a mechanism never fired
            // (a sidecar that loads zero types looks exactly like one that loads thousands and is never
            // consulted); `Cha.externalSupers` prints the other half, the hits.
            // The SPLIT's own precondition is counted separately from the supertype lists: a marker this
            // reader silently failed to understand — a shape it does not accept, a foreign engine's, a
            // future one's — costs 0 report entries and 0 effects (the split moves resolution ORDER, and
            // the corpus measurement for that rung was 125 orders / 0 effect changes), so an A/B cannot
            // tell a working reader from a dead one. This count can.
            if (System.getenv("CANDOR_DEPHIER_DEBUG") != null)
                System.err.println("DEPHIER load " + f + ": " + ctx().depSupers.size() + " types known, "
                        + ctx().depSplitKnown.size() + " with a known split");
        } catch (Exception e) {
            System.err.println("candor: CANDOR_DEPS hierarchy sidecar " + f + " is unreadable ("
                    + e.getMessage() + ") — failing (exit 2), a configured dep must not silently read pure");
            System.exit(2);
        }
    }

    /** The {@code @superclass} marker as type → superclass, or NULL when the sidecar does not carry a
     *  usable one — which means the kinds are unknown and {@link Cha#resolutionOrder} keeps the
     *  depth-ordered behaviour that shipped, never a guess.
     *
     *  <p>BOTH shapes are read, and that is deliberate. The current shape is a FLAT array
     *  {@code [type, superclass, …]} — chosen so every value in the sidecar is an array and a strictly
     *  typed reader (candor-rust's) does not discard the file. candor-java 0.23.1 shipped it as an OBJECT,
     *  so every dep report and sidecar that build wrote carries that form; narrowing this reader to the new
     *  shape alone would silently drop the split for all of them — a fabrication fix manufacturing the
     *  under-report it was closing. A malformed array (odd length) yields null rather than a partial
     *  pairing: an untrustworthy pairing must fall back to "kinds unknown", not to half a guess. */
    private static Map<String, String> readSuperclassMarker(JsonElement marker) {
        if (marker == null) return null;
        Map<String, String> out = new HashMap<>();
        if (marker.isJsonArray()) {
            var a = marker.getAsJsonArray();
            if (a.size() % 2 != 0) return null;
            for (int i = 0; i < a.size(); i += 2) {
                if (!a.get(i).isJsonPrimitive() || !a.get(i + 1).isJsonPrimitive()) return null;
                out.put(a.get(i).getAsString(), a.get(i + 1).getAsString());
            }
            return out;
        }
        if (marker.isJsonObject()) {                              // the 0.23.1 shape, still in the wild
            for (var e : marker.getAsJsonObject().entrySet())
                if (e.getValue().isJsonPrimitive()) out.put(e.getKey(), e.getValue().getAsString());
            return out;
        }
        return null;
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
     *  before {@code #}; this engine's own hash is the slash-form {@code owner/Class.method(desc)}, so
     *  split the OWNER portion only.
     *
     *  <p><b>THE OWNER PORTION ONLY, and that qualifier is the whole fix.</b> This once took the last
     *  {@code /} in the WHOLE hash — but a JVM descriptor is full of slashes ({@code (Ljava/lang/String;)V}),
     *  so for every method taking or returning a reference type the last {@code /} landed INSIDE the
     *  descriptor and the answer was {@code com.example.Svc.save(Ljava.lang}: not a package, and not one any
     *  bytecode could produce. So the owner is bounded first — everything before the descriptor's {@code (},
     *  then before the last {@code .} that separates the method name — and only then is the package taken.
     *
     *  <p>WHICH DIRECTION IT FAILED IN. The bogus name could never GRANT anything: it necessarily contains
     *  the {@code (} that opens the descriptor, and no package name can, so it matched nothing in
     *  {@code depCoveredPkgs}. The cost was the registration that never happened — {@code depChainedPkgs}
     *  is conjunct 3 of {@link Candor#untypedDepReceiver}, so a chained report with no envelope package
     *  field left the half-1 unanswerable-key disclosure silent and an INVOKEINTERFACE into an
     *  unnameable dep implementation read as a confident purity claim. See {@link DepEntryPackageTest} for
     *  the two-tree fixture and its single-tree control.
     *
     *  <p>The {@code pkg#qual} branch above was always exact and has always granted per-entry coverage, so
     *  this makes one hash form behave like the other rather than introducing a policy. */
    static String entryPackage(String hash) {
        int hashSep = hash.indexOf('#');
        if (hashSep > 0) return hash.substring(0, hashSep);
        int paren = hash.indexOf('(');                                  // the descriptor starts here
        String ownerAndMethod = paren >= 0 ? hash.substring(0, paren) : hash;
        int dot = ownerAndMethod.lastIndexOf('.');                      // owner/method separator
        String owner = dot > 0 ? ownerAndMethod.substring(0, dot) : ownerAndMethod;
        int slash = owner.lastIndexOf('/');
        return slash > 0 ? owner.substring(0, slash).replace('/', '.') : null;
    }

    /** ⟨0.21⟩ Does this dep report DECLARE ITSELF INCOMPLETE — i.e. does its `unanalyzed` manifest name
     *  source the producing scan could not analyze?
     *
     *  <p>WHY IT COSTS COVERAGE. SPEC §2 rule 3 turns a report's SILENCE into a purity claim: a key the
     *  report does not answer is answered pure, and registering the report's packages as covered is exactly
     *  what silences the κ ledger's {@code invisible: [pkg]} hedge so that silence can be read that way. A
     *  report carrying a non-empty `unanalyzed` has just said it never read some of its own source, so its
     *  silence about that source answers nothing — and chaining it was strictly WORSE than not chaining it:
     *  the dependency's own gate refuses to certify itself over unanalyzed code ({@link Candor} exits 2 for
     *  precisely this), and the consumer was certifying one on its behalf. The same door {@code 7e41327}
     *  closed for a report failing the §2.1 version check, with a different key. candor-ts found it first
     *  and closed it in its own sweep (`21277eb`); this is the JVM half.
     *
     *  <p><b>THE TREATMENT DIFFERS FROM STALENESS, and the difference is the whole point.</b> A stale
     *  report's ENTRIES are assertions from a build we do not trust, so they are downgraded to Unknown. An
     *  incomplete report's entries were derived from source it DID read and are true — only its SILENCE is
     *  not a purity claim. So the entries are kept exactly as they are and only COVERAGE is withheld:
     *  strictly additive, an answered key still answers, an unanswered one falls back to the ledger's
     *  hedge, and no effect is ever removed. Asserted in {@link StaleDepTrustTest}, not assumed — treating
     *  incomplete like stale fails the entries-kept row and only it.
     *
     *  <p><b>ABSENT means complete, PRESENT-BUT-MALFORMED means incomplete.</b> {@code ReportJson} omits
     *  the key entirely when the manifest is empty, so absence is this engine's own way of saying "I read
     *  everything" and treating it as incompleteness would hedge every report ever written. Anything else —
     *  a non-empty array, a JsonNull, a string, an object — is a completeness claim that cannot be read, and
     *  a claim that cannot be read is not a claim: it goes the fail-closed way, matching the field-by-field
     *  posture the entry parser below already takes for a malformed `inferred`. So the ONLY shapes that buy
     *  coverage are an absent key and an explicitly EMPTY array — a denylist of proven-safe shapes, never an
     *  allowlist of rejected ones (candor-spec: `candor-denylist-over-allowlist`). */
    static boolean declaresItselfIncomplete(JsonObject obj) {
        if (obj == null || !obj.has("unanalyzed")) return false;
        JsonElement un = obj.get("unanalyzed");
        return !(un.isJsonArray() && un.getAsJsonArray().isEmpty());
    }

    /** ⟨0.24⟩ Does this dep report say it JUDGED NOTHING — i.e. is {@code analyzed.count} zero?
     *
     *  <p><b>THE DEFECT.</b> A chained report carrying {@code functions: []} and {@code analyzed.count: 0}
     *  bought a consumer MORE confidence than not chaining the package at all. The caller dropped out of
     *  {@code functions} entirely — which under ⟨0.21⟩ is a positive PURITY claim — with no {@code invisible}
     *  on the entry, no {@code coverage.uncovered} in the envelope and no line on stderr, while the UNCHAINED
     *  arm of the same scan disclosed both. Measured on this engine before the fix: `deny Fs` exit 1 (trusted)
     *  → exit 0 (this arm), report entries 2 → 0, `coverage` present → absent. That is a silent under-report,
     *  and conformance PART 26 measured the same door in all four engines.
     *
     *  <p><b>WHAT THE FIX RESTORES IS THE DISCLOSURE, NOT THE VERDICT</b>, and the distinction is not a
     *  shortfall. The consumer has no evidence the dep performs `Fs` — the report it was handed says nothing
     *  about any unit — so re-asserting the effect would be fabrication, and this engine's channel for an
     *  uncovered package is the κ ledger, not `Unknown`. `deny Fs` therefore stays exit 0 on this arm,
     *  exactly as it is on the UNCHAINED arm, which is the FLOOR the rule asks for: not more confident than
     *  no report at all. In PART 26's letters the arm moves from `A` (silent purity claim) to `h`
     *  (HEDGED_LOSS — knowledge lost, disclosed), which is the correct §2.1 shape.
     *
     *  <p><b>WHY THE WIRE CAN ANSWER IT.</b> `functions: []` alone cannot: it is the shape of an all-pure
     *  dependency AND of one that analyzed nothing, and SPEC §2 chaining rule 3 requires a consumer to
     *  BELIEVE the first ("an all-pure dependency's empty report is a claim, not a blind spot"). ⟨0.21⟩'s
     *  {@code analyzed.count} is the integer that separates them — a facade package of pure re-exports scans
     *  to count 0, an all-pure two-function package to count 2 — and no engine was reading it. So this
     *  predicate is keyed on the COUNT, never on the emptiness of `functions`: hedging both shapes would not
     *  implement the rule, it would disable the claim rule 3 exists to protect. {@link StaleDepTrustTest}
     *  carries the count-n arm as an in-band control beside the count-0 one for exactly that reason.
     *
     *  <p><b>WHAT IT COSTS, AND WHAT IT DOES NOT.</b> Only COVERAGE is withheld — the treatment the ⟨0.21⟩
     *  incomplete arm gets, not the §2.1 stale one. A count-0 report has no entries to downgrade, so nothing
     *  is removed and the change is strictly additive; and {@code depChainedPkgs} stays ungated for the
     *  reason recorded at its own registration (it only ever ADDS disclosure, so routing a trust decision
     *  through it silences {@link Candor#untypedDepReceiver} where the κ ledger cannot replace it).
     *
     *  <p><b>THE THREE ROWS ⟨0.24⟩ SPELLS OUT, and the shapes each covers:</b>
     *  <ul>
     *    <li>{@code count} numeric and 0 (or negative) → judged nothing → NO coverage;</li>
     *    <li>{@code count} numeric and positive → n units judged → coverage, unchanged. Note this holds even
     *        with a non-empty `functions`, which is the ordinary case;</li>
     *    <li>{@code analyzed} ABSENT → a pre-⟨0.21⟩ producer, which has no manifest and so makes no claim.
     *        Judged-nothing iff `functions` is EMPTY: an empty report from a producer that cannot say whether
     *        it judged anything falls back to the unchained reading, while one that LISTS functions
     *        demonstrably judged units and keeps the coverage it has always had. (In this engine the §2.1
     *        version check almost always fires first on such a report — pre-⟨0.21⟩ builds carry a different
     *        build id — so this row is the belt to staleness's braces, not the load-bearing one.)</li>
     *    <li>{@code analyzed} PRESENT but unreadable (a JsonNull, a string, an object with no numeric
     *        `count`) → a judgment claim that cannot be READ is not a claim → NO coverage, the same
     *        fail-closed posture {@link #declaresItselfIncomplete} takes for a malformed `unanalyzed` and the
     *        entry parser takes for a malformed `inferred`. A denylist of proven-safe shapes.</li>
     *  </ul>
     *
     *  @param fns the report's {@code functions} array (possibly the bare-array root form), consulted ONLY
     *             on the manifest-absent row above. */
    static boolean claimsToHaveJudgedNothing(JsonObject obj, JsonArray fns) {
        if (obj == null || !obj.has("analyzed")) return fns == null || fns.isEmpty();
        JsonElement an = obj.get("analyzed");
        if (!an.isJsonObject()) return true;                        // unreadable manifest → not a claim
        JsonElement c = an.getAsJsonObject().get("count");
        if (c == null || !c.isJsonPrimitive() || !c.getAsJsonPrimitive().isNumber()) return true;
        return c.getAsInt() <= 0;
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
                String fname = f.getFileName().toString();
                if (fname.endsWith(".hierarchy.json")) {
                    loadDepHierarchy(f);
                    continue;                      // a hierarchy sidecar carries no `functions` and no effects
                }
                // ⟨0.24⟩ …and neither does any OTHER reserved sidecar segment (§2.2). A directory-form
                // CANDOR_DEPS walks every `.json` beside the report, so another engine's `.locs.json` /
                // `.gate.json` reached the report parser. Today they fall out of it harmlessly (no
                // `functions` array ⇒ skipped), so this changes no verdict — it is here because the reserved
                // set must have ONE reader in this engine. A second list that only happens to agree is the
                // state this rung exists to end, and the next sidecar shape is the one that would not.
                if (isSidecarName(fname)) continue;
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
                    if (fns == null) {
                        // NOT SILENTLY. A chained dep report with no `functions` grants NO coverage, so
                        // every call into that dep resolves to nothing and its callers read PURE — and
                        // the operator, who configured the dep precisely so that would not happen, saw
                        // no sign of it. `continue` on its own is the cardinal sin with the evidence
                        // sitting right there in CANDOR_DEPS.
                        //
                        // The SIDECARS are the legitimate case and they are identifiable by name, so
                        // they stay silent; anything else is named. Disclosed rather than exit 2 (the
                        // posture the unreadable-dep sibling above takes) because a deps DIRECTORY can
                        // legitimately hold unrelated JSON, and turning that into a red gate would be a
                        // false failure — but it can never be a silent one.
                        String fn = f.getFileName().toString();
                        if (!fn.endsWith(".hierarchy.json") && !fn.endsWith(".callgraph.json")) {
                            System.err.println("candor: chained dep " + f + " has no `functions` — it is not"
                                    + " a candor report, so it grants NO coverage and calls into it stay"
                                    + " Unknown rather than reading pure. Scan that dependency to close"
                                    + " the gap, or remove it from CANDOR_DEPS.");
                        }
                        continue;
                    }
                    String depVer = null;
                    if (obj != null && obj.has("candor") && obj.get("candor").isJsonObject()) {
                        JsonElement v = obj.getAsJsonObject("candor").get("version");
                        if (v != null && v.isJsonPrimitive()) depVer = v.getAsString(); // JsonNull → null → stale
                    }
                    // A report whose version can't be VERIFIED is not trusted (§2.1) — a missing
                    // header is as untrustworthy as a mismatched one (the Rust engine's rule;
                    // /code-review found the engines split three ways on versionless reports).
                    boolean stale = depVer == null || !depVer.equals(ownVersion);
                    boolean incomplete = declaresItselfIncomplete(obj);
                    // ⟨0.24⟩ the THIRD key on the same door: a report that judged NOTHING. See
                    // {@link #claimsToHaveJudgedNothing} — `functions: []` with `analyzed.count: 0` was
                    // buying strictly more confidence than not chaining the package at all.
                    boolean judgedNothing = claimsToHaveJudgedNothing(obj, fns);
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
                    } else if (incomplete) {
                        // Say it on STDERR too. `gradle test check` and the four-way conformance suite read
                        // the report and the exit code; the smoke suite is the leg that reads this channel,
                        // and standing-bar item 7g is the record of a defect sitting in the channel nobody's
                        // assertions looked at.
                        System.err.println("candor: CANDOR_DEPS report " + f + " declares itself INCOMPLETE"
                                + " (⟨0.21⟩ `unanalyzed` is non-empty or malformed) — its entries are kept,"
                                + " but its packages are NOT counted as covered, so a key it does not answer"
                                + " falls back to the κ ledger's `invisible: [pkg]` hedge instead of reading"
                                + " pure. Re-run the dependency's scan over source this build can analyze.");
                    } else if (judgedNothing) {
                        // Same channel as the two arms above, and for the same reason: the smoke suite is
                        // the leg that reads stderr, and a disclosure nobody's assertions look at is where
                        // defects sit. The remedy is named because a count-0 report is usually a
                        // MIS-TARGETED scan (an empty output directory, a facade module with no compiled
                        // classes of its own), not a fact about the dependency.
                        System.err.println("candor: CANDOR_DEPS report " + f + " judged NOTHING (⟨0.24⟩"
                                + " `analyzed.count` is 0, absent-with-no-functions, or unreadable) — its"
                                + " packages are NOT counted as covered, so a call into them falls back to"
                                + " the κ ledger's `invisible: [pkg]` hedge instead of reading pure. Point"
                                + " the dependency's scan at compiled classes it can actually analyze.");
                    }
                    // File-level coverage: the producer's own package name(s) register the report's
                    // packages as COVERED even when `functions` is empty — an all-pure dep's empty
                    // report is its purity claim (SPEC §2 rule 3; the serde_json lesson). Accept BOTH
                    // the spec's singular `"package": "<name>"` (what candor-report and candor-ts
                    // emit) AND this engine's own plural `packages[]` — reading only the array meant an
                    // all-pure spec-form report was ignored and its package falsely named a blind spot.
                    //
                    // ⟨0.21⟩ …AND NEITHER DOES A REPORT THAT DECLARES ITSELF INCOMPLETE. See
                    // {@link #declaresItselfIncomplete}: the same door as staleness with a different key.
                    //
                    // ⟨0.24⟩ …NOR DOES A REPORT THAT JUDGED NOTHING. `functions: []` is the shape of BOTH an
                    // all-pure dependency (rule 3's claim, which must survive) and one that analyzed no
                    // units at all; ⟨0.21⟩'s `analyzed.count` is the only thing on the wire that tells them
                    // apart. See {@link #claimsToHaveJudgedNothing}.
                    if (!stale && !incomplete && !judgedNothing)
                        ctx().depCoveredPkgs.addAll(reportPackages(obj));
                    for (JsonElement el : fns) {
                        if (!el.isJsonObject()) continue;                 // a non-object entry → skip (not pure-able)
                        JsonObject m = el.getAsJsonObject();
                        if (!m.has("hash") || !m.get("hash").isJsonPrimitive()) continue; // v0.1 / no cross-jar id
                        String h = m.get("hash").getAsString();
                        if (h.isBlank()) continue;
                        DepFn de = new DepFn();
                        de.stale = stale;
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
                            // §2 `calls` + `fn`: the dependency's OWN effect-relevant call graph. A dep
                            // entry whose Unknown was INHERITED carries no `unknownWhy` of its own (the
                            // field is direct-by-contract), so the reason class died one hop past where
                            // ⟨0.19⟩'s boundary fix looked. The chain is on the wire already — record it
                            // so {@link Candor#depTransitiveWhy} can walk it. Keyed by the report QUAL,
                            // which is what `calls` names.
                            if (m.has("fn") && m.get("fn").isJsonPrimitive()) {
                                de.fn = m.get("fn").getAsString();
                                if (!de.unknownWhy.isEmpty())
                                    ctx().depWhyByFn.computeIfAbsent(de.fn, k -> new ArrayList<>())
                                            .addAll(de.unknownWhy);
                                if (m.has("calls") && m.get("calls").isJsonArray()) {
                                    List<String> cs = ctx().depCallsByFn
                                            .computeIfAbsent(de.fn, k -> new ArrayList<>());
                                    for (JsonElement x : m.getAsJsonArray("calls"))
                                        if (x.isJsonPrimitive()) cs.add(x.getAsString());
                                }
                            }
                        }
                        // UNION on collision, never overwrite — see DepFn#unionWith for what
                        // last-non-empty-wins cost (a stale {Unknown} erasing a trusted Fs, `deny Fs`
                        // exit 1 -> 0) and why the order-independence matters.
                        //
                        // THE `!isEmpty()` GATE IS UNCHANGED, deliberately. It decides WHETHER AN ENTRY IS
                        // RECORDED AT ALL, which is a different question from how two recorded entries
                        // reconcile, and this commit is only answering the second. Admitting empty entries
                        // would make a key that is currently ABSENT resolve as present-and-pure, which is a
                        // new purity claim on a path nothing here has measured — exactly the kind of tail
                        // that turns a soundness fix into its mirror.
                        if (!de.effects.isEmpty()) {
                            DepFn prev = ctx().crossDeps.get(h);
                            if (prev == null) ctx().crossDeps.put(h, de);
                            else prev.unionWith(de);
                        }
                        // Entry-level coverage fallback (reports with no package field): the hash's
                        // package prefix gives the EXACT package. The spec join key is `pkg#qual`
                        // (Rust/TS) — take what's before `#`; this engine's own hash is the
                        // slash-form `owner/Class.method(desc)`, so fall back to the last `/`.
                        // The COVERAGE half is gated on trust for the same reason as the file-level
                        // registration above (an untrusted report's entry names a package, it does not
                        // vouch for it), ⟨0.21⟩ on the report declaring itself complete and ⟨0.24⟩ on its
                        // having judged anything at all, each for the reason recorded at its predicate; the
                        // CHAINED-NESS half is none of the three, for the reason recorded there. A count-0
                        // report reaches this loop with no entries, so the ⟨0.24⟩ conjunct here bites only on
                        // the CONTRADICTORY shapes — a manifest that cannot be read, or one claiming zero
                        // while listing functions — and it fails those closed rather than picking a side.
                        String pkg = entryPackage(h);
                        if (pkg == null) continue;
                        ctx().depChainedPkgs.add(pkg);
                        if (!stale && !incomplete && !judgedNothing) ctx().depCoveredPkgs.add(pkg);
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
        synthesizeReasonlessDepReasons();
    }

    /**
     * ⟨0.24⟩ SPEC §6.2 — MAKE THE REASONLESS {@code Unknown} UNREACHABLE, at the SOURCE.
     *
     * <p>A reason-scoped gate (`deny E Unknown[unresolved]`) quantifies over a function's reason-CLASS set.
     * The rule used to be keyed on ABSENCE: an empty class set was read as `{unresolved}`. Absence is not
     * upward-closed, so acquiring a SECOND, classifiable reason REMOVED the default — and a function
     * calling both a reasonless dependency and a reasoned one PASSED a gate that rejected a function
     * calling only the reasonless one. Adding a call turned a red verdict green, which is the silent
     * relaxation `reference/policy_model.py` Lemma 2 forbids (`Reject` is upward-closed). No rewriting of
     * the emptiness test could have separated those two functions: their class sets were IDENTICAL.
     *
     * <p>So the state is removed rather than handled, which is also what the formal model demands — Def 6
     * makes the reason set the CARRIER of the `Unknown`, so "Unknown present, no reasons" is not a
     * representable signature at all. A dependency ENTRY that carries `Unknown` and can account for none
     * of it gets an actual reason recorded here, at the point that `Unknown` enters this scan: `dep:<hash>`
     * ordinarily, `dep-stale:<pkg>` for a §2.1 distrusted producer. Both project to `unresolved`
     * ({@link io.poly.candor.model.ReasonClass#classify}: ⟨0.24⟩ SPEC §4 now REGISTERS both kinds and §6.2
     * fixes that class, so classify pins them on their own branch instead of leaning on the conservative
     * catch-all), so the fail-closed intent the old default had is kept, and it now COMPOSES: because the
     * reason rides the ENTRY rather than the consuming function, a caller of a reasonless entry and a
     * reasoned one accumulates `{unresolved, dispatch}` with no join-time special case. candor-swift
     * reached this shape independently, before the model was written; SPEC §6.2 names it as the one to copy.
     *
     * <p><b>It is conditional, and that is the whole fix.</b> "The entry carries `Unknown`" is NOT the
     * trigger — "and nothing accounts for it" is. {@link Candor#depTransitiveWhy} is the accounting: the
     * entry's own tags PLUS every tag reachable through the `calls` graph its report published, which is
     * exactly where an INHERITED `Unknown`'s reason lives. Contributing `unresolved` whenever an `Unknown`
     * is present would mark every chained `Unknown`-bearing entry, flood every narrowed `[class]` gate and
     * delete the feature (measured on candor-swift's corpus: 435 marked where the legitimate count is 0).
     *
     * <p>Runs ONCE, after every report is read, because `calls` may name an entry later in the same file.
     * Decisions are computed against the pre-pass state and only then applied, so the result cannot depend
     * on entry order; the {@code depTransWhyMemo} is dropped afterwards because the answers it holds were
     * computed before these tags existed.
     */
    private static void synthesizeReasonlessDepReasons() {
        AnalysisContext c = ctx();
        List<Map.Entry<String, DepFn>> reasonless = new ArrayList<>();
        for (var e : c.crossDeps.entrySet()) {
            DepFn de = e.getValue();
            if (!de.effects.hasUnknown()) continue;               // no Unknown → nothing to carry a reason
            if (!Candor.depTransitiveWhy(de).isEmpty()) continue; // already accounted for → NOT reasonless
            reasonless.add(e);
        }
        for (var e : reasonless) {
            String pkg = entryPackage(e.getKey());
            e.getValue().unknownWhy.add(e.getValue().stale
                    ? "dep-stale:" + (pkg == null ? "?" : pkg)
                    : "dep:" + e.getKey());
        }
        if (!reasonless.isEmpty()) c.depTransWhyMemo.clear();
    }
}
