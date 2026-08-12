package io.poly.candor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import io.poly.candor.model.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Read-only queries over a candor report (candor-spec §2): show / where / callers / map / diff.
 * The analyzer ({@link Candor}) writes the report; these answer questions about it WITHOUT
 * re-analysis — the sibling of the Rust impl's {@code candor-query}. Each takes an optional
 * {@code --json} flag for machine-readable output (the form an agent / MCP server consumes); the
 * default is the human view. Accepts the v0.2 {@code { candor, functions }} envelope and the legacy
 * v0.1 bare array.
 */
public final class Query {
    static final Set<String> COMMANDS =
            Set.of("show", "where", "callers", "map", "diff", "containment", "reachable", "path", "impact",
                    "blindspots", "tour", "gains", "whatif", "fix", "fix-gate", "unverified", "rewire",
                    "gate");   // ⟨0.24⟩ SPEC §3.1 — apply a policy to an EXISTING report, with no scan
    static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();

    // Boundary effects SHOULD live in a dedicated layer — their dispersion is the architecture signal
    // (NOT raw counts, which are domain-dependent). Ambient effects are expected to be cross-cutting
    // (logging/timestamps everywhere is fine), so they're reported but not scored. Unknown is excluded
    // (it's a visibility metric, not an effect). MEMBERSHIP is DERIVED from the §6.1 partition on the
    // Effect enum (the single source of truth, so adding an effect can't leave these stale); ORDER follows
    // the historical §6.1 display priority below (so the `containment` output stays stable), with any
    // effect beyond that list trailing alphabetically.
    private static final List<String> DISPLAY_ORDER =
            List.of("Db", "Net", "Llm", "Exec", "Fs", "Ipc", "Log", "Clock", "Rand", "Env");
    private static List<String> derive(java.util.function.Predicate<Effect> p) {
        return Arrays.stream(Effect.values()).filter(p).map(Effect::specName)
                .sorted(Comparator.comparingInt(n -> {
                    int i = DISPLAY_ORDER.indexOf(n);
                    return i < 0 ? Integer.MAX_VALUE : i;
                }))
                .toList();
    }
    static final List<String> CONTAINED = derive(Effect::isBoundary);
    static final List<String> AMBIENT = derive(Effect::isCrossCutting);

    static List<Effector> load(String path) throws Exception {
        JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
        // v0.2 self-describing envelope { candor, functions:[...] } OR legacy v0.1 bare array [...].
        // A parsable JSON that is NEITHER (an object with no `functions`, a scalar) is NOT a candor
        // report — FAIL LOUD. Returning List.of() silently read a half-written/foreign file as "all
        // pure", a silent under-report (gains then alarmed on everything; show said "no effects").
        JsonArray arr;
        if (root.isJsonObject()) {
            JsonObject obj = root.getAsJsonObject();
            if (!obj.has("functions"))
                throw new IllegalArgumentException("not a candor report: object has no 'functions' array");
            arr = obj.getAsJsonArray("functions"); // a present-but-empty [] is a valid pure report
        } else if (root.isJsonArray()) {
            arr = root.getAsJsonArray();
        } else {
            throw new IllegalArgumentException("not a candor report: expected an envelope object or a bare array");
        }
        if (arr == null) throw new IllegalArgumentException("candor report 'functions' is not an array");
        // ReportJson.parseEntries normalizes absent fields to empty/default (never null), so the
        // per-field normalization the old gson-into-Effector path needed is gone.
        List<Effector> fns = new ArrayList<>(io.poly.candor.model.ReportJson.parseEntries(arr));
        // An entry with no `fn` key, `fn: null`, or a blank `fn` is not addressable — every query keys,
        // sorts, and formats by `fn()`, so a null there NPEs and a blank one throws a
        // MissingFormatWidthException (`%-0s`). Such an entry can't be named, queried, or pathed; drop it
        // loudly rather than crash. A foreign file with NO valid entries is still caught above.
        int beforeFilter = fns.size();
        fns.removeIf(f -> f.fn() == null || f.fn().isEmpty());
        if (fns.size() < beforeFilter)
            System.err.println("candor: skipping " + (beforeFilter - fns.size())
                    + " report entr" + (beforeFilter - fns.size() == 1 ? "y" : "ies") + " with no 'fn'");
        // A report array that had elements but yielded ZERO usable functions (every entry was malformed —
        // e.g. a bare `[1,2,3]`) is corruption, NOT an effect-free crate: returning [] would let `tour`
        // print "nothing hidden" and a policy `map`/gate PASS — the §4 cardinal-sin false all-clear. Fail
        // loud (the caller relays this as exit 2). A CLEAN-empty report (arr is []) stays a valid pure
        // report — parity with the rust/ts/swift engines, which also exit 0 only on a well-formed empty.
        if (!arr.isEmpty() && fns.isEmpty())
            throw new IllegalArgumentException(
                    "no usable functions — every report entry was malformed (corrupt report); re-run the scan");
        fns.sort(Comparator.comparing(Effector::fn));
        return fns;
    }

    /** The two-positional comparative verbs (SPEC §3.3.1): `diff`/`gains`/`rewire` take `<current>
     *  <baseline>` — two explicit report locators, in that order — so report discovery does NOT apply to
     *  them (they compare two named reports). Every other verb takes at most one report, discovered or
     *  `--report`-supplied. */
    static final Set<String> TWO_REPORT = Set.of("diff", "gains", "rewire");
    /** The verbs that honour `--policy` (SPEC §3.3.1): whatif/fix/fix-gate/unverified. */
    static final Set<String> POLICY_VERBS = Set.of("whatif", "fix", "fix-gate", "unverified");

    /** Each verb's CANONICAL positional arity (SPEC §3.3.1 verb-args), the count of its OWN args — NOT the
     *  report (a flag, never a positional). This is the ARITY GATE for the deprecated leading-report /
     *  trailing-policy peels: an alias is claimed only from a SURPLUS positional (count &gt; arity), never
     *  from one the canonical form needs. `containment [<baseline>]` has arity 1 (its lone positional is the
     *  baseline, discovered report), so a single bare positional is never re-read as the report. The
     *  two-positional comparatives (diff/gains/rewire) are handled separately and not in this map. */
    static int canonicalArity(String cmd) {
        return switch (cmd) {
            case "path", "whatif", "fix" -> 2;              // <fn> <Effect>
            case "show", "where", "callers", "impact", "containment", "tour" -> 1; // one own-arg ([<baseline>] for containment; [<N>] for tour)
            default -> 0;                                    // map/reachable/blindspots/fix-gate/unverified
        };
    }

    /** Resolve a `--report <locator>` to a full report `.json` path, by the ONE §3.3.1 rule:
     *  a DIRECTORY → the `<dir>/.candor/report` prefix inside it; a path ending `.json` → that FULL path;
     *  otherwise a PREFIX (`<prefix>.<crate>.<backend>.json`). A dir/prefix is expanded to the single
     *  matching report file (sidecars are excluded — §2.2 ⟨0.24⟩'s reserved trailing segments, one rule in
     *  {@link Loader#isSidecarName}). Returns null (with a stderr reason) when a dir/prefix names no
     *  report file. */
    static String resolveReportLocator(String locator) {
        Path p = Path.of(locator);
        if (locator.endsWith(".json")) return locator;              // rule 2: a full report path, verbatim
        if (Files.isDirectory(p))                                    // rule 1: a directory → its .candor/report prefix
            return expandPrefix(p.resolve(".candor").resolve("report").toString(), locator);
        return expandPrefix(locator, locator);                      // rule 3: a bare prefix
    }

    /** Expand a report PREFIX (`<dir>/report`) to the single report file `<prefix>.<crate>.<backend>.json`
     *  beside it — the §3.3.1/§3.4 form the other engines write. A SIDECAR is not a report: the test is
     *  §2.2 ⟨0.24⟩'s reserved TRAILING SEGMENT ({@link Loader#isSidecarName}), never the segment COUNT the
     *  old wording here claimed — sidecar names are per-engine, so counting segments excludes this engine's
     *  own 3-segment sidecars and not a 2-segment one from another producer.
     *  When exactly one report matches, use it; when several do, take the lexicographically
     *  first (deterministic — the Java engine loads ONE report, unlike the Rust lint's multi-crate union),
     *  and disclose the choice. `original` is the user-typed locator, for the error message. Returns null
     *  when nothing matches. */
    static String expandPrefix(String prefix, String original) {
        List<String> hits = prefixHits(prefix);
        if (hits.isEmpty()) {
            reportNotFound(prefix, original);
            return null;
        }
        if (hits.size() > 1)
            System.err.println("candor: locator `" + original + "` matches " + hits.size()
                    + " reports; using " + hits.get(0));
        return hits.get(0);
    }

    /** ALL report files matching a PREFIX, sorted — the glob {@link #expandPrefix} chooses from, without
     *  the choosing (or its stderr chatter). Empty when nothing matches. */
    static List<String> prefixHits(String prefix) {
        Path pp = Path.of(prefix);
        Path dir = pp.getParent() != null ? pp.getParent() : Path.of(".");
        String base = pp.getFileName() != null ? pp.getFileName().toString() : prefix;
        String dot = base + ".";
        // Dedup by NORMALIZED path so the same file discovered two ways is ONE hit — the glob below yields
        // `dir/report.json` while the exact-file check builds `report.json` from the bare prefix; unnormalized
        // these are distinct strings and a lone `report.json` reported as "matches 2 reports" (a false
        // ambiguity disclosure — /code-review). The map keeps the FIRST-seen display string per identity.
        java.util.LinkedHashMap<String, String> hitsByKey = new java.util.LinkedHashMap<>();
        java.util.function.Consumer<Path> addHit = f -> {
            String key;
            try { key = f.toRealPath().toString(); }               // canonical identity when the file exists
            catch (Exception e) { key = f.toAbsolutePath().normalize().toString(); } // fallback: lexical
            hitsByKey.putIfAbsent(key, f.toString());
        };
        try (var s = Files.list(dir)) {
            s.forEach(f -> {
                String name = f.getFileName().toString();
                if (!name.startsWith(dot) || !name.endsWith(".json")) return;
                if (Loader.isSidecarName(name)) return;   // §2.2 ⟨0.24⟩ reserved segment — a sidecar is not a report
                addHit.accept(f);
            });
        } catch (Exception e) {
            // dir unreadable/absent — fall through to the not-found message below
        }
        // An exact `<prefix>.json` (the Java engine's own single-file form) also counts as a match — deduped
        // against the glob above by real-path identity, so it never double-counts a file the glob already saw.
        Path exact = Path.of(prefix + ".json");
        if (Files.isRegularFile(exact)) addHit.accept(exact);
        List<String> hits = new ArrayList<>(hitsByKey.values());
        Collections.sort(hits);
        return hits;
    }

    /** ALL report paths a locator names, by the same §3.3.1 rule as {@link #resolveReportLocator} — but
     *  where that resolver picks ONE (lexicographically first, disclosed), this returns the full match
     *  list, QUIETLY (the caller has already resolved-and-disclosed; this is for consumers that must see
     *  every matched report, e.g. gains' baseline-callgraph union). A `.json` locator is itself the list
     *  (the user named that file; it is honoured verbatim). The prefix/dir EXPANSION, though, is
     *  ENGINE-OWNED: only THIS engine's report shapes — `<base>.<module>.jvm.json` (what ReportWriter
     *  emits) and the exact `<prefix>.json` single-file form — join the list. A FOREIGN engine's report
     *  (`report.mycrate.scan.json`) sitting beside ours must NOT contribute its sidecar to a union
     *  consumer: its qual naming (`m::f`) can never contain JVM quals (`m.f`), so its "evidence" is
     *  systematically absent and gains' origin would read "new" where the truth is "unknown". */
    static List<String> resolveReportLocatorAll(String locator) {
        Path p = Path.of(locator);
        if (locator.endsWith(".json")) return List.of(locator);
        String prefix = Files.isDirectory(p)
                ? p.resolve(".candor").resolve("report").toString()
                : locator;
        Path pp = Path.of(prefix);
        String base = pp.getFileName() != null ? pp.getFileName().toString() : prefix;
        List<String> own = new ArrayList<>();
        for (String h : prefixHits(prefix)) {
            String name = Path.of(h).getFileName().toString();
            if (name.endsWith(".jvm.json") || name.equals(base + ".json")) own.add(h);
        }
        return own;
    }

    /** EVERY report file a locator names, by the same §3.3.1 rule as {@link #resolveReportLocator} — the
     *  set {@link #expandPrefix} picks ONE from, returned whole and QUIETLY.
     *
     *  <p>Distinct from {@link #resolveReportLocatorAll}, which additionally filters to this ENGINE's own
     *  report shapes because its consumer (gains' baseline-callgraph union) would mis-read a foreign
     *  engine's qual naming. The gate has no such constraint — it reads `inferred`/`unknownWhy`, which
     *  every engine writes in the same §2 shape, and `gate --report other-engine.scan.json` is a supported
     *  invocation — so this one takes the candidate set VERBATIM. Keeping the two apart matters: the set
     *  the gate reads MUST equal the set the "matches N reports" disclosure counted, or the disclosure
     *  lies about the answer. */
    static List<String> locatorReportSet(String locator) {
        if (locator == null) return List.of();
        if (locator.endsWith(".json")) return List.of(locator);   // rule 2: that FULL path, verbatim
        Path p = Path.of(locator);
        String prefix = Files.isDirectory(p)                       // rule 1: a directory → its .candor/report
                ? p.resolve(".candor").resolve("report").toString()
                : locator;                                         // rule 3: a bare prefix
        return prefixHits(prefix);
    }

    /** The `looked for …` line {@link #expandPrefix} prints when a dir/prefix locator names no report —
     *  shared so the SET resolver ({@link #locatorReportSet}) fails with the same words as the single one. */
    static void reportNotFound(String prefix, String original) {
        Path pp = Path.of(prefix);
        Path dir = pp.getParent() != null ? pp.getParent() : Path.of(".");
        String base = pp.getFileName() != null ? pp.getFileName().toString() : prefix;
        System.err.println("candor: no report found for locator `" + original + "` (looked for "
                + base + ".*.json under " + dir + ")");
    }

    /** The LOCATOR §3.3.1 discovery yields, BEFORE expansion: a `CANDOR_REPORT` env var overrides; else
     *  walk UP from the CWD for a `.candor/` directory and use its `report` prefix (the §3.4 config
     *  discovery mechanism, applied to the report). Returns null (with a stderr reason) when no `.candor/`
     *  is found. Kept separate from {@link #discoverReport} because `gate` needs the locator itself — a
     *  discovered PREFIX can name a report SET, and expanding it to one file first would throw the rest
     *  away before the verb ever saw them. */
    static String discoverReportLocator() {
        String override = System.getenv("CANDOR_REPORT");
        if (override != null && !override.isEmpty()) return override;
        Path p = Path.of("").toAbsolutePath();
        for (; p != null; p = p.getParent()) {
            Path candor = p.resolve(".candor");
            if (Files.isDirectory(candor)) return candor.resolve("report").toString();
        }
        System.err.println("candor: no report given and no `.candor/` directory found walking up from the CWD "
                + "— pass --report <locator> or set CANDOR_REPORT.");
        return null;
    }

    /** DISCOVER the report when no `--report` was given (SPEC §3.3.1). Returns the resolved report path, or
     *  null (with a stderr reason) when no `.candor/` is found or the prefix names no report. */
    static String discoverReport() {
        String loc = discoverReportLocator();
        return loc == null ? null : resolveReportLocator(loc);
    }

    /** Does `tok` resolve to an existing report (a `.json` file, or a dir/prefix with a matching report)?
     *  Used ONLY to detect the DEPRECATED leading-positional report form — so `where <report.json> Net`
     *  (old) is told apart from `where Net` (canonical, discovered). A quiet probe: it must NOT print the
     *  not-found chatter {@link #resolveReportLocator} does, so a canonical first-positional (an Effect / a
     *  fn substring) simply reads as "not a report". */
    static boolean looksLikeReport(String tok) {
        if (tok == null) return false;
        Path p = Path.of(tok);
        if (tok.endsWith(".json")) return Files.isRegularFile(p);
        if (Files.isDirectory(p))
            return Files.isRegularFile(p.resolve(".candor").resolve("report"))  // unlikely, but honour an exact file
                    || quietPrefixMatches(p.resolve(".candor").resolve("report").toString());
        return quietPrefixMatches(tok);
    }

    /** Does `tok` have the SHAPE of an EXPLICIT report locator the user clearly MEANT as a report — a path
     *  ending `.json`, or an existing directory (both §3.3.1 locator forms that resolve to a specific file),
     *  as opposed to a bare fn/effect substring? Used so a SURPLUS leading positional of that shape which
     *  names NOTHING fails LOUD naming it (cardinal-sin guard), instead of being left as a verb arg and
     *  silently falling through to discovery: `show <missing>.json foo` must error on the missing report,
     *  not answer "no function matching `<missing>.json`" at exit 0. A bare prefix (`report`) is deliberately
     *  NOT of this shape — it is indistinguishable from a fn substring, so it only peels when it actually
     *  {@link #looksLikeReport}. */
    static boolean explicitLocatorShape(String tok) {
        if (tok == null) return false;
        return tok.endsWith(".json") || Files.isDirectory(Path.of(tok));
    }

    /** True iff a report file matches the prefix, WITHOUT the stderr chatter of {@link #expandPrefix}. */
    static boolean quietPrefixMatches(String prefix) {
        Path pp = Path.of(prefix);
        Path dir = pp.getParent() != null ? pp.getParent() : Path.of(".");
        String base = pp.getFileName() != null ? pp.getFileName().toString() : prefix;
        String dot = base + ".";
        if (Files.isRegularFile(Path.of(prefix + ".json"))) return true;
        try (var s = Files.list(dir)) {
            return s.anyMatch(f -> {
                String n = f.getFileName().toString();
                return n.startsWith(dot) && n.endsWith(".json") && !Loader.isSidecarName(n);
            });
        } catch (Exception e) {
            return false;
        }
    }

    static int run(String[] args) {
        String cmd = args[0];
        boolean json = false;
        boolean includeUnknown = false; // `callers --include-unknown`: also disclose the unresolved-dispatch frontier
        boolean strict = false;         // `unverified --strict`: exit 1 on an unverified-purity hole
        boolean stats = false;          // `blindspots --stats`: the reason-class distribution, not the source list
        String classFlag = null;        // `blindspots --class <c,…>`: keep only Unknown sources of these reason classes
        // ── SPEC §3.3.1 ⟨0.27⟩ ARM FIRST, AND NEVER OVER AN INPUT.
        //
        // THE ⟨0.27⟩ SWEEP ADDED THIS TO `Candor.main` AND MISSED THIS VERB ENTIRELY, so the reference
        // engine's supply-chain gate still reproduced §3.3.1's own worked example verbatim:
        // `gate --report R --policy P --gate-json P` exited **0** with `"ok": true` after overwriting P
        // (control, different sink: exit 1). It also still armed mid-flag-loop, so an unknown flag BEFORE
        // `--gate-json` left the previous run's green on disk while the same mistake spelled the other
        // way round wrote a refusal — the argv-order dependence the rule exists to forbid. A pre-pass
        // learns the sink and this run's inputs with no side effects, before anything can exit or write.
        {
            String preGate = null, prePolicy = null, preReport = null;
            for (int i = 0; i < args.length; i++) {
                boolean hasVal = i + 1 < args.length;
                if (args[i].equals("--gate-json") && hasVal
                        && (args[i + 1].equals("-") || !args[i + 1].startsWith("-"))) preGate = args[++i];
                else if (args[i].equals("--policy") && hasVal && !args[i + 1].startsWith("-")) prePolicy = args[++i];
                else if (args[i].equals("--report") && hasVal && !args[i + 1].startsWith("-")) preReport = args[++i];
            }
            if (preGate != null) {
                // §3.3.1 names "a report being read (`gate --report`)" as an input. Writing the verdict
                // there destroys the very report the gate was asked to judge.
                Candor.refuseGateJsonOverInput(preGate, preReport, "--report");
                // Anchored at the CWD, not the report: this verb's policy ladder discovers the config
                // from the CWD, so asking the report's directory was a different question and left a
                // config-declared policy unguarded.
                Candor.refuseGateJsonOverAnyInput(preGate, ".", prePolicy);
                // ⟨0.28⟩ THE RUNG BINDS EVERY ROUTE. It shipped on the scan CLI only, so this verb kept
                // last-wins: a gate that FIRED wrote red to the last sink and left the first holding a
                // previous run's {"ok": true}. Every named sink gets the input checks too, and the input
                // exemption covers THAT PATH, not the run.
                var namedSinks = new java.util.ArrayList<String>();
                for (int i = 0; i < args.length; i++) {
                    if (args[i].equals("--gate-json") && i + 1 < args.length
                            && (args[i + 1].equals("-") || !args[i + 1].startsWith("-"))) {
                        String v = args[++i];
                        boolean seen = false;
                        for (String k : namedSinks)
                            if (k.equals(v) || (!k.equals("-") && !v.equals("-") && Candor.sameArtifact(k, v))) seen = true;
                        if (!seen) namedSinks.add(v);
                    }
                }
                for (String sNamed : namedSinks) {
                    if (sNamed.equals("-")) continue;
                    Candor.refuseGateJsonOverInput(sNamed, preReport, "--report");
                    Candor.refuseGateJsonOverAnyInput(sNamed, ".", prePolicy);
                }
                if (namedSinks.size() > 1) {
                    String list = String.join(", ", namedSinks);
                    System.err.println("candor: --gate-json given more than once (" + list + ") — refusing "
                            + "(exit 2). A gate publishes ONE verdict. Naming two sinks says where it goes "
                            + "twice, and the reader of the path that loses cannot tell it lost.");
                    var doc = new java.util.LinkedHashMap<String, Object>();
                    doc.put("spec", Candor.SPEC_VERSION);
                    doc.put("ok", false);
                    doc.put("refused", true);
                    doc.put("reason", "--gate-json was given more than once (" + list + ") — a run "
                            + "publishes one verdict to one sink");
                    String text = io.poly.candor.model.ReportJson.pretty(doc);
                    for (String sNamed : namedSinks) {
                        if (sNamed.equals("-")) { System.out.println(text); continue; }
                        try {
                            java.nio.file.Files.writeString(java.nio.file.Path.of(sNamed), text + "\n");
                        } catch (java.io.IOException | RuntimeException e) {
                            System.err.println("candor: could not write the refusal to --gate-json " + sNamed
                                    + " (" + e.getMessage() + ")");
                        }
                    }
                    System.exit(2);
                }
                Candor.armGateJson(preGate);
                // ⟨0.27⟩ …AND THE STREAM SINK'S ANALOG, which this pre-pass was missing while the SCAN
                // path had it. `armGateJson` writes a fail-closed placeholder to a FILE; a stream cannot
                // hold one, so `armGateJsonStream` installs the shutdown hook that emits the refusal on
                // any exit-2 path instead.
                //
                // Measured, same verb, same flag, both exit 2:
                //   gate --report R --policy P --gate-json - --frobnicate   0 bytes on stdout
                //   gate --report R --policy <missing> --gate-json -      164 bytes, the refusal
                // The second worked because `gate()` is reached and refuses from inside; the first is
                // rejected during arg parsing, before any of that runs. A machine consumer reading an
                // empty stream after exit 2 has nothing to distinguish it from a clean gate, which is
                // the exact channel §3.3.1 arming exists to close.
                //
                // Found by the 0.27 go/no-go panel, testing this engine's own changelog claim that ANY
                // exit-2 cause leaves the refusal as stdout's only content. PART 36's stream rows run
                // the SCAN route only, so conformance passed straight over it.
                if (preGate.equals("-")) Candor.armGateJsonStream();
            }
        }
        String reportFlag = null;       // --report <locator> (canonical §3.3.1)
        String policyFlag = null;       // --policy <file> (canonical §3.3.1)
        String gateJsonFlag = null;     // --gate-json <file|-> (⟨0.24⟩ `gate`, the scan path's own flag)
        List<String> pos = new ArrayList<>();
        // `--text`/`--human` are candor-ts's output-mode flags (#8): java prose is always the default, so
        // ACCEPT + ignore them — cross-engine `candor <verb> --text` must not error just because the report
        // routed to the JVM engine. (java already rejects a genuinely-unknown flag via rejectUnknownFlag.)
        Set<String> known = java.util.Set.of("--json", "--text", "--human", "--include-unknown", "--strict", "--stats", "--class", "--report", "--policy", "--gate-json");
        String usage = "candor " + cmd + " <verb-args…> [--report <locator>] [--policy <file>] [--json] [--strict] [--include-unknown]";
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--json" -> json = true;
                case "--text", "--human" -> { /* candor-ts output-mode flags; java prose is the default — accept + ignore */ }
                case "--include-unknown" -> includeUnknown = true;
                case "--strict" -> strict = true;
                case "--stats" -> stats = true;
                case "--class" -> {
                    if (i + 1 >= args.length) { System.err.println("candor: --class needs <class,…> (usage: " + usage + ")"); return 2; }
                    // ⟨0.24⟩ SPEC §6.2: `--class <c>[,<c>…]` takes ONE comma-separated list and is NOT
                    // repeatable — a second occurrence is a usage error, not a union. Unioning would answer
                    // a question the user did not ask (they wrote two filters and got neither); taking the
                    // last would silently discard the first. Both are a smaller number under a flag the
                    // user believes they widened.
                    if (classFlag != null) {
                        System.err.println("candor " + cmd + ": --class was given more than once (`" + classFlag
                                + "` then `" + args[i + 1] + "`). It takes ONE comma-separated list and is not "
                                + "repeatable — a second occurrence is a usage error, not a union. Write: --class "
                                + classFlag + "," + args[i + 1]);
                        return 2;
                    }
                    classFlag = args[++i];
                }
                case "--report" -> {
                    if (i + 1 >= args.length) { System.err.println("candor: --report needs a <locator> (usage: " + usage + ")"); return 2; }
                    reportFlag = args[++i];
                }
                case "--policy" -> {
                    if (i + 1 >= args.length) { System.err.println("candor: --policy needs a <file> (usage: " + usage + ")"); return 2; }
                    policyFlag = args[++i];
                }
                case "--gate-json" -> {
                    // Same dash-check as main()'s: a valueless OR flag-shaped value FAILS (exit 2), so
                    // `--gate-json --policy p` cannot swallow `--policy` and run gateless-green. `-` = stdout.
                    boolean ok = i + 1 < args.length && (args[i + 1].equals("-") || !args[i + 1].startsWith("-"));
                    if (!ok) { System.err.println("candor: --gate-json requires a value (a path, or `-` for stdout)"); return 2; }
                    gateJsonFlag = args[++i];
                    // (armed by the pre-pass above — arming HERE made the contract depend on argv order.)
                }
                default -> {
                    // an unknown --flag must FAIL, not be swallowed as a query positional (a typo'd
                    // --jsno otherwise returns prose to a wrapper expecting JSON) — same posture as main()
                    Candor.rejectUnknownFlag(args[i], known, usage);
                    pos.add(args[i]);
                }
            }
        }

        // ── DEPRECATED-ALIAS DETECTION (back-compat, §3.3.1) ────────────────────────────────────────────
        // The old form put the report as a LEADING POSITIONAL (a full `.json` path/dir/prefix), and — for
        // the policy verbs — the policy as a trailing positional. Detect them so the pre-0.10 invocations
        // the conformance suite drives (`candor where <report.json> Net --json`) stay green.
        //
        // ARITY-GATED (§3.3.1): the leading-report peel fires ONLY from a SURPLUS positional — the count must
        // EXCEED the verb's canonical arity ({@link #canonicalArity}). At count == arity every positional is
        // a verb arg the canonical form needs, so it is NEVER probed as a report: `where Net` is the effect
        // `Net` even when a stray `Net.app.jvm.json` sits in the CWD, and `containment <baseline>` (one
        // positional) is the baseline, discovered report — never re-read as the report (a silent gate-off).
        // CONTENT-GATED: of that surplus first positional, we peel it as the report when it actually
        // {@link #looksLikeReport}; a surplus first positional of EXPLICIT-LOCATOR SHAPE that names nothing
        // (`show <missing>.json foo`) is still consumed AS the report so the missing file fails LOUD naming
        // it — never silently dropped to discovery (the cardinal sin). Aligns with the candor-swift peel.
        String report = null;
        String reportLocator = null;         // the locator AS TYPED, before prefix expansion (see `gate` below)
        boolean explicitReportGiven = false; // did the user name a report (via --report or a leading locator)?
        if (TWO_REPORT.contains(cmd)) {
            // diff/gains/rewire: two positional locators <current> <baseline>. No discovery, no --report.
            if (reportFlag != null)
                System.err.println("candor: --report is ignored for `" + cmd + "` — it takes two positional report locators <current> <baseline>.");
        } else if (reportFlag != null) {
            explicitReportGiven = true;
            reportLocator = reportFlag;
        } else if (pos.size() > canonicalArity(cmd)
                && (looksLikeReport(pos.get(0)) || explicitLocatorShape(pos.get(0)))) {
            // DEPRECATED: a leading-positional report (surplus + report-shaped). Consume it, warn, resolve it
            // the same 3 ways. When it names nothing, load() below fails loud with the locator in parens.
            explicitReportGiven = true;
            System.err.println("candor: the leading-positional report is deprecated — use `--report " + pos.get(0)
                    + "` (report discovery + --report is the canonical §3.3.1 grammar). Still accepted for now.");
            reportLocator = pos.remove(0);
        } else if (!TWO_REPORT.contains(cmd)) {
            // canonical: discover the report (walk up for .candor/, or CANDOR_REPORT).
            reportLocator = discoverReportLocator();
            if (reportLocator == null) return 2;
        }

        // ⟨0.24⟩ THE REPORT SET, and why only `gate` reads it. §2: "A consumer SHOULD treat all reports
        // under one prefix as a single analysis world" — a PREFIX locator names a report SET, not a file.
        // {@link #expandPrefix} picks the lexicographically-first and DISCLOSES the choice on stderr, which
        // is a narrowing a human reading prose is told about. `gate` is the one verb whose output is a
        // MACHINE VERDICT — an exit code and a `--gate-json` document — and there a narrowing is invisible:
        // a violating sibling the locator named and the verb never opened comes back `ok: true`, exit 0.
        // That is the §4 false all-clear, so this verb reads EVERY report the locator names and gates over
        // the union. See {@link #gate} for the join rule and for why the other verbs are NOT changed here.
        List<String> reportSet = List.of();
        if (!TWO_REPORT.contains(cmd)) {
            if (cmd.equals("gate")) {
                reportSet = locatorReportSet(reportLocator);
                if (reportSet.isEmpty()) {
                    Path lp = Path.of(reportLocator);
                    reportNotFound(Files.isDirectory(lp)
                            ? lp.resolve(".candor").resolve("report").toString() : reportLocator, reportLocator);
                    return 2;
                }
                report = reportSet.get(0);
            } else {
                report = resolveReportLocator(reportLocator);
                if (report == null) return 2;
            }
        }

        // DEPRECATED: a trailing POSITIONAL policy on the policy verbs, when --policy wasn't given. whatif
        // takes <fn> <Effect> [policy] (index 2); fix <fn> <Effect> [policy] (index 2); fix-gate [policy]
        // (index 0); unverified [policy] (index 0). Only claim it as a policy when --policy is absent AND
        // there's an extra positional beyond the verb's fixed args.
        if (policyFlag == null && POLICY_VERBS.contains(cmd)) {
            int fixedArgs = switch (cmd) { case "whatif", "fix" -> 2; default -> 0; }; // <fn> <Effect> vs none
            if (pos.size() > fixedArgs) {
                policyFlag = pos.remove(fixedArgs);
                System.err.println("candor: the positional policy is deprecated — use `--policy " + policyFlag
                        + "`. Still accepted for now.");
            }
        }

        // `--gate-json` is the GATE's verdict flag: on a read-only query it would be silently inert, which is
        // the gateless-green shape (a wrapper writes a verdict path, reads nothing, and calls it clean).
        if (gateJsonFlag != null && !cmd.equals("gate")) {
            System.err.println("candor " + cmd + ": --gate-json applies to `gate` (and to a scan) — `" + cmd
                    + "` emits no gate verdict. Use `candor gate --report <locator> --policy <file> --gate-json "
                    + gateJsonFlag + "`.");
            return 2;
        }

        // The comparative verbs load their reports themselves (two positionals); `gate` loads the whole
        // report SET itself (above); the rest load `report`.
        List<Effector> fns = List.of();
        if (!TWO_REPORT.contains(cmd) && !cmd.equals("gate")) {
            try {
                fns = load(report);
            } catch (Exception e) {
                // load() throws PRECISE reasons ("not a candor report: object has no 'functions' array",
                // NoSuchFileException, a JSON syntax error) — relay them, don't discard the diagnostic.
                String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                System.err.println("candor: cannot read report " + report + " (" + why + ")");
                return 2;
            }
        }

        // ⟨0.24⟩ SPEC §6.2 THE FLAG'S VALUE GRAMMAR, parsed ONCE for every verb that takes `--class`, so a
        // value this engine cannot honour is refused on all of them by construction rather than by three
        // authors remembering. See #parseClassFilter for why it is exit 2 and not a warning.
        Set<ReasonClass> classFilter;
        try {
            classFilter = parseClassFilter(classFlag);
        } catch (ClassFilterUsageError e) {
            System.err.println("candor " + cmd + ": " + e.getMessage());
            return 2;
        }

        String a0 = pos.size() > 0 ? pos.get(0) : null; // first verb arg
        String a1 = pos.size() > 1 ? pos.get(1) : null; // second verb arg
        // ⟨0.28⟩ SPEC §2 — the DESCRIPTIVE verbs take the locator beside the resolved path for the same
        // reason the advisory ones do (see #advisoryUnanalyzed): the manifest that qualifies their answer
        // travels on the report SET, and reading only the lexicographically-first file would answer flat
        // over a manifest sitting in the sibling.
        ReportRef ref = new ReportRef(reportLocator, report);
        return switch (cmd) {
            case "show" -> show(fns, a0, json);
            case "where" -> where(fns, a0, json, ref);
            case "callers" -> callers(fns, report, a0, json, includeUnknown);
            case "map" -> map(fns, json, ref);
            case "diff" -> diff2(a0, a1, json);
            case "containment" -> containment(fns, a0, json, ref);
            case "reachable" -> reachable(fns, json, ref);
            case "path" -> path(fns, a0, a1, json);
            case "impact" -> impact(fns, a0, json);
            case "blindspots" -> blindspots(fns, json, stats, classFilter, ref);
            case "tour" -> tour(fns, report, a0, json, ref);
            case "gains" -> gains2(a0, a1, json, strict, policyFlag);
            // ⟨0.24⟩ the ADVISORY verbs take the LOCATOR beside the resolved path: SPEC §3.2 bounds their
            // incompleteness verdict by the GATE's over the same bytes, and the gate reads the report SET
            // the locator names (see #advisoryUnanalyzed).
            case "whatif" -> whatif(reportLocator, report, a0, a1, policyFlag, json);
            case "fix" -> fix(fns, reportLocator, report, a0, a1, policyFlag, json);
            case "fix-gate" -> fixGate(fns, reportLocator, report, policyFlag, json, strict);
            case "unverified" -> unverified(fns, reportLocator, report, policyFlag, json, strict, classFilter);
            case "rewire" -> rewire2(a0, a1, json);
            case "gate" -> gate(reportSet, a0, policyFlag, json, gateJsonFlag);
            default -> 2;
        };
    }

    /** `rewire <current> <baseline>` (§3.3.1 two-positional): resolve each locator to a report path (so its
     *  `.callgraph.json` sidecar can be derived) and delegate to {@link #rewire}. */
    static int rewire2(String curLoc, String baseLoc, boolean json) {
        if (baseLoc == null) return usage("rewire <current> <baseline> [--json]");
        String cur = resolveReportLocator(curLoc);
        String base = resolveReportLocator(baseLoc);
        if (cur == null || base == null) return 2;
        return rewire(cur, base, json);
    }

    /** `diff <current> <baseline>` (§3.3.1 two-positional): resolve each locator, load the current report,
     *  delegate to {@link #diff}. */
    static int diff2(String curLoc, String baseLoc, boolean json) {
        if (curLoc == null) return usage("diff <current> <baseline> [--json]");
        String cur = resolveReportLocator(curLoc);
        if (cur == null) return 2;
        List<Effector> curFns;
        try { curFns = load(cur); }
        catch (Exception e) {
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            System.err.println("candor: cannot read report " + cur + " (" + why + ")");
            return 2;
        }
        String base = baseLoc == null ? null : resolveReportLocator(baseLoc);
        if (baseLoc != null && base == null) return 2;
        return diff(curFns, cur, base, json);
    }

    /** `gains <current> <baseline>` (§3.3.1 two-positional): as {@link #diff2}, for the supply-chain gain.
     *  Advisory (exit 0) by default; `--strict` fails on ANY gained effect (a supply-chain CI gate). gains
     *  has no `--policy` of its own — the generic parser consumes it (a valid cross-verb flag), so a
     *  `gains cur base --policy p` a user reaches for expecting a gate would be SILENTLY dropped and exit 0.
     *  Reject it loud and point at the real gate (a `deny <E> gained` scan policy / `--strict`). */
    static int gains2(String curLoc, String baseLoc, boolean json, boolean strict, String policyFlag) {
        if (policyFlag != null) {
            System.err.println("candor gains: unknown flag `--policy` — gains is a diff view; to FAIL CI on a newly-gained effect gate at scan time with a `deny <E> gained` policy (AS-EFF-005), or use `--strict` to fail on ANY gain");
            return 2;
        }
        if (curLoc == null) return usage("gains <current> <baseline> [--json] [--strict]");
        String cur = resolveReportLocator(curLoc);
        if (cur == null) return 2;
        List<Effector> curFns;
        try { curFns = load(cur); }
        catch (Exception e) {
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            System.err.println("candor: cannot read report " + cur + " (" + why + ")");
            return 2;
        }
        String base = baseLoc == null ? null : resolveReportLocator(baseLoc);
        if (baseLoc != null && base == null) return 2;
        // The ORIGIN graph must see EVERY report the baseline locator matched: the report load above
        // deliberately picks one (disclosed), but existence-at-the-baseline is evidenced by ANY matched
        // report's callgraph sidecar — keying origin on just the chosen one would mislabel a fn from a
        // sibling report's graph as "new". ENGINE-OWNED matches only (resolveReportLocatorAll): a foreign
        // engine's sidecar beside ours is non-evidence, and an empty union means the graph is ABSENT.
        List<String> baseReports = baseLoc == null ? List.of() : resolveReportLocatorAll(baseLoc);
        // ⟨0.28⟩ the LOCATORS travel beside the resolved paths, for the reason the descriptive verbs take
        // them (see #reportCompleteness): the ⟨0.21⟩ manifest that qualifies this answer rides the report
        // SET, and reading only the file the single-report pick chose would answer flat over a manifest
        // sitting in its sibling. Both may be null (a missing baseline is the usage error inside).
        return gains(curFns, new ReportRef(curLoc, cur), new ReportRef(baseLoc, base), baseReports, json, strict);
    }

    static int usage(String u) {
        System.err.println("usage: candor " + u);
        return 2;
    }

    static List<String> sorted(List<String> l) {
        List<String> x = new ArrayList<>(l);
        Collections.sort(x);
        return x;
    }

    static void emit(Object o) {
        System.out.println(JSON.toJson(o));
    }

    /** Name-match tier: 3 = exact, 2 = SEGMENT-SUFFIX (`Svc.act` matches `app.Svc.act`/`Cases$Svc.act`
     *  but not `app.Svc.action` — the char before the query must be a JVM name boundary), 1 = substring,
     *  0 = none. Queries resolve at the BEST tier any candidate reaches, mirroring candor-query. The
     *  boundary is `.` OR `$`: nested-class names use `$` (`Cases$Svc.act`), so a `.`-only check dropped
     *  inner-class queries to substring tier and re-inflated the blast radius (/code-review found it). */
    static int matchTier(String name, String q) {
        // An EMPTY query matches NOTHING, never everything: `name.contains("")` is always true, so an
        // unset/empty fn arg (a shell variable that didn't expand) otherwise selected the WHOLE codebase and
        // produced a real-looking whole-graph blast-radius / policy verdict (same bug candor-rust fixed in
        // match_tier). An empty query is a usage error upstream; here it simply resolves to tier 0.
        if (q.isEmpty()) return 0;
        if (name.equals(q)) return 3;
        if (name.endsWith(q) && name.length() > q.length()) {
            char b = name.charAt(name.length() - q.length() - 1);
            if (b == '.' || b == '$') return 2;
        }
        if (name.contains(q)) return 1;
        return 0;
    }

    static int bestTier(java.util.stream.Stream<String> names, String q) {
        return names.mapToInt(n -> matchTier(n, q)).max().orElse(0);
    }

    /**
     * The policy ladder BELOW {@code --policy}: {@code CANDOR_POLICY}, then the {@code policy} key of
     * the discovered {@code .candor/config} — SPEC §3.3.1, "a QUERY verb inherits the scan grammar
     * unchanged … the same `--policy` fallback".
     *
     * <p>THE CONFIG RUNG WAS MISSING HERE. rust, ts and swift all read it, so `gate --report R` with a
     * checked-in `policy` key gated in three engines and refused with "a policy is required" in this
     * one — a 3-vs-1 split on the family's own "one config, one meaning" claim, on the surface a
     * supply-chain consumer uses. Found by a conformance row added the same day, which asserted the
     * config-declared policy GATES before asserting anything about the sink guard: the control was what
     * caught it.
     *
     * <p>Anchored at the CWD, which is where this verb's discovery starts — it has no scan target.
     */
    static String resolvePolicyFallback() {
        String env = System.getenv("CANDOR_POLICY");
        if (env != null) return env;
        try {
            java.nio.file.Path cfg = Config.discover(java.nio.file.Path.of("."));
            if (cfg == null) return null;
            String p = Config.load(cfg, false).valuesView().get("policy");
            return p == null || p.isEmpty() ? null : p;
        } catch (RuntimeException e) {
            return null;   // the loader refuses for real on the routes that must
        }
    }

    /** The parsed CANDOR_POLICY (Candor.{deny,allow,forbid}Rules) as canonical JSON, for the cross-impl
     *  policy-grammar differential (SPEC §6.2). A `pure` rule appears as a deny with empty `effects`.
     *  Rules are sorted so the comparison is order-independent. */
    static String policyJson() {
        List<Map<String, Object>> deny = new ArrayList<>();
        for (var r : AnalysisState.ctx().denyRules) {
            var m = new java.util.LinkedHashMap<String, Object>();
            m.put("effects", r.effects().toNames());
            m.put("scope", r.scope());
            // Reason-scoped `Unknown[class…]` (REASON-SCOPED-UNKNOWN-DESIGN.md): emit the sorted class
            // tokens ONLY when the rule narrows Unknown, so a bare `deny E`/`deny E Unknown` dump is
            // unchanged (byte-identical to pre-feature) and the four-way parsepolicy differential pins the
            // reason-class parsing across engines. Empty ⇒ `Unknown[*]`, so the key's absence = all classes.
            if (!r.unknownClasses().isEmpty())
                m.put("unknownClasses", r.unknownClasses().stream().map(ReasonClass::token).sorted().toList());
            // Net destination-class `Net[dest…]` (NET-DESTINATION-CLASS-DESIGN.md): emit the sorted dest tokens
            // ONLY when the rule narrows Net, so a bare `deny Net` dump stays byte-identical and the four-way
            // parsepolicy differential pins the destination-class parsing across engines. Empty ⇒ `Net[*]`.
            if (!r.netClasses().isEmpty())
                m.put("netClasses", r.netClasses().stream().sorted().toList());
            deny.add(m);
        }
        List<Map<String, Object>> allow = new ArrayList<>();
        // LinkedHashMap for these rows too, and DOUBLY so: `Map.of` iterates in a per-JVM-launch SALTED
        // order (the top-level comment below records the same defect one scope out), and the `byJson`
        // comparator four lines down sorts the rows BY THEIR SERIALIZED STRING — so with two or more
        // allow rules the salt decided the ROW order as well as the key order within each row. The same
        // policy file dumped differently on different launches of the same build, which is exactly what
        // a canonical dump for the four-way differential must never do.
        for (var r : AnalysisState.ctx().allowRules) {
            var m = new java.util.LinkedHashMap<String, Object>();
            m.put("effect", r.effect().specName());
            m.put("scope", r.scope());
            m.put("values", new ArrayList<>(r.values()));
            allow.add(m);
        }
        List<Map<String, Object>> forbid = new ArrayList<>();
        for (var r : AnalysisState.ctx().forbidRules) {
            var m = new java.util.LinkedHashMap<String, Object>();
            m.put("from", r.from());
            m.put("to", r.to());
            forbid.add(m);
        }
        Comparator<Map<String, Object>> byJson = Comparator.comparing(JSON::toJson);
        deny.sort(byJson); allow.sort(byJson); forbid.sort(byJson);
        // LinkedHashMap, not Map.of: `Map.of` iterates in a per-JVM-run SALTED order, so the dump's TOP-LEVEL
        // key order varied between runs of the same engine on the same file. Nothing byte-compares it today
        // (PART 4 parses the JSON), but a witness whose output is not reproducible is a poor witness.
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("deny", deny); out.put("allow", allow); out.put("forbid", forbid);
        // ⟨0.24⟩ SPEC §3.1 — `parsepolicy` MUST NOT REFUSE: it reports the parse AND what it could not
        // honour, so the unrecognised token APPEARS here instead of being dropped. A diff that cannot tell
        // "dropped" (the pre-⟨0.24⟩ behaviour) from "rejected" (the gate's posture, §6.2) cannot pin this
        // rung at all. Emitted only when non-empty, so a clean policy's dump is byte-identical to the
        // pre-feature one and the four-way PART 4 comparison (deny/allow/forbid) is untouched.
        if (!Policy.policyErrors.isEmpty()) {
            List<Map<String, Object>> errors = new ArrayList<>();
            // FILE ORDER, not sorted: the operator reads these against their policy top-to-bottom, and one
            // parse pass already makes the order deterministic.
            for (var e : Policy.policyErrors) {
                var m = new java.util.LinkedHashMap<String, Object>();
                m.put("kind", e.kind());
                m.put("token", e.token());
                m.put("accepted", e.accepted());
                m.put("rule", e.rule());
                m.put("message", e.message());
                errors.add(m);
            }
            out.put("errors", errors);
        }
        return JSON.toJson(out);
    }

    /** A function's effects, instant — `*` marks an effect performed in its own body. */
    static int show(List<Effector> fns, String q, boolean json) {
        if (q == null) return usage("show <function-substring> [--report <locator>] [--json]");
        int tier = bestTier(fns.stream().map(f -> f.fn()), q);
        List<Effector> hits = tier == 0 ? List.of()
                : fns.stream().filter(f -> matchTier(f.fn(), q) >= tier).collect(Collectors.toList());
        if (json) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Effector f : hits) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", f.fn());
                m.put("inferred", sorted(f.inferred().toNames()));
                m.put("direct", sorted(f.direct().toNames()));
                if (!f.fs().isEmpty()) m.put("fs", f.fs());
                // The engine resolves Net endpoints (hosts) per method; show MUST surface them like the
                // Rust engine (SPEC §3.1 `hosts?`) — the Effector record previously never parsed the field.
                if (!f.hosts().isEmpty()) m.put("hosts", f.hosts());
                // Literal effect surfaces (tables/paths/cmds) mirror fs/hosts — the Rust engine's show
                // surfaces them too; omitting them hid e.g. a Db fn's `tables`. Omit when empty.
                if (!f.tables().isEmpty()) m.put("tables", f.tables());
                if (!f.paths().isEmpty()) m.put("paths", f.paths());
                if (!f.cmds().isEmpty()) m.put("cmds", f.cmds());
                if (!f.netClass().isEmpty()) m.put("netClass", f.netClass()); // ⟨0.20⟩ Net destination-class
                m.put("unresolved", f.unresolved());
                out.add(m);
            }
            emit(out);
            return 0;
        }
        if (hits.isEmpty()) {
            System.out.println("candor: no effectful function matching `" + q + "` (pure functions are omitted).");
            return 0;
        }
        int w = Math.max(1, hits.stream().mapToInt(f -> f.fn().length()).max().orElse(0)); // never %-0s (an empty fn → MissingFormatWidthException)
        boolean anyStar = false;
        for (Effector f : hits) {
            Set<String> direct = new HashSet<>(f.direct().toNames());
            anyStar |= f.inferred().toNames().stream().anyMatch(direct::contains);
            String parts = sorted(f.inferred().toNames()).stream()
                    .map(x -> {
                        String star = direct.contains(x) ? "*" : "";
                        if (x.equals("Fs") && !f.fs().isEmpty()) return "Fs" + star + "(" + String.join(",", f.fs()) + ")";
                        return x + star;
                    })
                    .collect(Collectors.joining(" "));
            String unk = f.unresolved() ? "  ⚠ unresolved (set may be incomplete)" : "";
            System.out.printf("  %-" + w + "s  { %s }%s%n", f.fn(), parts, unk);
        }
        // Only explain the `*` when one was actually printed (every effect inherited => no marker).
        if (anyStar) System.out.println("  (* = performed in the function's own body; unmarked = via a callee)");
        return 0;
    }

    /** Which functions perform an effect — direct sources split from inheritors. */
    static int where(List<Effector> fns, String eff, boolean json, ReportRef ref) {
        if (eff == null) return usage("where <Effect> [--report <locator>] [--json]");
        // A typo'd/unknown effect NAME is a LOUD error (exit 2) — never a false-empty 0-result at exit 0 that
        // reads as an authoritative "nothing performs Net" when the user actually typed "Network" (corpus-audit
        // #3). A KNOWN effect that is simply absent stays a valid 0-result; an unknown name PRESENT in the
        // report (a spec extension effect) is allowed — so error only when the name is NEITHER known nor present.
        if (!Rules.KNOWN_EFFECTS.contains(eff) && !eff.equals("Unknown")
                && fns.stream().noneMatch(f -> f.inferred().toNames().contains(eff))) {
            System.err.println("candor where: unknown effect `" + eff + "` (known: " + String.join(", ", new java.util.TreeSet<>(Rules.KNOWN_EFFECTS)) + ", Unknown)");
            return 2;
        }
        List<String> direct = fns.stream().filter(f -> f.direct().toNames().contains(eff)).map(f -> f.fn()).sorted().toList();
        List<String> inherit = fns.stream()
                .filter(f -> f.inferred().toNames().contains(eff) && !f.direct().toNames().contains(eff)).map(f -> f.fn()).sorted().toList();
        // ⟨0.28⟩ SPEC §2 names this verb's `{"directly":[],"inherited":[]}` by measurement. AFTER the
        // usage/unknown-effect exit above, so a mistyped effect is still a plain usage error.
        ReportCompleteness comp = ref.completeness("where");
        if (json) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("effect", eff);
            m.put("directly", direct);
            m.put("inherited", inherit);
            comp.writeJson(m);
            emit(m);
            return 0;
        }
        // BEFORE the answer: a function in an unread unit performs `eff` or it does not, and NEITHER list
        // below can say which — so the caveat qualifies a populated answer exactly as much as an empty one.
        comp.printNote("the function(s) named below are only those candor could SEE perform " + eff,
                "A function in one of those is ABSENT from the report, so it cannot appear in either "
                + "list. " + comp.gateLine() + " Re-scan for a complete answer.");
        if (direct.isEmpty() && inherit.isEmpty()) {
            if (comp.mustHedge()) {
                // NOT "no function performs Fs" — that sentence is the prose spelling of the empty JSON
                // pair, and over these bytes candor has not examined enough to say it.
                System.out.println("candor: no function candor COULD SEE performs " + eff
                        + " — but see the INCOMPLETE note above; this is NOT \"nothing performs "
                        + eff + "\".");
                return 0;
            }
            System.out.println("candor: no function performs " + eff + " in the report.");
            return 0;
        }
        System.out.println((direct.size() + inherit.size()) + " function(s) perform " + eff + ":");
        if (!direct.isEmpty()) {
            System.out.println("  directly (" + direct.size() + "):");
            direct.forEach(s -> System.out.println("    " + s));
        }
        if (!inherit.isEmpty()) {
            System.out.println("  inherit it via a callee (" + inherit.size() + "):");
            inherit.forEach(s -> System.out.println("    " + s));
        }
        return 0;
    }

    /** Who calls a function — inverts the report's `calls` effect graph (no re-analysis). */
    static int callers(List<Effector> fns, String reportPath, String q, boolean json, boolean includeUnknown) {
        if (q == null) return usage("callers <function-substring> [--report <locator>] [--json] [--include-unknown]");
        // Prefer the full call-graph sidecar (written beside the report): it records EVERY function's
        // callees, including pure ones, so we can answer "who TRANSITIVELY calls X" for any function —
        // the blast radius an agent needs BEFORE adding an effect to X. The report alone only has
        // effect-relevant edges (it can't see a pure X), the old gap an agent-use eval surfaced.
        Map<String, List<String>> cg = loadCallgraph(reportPath);
        // Fallback (no sidecar): build a graph from the report's effect-relevant `calls` edges and run
        // the SAME query, so the output shape ({of,direct,transitive}) and JSON contract are identical
        // to the sidecar path (a /code-review finding: the old fallback emitted a {callee:[callers]} map
        // — and prose under --json — diverging from the pinned SPEC §3.1 shape). Transitive is
        // necessarily incomplete here (only effectful edges), which the sidecar exists to fix.
        if (cg == null || cg.isEmpty()) {
            cg = new LinkedHashMap<>();
            for (Effector f : fns) cg.put(f.fn(), new ArrayList<>(f.calls()));
        }
        // --include-unknown ⟨0.7⟩: the transitive `callers` set is candor's CONFIRMED reachers — it
        // cannot include a function that reaches `q` only through a dispatch candor declined to resolve
        // (an unresolved virtual/interface dispatch, disclosed as Unknown via `dispatch:OWNER.M`, not
        // silent-pure). Map each such function to the dispatch key(s) `OWNER.M`; the query then discloses
        // "these MAY also reach `q`" — precisely, by resolving whether a confirmed reacher is an OVERRIDE
        // of OWNER.M (same method name AND a subtype of OWNER per the hierarchy sidecar). Keys off the
        // canonical `dispatch:` reason (SPEC §4 ⟨0.7⟩); `callback:`/`reflect:`/`native:` are NOT frontier
        // sources (a function value / reflection / native boundary doesn't resolve to a hierarchy override).
        // Built only when the flag is set, so default output is byte-for-byte unchanged (cross-engine parity).
        Map<String, Set<String>> broadByFn = null;
        Map<String, List<String>> hier = null;
        if (includeUnknown) {
            broadByFn = new LinkedHashMap<>();
            for (Effector f : fns) {
                for (UnknownReason why : f.unknownWhy()) {
                    if (why.kind() == UnknownReason.Kind.DISPATCH) {
                        String key = why.detail(); // OWNER.M (dotted)
                        if (!key.isEmpty()) broadByFn.computeIfAbsent(f.fn(), k -> new TreeSet<>()).add(key);
                    }
                }
            }
            hier = loadHierarchy(reportPath); // null → the query falls back to a simple-name match (over-lists)
        }
        return callersViaCallgraph(cg, q, json, broadByFn, hier);
    }

    /** The bare method name of a `pkg.Class.method(desc)`: drop any `(…)` descriptor, then take the
     *  segment after the last dot. */
    static String simpleMethod(String fqn) {
        int paren = fqn.indexOf('(');
        String base = paren >= 0 ? fqn.substring(0, paren) : fqn;
        int dot = base.lastIndexOf('.');
        return dot >= 0 ? base.substring(dot + 1) : base;
    }

    /** The declaring type of a `pkg.Class.method(desc)`: drop any `(…)` descriptor, then the trailing
     *  `.method`. Inner-class `$` is preserved so it matches a hierarchy-sidecar key. */
    static String declaringType(String fqn) {
        int paren = fqn.indexOf('(');
        String base = paren >= 0 ? fqn.substring(0, paren) : fqn;
        int dot = base.lastIndexOf('.');
        return dot >= 0 ? base.substring(0, dot) : base;
    }

    /**
     * Lexicographic by UNICODE CODE POINT — the order SPEC §3.1 ⟨0.24⟩ pins for the frontier's
     * {@code viaDispatchOn} join, equivalently UTF-8 byte order.
     *
     * <p>Java's NATURAL String ordering ({@code String.compareTo}) is by UTF-16 CODE UNIT, which the clause
     * forbids: it agrees with code-point order on ASCII and disagrees above the BMP, because a supplementary
     * character is stored as a surrogate pair starting in {@code U+D800..U+DBFF} and so sorts as if it were
     * below every BMP character from {@code U+E000} up. Reachable, not theoretical — the dotted form is
     * {@code <owner>.<member>}, built from USER IDENTIFIERS, and all four analysed languages permit
     * non-ASCII identifiers.
     *
     * <p>Compared code point by code point rather than over {@code getBytes(UTF_8)}, which is the shorter
     * spelling of the same order but is NOT safe here: a {@code TreeSet} treats {@code compare == 0} as a
     * DUPLICATE, and UTF-8 encoding is lossy on an unpaired surrogate (they all encode to {@code ?}), so two
     * distinct details differing only in a lone surrogate would compare equal and one would be silently
     * DROPPED from the join — trading a conformance fix for the drop class this rung exists to close.
     * Code-point decomposition is injective over char sequences, so this stays consistent with equals.
     * Pinned by {@code QueryIncludeUnknownTest} in both directions.
     */
    static final Comparator<String> BY_CODE_POINT = (a, b) -> {
        int i = 0, j = 0;
        while (i < a.length() && j < b.length()) {
            int ca = a.codePointAt(i), cb = b.codePointAt(j);
            if (ca != cb) return Integer.compare(ca, cb);
            i += Character.charCount(ca);
            j += Character.charCount(cb);
        }
        return Integer.compare(a.length() - i, b.length() - j); // the shorter string is a prefix of the longer
    };

    /** Does this qualified name / `dispatch:` detail actually NAME an owner — i.e. is there a `.` in the
     *  part before any `(…)` descriptor? Mirrors the split {@link #simpleMethod}/{@link #declaringType}
     *  do, so it answers exactly the question they silently paper over: both fall back to the WHOLE string
     *  when there is no dot, so a dot-free input yields owner == member == the raw text and condition (3)
     *  is unanswerable rather than false. ⟨0.24⟩ */
    static boolean hasOwner(String qual) {
        int paren = qual.indexOf('(');
        return (paren >= 0 ? qual.substring(0, paren) : qual).indexOf('.') >= 0;
    }

    /** Load the type-hierarchy sidecar (`<report-stem>.hierarchy.json`, ⟨0.7⟩), or null if absent. */
    static Map<String, List<String>> loadHierarchy(String reportPath) {
        try {
            String hPath = reportPath.endsWith(".json")
                    ? reportPath.substring(0, reportPath.length() - 5) + ".hierarchy.json"
                    : reportPath + ".hierarchy.json";
            if (!Files.exists(Path.of(hPath))) return null;
            var o = JsonParser.parseString(Files.readString(Path.of(hPath))).getAsJsonObject();
            Map<String, List<String>> h = new LinkedHashMap<>();
            for (var e : o.entrySet()) {
                // `@` is the RESERVED METADATA NAMESPACE (SPEC §2.2). {@link ReportWriter#SUPERCLASS_KEY}'s
                // value is an ARRAY like every type's, so shape no longer tells them apart — without this
                // the marker becomes a phantom TYPE in the subtype walk.
                if (e.getKey().startsWith("@")) continue;
                // And still SKIP any entry whose value is not an array: this is the sidecar's SECOND
                // reader, `getAsJsonArray()` THROWS on an object, and the catch below swallows it into
                // `return null` — discarding the WHOLE hierarchy and dropping the dispatch frontier back to
                // a bare simple-name match. The first shape of the marker broke exactly this while
                // {@code Loader#loadDepHierarchy} was fine, and the whole suite was green through it. Kept
                // as defence in depth now that the writer no longer emits a non-array, because the file may
                // have been written by an older producer or another engine. Pinned by
                // {@code QueryIncludeUnknownTest#aSidecarSiblingKeyDoesNotDiscardTheWholeHierarchy}.
                if (!e.getValue().isJsonArray()) continue;
                List<String> sup = new ArrayList<>();
                for (JsonElement v : e.getValue().getAsJsonArray()) sup.add(v.getAsString());
                h.put(e.getKey(), sup);
            }
            return h;
        } catch (Exception e) {
            return null;
        }
    }

    /** ⟨0.26⟩ The three answers the hierarchy sidecar can give. `UNANSWERABLE` is the one the format could
     *  not express before: a type ABSENT from a present sidecar is one the pass never indexed, and reading
     *  that as "no supertypes" is a positive claim about a type nobody looked at. */
    enum Subtype { YES, NO, UNANSWERABLE }

    /** Is `type` a subtype of (or equal to) `owner`, per the hierarchy sidecar? Reflexive + transitive over
     *  recorded direct supertypes/interfaces.
     *
     *  <p>⟨0.26⟩ THREE-VALUED, and the ordering matters: a POSITIVE answer dominates. If a known path
     *  reaches `owner` the answer is YES even when some other branch ran into an unindexed type — the
     *  subtype relation is established, and the unknown branch cannot un-establish it. Only when no path
     *  proves it AND the walk met a type the sidecar has no key for is the answer UNANSWERABLE. NO is
     *  reserved for a walk that stayed entirely inside types the sidecar can answer for.
     *
     *  <p>SPEC §2.2 ⟨0.26⟩ makes the key set the manifest: a producer emits a key for every type it indexed,
     *  `[]` included. So `containsKey` is exactly "the pass answered for this type", and its absence is the
     *  disclosure trigger — same rule as §3.1's dot-free `dispatch:` detail and §2's unreadable manifest. */
    static Subtype subtypeOf(String type, String owner, Map<String, List<String>> hier) {
        if (type.equals(owner)) return Subtype.YES;
        boolean sawUnindexed = false;
        Set<String> seen = new HashSet<>();
        Deque<String> st = new ArrayDeque<>();
        st.push(type);
        while (!st.isEmpty()) {
            String cur = st.pop();
            // The KEY SET IS THE MANIFEST (§2.2 ⟨0.26⟩): no key means the pass never indexed this type, so
            // its supertypes are unknown rather than absent. `getOrDefault(..., List.of())` treated the two
            // alike, which is the whole defect — a frontier entry silently dropped by a sidecar that merely
            // did not cover one type.
            if (!hier.containsKey(cur)) { sawUnindexed = true; continue; }
            for (String s : hier.get(cur)) {
                if (s.equals(owner)) return Subtype.YES;   // positive dominates
                if (seen.add(s)) st.push(s);
            }
        }
        return sawUnindexed ? Subtype.UNANSWERABLE : Subtype.NO;
    }

    /** The two-valued form, for callers that must collapse. UNANSWERABLE collapses to TRUE — disclose,
     *  never drop — which is the direction §2.2 ⟨0.26⟩ requires and the opposite of what absence used to do. */
    static boolean isSubtypeOf(String type, String owner, Map<String, List<String>> hier) {
        return subtypeOf(type, owner, hier) != Subtype.NO;
    }

    /** Load the call-graph sidecar (`<report-minus-.json>.callgraph.json`), or null if absent/unreadable.
     *  A genuinely MISSING sidecar returns null SILENTLY — falling back to the report's inline `calls` is
     *  correct. But a sidecar that EXISTS yet fails to read/parse (corrupt/truncated) is disclosed on
     *  stderr before we return null: the fallback graph is strictly smaller, so a silent drop would let a
     *  gate verdict under-report (the §4 cardinal sin). Never silently drop graph edges a verdict depends on. */
    static Map<String, List<String>> loadCallgraph(String reportPath) {
        return loadCallgraphSignalled(reportPath).graph();
    }

    /** A signalled call-graph load: the graph (null when absent/unreadable) PLUS whether the load was
     *  PARTIAL — true iff the matched sidecar EXISTED but failed to read/parse (its edges were dropped,
     *  disclosed on stderr). An ABSENT sidecar is NOT partial: absence is a known state (empty graph),
     *  not dropped evidence. Consumers whose VERDICT depends on graph completeness (gains' `origin`)
     *  must read the flag — a dropped-edge graph proves absence of nothing. */
    record CallgraphLoad(Map<String, List<String>> graph, boolean partial) {}

    static CallgraphLoad loadCallgraphSignalled(String reportPath) {
        String cgPath = reportPath.endsWith(".json")
                ? reportPath.substring(0, reportPath.length() - 5) + ".callgraph.json"
                : reportPath + ".callgraph.json";
        if (!Files.exists(Path.of(cgPath))) return new CallgraphLoad(null, false); // no sidecar — silent fallback is correct
        try {
            var o = JsonParser.parseString(Files.readString(Path.of(cgPath))).getAsJsonObject();
            Map<String, List<String>> cg = new LinkedHashMap<>();
            for (var e : o.entrySet()) {
                List<String> callees = new ArrayList<>();
                for (JsonElement v : e.getValue().getAsJsonArray()) callees.add(v.getAsString());
                cg.put(e.getKey(), callees);
            }
            return new CallgraphLoad(cg, false);
        } catch (Exception e) {
            System.err.println("candor: call-graph sidecar " + cgPath
                    + " is unreadable (" + e.getClass().getSimpleName()
                    + ") — the call graph may be incomplete; falling back to the report's inline edges.");
            return new CallgraphLoad(null, true); // existed yet dropped — a PARTIAL graph, never a silent one
        }
    }

    /** The report's `package` name (the §2 envelope field, singular string — what candor-report/candor-ts
     *  write), or null if absent/blank/unreadable. The `tour` header prefers it (meaningful, locator-
     *  independent) over the prefix basename — mirrors the Rust reference's report_package(prefix). */
    static String reportPackage(String reportPath) {
        try {
            JsonElement root = JsonParser.parseString(Files.readString(Path.of(reportPath)));
            if (!root.isJsonObject()) return null;
            JsonObject obj = root.getAsJsonObject();
            if (obj.has("package") && obj.get("package").isJsonPrimitive()) {
                String pkg = obj.get("package").getAsString();
                if (!pkg.isEmpty()) return pkg;
            }
            // The `packages` PLURAL envelope — the JVM shape (SPEC §2), which THIS engine's own scan
            // emits: one entry names it verbatim; several name their longest common dotted prefix
            // (`com.uflexi.actions` + `com.uflexi.dao` → `com.uflexi`); none shared → null (basename).
            if (obj.has("packages") && obj.get("packages").isJsonArray()) {
                List<String> pkgs = new ArrayList<>();
                for (JsonElement e : obj.getAsJsonArray("packages"))
                    if (e.isJsonPrimitive() && !e.getAsString().isEmpty()) pkgs.add(e.getAsString());
                return packagesLabel(pkgs);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /** The longest common dot-separated prefix of a plural `packages` list — whole segments only
     *  (`com.ab` + `com.ac` share `com`, not `com.a`); null when nothing is shared. Mirrors the Rust
     *  reference's packages_label (tour.rs). */
    static String packagesLabel(List<String> pkgs) {
        if (pkgs.isEmpty()) return null;
        if (pkgs.size() == 1) return pkgs.get(0);
        String[] first = pkgs.get(0).split("\\.");
        int n = first.length;
        for (String p : pkgs.subList(1, pkgs.size())) {
            String[] segs = p.split("\\.");
            int i = 0;
            while (i < Math.min(n, segs.length) && segs[i].equals(first[i])) i++;
            n = i;
            if (n == 0) return null; // nothing shared — the basename fallback is more honest
        }
        return String.join(".", Arrays.copyOfRange(first, 0, n));
    }

    /** "Who reaches `q`?" over the full call graph: the DIRECT callers and the full TRANSITIVE set (the
     *  blast radius if `q` gained an effect). Works for any function, effectful or pure. Mirrors
     *  candor-scan's `callers_via_callgraph`. */
    static int callersViaCallgraph(Map<String, List<String>> cg, String q, boolean json) {
        return callersViaCallgraph(cg, q, json, null, null);
    }

    static int callersViaCallgraph(Map<String, List<String>> cg, String q, boolean json,
                                   Map<String, Set<String>> broadByFn, Map<String, List<String>> hier) {
        boolean incl = broadByFn != null; // --include-unknown: disclose the unresolved-dispatch frontier
        Map<String, List<String>> rev = new TreeMap<>(); // callee -> its direct callers
        for (var e : cg.entrySet())
            for (String callee : e.getValue())
                rev.computeIfAbsent(callee, k -> new ArrayList<>()).add(e.getKey());
        Set<String> names = new TreeSet<>(cg.keySet());
        for (var v : cg.values()) names.addAll(v);
        int tier = bestTier(names.stream(), q);
        List<String> targets = new ArrayList<>();
        for (String n : names) if (tier > 0 && matchTier(n, q) >= tier) targets.add(n);
        if (targets.isEmpty()) {
            // A nonexistent function is a LOUD error (exit 2), like path/impact — never an empty result at exit
            // 0, which reads as an authoritative "nothing calls it" for a fn that doesn't exist (corpus-audit
            // #3). Gated on a non-empty call graph so a report without one isn't misreported as "no such fn".
            if (names.isEmpty()) {
                // ⟨0.28⟩ UNANSWERABLE MUST REACH THE MACHINE CHANNEL (SPEC §3.3.1). This printed `{}` at
                // exit 0 while the human arm said "no call graph in the report" — human-fine,
                // machine-silent, which is the split that makes a defect a cardinal sin. A consumer
                // reading `direct`, or defaulting it (the fail-open idiom ⟨0.24⟩ names on every key in
                // this format), was told NOBODY CALLS this function: a blast radius of "safe to edit"
                // over a pair whose honest answer is "this run judged nothing". The ⟨0.28⟩ sidecar rule
                // one rung up did not create the hole — an absent sidecar always answered this way — it
                // aimed traffic at it, by making no-sidecar the STANDARD state after a failed run.
                //
                // BOTH CHANNELS FAIL CLOSED: the document names itself unanswerable AND the exit is
                // non-zero. §3.3.1 permits either, but each alone leaves a naive reader exposed — the key
                // alone still lets `d.get("direct", [])` read as a determined negative, and the exit alone
                // leaves a JSON consumer holding `{}`.
                //
                // ONLY THIS BRANCH. `names.isEmpty()` means there is NO GRAPH AT ALL (no sidecar and no
                // report entry to fall back on), which is the unanswerable case. A function with no
                // callers over a REAL graph still answers `direct: []` at exit 0 below — that is a
                // determined negative and it is correct — and a name absent from a real graph still exits
                // 2 as "no function matching", which is the branch below this one.
                String why = "no call graph in the report — the §2.2 sidecar is absent and the report "
                        + "carries no call edges either, so who calls this function is UNANSWERABLE, "
                        + "not empty (SPEC §3.3.1 ⟨0.28⟩)";
                if (json) {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("of", List.of(q));
                    out.put("unanswerable", why);
                    emit(out);
                } else {
                    System.out.println("candor: " + why);
                }
                return 2;
            }
            System.err.println("candor callers: no function matching `" + q + "` in the call graph");
            return 2;
        }
        TreeSet<String> direct = new TreeSet<>();
        for (String t : targets) direct.addAll(rev.getOrDefault(t, List.of()));
        TreeSet<String> all = new TreeSet<>(); // transitive closure of callers (reverse BFS)
        Deque<String> stack = new ArrayDeque<>(targets);
        while (!stack.isEmpty()) {
            String n = stack.pop();
            for (String c : rev.getOrDefault(n, List.of())) if (all.add(c)) stack.push(c);
        }
        // The unresolved-dispatch frontier (--include-unknown only): a function F broad-dispatches on
        // OWNER.M (carries dispatch:OWNER.M — an Unknown candor disclosed rather than resolve). F
        // MAY also reach `q` iff a confirmed reacher R is an OVERRIDE of OWNER.M — same method name AND R's
        // declaring type is a subtype of OWNER per the hierarchy sidecar. The subtype check (vs a bare
        // simple-name match) drops unrelated same-named dispatches — PRECISE. If the hierarchy sidecar is
        // absent OR empty, fall back to a simple-name match, which OVER-lists — the safe direction
        // for a lower-bound disclosure. candor never asserts these; they are disclosed as "cannot confirm".
        List<Map<String, String>> possible = new ArrayList<>();
        if (incl) {
            // An EMPTY hierarchy sidecar is the SAME INPUT as an absent one — what rust (`has_hier`,
            // callers.rs) and ts (`hasHier`, query-core.mjs) already do. `{}` is not the claim "no type has
            // a supertype"; it is overwhelmingly "the hierarchy pass found nothing / was not run / wrote a
            // stub". Honouring it makes isSubtypeOf fail for EVERY type, so condition (3) fails for every
            // dotted source and the whole frontier collapses to []. MEASURED before this guard: the same
            // report that discloses a frontier entry with the sidecar absent disclosed NOTHING with a `{}`
            // sidecar — a disclosed over-list silently turned into an empty answer a consumer reads as
            // "nothing may reach the target through an unresolved dispatch".
            boolean hasHier = hier != null && !hier.isEmpty();
            Set<String> confirmed = new HashSet<>(all);
            confirmed.addAll(targets);
            // confirmed reachers indexed by simple method name -> their declaring types (for the subtype check)
            Map<String, List<String>> reacherTypesByMethod = new HashMap<>();
            for (String r : confirmed)
                reacherTypesByMethod.computeIfAbsent(simpleMethod(r), k -> new ArrayList<>()).add(declaringType(r));
            for (var e : new TreeMap<>(broadByFn).entrySet()) {
                if (confirmed.contains(e.getKey())) continue; // already a confirmed caller — not "additional"
                // BY_CODE_POINT, not natural order: ⟨0.24⟩ pins this join as sorted by CODE POINT, and
                // `String.compareTo` — what `new TreeSet<>()` would use — sorts by UTF-16 code unit, which
                // differs above the BMP. Sorted + deduplicated by construction, as the clause requires.
                TreeSet<String> hits = new TreeSet<>(BY_CODE_POINT);
                for (String key : e.getValue()) { // key = OWNER.M, or a DOT-FREE detail (no owner at all)
                    if (!hasOwner(key)) {
                        // ⟨0.24⟩ A DOT-FREE `dispatch:` detail (e.g. candor-rust's `untyped cross-package
                        // receiver`) names NO owner and NO member, so condition (3) — "is a confirmed
                        // reacher an override of OWNER.M?" — is UNANSWERABLE. An unanswerable condition
                        // MUST NOT be scored as a failed one: disclose the entry with the RAW DETAIL
                        // verbatim as `viaDispatchOn`, never drop it. Same direction the no-hierarchy
                        // fallback takes one rung up. Detected STRUCTURALLY (no dot before any descriptor),
                        // NOT by matching a known wording — an allowlist of strings silently drops every
                        // wording it does not enumerate, which is this defect itself.
                        hits.add(key);
                        continue;
                    }
                    String m = simpleMethod(key);
                    String owner = declaringType(key);
                    List<String> reacherTypes = reacherTypesByMethod.get(m);
                    if (reacherTypes == null) continue;
                    boolean hit = !hasHier // no usable hierarchy sidecar → simple-name match (over-lists)
                            || reacherTypes.stream().anyMatch(t -> isSubtypeOf(t, owner, hier));
                    if (hit) hits.add(m);
                }
                if (!hits.isEmpty()) {
                    Map<String, String> row = new LinkedHashMap<>();
                    row.put("fn", e.getKey());
                    row.put("viaDispatchOn", String.join(",", hits));
                    possible.add(row);
                }
            }
        }
        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("of", targets);
            out.put("direct", new ArrayList<>(direct));
            out.put("transitive", new ArrayList<>(all));
            if (incl) out.put("possibleViaUnknownDispatch", possible); // present only under --include-unknown
            emit(out);
            return 0;
        }
        String tgt = String.join(", ", targets);
        if (all.isEmpty() && possible.isEmpty()) {
            System.out.println("  `" + tgt + "` has no callers (nothing in this codebase calls it).");
            return 0;
        }
        if (!all.isEmpty()) {
            System.out.println("  `" + tgt + "` is reached by " + all.size()
                    + " function(s) (the blast radius if it gained an effect):");
            for (String c : all) System.out.println("      " + c + (direct.contains(c) ? " (direct)" : ""));
        }
        if (incl && !possible.isEmpty()) {
            System.out.println("  + " + possible.size() + " function(s) MAY also reach `" + tgt
                    + "` via an unresolved broad dispatch candor declined to resolve (cannot confirm):");
            for (Map<String, String> r : possible)
                System.out.println("      " + r.get("fn") + "  (via dispatch on " + r.get("viaDispatchOn") + ")");
        }
        return 0;
    }

    // ── ⟨0.24⟩ SPEC §3.2: THE ADVISORY VERBS' COMPLETENESS RULE, IN ONE PLACE ──────────────────────────
    //
    // `0075987` ruled the omit-`ok` rule for `whatif`; this engine implemented it for `whatif` and the
    // siblings never got sent back, which is `ec1a441`'s subject and the eighth time §3.2 has been scoped
    // to the verb its defect was found in. MEASURED here on the release reviewer's fixture — a report
    // declaring one `unanalyzed` unit, NO holes at all, and a `deny Net app` nothing violates:
    //
    //     gate --report        exit 2   ok:false  incomplete:true  + the manifest      ← correct
    //     unverified --strict  exit 0   {"ok": true,  "unverified": []}
    //     fix-gate  --strict   exit 0   {"ok": true,  "remedies":   []}
    //     …and stdout: "every function in a pure/deny layer is PROVABLY clean ✓", over a report that
    //     declares source candor could not read.
    //
    // So these three functions exist rather than a fourth copy of the rule at a fourth call site. They are
    // deliberately the SAME shape `whatif` already emitted (candor-spec `ec1a441`, candor-swift
    // `emitAdvisoryAnswer`, candor-ts `advisoryAnswer` — all byte-aligned), because the point of the clause
    // is that one law binds every verb that answers `ok`.

    /** ⟨0.24⟩ SPEC §3.2 — the ⟨0.21⟩ COMPLETENESS MANIFEST as an ADVISORY verb must read it: EVERY report
     *  file the locator names, unioned, through {@link #readEnvelope} — the GATE's own reader over the
     *  GATE's own report set ({@link #locatorReportSet}).
     *
     *  <p><b>The set and not the one file, because {@code 93cef40} states the rule as a RELATION: the
     *  advisory verb's incompleteness verdict must be at least as pessimistic as the gate's OVER THE SAME
     *  BYTES.</b> A prefix locator names a report SET (§2, "a single analysis world") and {@code gate}
     *  unions it; {@link #expandPrefix} picks the lexicographically-first for every other verb. Reading
     *  only that one file makes {@code unverified --strict} answer clean over a manifest sitting in the
     *  sibling the gate exits 2 on — the same under-report this rung closes, one resolution step out.
     *
     *  <p>LENIENT per file, and the leniency is the point: the gate route is CERTIFYING, so a report it
     *  cannot read is a hard failure that names the file; these verbs are advisory, and refusing to answer
     *  at all is strictly less than the partial answer §3.2 asks for. An unreadable sibling is DISCLOSED
     *  rather than dropped silently (candor-ts's reader is silent here; a dropped file is exactly the
     *  evidence this rule is about). The ELEMENT rule lives in {@link #readEnvelope} and follows from the
     *  same relation: a member is counted the moment it is an object, because a manifest member that
     *  cannot be read is still a member saying something was not analysed. */
    static List<String[]> advisoryUnanalyzed(String locator, String resolved, String who) {
        return reportCompleteness(locator, resolved, who).unanalyzed();
    }

    // ── ⟨0.28⟩ SPEC §2: …AND "EVERY ADVISORY VERB" WAS ITSELF THE SCOPING MISTAKE ──────────────────────
    //
    // The block above says the completeness manifest is what an ADVISORY verb must read, and the
    // DESCRIPTIVE verbs — the ones that answer a question rather than render a verdict — were never sent
    // back for it. SPEC §2 ⟨0.28⟩ corrects the clause to the condition that makes it true: the obligation
    // binds "any verb whose output could be read as a NEGATIVE FINDING about the code — a verdict, an
    // empty result set, or a zero count". An empty result set is precisely what these verbs produce.
    // MEASURED on the jar built from the commit before this one, over a report declaring
    // `analyzed.count: 0` and a non-empty `unanalyzed` — the standard post-failure artifact since the
    // ⟨0.28⟩ arming rung, i.e. what is on disk after a failed run:
    //
    //     blindspots   {"sources":[],"totalUnknown":0}                exit 0, no hedge on either channel
    //     containment  {"layerPrefix":"","contained":[],"ambient":{}} exit 0, no hedge
    //     reachable    {"entryPoints":0,"effects":{}}                 exit 0, no hedge
    //     map          {}                                             exit 0, no hedge
    //     tour         {"reaches":[]}                                 exit 0, no hedge
    //     where Fs     {"effect":"Fs","directly":[],"inherited":[]}   exit 0, no hedge
    //
    // "no blind spots" out of a report whose own manifest names a file it could not read. A consumer
    // cannot tell *nobody performs `Fs`* from *nothing was examined*. The SAME reader, the same two
    // channels, the same no-op-when-complete rule — a second mechanism would be the two-copies mistake
    // {@link #advisoryAnswer} exists to prevent, one level out.

    /** ⟨0.28⟩ The ⟨0.21⟩ manifest as far as it could be READ, unioned over the report SET a locator names.
     *
     *  <p><b>THREE CAUSES, NOT THREE SPELLINGS OF ONE.</b> {@code unanalyzed} names source the producing
     *  scan could not READ. {@code judgedNothing} is SPEC §2's {@code analyzed.count: 0} row — a scan that
     *  read whatever it read and reached no conclusion about any of it, so there is no file to name and
     *  the manifest is legitimately ABSENT; without this arm the reader saw a complete report and every
     *  verb answered {@code {}} over it just the same. {@code unreadable} is a report file this verb could
     *  not re-read at all. Only the union covers both the post-failure artifact (which carries the first
     *  two) and the facade/re-export report (which carries only the second).
     *
     *  @param unanalyzed the ⟨0.21⟩ manifest rows, {@code {path, reason}}
     *  @param judgedNothing one label per report file declaring {@code analyzed.count: 0}
     *  @param unreadable one path per report file this verb could not re-read (already disclosed on stderr
     *      by {@link #reportCompleteness}) */
    record ReportCompleteness(List<String[]> unanalyzed, List<String> judgedNothing, List<String> unreadable) {
        /** Nothing to disclose — for a caller with no report locator at all (a unit test driving a verb
         *  over an in-memory entry list). Every channel below is a no-op on it. */
        static final ReportCompleteness NONE = new ReportCompleteness(List.of(), List.of(), List.of());

        /** Is the universe this verb reasoned over known-partial in the way the GATE also refuses over?
         *  {@code judgedNothing} is deliberately NOT an arm — see {@link #mustHedge}. */
        boolean incomplete() { return !unanalyzed.isEmpty() || !unreadable.isEmpty(); }

        /** ⟨0.28⟩ <b>Is there anything at all to disclose — the trigger for an ANSWER, where
         *  {@link #incomplete} is the trigger for a VERDICT.</b>
         *
         *  <p>{@code analyzed.count: 0} reaches both DISCLOSURE channels and stops at the exit code, and
         *  the split is load-bearing. ⟨0.24⟩ ruled count-0 explicitly the other way for exit codes — "a
         *  disclosure, not an exit code" — because {@code gate --report} exits 0 over a facade package,
         *  and a verb exiting 2 there would claim it got LESS far than the gate on identical bytes, which
         *  is the mirror of the over-claim {@code --strict} exists to prevent. A descriptive verb asks
         *  THIS: its empty set is a negative finding under all three causes, and it has no exit code for
         *  the distinction to matter to. */
        boolean mustHedge() { return incomplete() || !judgedNothing.isEmpty(); }

        /** Union in a SECOND locator's manifest, for a verb that reads two — {@code containment
         *  <baseline>}, whose answer is a DIFFERENCE and is therefore unsound if EITHER side is partial,
         *  in opposite directions: a leak living in an unread unit of the CURRENT tree is missed, while
         *  one living in an unread unit of the BASELINE reads as newly appeared, at exit 1. One
         *  {@code ReportCompleteness} rather than two notes, because {@link #writeJson} writes fixed key
         *  names and calling it twice would have the second locator's manifest overwrite the first's. */
        ReportCompleteness absorb(ReportCompleteness other) {
            List<String[]> u = new ArrayList<>(unanalyzed); u.addAll(other.unanalyzed);
            List<String> j = new ArrayList<>(judgedNothing); j.addAll(other.judgedNothing);
            List<String> r = new ArrayList<>(unreadable); r.addAll(other.unreadable);
            return new ReportCompleteness(u, j, r);
        }

        /** What {@code gate --report} does over THESE SAME BYTES, as one sentence for the note's tail — a
         *  method and not a constant, because the two causes get OPPOSITE answers. Every pre-⟨0.28⟩ note
         *  in this file closes with "`gate --report` exits 2 over it", which is true of {@code unanalyzed}
         *  (§3.3 makes an incomplete analysis of the target's own code an exit-2 cause) and FALSE of
         *  {@code analyzed.count: 0}. A warning that sends the reader to a CI job which then passes
         *  teaches them the warning is noise — the disclosure discrediting itself. The count-0 sentence
         *  says the opposite, and says why it is the more urgent of the two: nothing downstream fails
         *  closed on these bytes, so this note is the whole of the warning. */
        String gateLine() {
            return incomplete()
                    ? "`gate --report` exits 2 over these bytes."
                    : "NOTHING DOWNSTREAM WILL CATCH THIS FOR YOU — `gate --report` exits 0 over a "
                      + "judged-nothing report (⟨0.24⟩: a disclosure, not an exit code), so this note is "
                      + "the whole of the warning.";
        }

        /** The key names {@link #writeJson} is about to write — asked of the fields ACTUALLY going out,
         *  never of a hardcoded list, so {@code map}'s collision check below cannot report a displacement
         *  that did not happen (the {@code net-partner} failure this family already paid for: a key
         *  reported ignored while being honoured, pointed the other way). Empty on a complete report. */
        List<String> keys() {
            if (!mustHedge()) return List.of();
            List<String> k = new ArrayList<>(List.of("incomplete"));
            if (!unanalyzed.isEmpty()) k.add("unanalyzed");
            if (!judgedNothing.isEmpty()) k.add("judgedNothing");
            return k;
        }

        /** The MACHINE half — a NO-OP on a complete report, so an ordinary run is byte-identical.
         *  {@code incomplete: true} is the one flag EVERY cause raises, so a consumer that only branches
         *  on it is safe under all of them; the arrays name WHICH, because the causes want different
         *  repairs (a scan that can READ a file vs a scan that reaches a conclusion) and each is omitted
         *  when empty, so a document raised by {@code unanalyzed} alone stays byte-identical to a
         *  pre-⟨0.28⟩ one. Appends to a LinkedHashMap/TreeMap the caller already built — never
         *  {@code toJson}-and-reparse, which is where candor-rust's first draft silently RE-SORTED the
         *  answers it was disclosing about. */
        void writeJson(Map<String, Object> out) { writeJson(out, ""); }

        /** ⟨0.28⟩ The same machine half under a NAMESPACE PREFIX, for a verb that reads TWO reports which
         *  fail in DIFFERENT DIRECTIONS and must therefore be disclosed SEPARATELY — {@code gains}, whose
         *  answer rests on a current and a baseline. An incomplete CURRENT means the gained set may be
         *  SHORT (effects the reader is not being told about); an incomplete BASELINE means the comparison
         *  FLOOR is soft, so the existing-vs-new {@code origin} split this verb exists for is unreliable.
         *  Collapsing them into one flag would say "something here is incomplete" and leave a supply-chain
         *  reviewer unable to act on it. The prefixed spelling ({@code baselineIncomplete},
         *  {@code baselineUnanalyzed}) is a CROSS-ENGINE WIRE SURFACE — candor-rust fe5d831 publishes
         *  exactly these names — and it mirrors the shape this verb already uses for the weaker caveat
         *  ({@code coverage} for the current, {@code coverageDelta} for the difference) rather than
         *  inventing a second one. {@link #absorb} is the OTHER answer to two reports and is not
         *  interchangeable: it is right for {@code containment}, whose single verdict is unsound if either
         *  side is partial, and wrong here, where which side is soft changes what the reader should do. */
        void writeJson(Map<String, Object> out, String prefix) {
            if (!mustHedge()) return;
            out.put(prefixed(prefix, "incomplete"), true);
            if (!unanalyzed.isEmpty()) out.put(prefixed(prefix, "unanalyzed"), manifestJson(unanalyzed));
            if (!judgedNothing.isEmpty())
                out.put(prefixed(prefix, "judgedNothing"), List.copyOf(judgedNothing));
        }

        /** {@code ""} → the bare key (byte-identical to every pre-prefix caller); otherwise
         *  {@code baseline} + {@code Incomplete}/{@code Unanalyzed}/{@code JudgedNothing}. */
        private static String prefixed(String prefix, String name) {
            return prefix.isEmpty() ? name
                    : prefix + Character.toUpperCase(name.charAt(0)) + name.substring(1);
        }

        /** The HUMAN half, BEFORE the answer — it qualifies a NON-empty result as much as an empty one.
         *  On STDOUT, beside the answer it qualifies (never stderr: these verbs' human output IS stdout,
         *  and a caveat on the other stream is one `2>/dev/null` from gone), and only ever reached on the
         *  human channel — the {@code --json} branches return above it. A no-op on a complete report. */
        void printNote(String soWhat, String tail) {
            if (!mustHedge()) return;
            List<String> causes = new ArrayList<>();
            int units = unanalyzed.size() + unreadable.size();
            if (units > 0) causes.add(units + " unit(s) candor could not analyze");
            if (!judgedNothing.isEmpty())
                causes.add(judgedNothing.size() + " report(s) that JUDGED NOTHING (`analyzed.count: 0`)");
            System.out.println("  ⚠ INCOMPLETE — the report(s) under this locator declare "
                    + String.join(", and ", causes) + ",");
            System.out.println("      so " + soWhat + ":");
            for (String[] u : unanalyzed) System.out.println("      " + u[0] + " — " + u[1]);
            for (String p : unreadable)
                System.out.println("      " + p + " — this report could not be re-read (see stderr)");
            for (String p : judgedNothing)
                System.out.println("      " + p + " — `analyzed.count: 0`: this report judged NOTHING, so "
                        + "it names no function at all and its silence is not a purity claim");
            System.out.println("      " + tail);
        }
    }

    /** The label the judged-nothing disclosures use for one report file: its §2 package name (the thing
     *  the operator recognises) plus the path (the thing they can re-scan). One spelling, so the gate
     *  route's advisory and the descriptive verbs' manifest name the same report the same way. */
    static String judgedNothingLabel(Envelope env, String path) {
        return (env.packageName() != null ? env.packageName() : "<unnamed package>") + " (" + path + ")";
    }

    /** ⟨0.28⟩ Read {@link ReportCompleteness} over the report SET a locator names — the same set, through
     *  the same {@link #readEnvelope}, that {@link #advisoryUnanalyzed} has always used, now also
     *  answering SPEC §2's {@code analyzed.count: 0} row. LENIENT per file for the reason given above: a
     *  report this verb cannot re-read is DISCLOSED on stderr and recorded as {@code unreadable} (which
     *  hedges the answer) rather than dropped — a dropped file is exactly the evidence this rule is about. */
    static ReportCompleteness reportCompleteness(String locator, String resolved, String who) {
        List<String> set = new ArrayList<>(locatorReportSet(locator));
        if (set.isEmpty() && resolved != null) set.add(resolved);
        List<String[]> un = new ArrayList<>();
        List<String> jn = new ArrayList<>();
        List<String> bad = new ArrayList<>();
        for (String r : set) {
            Envelope env;
            try {
                env = readEnvelope(r);
            } catch (Exception e) {
                System.err.println("candor " + who + ": report " + r + " could not be re-read ("
                        + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName())
                        + ") — its completeness manifest is OMITTED from this answer");
                bad.add(r);
                continue;
            }
            un.addAll(env.unanalyzed());
            // The PATH, not {@link #judgedNothingLabel}'s package-qualified form: this list goes on the
            // MACHINE channel, where the actionable identifier is the file to re-scan, and it is the
            // shape candor-rust's `judgedNothing` already publishes. (The label form stays on the gate
            // route's stderr advisory, where a human is reading and `<unnamed package>` is prose, not a
            // value a consumer keys on.)
            if (env.judgedNothing()) jn.add(r);
        }
        return new ReportCompleteness(un, jn, bad);
    }

    /** The report a DESCRIPTIVE verb is answering over: the LOCATOR (which may name a report SET, §2 "a
     *  single analysis world") beside the single path the verb's own answer was computed from. Threaded so
     *  the six verbs can read the manifest that travels WITH their input; {@link #NONE} for a caller that
     *  has no locator at all. */
    record ReportRef(String locator, String resolved) {
        static final ReportRef NONE = new ReportRef(null, null);
        ReportCompleteness completeness(String who) { return reportCompleteness(locator, resolved, who); }
    }

    /** The ⟨0.21⟩ manifest as wire rows — one spelling, shared by every verb that discloses it. */
    static List<Map<String, Object>> manifestJson(List<String[]> unanalyzed) {
        List<Map<String, Object>> un = new ArrayList<>();
        for (String[] u : unanalyzed) {
            var m = new LinkedHashMap<String, Object>();
            m.put("path", u[0]);
            m.put("reason", u[1]);
            un.add(m);
        }
        return un;
    }

    /** ⟨0.24⟩ SPEC §3.2 — FINISH AN ADVISORY VERB'S JSON ANSWER. Over a report the verb could read WHOLE,
     *  under a policy it could read WHOLE: {@code ok} plus the verb's own body, byte for byte as before.
     *  Under EITHER of the two ways that fails — the report declares {@code unanalyzed}, or the gate would
     *  have WITHHELD a rule — {@code ok} is <b>OMITTED</b>, and the disclosure that names the gap
     *  ({@code unevaluated}, or {@code incomplete: true} + the manifest) takes its place.
     *
     *  <p><b>TWO TRIGGERS, ONE ANSWER (candor-spec {@code 142740a}).</b> {@code 4fd140c} ruled the withheld
     *  case to {@code ok: false} and that was wrong by the argument in the very next paragraph: on an
     *  ADVISORY verb {@code false} asserts <i>"a hole/crossing exists, here it is"</i> — and where a rule was
     *  withheld NO hole was found, the question was DECLINED. That is the fabrication mirror, which is
     *  exactly why the incompleteness trigger omits the field. The two are the same shape and they looked
     *  different only because they were ruled in two clauses a day apart. MEASURED before this repair, on a
     *  report carrying {@code Net}+{@code hosts} with no {@code netClass} under {@code deny
     *  Net[unknown-host] app}: rust/ts/swift omitted, java alone answered {@code false} — a 1-against-3
     *  split, the sibling of the 2-against-2 one this rung had just closed.
     *
     *  <p><b>AND NEITHER BOOLEAN IS A STATEMENT THE INPUT LICENSES</b>, which is the property both triggers
     *  share. {@code ok: true} certifies a universe the verb knows it cannot see all of — a function in an
     *  unparsed file is absent from {@code functions}, a boundary under a withheld rule was never
     *  adjudicated. So the field goes: {@code if (r.ok)} gets a falsy value and fails safe, and a consumer
     *  that looks further learns precisely what went unread or unevaluated.
     *
     *  <p>DELIBERATELY NOT the gate verdict's shape ({@code ok:false} + {@code incomplete:true},
     *  {@link Candor#writeGateJson}) nor the refusal document's ({@code ok:false} + {@code refused:true}):
     *  in BOTH of those {@code ok:false} is TRUE — the gate did not certify — whereas here neither value
     *  is. A shape is copied for its reasoning, not for its familiarity, and the gate is NOT changed to
     *  match. The verb's own array still ships either way: a partial answer that says it is partial beats
     *  a refusal.
     *
     *  <p><b>{@code unevaluated} IS WRITTEN HERE, not by the caller.</b> A trigger whose disclosure is
     *  emitted in one place and whose consequence is decided in another is precisely how these two clauses
     *  drifted apart in the first place — {@code whatif} held the incompleteness rule inline and its
     *  siblings never got it. One producer decides both. */
    static Map<String, Object> advisoryAnswer(boolean ok, List<String[]> unanalyzed,
                                              List<String[]> unevaluated, Map<String, Object> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (unanalyzed.isEmpty() && unevaluated.isEmpty()) out.put("ok", ok);
        out.putAll(body);
        if (!unevaluated.isEmpty()) out.put("unevaluated", Candor.unevaluatedJson(unevaluated));
        if (!unanalyzed.isEmpty()) {
            out.put("incomplete", true);
            out.put("unanalyzed", manifestJson(unanalyzed));
        }
        return out;
    }

    /** ⟨0.24⟩ SPEC §3.2 — <b>THE OTHER CHANNEL.</b> {@link #advisoryAnswer} withdraws the claim from the
     *  JSON; this withdraws it from the one a human reads, and the clause requires both because a test
     *  that reads one channel is evidence about one channel. candor-rust built a mutant that kept the
     *  whole JSON fix and deleted only the printed line, and it SURVIVED that engine's entire suite —
     *  absence-asserts on {@code ok} cannot see stdout. This engine found the identical hole in `whatif`:
     *  {@code ✓ within policy} IS the prose {@code ok: true}, so removing the field while leaving the
     *  sentence standing MOVES the false all-clear rather than removing it.
     *
     *  <p>This names WHAT went unread; withdrawing the sentence itself is each verb's own job, because the
     *  sentence is (see the call sites: the tick, "nothing to fix", "no remedy"). {@code tail} is per-verb
     *  because the CONSEQUENCE is: {@code unverified}/{@code fix-gate} withdraw {@code ok} and their
     *  {@code --strict} exits 2, while {@code fix} answers about ONE function and carries neither field nor
     *  flag — a note promising both would describe a document the reader is not holding. */
    static void advisoryIncompleteNote(String who, List<String[]> unanalyzed, String tail) {
        if (unanalyzed.isEmpty()) return;
        System.err.println("candor " + who + ": the report declares " + unanalyzed.size()
                + " unit(s) candor could not analyze, so `gate --report` exits 2 over it — and an advisory "
                + "verb may be LESS certain than the gate, never MORE (SPEC §3.2):");
        for (String[] u : unanalyzed)
            System.err.println("    " + u[0] + (u[1] == null || u[1].isEmpty() ? "" : "  (" + u[1] + ")"));
        System.err.println("  " + tail);
    }

    /** The {@link #advisoryIncompleteNote} tail for the two verbs that answer `ok` and take `--strict`. */
    static final String INCOMPLETE_TAIL_STRICT =
            "(`ok` is OMITTED — neither value is a statement this input licenses; `--strict` exits 2, the "
            + "could-not-evaluate code)";

    /** ⟨0.24⟩ `142740a` — the same sentence for the WITHHELD-RULE trigger, because it is the same answer.
     *  The prose channel carries it for the reason §3.2 gives twice: a limit stated only under `--json`
     *  leaves the human reading the unqualified verdict. */
    static final String UNEVALUATED_TAIL_STRICT =
            "(`ok` is OMITTED from `--json` — a declined question is not a finding, and not a pass either; "
            + "`--strict` exits 2, the could-not-evaluate code.)";

    /** whatif <report> <fn> <Effect> [policy] — the PRE-EDIT verdict (mirrors candor-query). Computes the
     *  blast radius of introducing `effect` into `fn` (the fn + every transitive caller, all of which would
     *  gain it), then — given a policy — reports which of them would VIOLATE a `deny <Effect>`/`pure`
     *  boundary. Answers "if I add a network call here, what propagates and is it allowed?" BEFORE the edit.
     *  Reuses Policy.parsePolicy/scopeMatches so the verdict matches what the real gate would do. */
    static int whatif(String reportLocator, String reportPath, String fn, String effect, String policyPath,
                      boolean json) {
        if (fn == null || effect == null) return usage("whatif <fn> <Effect> [--report <locator>] [--policy <file>] [--json]");
        // Validate the effect against the vocabulary: a typo'd/lowercase effect (`net`) matches no deny
        // rule and would print an authoritative-looking clean verdict — a false green light for the very
        // edit the policy forbids (/code-review). Reject it as a usage error, not a pass.
        if (!Rules.KNOWN_EFFECTS.contains(effect) && !effect.equals("Unknown")) {
            System.err.println("candor: unknown effect `" + effect + "` (expected one of "
                    + Rules.KNOWN_EFFECTS + " or Unknown)");
            return 2;
        }
        Map<String, List<String>> cg = loadCallgraph(reportPath);
        if (cg == null || cg.isEmpty()) {
            System.out.println("candor: no call-graph sidecar beside the report (re-run analysis with --json).");
            return 2;
        }
        Map<String, List<String>> rev = new TreeMap<>(); // callee -> direct callers
        for (var e : cg.entrySet())
            for (String c : e.getValue()) rev.computeIfAbsent(c, k -> new ArrayList<>()).add(e.getKey());
        Set<String> names = new TreeSet<>(cg.keySet());
        for (var v : cg.values()) names.addAll(v);
        int tier = bestTier(names.stream(), fn);
        List<String> targets = new ArrayList<>();
        for (String n : names) if (tier > 0 && matchTier(n, fn) >= tier) targets.add(n);
        if (targets.isEmpty()) {
            System.out.println("candor: no function matching `" + fn + "` in the call graph.");
            return 2;
        }
        TreeSet<String> affected = new TreeSet<>(targets); // target(s) + every transitive caller gain `effect`
        Deque<String> stack = new ArrayDeque<>(targets);
        while (!stack.isEmpty()) {
            String n = stack.pop();
            for (String c : rev.getOrDefault(n, List.of())) if (affected.add(c)) stack.push(c);
        }

        if (policyPath == null) policyPath = resolvePolicyFallback();
        List<String[]> violations = new ArrayList<>(); // {fn, rule-desc}
        if (policyPath != null) {
            AnalysisState.ctx().denyRules.clear();
            // ⟨0.24⟩ POLICY VOCABULARY, anchored at the policy file (SPEC §3.1) — the same call the gate
            // and scan routes make. `whatif` never loaded it at all, so a policy using a config-declared
            // `unknown-alias` was silently rewritten here (widened or narrowed) while the gate honoured
            // it: the same rule, two meanings, in the verb an agent consults BEFORE editing.
            AnalysisState.ctx().unknownAliases.putAll(
                    Config.policyVocabulary(Path.of(policyPath)).unknownAliases());
            // A SPECIFIED-but-unreadable policy must FAIL LOUD, not silently yield ok:true — a typo'd
            // CANDOR_POLICY path otherwise reads as "no violations" and an agent proceeds with a
            // forbidden edit believing the boundary was checked (/code-review; mirrors the gate's own
            // loud-on-unreadable contract and the diff/rewire path checks).
            if (!Policy.parsePolicy(policyPath)) {
                System.err.println("candor: " + Policy.policyFailure(policyPath) + " — verdict NOT computed.");
                return 2;
            }
            for (String f : affected) {
                for (var r : AnalysisState.ctx().denyRules) {
                    boolean denies = r.effects().isEmpty() || r.effects().toNames().contains(effect);
                    if (denies && Policy.scopeMatches(f, r.scope())) {
                        // ⟨0.24⟩ THE OPERATOR'S OWN LINE, QUOTED — not one rebuilt from `effect`, which is
                        // the effect they ASKED ABOUT rather than the rule's own set. `src` is already
                        // comment-stripped and end-trimmed by #parsePolicy, so this is exactly what they
                        // wrote. MEASURED before the change, and every row names a rule nobody wrote:
                        //   `deny Unknown[reflect] app`   printed back as  `deny Unknown app`
                        //   `deny Net[unknown-host] app`  printed back as  `deny Net app`
                        //   `deny Net Db  app`            printed back as  `deny Net app`
                        // The first two are the sharp ones — a NARROWED rule shown as the WIDE one, in the
                        // verb an agent reads BEFORE editing, so the operator's own scoping is invisible at
                        // exactly the moment they are deciding whether it protects them. The third has no
                        // filter in sight and the same root cause: rebuilding from the question dropped the
                        // operator's other denied effect too.
                        //
                        // …AND THE ORDER MATTERS: quoting `src` while the verdict stayed filter-blind would
                        // be WORSE than the bug it fixes — the same unconditional "WOULD VIOLATE", now
                        // attributed to the narrowed line, reading as though candor had evaluated a filter
                        // it did not. So the unevaluated narrowing is named beside it (SPEC §3.1: an
                        // unanswerable condition is DISCLOSED, never scored as a failed one). See
                        // Policy#narrowingCondition for why this does NOT reuse #classNarrowingFires.
                        violations.add(new String[]{f, r.src(), Policy.narrowingCondition(r, effect)});
                        break;
                    }
                }
            }
        }

        // ⟨0.24⟩ IS THE REPORT THIS ANSWER IS COMPUTED FROM COMPLETE? (SPEC §3.2, candor-spec 0075987.)
        // `affected` is a transitive-CALLER closure, so an unparsed file's caller is INVISIBLE to it: the
        // blast radius is a LOWER BOUND, and the verdict drawn from it cannot be more certain than that.
        // A report that cannot be parsed at all is corrupt input, not an effect-free package (§3.1) — and
        // this verb reads only the callgraph SIDECAR, so it would otherwise answer over a report it never
        // opened. Fail loud instead.
        try {
            readEnvelope(reportPath);
        } catch (Exception e) {
            System.err.println("candor: cannot read report " + reportPath + " ("
                    + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName())
                    + ") — verdict NOT computed. A blast radius answered from the call-graph sidecar alone "
                    + "would be a pre-edit all-clear over a report nothing checked.");
            return 2;
        }
        // ⟨0.24⟩ …and over the whole report SET the locator names, which is the set the gate reads — see
        // {@link #advisoryUnanalyzed}. The loud read above stays: it is about THIS verb's own input (it
        // reads only the callgraph sidecar, so without it the verb answers over a report it never opened),
        // whereas the manifest is about what the gate would refuse over the same bytes.
        List<String[]> unanalyzed = advisoryUnanalyzed(reportLocator, reportPath, "whatif");

        if (json) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("of", targets);
            body.put("effect", effect);
            body.put("affected", new ArrayList<>(affected));
            List<Map<String, String>> vs = new ArrayList<>();
            for (String[] v : violations) {
                // ⟨0.24⟩ `conditional` is PER-VIOLATION and a STRING (SPEC §3.1, candor-spec 901f14d —
                // which corrects an earlier pin written from a description of rust's behaviour rather than
                // its output). The condition qualifies THIS finding, so it belongs on this finding and not
                // in a parallel list a consumer has to re-join. OMITTED when the rule does not narrow: a
                // `conditional` on every violation would train the reader to ignore it, which is the same
                // failure as naming a config that changed nothing — so its ABSENCE has to keep meaning
                // "this verdict rests on nothing candor could not evaluate".
                Map<String, String> m = new LinkedHashMap<>();
                m.put("fn", v[0]);
                m.put("rule", v[1]);
                if (v[2] != null) m.put("conditional", v[2]);
                vs.add(m);
            }
            body.put("violations", vs);
            // ⟨0.24⟩ **OVER AN INCOMPLETE REPORT, `ok` IS OMITTED — not `true`, and not `false` either.**
            // The argument now lives on {@link #advisoryAnswer}, which `unverified` and `fix-gate` share:
            // `ec1a441` ruled that the same law binds every advisory verb, and this engine's copy of it
            // sitting inline here is why the siblings did not have it. `affected`/`violations` still ship:
            // a partial answer that says it is partial beats a refusal, and `whatif` is consulted BEFORE an
            // edit, where the alternative is the operator guessing. The EXIT CODE is unchanged (0/1 on the
            // violations actually found) — it is the answer to "did I find one", which is a question this
            // run can still answer, and this verb has no `--strict` for §3.2 to rule an exit for.
            // No `unevaluated` list here: this verb discloses an unanswerable narrowing PER VIOLATION, as
            // `conditional` (§3.1) — see the `violations` loop above. It has no rule-level channel to pass.
            emit(advisoryAnswer(violations.isEmpty(), unanalyzed, List.of(), body));
            return violations.isEmpty() ? 0 : 1;
        }
        System.out.println("whatif: adding `" + effect + "` to `" + String.join(", ", targets) + "`");
        System.out.println("  → propagates to " + affected.size() + " function(s) (the blast radius):");
        for (String f : affected) System.out.println("      " + f);
        // ⟨0.24⟩ …and the PROSE channel carries the same limit. "✓ within policy" is the human `ok: true`,
        // and leaving it unqualified here while omitting the field in JSON would close one channel and
        // leave the identical false all-clear open in the other.
        if (!unanalyzed.isEmpty())
            System.out.println("  ⚠ the report declares " + unanalyzed.size() + " unanalyzed unit(s) — this "
                    + "blast radius is a LOWER BOUND (a caller in an unanalyzed unit is invisible to it):"
                    + unanalyzed.stream().limit(5).map(u -> "\n      " + u[0] + " (" + u[1] + ")")
                            .reduce("", String::concat)
                    + (unanalyzed.size() > 5 ? "\n      … and " + (unanalyzed.size() - 5) + " more" : ""));
        if (policyPath == null) {
            System.out.println("  (no policy given — pass a policy file or set CANDOR_POLICY for the gate verdict)");
            return 0;
        }
        if (violations.isEmpty()) {
            System.out.println(unanalyzed.isEmpty()
                    ? "  ✓ within policy — this edit introduces no `deny`/`pure` boundary violation."
                    : "  · no `deny`/`pure` violation among the functions candor could SEE — NOT an "
                      + "all-clear, since the report is incomplete (above).");
            return 0;
        }
        System.out.println("  ⚠ WOULD VIOLATE policy (" + violations.size() + ") — run BEFORE the edit:");
        for (String[] v : violations) {
            System.out.println("      [AS-EFF-006] `" + v[0] + "`  (rule: `" + v[1] + "`)");
            // ⟨0.24⟩ THE PROSE CHANNEL CARRIES THE SAME QUALIFIER. A condition disclosed only in `--json`
            // leaves the human reading the identical unconditional verdict beside the identical narrowed
            // line — the exact defect, in the channel that is consulted more.
            if (v[2] != null) {
                System.out.println("          …IF " + v[2] + ".");
                System.out.println("          This rule NARROWS, and the effect you have not written yet has no class to");
                System.out.println("          match — candor charges it fail-closed rather than guessing which you'd add.");
            }
        }
        return 1;
    }

    /** The deny/`pure` scope (the "layer") that forbids `effect` at `fn`, or null if performing it there is
     *  allowed. Mirrors the gate's own AS-EFF-006 predicate (Policy.checkPolicy): a `deny` fires when it
     *  names the effect; a `pure` rule (empty effects) forbids every real effect but not Unknown. Reads the
     *  parsed deny rules from the thread-local context (the caller must have parsed a policy first).
     *
     *  <p>⟨0.24⟩ …AND THE RULE'S OWN {@code Unknown[class…]} / {@code Net[dest…]} NARROWING, through the
     *  gate's {@link Policy#classNarrowingFires}. "Mirrors the gate's predicate" was true when written and
     *  stopped being true when the rung landed: naming the effect is not the same as forbidding it HERE.
     *  MEASURED — {@code deny Unknown[reflect,unresolved] app} over a report whose only hole is
     *  {@code native:dlopen} produced a full hoist plan and {@code --strict} exit 1 for a boundary the gate
     *  (correctly, exit 0) does not draw: a red CI check and an instruction to restructure code around a
     *  line the policy does not contain.
     *
     *  <p>⟨0.24⟩ …AND NOT A RULE THE GATE WITHHELD (SPEC §3.2). {@code classNarrowingFires} returns the same
     *  {@code false} for "the filter says a DIFFERENT class" and for "the field the filter reads is ABSENT",
     *  and those are opposite statements: the first is a boundary the policy does not draw, the second is a
     *  boundary the gate REFUSED to adjudicate. Both used to end the loop the same way — {@code null}, "no
     *  policy forbids it there" — so `fix` reported "nothing to fix" and `fix-gate` reported {@code ok:true}
     *  over a report the gate exits 2 on. The remedy premised on the refused evidence is the mirror harm and
     *  is measured in {@link #fixGate}: over `deny Unknown[unresolved] app` and an entry whose `Unknown` is
     *  INHERITED with no reason reachable, the gate refused while `fix-gate --strict` returned a full hoist
     *  plan for `app.inherits` and exit 1.
     *
     *  @param withheld {@link #unanswerableScopedFilters}'s triples; {@code Set.of()} means "nothing was
     *                  withheld", which is the scan route and every answerable report */
    static String deniedLayer(String fn, String effect, Policy.GateInput gi, Set<String> withheld) {
        Effect e = Effect.fromSpecName(effect);
        for (var r : AnalysisState.ctx().denyRules) {
            boolean denies = r.effects().isEmpty() ? !effect.equals("Unknown") : r.effects().toNames().contains(effect);
            if (!denies || !Policy.scopeMatches(fn, r.scope())) continue;
            if (Policy.withheldAt(withheld, r, fn)) continue;                      // the gate could not judge it
            if (e != null && !Policy.classNarrowingFires(r, gi, fn, e)) continue;  // outside the rule's classes
            return r.scope();
        }
        return null;
    }

    /** The report's RAW {@code unknownWhy} channel — what §6.2's class matching resolves over — or an empty
     *  map when there is no readable report beside the entries, which makes
     *  {@link Policy#gateInputFromReport} fall back to the PARSED reasons the entries already carry. The
     *  raw form matters only for a colon-free tag ({@code missing-config}), which {@code UnknownReason.parse}
     *  drops; the fallback therefore loses a `setup` classification and floors to `unresolved`, which is the
     *  conservative direction for both verbs that call this (a hole named rather than missed). */
    static Map<String, List<String>> rawUnknownWhy(String reportPath) {
        if (reportPath == null) return Map.of();
        try {
            return readEnvelope(reportPath).rawUnknownWhy();
        } catch (Exception e) {
            return Map.of();
        }
    }

    /** A computed boundary remedy (integrations/FIX-SPEC.md) — the deterministic cut between "must stay
     *  pure" (`deniedSpan`) and "may perform the effect" (`hoistTo`). The Java mirror of candor-query's
     *  RemedyPlan. */
    private record Remedy(String fn, String effect, String layer, boolean cleanHoist,
                          List<String> sites, List<String> deniedSpan, List<String> hoistTo,
                          List<String> hoistHigher, String allowEdit) {
        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("fn", fn);
            m.put("effect", effect);
            m.put("layer", layer);
            m.put("cleanHoist", cleanHoist);
            m.put("site", sites);
            m.put("deniedSpan", deniedSpan);
            m.put("hoistTo", hoistTo);
            m.put("hoistHigher", hoistHigher);
            m.put("policyAlternative", allowEdit);
            return m;
        }
        /** Folds the many inheritors of one root cause to a single remedy: the plan is fixed by its effect,
         *  layer, site and hoist target — not by which inheriting function tripped the gate. */
        String dedupKey() { return effect + "|" + layer + "|" + sites + "|" + hoistTo; }
        void renderText(StringBuilder out) {
            // An empty scope is a GLOBAL rule (`deny Exec` with no layer — program-wide); render a real word,
            // not the literal "this", which read like an unsubstituted template variable (#12a).
            String layerLabel = layer.isEmpty() ? "global" : "`" + layer + "`";
            String siteList = sites.isEmpty()
                    ? "(not a local source — a cross-jar or Unknown effect)"
                    : sites.stream().map(x -> "`" + x + "`").collect(Collectors.joining(", "));
            out.append("candor fix — hoist ").append(effect).append(" out of the ").append(layerLabel).append(" boundary\n\n");
            out.append("  The violation: `").append(fn).append("` performs ").append(effect)
               .append(", which the ").append(layerLabel).append(" layer forbids.\n");
            out.append("  Performed directly at: ").append(siteList).append("\n");
            String span = deniedSpan.stream().limit(6).map(x -> "`" + x + "`").collect(Collectors.joining(", "))
                    + (deniedSpan.size() > 6 ? ", …" : "");
            out.append("  Forbidden across ").append(deniedSpan.size())
               .append(" function(s) in the layer (they inherited it): ").append(span).append("\n\n");
            if (cleanHoist) {
                out.append("  THE FIX — hoist the effect to the boundary:\n");
                out.append("    · Perform ").append(effect).append(" at: ")
                   .append(hoistTo.stream().map(x -> "`" + x + "`").collect(Collectors.joining(", ")))
                   .append("  (an allowed layer that already calls into the domain).\n");
                out.append("    · Pass the result down as a parameter; the ").append(deniedSpan.size())
                   .append(" function(s) above then stay pure.\n");
                out.append("    · Re-run the gate — the ").append(layerLabel).append(" blast radius for ")
                   .append(effect).append(" should be empty.\n");
                if (!hoistHigher.isEmpty()) {
                    String tops = hoistHigher.stream().limit(4).map(x -> "`" + x + "`").collect(Collectors.joining(", "))
                            + (hoistHigher.size() > 4 ? ", …" : "");
                    out.append("    · TRADE-OFF — or hoist higher (up to ").append(tops).append("): the effect then originates further up,\n");
                    out.append("      keeping the ").append(hoistHigher.size())
                       .append(" intervening allowed-layer function(s) pure too, at the cost of threading it through more signatures.\n");
                }
                out.append("\n");
                out.append("  ALTERNATIVE — if the ").append(layerLabel).append(" layer is MEANT to perform ")
                   .append(effect).append(", it's a policy bug,\n");
                out.append("  not a code one: relax the boundary with  `").append(allowEdit).append("`.\n");
            } else {
                if (!hoistTo.isEmpty()) { // SANDWICHED: a frontier exists but a forbidden layer calls into it
                    out.append("  NO CLEAN HOIST — the nearest allowed layer (")
                       .append(hoistTo.stream().map(x -> "`" + x + "`").collect(Collectors.joining(", ")))
                       .append(") is itself CALLED BY a ").append(effect).append("-forbidding layer,\n");
                    out.append("  so hoisting ").append(effect)
                       .append(" there would leave that caller violating (a forbidden layer sandwiching an allowed one).\n");
                } else {
                    out.append("  NO CLEAN HOIST — every caller up to the entry points is also in a ")
                       .append(effect).append("-forbidding layer.\n");
                }
                out.append("  Three ways to fix it:\n");
                out.append("    (a) HOIST TO A NEW ENTRY POINT (recommended) — add a thin method ABOVE the ").append(layerLabel)
                   .append(" layer that performs\n");
                out.append("        ").append(effect).append(" and passes the result DOWN as plain DATA; the ").append(layerLabel)
                   .append(" methods take it as a parameter and become\n");
                out.append("        PROVABLY pure (candor verifies no effect — clean under any policy). candor says \"no clean hoist\"\n");
                out.append("        only because no allowed caller EXISTS yet — you can add one; simplest fix.\n");
                out.append("    (b) INJECT via a functional value — give the ").append(layerLabel)
                   .append(" layer a FUNCTION parameter (a Supplier / method reference)\n");
                out.append("        supplied by an allowed adapter. This clears `deny ").append(effect)
                   .append("`, but candor can't see THROUGH the injected\n");
                out.append("        function, so it reads the ").append(layerLabel)
                   .append(" as Unknown — a hole a `deny ").append(effect).append(" Unknown` policy would still flag;\n");
                out.append("        prefer (a) for provable purity. Do NOT use a resolvable interface impl: candor resolves the\n");
                out.append("        dispatch back to its ").append(effect).append("-performing impl, so the ").append(layerLabel)
                   .append(" still trips the gate.\n");
                out.append("    (c) If the ").append(layerLabel).append(" layer legitimately needs ").append(effect)
                   .append(", relax the boundary:  `").append(allowEdit).append("`.\n");
            }
        }
    }

    /** The cut itself — pure over the report graph. `start` performs `effect` and sits in the deny-`effect`
     *  layer `layer`; `cg` is caller→callees (the sidecar), `rev` its inverse, `byName` the effector index.
     *  Returns the direct site(s), the denied span, and the hoist frontier. Shared by `fix` and `fix-gate`.
     *
     *  <p>⟨0.24⟩ {@code withheld} rides all the way in, because the SPAN and the FRONTIER are the same
     *  question as the entry: a caller the gate could not judge must not be named as the allowed layer to
     *  hoist the effect INTO. In practice the entry guard has already fired for the whole chain — a report
     *  that dropped the `netClass`/reason channel dropped it for every entry, and {@code
     *  Policy#gateInputFromReport} reads those fields VERBATIM rather than propagating them — but the
     *  predicate is one predicate, so it is passed rather than approximated here. */
    static Remedy computeRemedy(String start, String effect, String layer,
                                Map<String, List<String>> cg, Map<String, List<String>> rev,
                                Map<String, Effector> byName, Policy.GateInput gi, Set<String> withheld) {
        // direct site(s) S: forward BFS from `start` through effect-carrying callees to the DIRECT source(s).
        TreeSet<String> sites = new TreeSet<>();
        TreeSet<String> fseen = new TreeSet<>();
        Deque<String> fq = new ArrayDeque<>();
        fq.add(start);
        fseen.add(start);
        while (!fq.isEmpty()) {
            String cur = fq.poll();
            Effector fe = byName.get(cur);
            if (fe != null && fe.direct().toNames().contains(effect)) sites.add(cur);
            for (String c : cg.getOrDefault(cur, List.of())) {
                Effector ce = byName.get(c);
                if (ce != null && ce.inferred().toNames().contains(effect) && fseen.add(c)) fq.add(c);
            }
        }
        // ANCHOR on the site(s) (fall back to `start` for a cross-jar/Unknown source with no local site) and
        // walk UP: denied-layer effect-carriers are the pure span; the allowed-layer callers where the climb
        // stops are the hoist frontier. Site-anchored so the span is the SAME whichever inheriting function
        // triggered it (root-independent) — the two domain functions collapse to one identical remedy.
        Set<String> anchors = sites.isEmpty() ? Set.of(start) : sites;
        TreeSet<String> deniedSpan = new TreeSet<>();
        TreeSet<String> hoist = new TreeSet<>();
        Deque<String> up = new ArrayDeque<>();
        for (String a : anchors) {
            if (deniedLayer(a, effect, gi, withheld) != null) deniedSpan.add(a); // a site that is itself in the denied layer
            up.add(a);
        }
        while (!up.isEmpty()) {
            String cur = up.poll();
            for (String caller : rev.getOrDefault(cur, List.of())) {
                Effector ce = byName.get(caller);
                // skip a caller that doesn't route the effect — INCLUDING one absent from the report (a pure
                // callgraph-only node never carries the effect). Skipping the absent case matches candor-swift
                // and avoids naming a pure node as a hoist target. (/code-review — was `ce != null && !…`.)
                if (ce == null || !ce.inferred().toNames().contains(effect)) continue;
                if (deniedLayer(caller, effect, gi, withheld) != null) {
                    if (deniedSpan.add(caller)) up.add(caller); // denied → part of the span; keep climbing
                } else {
                    hoist.add(caller); // allowed → the boundary; the effect should originate here
                }
            }
        }
        // higher hoist options: allowed-layer transitive callers of the minimal frontier that also route the
        // effect — hoisting higher keeps the frontier pure too, at the cost of threading through more
        // signatures (FIX-SPEC: the trade-off, disclosed not hidden).
        // The SANDWICHED-layer check (/code-review): a hoist is CLEAN only if no forbidden fn sits ABOVE the
        // frontier. If a denied fn calls into a hoist target, hoisting the effect there leaves that caller
        // violating. Detected in the same climb that gathers `higher` (the allowed ancestors).
        TreeSet<String> higher = new TreeSet<>();
        boolean sandwiched = false;
        TreeSet<String> hseen = new TreeSet<>(hoist);
        Deque<String> hq = new ArrayDeque<>(hoist);
        while (!hq.isEmpty()) {
            String cur = hq.poll();
            for (String caller : rev.getOrDefault(cur, List.of())) {
                Effector ce = byName.get(caller);
                if (ce == null || !ce.inferred().toNames().contains(effect)) continue;
                if (deniedLayer(caller, effect, gi, withheld) != null) {
                    sandwiched = true;
                } else if (hseen.add(caller)) {
                    higher.add(caller);
                    hq.add(caller);
                }
            }
        }
        boolean cleanHoist = !hoist.isEmpty() && !sandwiched;
        String allowEdit = layer.isEmpty() ? "allow " + effect : "allow " + effect + " " + layer;
        return new Remedy(start, effect, layer, cleanHoist,
                new ArrayList<>(sites), new ArrayList<>(deniedSpan), new ArrayList<>(hoist), new ArrayList<>(higher), allowEdit);
    }

    /** Load a policy into the thread-local deny rules, fail-loud (exit 2) on an unreadable path — the same
     *  contract as `whatif`. Returns the RESOLVED policy path on success (the argument, or {@code
     *  CANDOR_POLICY} when it was absent — the advisory verbs quote it in their ⟨0.24⟩ `unevaluated` rows,
     *  and quoting the unresolved `null` would print a re-run instruction that does not work); on failure
     *  prints the reason, returns null, and the caller returns 2. */
    private static String loadPolicyOrFail(String policyPath, String who) {
        if (policyPath == null) policyPath = resolvePolicyFallback();
        if (policyPath == null) {
            System.err.println("candor " + who + ": a policy is required (pass a policy file or set CANDOR_POLICY) — the fix is the refactor that restores the boundary the edit crossed.");
            return null;
        }
        AnalysisState.ctx().denyRules.clear();
        // ⟨0.24⟩ POLICY VOCABULARY, anchored at the policy file (SPEC §3.1) — as `whatif` and the two gate
        // routes do. `fix-gate` must compute the hoist for the rule the GATE will run, not for a rewritten
        // one; without this an `Unknown[<alias>]` rule named a different boundary here than there.
        AnalysisState.ctx().unknownAliases.putAll(
                Config.policyVocabulary(Path.of(policyPath)).unknownAliases());
        if (!Policy.parsePolicy(policyPath)) {
            // The CONSEQUENCE is the calling verb's, not the loader's. This helper is shared by `fix`,
            // `fix-gate` and `unverified`, and `unverified` computes no fix — it reports which functions
            // PASS their policy without being provably clean, so an unhonourable policy costs it the
            // CHECK, not a remedy. The posture (refuse rather than proceed on a policy read differently
            // from how it was written) is right; only the noun was borrowed from the sibling verb.
            System.err.println("candor " + who + ": " + Policy.policyFailure(policyPath) + " — "
                    + ("unverified".equals(who) ? "nothing was checked" : "no fix computed") + ".");
            return null;
        }
        return policyPath;
    }

    private static Map<String, List<String>> reverseGraph(Map<String, List<String>> cg) {
        Map<String, List<String>> rev = new TreeMap<>(); // callee -> direct callers
        for (var e : cg.entrySet())
            for (String c : e.getValue()) rev.computeIfAbsent(c, k -> new ArrayList<>()).add(e.getKey());
        return rev;
    }

    /** The graph the cut walks: the `.callgraph.json` sidecar if present, else the report entries' inline
     *  `calls` (so a sidecar-less report — a `--json -` stdout dump, a hand-authored report, or one whose
     *  sidecar was cleaned — still gets the real cut, not a degenerate empty-graph remedy). Mirrors
     *  candor-query (which never reads the sidecar) and candor-swift's fallback; the `callers` command falls
     *  back the same way. (/code-review — Java/TS previously emitted `no clean hoist` here.) */
    static Map<String, List<String>> fixGraph(String reportPath, List<Effector> fns) {
        Map<String, List<String>> cg = loadCallgraph(reportPath);
        if (cg != null && !cg.isEmpty()) return cg;
        Map<String, List<String>> inline = new LinkedHashMap<>();
        for (Effector f : fns) inline.put(f.fn(), f.calls());
        return inline;
    }

    /** fix <report> <fn> <Effect> [policy] — the BOUNDARY FIX (integrations/FIX-SPEC.md, the remedial inverse
     *  of whatif). When `fn` performs `effect` in a layer the policy forbids, compute where the effect belongs
     *  (hoist to the nearest allowed-layer caller) and which functions become pure and thread the value.
     *  Advisory: candor names the structure, you write the code; the gate re-scan stays the ground truth. */
    static int fix(List<Effector> fns, String reportLocator, String reportPath, String fn, String effect,
                   String policyPath, boolean json) {
        if (fn == null || effect == null) return usage("fix <fn> <Effect> [--report <locator>] [--policy <file>] [--json]");
        if (!Rules.KNOWN_EFFECTS.contains(effect) && !effect.equals("Unknown")) {
            System.err.println("candor: unknown effect `" + effect + "` (expected one of " + Rules.KNOWN_EFFECTS + " or Unknown)");
            return 2;
        }
        if (loadPolicyOrFail(policyPath, "fix") == null) return 2;
        // ⟨0.24⟩ SPEC §3.2 (`ec1a441`) — this verb answers about ONE function and carries neither `ok` nor
        // `--strict`, so it has no field to withdraw and no exit to fail. What it DOES have is the same
        // sentence: `no policy forbids it there — nothing to fix` over a report declaring source candor
        // could not read is the prose all-clear, in the channel §3.2 says a test cannot see.
        List<String[]> unanalyzed = advisoryUnanalyzed(reportLocator, reportPath, "fix");
        advisoryIncompleteNote("fix", unanalyzed,
                "(this verb answers about ONE function and carries no `ok` and no `--strict` — what it loses "
                + "is REACH: a caller inside an unanalyzed unit is invisible to the hoist below)");

        Map<String, Effector> byName = new HashMap<>();
        for (Effector f : fns) byName.put(f.fn(), f);
        Map<String, List<String>> cg = fixGraph(reportPath, fns);
        Map<String, List<String>> rev = reverseGraph(cg);
        // ⟨0.24⟩ the reason/destination channel a NARROWED rule is evaluated over — built by the same
        // Policy#gateInputFromReport the gate itself uses, never a second copy (SPEC §6.2).
        Policy.GateInput gi = Policy.gateInputFromReport(fns, rawUnknownWhy(reportPath));
        // ⟨0.24⟩ SPEC §3.2 — and the (rule, fn, effect) triples the GATE would refuse over these same bytes.
        Unanswerable scoped = unanswerableScopedFilters(gi);

        // Resolve `fn` among the best-tier matches, PREFERRING one that performs the effect (so a bare leaf
        // resolves to the violating fn, not a same-named pure sibling). Must match candor-query/ts/swift — a
        // divergence flips a real remedy into a false "nothing to hoist". (/code-review.)
        int tier = bestTier(fns.stream().map(Effector::fn), fn);
        List<Effector> tierMatches = new ArrayList<>();
        for (Effector f : fns) if (tier > 0 && matchTier(f.fn(), fn) >= tier) tierMatches.add(f);
        String start = tierMatches.stream().filter(f -> f.inferred().toNames().contains(effect)).findFirst()
                .map(Effector::fn).orElse(tierMatches.isEmpty() ? null : tierMatches.get(0).fn());
        if (start == null) {
            System.err.println("candor fix: no function matching `" + fn + "`.");
            return 2;
        }
        Effector se = byName.get(start);
        if (se == null || !se.inferred().toNames().contains(effect)) {
            System.out.println("candor fix: `" + start + "` does not perform " + effect + " — nothing to hoist."
                    + (unanalyzed.isEmpty() ? "" : " (NOT an all-clear: the report declares "
                        + unanalyzed.size() + " unanalyzed unit(s), above.)"));
            return 0;
        }
        // ⟨0.24⟩ SPEC §3.2 — THE REFUSAL COMES FIRST, because "no policy forbids it there" and "the gate
        // could not tell" are different sentences and only one of them is true here. Answered before
        // `deniedLayer` returns null for the second reason, so the two never collapse into the first.
        List<Withheld> here = scoped.functions().stream()
                .filter(w -> w.fn().equals(start) && w.effect().equals(effect)).toList();
        if (!here.isEmpty()) {
            for (Withheld w : here) System.err.println("candor fix: " + w.why());
            System.err.println("candor fix: no remedy computed — a hoist plan for a boundary the gate "
                    + "REFUSED to adjudicate would be a confident instruction resting on a guess. Widen the "
                    + "rule or gate at scan time, then re-run.");
            if (json) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("fn", start);
                out.put("effect", effect);
                out.put("unevaluated", Candor.unevaluatedJson(
                        here.stream().map(w -> new String[]{w.rule(), w.why()}).toList()));
                if (!unanalyzed.isEmpty()) {
                    out.put("incomplete", true);
                    out.put("unanalyzed", manifestJson(unanalyzed));
                }
                emit(out);
            }
            return 2;
        }
        String layer = deniedLayer(start, effect, gi, scoped.triples());
        if (layer == null) {
            System.out.println("candor fix: `" + start + "` performs " + effect
                    + ", but no policy forbids it there — the boundary isn't crossed, nothing to fix."
                    + (unanalyzed.isEmpty() ? "" : " (NOT an all-clear: the report declares "
                        + unanalyzed.size() + " unanalyzed unit(s), above — a caller in one of them is "
                        + "invisible to the hoist this verb would have computed.)"));
            return 0;
        }
        Remedy plan = computeRemedy(start, effect, layer, cg, rev, byName, gi, scoped.triples());
        if (json) {
            // The plan is a DOCUMENT, not a verdict — it carries no `ok` to withdraw. The manifest rides it
            // for the reason §3.2 gives about the hoist FRONTIER: a caller inside an unanalyzed unit is
            // absent from `functions`, so the computed frontier is a lower bound and the agent editing to
            // it deserves to know which file it could not see.
            Map<String, Object> out = new LinkedHashMap<>(plan.toJson());
            if (!unanalyzed.isEmpty()) {
                out.put("incomplete", true);
                out.put("unanalyzed", manifestJson(unanalyzed));
            }
            emit(out);
            return 0;
        }
        StringBuilder sb = new StringBuilder();
        plan.renderText(sb);
        System.out.print(sb);
        System.out.println("\n  (Advisory: candor names the shape, you write the code; the gate re-scan verifies the fix.)");
        if (!unanalyzed.isEmpty())
            System.out.println("  ⚠ the hoist frontier is a LOWER BOUND — the report declares "
                    + unanalyzed.size() + " unanalyzed unit(s) (above); a caller in one is invisible to it.");
        return 0;
    }

    /** fix-gate <report> [policy] — a remedy for EVERY deny/`pure` (AS-EFF-006) boundary crossing in the
     *  report, collapsing the inheritors of one root cause to a single plan. The edit-time loop folds this
     *  into the block message so the agent gets the FIX, not just the finding. Scope is AS-EFF-006 only —
     *  the one refactor candor can compute; allowlist/layering findings are a different shape.
     *
     *  <p>⟨0.24⟩ <b>AND NO REMEDY PREMISED ON EVIDENCE THE GATE REFUSED TO READ</b> (SPEC §3.2). MEASURED
     *  on this engine before the repair, one hand-built report — an entry whose {@code Unknown} is INHERITED
     *  with no reason reachable, under {@code deny Unknown[unresolved] app}:
     *  <pre>
     *    gate --report        exit 2, refused — it CANNOT judge `app.inherits`
     *    fix-gate             ok:false + a full hoist plan for `app.inherits`
     *    fix-gate --strict    exit 1 — a red CI check and an instruction to restructure code around a
     *                         boundary the gate declined to adjudicate
     *  </pre>
     *  The mechanism is the one {@link #deniedLayer} names: {@code reasonClassesOf} floors an absent class
     *  set to {@code unresolved}, so the narrowing FIRED on the fail-closed default for the very datum the
     *  gate refused to read — right for the gate (which then refuses), a fabricated premise for a remedy. */
    static int fixGate(List<Effector> fns, String reportLocator, String reportPath, String policyPath,
                       boolean json, boolean strict) {
        String pol = loadPolicyOrFail(policyPath, "fix-gate");
        if (pol == null) return 2;
        // ⟨0.24⟩ SPEC §3.2 (`ec1a441`) — is the report this remedy is computed from COMPLETE? See
        // {@link #advisoryUnanalyzed} / {@link #advisoryAnswer}: `ok: true` here reads "no crossings left
        // to fix", which over an unread file is a claim about a universe this verb cannot enumerate.
        List<String[]> unanalyzed = advisoryUnanalyzed(reportLocator, reportPath, "fix-gate");

        Map<String, Effector> byName = new HashMap<>();
        for (Effector f : fns) byName.put(f.fn(), f);
        Map<String, List<String>> cg = fixGraph(reportPath, fns);
        Map<String, List<String>> rev = reverseGraph(cg);
        // ⟨0.24⟩ as `fix` — the SAME gate input, so a narrowed rule names the same boundary in both verbs.
        Policy.GateInput gi = Policy.gateInputFromReport(fns, rawUnknownWhy(reportPath));
        // ⟨0.24⟩ …and the SAME withholding, from the same producer the gate reads (SPEC §3.2).
        Unanswerable scoped = unanswerableScopedFilters(gi);
        List<String[]> unevaluated = new ArrayList<>(policyKindUnevaluated(pol));
        unevaluated.addAll(scoped.disclosures());

        Map<String, Remedy> plans = new TreeMap<>();
        for (Effector f : fns) {
            for (String effect : f.inferred().toNames()) {
                String layer = deniedLayer(f.fn(), effect, gi, scoped.triples());
                if (layer != null) {
                    Remedy p = computeRemedy(f.fn(), effect, layer, cg, rev, byName, gi, scoped.triples());
                    plans.putIfAbsent(p.dedupKey(), p);
                }
            }
        }
        // ⟨0.24⟩ `ok` IS THE CLAIM, and it is bounded above by the gate's. With a rule left unevaluated the
        // claim is not made AT ALL — `142740a`: `true` would be a statement about the rules this verb could
        // read rather than about the policy, and `false` would assert a crossing beside an empty `remedies`
        // that nobody found. {@link #advisoryAnswer} withholds the field; `clean` survives only to rank the
        // exit below, where "did I find a crossing" is still a question this run answered.
        boolean clean = plans.isEmpty() && unevaluated.isEmpty();
        if (json) {
            Map<String, Object> body = new LinkedHashMap<>();
            List<Map<String, Object>> rem = new ArrayList<>();
            for (Remedy p : plans.values()) rem.add(p.toJson());
            body.put("remedies", rem);
            emit(advisoryAnswer(clean, unanalyzed, unevaluated, body));
            // Advisory by default (exit 0 — the agent fix-loop reads the remedy and edits); `--strict` makes
            // the exit follow `ok`, so CI can REQUIRE zero outstanding crossings (mirrors `unverified --strict`).
            // ⟨0.24⟩ 2, not 1, when a rule went unevaluated OR the report is incomplete: SPEC §3.2 pins the
            // exit to the GATE's, and neither a refusal nor an unread file is a crossing the operator can go
            // and fix. Could-not-fully-evaluate OUTRANKS found-a-crossing, for the same reason.
            if (strict && (!unevaluated.isEmpty() || !unanalyzed.isEmpty())) return 2;
            return strict && !plans.isEmpty() ? 1 : 0;
        }
        for (String[] u : unevaluated) System.err.println("candor fix-gate: " + u[1]);
        advisoryIncompleteNote("fix-gate", unanalyzed, INCOMPLETE_TAIL_STRICT);
        if (plans.isEmpty()) {
            if (unevaluated.isEmpty() && unanalyzed.isEmpty()) {
                System.out.println("candor fix-gate: no deny/pure boundary crossings in this report ✓");
                return 0;
            }
            // ⟨0.24⟩ THE TICK IS THE PROSE `ok: true`, so it is WITHDRAWN here and not merely annotated.
            if (!unevaluated.isEmpty())
                System.out.println("candor fix-gate: no remedy — " + unevaluated.size() + " policy rule(s) could "
                        + "not be evaluated against this report (above), and `gate --report` refuses over them. "
                        + "NOT an all-clear: a hoist plan premised on evidence the gate declined to read would "
                        + "be a confident instruction resting on a guess. " + UNEVALUATED_TAIL_STRICT);
            if (!unanalyzed.isEmpty())
                System.out.println("candor fix-gate: no deny/pure boundary crossing among the functions candor "
                        + "could SEE — NOT an all-clear: " + unanalyzed.size() + " unit(s) went unanalyzed "
                        + "(above), and a crossing inside one is absent from `functions`, so this verb cannot "
                        + "enumerate it at all.");
            return strict ? 2 : 0;
        }
        int n = plans.size();
        System.out.println("candor fix — " + n + " boundary " + (n == 1 ? "remedy" : "remedies") + " for this change:\n");
        int i = 0;
        for (Remedy p : plans.values()) {
            if (i++ > 0) System.out.println("  ────────────────────────────────────────");
            StringBuilder sb = new StringBuilder();
            p.renderText(sb);
            System.out.print(sb);
        }
        System.out.println("\n  (Advisory: candor names the shape, you write the code; the gate re-scan verifies each fix.)");
        // ⟨0.24⟩ …and the list above is a LOWER BOUND when the report is incomplete: a crossing inside an
        // unanalyzed unit is absent from `functions`, so "these are the remedies" is the same over-claim
        // the tick was, in the branch that DID find something.
        if (!unanalyzed.isEmpty())
            System.out.println("  ⚠ NOT the whole list — the report declares " + unanalyzed.size()
                    + " unanalyzed unit(s) (above); a crossing inside one is invisible here.");
        if (strict) {
            if (!unevaluated.isEmpty() || !unanalyzed.isEmpty()) {
                System.out.println("  (--strict: " + n + " outstanding boundary crossing(s), AND "
                        + (unevaluated.isEmpty() ? "" : unevaluated.size() + " rule(s) the gate could not evaluate")
                        + (unevaluated.isEmpty() || unanalyzed.isEmpty() ? "" : " AND ")
                        + (unanalyzed.isEmpty() ? "" : unanalyzed.size() + " unit(s) candor could not analyze")
                        + " → exit 2, as the gate)");
                return 2;
            }
            System.out.println("  (--strict: " + n + " outstanding boundary crossing(s) → exit 1)");
            return 1;
        }
        return 0;
    }

    /** unverified <report> [policy] — the PROVABLE-PURITY disclosure (eval/fixloop/DISPATCH-NOTE.md, mirrors
     *  candor-query). A `pure`/`deny E` layer PASSES a function that carries none of its forbidden effects —
     *  but if that function is Unknown (an unresolvable call), the pass is UNVERIFIED: the Unknown could hide
     *  the very effect the rule forbids (the fn/closure-port hole). Names each such function + the
     *  `deny E Unknown <scope>` upgrade. Advisory (exit 0); `--strict` → exit 1. The gate verdict is untouched.
     *
     *  <p>⟨0.24⟩ <b>…AND EVERY FUNCTION THE GATE COULD NOT JUDGE</b> (SPEC §3.2, the ADVISORY-VERB
     *  CONFIDENCE LAW). A function the gate WITHHELD on is an unverified hole in the strongest sense this
     *  verb has: it is literally <i>"your green gate is not provably green"</i>, and it is the one case
     *  where the verb was silent. MEASURED on this engine before the repair, the conformance R11 report —
     *  {@code hosts} present, {@code netClass} absent — under {@code deny Net[unknown-host] app}:
     *  <pre>
     *    gate --report   exit 2   §3.1 answerability refusal — it CANNOT judge `app.noClass`
     *    unverified      exit 0   names `app.nativeHole` (a DIFFERENT hole) and clears `app.noClass`
     *  </pre>
     *  and on a report whose {@code Unknown} is INHERITED with no reason reachable, under
     *  {@code deny Unknown[unresolved] app}, the same defect with nothing left to hide behind:
     *  {@code gate --report} exit 2, {@code unverified} {@code ok:true, unverified: []}.
     *
     *  <p>The mechanism was not one bug but the ABSENCE of a question. This verb's hole predicate asks "does
     *  the gate PASS this function while it is Unknown?", and both halves of that quietly assume the gate
     *  reached a verdict at all: {@code app.noClass} carries no {@code Unknown} so it was never a candidate,
     *  and {@code app.inherits} had its narrowing FIRE on {@code reasonClassesOf}'s fail-closed
     *  {@code unresolved} floor — a class derived from the very field the gate refused to read. Naming the
     *  derived class is what §3.2 forbids; the reason recorded is the ABSENT FIELD ({@link #withheldWhy}).
     *
     *  <p><b>The `--class` filter is NOT applied to these entries</b>, and that is the point rather than an
     *  omission: {@code --class} selects on the reason-class channel, and a withheld entry is precisely one
     *  whose channel the gate could not read. Filtering it on a class derived from the absent field is the
     *  fallback derivation this law removes, one level over — and it would drop the entry silently, which is
     *  the direction that costs a disclosure. */
    static int unverified(List<Effector> fns, String reportLocator, String reportPath, String policyPath,
                          boolean json, boolean strict, Set<ReasonClass> classFilter) {
        String pol = loadPolicyOrFail(policyPath, "unverified");
        if (pol == null) return 2;
        // ⟨0.24⟩ SPEC §3.2 (`ec1a441`) — THE SHARPEST CASE IN THE FAMILY. This is the verb that exists to
        // say "your green gate is not provably green", and it was certifying a set it knows it cannot see
        // all of: a function in an unanalyzed file is absent from `functions`, so it cannot be enumerated
        // as an unverified pass — and that absence is exactly what this verb would have to report. See
        // {@link #advisoryUnanalyzed} / {@link #advisoryAnswer}.
        List<String[]> unanalyzed = advisoryUnanalyzed(reportLocator, reportPath, "unverified");
        List<PolicyRule.Deny> deny = AnalysisState.ctx().denyRules;
        record Hole(Effector fn, PolicyRule.Deny rule) {}
        // `--class <c,…>` (SPEC §6.2 ⟨0.24⟩): keep the holes whose reason classes intersect the filter,
        // resolved by the SAME code the gate beside this disclosure uses — Policy#reasonClassesOf over
        // Policy#gateInputFromReport. §6.2 requires exactly that ("THE GATE AND THE DISCLOSURE MUST APPLY
        // THE SAME RULE, AND SHOULD SHARE THE SAME CODE"), and this verb is the query it was written about:
        // the filter used to test `f.unknownWhy()`, the DIRECT field, which is
        //   (1) the wrong question — §4 makes `unknownWhy` direct-only by design, so a function whose
        //       `Unknown` is purely INHERITED carries no reason of its own and matched NO filter; and
        //   (2) fail-OPEN — an entry the filter could not classify was dropped by EVERY filter, including
        //       one naming its own class, so `unverified` under-reported the holes it exists to surface,
        //       and under-reported MORE the more the user narrowed.
        // MEASURED on the PART 27 fixture, before → after: `--class unresolved` 0 → 3 of 7 and `--class
        // dynamic` 2 → 7. The disclosure now agrees with the gate rather than contradicting it.
        //
        // NOT shared with `blindspots --class`, deliberately: §3.1 makes `blindspots` the SOURCE view and
        // EXCLUDES a unit whose `Unknown` is purely inherited, so every entry it filters carries a direct
        // reason by construction and the direct-only read is CORRECT there. Resolving transitively would
        // pull in exactly the units that verb is defined to exclude. One verb's definition is the other
        // verb's bug — a shared code path would be a shared defect here.
        //
        // ⟨0.24⟩ THE GATE INPUT IS NOW BUILT UNCONDITIONALLY, not only under `--class`. The HOLE PREDICATE
        // itself needs the reason/destination channel: a `deny E Unknown[c…]` / `deny Net[dest…]` rule that
        // does not fire at this function PASSES it, and a pass while Unknown is the hole this verb exists to
        // name. While the channel was `--class`-only, `unverified` computed from the effect set alone and
        // reported ok:true over exactly that layer — see Policy#classNarrowingFires for the measurement.
        Map<String, List<String>> rawWhy = Map.of();
        if (reportPath != null) {
            // The RAW `unknownWhy` strings, for the reason Policy#gateInputFromReport documents: a
            // colon-free tag (`missing-config`) is dropped by `UnknownReason.parse`, so reading the parsed
            // reasons would silently reclassify a `setup` entry as `unresolved` and put it back inside
            // `--class dynamic`, which by definition excludes `setup`.
            try {
                rawWhy = readEnvelope(reportPath).rawUnknownWhy();
            } catch (Exception e) {
                // `--class` keeps its loud contract: the user NAMED a class channel, so answering over a
                // fallback would silently answer a narrower question. Without the flag the parsed reasons
                // the entries already carry are the same data minus the colon-free tags, and that loss
                // floors to `unresolved` — the direction that names a hole rather than missing one.
                if (classFilter != null) {
                    String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                    System.err.println("candor unverified: --class needs the report's reason channel, but "
                            + reportPath + " could not be re-read (" + why + ")");
                    return 2;
                }
            }
        }
        final Policy.GateInput gi = Policy.gateInputFromReport(fns, rawWhy);
        // ⟨0.24⟩ SPEC §3.2 — WHAT THE GATE WOULD REFUSE OVER THESE BYTES, from the gate's own producer.
        Unanswerable scoped = unanswerableScopedFilters(gi);
        List<String[]> unevaluated = new ArrayList<>(policyKindUnevaluated(pol));
        unevaluated.addAll(scoped.disclosures());
        java.util.function.Predicate<Effector> classMatch =
                f -> Policy.reasonClassMatches(gi, f.fn(), classFilter);
        List<Hole> holes = new ArrayList<>();
        for (Effector e : fns) {
            // Same predicate as the gate note (Policy.unverifiedHoleRule) — one definition of a hole.
            PolicyRule.Deny r = Policy.unverifiedHoleRule(e.fn(), e.inferred(), deny, gi, scoped.triples());
            if (r != null && classMatch.test(e)) holes.add(new Hole(e, r));
        }
        // ⟨0.24⟩ …AND THE FUNCTIONS THE GATE COULD NOT JUDGE. Sorted by code point over (fn, rule, effect)
        // — locale-independent (§2), and a total order so the list is byte-stable whatever order the rules
        // and entries arrived in. Deduped on the same triple: two rules withholding the same effect at the
        // same function are two rows, one rule twice is one.
        List<Withheld> unjudged = scoped.functions().stream()
                .sorted(Comparator.comparing(Withheld::fn).thenComparing(Withheld::rule)
                        .thenComparing(Withheld::effect))
                .distinct().toList();
        // `ok` IS THE CLAIM, and §3.2 bounds it above by the gate's: a run in which the gate refused cannot
        // report a clean bill here, whether the refusal named functions (`unjudged`) or a whole rule kind.
        // ⟨0.24⟩ `142740a`: under a withheld rule it makes NO claim — {@link #advisoryAnswer} omits the
        // field. `unjudged` is non-empty only when `unevaluated` is (one producer emits both, per function
        // and per rule), so the two arms of that refusal reach the same answer by construction; `clean`
        // survives to rank the EXIT, which is about what this run did find.
        boolean clean = holes.isEmpty() && unjudged.isEmpty() && unevaluated.isEmpty();
        if (json) {
            List<Map<String, Object>> items = new ArrayList<>();
            for (Hole h : holes) {
                String[] ru = Policy.ruleUpgrade(h.rule(), Policy.reasonClassesOf(gi, h.fn().fn()));
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", h.fn().fn());
                m.put("rule", ru[0]);
                m.put("unknownWhy", h.fn().unknownWhy().stream().sorted().map(UnknownReason::format).toList());
                m.put("upgrade", ru[1]);
                items.add(m);
            }
            // The withheld entries ride the SAME array — a consumer asking "which functions are not provably
            // clean" must not have to know about a second key to get the ones the gate could not judge, which
            // are the least provable of all. They are told apart by `why`, present only here, and the rule is
            // quoted VERBATIM (never reconstructed through #ruleUpgrade, whose job is to name a filter this
            // engine could evaluate).
            for (Withheld w : unjudged) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", w.fn());
                m.put("rule", w.rule());
                m.put("unknownWhy", List.of());
                m.put("why", w.why());
                m.put("upgrade", w.widen());
                items.add(m);
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("unverified", items);
            emit(advisoryAnswer(clean, unanalyzed, unevaluated, body));
            // ⟨0.24⟩ 2, not 1, when the gate would have refused OR the report is incomplete — SPEC §3.2
            // pins the exit to the gate's, and could-not-fully-evaluate outranks found-a-hole.
            if (strict && (!unevaluated.isEmpty() || !unanalyzed.isEmpty())) return 2;
            return strict && !holes.isEmpty() ? 1 : 0;
        }
        // THE PROSE CHANNEL CARRIES THE SAME DISCLOSURE, for the reason `whatif` states one verb over: a
        // qualifier that exists only in `--json` leaves the human reading the identical all-clear.
        for (Withheld w : unjudged) System.err.println("candor unverified: " + w.why());
        for (String[] u : unevaluated)
            if (unjudged.stream().noneMatch(w -> w.rule().equals(u[0])))
                System.err.println("candor unverified: " + u[1]);
        advisoryIncompleteNote("unverified", unanalyzed, INCOMPLETE_TAIL_STRICT);
        if (holes.isEmpty() && unjudged.isEmpty()) {
            if (unevaluated.isEmpty() && unanalyzed.isEmpty()) {
                System.out.println("candor unverified: every function in a pure/deny layer is PROVABLY clean (no Unknown holes) ✓");
                return 0;
            }
            // ⟨0.24⟩ `… is PROVABLY clean ✓` IS the prose `ok: true` — it is WITHDRAWN, not annotated.
            // Omitting the JSON field while leaving the sentence standing MOVES the false all-clear.
            if (!unevaluated.isEmpty())
                System.out.println("candor unverified: no Unknown holes among the rules this report can answer — "
                        + "but " + unevaluated.size() + " rule(s) went unevaluated (above) and `gate --report` "
                        + "refuses over them. NOT an all-clear. " + UNEVALUATED_TAIL_STRICT);
            if (!unanalyzed.isEmpty())
                System.out.println("candor unverified: no Unknown holes among the functions candor could SEE — "
                        + "NOT an all-clear: " + unanalyzed.size() + " unit(s) went unanalyzed (above), and a "
                        + "hole inside one is absent from `functions`, so this verb cannot enumerate it at all.");
            return strict ? 2 : 0;
        }
        int n = holes.size() + unjudged.size();
        System.out.println("candor unverified — " + n + " function(s) are not PROVABLY clean under this policy:\n");
        TreeSet<String> upgrades = new TreeSet<>();
        for (Hole h : holes) {
            String[] ru = Policy.ruleUpgrade(h.rule(), Policy.reasonClassesOf(gi, h.fn().fn()));
            upgrades.add(ru[1]);
            String why = h.fn().unknownWhy().isEmpty() ? "an unresolvable call"
                    : h.fn().unknownWhy().stream().sorted().map(UnknownReason::format).collect(Collectors.joining(", "));
            System.out.println("  `" + h.fn().fn() + "`  (in `" + ru[0] + "`)");
            System.out.println("     is Unknown (" + why + ") — candor can't confirm it's free of the forbidden effect(s);");
            System.out.println("     the Unknown could hide the very effect the rule forbids (e.g. a fn/closure-injected port).");
            System.out.println("     → make it provable:  add  `" + ru[1] + "`");
            System.out.println();
        }
        for (Withheld w : unjudged) {
            System.out.println("  `" + w.fn() + "`  (under `" + w.rule() + "`)");
            System.out.println("     is UNJUDGED — `gate --report` could not evaluate that rule here at all, so");
            System.out.println("     nothing about this function's compliance has been established either way.");
            System.out.println("     → " + w.why());
            System.out.println("     → make the rule answerable HERE:  `" + w.widen() + "`");
            System.out.println();
        }
        if (!holes.isEmpty())
            System.out.println("  The gate PASSES the function(s) above — that part is advisory. To REQUIRE "
                    + "provable purity, add:");
        for (String u : upgrades) System.out.println("      " + u);
        if (!unjudged.isEmpty())
            System.out.println("  The gate does NOT pass the UNJUDGED function(s): it exits 2 over this report. "
                    + "This verb cannot be more certain than the gate it stands beside.");
        // ⟨0.24⟩ …and the list above is a LOWER BOUND when the report is incomplete: an Unknown hole inside
        // an unanalyzed unit is absent from `functions`, so "these are the functions that are not provably
        // clean" is the same over-claim the tick was, in the branch that DID find something.
        if (!unanalyzed.isEmpty())
            System.out.println("  ⚠ NOT the whole list — the report declares " + unanalyzed.size()
                    + " unanalyzed unit(s) (above); a hole inside one is invisible here.");
        // The same tail as the `--json` path, reached by BOTH shapes of the run. A policy that mixes a HOLE
        // (exit 1) with a rule the gate REFUSED (exit 2) is the case where a `return` inside the block above
        // would have given 1 in this channel and 2 in the other, over identical input. The refusal wins: it
        // is the gate's own code, and a rule that was never evaluated is not a crossing anyone can go and fix.
        // An unread FILE ranks with it, for the reason §3.2 gives: neither is a finding anyone can act on.
        if (strict && (!unevaluated.isEmpty() || !unanalyzed.isEmpty())) return 2;
        return strict ? 1 : 0;
    }

    // ── ⟨0.24⟩ `gate --report <locator> --policy <file>` (SPEC §3.1) ────────────────────────────────────

    /**
     * THE THIRD ANSWERABILITY CASE — a class-scoped {@code deny} filter over a report that cannot answer it.
     * Returns the refusal message, or null when every scoped filter is answerable.
     *
     * <p>A bare {@code deny Net} / {@code deny Unknown} asks a question the effect set alone answers. A
     * SCOPED one — {@code deny Net[unknown-host]}, {@code deny Unknown[dispatch]} — asks a second question
     * ("…and is the destination / the reason class one of THESE?") and NARROWS the gate on the answer. When
     * the report does not carry the evidence for that second question, the fields it is read from are
     * simply absent, both matchers see an empty set, no class matches, and the effect is dropped from the
     * violation. <b>The narrowing succeeds because the evidence is missing.</b> That is an absence-keyed
     * relaxation of a fail-closed security gate — the defect class ⟨0.24⟩ exists to remove — and it is
     * silent, because the scoped rule is exactly the one a hardening team reaches for.
     *
     * <p>MEASURED on this engine before this check, one function per row, hand-built reports:
     * <pre>
     *   report                                   deny Net[unknown-host]   deny Net
     *   Net-bearing entry, netClass ABSENT       exit 0  ← green          exit 1
     *   the same entry, netClass PRESENT         exit 1                   exit 1
     *
     *   report                                   deny Unknown[dispatch]   deny Unknown
     *   inherited Unknown, `calls` ABSENT        exit 0  ← green          exit 1
     *   the same pair, `calls` PRESENT           exit 1                   exit 1
     * </pre>
     *
     * <p>Refusing does NOT cost equivalence with {@code scan --policy}, because neither state is reachable
     * in a report this engine wrote:
     * <ul>
     *   <li>{@code netClass} is emitted for EVERY {@code Net}-bearing entry and is never empty — the
     *       derivation adds {@code unknown-host} whenever no host is visible ({@code ReportWriter}), which
     *       is the fail-closed floor. An empty set on a {@code Net}-bearing entry therefore means "this
     *       producer did not carry the field", never "this function reaches nothing".</li>
     *   <li>an {@code Unknown} that is INHERITED comes from a callee that carries {@code Unknown}, so that
     *       callee is effectful and is in {@code calls} by construction; and an {@code Unknown} raised
     *       DIRECTLY records its {@code unknownWhy} at the site (the ⟨0.24⟩ producer-side repair). So an
     *       in-scope {@code Unknown} function with an EMPTY resolved class set cannot arise from a scan —
     *       only from a report that dropped the channel.</li>
     * </ul>
     * The check is per (rule, function, EFFECT) — not per policy and (candor-spec {@code b3748ed}) not per
     * (rule, function) either. A scoped rule whose matched functions all carry their evidence evaluates
     * normally; a rule that names {@code Fs} beside a {@code Net[unknown-host]} it cannot answer FIRES for
     * the {@code Fs} and is withheld only for the {@code Net}. Withholding the pair let one unevidenced
     * effect delete a certain finding standing beside it — see {@link Policy#gate} for the measurement.
     *
     * <p>⟨0.24⟩ Returns EVERY unanswerable rule (one row per rule, the message naming a witness function)
     * rather than the first, because a refusal no longer short-circuits the run: {@link #gate} evaluates
     * the answerable rules first and discloses this whole list whichever way the verdict goes.
     */
    /** ⟨0.24⟩ SPEC §3.1: a refusal writes its {@code --gate-json} document (to BOTH sinks when both were
     *  asked for — {@code --json} is {@code --gate-json -}) and then exits 2. Returning the exit code from
     *  here rather than beside each call keeps "refused" and "wrote the refusal" from ever separating. */
    /** The verdict's sink dedupe — see {@link #refuse}: `--json` IS `--gate-json -`, so naming both
     *  wrote one document twice onto one stream. */
    private static void writeGateVerdictOnce(boolean json, String gateJsonPath, int violations,
                                             Candor.GateFacts facts, List<String[]> unevaluated) {
        java.util.LinkedHashSet<String> sinks = new java.util.LinkedHashSet<>();
        if (json) sinks.add("-");
        if (gateJsonPath != null) sinks.add(gateJsonPath);
        for (String sink : sinks) Candor.writeGateJson(sink, violations, facts, unevaluated);
    }

    private static int refuse(boolean json, String gateJsonPath, String reason, List<String[]> unevaluated) {
        // ONE ARTIFACT, ONE DOCUMENT. §3.1 says `--json` IS `--gate-json -`, so `--json --gate-json -`
        // names the SAME sink twice — and writing both put TWO concatenated JSON objects on one stream,
        // which is unparseable to exactly the machine consumer the "exactly once, as the stream's only
        // content" clause serves. Dedupe by artifact, not by flag.
        java.util.LinkedHashSet<String> sinks = new java.util.LinkedHashSet<>();
        if (json) sinks.add("-");
        if (gateJsonPath != null) sinks.add(gateJsonPath);
        for (String sink : sinks) Candor.writeRefusedGateJson(sink, reason, unevaluated);
        return 2;
    }

    /** ⟨0.24⟩ {@code triples} holds one {@link Policy#unanswerableKey} per (rule, function, EFFECT) the
     *  gate must withhold — never per (rule, function): see {@link Policy#gate}.
     *
     *  <p>{@code functions} is the SAME withholding, listed PER FUNCTION rather than per (rule, cause).
     *  The gate needs the set (to withhold) and the per-cause rows (to disclose); the two advisory verbs
     *  beside it need the per-FUNCTION form, because SPEC §3.2 requires them to NAME the function the gate
     *  could not judge. One producer, three shapes of the one answer — never a second scan of the report. */
    record Unanswerable(List<String[]> disclosures, Set<String> triples, List<Withheld> functions) {}

    /** ⟨0.24⟩ One function the gate could NOT judge, and WHY — {@code why} names the ABSENT FIELD, never
     *  the class that field would have carried. SPEC §3.2: "the reason recorded is the missing evidence,
     *  never the derived class." A derived class here would be the second opinion the law forbids: it is
     *  exactly the value the gate declined to invent. */
    record Withheld(String fn, String rule, String effect, String why, String widen) {}

    static Unanswerable unanswerableScopedFilters(Policy.GateInput gi) {
        List<String[]> out = new ArrayList<>();
        Set<String> triples = new java.util.LinkedHashSet<>();
        List<Withheld> perFn = new ArrayList<>();
        for (PolicyRule.Deny r : AnalysisState.ctx().denyRules) {
            List<String> netless = new ArrayList<>(), reasonless = new ArrayList<>();
            for (var e : new TreeMap<>(gi.inferred()).entrySet()) {
                String fn = e.getKey();
                if (!Policy.scopeMatches(fn, r.scope())) continue;
                List<String> names = e.getValue().toNames();
                // TWO INDEPENDENT CAUSES, TESTED INDEPENDENTLY — `if`, never `else if`. Under the old
                // per-(rule, function) key the two collapsed harmlessly, because either one withheld the
                // whole pair. Per EFFECT they cannot: a `deny Net[…] Unknown[…]` rule over a function that
                // is BOTH netClass-less AND reasonless would, with an `else`, withhold only `Net` and let
                // `Unknown` fire on `reasonClassesOf`'s `unresolved` floor — the exact fabrication the
                // Unknown branch exists to prevent, reintroduced by the granularity fix for its mirror.
                if (!r.netClasses().isEmpty() && names.contains("Net")
                        && gi.netClasses().getOrDefault(fn, List.of()).isEmpty()) {
                    netless.add(fn);
                    triples.add(Policy.unanswerableKey(r, fn, Effect.NET));
                    perFn.add(new Withheld(fn, r.src().trim(), "Net", withheldWhy(r, fn, "Net",
                            "`netClass`", "the Net destination class"), widen(r, "Net")));
                }
                if (!r.unknownClasses().isEmpty() && names.contains("Unknown")
                        && gi.reasonClasses().getOrDefault(fn, new TreeSet<>()).isEmpty()) {
                    reasonless.add(fn);
                    triples.add(Policy.unanswerableKey(r, fn, Effect.UNKNOWN));
                    perFn.add(new Withheld(fn, r.src().trim(), "Unknown", withheldWhy(r, fn, "Unknown",
                            "`unknownWhy` (its own, or one reachable over `calls`)", "the Unknown reason class"),
                            widen(r, "Unknown")));
                }
            }
            // One disclosure row per (rule, cause), naming EVERY function it withheld — not just the first.
            // A message that named one witness while silently withholding forty would be the deleted
            // disclosure one level down, on exactly the exit-1 path §3.1 now routes these through.
            if (!netless.isEmpty())
                out.add(new String[]{r.src().trim(),
                        "`" + r.src().trim() + "` narrows on the Net DESTINATION CLASS, but " + names(netless)
                        + " carr" + (netless.size() == 1 ? "ies" : "y") + " Net with no `netClass` in this "
                        + "report — the field the filter reads is absent, so the narrowing would succeed for "
                        + "lack of evidence and drop a Net the bare `deny Net` catches. The rule's Net PART "
                        + "is NOT EVALUATED for those functions rather than passed: an absent optional field "
                        + "must not relax a fail-closed gate. Any OTHER effect this rule names is decided on "
                        + "its own evidence and still fires. Use the bare `deny Net`, or gate at scan time."});
            if (!reasonless.isEmpty())
                out.add(new String[]{r.src().trim(),
                        "`" + r.src().trim() + "` narrows on the Unknown REASON CLASS, but " + names(reasonless)
                        + " carr" + (reasonless.size() == 1 ? "ies" : "y") + " Unknown with no reason "
                        + "reachable in this report — neither its own `unknownWhy` nor a `calls` edge to one. "
                        + "§6.2 requires the class set to resolve TRANSITIVELY over the gate's reach; with the "
                        + "channel missing, every narrowed filter silently tolerates while only the bare "
                        + "`deny Unknown` fires. The rule's Unknown PART is NOT EVALUATED for those "
                        + "functions; any other effect it names is decided on its own evidence and still "
                        + "fires. Use the bare `deny Unknown`, or gate at scan time."});
        }
        return new Unanswerable(out, triples, perFn);
    }

    /** ⟨0.24⟩ SPEC §3.2 — the per-function reason: WHICH FIELD WAS ABSENT, and that the gate WITHHELD
     *  rather than passed. Deliberately says nothing about which class the fn would have been in: that
     *  value is precisely the one the gate declined to invent, and repeating a derivation of it beside a
     *  refusal is the second opinion §3.2 rules out. */
    /** ⟨0.24⟩ The rule REWRITTEN so this report can answer it: the bare, unnarrowed form. It is what the
     *  gate's own refusal already recommends ("Use the bare `deny Net`, or gate at scan time"), and it is
     *  the only edit that turns a refusal into a verdict without inventing the missing datum — the narrowed
     *  rule cannot be evaluated here at ALL, so there is no narrower ask to offer. */
    private static String widen(PolicyRule.Deny r, String effect) {
        return ("deny " + effect + " " + r.scope()).trim();
    }

    private static String withheldWhy(PolicyRule.Deny r, String fn, String effect, String field, String what) {
        return "`gate --report` could NOT evaluate `" + r.src().trim() + "` at `" + fn + "`: the rule narrows "
                + "on " + what + ", and this entry carries " + effect + " with no " + field + " in this report. "
                + "The rule's " + effect + " part is WITHHELD there, not passed — so this function is "
                + "UNJUDGED, and any verdict about it from this verb would be more confident than the gate's "
                + "over identical bytes. Use the bare `deny " + effect + "`, or gate at scan time.";
    }

    /**
     * ⟨0.24⟩ THE RULE KINDS {@code gate --report} CANNOT EVALUATE AT ALL over a report, whatever the report
     * says — {@code forbid} (needs the FULL call graph) and {@code allow} (needs the AS-EFF-008
     * surface-completeness marker, which does not ride the wire). One {@code {rule, why}} row per rule, the
     * raw policy line verbatim; see {@link #gate} for why the shape is per-RULE and not a kind aggregate.
     *
     * <p><b>Hoisted here because SPEC §3.2 makes it three consumers, not one.</b> An advisory verb that
     * answers over a policy whose {@code allow} rules the gate REFUSED is more confident than the gate over
     * identical bytes — the same law, one rule-kind over from the per-function case. {@code unverified} and
     * {@code fix-gate} evaluate neither kind, so they cannot name a function for these; what they can do,
     * and now do, is carry the rows and decline to claim a clean bill beside them. NON-DESTRUCTIVE: the
     * caller decides whether to clear the rules from the context, and only the gate has reason to.
     */
    static List<String[]> policyKindUnevaluated(String policyPath) {
        List<String[]> out = new ArrayList<>();
        for (PolicyRule.Forbid f : AnalysisState.ctx().forbidRules)
            out.add(new String[]{f.src().trim(),
                    "`" + f.src().trim() + "` is a `forbid` rule, which `gate --report` cannot evaluate — "
                    + "a report's `calls` graph is EFFECT-RELEVANT, so a crossing into a wholly pure unit "
                    + "is invisible in it and the rule would read green where a scan fails. Gate layering "
                    + "at scan time: candor <classes> --policy " + policyPath});
        for (PolicyRule.Allow a : AnalysisState.ctx().allowRules)
            out.add(new String[]{a.src().trim(),
                    "`" + a.src().trim() + "` is an `allow` rule, which `gate --report` cannot evaluate — "
                    + "the AS-EFF-008 surface-completeness marker does not ride the report wire, so a "
                    + "benign visible literal beside a runtime-computed endpoint would be CERTIFIED here "
                    + "and flagged by a scan. (`netClass: unknown-host` is NOT that marker — it also names "
                    + "a merely unrecognised host.) Gate allowlists at scan time: candor <classes> "
                    + "--policy " + policyPath});
        return out;
    }

    /** `a`, `a` and `b`, `a`, `b` and `c` — the withheld functions, all of them, in report order. */
    private static String names(List<String> fns) {
        List<String> q = fns.stream().map(f -> "`" + f + "`").collect(Collectors.toList());
        if (q.size() == 1) return q.get(0);
        return String.join(", ", q.subList(0, q.size() - 1)) + " and " + q.get(q.size() - 1);
    }

    /** The §2 ENVELOPE facts the gate verdict needs, none of which survive {@link #load} (which returns
     *  only the {@code functions} array): the ⟨0.21⟩ completeness manifest, the ⟨0.15⟩ κ-coverage ledger,
     *  and the RAW {@code unknownWhy} strings (see {@link Policy#gateInputFromReport}). Read from the SAME
     *  file, in one pass — no sidecar, no second locator. */
    /** @param judgedNothing ⟨0.24⟩ SPEC §2 — does this report say it JUDGED NOTHING (`analyzed.count: 0`)?
     *      Decided by {@link Loader#claimsToHaveJudgedNothing}, the SHARED predicate the chained-dep join
     *      already uses, so a report cannot be judged-nothing on one route and not on another. It is NOT
     *      `analyzedCount() == 0`, which this verb's gate route used to ask inline and which gets the
     *      manifest-ABSENT row wrong: a legacy bare-array report has no `analyzed` key, reads back as 0
     *      here, and would be called judged-nothing while LISTING functions it demonstrably judged
     *      (⟨0.24⟩ row 3 — absent manifest ⇒ judged-nothing iff `functions` is empty). */
    record Envelope(int analyzedCount, List<String[]> unanalyzed, List<Map.Entry<String, Integer>> uncovered,
                    Map<String, List<String>> rawUnknownWhy, String packageName, boolean judgedNothing) {}

    static Envelope readEnvelope(String path) throws Exception {
        JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
        Map<String, List<String>> raw = new HashMap<>();
        List<String[]> unanalyzed = new ArrayList<>();
        List<Map.Entry<String, Integer>> uncovered = new ArrayList<>();
        int analyzed = 0;
        String pkg = null;                 // §2 `package`/`packages` — for the judged-nothing advisory
        JsonArray fns = null;
        JsonObject envObj = null;          // the §2 envelope, or null for the legacy v0.1 bare array
        if (root.isJsonObject()) {
            JsonObject o = root.getAsJsonObject();
            envObj = o;
            if (o.has("package") && o.get("package").isJsonPrimitive())
                pkg = o.get("package").getAsString();
            else if (o.has("packages") && o.get("packages").isJsonArray()) {
                List<String> ps = new ArrayList<>();
                for (JsonElement e : o.getAsJsonArray("packages"))
                    if (e.isJsonPrimitive()) ps.add(e.getAsString());
                if (!ps.isEmpty()) pkg = String.join("+", ps);
            }
            if (o.has("analyzed") && o.get("analyzed").isJsonObject()) {
                JsonObject a = o.getAsJsonObject("analyzed");
                if (a.has("count") && a.get("count").isJsonPrimitive()) analyzed = a.get("count").getAsInt();
            }
            // PRESENT BUT UNREADABLE IS NOT ABSENT — SPEC §2 ⟨0.24⟩'s signature-key rule: "SIGNATURE keys
            // — `functions`, `inferred`, `direct`, `unknownWhy`, `netClass`, `analyzed`, `unanalyzed` —
            // carry the claim. One unreadable among them means the document's claim cannot be trusted,
            // whatever this particular policy happens to ask. Refuse."
            //
            // This read was `has(…) && isJsonArray()`, so a present-but-non-array `unanalyzed` failed the
            // condition and was SILENTLY SKIPPED — the manifest whose whole job is to say "there is code I
            // could not analyze" was read as "there is none". MEASURED against the other three engines,
            // on a report whose `unanalyzed` is a string and which has nothing else to report:
            //
            //     rust exit 2    ts exit 2    swift exit 2       java exit 0   <- trusted it
            //
            // Throwing routes it to the caller's existing `refuse(…)`, which is the §3.1 refusal shape the
            // other three already emit. ABSENT STAYS ABSENT: a report with no `unanalyzed` key is a
            // complete scan (or a pre-⟨0.21⟩ producer) and is untouched — the distinction this turns on is
            // present-and-garbled, never missing.
            if (o.has("unanalyzed") && !o.get("unanalyzed").isJsonArray())
                throw new IllegalStateException(
                        "`unanalyzed` is present but is not an array — a SIGNATURE key that cannot be read "
                        + "impeaches the whole document (§2), so this gate cannot certify it");
            if (o.has("unanalyzed") && o.get("unanalyzed").isJsonArray())
                for (JsonElement e : o.getAsJsonArray("unanalyzed"))
                    if (e.isJsonObject()) {
                        JsonObject u = e.getAsJsonObject();
                        unanalyzed.add(new String[]{
                                u.has("path") ? u.get("path").getAsString() : "",
                                u.has("reason") ? u.get("reason").getAsString() : ""});
                    }
            if (o.has("coverage") && o.get("coverage").isJsonObject()) {
                JsonObject c = o.getAsJsonObject("coverage");
                if (c.has("uncovered") && c.get("uncovered").isJsonArray())
                    for (JsonElement e : c.getAsJsonArray("uncovered"))
                        if (e.isJsonObject()) {
                            JsonObject u = e.getAsJsonObject();
                            uncovered.add(Map.entry(u.has("name") ? u.get("name").getAsString() : "?",
                                    u.has("calls") ? u.get("calls").getAsInt() : 0));
                        }
            }
            if (o.has("functions") && o.get("functions").isJsonArray()) fns = o.getAsJsonArray("functions");
        } else if (root.isJsonArray()) {
            fns = root.getAsJsonArray();   // the legacy v0.1 bare array — no envelope facts to read
        }
        if (fns != null)
            for (JsonElement e : fns) {
                if (!e.isJsonObject()) continue;
                JsonObject o = e.getAsJsonObject();
                if (!o.has("fn") || !o.get("fn").isJsonPrimitive()) continue;
                if (!o.has("unknownWhy") || !o.get("unknownWhy").isJsonArray()) continue;
                List<String> ws = new ArrayList<>();
                for (JsonElement w : o.getAsJsonArray("unknownWhy"))
                    if (w.isJsonPrimitive()) ws.add(w.getAsString());
                if (!ws.isEmpty()) raw.put(o.get("fn").getAsString(), ws);
            }
        return new Envelope(analyzed, unanalyzed, uncovered, raw, pkg,
                Loader.claimsToHaveJudgedNothing(envObj, fns));
    }

    /**
     * ⟨0.24⟩ {@code gate --report <locator> --policy <file>} — apply a policy to an EXISTING report, with no
     * scan (SPEC §3.1). Exit codes and verdict shape are exactly {@code scan --policy}'s; the only
     * difference is where {@code S} and {@code D} come from.
     *
     * <p><b>Why it is a MUST and not a convenience.</b> {@code scan --policy} recomputes {@code S} from
     * source, so the classifier is always in the loop; {@code whatif} reports only what a hypothetical
     * INTRODUCES (a report already carrying {@code Net} under {@code deny Net} answers {@code ok: true}, by
     * design). The gate was therefore never reachable as a function of a GIVEN signature, and a defect in
     * the gate was indistinguishable from a defect in the classifier by any test that could be written.
     * With this verb, conformance can hand the engine a signature {@code reference/policy_model.py} has
     * already judged and compare verdicts directly.
     *
     * <p><b>It reads the report file and nothing else.</b> No callgraph sidecar, no chained dep, no
     * hierarchy sidecar, no re-classification — see {@link Policy#gateInputFromReport}, which is where that
     * is enforced and argued. An ABSENT entry is absent: the ⟨0.21⟩ purity claim, taken as given.
     *
     * <p><b>ANSWERABILITY (the refusals below).</b> Two §6.2 rule kinds need evidence the ⟨0.24⟩ wire
     * format does not carry, so this verb REFUSES them (exit 2) rather than evaluating them on partial
     * evidence — which would be the gateless-green failure the gate exists to prevent, in the fail-OPEN
     * direction, on a policy the user believed was enforced:
     * <ul>
     *   <li>{@code forbid A -> B} needs the FULL call graph. A report's {@code calls} is EFFECT-RELEVANT
     *       (ReportWriter keeps only callees with a non-empty effect set), which is complete for any
     *       crossing into an EFFECTFUL unit — effects propagate, so every intermediate on such a path is
     *       itself effectful and present — but blind to a crossing into a wholly PURE unit, and
     *       {@code forbid} matches on NAME, not on effect. So {@code forbid domain -> infra} would pass on
     *       a report where the scan fails.</li>
     *   <li>{@code allow <E> …} (ANY effect) needs the AS-EFF-008 surface-completeness marker, and the
     *       ⟨0.24⟩ wire does not carry it in any form. Without it a function with one visible {@code git}
     *       literal AND one runtime-computed command is CERTIFIED by {@code allow Exec git} while the scan
     *       flags it — fail-open, on the rule whose entire job is to stop a benign literal from masking an
     *       invisible endpoint. {@code netClass: unknown-host} looks like the marker for {@code Net} and is
     *       NOT: {@code Literals.netDestClass} returns it for any UNRECOGNISED host too, so reading it as
     *       "masked" flags functions whose surface is fully visible (measured — it flagged 2 the scan
     *       passes, before this refusal replaced it).</li>
     * </ul>
     * Both refusals name what a future format rung would have to add — a per-function
     * {@code surfaceIncomplete} field, and a call graph that is not effect-filtered. The point of stating
     * them as refusals rather than as caveats is that everything this verb DOES accept — {@code deny} and
     * {@code pure}, which is exactly the {@code (S, D)} gate §3.1 ⟨0.24⟩ frames the verb around — is
     * verdict-equivalent to {@code scan --policy}, and that is a property a test can hold it to.
     *
     * <p><b>⟨0.24⟩ IT GATES THE WHOLE REPORT SET A LOCATOR NAMES, not one file of it.</b> §2: reports under
     * one prefix are "a single analysis world". {@link #expandPrefix} — the engine-wide resolver every
     * other verb uses — picks the lexicographically-first match and discloses the choice on stderr. On a
     * prose verb that is a narrowing the reader is told about; here the output is a MACHINE verdict, and a
     * violating sibling that the locator NAMED and the verb never opened comes back `ok: true`, exit 0,
     * over an `analyzed.count` that silently excludes it. Measured on a two-report prefix whose violation
     * sat in the second file: exit 0 / analyzed 3 / 0 violations, where candor-rust and candor-ts both gave
     * exit 1 / analyzed 4 / 1 violation. So this verb resolves the locator to the SET
     * ({@link #locatorReportSet}) and unions it: `analyzed.count` SUMS, `unanalyzed` and the κ ledger
     * concatenate, and the entries join in {@link Policy#gateInputFromReport}, which already merges a
     * repeated `fn` by UNION — the direction that cannot turn a violation into a pass (§2's "join across
     * reports by `hash`, never by bare `fn`" hazard, resolved in the safe direction rather than by dropping
     * a colliding entry). A locator naming ONE report is byte-identical to before.
     *
     * <p>Scoped to this verb DELIBERATELY. The read-only verbs derive per-report SIDECARS from the resolved
     * path — {@code callers}/{@code tour}/{@code whatif}/{@code fix} all call {@link #loadCallgraph} —
     * so unioning their ENTRIES while leaving the graph anchored on one report would answer "no callers"
     * for every sibling's function: a silent under-report introduced by the repair. They keep the
     * single-report reading and its stderr disclosure until the sidecars travel with it.
     *
     * @param surplus a stray positional — {@code gate} takes none (a usage error, never ignored)
     */
    static int gate(List<String> reportPaths, String surplus, String policyPath,
                    boolean json, String gateJsonPath) {
        // ⟨0.24⟩ Every `return 2` below that is a REFUSAL — the gate declining to give a verdict — writes
        // its refusal DOCUMENT first (SPEC §3.1: a refusal that writes nothing leaves a CI wrapper reading
        // the previous run's green file as current). A USAGE error is deliberately not one of them: the
        // command was never a gate invocation, so there is nothing to refuse, and writing a verdict for a
        // typo'd flag would put a document where the operator's own shell already failed.
        if (surplus != null) {
            System.err.println("candor gate: unexpected argument `" + surplus + "` (usage: candor gate "
                    + "--report <locator> --policy <file> [--json] [--gate-json <file>])");
            return 2;
        }
        if (policyPath == null) policyPath = resolvePolicyFallback();
        if (policyPath == null) {
            System.err.println("candor gate: a policy is required — pass `--policy <file>` or set CANDOR_POLICY. "
                    + "`gate` applies a policy to an existing report; with no policy there is no verdict to give.");
            return 2;
        }
        AnalysisState.ctx().denyRules.clear();
        AnalysisState.ctx().allowRules.clear();
        AnalysisState.ctx().forbidRules.clear();
        // ⟨0.19⟩ `unknown-alias` expansion for an `Unknown[<alias>]` filter. Anchored to the POLICY file, as
        // `parsepolicy` anchors it — an alias is part of the policy's own vocabulary, not of the report. The
        // ⟨0.20⟩ `net-partner` list is deliberately NOT loaded: `netClass` is read verbatim from the report,
        // so re-classifying its hosts through THIS machine's config would be exactly the re-derivation the
        // §3.1 ⟨0.24⟩ MUST NOT forbids (and would make the verdict depend on the consumer's CWD).
        // ⟨0.24⟩ `Config.policyVocabulary` IS this anchor, named — and the SCAN route now calls the same
        // method for the same reason, so the two routes cannot expand a rule differently (SPEC §3.1).
        Config vocab = Config.policyVocabulary(Path.of(policyPath));
        // ⟨0.28⟩ THE `engine` PIN IS DISCLOSED HERE, NEVER ENFORCED. `gate` applies a policy to a report
        // SOMEONE ELSE PRODUCED — possibly another engine entirely — so refusing because THIS build is
        // not the pinned one would fail a perfectly valid evaluation, and §3.4 scopes the pin to a
        // producer that ANALYSES code. But silence is not right either: policy SEMANTICS move with engine
        // versions (⟨0.24⟩ was the first rung that could turn a green gate red), so a verdict computed by
        // an unpinned build is one the operator should be told about before trusting it. Same posture as
        // the UNDETERMINED pin on the scan route — say it once, change nothing. Raised by review, which
        // argued the gate is the enforcement surface and deserved more than the silence it had.
        String gatePin = vocab.enginePinForThisEngine();
        if (Config.pinVerdict(gatePin, ReportWriter.release()) == Config.PinVerdict.MISMATCH) {
            System.err.println("candor gate: " + (vocab.source() != null ? vocab.source() : ".candor/config")
                    + " pins engine " + gatePin + " and this is candor-java " + ReportWriter.release()
                    + ". The verdict stands — `gate` evaluates a report it did not produce — but the policy"
                    + " semantics applied are this build's, not the pinned build's.");
        }
        AnalysisState.ctx().unknownAliases.putAll(vocab.unknownAliases());
        AnalysisState.ctx().vocabularySource = !vocab.unknownAliases().isEmpty() && vocab.source() != null
                ? vocab.source().toString() : null;
        if (!Policy.parsePolicy(policyPath)) {
            String why = Policy.policyFailure(policyPath);
            System.err.println("candor gate: " + why);
            // ⟨0.24⟩ the refusal names EVERY rule it left unevaluated, not just the offending one — the
            // same rows, from the same helper, the SCAN route's refusal carries, so the two routes'
            // refusal documents cannot drift (SPEC §3.1's byte-equality MUST).
            return refuse(json, gateJsonPath, why, Policy.unhonouredRules(policyPath));
        }
        // ⟨0.28⟩ SPEC §6.2 — a CONFIGURED policy that yielded ZERO RULES refuses exactly as an unreadable
        // one does, and THIS ROUTE GETS IT TOO: the clause was measured on `gate --report` as well as on
        // the scan, and a route is not covered by its sibling. Same words, same whole-policy `unevaluated`
        // row, same sink handling as the branch directly above, so the two routes' refusal documents
        // cannot drift (§3.1's byte-equality MUST). Placed BEFORE the `forbid`/`allow` rules are removed
        // from the evaluation below — an allow-only policy is an ordinary gate and must NOT refuse here.
        if (Policy.policyYieldedNoRules()) {
            String why = Policy.zeroRulePolicyFailure(policyPath);
            System.err.println("candor gate: " + why);
            return refuse(json, gateJsonPath, why, Policy.zeroRuleUnevaluated(policyPath));
        }
        // ⟨0.24⟩ THE ANSWERABILITY REFUSALS ARE COLLECTED, NOT RETURNED ON — SPEC §3.1's corrected
        // precedence is **violation (1) > refusal (2) > incomplete (2)**. If some other rule FIRES on
        // evidence this report carries, the policy is REJECTED, and because `Reject` is upward-closed
        // (PAPER3 Lemma 2) however the unanswerable rule would have resolved cannot un-reject it: exit 1
        // is CERTAIN there, and strictly more informative than exit 2 because it names the violation.
        //
        // MEASURED on this engine before the repair, one hand-built report carrying an `Fs` unit and an
        // `Unknown` unit with no reason: `deny Fs app` alone → exit 1 + a verdict document naming the
        // violation; `deny Fs app` PLUS `deny Unknown[dispatch] app` → exit 2 and NO document at all. The
        // certain violation was deleted from the machine-consumer channel by the refusal standing beside
        // it — the same harm as an incomplete-analysis path that writes nothing.
        //
        // The refused rules are REMOVED from the evaluation (`forbid`/`allow` whole-policy, per §3.1's
        // granularity rule) rather than approximated: dropping a rule can only REMOVE violations, so a
        // surviving exit 1 stays certain. They are disclosed either way — exit 1 reports the violation it
        // is sure of, it does not conceal the part it could not read.
        //
        // ⟨0.24⟩ ONE ROW PER RULE, THE RAW POLICY LINE VERBATIM (SPEC §3.1's pinned shape). These two used
        // to be KIND AGGREGATES — `"forbid (× 2)"`, `"allow Fs/Net"` — which satisfies a naive reading of
        // "disclose which rules could not be evaluated" while answering a different question: how many, not
        // which. Two distinct `forbid` lines collapsed into one entry and the operator could not tell from
        // the document which of their boundaries had gone unchecked. The scoped-filter disclosures below
        // already emitted `r.src()`, so this is the shape the rest of the list was already in.
        List<String[]> unevaluated = new ArrayList<>(policyKindUnevaluated(policyPath));
        // The rules are REMOVED from the evaluation once disclosed — whole-policy, per §3.1's granularity
        // rule. Only the gate does this; the advisory verbs read the same list without mutating the context,
        // because they never evaluate a `forbid`/`allow` rule in the first place.
        AnalysisState.ctx().forbidRules.clear();
        AnalysisState.ctx().allowRules.clear();

        // Load EVERY report the locator named, and refuse the whole run if ANY of them fails to load.
        // §3.1: "a report that cannot be parsed is corrupt input, not an effect-free package … A located
        // report that yields no trustworthy functions MUST fail loudly." Over a SET that has to mean the
        // set: a half-written sibling is exactly the file that would have carried the violation, and
        // gating over its readable neighbours would publish a green verdict whose only evidence is which
        // file the writer happened to finish.
        List<Effector> fns = new ArrayList<>();
        int analyzedCount = 0;
        List<String[]> unanalyzed = new ArrayList<>();
        List<Map.Entry<String, Integer>> uncovered = new ArrayList<>();
        Map<String, List<String>> rawWhy = new HashMap<>();
        List<String> judgedNothing = new ArrayList<>();
        for (String reportPath : reportPaths) {
            Envelope env;
            try {
                fns.addAll(load(reportPath));
                env = readEnvelope(reportPath);
            } catch (Exception e) {
                String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                String msg = "cannot read report " + reportPath + " (" + why + ")"
                        + (reportPaths.size() > 1 ? " — refusing to gate over a report set one of whose "
                        + reportPaths.size() + " reports did not load; a green verdict would rest on which "
                        + "files happened to be readable" : "");
                System.err.println("candor gate: " + msg);
                return refuse(json, gateJsonPath, msg, List.of());
            }
            analyzedCount += env.analyzedCount();
            unanalyzed.addAll(env.unanalyzed());
            uncovered.addAll(env.uncovered());
            // A repeated `fn` across reports joins by UNION here too — same direction as the entry join.
            for (var e : env.rawUnknownWhy().entrySet())
                rawWhy.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).addAll(e.getValue());
            // ⟨0.28⟩ Via {@link Envelope#judgedNothing} — the SHARED predicate — and no longer the inline
            // `analyzedCount() == 0` this line used to ask. The descriptive verbs now read the same row
            // (see {@link #reportCompleteness}); two spellings of "judged nothing" in one file is exactly
            // how a report comes to be judged-nothing on one route and not on the other.
            if (env.judgedNothing())
                judgedNothing.add(judgedNothingLabel(env, reportPath));
        }
        if (reportPaths.size() > 1)
            System.err.println("candor gate: locator names " + reportPaths.size()
                    + " reports — gating over all of them as one analysis world (§2): "
                    + String.join(", ", reportPaths));
        Policy.GateInput gi = Policy.gateInputFromReport(fns, rawWhy);

        // THE THIRD ANSWERABILITY CASE, and the only one that depends on the REPORT rather than the policy
        // alone. See #unanswerableScopedFilters — a class-scoped `deny` NARROWS the gate, and a narrowing is
        // sound only where the report can answer the narrowing question. Collected, not returned on: the
        // rule STAYS in the evaluation (unlike `forbid`/`allow`, whose granularity §3.1 makes whole-policy),
        // because the same rule may fire on a sibling function that DOES carry its evidence — and a rule
        // that fires is answered, not refused. ⟨0.24⟩ …and it may fire for one of its OWN EFFECTS on the
        // very function it is withheld for on another, which is why the withhold set is keyed on
        // (rule, function, effect). The withheld triples are disclosed below whichever way the verdict
        // goes, so nothing tolerated is silent.
        Unanswerable scoped = unanswerableScopedFilters(gi);
        unevaluated.addAll(scoped.disclosures());

        // Route the gate's HUMAN output exactly as a scan does: to stderr whenever stdout carries the
        // verdict document, so `candor gate … --json | jq` sees pure JSON.
        // `human` is the stream EVERY line of prose uses — the AS-EFF diagnostics AND the trailer. Reading
        // `Candor.diagOut` back for the trailer, after the finally-block restore below, put that line on
        // stdout and corrupted the verdict document `--json` had just written there. Caught by piping the
        // real CLI into a JSON parser; the identical class the scan path fixed for `--gate-json -`.
        java.io.PrintStream human = (json || "-".equals(gateJsonPath)) ? System.err : System.out;
        java.io.PrintStream prior = Candor.diagOut;
        Candor.diagOut = human;
        Candor.gateCapture = true;
        Candor.gateViolations.clear();
        Candor.gateZeroMatch.clear();
        int violations;
        try {
            violations = Policy.gate(gi, scoped.triples());
        } finally {
            Candor.diagOut = prior;
        }
        // A REFUSAL is not "no violations": with every unanswerable rule withheld from the evaluation, a
        // zero here means "nothing the gate COULD read fired", which is not a clean bill. Say the refusal
        // instead (below) rather than a green line the operator will read as the verdict.
        if (violations == 0 && unevaluated.isEmpty()) human.println("candor-java: no violations");
        else if (violations > 0) human.println("→ candor fix-gate names the remedy for each");

        // ⟨0.24⟩ A REPORT THAT JUDGED NOTHING LICENSES NO PURITY CLAIM — SPEC §2/§3.1. `analyzed.count: 0`
        // says the producer analysed no units at all, so this verb's `no violations` is a statement about
        // an empty set and NOT about the package. It must be SAID.
        //
        // As a DISCLOSURE, and only that: the exit code and the verdict document are untouched. §3.1's
        // byte-equality MUST binds the gate route to `scan --policy`, and a scan of an empty facade package
        // exits 0 with a clean verdict — so refusing here would break byte-equality on the very reports
        // (~7-10% of real dependency reports, measured) it is trying to protect, and §3.3 enumerates
        // exactly two exit-2 causes, neither of which is a judged-nothing DEPENDENCY. Manufacturing a
        // violation instead would assert an effect the consumer has no evidence for. The harm this clause
        // names is the DELETED DISCLOSURE, so the repair is the disclosure. (This engine printed
        // `candor-java: no violations` with ZERO bytes on stderr; candor-ts is the model.)
        //
        // System.err explicitly, never `human`: with `--json`/`--gate-json -` the human stream IS stderr,
        // but without them it is STDOUT, and putting an advisory there would corrupt a verdict document a
        // consumer is piping.
        if (!judgedNothing.isEmpty())
            System.err.println("candor gate: NOTE — " + judgedNothing.size() + " of the "
                    + reportPaths.size() + " report(s) gated declare `analyzed.count: 0`, i.e. they JUDGED "
                    + "NOTHING: " + String.join(", ", judgedNothing) + ". A verdict over them is a statement "
                    + "about an empty set, not a purity claim about the package — nothing here was checked. "
                    + "(Advisory: the exit code and the verdict document are unchanged; re-run the producing "
                    + "scan over the package's own sources if you meant to gate it.)");

        // ⟨0.24⟩ THE DISCLOSURE THE PRECEDENCE RULE OWES. Whatever the verdict, every rule this run could
        // not evaluate is named — on stderr for the operator, and (below) in the verdict document for the
        // machine consumer, because a violation list that silently omits a rule's tolerated functions is
        // the same deleted-disclosure defect one level down.
        for (String[] u : unevaluated) System.err.println("candor gate: " + u[1]);

        var facts = new Candor.GateFacts(analyzedCount, unanalyzed, uncovered);
        // `--json` IS `--gate-json -`: the verb's machine output is the gate verdict, the same document and
        // the same builder the scan writes, so a consumer cannot tell the two routes apart from the output.
        if (violations > 0) {
            // VIOLATION DOMINATES REFUSAL (§3.1 ⟨0.24⟩). Certain by Lemma 2: the rules withheld above could
            // only have ADDED violations, so exit 1 is not a guess and the document must carry it.
            if (!unevaluated.isEmpty())
                System.err.println("candor gate: exiting 1 on the violation(s) above — a rule that FIRED on "
                        + "evidence this report carries REJECTS the policy, and `Reject` is upward-closed "
                        + "(PAPER3 Lemma 2), so however the " + unevaluated.size() + " unevaluated rule(s) "
                        + "would have resolved cannot un-reject it. The verdict document names them under "
                        + "`unevaluated`.");
            writeGateVerdictOnce(json, gateJsonPath, violations, facts, unevaluated);
            return 1;
        }
        // No rule fired. NOW the refusal is the answer — the gate could not be evaluated as written, and
        // there is no certain verdict standing above it.
        if (!unevaluated.isEmpty())
            return refuse(json, gateJsonPath, unevaluated.size()
                    + " policy rule(s) could not be evaluated against this report", unevaluated);
        writeGateVerdictOnce(json, gateJsonPath, violations, facts, unevaluated);
        // ⟨0.21⟩ COMPLETENESS MANIFEST: a gate cannot be green over code candor never analyzed. The scan
        // path exits 2 on its own `unanalyzed`; here the same manifest travels ON the report, so the same
        // verdict follows from it. A real violation (exit 1, above) dominates, as it does there.
        if (!unanalyzed.isEmpty()) {
            System.err.println("candor gate: NOT certified — the report declares " + unanalyzed.size()
                    + " unit(s) candor could not analyze; a gate cannot be green over unanalyzed code");
            return 2;
        }
        return 0;
    }

    /** rewire <cur-report> <baseline-report> — the de-wiring detector (mirrors candor-query). Diffs the
     *  two call-graph sidecars and flags edges a method DROPPED (a call it made in the baseline and no
     *  longer makes). The effect gate checks effect BOUNDARIES, not correctness, so it can be satisfied by
     *  *disconnecting* functionality (a method stops calling the chain that performs the forbidden effect —
     *  gate passes, feature broken). That removal is invisible to the effect diff but it's in the call
     *  graph. Run alongside `policy`: a green gate PLUS a clean rewire = boundary respected, feature intact. */
    static int rewire(String curReport, String baseReport, boolean json) {
        if (baseReport == null) return usage("rewire <cur-report.json> <baseline-report.json> [--json]");
        Map<String, List<String>> cur = loadCallgraph(curReport);
        Map<String, List<String>> base = loadCallgraph(baseReport);
        if (base == null || base.isEmpty()) {
            System.out.println("candor: no baseline call graph beside " + baseReport + " (need its .callgraph.json).");
            return 2;
        }
        // The CURRENT side must be guarded too: a missing/typo'd current sidecar previously loaded as an
        // empty graph, reporting EVERY baseline edge as "dropped" (a wall of false de-wiring, exit 1) —
        // a CI alarm on a path typo. Fail loud instead, matching the baseline-side and diff/whatif checks.
        // (/code-review found this asymmetry in both engines.)
        if (cur == null || cur.isEmpty()) {
            System.out.println("candor: no current call graph beside " + curReport + " (need its .callgraph.json).");
            return 2;
        }
        TreeMap<String, List<String>> dropped = new TreeMap<>();
        for (var e : base.entrySet()) {
            Set<String> now = new HashSet<>(cur.getOrDefault(e.getKey(), List.of()));
            List<String> gone = e.getValue().stream().filter(c -> !now.contains(c)).collect(Collectors.toList());
            if (!gone.isEmpty()) dropped.put(e.getKey(), gone);
        }
        if (json) {
            List<Map<String, Object>> ds = new ArrayList<>();
            // LinkedHashMap, not `Map.of` — the containment fix's reasoning applies row by row: a two-pair
            // `Map.of` is a salted MapN, so these rows' key order flipped between JVM launches of the same
            // build. caller-then-callees, the order the human arm below prints them in.
            for (var e : dropped.entrySet()) {
                var row = new LinkedHashMap<String, Object>();
                row.put("caller", e.getKey());
                row.put("no_longer_calls", e.getValue());
                ds.add(row);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("dropped", ds);
            out.put("ok", dropped.isEmpty());
            emit(out);
            return dropped.isEmpty() ? 0 : 1;
        }
        if (dropped.isEmpty()) {
            System.out.println("  no call edges dropped vs the baseline — nothing de-wired.");
            return 0;
        }
        System.out.println("  " + dropped.size() + " method(s) DROPPED a call they made in the baseline — a "
                + "'fix' may have disconnected functionality (the effect gate can pass while the feature is "
                + "broken; verify it still works):");
        for (var e : dropped.entrySet())
            System.out.println("      " + e.getKey() + "  ⊘  no longer calls: " + String.join(", ", e.getValue()));
        return 1;
    }

    /** A class -> effects overview of the whole report, most-effectful first. */
    static int map(List<Effector> fns, boolean json, ReportRef ref) {
        Map<String, TreeSet<String>> mods = new HashMap<>();
        Map<String, Integer> counts = new HashMap<>();
        for (Effector f : fns) {
            int dot = f.fn().lastIndexOf('.');
            String mod = dot > 0 ? f.fn().substring(0, dot) : f.fn(); // declaring class
            mods.computeIfAbsent(mod, k -> new TreeSet<>())
                    .addAll(f.inferred().without(Effect.UNKNOWN).toNames());
            counts.merge(mod, 1, Integer::sum);
        }
        // ⟨0.28⟩ `map` answers `{}`, which SPEC §2 makes the strongest determined negative there is: every
        // key a consumer reads defaults to empty, so `doc.get("app.Db", {})` cannot tell an empty overview
        // from an unexamined one.
        ReportCompleteness comp = ref.completeness("map");
        if (json) {
            Map<String, Object> out = new TreeMap<>();
            for (var m : mods.keySet()) {
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("effects", new ArrayList<>(mods.get(m)));
                v.put("functions", counts.get(m));
                out.put(m, v);
            }
            // THE ONE DOCUMENT WHOSE TOP LEVEL IS A USER NAMESPACE, so a disclosure key can in principle
            // land on a real class (`class incomplete`). It cannot be dodged by nesting — a consumer
            // branching on `"incomplete" in doc` never sees a nested one — and `put` OVERWRITES, so a
            // silently displaced class row would be the dropped row this whole rung exists to remove. So
            // the collision is DISCLOSED, loudly and by name, and the hedge still wins: a lost row the
            // operator has been told about beats a false all-clear nobody has.
            for (String k : comp.keys())
                if (out.containsKey(k))
                    System.err.println("candor map: this report has a class literally named `" + k
                            + "`, which collides with the ⟨0.28⟩ incompleteness disclosure this answer "
                            + "must carry — the disclosure wins and that class's row is NOT in the JSON "
                            + "below. Its effects are in the text output (drop --json).");
            comp.writeJson(out);
            emit(out);
            return 0;
        }
        comp.printNote("the class rows below cover only the source candor read",
                "A class living wholly in one of those is MISSING from the overview, and one that IS "
                + "listed may be missing functions. " + comp.gateLine() + " Re-scan for a complete map.");
        if (mods.isEmpty()) {
            if (comp.mustHedge()) {
                System.out.println("candor: no effectful function candor COULD SEE — but see the "
                        + "INCOMPLETE note above; this is NOT \"the code performs no effects\".");
                return 0;
            }
            System.out.println("candor: no effectful functions in the report.");
            return 0;
        }
        int total = counts.values().stream().mapToInt(i -> i).sum();
        System.out.println("candor map — " + total + " effectful functions across " + mods.size() + " class(es)\n");
        int w = mods.keySet().stream().mapToInt(String::length).max().orElse(0);
        mods.keySet().stream()
                .sorted((a, b) -> counts.get(b).equals(counts.get(a)) ? a.compareTo(b) : counts.get(b) - counts.get(a))
                .forEach(m -> {
                    int n = counts.get(m);
                    System.out.printf("  %-" + w + "s  { %s }  (%d fn%s)%n",
                            m, String.join(" ", mods.get(m)), n, n == 1 ? "" : "s");
                });
        return 0;
    }

    /** Per-function effect delta vs a baseline report (+gained / -lost). */
    /** The producing build of the report at {@code path} — its {@code candor.version} header (SPEC §2.1
     *  provenance), or null when unreadable/absent (a legacy bare-array report). Tolerant by design: the
     *  comparison QUERIES below only DISCLOSE provenance; the fail-closed reading of a bad report already
     *  happened in {@link #load}. */
    /** ⟨0.15 staged⟩ The report envelope's `coverage` field (the κ ledger as data — COVERAGE-DESIGN §1),
     *  parsed tolerantly like {@link #reportVersion}: null when absent (a fully-covered or pre-⟨0.15⟩
     *  report), unreadable, or not the expected object shape. Consumers (gains) re-disclose it verbatim. */
    static JsonObject reportCoverage(String path) {
        try {
            JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
            if (!root.isJsonObject()) return null;
            JsonElement c = root.getAsJsonObject().get("coverage");
            return c != null && c.isJsonObject() ? c.getAsJsonObject() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** The uncovered package NAMES a parsed `coverage` object carries (empty when null/malformed) — the
     *  set gains' coverageDelta compares. Names, not counts: a call-count wobble is ordinary code change;
     *  a package ENTERING or LEAVING the uncovered set is the coverage signal. ⟨0.15 staged⟩ */
    private static TreeSet<String> uncoveredNames(JsonObject coverage) {
        TreeSet<String> names = new TreeSet<>();
        if (coverage == null || !coverage.has("uncovered") || !coverage.get("uncovered").isJsonArray())
            return names;
        for (JsonElement e : coverage.getAsJsonArray("uncovered")) {
            if (!e.isJsonObject()) continue;
            JsonElement n = e.getAsJsonObject().get("name");
            if (n != null && n.isJsonPrimitive()) names.add(n.getAsString());
        }
        return names;
    }

    static String reportVersion(String path) {
        try {
            JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
            if (!root.isJsonObject()) return null;
            JsonObject obj = root.getAsJsonObject();
            if (!obj.has("candor") || !obj.get("candor").isJsonObject()) return null;
            JsonElement v = obj.getAsJsonObject("candor").get("version");
            return v != null && v.isJsonPrimitive() ? v.getAsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** §2.1 stale-baseline DISCLOSURE for the read-only comparison queries (`diff`/`gains`): a baseline is
     *  comparable only to reports from its own producing build, so a version mismatch means the delta may
     *  be the ENGINE reclassifying (a κ batch unmasking effects), not the code changing. Unlike the
     *  baseline GUARD (fail-closed, exit 2, no evaluation), a query still ANSWERS — it discloses: one
     *  stderr ⚠ line (when the two versions are both known and differ) + unconditional
     *  {@code baseline_version}/{@code engine_version} provenance fields in the JSON envelope (empty when
     *  unknown). Mirrors candor-ts query.mjs / candor-query DiffJson exactly (cross-engine parity). */
    private static boolean discloseVersionMismatch(String engineV, String baseV, String consequence) {
        boolean mismatch = engineV != null && !engineV.isEmpty() && baseV != null && !baseV.isEmpty()
                && !engineV.equals(baseV);
        if (mismatch)
            System.err.println("candor-java: ⚠ baseline @" + baseV + " ≠ engine @" + engineV + " — " + consequence);
        return mismatch;
    }

    static int diff(List<Effector> cur, String curPath, String basePath, boolean json) {
        if (basePath == null) return usage("diff <report.json> <baseline.json> [--json]");
        List<Effector> base;
        try {
            base = load(basePath);
        } catch (Exception e) {
            // Diagnostics go to STDERR (mirrors the load() relay in run()): under --json a consumer
            // parses stdout as JSON, so a prose line there is garbage on the machine channel — and the
            // corrupt-report loudness rule wants the disclosure where diagnostics live. Relay load()'s
            // precise reason, exit 2, NOTHING on stdout.
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            System.err.println("candor: cannot read baseline " + basePath + " (" + why + ")");
            return 2;
        }
        String engineV = reportVersion(curPath), baseV = reportVersion(basePath);
        boolean versionMismatch = discloseVersionMismatch(engineV, baseV,
                "some changes may be the engine reclassifying, not your code. Treat an engine swap as"
                + " baseline-invalidating: review, then regenerate the baseline.");
        Map<String, Set<String>> b = unionByFn(base, f -> f.inferred().toNames());
        Map<String, Set<String>> c = unionByFn(cur, f -> f.inferred().toNames());
        Map<String, Set<String>> cd = unionByFn(cur, f -> f.direct().toNames());
        TreeSet<String> all = new TreeSet<>();
        all.addAll(b.keySet());
        all.addAll(c.keySet());
        List<Map<String, Object>> changes = new ArrayList<>();
        for (String fn : all) {
            Set<String> bi = b.getOrDefault(fn, Set.of());
            Set<String> ci = c.getOrDefault(fn, Set.of());
            List<String> gained = ci.stream().filter(x -> !bi.contains(x)).sorted().toList();
            List<String> lost = bi.stream().filter(x -> !ci.contains(x)).sorted().toList();
            if (gained.isEmpty() && lost.isEmpty()) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("fn", fn);
            m.put("gained", gained);
            // A gained effect is INTRODUCED here if it's in this method's own `direct` set, else
            // INHERITED from a callee — the source vs the blast radius (mirrors candor-query).
            Set<String> dir = cd.getOrDefault(fn, Set.of());
            m.put("introduced", gained.stream().filter(dir::contains).toList());
            m.put("inherited", gained.stream().filter(x -> !dir.contains(x)).toList());
            m.put("lost", lost);
            m.put("status", !c.containsKey(fn) ? "removed" : (!b.containsKey(fn) ? "new" : "changed"));
            changes.add(m);
        }
        // Exit parity with candor-ts (query.mjs `diff`): diff DISCLOSES (it is not a gate), but its
        // gained-effect exit 1 is the same-build ratchet convenience — exit 1 iff SOME function gained
        // an effect AND the baseline came from this engine build. Under a version mismatch that signal
        // is BOGUS (the "gain" may be the engine reclassifying after a coverage batch — unmasking, not
        // regression), so exit 0 and let the stderr ⚠ inform: never deliver the unmasking wave as a CI
        // failure (§2.1: guards fail closed, queries disclose). `gains` deliberately keeps exit 0
        // always — in candor-ts the exit-1 contract belongs to diff alone.
        boolean gain = !versionMismatch
                && changes.stream().anyMatch(m -> !((List<?>) m.get("gained")).isEmpty());
        if (json) {
            // The cross-language shape (SPEC §3.1): an envelope with baseline_version/engine_version
            // provenance (unconditional, "" when unknown — the candor-ts/candor-query field set) then
            // `changes`. A bare array here used to diverge from the Rust engine; then the provenance
            // fields were missing while ts/rust carried them (cross-engine parity, conformance PART 15).
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("baseline_version", baseV == null ? "" : baseV);
            out.put("engine_version", engineV == null ? "" : engineV);
            out.put("changes", changes);
            emit(out);
            return gain ? 1 : 0;
        }
        if (changes.isEmpty()) {
            System.out.println("candor: no effect changes vs " + basePath + ".");
            return 0;
        }
        for (Map<String, Object> m : changes) {
            @SuppressWarnings("unchecked")
            List<String> gained = (List<String>) m.get("gained");
            @SuppressWarnings("unchecked")
            List<String> lost = (List<String>) m.get("lost");
            List<String> parts = new ArrayList<>();
            gained.forEach(x -> parts.add("+" + x));
            lost.forEach(x -> parts.add("-" + x));
            String st = (String) m.get("status");
            String tag = st.equals("removed") ? "  (removed fn)" : (st.equals("new") ? "  (new fn)" : "");
            System.out.println("  " + m.get("fn") + tag + "   { " + String.join(" ", parts) + " }");
        }
        return gain ? 1 : 0;
    }

    /** Effects indexed by function name, UNION-merging rows that share a name. A report built by a
     *  candor engine has one row per fn, but a hand-merged or cross-jar-combined report can repeat a
     *  fn — keep-first would then DROP a row's effects and make diff/gains FABRICATE a phantom gain (or
     *  MISS a real one). Unioning is the safe direction: it never drops an effect. Mirrors candor-rust
     *  `load_fninfo` (union-at-load) and candor-ts `effectsByFn`. */
    static Map<String, Set<String>> unionByFn(List<Effector> fns, java.util.function.Function<Effector, Collection<String>> pick) {
        Map<String, Set<String>> m = new HashMap<>();
        for (Effector f : fns) m.computeIfAbsent(f.fn(), k -> new HashSet<>()).addAll(pick.apply(f));
        return m;
    }

    /** gains — the package-level SUPPLY-CHAIN alarm (SPEC §5.1): the UNION of effects the surface gained
     *  between two reports (base -> cur), with per-function detail. A dependency that grew a Net/Exec reach
     *  between releases. {gained:[Effect], byFunction:[{effect,fn,origin}]} — the cross-engine
     *  machine-readable form. Always exit 0 (candor-ts parity: the gained-effect exit-1 contract belongs to
     *  `diff` alone; gains is a pure disclosure whose consumers read the JSON, not the exit code). */
    static int gains(List<Effector> cur, ReportRef curRef, ReportRef baseRef, List<String> baseReports, boolean json, boolean strict) {
        String curPath = curRef.resolved(), basePath = baseRef.resolved();
        if (basePath == null) return usage("gains <report.json> <baseline.json> [--json] [--strict]");
        // An EMPTY union is meaningful, not a gap to paper over: the locator expanded to no ENGINE-OWNED
        // report (e.g. only a foreign engine's report matched the prefix), so the baseline graph is
        // ABSENT and origin resolves "unknown". Falling back to basePath here would resurrect the
        // foreign sidecar the union just excluded. A null list is a direct-caller convenience only.
        if (baseReports == null) baseReports = List.of();
        List<Effector> base;
        try {
            base = load(basePath);
        } catch (Exception e) {
            // STDERR + exit 2, stdout untouched — same rationale as diff's handler above: `gains --json`
            // stdout is a machine channel, and the corrupt-baseline disclosure belongs on stderr.
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            System.err.println("candor: cannot read baseline " + basePath + " (" + why + ")");
            return 2;
        }
        String engineV = reportVersion(curPath), baseV = reportVersion(basePath);
        discloseVersionMismatch(engineV, baseV,
                "a \"gained capability\" may be the engine reclassifying, not the dependency changing."
                + " Regenerate both reports with one build to compare releases.");
        Map<String, Set<String>> b = unionByFn(base, f -> f.inferred().toNames());
        Map<String, Set<String>> c = unionByFn(cur, f -> f.inferred().toNames()); // union cur too: no dup double-count
        TreeSet<String> gained = new TreeSet<>();
        List<Map<String, Object>> byFunction = new ArrayList<>();
        for (String fn : new TreeSet<>(c.keySet())) {
            Set<String> bi = b.getOrDefault(fn, Set.of());
            for (String e : new TreeSet<>(c.get(fn))) {
                if (!bi.contains(e)) {
                    gained.add(e);
                    Map<String, Object> m = new TreeMap<>(); // alphabetical keys: effect, fn, origin
                    m.put("fn", fn);
                    m.put("effect", e);
                    byFunction.add(m);
                }
            }
        }
        if (json) {
            // ⟨spec 0.12 staged⟩ each byFunction entry carries `origin` — the candor-gains prototype's
            // key finding promoted into the open query. A gain on a fn that EXISTED at the baseline
            // (shipped pure, now does Net — the supply-chain attack signal) is a different alarm from a
            // NEW fn that does Net (a feature). Reports OMIT pure functions (SPEC §2), so existence is
            // keyed on the baseline CALLGRAPH sidecars — every ENGINE-OWNED report the baseline locator
            // matched (a baseline-pure fn is a graph node with no report entry; a FOREIGN engine's
            // sidecar is excluded — its `m::f` quals never evidence a JVM fn). The ladder:
            //   "existing" — in the baseline report, or a baseline-callgraph node (caller or callee);
            //   "unknown"  — absent from the baseline report AND the graph is EMPTY (no sidecar found)
            //                OR PARTIAL (a matched sidecar existed but failed to read/parse — its
            //                dropped nodes prove nothing): existence is undecidable — DISCLOSED, never
            //                guessed. A partial graph must never downgrade the supply-chain attack
            //                signal ("existing fn gained an effect") to a feature ("new fn").
            //   "new"      — in neither, under a COMPLETE graph (the fn did not exist at the baseline).
            // JSON-only: the human `fn\teffect` TSV is a pinned consumer surface (line-matched by
            // callers' seen-file dedup) and stays byte-stable. Mirrors candor-rust cmd_gains.
            Set<String> baseCgNodes = new HashSet<>();
            boolean cgPartial = false;
            for (String rp : baseReports) {
                CallgraphLoad l = loadCallgraphSignalled(rp); // discloses a corrupt sidecar on stderr
                cgPartial |= l.partial();
                if (l.graph() != null)
                    for (var e : l.graph().entrySet()) {
                        baseCgNodes.add(e.getKey());
                        baseCgNodes.addAll(e.getValue());
                    }
            }
            for (Map<String, Object> m : byFunction) {
                String fn = (String) m.get("fn");
                m.put("origin", b.containsKey(fn) ? "existing"
                        : baseCgNodes.contains(fn) ? "existing"
                        : (baseCgNodes.isEmpty() || cgPartial) ? "unknown"
                        : "new");
            }
            Map<String, Object> out = new LinkedHashMap<>();
            // provenance first (unconditional, "" when unknown), then the gains — the candor-ts order.
            out.put("baseline_version", baseV == null ? "" : baseV);
            out.put("engine_version", engineV == null ? "" : engineV);
            out.put("gained", new ArrayList<>(gained));
            out.put("byFunction", byFunction);
            // ⟨0.15 staged⟩ coverage re-disclosure (COVERAGE-DESIGN §3): a "no gains" over an uncovered
            // dep must not read as total — carry the CURRENT report's envelope `coverage` verbatim when
            // present. When the baseline's uncovered NAME set differs (a dep became uncovered between
            // scans — itself a signal, e.g. a chained dep report went missing), disclose `coverageDelta`.
            // ADDITIVE + JSON-only: verdict fields/exit unchanged; the human TSV is a pinned surface.
            JsonObject curCov = reportCoverage(curPath);
            JsonObject baseCov = reportCoverage(basePath);
            if (curCov != null) out.put("coverage", curCov);
            TreeSet<String> curNames = uncoveredNames(curCov), baseNames = uncoveredNames(baseCov);
            if (!curNames.equals(baseNames)) {
                Map<String, Object> delta = new LinkedHashMap<>();
                delta.put("nowUncovered", curNames.stream().filter(n -> !baseNames.contains(n)).toList());
                delta.put("noLongerUncovered", baseNames.stream().filter(n -> !curNames.contains(n)).toList());
                out.put("coverageDelta", delta);
            }
            // ⟨0.28⟩ SPEC §2 — AND THE SAME MUST CARRIES THE ⟨0.21⟩ MANIFEST, which is the STRONGER
            // caveat and the one that was not travelling. The three lines above have carried the CURRENT
            // report's `coverage` since ⟨0.15⟩, for the reason §2 gives — a "no gains" over an uncovered
            // dep reads clean with false confidence. Measured, THIS verb, on THAT report, in THIS output,
            // dropped `unanalyzed`: `coverage.uncovered` says "I could not see into this dependency",
            // `unanalyzed` says "I could not read this file of your OWN code", and `analyzed.count: 0`
            // says "I judged nothing at all". The mechanism was already here and pointed at the weaker
            // field, so this reuses it (#reportCompleteness, the one reader the descriptive and advisory
            // verbs share) rather than growing a second one.
            //
            // BOTH SIDES, SEPARATELY — see ReportCompleteness#writeJson(Map, String) for why one combined
            // flag would be unactionable. Read through the LOCATORS, not the two resolved paths: a locator
            // may name a report SET (§2 "a single analysis world") and the manifest that qualifies this
            // answer can sit in the sibling the single-file pick above did not choose.
            //
            // JSON-only and verdict-preserving, on the same terms as the coverage block: the human
            // `fn\teffect` TSV is a pinned consumer surface, and the exit below is untouched — `gains` is
            // advisory by default and `--strict` keys on the GAINED SET, which this does not touch.
            curRef.completeness("gains").writeJson(out);
            baseRef.completeness("gains (baseline)").writeJson(out, "baseline");
            emit(out);
            // Advisory by default (exit 0 — gains is a diff view); `--strict` fails on ANY gained effect so a
            // supply-chain CI job can require a bump introduce no new capability (mirrors `unverified --strict`).
            return strict && !gained.isEmpty() ? 1 : 0;
        }
        for (Map<String, Object> m : byFunction) System.out.println(m.get("fn") + "\t" + m.get("effect"));
        if (strict && !gained.isEmpty()) {
            System.err.println("candor gains --strict: the surface gained new effect(s) vs the baseline → exit 1");
            return 1;
        }
        return 0;
    }

    /** The longest dotted-segment prefix shared by EVERY function name — the codebase root, so the next
     *  segment is the architectural "layer" (`com.uflexi.nems` → `model`/`dao`/`actions`). Adapts to any
     *  package root without configuration. */
    static String[] commonPrefix(List<Effector> fns) {
        String[] best = null;
        for (Effector f : fns) {
            String[] segs = f.fn().split("\\.");
            if (best == null) { best = segs; continue; }
            int n = Math.min(best.length, segs.length), i = 0;
            while (i < n && best[i].equals(segs[i])) i++;
            best = Arrays.copyOf(best, i);
        }
        return best == null ? new String[0] : best;
    }

    /** The layer a function belongs to: the PACKAGE segment after the common root prefix — not a
     *  Class/method leaf. A Java name ends `…Package.Class.method`, so the segment is a package layer
     *  only when a `Class.method` pair (2 segments) follows it; a class in the root package buckets into
     *  `(root)` rather than becoming its own pseudo-layer. */
    static String layerOf(String fn, int prefixLen) {
        String[] segs = fn.split("\\.");
        return prefixLen + 2 < segs.length ? segs[prefixLen] : "(root)";
    }

    /** blindspots (SPEC §3.1 ⟨0.6⟩) — the Unknown SOURCES: units whose OWN body has an unresolvable call
     *  (so they carry `unknownWhy`), each ranked by its Unknown blast radius (the transitive callers that
     *  inherit `Unknown` through it). The actionable inverse of a widely-propagated `Unknown`: a report can
     *  read 60% Unknown from a handful of root causes — this names them, ranked, to declare/resolve/accept.
     *  Reverse-BFS over the report's effect-relevant `calls` edges (the channel Unknown propagates along),
     *  the same graph `impact` uses. */
    /** ⟨0.24⟩ Thrown by {@link #parseClassFilter} for a {@code --class} value this engine cannot honour.
     *  Carries the message the CLI prints verbatim; {@link #run} turns it into exit 2. */
    static final class ClassFilterUsageError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        ClassFilterUsageError(String message) { super(message); }
    }

    /** The accepted {@code --class} vocabulary, named in every refusal so the user never has to guess. */
    private static final String CLASS_TOKENS =
            "reflect, dispatch, indirect, native, unresolved, setup (aliases: dynamic, *)";

    /**
     * Parse a {@code --class <c,…>} filter into reason classes: the six tokens, {@code dynamic} (every
     * genuine class — which by its own definition EXCLUDES {@code setup}), or {@code *} (no filter → null,
     * as an absent flag is). Shared by {@code blindspots} and {@code unverified} so the drill-down
     * vocabulary matches the §6.2 policy one.
     *
     * <p>⟨0.24⟩ AN UNRECOGNISED TOKEN IS A USAGE ERROR (exit 2), NOT A WARNING. This used to print
     * "ignores unknown reason-class `x`" and carry on, which is the POLICY side's drop-with-warning rule
     * applied where it inverts: on the policy side a dropped token leaves a WIDER rule standing, so the
     * gate can only over-fire; here it leaves a NARROWER filter, so {@code --class dyanmic} silently
     * answers a question the user did not ask, WITH A SMALLER NUMBER — on the one verb whose job is to
     * name the holes a green gate is hiding. That is a fail-open disclosure, and a query flag that cannot
     * be honoured is refused rather than approximated. An empty value ({@code --class ""}, {@code
     * --class ,}) is refused for the same reason: it names no class, so it selects nothing, which is the
     * narrowest wrong answer of all.
     *
     * @throws ClassFilterUsageError on an unrecognised or empty value; the caller prints it and exits 2
     */
    static Set<ReasonClass> parseClassFilter(String spec) {
        if (spec == null) return null;
        Set<ReasonClass> out = new java.util.LinkedHashSet<>();
        for (String t : spec.split(",", -1)) {
            t = t.trim();
            if (t.isEmpty()) continue;
            if (t.equals("*")) return null;                       // explicit "all" ⇒ no filter
            if (t.equals("dynamic")) { out.addAll(ReasonClass.dynamicSet()); continue; }
            ReasonClass rc = ReasonClass.fromToken(t);
            if (rc == null) throw new ClassFilterUsageError("--class does not accept `" + t
                    + "` — it names no reason class, and a filter that cannot be honoured would answer a "
                    + "NARROWER question than the one asked, with a smaller number. Accepted: " + CLASS_TOKENS);
            out.add(rc);
        }
        if (out.isEmpty()) throw new ClassFilterUsageError("--class was given the empty value `" + spec
                + "`, which names no reason class and would select nothing. Accepted: " + CLASS_TOKENS
                + "; omit the flag (or use `*`) for no filter.");
        return out;
    }

    static int blindspots(List<Effector> fns, boolean json, boolean stats, Set<ReasonClass> classFilter,
                          ReportRef ref) {
        // ⟨0.28⟩ THE SHARPEST INSTANCE IN SPEC §2's LIST, and the one that names this verb: over a report
        // whose own manifest names a file it could not read, `blindspots` answered
        // `{"sources":[],"totalUnknown":0}` — *no blind spots* — at exit 0. The unread unit IS a blind
        // spot, of the one kind this verb exists to enumerate, and it is the one kind that cannot appear
        // in `sources`: there is no report entry for it to carry an `unknownWhy`.
        ReportCompleteness comp = ref.completeness("blindspots");
        String bsSoWhat = "the Unknown source(s) below are only those inside the source candor read";
        String bsTail = "An unread unit is a blind spot too, and it carries no `unknownWhy` to be listed "
                + "under — so it is HERE and not below. " + comp.gateLine() + " Re-scan for the full picture.";
        Map<String, List<String>> rev = new HashMap<>();
        for (Effector f : fns) for (String c : f.calls()) rev.computeIfAbsent(c, k -> new ArrayList<>()).add(f.fn());
        // `--class <c,…>` (SPEC §3.1 ⟨0.20⟩): keep only Unknown SOURCES whose reason classes intersect the
        // filter — the drill-down companion to `--stats` (which sizes; this names). null = no filter.
        java.util.function.Predicate<Effector> classMatch = f -> classFilter == null
                || (f.unknownWhy() != null && f.unknownWhy().stream()
                        .anyMatch(ur -> classFilter.contains(ReasonClass.classify(ur.format()))));
        int totalUnknown = (int) fns.stream().filter(f -> f.inferred().hasUnknown()).count();
        // `--stats` (SPEC §3.1 ⟨0.20⟩): the reason-class DISTRIBUTION over the Unknown SOURCES — how much
        // Unknown, by class {reflect,dispatch,indirect,native,unresolved,setup} — so a team can SIZE the
        // blind-spot cost (and separate genuine dynamism from `setup` mis-config) BEFORE turning on
        // `deny E Unknown`. Counts SOURCE functions per class (a multi-reason fn counts in each class it has).
        if (stats) {
            java.util.Map<String, Integer> byClass = new java.util.LinkedHashMap<>();
            for (ReasonClass c : ReasonClass.values()) byClass.put(c.token(), 0);
            int sources = 0;
            for (Effector f : fns) {
                if (f.unknownWhy() == null || f.unknownWhy().isEmpty() || !classMatch.test(f)) continue;
                sources++;
                java.util.Set<ReasonClass> classes = f.unknownWhy().stream()
                        .map(ur -> ReasonClass.classify(ur.format())).collect(Collectors.toSet());
                for (ReasonClass c : classes) byClass.merge(c.token(), 1, Integer::sum);
            }
            if (json) {
                java.util.Map<String, Object> out = new LinkedHashMap<>();
                out.put("byClass", byClass);           // ALL six classes, stable order (0 when absent)
                out.put("sources", sources);
                out.put("totalUnknown", totalUnknown);
                // ⟨0.28⟩ `--stats` is the same answer summarised, so it takes the same hedge: sizing the
                // blind-spot cost off an all-zero distribution computed over nothing is exactly the
                // decision this rung is here to stop.
                comp.writeJson(out);
                emit(out);
                return 0;
            }
            comp.printNote(bsSoWhat, bsTail);
            if (sources == 0) {
                if (comp.mustHedge()) {
                    System.out.println("  no Unknown source inside what candor COULD SEE — but see the "
                            + "INCOMPLETE note above; this distribution is not a measure of the whole crate.");
                    return 0;
                }
                System.out.println("  no Unknown sources — nothing to classify (no direct-Unknown in this report).");
                return 0;
            }
            System.out.println("  " + sources + " Unknown source(s) by reason class (of " + totalUnknown
                    + " Unknown function(s)) — size the blind-spot cost before `deny E Unknown[…]`:");
            byClass.entrySet().stream()
                    .filter(e -> e.getValue() > 0)
                    .sorted((a, b) -> b.getValue() - a.getValue())   // most-common class first
                    .forEach(e -> System.out.printf("  %-12s %4d%s%n", e.getKey(), e.getValue(),
                            e.getKey().equals("setup") ? "   ← fixable: the scan isn't configured, not a real blind spot" : ""));
            return 0;
        }
        List<Map<String, Object>> sources = new ArrayList<>();
        for (Effector f : fns) {
            if (f.unknownWhy() == null || f.unknownWhy().isEmpty() || !classMatch.test(f)) continue; // a SOURCE of a matching class
            Set<String> affected = new TreeSet<>();
            Deque<String> q = new ArrayDeque<>();
            Set<String> seen = new HashSet<>();
            q.add(f.fn());
            seen.add(f.fn());
            while (!q.isEmpty()) {
                String cur = q.poll();
                for (String caller : rev.getOrDefault(cur, List.of()))
                    if (seen.add(caller)) { affected.add(caller); q.add(caller); }
            }
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("fn", f.fn());
            s.put("why", f.unknownWhy().stream().map(UnknownReason::format).collect(Collectors.toList()));
            s.put("reaches", affected.size());
            s.put("affected", new ArrayList<>(affected)); // sorted (TreeSet): stable cross-engine shape
            sources.add(s);
        }
        sources.sort((a, b) -> Integer.compare((Integer) b.get("reaches"), (Integer) a.get("reaches")));
        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("sources", sources);
            out.put("totalUnknown", totalUnknown);
            comp.writeJson(out);
            emit(out);
            return 0;
        }
        comp.printNote(bsSoWhat, bsTail);
        if (sources.isEmpty()) {
            if (comp.mustHedge()) {
                // NOT "every call resolved". Over these bytes candor did not see every call.
                System.out.println("  no Unknown source inside what candor COULD SEE — but see the "
                        + "INCOMPLETE note above; this is NOT \"no blind spots\".");
                return 0;
            }
            System.out.println("  no Unknown sources — every call resolved (or no Unknown in this report).");
            return 0;
        }
        System.out.println("  " + sources.size() + " Unknown source(s) explaining " + totalUnknown
                + " Unknown function(s) — the blind spots to declare, resolve, or accept:");
        for (Map<String, Object> s : sources)
            System.out.printf("  %-52s reaches %4d  %s%n", leaf((String) s.get("fn")),
                    (Integer) s.get("reaches"), s.get("why"));
        return 0;
    }

    /** tour [<N>] (SURFACE-BEST-FIND-DESIGN.md, P2) — the N (default 10) most SURPRISING transitive reaches
     *  in the report's crate, each with a ready-to-run {@code candor path <fn> <effect>}. The on-demand,
     *  top-N version of the scan-time note: it delegates to the SHARED {@link Surface#bestFinds} (the same
     *  heuristic the scan note uses, so the ranking can't drift), reading the report entries + the callgraph
     *  sidecar the scan already wrote. Read-only, no re-scan. The EXACT port of candor-query's {@code tour}.
     *
     *  <p>{@code arg} is the optional positional N; a non-integer is a usage error (exit 2). {@code report}
     *  is the resolved report path (its {@code .callgraph.json} sidecar drives the transitive walk). */
    static int tour(List<Effector> fns, String reportPath, String arg, boolean json, ReportRef ref) {
        // The lone optional positional is N (how many to list); default 10. It MUST be a positive integer —
        // a non-integer OR zero is a usage error (exit 2). `tour 0` must never print the honest-sounding
        // "nothing hidden" over an effectful crate: that would be a false all-clear (the §4 cardinal sin).
        int n = 10;
        if (arg != null) {
            try {
                n = Integer.parseInt(arg);
                if (n < 1) throw new NumberFormatException();
            } catch (NumberFormatException ex) {
                System.err.println("usage: candor tour [<N>] [--report <locator>] [--json]   (N is a positive integer ≥ 1)");
                return 2;
            }
        }

        // Build the maps the heuristic wants from the report entries + the callgraph sidecar. `inferred`/
        // `direct` come from the report; `calls` prefers the full callgraph sidecar (records EVERY edge —
        // like the scan held in memory) and falls back to the report's effect-relevant `calls`. `loc` maps a
        // function to its "file:line" for the source callout.
        Map<String, EffectSet> inferred = new HashMap<>();
        Map<String, EffectSet> direct = new HashMap<>();
        Map<String, String> loc = new HashMap<>();
        for (Effector e : fns) {
            inferred.put(e.fn(), e.inferred());
            if (!e.direct().toNames().isEmpty()) direct.put(e.fn(), e.direct());
            if (!e.loc().isEmpty()) loc.put(e.fn(), e.loc());
        }
        Map<String, Set<String>> calls = new HashMap<>();
        Map<String, List<String>> cg = loadCallgraph(reportPath);
        if (cg == null || cg.isEmpty()) {
            for (Effector e : fns) if (!e.calls().isEmpty()) calls.put(e.fn(), new HashSet<>(e.calls()));
        } else {
            for (var e : cg.entrySet()) calls.put(e.getKey(), new HashSet<>(e.getValue()));
        }

        List<Surface.Find> finds = Surface.bestFinds(inferred, direct, calls, loc, n);

        // The header names the report's PACKAGE (from the §2 envelope) — meaningful and locator-independent,
        // so every engine and every --report form print the same crate. Falls back to the report/prefix
        // basename (matches the Rust reference's report_package(pre).unwrap_or_else(prefix_base)).
        String basename = Path.of(reportPath).getFileName() != null
                ? Path.of(reportPath).getFileName().toString() : reportPath;
        String pkg = reportPackage(reportPath);
        String crateName = pkg != null ? pkg : basename;

        // ⟨0.28⟩ AND THE SAME ARGUMENT AS THE `unknown` FIELD BELOW, ONE CAUSE OVER. That field exists
        // because a bare `{"reaches":[]}` read as clean to the agent loop over a mostly-Unknown graph; a
        // report that judged nothing, or that names a file it could not read, produces the IDENTICAL
        // empty array from strictly less evidence — and the ⅓-Unknown threshold cannot see it, because an
        // unread unit contributes no entry and so moves neither `unknown` nor `total`.
        ReportCompleteness comp = ref.completeness("tour");
        String tSoWhat = "the reaches below are ranked over only the call graph candor could see";
        String tTail = "A surprising reach whose path runs through an unread unit is not ranked here at "
                + "all, and cannot be. " + comp.gateLine() + " Re-scan for the full tour.";

        if (json) {
            List<Map<String, Object>> reaches = new ArrayList<>();
            for (Surface.Find f : finds) {
                // Alphabetical key order (effect, fn, hops, loc, score, source) — matches the Rust + Swift
                // reference's serde field-name sort. A TreeMap emits keys in sorted order.
                Map<String, Object> m = new TreeMap<>();
                m.put("fn", f.func);
                m.put("effect", f.effect);
                m.put("hops", f.hops);
                m.put("source", f.source);
                m.put("loc", f.sourceLoc);
                m.put("score", f.score);
                reaches.add(m);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("reaches", reaches);
            // The MACHINE half of the mostly-Unknown disclosure (Fable-review finding E): a JSON consumer
            // (the agent loop) got a bare {"reaches":[]} and read it as clean — the same false all-clear the
            // text branch qualifies. ADDITIVE + present only when the ≥⅓-Unknown threshold trips (byte-
            // identical otherwise); `unknown` sorts after `reaches` to match Rust's serde output.
            long tot = inferred.values().stream().filter(es -> !es.toNames().isEmpty()).count();
            long unk = inferred.values().stream().filter(es -> es.toNames().contains("Unknown")).count();
            if (tot > 0 && unk * 3 >= tot) {
                Map<String, Object> u = new TreeMap<>();  // count, total (sorted, matching serde)
                u.put("count", unk); u.put("total", tot);
                out.put("unknown", u);
            }
            comp.writeJson(out);
            // Pure JSON to stdout, compact (no pretty-printing) — matches the Rust reference's
            // serde_json::to_string. The shared JSON serializer here pretty-prints, so build a compact one.
            System.out.println(new GsonBuilder().create().toJson(out));
            return 0;
        }

        comp.printNote(tSoWhat, tTail);
        if (finds.isEmpty()) {
            // Effectful-but-nothing-surprising vs genuinely-pure both land here; either way the honest line
            // is the useful answer (never a manufactured surprise) — mirrors the scan-note fallback. BUT never
            // reassure "nothing hidden" over a meaningfully-Unknown graph: the Unknowns ARE the hidden part
            // (re-audit cardinal sin; four-way with candor-ts/rust). ≥⅓ effectful Unknown → qualify + blindspots.
            long total = inferred.values().stream().filter(es -> !es.toNames().isEmpty()).count();
            long unknown = inferred.values().stream().filter(es -> es.toNames().contains("Unknown")).count();
            if (total > 0 && unknown * 3 >= total) {
                System.out.println("candor: no surprising reaches — but " + unknown + " of " + total
                    + " function(s) are Unknown (unresolved calls; their transitive effects are NOT analyzed). "
                    + "Run `candor blindspots` — the report records a reason for each.");
                return 0;
            }
            if (comp.mustHedge()) {
                // "nothing hidden" is the single most reassuring sentence this binary prints, and over a
                // report that judged nothing it is the false all-clear in plain English. The ⅓-Unknown
                // branch above cannot catch this case, for the reason given where `comp` is read.
                System.out.println("candor: nothing hidden in what candor COULD SEE — but see the "
                        + "INCOMPLETE note above; this is NOT \"nothing is hidden\".");
                return 0;
            }
            System.out.println("candor: nothing hidden — every effect sits where its name says it should.");
            return 0;
        }
        System.out.println("candor tour — the " + finds.size() + " most surprising reach"
                + (finds.size() == 1 ? "" : "es") + " in " + crateName + ":");
        int i = 1;
        for (Surface.Find f : finds) {
            String hopWord = f.hops == 1 ? "hop" : "hops";
            String whereS = f.sourceLoc.isEmpty() ? "" : " (" + f.sourceLoc + ")";
            System.out.println("  " + i + ". `" + f.func + "` performs " + f.effect + ", " + f.hops
                    + " " + hopWord + " away via `" + f.source + "`" + whereS);
            System.out.println("     →  candor path " + f.func + " " + f.effect);
            i++;
        }
        return 0;
    }

    /** impact — the blast radius of a function: every effectful method that TRANSITIVELY calls it, and
     *  which ENTRY POINTS (runtime roots) are downstream — "if I change this, what surfaces at runtime?".
     *  The backward dual of `path`; the transitive, entry-point-scoped version of `callers`. Read-only,
     *  reversing the report's effect-relevant `calls` graph. Scoped to effectful targets (the report's
     *  `calls` only records effect-carrying edges, so a pure fn — omitted from the report — has no blast
     *  radius to trace; that's the honest limit of working from the report). */
    static int impact(List<Effector> fns, String fnArg, boolean json) {
        if (fnArg == null) return usage("impact <fn-substring> [--report <locator>] [--json]");
        Map<String, Effector> byName = new HashMap<>();
        for (Effector f : fns) byName.putIfAbsent(f.fn(), f);
        Effector target = fns.stream().filter(f -> f.fn().equals(fnArg)).findFirst()
                .orElseGet(() -> fns.stream().filter(f -> f.fn().contains(fnArg)).findFirst().orElse(null));
        if (target == null) {
            System.err.println("candor impact: no function matching '" + fnArg + "'");
            return 2;
        }
        // Reverse the effect-relevant call graph: callee -> [callers], then BFS backward from the target.
        Map<String, List<String>> rev = new HashMap<>();
        for (Effector f : fns) for (String c : f.calls()) rev.computeIfAbsent(c, k -> new ArrayList<>()).add(f.fn());
        Set<String> affected = new LinkedHashSet<>();
        Deque<String> q = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        q.add(target.fn());
        seen.add(target.fn());
        while (!q.isEmpty()) {
            String cur = q.poll();
            for (String caller : rev.getOrDefault(cur, List.of()))
                if (seen.add(caller)) { affected.add(caller); q.add(caller); }
        }
        // Entry points downstream — the runtime roots a change here surfaces through (target included if it
        // is itself a root).
        List<Effector> roots = new ArrayList<>();
        if (target.entryPoint()) roots.add(target);
        affected.stream().map(byName::get).filter(f -> f != null && f.entryPoint())
                .sorted(Comparator.comparing(f -> f.fn())).forEach(roots::add);

        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("fn", target.fn());
            out.put("affectedCount", affected.size());
            out.put("affected", new ArrayList<>(new TreeSet<>(affected))); // sorted: stable cross-engine shape
            List<Map<String, Object>> rs = new ArrayList<>();
            for (Effector r : roots) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", r.fn());
                m.put("inferred", r.inferred().toNames());
                rs.add(m);
            }
            out.put("entryPoints", rs);
            emit(out);
            return 0;
        }
        System.out.println("candor impact — what changing `" + target.fn() + "` affects:\n");
        System.out.println("  " + affected.size() + " effectful function"
                + (affected.size() == 1 ? "" : "s") + " transitively call it.");
        if (roots.isEmpty()) {
            System.out.println("  No entry point reaches it — not on a runtime path (dead, or a "
                    + "library fn invoked only externally).");
            return 0;
        }
        System.out.println("  " + roots.size() + " entry point" + (roots.size() == 1 ? "" : "s")
                + " downstream (a change here surfaces at runtime via):");
        for (Effector r : roots)
            System.out.println("    " + r.fn() + "   { " + String.join(", ", r.inferred().toNames()) + " }");
        return 0;
    }

    /** The `path --json` document — fn, effect, path (then `note`, when the source is not locally
     *  traceable), the order the question was asked in. ONE builder for the verb's three emits, so they
     *  cannot disagree about the key order the way three separate literals already had (see the salted
     *  `Map.of` note at the no-effect emit). */
    private static Map<String, Object> pathDoc(String fn, String effect, List<?> path, String note) {
        var m = new LinkedHashMap<String, Object>();
        m.put("fn", fn);
        m.put("effect", effect);
        m.put("path", path);
        if (note != null) m.put("note", note);
        return m;
    }

    /** path — the call chain by which a function comes to perform an effect: a shortest-path BFS over the
     *  effect-relevant `calls` graph from <fn> to the nearest method that performs <effect> DIRECTLY (the
     *  source). Answers "this method touches Net — through WHAT?", the chain `where` (who performs it) and
     *  `callers` (who calls X) describe the ends of but never connect. Read-only over the report. */
    static int path(List<Effector> fns, String fnArg, String effect, boolean json) {
        if (fnArg == null || effect == null)
            return usage("path <fn-substring> <Effect> [--report <locator>] [--json]");
        Map<String, Effector> byName = new HashMap<>();
        for (Effector f : fns) byName.putIfAbsent(f.fn(), f);
        Effector start = fns.stream().filter(f -> f.fn().equals(fnArg)).findFirst()
                .orElseGet(() -> fns.stream().filter(f -> f.fn().contains(fnArg)).findFirst().orElse(null));
        if (start == null) {
            System.err.println("candor path: no function matching '" + fnArg + "'");
            return 2;
        }
        if (!start.inferred().toNames().contains(effect)) {
            // In --json mode stdout must be JSON-only (a jq/MCP consumer parses it); send the human note
            // to stderr so it doesn't precede the JSON object on stdout.
            (json ? System.err : System.out).println(start.fn() + " does not perform " + effect
                    + "  (inferred: " + start.inferred().toNames() + ")");
            // LinkedHashMap in all three of this verb's emits, not `Map.of` — the containment fix (and its
            // measurement) sits in this same file: a 3+-pair `Map.of` iterates in a per-JVM-launch SALTED
            // order, so the same build emitted `{fn,effect,path}` or `{path,fn,effect}` according to the
            // launch. fn-effect-path, the order the question was asked in.
            if (json) emit(pathDoc(start.fn(), effect, List.of(), null));
            return 0;
        }
        // BFS following `calls`, only through callees that carry the effect, to the first DIRECT source.
        Map<String, String> prev = new HashMap<>();
        Deque<String> q = new ArrayDeque<>();
        q.add(start.fn());
        prev.put(start.fn(), null);
        String source = null;
        while (!q.isEmpty()) {
            String cur = q.poll();
            Effector f = byName.get(cur);
            if (f == null) continue;
            if (f.direct().toNames().contains(effect)) { source = cur; break; }
            for (String c : f.calls()) {
                Effector cf = byName.get(c);
                if (cf != null && cf.inferred().toNames().contains(effect) && !prev.containsKey(c)) {
                    prev.put(c, cur);
                    q.add(c);
                }
            }
        }
        if (source == null) {
            // Inferred but no LOCAL direct source on a `calls` path — reached cross-jar, via a
            // Spring-synthesized callee (repo/Feign), or through an Unknown. Honest: not locally traceable.
            String msg = start.fn() + " performs " + effect
                    + " but its source is not a local method (cross-jar, framework-synthesized, or via Unknown) "
                    + "— not statically traceable.";
            // --json: stdout JSON-only, the human note goes to stderr (see the no-effect branch above).
            (json ? System.err : System.out).println(msg);
            if (json) emit(pathDoc(start.fn(), effect, List.of(), "source not locally traceable"));
            return 0;
        }
        List<String> chain = new ArrayList<>();
        for (String n = source; n != null; n = prev.get(n)) chain.add(n);
        Collections.reverse(chain);

        if (json) {
            List<Map<String, Object>> steps = new ArrayList<>();
            for (int i = 0; i < chain.size(); i++) {
                Effector f = byName.get(chain.get(i));
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", chain.get(i));
                m.put("loc", f != null ? f.loc() : "");
                m.put("source", i == chain.size() - 1);
                steps.add(m);
            }
            emit(pathDoc(start.fn(), effect, steps, null));
            return 0;
        }
        System.out.println("candor path — how `" + start.fn() + "` comes to perform " + effect + ":\n");
        for (int i = 0; i < chain.size(); i++) {
            Effector f = byName.get(chain.get(i));
            String indent = "  ".repeat(i + 1);
            String arrow = i == 0 ? "" : "→ ";
            boolean isSource = i == chain.size() - 1;
            String tag = isSource
                    ? "   [" + effect + " source" + (f != null && !f.loc().isEmpty() ? " @ " + f.loc() : "") + "]"
                    : "";
            System.out.println(indent + arrow + chain.get(i) + tag);
        }
        return 0;
    }

    /** reachable — the effects the program ACTUALLY performs at runtime: the union over its ENTRY POINTS
     *  (the runtime-invoked roots — main, web/queue handlers, lifecycle hooks, task bodies, finalize).
     *  Because `inferred` is already transitive, an entry point's set IS its full reachable surface, so
     *  the union answers "what does this service do when the framework drives it" — the question the raw
     *  per-method dump can't, since most effectful methods are never called by project code directly.
     *  Lists each effect with how many entry points reach it (+ a few examples); Unknown flagged as the
     *  visibility caveat it is. No entry points → says so (nothing is marked runtime-invoked). */
    static int reachable(List<Effector> fns, boolean json, ReportRef ref) {
        List<Effector> entries = fns.stream().filter(f -> f.entryPoint())
                .sorted(Comparator.comparing(f -> f.fn())).toList();
        TreeMap<String, List<String>> byEffect = new TreeMap<>();
        for (Effector f : entries)
            for (String e : f.inferred().toNames()) byEffect.computeIfAbsent(e, k -> new ArrayList<>()).add(f.fn());

        // ⟨0.28⟩ `{"entryPoints":0,"effects":{}}` is the strongest claim this tool can make — *the program
        // performs no effect at runtime* — and over a report that judged nothing it rests on no evidence
        // at all. It is also the one answer here that stays a determined negative on GOOD data (a library
        // has no entry points), which is exactly why the caveat must be a KEY and not something the
        // consumer is expected to infer from the emptiness.
        ReportCompleteness comp = ref.completeness("reachable");
        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("entryPoints", entries.size());
            Map<String, Object> effects = new LinkedHashMap<>();
            byEffect.forEach((e, who) -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("count", who.size());
                m.put("via", who);
                effects.put(e, m);
            });
            out.put("effects", effects);
            comp.writeJson(out);
            System.out.println(JSON.toJson(out));
            return 0;
        }

        comp.printNote("the runtime effect set below is a union over only the entry points candor could see",
                "An entry point in an unread unit contributes NOTHING to this union, and neither does any "
                + "effect it reaches. " + comp.gateLine()
                + " Re-scan before treating this as the program's runtime surface.");
        System.out.println("candor reachable — effects the program performs at runtime "
                + "(union over " + entries.size() + " entry point" + (entries.size() == 1 ? "" : "s") + ")");
        if (entries.isEmpty()) {
            if (comp.mustHedge()) {
                System.out.println("  (no entry point in what candor COULD SEE — see the INCOMPLETE note "
                        + "above; this is NOT \"nothing is marked runtime-invoked\")");
                return 0;
            }
            System.out.println("  (no entry points in this report — nothing is marked runtime-invoked)");
            return 0;
        }
        // Boundary effects first (the ones that matter for a capability budget), then ambient, then the
        // Unknown caveat. Anything else (shouldn't occur) trails. Clipboard is a boundary effect, so it
        // rides in CONTAINED.
        List<String> order = new ArrayList<>();
        order.addAll(CONTAINED);
        order.addAll(AMBIENT);
        order.add("Unknown");
        List<String> seen = new ArrayList<>(byEffect.keySet());
        seen.sort(Comparator.comparingInt(e -> { int i = order.indexOf(e); return i < 0 ? order.size() : i; }));
        for (String e : seen) {
            List<String> who = byEffect.get(e);
            String tag = e.equals("Unknown") ? "   ← visibility caveat, not a performed effect" : "";
            String examples = who.stream().limit(3).map(Query::leaf).collect(Collectors.joining(", "));
            if (who.size() > 3) examples += ", …";
            System.out.printf("  %-10s %3d  (%s)%s%n", e, who.size(), examples, tag);
        }
        long pure = entries.stream().filter(f -> f.inferred().isEmpty()).count();
        System.out.println("\n  " + entries.size() + " entry point" + (entries.size() == 1 ? "" : "s")
                + "; " + pure + " perform no effect (pure roots).");
        return 0;
    }

    /** Last dotted segment-pair of a fully-qualified method name, for compact examples. */
    static String leaf(String fn) {
        String[] s = fn.split("\\.");
        return s.length >= 2 ? s[s.length - 2] + "." + s[s.length - 1] : fn;
    }

    /** containment — how well each BOUNDARY effect (Db/Net/Exec/Fs/Ipc) stays in one layer, the
     *  domain-INDEPENDENT architecture signal the "leaky cross-cutting" intuition points at (a ratio /
     *  structure, not a count). With a baseline argument it's a RATCHET: fail (exit 1) if a contained
     *  effect appears in a layer it wasn't in before — "DB must not leak into a new module". Ambient
     *  effects (Log/Clock/…) are reported but not scored (cross-cutting is expected). This is a
     *  diagnostic + ratchet, deliberately NOT a single gameable "score". */
    static int containment(List<Effector> fns, String basePath, boolean json, ReportRef ref) {
        // ⟨0.28⟩ `{"contained":[],"ambient":{}}` reads as *this codebase performs no boundary effect and
        // therefore has perfect containment*, and over a report that judged nothing it is a statement
        // about nothing. The BASELINE's manifest is folded in below when the ratchet runs.
        ReportCompleteness comp = ref.completeness("containment");
        String[] prefix = commonPrefix(fns);
        int pl = prefix.length;
        // effect -> (layer -> count of methods performing it DIRECTLY)
        Map<String, TreeMap<String, Integer>> byEff = new LinkedHashMap<>();
        for (Effector f : fns)
            for (String eff : f.direct().toNames())
                byEff.computeIfAbsent(eff, k -> new TreeMap<>()).merge(layerOf(f.fn(), pl), 1, Integer::sum);

        // RATCHET mode: a baseline report was given — flag any NEW (contained-effect, layer) pair.
        if (basePath != null) {
            List<Effector> base;
            try { base = load(basePath); } catch (Exception e) {
                // stderr, not stdout: --json consumers parse stdout (same contract as diff/gains).
                String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                System.err.println("candor: cannot read baseline " + basePath + " (" + why + ")");
                return 2;
            }
            // ⟨0.28⟩ A DIFFERENCE IS UNSOUND IF EITHER SIDE IS PARTIAL, and the two sides fail in OPPOSITE
            // directions: a leak living in an unread unit of the CURRENT tree is missed (a false
            // all-clear at exit 0), while one living in an unread unit of the BASELINE reads as newly
            // appeared (a fabricated leak, at exit 1). So both are read — see ReportCompleteness#absorb.
            comp = comp.absorb(reportCompleteness(basePath, basePath, "containment (baseline)"));
            int bpl = commonPrefix(base).length;
            Map<String, Set<String>> baseLayers = new HashMap<>();
            for (Effector f : base)
                for (String eff : f.direct().toNames())
                    baseLayers.computeIfAbsent(eff, k -> new HashSet<>()).add(layerOf(f.fn(), bpl));
            List<String> leaks = new ArrayList<>();    // regression: a contained effect entered a NEW layer
            List<String> cleanups = new ArrayList<>(); // improvement: a contained effect LEFT a layer
            for (String eff : CONTAINED) {
                Set<String> now = byEff.containsKey(eff) ? byEff.get(eff).keySet() : Set.of();
                Set<String> was = baseLayers.getOrDefault(eff, Set.of());
                for (String layer : now) if (!was.contains(layer)) leaks.add(eff + " → " + layer);
                for (String layer : was) if (!now.contains(layer)) cleanups.add(eff + " ⊘ " + layer);
            }
            Collections.sort(leaks);
            Collections.sort(cleanups);
            if (json) {
                // A LinkedHashMap and no longer `Map.of`, which has no defined iteration order: with two
                // entries `Map.of` is a salted `MapN`, so this document's key order FLIPPED between JVM
                // runs (measured — 8 runs of the identical command gave `{cleanups,leaks}` 6 times and
                // `{leaks,cleanups}` twice). Fixed to leaks-then-cleanups, matching candor-rust's
                // serialization order, so the ⟨0.28⟩ keys have a stable place to land after them.
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("leaks", leaks);
                out.put("cleanups", cleanups);
                comp.writeJson(out);
                emit(out);
                return leaks.isEmpty() ? 0 : 1;
            }
            comp.printNote("the leak/cleanup lists below are a difference between two partially-read trees",
                    "A leak in one of those unread units is MISSING from this ratchet, and one that was "
                    + "always there but sat in an unread BASELINE unit would read as new. This verb's own "
                    + "EXIT CODE is unchanged — the rung adds a caveat, it does not refuse. " + comp.gateLine());
            if (!leaks.isEmpty()) {
                System.out.println("[AS-EFF-010] a boundary effect leaked into a layer it wasn't in:");
                for (String l : leaks) System.out.println("  " + l);
            }
            // A positive note when things got better — improvement is worth surfacing, not just failure.
            if (!cleanups.isEmpty()) {
                System.out.println((leaks.isEmpty() ? "" : "\n") + "✓ improved — a boundary effect left a layer:");
                for (String c : cleanups) System.out.println("  " + c);
            }
            if (leaks.isEmpty() && cleanups.isEmpty())
                System.out.println("candor containment: unchanged vs " + basePath + " (no leaks, no cleanups).");
            else if (leaks.isEmpty())
                // NO `✓` over a partial difference: the tick is the prose spelling of an empty `leaks`,
                // and the note above has just named units neither side was read over.
                System.out.println(comp.mustHedge()
                        ? "\ncandor containment: no regression IN WHAT CANDOR COULD SEE — see the "
                          + "INCOMPLETE note above"
                        : "\ncandor containment: no regressions ✓");
            if (!leaks.isEmpty())
                System.out.println("\nfix: keep the call in its boundary layer, or refresh the baseline if intended.");
            return leaks.isEmpty() ? 0 : 1;
        }

        // REPORT mode: the containment diagnostic.
        if (json) {
            List<Map<String, Object>> contained = new ArrayList<>();
            for (String eff : CONTAINED) {
                TreeMap<String, Integer> layers = byEff.get(eff);
                if (layers == null) continue;
                int tot = layers.values().stream().mapToInt(i -> i).sum();
                var owner = Collections.max(layers.entrySet(), Map.Entry.comparingByValue());
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("effect", eff);
                m.put("containmentPct", 100 * owner.getValue() / tot);
                m.put("layers", layers.size());
                m.put("owner", owner.getKey());
                m.put("placement", new TreeMap<>(layers));
                contained.add(m);
            }
            Map<String, Object> ambient = new LinkedHashMap<>();
            for (String eff : AMBIENT) if (byEff.containsKey(eff)) ambient.put(eff, byEff.get(eff).size());
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("layerPrefix", String.join(".", prefix));
            out.put("contained", contained);
            out.put("ambient", ambient);
            comp.writeJson(out);
            emit(out);
            return 0;
        }
        comp.printNote("the containment percentages below are computed over only the source candor read",
                "A boundary call in an unread unit is in NOBODY's layer here, so a 100% is a share of a "
                + "partial denominator. " + comp.gateLine() + " Re-scan before ratcheting.");
        System.out.println("candor containment — how well each boundary effect stays in one layer");
        System.out.println("(layers = the segment after the common root `" + String.join(".", prefix) + "`;"
                + " the signal is dispersion, NOT effect count)\n");
        System.out.printf("  %-7s %9s %7s   %s%n", "effect", "contained", "layers", "owner  ← leaked into");
        boolean any = false;
        for (String eff : CONTAINED) {
            TreeMap<String, Integer> layers = byEff.get(eff);
            if (layers == null) continue;
            any = true;
            int tot = layers.values().stream().mapToInt(i -> i).sum();
            var owner = Collections.max(layers.entrySet(), Map.Entry.comparingByValue());
            String leaks = layers.entrySet().stream()
                    .filter(e2 -> !e2.getKey().equals(owner.getKey()))
                    .sorted((a, b) -> b.getValue() - a.getValue())
                    .map(e2 -> e2.getKey() + ":" + e2.getValue())
                    .collect(Collectors.joining(", "));
            System.out.printf("  %-7s %8d%% %7d   %s%n", eff, 100 * owner.getValue() / tot, layers.size(),
                    owner.getKey() + " (" + owner.getValue() + ")" + (leaks.isEmpty() ? "" : "  ← " + leaks));
        }
        if (!any) System.out.println(comp.mustHedge()
                ? "  (no boundary effect in what candor COULD SEE — see the INCOMPLETE note above)"
                : "  (no boundary effects in the report)");
        String amb = AMBIENT.stream().filter(byEff::containsKey)
                .map(e -> e + " " + byEff.get(e).size() + "L").collect(Collectors.joining(", "));
        if (!amb.isEmpty())
            System.out.println("\n  ambient (cross-cutting expected, not scored): " + amb);
        System.out.println("\n  containment% = share of an effect's direct uses in its dominant layer; "
                + "100% = fully contained.\n  ratchet a baseline: candor containment <baseline.json> "
                + "(exit 1 if an effect leaks into a new layer).");
        return 0;
    }

    private Query() {}
}
