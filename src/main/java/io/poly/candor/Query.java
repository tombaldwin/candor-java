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
        return switch (cmd) {
            case "show" -> show(fns, a0, json);
            case "where" -> where(fns, a0, json);
            case "callers" -> callers(fns, report, a0, json, includeUnknown);
            case "map" -> map(fns, json);
            case "diff" -> diff2(a0, a1, json);
            case "containment" -> containment(fns, a0, json);
            case "reachable" -> reachable(fns, json);
            case "path" -> path(fns, a0, a1, json);
            case "impact" -> impact(fns, a0, json);
            case "blindspots" -> blindspots(fns, json, stats, classFilter);
            case "tour" -> tour(fns, report, a0, json);
            case "gains" -> gains2(a0, a1, json, strict, policyFlag);
            case "whatif" -> whatif(report, a0, a1, policyFlag, json);
            case "fix" -> fix(fns, report, a0, a1, policyFlag, json);
            case "fix-gate" -> fixGate(fns, report, policyFlag, json, strict);
            case "unverified" -> unverified(fns, report, policyFlag, json, strict, classFilter);
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
        return gains(curFns, cur, base, baseReports, json, strict);
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
        for (var r : AnalysisState.ctx().allowRules)
            allow.add(Map.of("effect", r.effect().specName(), "scope", r.scope(), "values", new ArrayList<>(r.values())));
        List<Map<String, Object>> forbid = new ArrayList<>();
        for (var r : AnalysisState.ctx().forbidRules)
            forbid.add(Map.of("from", r.from(), "to", r.to()));
        Comparator<Map<String, Object>> byJson = Comparator.comparing(JSON::toJson);
        deny.sort(byJson); allow.sort(byJson); forbid.sort(byJson);
        return JSON.toJson(Map.of("deny", deny, "allow", allow, "forbid", forbid));
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
    static int where(List<Effector> fns, String eff, boolean json) {
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
        if (json) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("effect", eff);
            m.put("directly", direct);
            m.put("inherited", inherit);
            emit(m);
            return 0;
        }
        if (direct.isEmpty() && inherit.isEmpty()) {
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

    /** Is `type` a subtype of (or equal to) `owner`, per the hierarchy sidecar? Reflexive + transitive
     *  over recorded direct supertypes/interfaces. */
    static boolean isSubtypeOf(String type, String owner, Map<String, List<String>> hier) {
        if (type.equals(owner)) return true;
        Set<String> seen = new HashSet<>();
        Deque<String> st = new ArrayDeque<>();
        st.push(type);
        while (!st.isEmpty()) {
            for (String s : hier.getOrDefault(st.pop(), List.of())) {
                if (s.equals(owner)) return true;
                if (seen.add(s)) st.push(s);
            }
        }
        return false;
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
                if (json) emit(new LinkedHashMap<>());
                else System.out.println("candor: no call graph in the report.");
                return 0;
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

    /** whatif <report> <fn> <Effect> [policy] — the PRE-EDIT verdict (mirrors candor-query). Computes the
     *  blast radius of introducing `effect` into `fn` (the fn + every transitive caller, all of which would
     *  gain it), then — given a policy — reports which of them would VIOLATE a `deny <Effect>`/`pure`
     *  boundary. Answers "if I add a network call here, what propagates and is it allowed?" BEFORE the edit.
     *  Reuses Policy.parsePolicy/scopeMatches so the verdict matches what the real gate would do. */
    static int whatif(String reportPath, String fn, String effect, String policyPath, boolean json) {
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

        if (policyPath == null) policyPath = System.getenv("CANDOR_POLICY");
        List<String[]> violations = new ArrayList<>(); // {fn, rule-desc}
        if (policyPath != null) {
            AnalysisState.ctx().denyRules.clear();
            // A SPECIFIED-but-unreadable policy must FAIL LOUD, not silently yield ok:true — a typo'd
            // CANDOR_POLICY path otherwise reads as "no violations" and an agent proceeds with a
            // forbidden edit believing the boundary was checked (/code-review; mirrors the gate's own
            // loud-on-unreadable contract and the diff/rewire path checks).
            if (!Policy.parsePolicy(policyPath)) {
                System.err.println("candor: policy `" + policyPath + "` could not be read — verdict NOT computed.");
                return 2;
            }
            for (String f : affected) {
                for (var r : AnalysisState.ctx().denyRules) {
                    boolean denies = r.effects().isEmpty() || r.effects().toNames().contains(effect);
                    if (denies && Policy.scopeMatches(f, r.scope())) {
                        String desc = r.effects().isEmpty()
                                ? "pure" + (r.scope().isEmpty() ? "" : " " + r.scope())
                                : "deny " + effect + (r.scope().isEmpty() ? "" : " " + r.scope());
                        violations.add(new String[]{f, desc});
                        break;
                    }
                }
            }
        }

        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("of", targets);
            out.put("effect", effect);
            out.put("affected", new ArrayList<>(affected));
            List<Map<String, String>> vs = new ArrayList<>();
            for (String[] v : violations) vs.add(Map.of("fn", v[0], "rule", v[1]));
            out.put("violations", vs);
            out.put("ok", violations.isEmpty());
            emit(out);
            return violations.isEmpty() ? 0 : 1;
        }
        System.out.println("whatif: adding `" + effect + "` to `" + String.join(", ", targets) + "`");
        System.out.println("  → propagates to " + affected.size() + " function(s) (the blast radius):");
        for (String f : affected) System.out.println("      " + f);
        if (policyPath == null) {
            System.out.println("  (no policy given — pass a policy file or set CANDOR_POLICY for the gate verdict)");
            return 0;
        }
        if (violations.isEmpty()) {
            System.out.println("  ✓ within policy — this edit introduces no `deny`/`pure` boundary violation.");
            return 0;
        }
        System.out.println("  ⚠ WOULD VIOLATE policy (" + violations.size() + ") — run BEFORE the edit:");
        for (String[] v : violations) System.out.println("      [AS-EFF-006] `" + v[0] + "`  (rule: `" + v[1] + "`)");
        return 1;
    }

    /** The deny/`pure` scope (the "layer") that forbids `effect` at `fn`, or null if performing it there is
     *  allowed. Mirrors the gate's own AS-EFF-006 predicate (Policy.checkPolicy): a `deny` fires when it
     *  names the effect; a `pure` rule (empty effects) forbids every real effect but not Unknown. Reads the
     *  parsed deny rules from the thread-local context (the caller must have parsed a policy first). */
    static String deniedLayer(String fn, String effect) {
        for (var r : AnalysisState.ctx().denyRules) {
            boolean denies = r.effects().isEmpty() ? !effect.equals("Unknown") : r.effects().toNames().contains(effect);
            if (denies && Policy.scopeMatches(fn, r.scope())) return r.scope();
        }
        return null;
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
     *  Returns the direct site(s), the denied span, and the hoist frontier. Shared by `fix` and `fix-gate`. */
    static Remedy computeRemedy(String start, String effect, String layer,
                                Map<String, List<String>> cg, Map<String, List<String>> rev,
                                Map<String, Effector> byName) {
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
            if (deniedLayer(a, effect) != null) deniedSpan.add(a); // a site that is itself in the denied layer
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
                if (deniedLayer(caller, effect) != null) {
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
                if (deniedLayer(caller, effect) != null) {
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
     *  contract as `whatif`. Returns true on success; on failure prints the reason and the caller returns 2. */
    private static boolean loadPolicyOrFail(String policyPath, String who) {
        if (policyPath == null) policyPath = System.getenv("CANDOR_POLICY");
        if (policyPath == null) {
            System.err.println("candor " + who + ": a policy is required (pass a policy file or set CANDOR_POLICY) — the fix is the refactor that restores the boundary the edit crossed.");
            return false;
        }
        AnalysisState.ctx().denyRules.clear();
        if (!Policy.parsePolicy(policyPath)) {
            System.err.println("candor: policy `" + policyPath + "` could not be read — no fix computed.");
            return false;
        }
        return true;
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
    static int fix(List<Effector> fns, String reportPath, String fn, String effect, String policyPath, boolean json) {
        if (fn == null || effect == null) return usage("fix <fn> <Effect> [--report <locator>] [--policy <file>] [--json]");
        if (!Rules.KNOWN_EFFECTS.contains(effect) && !effect.equals("Unknown")) {
            System.err.println("candor: unknown effect `" + effect + "` (expected one of " + Rules.KNOWN_EFFECTS + " or Unknown)");
            return 2;
        }
        if (!loadPolicyOrFail(policyPath, "fix")) return 2;

        Map<String, Effector> byName = new HashMap<>();
        for (Effector f : fns) byName.put(f.fn(), f);
        Map<String, List<String>> cg = fixGraph(reportPath, fns);
        Map<String, List<String>> rev = reverseGraph(cg);

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
            System.out.println("candor fix: `" + start + "` does not perform " + effect + " — nothing to hoist.");
            return 0;
        }
        String layer = deniedLayer(start, effect);
        if (layer == null) {
            System.out.println("candor fix: `" + start + "` performs " + effect
                    + ", but no policy forbids it there — the boundary isn't crossed, nothing to fix.");
            return 0;
        }
        Remedy plan = computeRemedy(start, effect, layer, cg, rev, byName);
        if (json) {
            emit(plan.toJson());
            return 0;
        }
        StringBuilder sb = new StringBuilder();
        plan.renderText(sb);
        System.out.print(sb);
        System.out.println("\n  (Advisory: candor names the shape, you write the code; the gate re-scan verifies the fix.)");
        return 0;
    }

    /** fix-gate <report> [policy] — a remedy for EVERY deny/`pure` (AS-EFF-006) boundary crossing in the
     *  report, collapsing the inheritors of one root cause to a single plan. The edit-time loop folds this
     *  into the block message so the agent gets the FIX, not just the finding. Scope is AS-EFF-006 only —
     *  the one refactor candor can compute; allowlist/layering findings are a different shape. */
    static int fixGate(List<Effector> fns, String reportPath, String policyPath, boolean json, boolean strict) {
        if (!loadPolicyOrFail(policyPath, "fix-gate")) return 2;

        Map<String, Effector> byName = new HashMap<>();
        for (Effector f : fns) byName.put(f.fn(), f);
        Map<String, List<String>> cg = fixGraph(reportPath, fns);
        Map<String, List<String>> rev = reverseGraph(cg);

        Map<String, Remedy> plans = new TreeMap<>();
        for (Effector f : fns) {
            for (String effect : f.inferred().toNames()) {
                String layer = deniedLayer(f.fn(), effect);
                if (layer != null) {
                    Remedy p = computeRemedy(f.fn(), effect, layer, cg, rev, byName);
                    plans.putIfAbsent(p.dedupKey(), p);
                }
            }
        }
        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", plans.isEmpty());
            List<Map<String, Object>> rem = new ArrayList<>();
            for (Remedy p : plans.values()) rem.add(p.toJson());
            out.put("remedies", rem);
            emit(out);
            // Advisory by default (exit 0 — the agent fix-loop reads the remedy and edits); `--strict` makes
            // the exit follow `ok`, so CI can REQUIRE zero outstanding crossings (mirrors `unverified --strict`).
            return strict && !plans.isEmpty() ? 1 : 0;
        }
        if (plans.isEmpty()) {
            System.out.println("candor fix-gate: no deny/pure boundary crossings in this report ✓");
            return 0;
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
        if (strict) {
            System.out.println("  (--strict: " + n + " outstanding boundary crossing(s) → exit 1)");
            return 1;
        }
        return 0;
    }

    /** unverified <report> [policy] — the PROVABLE-PURITY disclosure (eval/fixloop/DISPATCH-NOTE.md, mirrors
     *  candor-query). A `pure`/`deny E` layer PASSES a function that carries none of its forbidden effects —
     *  but if that function is Unknown (an unresolvable call), the pass is UNVERIFIED: the Unknown could hide
     *  the very effect the rule forbids (the fn/closure-port hole). Names each such function + the
     *  `deny E Unknown <scope>` upgrade. Advisory (exit 0); `--strict` → exit 1. The gate verdict is untouched. */
    static int unverified(List<Effector> fns, String reportPath, String policyPath, boolean json,
                          boolean strict, Set<ReasonClass> classFilter) {
        if (!loadPolicyOrFail(policyPath, "unverified")) return 2;
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
        Policy.GateInput gi = null;
        if (classFilter != null) {
            // The RAW `unknownWhy` strings, for the reason Policy#gateInputFromReport documents: a
            // colon-free tag (`missing-config`) is dropped by `UnknownReason.parse`, so reading the parsed
            // reasons would silently reclassify a `setup` entry as `unresolved` and put it back inside
            // `--class dynamic`, which by definition excludes `setup`.
            Envelope env;
            try {
                env = readEnvelope(reportPath);
            } catch (Exception e) {
                String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                System.err.println("candor unverified: --class needs the report's reason channel, but "
                        + reportPath + " could not be re-read (" + why + ")");
                return 2;
            }
            gi = Policy.gateInputFromReport(fns, env.rawUnknownWhy());
        }
        final Policy.GateInput gin = gi;
        java.util.function.Predicate<Effector> classMatch =
                f -> Policy.reasonClassMatches(gin, f.fn(), classFilter);
        List<Hole> holes = new ArrayList<>();
        for (Effector e : fns) {
            // Same predicate as the gate note (Policy.unverifiedHoleRule) — one definition of a hole.
            PolicyRule.Deny r = Policy.unverifiedHoleRule(e.fn(), e.inferred(), deny);
            if (r != null && classMatch.test(e)) holes.add(new Hole(e, r));
        }
        if (json) {
            List<Map<String, Object>> items = new ArrayList<>();
            for (Hole h : holes) {
                String[] ru = Policy.ruleUpgrade(h.rule());
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", h.fn().fn());
                m.put("rule", ru[0]);
                m.put("unknownWhy", h.fn().unknownWhy().stream().sorted().map(UnknownReason::format).toList());
                m.put("upgrade", ru[1]);
                items.add(m);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", holes.isEmpty());
            out.put("unverified", items);
            emit(out);
            return strict && !holes.isEmpty() ? 1 : 0;
        }
        if (holes.isEmpty()) {
            System.out.println("candor unverified: every function in a pure/deny layer is PROVABLY clean (no Unknown holes) ✓");
            return 0;
        }
        System.out.println("candor unverified — " + holes.size() + " function(s) PASS their policy but aren't PROVABLY clean:\n");
        TreeSet<String> upgrades = new TreeSet<>();
        for (Hole h : holes) {
            String[] ru = Policy.ruleUpgrade(h.rule());
            upgrades.add(ru[1]);
            String why = h.fn().unknownWhy().isEmpty() ? "an unresolvable call"
                    : h.fn().unknownWhy().stream().sorted().map(UnknownReason::format).collect(Collectors.joining(", "));
            System.out.println("  `" + h.fn().fn() + "`  (in `" + ru[0] + "`)");
            System.out.println("     is Unknown (" + why + ") — candor can't confirm it's free of the forbidden effect(s);");
            System.out.println("     the Unknown could hide the very effect the rule forbids (e.g. a fn/closure-injected port).");
            System.out.println("     → make it provable:  add  `" + ru[1] + "`");
            System.out.println();
        }
        System.out.println("  The gate still PASSES — this is advisory. To REQUIRE provable purity, add:");
        for (String u : upgrades) System.out.println("      " + u);
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
     * The check is per (rule, function), not per policy, so a scoped rule whose matched functions all carry
     * their evidence evaluates normally; only the rule that would have been silently narrowed is refused.
     */
    static String unanswerableScopedFilter(Policy.GateInput gi) {
        for (PolicyRule.Deny r : AnalysisState.ctx().denyRules) {
            for (var e : new TreeMap<>(gi.inferred()).entrySet()) {
                String fn = e.getKey();
                if (!Policy.scopeMatches(fn, r.scope())) continue;
                List<String> names = e.getValue().toNames();
                if (!r.netClasses().isEmpty() && names.contains("Net")
                        && gi.netClasses().getOrDefault(fn, List.of()).isEmpty())
                    return "`" + r.src().trim() + "` narrows on the Net DESTINATION CLASS, but `" + fn
                            + "` carries Net with no `netClass` in this report — the field the filter reads "
                            + "is absent, so the narrowing would succeed for lack of evidence and drop a Net "
                            + "the bare `deny Net` catches. Refusing (exit 2) rather than passing: an absent "
                            + "optional field must not relax a fail-closed gate. Use the bare `deny Net`, or "
                            + "gate at scan time.";
                if (!r.unknownClasses().isEmpty() && names.contains("Unknown")
                        && gi.reasonClasses().getOrDefault(fn, new TreeSet<>()).isEmpty())
                    return "`" + r.src().trim() + "` narrows on the Unknown REASON CLASS, but `" + fn
                            + "` carries Unknown with no reason reachable in this report — neither its own "
                            + "`unknownWhy` nor a `calls` edge to one. §6.2 requires the class set to resolve "
                            + "TRANSITIVELY over the gate's reach; with the channel missing, every narrowed "
                            + "filter silently tolerates while only the bare `deny Unknown` fires. Refusing "
                            + "(exit 2). Use the bare `deny Unknown`, or gate at scan time.";
            }
        }
        return null;
    }

    /** The §2 ENVELOPE facts the gate verdict needs, none of which survive {@link #load} (which returns
     *  only the {@code functions} array): the ⟨0.21⟩ completeness manifest, the ⟨0.15⟩ κ-coverage ledger,
     *  and the RAW {@code unknownWhy} strings (see {@link Policy#gateInputFromReport}). Read from the SAME
     *  file, in one pass — no sidecar, no second locator. */
    record Envelope(int analyzedCount, List<String[]> unanalyzed, List<Map.Entry<String, Integer>> uncovered,
                    Map<String, List<String>> rawUnknownWhy, String packageName) {}

    static Envelope readEnvelope(String path) throws Exception {
        JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
        Map<String, List<String>> raw = new HashMap<>();
        List<String[]> unanalyzed = new ArrayList<>();
        List<Map.Entry<String, Integer>> uncovered = new ArrayList<>();
        int analyzed = 0;
        String pkg = null;                 // §2 `package`/`packages` — for the judged-nothing advisory
        JsonArray fns = null;
        if (root.isJsonObject()) {
            JsonObject o = root.getAsJsonObject();
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
        return new Envelope(analyzed, unanalyzed, uncovered, raw, pkg);
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
        if (surplus != null) {
            System.err.println("candor gate: unexpected argument `" + surplus + "` (usage: candor gate "
                    + "--report <locator> --policy <file> [--json] [--gate-json <file>])");
            return 2;
        }
        if (policyPath == null) policyPath = System.getenv("CANDOR_POLICY");
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
        AnalysisState.ctx().unknownAliases.putAll(Config.forTarget(Path.of(policyPath)).unknownAliases());
        if (!Policy.parsePolicy(policyPath)) {
            System.err.println("candor gate: policy file " + policyPath
                    + " could not be read — failing (exit 2), policy NOT evaluated");
            return 2;
        }
        // The answerability refusals (see the javadoc). Loud, exit 2, naming the rule and the reason.
        if (!AnalysisState.ctx().forbidRules.isEmpty()) {
            System.err.println("candor gate: this policy has " + AnalysisState.ctx().forbidRules.size()
                    + " `forbid` rule(s), which `gate --report` cannot evaluate — a report's `calls` graph is "
                    + "EFFECT-RELEVANT, so a crossing into a wholly pure unit is invisible in it and the rule "
                    + "would read green where a scan fails. Gate layering at scan time: candor <classes> --policy "
                    + policyPath);
            return 2;
        }
        if (!AnalysisState.ctx().allowRules.isEmpty()) {
            List<String> effects = AnalysisState.ctx().allowRules.stream()
                    .map(r -> r.effect().specName()).distinct().sorted().collect(Collectors.toList());
            System.err.println("candor gate: this policy has `allow " + String.join("`/`", effects)
                    + "` rule(s), which `gate --report` cannot evaluate — the AS-EFF-008 surface-completeness "
                    + "marker does not ride the report wire, so a benign visible literal beside a "
                    + "runtime-computed endpoint would be CERTIFIED here and flagged by a scan. (`netClass: "
                    + "unknown-host` is NOT that marker — it also names a merely unrecognised host.) Gate "
                    + "allowlists at scan time: candor <classes> --policy " + policyPath);
            return 2;
        }

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
                System.err.println("candor gate: cannot read report " + reportPath + " (" + why + ")"
                        + (reportPaths.size() > 1 ? " — refusing to gate over a report set one of whose "
                        + reportPaths.size() + " reports did not load; a green verdict would rest on which "
                        + "files happened to be readable" : ""));
                return 2;
            }
            analyzedCount += env.analyzedCount();
            unanalyzed.addAll(env.unanalyzed());
            uncovered.addAll(env.uncovered());
            // A repeated `fn` across reports joins by UNION here too — same direction as the entry join.
            for (var e : env.rawUnknownWhy().entrySet())
                rawWhy.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).addAll(e.getValue());
            if (env.analyzedCount() == 0)
                judgedNothing.add((env.packageName() != null ? env.packageName() : "<unnamed package>")
                        + " (" + reportPath + ")");
        }
        if (reportPaths.size() > 1)
            System.err.println("candor gate: locator names " + reportPaths.size()
                    + " reports — gating over all of them as one analysis world (§2): "
                    + String.join(", ", reportPaths));
        Policy.GateInput gi = Policy.gateInputFromReport(fns, rawWhy);

        // THE THIRD ANSWERABILITY CASE, and the only one that depends on the REPORT rather than the policy
        // alone. See #unanswerableScopedFilter — a class-scoped `deny` NARROWS the gate, and a narrowing is
        // sound only where the report can answer the narrowing question.
        String unanswerable = unanswerableScopedFilter(gi);
        if (unanswerable != null) {
            System.err.println("candor gate: " + unanswerable);
            return 2;
        }

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
        int violations;
        try {
            violations = Policy.gate(gi);
        } finally {
            Candor.diagOut = prior;
        }
        if (violations == 0) human.println("candor-java: no violations");
        else human.println("→ candor fix-gate names the remedy for each");

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

        var facts = new Candor.GateFacts(analyzedCount, unanalyzed, uncovered);
        // `--json` IS `--gate-json -`: the verb's machine output is the gate verdict, the same document and
        // the same builder the scan writes, so a consumer cannot tell the two routes apart from the output.
        if (json) Candor.writeGateJson("-", violations, facts);
        if (gateJsonPath != null) Candor.writeGateJson(gateJsonPath, violations, facts);
        if (violations > 0) return 1;
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
            for (var e : dropped.entrySet()) ds.add(Map.of("caller", e.getKey(), "no_longer_calls", e.getValue()));
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
    static int map(List<Effector> fns, boolean json) {
        Map<String, TreeSet<String>> mods = new HashMap<>();
        Map<String, Integer> counts = new HashMap<>();
        for (Effector f : fns) {
            int dot = f.fn().lastIndexOf('.');
            String mod = dot > 0 ? f.fn().substring(0, dot) : f.fn(); // declaring class
            mods.computeIfAbsent(mod, k -> new TreeSet<>())
                    .addAll(f.inferred().without(Effect.UNKNOWN).toNames());
            counts.merge(mod, 1, Integer::sum);
        }
        if (json) {
            Map<String, Object> out = new TreeMap<>();
            for (var m : mods.keySet()) {
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("effects", new ArrayList<>(mods.get(m)));
                v.put("functions", counts.get(m));
                out.put(m, v);
            }
            emit(out);
            return 0;
        }
        if (mods.isEmpty()) {
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
    static int gains(List<Effector> cur, String curPath, String basePath, List<String> baseReports, boolean json, boolean strict) {
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

    static int blindspots(List<Effector> fns, boolean json, boolean stats, Set<ReasonClass> classFilter) {
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
                emit(out);
                return 0;
            }
            if (sources == 0) {
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
            emit(out);
            return 0;
        }
        if (sources.isEmpty()) {
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
    static int tour(List<Effector> fns, String reportPath, String arg, boolean json) {
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
            // Pure JSON to stdout, compact (no pretty-printing) — matches the Rust reference's
            // serde_json::to_string. The shared JSON serializer here pretty-prints, so build a compact one.
            System.out.println(new GsonBuilder().create().toJson(out));
            return 0;
        }

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
                    + "Run `candor blindspots`; unresolvable imports or missing project config are the usual cause.");
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
            if (json) emit(Map.of("fn", start.fn(), "effect", effect, "path", List.of()));
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
            if (json) emit(Map.of("fn", start.fn(), "effect", effect, "path", List.of(),
                    "note", "source not locally traceable"));
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
            emit(Map.of("fn", start.fn(), "effect", effect, "path", steps));
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
    static int reachable(List<Effector> fns, boolean json) {
        List<Effector> entries = fns.stream().filter(f -> f.entryPoint())
                .sorted(Comparator.comparing(f -> f.fn())).toList();
        TreeMap<String, List<String>> byEffect = new TreeMap<>();
        for (Effector f : entries)
            for (String e : f.inferred().toNames()) byEffect.computeIfAbsent(e, k -> new ArrayList<>()).add(f.fn());

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
            System.out.println(JSON.toJson(out));
            return 0;
        }

        System.out.println("candor reachable — effects the program performs at runtime "
                + "(union over " + entries.size() + " entry point" + (entries.size() == 1 ? "" : "s") + ")");
        if (entries.isEmpty()) {
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
    static int containment(List<Effector> fns, String basePath, boolean json) {
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
                emit(Map.of("leaks", leaks, "cleanups", cleanups));
                return leaks.isEmpty() ? 0 : 1;
            }
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
                System.out.println("\ncandor containment: no regressions ✓");
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
            emit(out);
            return 0;
        }
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
        if (!any) System.out.println("  (no boundary effects in the report)");
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
