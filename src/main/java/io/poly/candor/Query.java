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
                    "blindspots", "tour", "gains", "whatif", "fix", "fix-gate", "unverified", "rewire");
    static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();

    // Boundary effects SHOULD live in a dedicated layer — their dispersion is the architecture signal
    // (NOT raw counts, which are domain-dependent). Ambient effects are expected to be cross-cutting
    // (logging/timestamps everywhere is fine), so they're reported but not scored. Unknown is excluded
    // (it's a visibility metric, not an effect). MEMBERSHIP is DERIVED from the §6.1 partition on the
    // Effect enum (the single source of truth, so adding an effect can't leave these stale); ORDER follows
    // the historical §6.1 display priority below (so the `containment` output stays stable), with any
    // effect beyond that list trailing alphabetically.
    private static final List<String> DISPLAY_ORDER =
            List.of("Db", "Net", "Exec", "Fs", "Ipc", "Log", "Clock", "Rand", "Env");
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
     *  matching report file (sidecars — `.callgraph.json`/`.hierarchy.json` — are excluded). Returns null
     *  (with a stderr reason) when a dir/prefix names no report file. */
    static String resolveReportLocator(String locator) {
        Path p = Path.of(locator);
        if (locator.endsWith(".json")) return locator;              // rule 2: a full report path, verbatim
        if (Files.isDirectory(p))                                    // rule 1: a directory → its .candor/report prefix
            return expandPrefix(p.resolve(".candor").resolve("report").toString(), locator);
        return expandPrefix(locator, locator);                      // rule 3: a bare prefix
    }

    /** Expand a report PREFIX (`<dir>/report`) to the single report file `<prefix>.<crate>.<backend>.json`
     *  beside it — the §3.3.1/§3.4 form the other engines write. A `.callgraph.json`/`.hierarchy.json`
     *  sidecar is NOT a report (it has a 3rd dotted segment before `.json`, or its middle segment is a
     *  sidecar tag). When exactly one report matches, use it; when several do, take the lexicographically
     *  first (deterministic — the Java engine loads ONE report, unlike the Rust lint's multi-crate union),
     *  and disclose the choice. `original` is the user-typed locator, for the error message. Returns null
     *  when nothing matches. */
    static String expandPrefix(String prefix, String original) {
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
                if (name.endsWith(".callgraph.json") || name.endsWith(".hierarchy.json")) return; // sidecars aren't reports
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
        if (hits.isEmpty()) {
            System.err.println("candor: no report found for locator `" + original + "` (looked for "
                    + dot + "*.json under " + dir + ")");
            return null;
        }
        Collections.sort(hits);
        if (hits.size() > 1)
            System.err.println("candor: locator `" + original + "` matches " + hits.size()
                    + " reports; using " + hits.get(0));
        return hits.get(0);
    }

    /** DISCOVER the report when no `--report` was given (SPEC §3.3.1): a `CANDOR_REPORT` env var overrides;
     *  else walk UP from the CWD for a `.candor/` directory and use its `report` prefix (the §3.4 config
     *  discovery mechanism, applied to the report). Returns the resolved report path, or null (with a
     *  stderr reason) when no `.candor/` is found or the prefix names no report. */
    static String discoverReport() {
        String override = System.getenv("CANDOR_REPORT");
        if (override != null && !override.isEmpty()) return resolveReportLocator(override);
        Path p = Path.of("").toAbsolutePath();
        for (; p != null; p = p.getParent()) {
            Path candor = p.resolve(".candor");
            if (Files.isDirectory(candor))
                return expandPrefix(candor.resolve("report").toString(), candor.resolve("report").toString());
        }
        System.err.println("candor: no report given and no `.candor/` directory found walking up from the CWD "
                + "— pass --report <locator> or set CANDOR_REPORT.");
        return null;
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
                return n.startsWith(dot) && n.endsWith(".json")
                        && !n.endsWith(".callgraph.json") && !n.endsWith(".hierarchy.json");
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
        String reportFlag = null;       // --report <locator> (canonical §3.3.1)
        String policyFlag = null;       // --policy <file> (canonical §3.3.1)
        List<String> pos = new ArrayList<>();
        Set<String> known = java.util.Set.of("--json", "--include-unknown", "--strict", "--report", "--policy");
        String usage = "candor " + cmd + " <verb-args…> [--report <locator>] [--policy <file>] [--json] [--strict] [--include-unknown]";
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--json" -> json = true;
                case "--include-unknown" -> includeUnknown = true;
                case "--strict" -> strict = true;
                case "--report" -> {
                    if (i + 1 >= args.length) { System.err.println("candor: --report needs a <locator> (usage: " + usage + ")"); return 2; }
                    reportFlag = args[++i];
                }
                case "--policy" -> {
                    if (i + 1 >= args.length) { System.err.println("candor: --policy needs a <file> (usage: " + usage + ")"); return 2; }
                    policyFlag = args[++i];
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
        boolean explicitReportGiven = false; // did the user name a report (via --report or a leading locator)?
        if (TWO_REPORT.contains(cmd)) {
            // diff/gains/rewire: two positional locators <current> <baseline>. No discovery, no --report.
            if (reportFlag != null)
                System.err.println("candor: --report is ignored for `" + cmd + "` — it takes two positional report locators <current> <baseline>.");
        } else if (reportFlag != null) {
            explicitReportGiven = true;
            report = resolveReportLocator(reportFlag);
            if (report == null) return 2;
        } else if (pos.size() > canonicalArity(cmd)
                && (looksLikeReport(pos.get(0)) || explicitLocatorShape(pos.get(0)))) {
            // DEPRECATED: a leading-positional report (surplus + report-shaped). Consume it, warn, resolve it
            // the same 3 ways. When it names nothing, load() below fails loud with the locator in parens.
            explicitReportGiven = true;
            System.err.println("candor: the leading-positional report is deprecated — use `--report " + pos.get(0)
                    + "` (report discovery + --report is the canonical §3.3.1 grammar). Still accepted for now.");
            report = resolveReportLocator(pos.remove(0));
            if (report == null) return 2;
        } else {
            // canonical: discover the report (walk up for .candor/, or CANDOR_REPORT).
            report = discoverReport();
            if (report == null) return 2;
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

        // The comparative verbs load their reports themselves (two positionals); the rest load `report`.
        List<Effector> fns = List.of();
        if (!TWO_REPORT.contains(cmd)) {
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
            case "blindspots" -> blindspots(fns, json);
            case "tour" -> tour(fns, report, a0, json);
            case "gains" -> gains2(a0, a1, json);
            case "whatif" -> whatif(report, a0, a1, policyFlag, json);
            case "fix" -> fix(fns, report, a0, a1, policyFlag, json);
            case "fix-gate" -> fixGate(fns, report, policyFlag, json);
            case "unverified" -> unverified(fns, policyFlag, json, strict);
            case "rewire" -> rewire2(a0, a1, json);
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

    /** `gains <current> <baseline>` (§3.3.1 two-positional): as {@link #diff2}, for the supply-chain gain. */
    static int gains2(String curLoc, String baseLoc, boolean json) {
        if (curLoc == null) return usage("gains <current> <baseline> [--json]");
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
        return gains(curFns, cur, base, json);
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
        for (var r : AnalysisState.ctx().denyRules)
            deny.add(Map.of("effects", r.effects().toNames(), "scope", r.scope()));
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
        if (q == null) return usage("show <report.json> <function-substring> [--json]");
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
        if (eff == null) return usage("where <report.json> <Effect> [--json]");
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
        if (q == null) return usage("callers <report.json> <function-substring> [--json] [--include-unknown]");
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
        String cgPath = reportPath.endsWith(".json")
                ? reportPath.substring(0, reportPath.length() - 5) + ".callgraph.json"
                : reportPath + ".callgraph.json";
        if (!Files.exists(Path.of(cgPath))) return null; // no sidecar — silent fallback is correct
        try {
            var o = JsonParser.parseString(Files.readString(Path.of(cgPath))).getAsJsonObject();
            Map<String, List<String>> cg = new LinkedHashMap<>();
            for (var e : o.entrySet()) {
                List<String> callees = new ArrayList<>();
                for (JsonElement v : e.getValue().getAsJsonArray()) callees.add(v.getAsString());
                cg.put(e.getKey(), callees);
            }
            return cg;
        } catch (Exception e) {
            System.err.println("candor: call-graph sidecar " + cgPath
                    + " is unreadable (" + e.getClass().getSimpleName()
                    + ") — the call graph may be incomplete; falling back to the report's inline edges.");
            return null;
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
            if (!obj.has("package") || !obj.get("package").isJsonPrimitive()) return null;
            String pkg = obj.get("package").getAsString();
            return pkg.isEmpty() ? null : pkg;
        } catch (Exception e) {
            return null;
        }
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
            if (json) emit(new LinkedHashMap<>());
            else System.out.println("candor: no function matching `" + q + "` found in the call graph.");
            return 0;
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
        // absent (hier == null), fall back to a simple-name match, which OVER-lists — the safe direction
        // for a lower-bound disclosure. candor never asserts these; they are disclosed as "cannot confirm".
        List<Map<String, String>> possible = new ArrayList<>();
        if (incl) {
            Set<String> confirmed = new HashSet<>(all);
            confirmed.addAll(targets);
            // confirmed reachers indexed by simple method name -> their declaring types (for the subtype check)
            Map<String, List<String>> reacherTypesByMethod = new HashMap<>();
            for (String r : confirmed)
                reacherTypesByMethod.computeIfAbsent(simpleMethod(r), k -> new ArrayList<>()).add(declaringType(r));
            for (var e : new TreeMap<>(broadByFn).entrySet()) {
                if (confirmed.contains(e.getKey())) continue; // already a confirmed caller — not "additional"
                TreeSet<String> hits = new TreeSet<>();
                for (String key : e.getValue()) { // key = OWNER.M (dotted)
                    String m = simpleMethod(key);
                    String owner = declaringType(key);
                    List<String> reacherTypes = reacherTypesByMethod.get(m);
                    if (reacherTypes == null) continue;
                    boolean hit = hier == null // no hierarchy sidecar → simple-name match (over-lists)
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
        if (fn == null || effect == null) return usage("whatif <report.json> <fn> <Effect> [policy] [--json]");
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
            String layerLabel = layer.isEmpty() ? "this" : "`" + layer + "`";
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
        if (fn == null || effect == null) return usage("fix <report.json> <fn> <Effect> [policy] [--json]");
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
    static int fixGate(List<Effector> fns, String reportPath, String policyPath, boolean json) {
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
            return 0;
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
        return 0;
    }

    /** unverified <report> [policy] — the PROVABLE-PURITY disclosure (eval/fixloop/DISPATCH-NOTE.md, mirrors
     *  candor-query). A `pure`/`deny E` layer PASSES a function that carries none of its forbidden effects —
     *  but if that function is Unknown (an unresolvable call), the pass is UNVERIFIED: the Unknown could hide
     *  the very effect the rule forbids (the fn/closure-port hole). Names each such function + the
     *  `deny E Unknown <scope>` upgrade. Advisory (exit 0); `--strict` → exit 1. The gate verdict is untouched. */
    static int unverified(List<Effector> fns, String policyPath, boolean json, boolean strict) {
        if (!loadPolicyOrFail(policyPath, "unverified")) return 2;
        List<PolicyRule.Deny> deny = AnalysisState.ctx().denyRules;
        record Hole(Effector fn, PolicyRule.Deny rule) {}
        List<Hole> holes = new ArrayList<>();
        for (Effector e : fns) {
            // Same predicate as the gate note (Policy.unverifiedHoleRule) — one definition of a hole.
            PolicyRule.Deny r = Policy.unverifiedHoleRule(e.fn(), e.inferred(), deny);
            if (r != null) holes.add(new Hole(e, r));
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
            System.out.println("candor: cannot read baseline " + basePath);
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
     *  between releases. {gained:[Effect], byFunction:[{fn,effect}]} — the cross-engine machine-readable form.
     *  Always exit 0 (candor-ts parity: the gained-effect exit-1 contract belongs to `diff` alone; gains is
     *  a pure disclosure whose consumers read the JSON, not the exit code). */
    static int gains(List<Effector> cur, String curPath, String basePath, boolean json) {
        if (basePath == null) return usage("gains <report.json> <baseline.json> [--json]");
        List<Effector> base;
        try {
            base = load(basePath);
        } catch (Exception e) {
            System.out.println("candor: cannot read baseline " + basePath);
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
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("fn", fn);
                    m.put("effect", e);
                    byFunction.add(m);
                }
            }
        }
        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            // provenance first (unconditional, "" when unknown), then the gains — the candor-ts order.
            out.put("baseline_version", baseV == null ? "" : baseV);
            out.put("engine_version", engineV == null ? "" : engineV);
            out.put("gained", new ArrayList<>(gained));
            out.put("byFunction", byFunction);
            emit(out);
            return 0;
        }
        for (Map<String, Object> m : byFunction) System.out.println(m.get("fn") + "\t" + m.get("effect"));
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
    static int blindspots(List<Effector> fns, boolean json) {
        Map<String, List<String>> rev = new HashMap<>();
        for (Effector f : fns) for (String c : f.calls()) rev.computeIfAbsent(c, k -> new ArrayList<>()).add(f.fn());
        int totalUnknown = (int) fns.stream().filter(f -> f.inferred().hasUnknown()).count();
        List<Map<String, Object>> sources = new ArrayList<>();
        for (Effector f : fns) {
            if (f.unknownWhy() == null || f.unknownWhy().isEmpty()) continue; // a SOURCE carries its own why
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
            // Pure JSON to stdout, compact (no pretty-printing) — matches the Rust reference's
            // serde_json::to_string. The shared JSON serializer here pretty-prints, so build a compact one.
            System.out.println(new GsonBuilder().create().toJson(out));
            return 0;
        }

        if (finds.isEmpty()) {
            // Effectful-but-nothing-surprising vs genuinely-pure both land here; either way the honest line
            // is the useful answer (never a manufactured surprise) — mirrors the scan-note fallback.
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
        if (fnArg == null) return usage("impact <report.json> <fn-substring> [--json]");
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
            return usage("path <report.json> <fn-substring> <Effect> [--json]");
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
                System.out.println("candor: cannot read baseline " + basePath); return 2;
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
                + "100% = fully contained.\n  ratchet a baseline: candor containment <report> <baseline.json> "
                + "(exit 1 if an effect leaks into a new layer).");
        return 0;
    }

    private Query() {}
}
