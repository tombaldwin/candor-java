package candor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

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
                    "whatif", "rewire");
    static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();

    // Boundary effects SHOULD live in a dedicated layer — their dispersion is the architecture signal
    // (NOT raw counts, which are domain-dependent). Ambient effects are expected to be cross-cutting
    // (logging/timestamps everywhere is fine), so they're reported but not scored. Unknown is excluded
    // (it's a visibility metric, not an effect).
    static final List<String> CONTAINED = List.of("Db", "Net", "Exec", "Fs", "Ipc");
    static final List<String> AMBIENT = List.of("Log", "Clock", "Rand", "Env");

    /** One report entry (only the fields the queries read; gson ignores the rest). */
    static final class Fn {
        String fn = "";
        String loc = "";
        List<String> inferred = List.of();
        List<String> direct = List.of();
        List<String> calls = List.of();
        List<String> fs = List.of();
        List<String> hosts = List.of();
        boolean unresolved;
        boolean entryPoint;
    }

    static List<Fn> load(String path) throws Exception {
        JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
        // v0.2 self-describing envelope { candor, functions:[...] } OR legacy v0.1 bare array [...].
        JsonArray arr = root.isJsonObject()
                ? root.getAsJsonObject().getAsJsonArray("functions")
                : (root.isJsonArray() ? root.getAsJsonArray() : null);
        if (arr == null) return List.of();
        List<Fn> fns = new Gson().fromJson(arr, new TypeToken<List<Fn>>() {}.getType());
        for (Fn f : fns) { // gson leaves absent optional arrays null — normalize
            if (f.inferred == null) f.inferred = List.of();
            if (f.direct == null) f.direct = List.of();
            if (f.calls == null) f.calls = List.of();
            if (f.fs == null) f.fs = List.of();
            if (f.hosts == null) f.hosts = List.of();
            if (f.loc == null) f.loc = "";
        }
        fns.sort(Comparator.comparing(f -> f.fn));
        return fns;
    }

    static int run(String[] args) {
        String cmd = args[0];
        boolean json = false;
        List<String> pos = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--json")) json = true;
            else pos.add(args[i]);
        }
        if (pos.isEmpty()) {
            System.err.println("usage: candor " + cmd + " <report.json> [arg] [--json]");
            return 2;
        }
        List<Fn> fns;
        try {
            fns = load(pos.get(0));
        } catch (Exception e) {
            System.err.println("candor: cannot read report " + pos.get(0));
            return 2;
        }
        String arg = pos.size() > 1 ? pos.get(1) : null;
        String arg2 = pos.size() > 2 ? pos.get(2) : null;
        return switch (cmd) {
            case "show" -> show(fns, arg, json);
            case "where" -> where(fns, arg, json);
            case "callers" -> callers(fns, pos.get(0), arg, json);
            case "map" -> map(fns, json);
            case "diff" -> diff(fns, arg, json);
            case "containment" -> containment(fns, arg, json);
            case "reachable" -> reachable(fns, json);
            case "path" -> path(fns, arg, arg2, json);
            case "impact" -> impact(fns, arg, json);
            case "whatif" -> whatif(pos.get(0), arg, arg2, pos.size() > 3 ? pos.get(3) : null, json);
            case "rewire" -> rewire(pos.get(0), arg, json);
            default -> 2;
        };
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
        for (var r : Candor.denyRules)
            deny.add(Map.of("effects", new ArrayList<>(r.effects), "scope", r.scope));
        List<Map<String, Object>> allow = new ArrayList<>();
        for (var r : Candor.allowRules)
            allow.add(Map.of("effect", r.effect, "scope", r.scope, "values", new ArrayList<>(r.values)));
        List<Map<String, Object>> forbid = new ArrayList<>();
        for (var r : Candor.forbidRules)
            forbid.add(Map.of("from", r.from, "to", r.to));
        Comparator<Map<String, Object>> byJson = Comparator.comparing(JSON::toJson);
        deny.sort(byJson); allow.sort(byJson); forbid.sort(byJson);
        return JSON.toJson(Map.of("deny", deny, "allow", allow, "forbid", forbid));
    }

    /** A function's effects, instant — `*` marks an effect performed in its own body. */
    static int show(List<Fn> fns, String q, boolean json) {
        if (q == null) return usage("show <report.json> <function-substring> [--json]");
        int tier = bestTier(fns.stream().map(f -> f.fn), q);
        List<Fn> hits = tier == 0 ? List.of()
                : fns.stream().filter(f -> matchTier(f.fn, q) >= tier).collect(Collectors.toList());
        if (json) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Fn f : hits) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", f.fn);
                m.put("inferred", sorted(f.inferred));
                m.put("direct", sorted(f.direct));
                if (!f.fs.isEmpty()) m.put("fs", f.fs);
                // The engine resolves Net endpoints (hosts) per method; show MUST surface them like the
                // Rust engine (SPEC §3.1 `hosts?`) — the Fn record previously never parsed the field.
                if (f.hosts != null && !f.hosts.isEmpty()) m.put("hosts", f.hosts);
                m.put("unresolved", f.unresolved);
                out.add(m);
            }
            emit(out);
            return 0;
        }
        if (hits.isEmpty()) {
            System.out.println("candor: no effectful function matching `" + q + "` (pure functions are omitted).");
            return 0;
        }
        int w = hits.stream().mapToInt(f -> f.fn.length()).max().orElse(0);
        for (Fn f : hits) {
            Set<String> direct = new HashSet<>(f.direct);
            String parts = sorted(f.inferred).stream()
                    .map(x -> {
                        String star = direct.contains(x) ? "*" : "";
                        if (x.equals("Fs") && !f.fs.isEmpty()) return "Fs" + star + "(" + String.join(",", f.fs) + ")";
                        return x + star;
                    })
                    .collect(Collectors.joining(" "));
            String unk = f.unresolved ? "  ⚠ unresolved (set may be incomplete)" : "";
            System.out.printf("  %-" + w + "s  { %s }%s%n", f.fn, parts, unk);
        }
        System.out.println("  (* = performed in the function's own body; unmarked = via a callee)");
        return 0;
    }

    /** Which functions perform an effect — direct sources split from inheritors. */
    static int where(List<Fn> fns, String eff, boolean json) {
        if (eff == null) return usage("where <report.json> <Effect> [--json]");
        List<String> direct = fns.stream().filter(f -> f.direct.contains(eff)).map(f -> f.fn).sorted().toList();
        List<String> inherit = fns.stream()
                .filter(f -> f.inferred.contains(eff) && !f.direct.contains(eff)).map(f -> f.fn).sorted().toList();
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
    static int callers(List<Fn> fns, String reportPath, String q, boolean json) {
        if (q == null) return usage("callers <report.json> <function-substring> [--json]");
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
            for (Fn f : fns) cg.put(f.fn, new ArrayList<>(f.calls));
        }
        return callersViaCallgraph(cg, q, json);
    }

    /** Load the call-graph sidecar (`<report-minus-.json>.callgraph.json`), or null if absent/unreadable. */
    static Map<String, List<String>> loadCallgraph(String reportPath) {
        try {
            String cgPath = reportPath.endsWith(".json")
                    ? reportPath.substring(0, reportPath.length() - 5) + ".callgraph.json"
                    : reportPath + ".callgraph.json";
            if (!Files.exists(Path.of(cgPath))) return null;
            var o = JsonParser.parseString(Files.readString(Path.of(cgPath))).getAsJsonObject();
            Map<String, List<String>> cg = new LinkedHashMap<>();
            for (var e : o.entrySet()) {
                List<String> callees = new ArrayList<>();
                for (JsonElement v : e.getValue().getAsJsonArray()) callees.add(v.getAsString());
                cg.put(e.getKey(), callees);
            }
            return cg;
        } catch (Exception e) {
            return null;
        }
    }

    /** "Who reaches `q`?" over the full call graph: the DIRECT callers and the full TRANSITIVE set (the
     *  blast radius if `q` gained an effect). Works for any function, effectful or pure. Mirrors
     *  candor-scan's `callers_via_callgraph`. */
    static int callersViaCallgraph(Map<String, List<String>> cg, String q, boolean json) {
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
        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("of", targets);
            out.put("direct", new ArrayList<>(direct));
            out.put("transitive", new ArrayList<>(all));
            emit(out);
            return 0;
        }
        String tgt = String.join(", ", targets);
        if (all.isEmpty()) {
            System.out.println("  `" + tgt + "` has no callers (nothing in this codebase calls it).");
            return 0;
        }
        System.out.println("  `" + tgt + "` is reached by " + all.size()
                + " function(s) (the blast radius if it gained an effect):");
        for (String c : all) System.out.println("      " + c + (direct.contains(c) ? " (direct)" : ""));
        return 0;
    }

    /** whatif <report> <fn> <Effect> [policy] — the PRE-EDIT verdict (mirrors candor-query). Computes the
     *  blast radius of introducing `effect` into `fn` (the fn + every transitive caller, all of which would
     *  gain it), then — given a policy — reports which of them would VIOLATE a `deny <Effect>`/`pure`
     *  boundary. Answers "if I add a network call here, what propagates and is it allowed?" BEFORE the edit.
     *  Reuses Candor.parsePolicy/scopeMatches so the verdict matches what the real gate would do. */
    static int whatif(String reportPath, String fn, String effect, String policyPath, boolean json) {
        if (fn == null || effect == null) return usage("whatif <report.json> <fn> <Effect> [policy] [--json]");
        // Validate the effect against the vocabulary: a typo'd/lowercase effect (`net`) matches no deny
        // rule and would print an authoritative-looking clean verdict — a false green light for the very
        // edit the policy forbids (/code-review). Reject it as a usage error, not a pass.
        if (!Candor.KNOWN_EFFECTS.contains(effect) && !effect.equals("Unknown")) {
            System.err.println("candor: unknown effect `" + effect + "` (expected one of "
                    + Candor.KNOWN_EFFECTS + " or Unknown)");
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
            Candor.denyRules.clear();
            // A SPECIFIED-but-unreadable policy must FAIL LOUD, not silently yield ok:true — a typo'd
            // CANDOR_POLICY path otherwise reads as "no violations" and an agent proceeds with a
            // forbidden edit believing the boundary was checked (/code-review; mirrors the gate's own
            // loud-on-unreadable contract and the diff/rewire path checks).
            if (!Candor.parsePolicy(policyPath)) {
                System.err.println("candor: policy `" + policyPath + "` could not be read — verdict NOT computed.");
                return 2;
            }
            for (String f : affected) {
                for (var r : Candor.denyRules) {
                    boolean denies = r.effects.isEmpty() || r.effects.contains(effect);
                    if (denies && Candor.scopeMatches(f, r.scope)) {
                        String desc = r.effects.isEmpty()
                                ? "pure" + (r.scope.isEmpty() ? "" : " " + r.scope)
                                : "deny " + effect + (r.scope.isEmpty() ? "" : " " + r.scope);
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
    static int map(List<Fn> fns, boolean json) {
        Map<String, TreeSet<String>> mods = new HashMap<>();
        Map<String, Integer> counts = new HashMap<>();
        for (Fn f : fns) {
            int dot = f.fn.lastIndexOf('.');
            String mod = dot > 0 ? f.fn.substring(0, dot) : f.fn; // declaring class
            mods.computeIfAbsent(mod, k -> new TreeSet<>())
                    .addAll(f.inferred.stream().filter(x -> !x.equals("Unknown")).toList());
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
    static int diff(List<Fn> cur, String basePath, boolean json) {
        if (basePath == null) return usage("diff <report.json> <baseline.json> [--json]");
        List<Fn> base;
        try {
            base = load(basePath);
        } catch (Exception e) {
            System.out.println("candor: cannot read baseline " + basePath);
            return 2;
        }
        Map<String, Set<String>> b = base.stream().collect(Collectors.toMap(f -> f.fn, f -> new HashSet<>(f.inferred), (x, y) -> x));
        Map<String, Set<String>> c = cur.stream().collect(Collectors.toMap(f -> f.fn, f -> new HashSet<>(f.inferred), (x, y) -> x));
        Map<String, Set<String>> cd = cur.stream().collect(Collectors.toMap(f -> f.fn, f -> new HashSet<>(f.direct), (x, y) -> x));
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
        if (json) {
            // The cross-language shape (SPEC §3.1): an envelope with `changes`, matching candor-query
            // (whose envelope also carries baseline/engine provenance — optional fields a consumer
            // must tolerate). A bare array here used to diverge from the Rust engine.
            emit(Map.of("changes", changes));
            return 0;
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
        return 0;
    }

    /** The longest dotted-segment prefix shared by EVERY function name — the codebase root, so the next
     *  segment is the architectural "layer" (`com.uflexi.nems` → `model`/`dao`/`actions`). Adapts to any
     *  package root without configuration. */
    static String[] commonPrefix(List<Fn> fns) {
        String[] best = null;
        for (Fn f : fns) {
            String[] segs = f.fn.split("\\.");
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

    /** impact — the blast radius of a function: every effectful method that TRANSITIVELY calls it, and
     *  which ENTRY POINTS (runtime roots) are downstream — "if I change this, what surfaces at runtime?".
     *  The backward dual of `path`; the transitive, entry-point-scoped version of `callers`. Read-only,
     *  reversing the report's effect-relevant `calls` graph. Scoped to effectful targets (the report's
     *  `calls` only records effect-carrying edges, so a pure fn — omitted from the report — has no blast
     *  radius to trace; that's the honest limit of working from the report). */
    static int impact(List<Fn> fns, String fnArg, boolean json) {
        if (fnArg == null) return usage("impact <report.json> <fn-substring> [--json]");
        Map<String, Fn> byName = new HashMap<>();
        for (Fn f : fns) byName.putIfAbsent(f.fn, f);
        Fn target = fns.stream().filter(f -> f.fn.equals(fnArg)).findFirst()
                .orElseGet(() -> fns.stream().filter(f -> f.fn.contains(fnArg)).findFirst().orElse(null));
        if (target == null) {
            System.err.println("candor impact: no function matching '" + fnArg + "'");
            return 2;
        }
        // Reverse the effect-relevant call graph: callee -> [callers], then BFS backward from the target.
        Map<String, List<String>> rev = new HashMap<>();
        for (Fn f : fns) for (String c : f.calls) rev.computeIfAbsent(c, k -> new ArrayList<>()).add(f.fn);
        Set<String> affected = new LinkedHashSet<>();
        Deque<String> q = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        q.add(target.fn);
        seen.add(target.fn);
        while (!q.isEmpty()) {
            String cur = q.poll();
            for (String caller : rev.getOrDefault(cur, List.of()))
                if (seen.add(caller)) { affected.add(caller); q.add(caller); }
        }
        // Entry points downstream — the runtime roots a change here surfaces through (target included if it
        // is itself a root).
        List<Fn> roots = new ArrayList<>();
        if (target.entryPoint) roots.add(target);
        affected.stream().map(byName::get).filter(f -> f != null && f.entryPoint)
                .sorted(Comparator.comparing(f -> f.fn)).forEach(roots::add);

        if (json) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("fn", target.fn);
            out.put("affectedCount", affected.size());
            List<Map<String, Object>> rs = new ArrayList<>();
            for (Fn r : roots) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", r.fn);
                m.put("inferred", r.inferred);
                rs.add(m);
            }
            out.put("entryPoints", rs);
            emit(out);
            return 0;
        }
        System.out.println("candor impact — what changing `" + target.fn + "` affects:\n");
        System.out.println("  " + affected.size() + " effectful function"
                + (affected.size() == 1 ? "" : "s") + " transitively call it.");
        if (roots.isEmpty()) {
            System.out.println("  No entry point reaches it — not on a runtime path (dead, or a "
                    + "library fn invoked only externally).");
            return 0;
        }
        System.out.println("  " + roots.size() + " entry point" + (roots.size() == 1 ? "" : "s")
                + " downstream (a change here surfaces at runtime via):");
        for (Fn r : roots)
            System.out.println("    " + r.fn + "   { " + String.join(", ", r.inferred) + " }");
        return 0;
    }

    /** path — the call chain by which a function comes to perform an effect: a shortest-path BFS over the
     *  effect-relevant `calls` graph from <fn> to the nearest method that performs <effect> DIRECTLY (the
     *  source). Answers "this method touches Net — through WHAT?", the chain `where` (who performs it) and
     *  `callers` (who calls X) describe the ends of but never connect. Read-only over the report. */
    static int path(List<Fn> fns, String fnArg, String effect, boolean json) {
        if (fnArg == null || effect == null)
            return usage("path <report.json> <fn-substring> <Effect> [--json]");
        Map<String, Fn> byName = new HashMap<>();
        for (Fn f : fns) byName.putIfAbsent(f.fn, f);
        Fn start = fns.stream().filter(f -> f.fn.equals(fnArg)).findFirst()
                .orElseGet(() -> fns.stream().filter(f -> f.fn.contains(fnArg)).findFirst().orElse(null));
        if (start == null) {
            System.err.println("candor path: no function matching '" + fnArg + "'");
            return 2;
        }
        if (!start.inferred.contains(effect)) {
            System.out.println(start.fn + " does not perform " + effect
                    + "  (inferred: " + start.inferred + ")");
            if (json) emit(Map.of("fn", start.fn, "effect", effect, "path", List.of()));
            return 0;
        }
        // BFS following `calls`, only through callees that carry the effect, to the first DIRECT source.
        Map<String, String> prev = new HashMap<>();
        Deque<String> q = new ArrayDeque<>();
        q.add(start.fn);
        prev.put(start.fn, null);
        String source = null;
        while (!q.isEmpty()) {
            String cur = q.poll();
            Fn f = byName.get(cur);
            if (f == null) continue;
            if (f.direct.contains(effect)) { source = cur; break; }
            for (String c : f.calls) {
                Fn cf = byName.get(c);
                if (cf != null && cf.inferred.contains(effect) && !prev.containsKey(c)) {
                    prev.put(c, cur);
                    q.add(c);
                }
            }
        }
        if (source == null) {
            // Inferred but no LOCAL direct source on a `calls` path — reached cross-jar, via a
            // Spring-synthesized callee (repo/Feign), or through an Unknown. Honest: not locally traceable.
            String msg = start.fn + " performs " + effect
                    + " but its source is not a local method (cross-jar, framework-synthesized, or via Unknown) "
                    + "— not statically traceable.";
            System.out.println(msg);
            if (json) emit(Map.of("fn", start.fn, "effect", effect, "path", List.of(),
                    "note", "source not locally traceable"));
            return 0;
        }
        List<String> chain = new ArrayList<>();
        for (String n = source; n != null; n = prev.get(n)) chain.add(n);
        Collections.reverse(chain);

        if (json) {
            List<Map<String, Object>> steps = new ArrayList<>();
            for (int i = 0; i < chain.size(); i++) {
                Fn f = byName.get(chain.get(i));
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", chain.get(i));
                m.put("loc", f != null ? f.loc : "");
                m.put("source", i == chain.size() - 1);
                steps.add(m);
            }
            emit(Map.of("fn", start.fn, "effect", effect, "path", steps));
            return 0;
        }
        System.out.println("candor path — how `" + start.fn + "` comes to perform " + effect + ":\n");
        for (int i = 0; i < chain.size(); i++) {
            Fn f = byName.get(chain.get(i));
            String indent = "  ".repeat(i + 1);
            String arrow = i == 0 ? "" : "→ ";
            boolean isSource = i == chain.size() - 1;
            String tag = isSource
                    ? "   [" + effect + " source" + (f != null && !f.loc.isEmpty() ? " @ " + f.loc : "") + "]"
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
    static int reachable(List<Fn> fns, boolean json) {
        List<Fn> entries = fns.stream().filter(f -> f.entryPoint)
                .sorted(Comparator.comparing(f -> f.fn)).toList();
        TreeMap<String, List<String>> byEffect = new TreeMap<>();
        for (Fn f : entries)
            for (String e : f.inferred) byEffect.computeIfAbsent(e, k -> new ArrayList<>()).add(f.fn);

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
        // Unknown caveat. Anything else (shouldn't occur) trails alphabetically.
        // Boundary effects first, then ambient, then Clipboard (a peripheral capability in neither
        // set), then the Unknown caveat. Anything else trails.
        List<String> order = new ArrayList<>();
        order.addAll(CONTAINED);
        order.addAll(AMBIENT);
        order.add("Clipboard");
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
        long pure = entries.stream().filter(f -> f.inferred.isEmpty()).count();
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
    static int containment(List<Fn> fns, String basePath, boolean json) {
        String[] prefix = commonPrefix(fns);
        int pl = prefix.length;
        // effect -> (layer -> count of methods performing it DIRECTLY)
        Map<String, TreeMap<String, Integer>> byEff = new LinkedHashMap<>();
        for (Fn f : fns)
            for (String eff : f.direct)
                byEff.computeIfAbsent(eff, k -> new TreeMap<>()).merge(layerOf(f.fn, pl), 1, Integer::sum);

        // RATCHET mode: a baseline report was given — flag any NEW (contained-effect, layer) pair.
        if (basePath != null) {
            List<Fn> base;
            try { base = load(basePath); } catch (Exception e) {
                System.out.println("candor: cannot read baseline " + basePath); return 2;
            }
            int bpl = commonPrefix(base).length;
            Map<String, Set<String>> baseLayers = new HashMap<>();
            for (Fn f : base)
                for (String eff : f.direct)
                    baseLayers.computeIfAbsent(eff, k -> new HashSet<>()).add(layerOf(f.fn, bpl));
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
