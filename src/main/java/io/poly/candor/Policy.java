package io.poly.candor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import com.google.gson.*;
import com.google.gson.reflect.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Cha.*;
import static io.poly.candor.Literals.*;

/** Architecture-as-code policy + gate (candor-spec §5): the deny/pure (AS-EFF-006), allow-in
 *  (AS-EFF-008) and forbid A->B (AS-EFF-009) rule types + their parsed-rule lists, the checkers
 *  (checkNoAmbient/checkTaint/checkPolicy/checkAllowlist + parsePolicy/scopeMatches/nameSegments/
 *  reachesScope) and the AS-EFF-005 baseline-drift checker (checkBaseline + loadBaseline). EXTRACTED
 *  verbatim from Candor.java (refactor P5); re-exposed to Candor + Query as bare names via
 *  `import static io.poly.candor.Policy.*`; reads shared state via the Candor/Cha/Literals static
 *  imports. KNOWN_EFFECTS + rejectUnknownFlag stay in Candor. See REFACTOR_PLAN.md. */
final class Policy {
    /** A `deny <Effect…> [scope]` or `pure <scope>` rule. `effects` empty ⇒ a `pure` rule (ANY effect is
     *  forbidden). `scope` empty ⇒ the whole project. */
    static class DenyRule { TreeSet<String> effects = new TreeSet<>(); String scope = ""; String src; }
    /** An `allow <Effect> [in <scope>] <value…>` rule: a method in scope performing that effect may reach
     *  ONLY the listed values (Net hosts today). `scope` empty ⇒ whole project. */
    static class AllowRule { String effect; String scope = ""; TreeSet<String> values = new TreeSet<>(); String src; }
    /** A `forbid <A> -> <B>` rule: a method in scope A must not transitively reach into scope B. */
    static class ForbidRule { String from, to; }

    // CANDOR_POLICY rules (architecture-as-code, candor-spec §5). `deny`/`pure` = AS-EFF-006 (what a
    // layer may do); `allow … in …` = AS-EFF-008 (which endpoints); `forbid A -> B` = AS-EFF-009 (who
    // a layer may depend on).
    static final List<DenyRule> denyRules = new ArrayList<>();
    static final List<AllowRule> allowRules = new ArrayList<>();
    static final List<ForbidRule> forbidRules = new ArrayList<>();

    /** AS-EFF-004: flag direct use of ambient authority (route it through an injected collaborator). */
    static int checkNoAmbient(Map<String, TreeSet<String>> inferred, String scope) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            if (!gateScopeCovers(scope, e.getKey())) continue;
            List<String> ambient = direct.getOrDefault(e.getKey(), new TreeSet<>()).stream()
                    .filter(AMBIENT::contains).sorted().collect(Collectors.toList());
            if (!ambient.isEmpty()) {
                System.out.printf("[AS-EFF-004] `%s` uses ambient authority { %s } directly; "
                        + "route it through an injected collaborator / capability%n",
                        e.getKey(), String.join(", ", ambient));
                v++;
            }
        }
        return v;
    }

    /**
     * AS-EFF-007 (CANDOR_TAINT): a function performs an injection-class effect on a CALLER-DERIVED argument
     * (path traversal / command / SQL injection / SSRF). HEURISTIC + ADVISORY — an intraprocedural,
     * over-approximating dataflow (the `tainted` map is built in `analyze` by the taint `Analyzer`); it
     * misses cross-method flow and over-flags a parameter that is actually validated. Mirrors the Rust
     * impl's syntactic taint nudge. Emits findings but never fails CI (returns the count for messaging only).
     */
    static int checkTaint(Map<String, TreeSet<String>> inferred) {
        int v = 0;
        for (var e : new TreeMap<>(tainted).entrySet()) {
            if (e.getValue().isEmpty()) continue;
            System.out.printf("[AS-EFF-007] `%s` performs { %s } on caller-derived input (an injection "
                    + "surface — validate/sanitize it, or confirm the source is trusted); heuristic, may "
                    + "over- or under-flag%n", e.getKey(), String.join(", ", e.getValue()));
            v++;
        }
        return v;
    }


    /** AS-EFF-005: flag a function that gained an effect versus a saved baseline report. */
    static int checkBaseline(Map<String, TreeSet<String>> inferred, String path) {
        Map<String, Set<String>> base = loadBaseline(path);
        if (base == null) {
            System.err.println("candor-java: CANDOR_BASELINE set but " + path
                    + " could not be loaded — the regression guard is NOT active");
            return 0;
        }
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            Set<String> prior = base.get(e.getKey());
            if (prior == null) continue; // new function — reviewed as new code, not a regression
            List<String> gained = e.getValue().stream()
                    .filter(x -> !prior.contains(x)).sorted().collect(Collectors.toList());
            if (!gained.isEmpty()) {
                System.out.printf("[AS-EFF-005] `%s` gained effect { %s } not present in the baseline%n",
                        e.getKey(), String.join(", ", gained));
                v++;
            }
        }
        return v;
    }

    /** CANDOR_POLICY (candor-spec §5): architecture-as-code. Enforces all three boundary kinds, each
     *  TRANSITIVELY (so they catch what a local diff hides):
     *   - AS-EFF-006 `deny <Effect…> [scope]` / `pure <scope>` — WHAT a layer may do.
     *   - AS-EFF-008 `allow <Effect> in <scope> <value…>` — WHICH literals (Net hosts / Exec commands /
     *     Fs paths) it may reach, against the visible surface.
     *   - AS-EFF-009 `forbid <A> -> <B>` — WHO a layer may depend on (reachability over the call graph).
     *  A set-but-unreadable policy is LOUD (not silently passing). */
    static int checkPolicy(Map<String, TreeSet<String>> inferred, String path) {
        if (!parsePolicy(path)) {
            // A SET-but-unreadable policy FAILS the run (exit 2) — it must never gate-pass: a
            // typo'd CANDOR_POLICY path otherwise runs gateless and green (spec §6.2). Found by
            // the spec review: this engine printed loudly but returned clean; the siblings exit 2.
            System.err.println("candor-java: CANDOR_POLICY=" + path
                    + " could not be read — failing (exit 2), policy NOT evaluated");
            System.exit(2);
        }
        int v = 0;
        // AS-EFF-006: a method in scope must not perform (transitively) a denied effect.
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            for (DenyRule r : denyRules) {
                if (!scopeMatches(fn, r.scope)) continue;
                List<String> bad = r.effects.isEmpty()
                        ? e.getValue().stream().filter(x -> !x.equals("Unknown")).sorted().collect(Collectors.toList())
                        : e.getValue().stream().filter(r.effects::contains).sorted().collect(Collectors.toList());
                if (!bad.isEmpty()) {
                    System.out.printf("[AS-EFF-006] `%s` performs { %s }, forbidden by policy%s: `%s`%n",
                            fn, String.join(", ", bad),
                            r.scope.isEmpty() ? "" : " (scope `" + r.scope + "`)", r.src);
                    v++;
                }
            }
        }
        // AS-EFF-008: a method in an allow-listed scope may reach ONLY the listed literals — Net hosts
        // (matched by hostname), Exec commands (by basename), Fs paths (by path-prefix at a boundary).
        // Certifies the VISIBLE literal surface (propagated transitively). A method whose surface is empty OR
        // INCOMPLETE (a structurally-invisible reach — see surfaceIncomplete) can't be certified: fail-closed,
        // so a benign visible literal can't MASK an invisible forbidden endpoint.
        Map<String, TreeSet<String>> incomplete = literalFixpoint(surfaceIncomplete);
        v += checkAllowlist(inferred, "Net", literalFixpoint(hostsDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> hostPart(a).equals(hostPart(reached))));
        v += checkAllowlist(inferred, "Exec", literalFixpoint(cmdsDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> cmdBase(a).equals(cmdBase(reached))));
        v += checkAllowlist(inferred, "Fs", literalFixpoint(pathsDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> pathCovered(a, reached)));
        v += checkAllowlist(inferred, "Db", literalFixpoint(tablesDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> tableCovered(a, reached)));
        // AS-EFF-009: a method in scope A must not transitively reach into scope B (over the call graph).
        for (ForbidRule r : forbidRules) {
            for (String fn : new TreeSet<>(edges.keySet())) {
                if (!scopeMatches(fn, r.from)) continue;
                String hit = reachesScope(fn, r.to);
                if (hit != null) {
                    System.out.printf("[AS-EFF-009] `%s` reaches into a forbidden layer (via `%s`), "
                            + "violating policy: `forbid %s -> %s`%n", fn, hit, r.from, r.to);
                    v++;
                }
            }
        }
        return v;
    }

    /** AS-EFF-008 for one effect: for EACH `allow <effect> …` rule whose scope matches, the method
     *  performing `effect` must reach ONLY covered literals (per the effect's `covered` matcher).
     *  Per-rule, not unioned across rules — the SEMANTICS predicate quantifies over each rule `r`
     *  (and the Rust gate checks per rule), so two half-covering rules don't pass by union. A method
     *  whose reached surface is EMPTY is a violation too — "a literal it cannot see" can't be
     *  certified (lits_e(f) = ∅ in the predicate). No matching `allow` rule ⇒ unchecked. */
    static int checkAllowlist(Map<String, TreeSet<String>> inferred, String effect,
            Map<String, TreeSet<String>> reachedAcc, Map<String, TreeSet<String>> incompleteAcc,
            java.util.function.BiPredicate<Set<String>, String> covered) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            if (!e.getValue().contains(effect)) continue;
            for (AllowRule r : allowRules) {
                if (!effect.equals(r.effect) || !scopeMatches(fn, r.scope)) continue;
                TreeSet<String> reached = reachedAcc.getOrDefault(fn, new TreeSet<>());
                // Empty surface OR an INCOMPLETE one (a structurally-invisible reach — a host-less Net owner
                // or a runtime-host call) can't be certified: fail-closed. Without the incompleteness gate a
                // benign visible literal would MASK the invisible forbidden endpoint (the gate EVASION).
                if (reached.isEmpty() || incompleteAcc.getOrDefault(fn, new TreeSet<>()).contains(effect)) {
                    System.out.printf("[AS-EFF-008] `%s` performs %s with no visible literal — the "
                            + "surface cannot be certified: `allow %s%s %s`%n", fn, effect, effect,
                            r.scope.isEmpty() ? "" : " in " + r.scope,
                            String.join(" ", r.values));
                    v++;
                    continue;
                }
                List<String> bad = reached.stream()
                        .filter(x -> !covered.test(r.values, x)).sorted().collect(Collectors.toList());
                if (!bad.isEmpty()) {
                    System.out.printf("[AS-EFF-008] `%s` reaches { %s } outside the allowlist, forbidden by "
                            + "policy%s: `allow %s … %s`%n", fn, String.join(", ", bad),
                            r.scope.isEmpty() ? "" : " (scope `" + r.scope + "`)", effect,
                            String.join(" ", r.values));
                    v++;
                }
            }
        }
        return v;
    }

    /** Parse a CANDOR_POLICY file into deny/forbid rules. One rule per line; `#` comments + blanks
     *  ignored. Returns false if the file can't be read (so the caller can fail loud). */
    /** SPEC §6.2: a malformed/unknown policy line is "ignored with a WARNING" — never silently
     *  reinterpreted (a security gate must not). Mirrors the Rust parser's eprintln warnings. */
    static void warnPolicy(String line, String reason) {
        System.err.println("candor: ignoring policy rule (" + reason + "): " + line);
    }

    static boolean parsePolicy(String path) {
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of(path));
        } catch (IOException e) {
            return false;
        }
        for (String raw : lines) {
            // SPEC §6.2 lexical: `#` begins a comment to end-of-line (strip it, mirroring the Rust
            // parser's `raw_line.split('#').next()`); blank/comment-only lines are ignored. A bare
            // `startsWith("#")` check left an INLINE comment's tokens in the rule — `deny Exec # x`
            // neutered the deny (scope="#"), `allow Net … # x` widened the allowlist. (/code-review.)
            String line = raw.split("#", 2)[0].trim();
            if (line.isEmpty()) continue;
            String[] t = line.split("\\s+");
            switch (t[0]) {
                case "deny": {
                    // SPEC §6.2: read tokens left-to-right; each known effect (or `Unknown`) joins the
                    // forbidden set; the FIRST non-effect token is the scope and ENDS the rule. A `deny`
                    // naming no known effect is DROPPED — it is NOT a `pure` rule (that distinction is
                    // load-bearing: an empty-effect rule would forbid EVERYTHING). `Unknown` is denyable
                    // so `deny Unknown <scope>` can forbid the unverifiable case (AS-EFF-008's companion).
                    DenyRule r = new DenyRule();
                    r.src = line;
                    for (int i = 1; i < t.length; i++) {
                        if (KNOWN_EFFECTS.contains(t[i]) || "Unknown".equals(t[i])) r.effects.add(t[i]);
                        else { r.scope = t[i]; break; }
                    }
                    if (r.effects.isEmpty()) { warnPolicy(line, "names no known effect"); break; }
                    denyRules.add(r);
                    break;
                }
                case "pure": {
                    DenyRule r = new DenyRule(); // empty effects = ANY effect forbidden
                    r.src = line;
                    if (t.length > 1) r.scope = t[1];
                    denyRules.add(r);
                    break;
                }
                case "forbid": {
                    // SPEC §6.2: `forbid <A> -> <B>` — two scopes separated by a literal `->` TOKEN
                    // (so `forbid a->b` without surrounding spaces is malformed and dropped).
                    if (t.length >= 4 && t[2].equals("->")) {
                        ForbidRule r = new ForbidRule();
                        r.from = t[1];
                        r.to = t[3];
                        forbidRules.add(r);
                    } else {
                        warnPolicy(line, "want `forbid <scope> -> <scope>`");
                    }
                    break;
                }
                case "allow": {
                    // SPEC §6.2: `allow <Effect> [in <scope>] <value…>` — the effect MUST be one of the
                    // three that carry a literal surface; an `allow` for any other effect is dropped.
                    if (t.length < 3) { warnPolicy(line, "allow names no values"); break; }
                    if (!t[1].equals("Net") && !t[1].equals("Exec") && !t[1].equals("Fs") && !t[1].equals("Db")) {
                        warnPolicy(line, "allow supports only Net hosts / Exec commands / Fs paths / Db tables");
                        break;
                    }
                    AllowRule r = new AllowRule();
                    r.src = line;
                    r.effect = t[1];
                    // optional `in <scope>` prefix; `in` ENDS the keyword even with no scope/value after
                    // (`allow Net in` → no values → dropped), matching the Rust parser. A bare
                    // `t.length > 3` guard let a value-less `allow Net in` keep "in" as an allowed value.
                    int vi = 2;
                    if (t[2].equals("in")) { r.scope = t.length > 3 ? t[3] : ""; vi = 4; }
                    for (int i = vi; i < t.length; i++) r.values.add(t[i]);
                    if (r.values.isEmpty()) { warnPolicy(line, "allow names no values"); break; }
                    allowRules.add(r);
                    break;
                }
                default:
                    warnPolicy(line, "unknown rule kind `" + t[0] + "`");
                    break;
            }
        }
        return true;
    }

    /** A policy scope matches a method by dotted SEGMENT (so `domain` matches `app.domain.Svc.handle`
     *  and the `domain_logic` package, but not `subdomain`). Mirrors the Rust impl's `scope_matches`:
     *  a contiguous run of segments — intermediate segments exact, the LAST a prefix. Empty scope ⇒
     *  whole project (matches everything). */
    static boolean scopeMatches(String name, String scope) {
        if (scope.isEmpty()) return true;
        String[] segs = nameSegments(name);
        String[] parts = nameSegments(scope);
        if (parts.length == 0 || parts.length > segs.length) return false;
        String last = parts[parts.length - 1];
        for (int i = 0; i + parts.length <= segs.length; i++) {
            boolean ok = true;
            for (int j = 0; j < parts.length - 1; j++)
                if (!segs[i + j].equals(parts[j])) { ok = false; break; }
            if (ok && segs[i + parts.length - 1].startsWith(last)) return true;
        }
        return false;
    }

    /** Split a name OR a policy scope into segments on BOTH `.` and `::`, dropping empties. candor-java
     *  node ids are dotted (`com.foo.A.m`), but spec §6.2 + the conformance battery write scopes with `::`
     *  (`app::db`, `forbid app::web -> app::db`) and a Rust report names fns with `::` — so a `::`-written
     *  policy scope must still match a dotted name (it silently never did: the gate was a dead rule →
     *  a real violation passed). Mirrors the Rust impl's `name_segments` (splits on `.` and `:`). */
    static String[] nameSegments(String s) {
        List<String> out = new ArrayList<>();
        for (String seg : s.split("[.:]")) if (!seg.isEmpty()) out.add(seg);
        return out.toArray(new String[0]);
    }

    /** Forward reachability over the project call graph: the first method `start` transitively reaches
     *  whose name matches `scope` (seeded from `start`'s direct callees, so `start` itself isn't a hit),
     *  or null. Used for AS-EFF-009 layering. */
    static String reachesScope(String start, String scope) {
        Deque<String> stack = new ArrayDeque<>(edges.getOrDefault(start, Set.of()));
        Set<String> seen = new HashSet<>();
        while (!stack.isEmpty()) {
            String n = stack.pop();
            if (!seen.add(n)) continue;
            if (scopeMatches(n, scope)) return n;
            for (String c : edges.getOrDefault(n, Set.of())) if (!seen.contains(c)) stack.push(c);
        }
        return null;
    }

    static class BaseEntry { String fn; List<String> inferred; }

    static Map<String, Set<String>> loadBaseline(String path) {
        try {
            String text = Files.readString(Path.of(path));
            // Accept BOTH the v0.2 self-describing envelope `{ candor, functions:[...] }` and the legacy
            // v0.1 bare array `[...]` — the migration contract (candor-spec §2: readers MUST accept both).
            JsonElement root = JsonParser.parseString(text);
            JsonArray arr = root.isJsonObject()
                    ? root.getAsJsonObject().getAsJsonArray("functions")
                    : (root.isJsonArray() ? root.getAsJsonArray() : null);
            if (arr == null) return null;
            List<BaseEntry> entries = new Gson().fromJson(arr, new TypeToken<List<BaseEntry>>() {}.getType());
            Map<String, Set<String>> m = new HashMap<>();
            for (BaseEntry e : entries) if (e.fn != null) m.put(e.fn, new HashSet<>(e.inferred == null ? List.of() : e.inferred));
            return m;
        } catch (Exception ex) {
            return null;
        }
    }
}
