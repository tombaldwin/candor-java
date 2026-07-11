package io.poly.candor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import com.google.gson.*;
import com.google.gson.reflect.*;
import io.poly.candor.model.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.Rules.*;
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
    // CANDOR_POLICY rules (architecture-as-code, candor-spec §6.2), the typed sealed model.PolicyRule
    // family. `deny`/`pure` (Deny) = AS-EFF-006 (what a layer may do); `allow … in …` (Allow) =
    // AS-EFF-008 (which endpoints); `forbid A -> B` (Forbid) = AS-EFF-009 (who a layer may depend on).

    /** AS-EFF-004: flag direct use of ambient authority (route it through an injected collaborator). */
    static int checkNoAmbient(Map<String, EffectSet> inferred, String scope) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            if (!gateScopeCovers(scope, e.getKey())) continue;
            List<String> ambient = ctx().direct.getOrDefault(e.getKey(), EffectSet.empty()).effects().stream()
                    .filter(AMBIENT::contains).map(Effect::specName).sorted().collect(Collectors.toList());
            if (!ambient.isEmpty()) {
                diag(DiagnosticCode.AS_EFF_004, ambient, "`%s` uses ambient authority { %s } directly; "
                        + "route it through an injected collaborator / capability",
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
    static int checkTaint(Map<String, EffectSet> inferred) {
        int v = 0;
        for (var e : new TreeMap<>(ctx().tainted).entrySet()) {
            if (e.getValue().isEmpty()) continue;
            List<String> te = e.getValue().toNames();
            diag(DiagnosticCode.AS_EFF_007, te, "`%s` performs { %s } on caller-derived input (an injection "
                    + "surface — validate/sanitize it, or confirm the source is trusted); heuristic, may "
                    + "over- or under-flag", e.getKey(), String.join(", ", te));
            v++;
        }
        return v;
    }


    /** AS-EFF-005: flag a function that gained an effect versus a saved baseline report. */
    static int checkBaseline(Map<String, EffectSet> inferred, String path) {
        Map<String, EffectSet> base = loadBaseline(path);
        if (base == null) {
            // Distinguish ABSENT (ratchet not adopted — a note, exit 0) from PRESENT-BUT-UNLOADABLE
            // (corrupt/truncated/merge-conflict-markers — INVALID gate input, fail closed exit 2). The
            // old code conflated both into a fail-OPEN note, so a corrupt baseline silently disabled the
            // guard while a versionless one failed closed — inverted severity (review §2.1 gap).
            if (!java.nio.file.Files.exists(java.nio.file.Path.of(path))) {
                System.err.println("candor-java: CANDOR_BASELINE " + path + " does not exist — the "
                        + "regression guard is not active (record one: candor <target> --json " + path + ").");
                return 0;
            }
            System.err.println("candor-java: CANDOR_BASELINE " + path + " exists but could not be parsed "
                    + "(corrupt/truncated?) — failing (exit 2); the guard must not silently pass on an "
                    + "unreadable baseline (the unreadable-policy class, §6.2). Regenerate it: candor "
                    + "<target> --json " + path);
            System.exit(2);
        }
        // §2.1: a baseline is comparable only to its OWN producing version — a stale baseline is INVALID
        // GATE INPUT, the unreadable-policy class (§6.2). Evaluating it produces semi-garbage in both
        // directions (unmasking noise that trains people to dismiss AS-EFF-005, with any real regression
        // hidden inside the wave), and silently skipping is an unbounded fail-open window. So: do NOT
        // evaluate, say it once clearly, exit 2. The aligned family posture (cargo-candor guard matches);
        // read-only diff/gains QUERIES disclose instead of failing — a comparison the user explicitly
        // asked for should inform. A missing baseline FILE stays a note (ratchet not yet adopted — the
        // adopt workflow sets CANDOR_BASELINE unconditionally by contract).
        String baseVersion = baselineVersion(path);
        String current = ReportWriter.provenance()[0];
        if (baseVersion == null) {
            System.err.println("candor-java: the baseline " + path + " has no provenance header (a legacy/"
                    + "bare-array report) — a baseline is comparable only to its producing build (§2.1)."
                    + " Failing (exit 2); regenerate it with this build: candor <target> --json " + path);
            System.exit(2);
        }
        if (!baseVersion.equals(current)) {
            System.err.println("candor-java: the baseline " + path + " was produced by engine build "
                    + baseVersion + " but this is build " + current + " — coverage batches change reports,"
                    + " so an engine swap is baseline-invalidating and the gate cannot evaluate (exit 2,"
                    + " the unreadable-policy class; never a silent skip, never a bogus AS-EFF-005 wave)."
                    + " Regenerate deliberately with this build: candor <target> --json " + path);
            System.exit(2);
        }
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            EffectSet prior = base.get(e.getKey());
            if (prior == null) continue; // new function — reviewed as new code, not a regression
            List<String> gained = e.getValue().minus(prior).toNames();
            if (!gained.isEmpty()) {
                diag(DiagnosticCode.AS_EFF_005, gained, "`%s` gained effect { %s } not present in the baseline",
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
    static int checkPolicy(Map<String, EffectSet> inferred, String path) {
        if (!parsePolicy(path)) {
            // A SET-but-unreadable policy FAILS the run (exit 2) — it must never gate-pass: a
            // typo'd CANDOR_POLICY path otherwise runs gateless and green (spec §6.2). Found by
            // the spec review: this engine printed loudly but returned clean; the siblings exit 2.
            System.err.println("candor-java: policy file " + path
                    + " could not be read — failing (exit 2), policy NOT evaluated");
            System.exit(2);
        }
        int v = 0;
        // AS-EFF-006: a method in scope must not perform (transitively) a denied effect.
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            for (PolicyRule.Deny r : ctx().denyRules) {
                if (!scopeMatches(fn, r.scope())) continue;
                // pure rule (empty effects) ⇒ any effect except Unknown (handled by AS-EFF-003);
                // deny rule ⇒ the inferred effects that intersect the denied set. Test the EnumSet
                // directly; only materialize the sorted names on an actual violation (rare).
                EffectSet bad = r.effects().isEmpty()
                        ? e.getValue().without(Effect.UNKNOWN)
                        : e.getValue().intersect(r.effects());
                if (!bad.isEmpty()) {
                    List<String> bn = bad.toNames();
                    diag(DiagnosticCode.AS_EFF_006, bn, "`%s` performs { %s }, forbidden by policy%s: `%s`",
                            fn, String.join(", ", bn),
                            r.scope().isEmpty() ? "" : " (scope `" + r.scope() + "`)", r.src());
                    v++;
                }
            }
        }
        // Provable-purity DISCLOSURE (advisory — NEVER a violation, so `v`/exit are untouched): methods in a
        // pure/deny scope that PASS but are Unknown (the Unknown could hide the forbidden effect — a
        // fn/closure-injected port). Surfaces the gap automatically (eval/fixloop/DISPATCH-NOTE.md).
        List<String[]> holes = new ArrayList<>();
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            if (!e.getValue().toNames().contains("Unknown")) continue;
            for (PolicyRule.Deny r : ctx().denyRules) {
                if (!scopeMatches(fn, r.scope())) continue;
                boolean violates = r.effects().isEmpty()
                        ? !e.getValue().without(Effect.UNKNOWN).isEmpty()
                        : !e.getValue().intersect(r.effects()).isEmpty();
                if (violates) continue;
                String suffix = r.scope().isEmpty() ? "" : " " + r.scope();
                String upgrade = r.effects().isEmpty() ? "deny Unknown" + suffix
                        : "deny " + String.join(" ", r.effects().toNames()) + " Unknown" + suffix;
                holes.add(new String[]{fn, upgrade});
                break;
            }
        }
        if (!holes.isEmpty()) {
            System.err.println("candor-java: note — " + holes.size()
                    + " method(s) PASS the policy but are Unknown (purity NOT verified — the Unknown could hide a forbidden effect):");
            for (String[] h : holes) System.err.println("    `" + h[0] + "`  → add  `" + h[1] + "`");
            System.err.println("  (advisory; add the upgrade(s) to REQUIRE provable purity, or run `candor unverified` for detail — the gate verdict is unchanged)");
        }
        // AS-EFF-008: a method in an allow-listed scope may reach ONLY the listed literals — Net hosts
        // (matched by hostname), Exec commands (by basename), Fs paths (by path-prefix at a boundary).
        // Certifies the VISIBLE literal surface (propagated transitively). A method whose surface is empty OR
        // INCOMPLETE (a structurally-invisible reach — see surfaceIncomplete) can't be certified: fail-closed,
        // so a benign visible literal can't MASK an invisible forbidden endpoint.
        Map<String, TreeSet<String>> incomplete = literalFixpoint(ctx().surfaceIncomplete);
        v += checkAllowlist(inferred, "Net", literalFixpoint(ctx().hostsDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> hostPart(a).equals(hostPart(reached))));
        v += checkAllowlist(inferred, "Exec", literalFixpoint(ctx().cmdsDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> cmdBase(a).equals(cmdBase(reached))));
        v += checkAllowlist(inferred, "Fs", literalFixpoint(ctx().pathsDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> pathCovered(a, reached)));
        v += checkAllowlist(inferred, "Db", literalFixpoint(ctx().tablesDirect), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> tableCovered(a, reached)));
        // AS-EFF-009: a method in scope A must not transitively reach into scope B (over the call graph).
        for (PolicyRule.Forbid r : ctx().forbidRules) {
            for (String fn : new TreeSet<>(ctx().edges.keySet())) {
                if (!scopeMatches(fn, r.from())) continue;
                String hit = reachesScope(fn, r.to());
                if (hit != null) {
                    diag(DiagnosticCode.AS_EFF_009, "`%s` reaches into a forbidden layer (via `%s`), "
                            + "violating policy: `forbid %s -> %s`", fn, hit, r.from(), r.to());
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
    static int checkAllowlist(Map<String, EffectSet> inferred, String effect,
            Map<String, TreeSet<String>> reachedAcc, Map<String, TreeSet<String>> incompleteAcc,
            java.util.function.BiPredicate<Set<String>, String> covered) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            if (!e.getValue().contains(Effect.fromSpecName(effect))) continue;
            for (PolicyRule.Allow r : ctx().allowRules) {
                if (!effect.equals(r.effect().specName()) || !scopeMatches(fn, r.scope())) continue;
                TreeSet<String> reached = reachedAcc.getOrDefault(fn, new TreeSet<>());
                // Empty surface OR an INCOMPLETE one (a structurally-invisible reach — a host-less Net owner
                // or a runtime-host call) can't be certified: fail-closed. Without the incompleteness gate a
                // benign visible literal would MASK the invisible forbidden endpoint (the gate EVASION).
                if (reached.isEmpty() || incompleteAcc.getOrDefault(fn, new TreeSet<>()).contains(effect)) {
                    diag(DiagnosticCode.AS_EFF_008, List.of(effect), "`%s` performs %s with no visible literal "
                            + "— the surface cannot be certified: `allow %s%s %s`", fn, effect, effect,
                            r.scope().isEmpty() ? "" : " in " + r.scope(),
                            String.join(" ", r.values()));
                    v++;
                    continue;
                }
                List<String> bad = reached.stream()
                        .filter(x -> !covered.test(r.values(), x)).sorted().collect(Collectors.toList());
                if (!bad.isEmpty()) {
                    diag(DiagnosticCode.AS_EFF_008, List.of(effect), "`%s` reaches { %s } outside the allowlist, "
                            + "forbidden by policy%s: `allow %s … %s`", fn, String.join(", ", bad),
                            r.scope().isEmpty() ? "" : " (scope `" + r.scope() + "`)", effect,
                            String.join(" ", r.values()));
                    v++;
                }
            }
        }
        return v;
    }

    /** SPEC §6.2: a malformed/unknown policy line is "ignored with a WARNING" — never silently
     *  reinterpreted (a security gate must not). Mirrors the Rust parser's eprintln warnings. */
    static void warnPolicy(String line, String reason) {
        System.err.println("candor: ignoring policy rule (" + reason + "): " + line);
    }

    /** Parse a CANDOR_POLICY file into deny/forbid rules. One rule per line; `#` comments + blanks
     *  ignored. Returns false if the file can't be read (so the caller can fail loud). */
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
                    List<String> effNames = new ArrayList<>();
                    String scope = "";
                    for (int i = 1; i < t.length; i++) {
                        if (KNOWN_EFFECTS.contains(t[i]) || "Unknown".equals(t[i])) effNames.add(t[i]);
                        else { scope = t[i]; break; }
                    }
                    if (effNames.isEmpty()) { warnPolicy(line, "names no known effect"); break; }
                    ctx().denyRules.add(new PolicyRule.Deny(EffectSet.ofNames(effNames), scope, line));
                    break;
                }
                case "pure": {
                    // empty effects = ANY effect forbidden
                    ctx().denyRules.add(new PolicyRule.Deny(EffectSet.empty(), t.length > 1 ? t[1] : "", line));
                    break;
                }
                case "forbid": {
                    // SPEC §6.2: `forbid <A> -> <B>` — two scopes separated by a literal `->` TOKEN
                    // (so `forbid a->b` without surrounding spaces is malformed and dropped).
                    if (t.length >= 4 && t[2].equals("->")) {
                        ctx().forbidRules.add(new PolicyRule.Forbid(t[1], t[3]));
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
                    String scope = "";
                    // optional `in <scope>` prefix; `in` ENDS the keyword even with no scope/value after
                    // (`allow Net in` → no values → dropped), matching the Rust parser. A bare
                    // `t.length > 3` guard let a value-less `allow Net in` keep "in" as an allowed value.
                    int vi = 2;
                    if (t[2].equals("in")) { scope = t.length > 3 ? t[3] : ""; vi = 4; }
                    TreeSet<String> values = new TreeSet<>(); // sorted: the wire surface order
                    for (int i = vi; i < t.length; i++) values.add(t[i]);
                    if (values.isEmpty()) { warnPolicy(line, "allow names no values"); break; }
                    ctx().allowRules.add(new PolicyRule.Allow(Effect.fromSpecName(t[1]), scope, values, line));
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
     *  whole project (matches everything). FAMILY RULING (§6.2 ↔ §3.1): scope segments split on the
     *  same boundaries as the query name ladder — for the JVM that INCLUDES the `$` nested-type
     *  boundary (the ladder already pins `Svc.act` matching `Cases$Svc.act`), so `deny Net client` /
     *  `forbid app -> repo` bite on a function in a nested class (`q.L$app.entry`) exactly as a rust
     *  module or swift enum-namespace member matches. */
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

    /** Split a name OR a policy scope into segments on `.`, `::` AND the JVM's `$` nested-type boundary,
     *  dropping empties. candor-java node ids are dotted (`com.foo.A.m`), but spec §6.2 + the conformance
     *  battery write scopes with `::` (`app::db`, `forbid app::web -> app::db`) and a Rust report names
     *  fns with `::` — so a `::`-written policy scope must still match a dotted name (it silently never
     *  did: the gate was a dead rule → a real violation passed). `$` is a segment boundary too (family
     *  ruling): javac compiles a nested type to `Outer$Inner`, so without it a scope naming the nested
     *  class (`deny Net client` vs `q.L$client.entry`) was silently inert on the JVM while the same
     *  policy bit on the rust/swift engines. Mirrors the Rust impl's `name_segments` (splits on `.`/`:`),
     *  extended with the JVM-only boundary. */
    static String[] nameSegments(String s) {
        List<String> out = new ArrayList<>();
        for (String seg : s.split("[.:$]")) if (!seg.isEmpty()) out.add(seg);
        return out.toArray(new String[0]);
    }

    /** Forward reachability over the project call graph: the first method `start` transitively reaches
     *  whose name matches `scope` (seeded from `start`'s direct callees, so `start` itself isn't a hit),
     *  or null. Used for AS-EFF-009 layering. */
    static String reachesScope(String start, String scope) {
        Deque<String> stack = new ArrayDeque<>(ctx().edges.getOrDefault(start, Set.of()));
        Set<String> seen = new HashSet<>();
        while (!stack.isEmpty()) {
            String n = stack.pop();
            if (!seen.add(n)) continue;
            if (scopeMatches(n, scope)) return n;
            for (String c : ctx().edges.getOrDefault(n, Set.of())) if (!seen.contains(c)) stack.push(c);
        }
        return null;
    }

    static Map<String, EffectSet> loadBaseline(String path) {
        try {
            String text = Files.readString(Path.of(path));
            // Accept BOTH the v0.2 self-describing envelope `{ candor, functions:[...] }` and the legacy
            // v0.1 bare array `[...]` (candor-spec §2: readers MUST accept both). One read path: route it
            // through ReportJson.parseEntries (the single deserializer) and read each Effector's inferred.
            JsonElement root = JsonParser.parseString(text);
            JsonArray arr = root.isJsonObject()
                    ? root.getAsJsonObject().getAsJsonArray("functions")
                    : (root.isJsonArray() ? root.getAsJsonArray() : null);
            if (arr == null) return null;
            Map<String, EffectSet> m = new HashMap<>();
            for (Effector e : ReportJson.parseEntries(arr))
                if (e.fn() != null && !e.fn().isEmpty()) m.put(e.fn(), e.inferred());
            return m;
        } catch (Exception ex) {
            return null;
        }
    }

    /** The baseline's PRODUCING engine build (the §2.1 envelope `candor.version`) — null for the legacy
     *  v0.1 bare array or an unreadable header (then no version comparison is possible: absent provenance
     *  is already the §2.1 "as unverifiable as a mismatch" case, and the guard note stays silent only
     *  because there is nothing concrete to compare). */
    static String baselineVersion(String path) {
        try {
            JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
            if (!root.isJsonObject()) return null;
            JsonElement c = root.getAsJsonObject().get("candor");
            if (c == null || !c.isJsonObject()) return null;
            JsonElement ver = c.getAsJsonObject().get("version");
            return ver != null && ver.isJsonPrimitive() ? ver.getAsString() : null;
        } catch (Exception ex) {
            return null;
        }
    }
}
