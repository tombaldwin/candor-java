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
        // ⟨0.16⟩ Callgraph-aware existence. A function ABSENT from the baseline REPORT is not
        // necessarily new: reports OMIT pure functions (§2), so a formerly-PURE fn that turns effectful
        // reads as "new code" and escapes the guard — the sharpest supply-chain shape. Key existence on
        // the baseline CALLGRAPH sidecar instead (§2.2 — it lists pure leaves), exactly as `gains --json`'s
        // `origin` field does: reuse Query's signalled callgraph load + the caller∪callee node-union.
        //   - sidecar PRESENT: a fn that is a node in it (even with an empty/pure baseline effect set)
        //     and now performs ANY effect is a GAIN → violation. A fn genuinely ABSENT from the graph is
        //     real new code → exempt. This makes pure→effectful a violation.
        //   - sidecar ABSENT: degrade to report-only existence (a formerly-pure fn reads as new — the
        //     pre-⟨0.16⟩ semantics; the guard still catches widening on already-effectful fns). Not a
        //     failure — just the weaker guard, disclosed once on stderr.
        //   - sidecar PRESENT-but-corrupt: fail closed (exit 2), same as a corrupt baseline report — a
        //     broken sidecar must not silently NARROW the guard (drop its pure-leaf nodes → pure→effectful
        //     would masquerade as new). This mirrors gains' "a partial graph proves absence of nothing".
        Query.CallgraphLoad cgl = Query.loadCallgraphSignalled(path); // discloses a corrupt sidecar on stderr
        if (cgl.partial()) {
            System.err.println("candor-java: the baseline call-graph sidecar beside " + path + " is corrupt/"
                    + "unreadable — failing (exit 2); the guard must not silently narrow to report-only "
                    + "existence on a broken sidecar (a formerly-pure→effectful gain would masquerade as new "
                    + "code). Regenerate the baseline: candor <target> --json " + path);
            System.exit(2);
        }
        Set<String> baseCgNodes = new HashSet<>();
        boolean sidecarPresent = cgl.graph() != null;
        if (sidecarPresent) {
            for (var cge : cgl.graph().entrySet()) {
                baseCgNodes.add(cge.getKey());
                baseCgNodes.addAll(cge.getValue());
            }
        } else {
            // Report-only degradation: a formerly-pure fn is indistinguishable from new code, so the
            // pure→effectful transition slips through. Say it once — the guard is weaker here.
            System.err.println("candor-java: no call-graph sidecar beside the baseline " + path
                    + " (looked for its .callgraph.json) — the regression guard degrades to report-only "
                    + "existence: a formerly-pure function that turns effectful reads as new code and is NOT "
                    + "flagged. Regenerate the baseline with a file-mode --json to emit the sidecar and get "
                    + "the full pure→effectful guard.");
        }
        int v = 0;
        // ⟨0.16⟩ Functions whose ONLY gain vs the baseline is `Unknown` — the §4 trust marker,
        // NOT an effect (`pure` policies already exclude it). On real dependency bumps an Unknown-only
        // gain is dominated by resolution noise (dispatch-resolution variance; a JVM anonymous class's
        // positional `$N` differs across versions — SOUNDNESS-LOG 2026-07-16), so it is ADVISORY, never a
        // regression: collect the names and disclose them once, don't raise AS-EFF-005 or exit 1.
        List<String> unknownOnly = new ArrayList<>();
        for (var e : new TreeMap<>(inferred).entrySet()) {
            EffectSet prior = base.get(e.getKey());
            if (prior == null) {
                // Absent from the baseline REPORT. With a sidecar we can tell a formerly-pure fn (a graph
                // node, baseline effect set ∅) from genuinely new code (absent from the graph too):
                //   - graph node → treat its baseline as ∅ (empty): ANY current effect is a gain.
                //   - not a graph node → real new code → exempt (reviewed as new, not a regression).
                // Without a sidecar, existence is report-only: absent means "new" → exempt (pre-⟨0.16⟩).
                if (sidecarPresent && baseCgNodes.contains(e.getKey())) {
                    prior = EffectSet.empty(); // formerly pure — a graph node with no report entry
                } else {
                    continue; // new function (or report-only degradation) — reviewed as new code
                }
            }
            EffectSet gainedSet = e.getValue().minus(prior);
            if (gainedSet.isEmpty()) {
                continue;
            }
            // ⟨0.16⟩ Split the gain: the ratchet fires only on a REAL boundary effect. An
            // Unknown-ONLY gain is advisory (disclosed below), and the REAL gained set (Unknown filtered
            // out) is what the violation reports, so a mixed real+Unknown gain never shows `Unknown`.
            List<String> gained = gainedSet.without(Effect.UNKNOWN).toNames();
            if (gained.isEmpty()) {
                // ⟨unknown-ratchet⟩ OPT-IN (config `unknown-ratchet` / CANDOR_UNKNOWN_RATCHET, default OFF).
                // This is what makes `deny E Unknown` adoptable on legacy DI/reflection-heavy code: the CURRENT
                // Unknown surface is GRANDFATHERED (a fn already Unknown in the baseline shows no gain ⇒ never
                // flagged), and only a NEWLY-introduced Unknown — a blind spot the baseline did not have — fails.
                // So a team freezes today's report as the baseline and the strict gate ratchets the Unknown
                // surface DOWN instead of failing everywhere on day one. Grandfather one by regenerating the
                // baseline. Default OFF preserves the ⟨0.16⟩ advisory posture (Unknown-gains = resolution noise).
                if (ctx().unknownRatchet) {
                    diag(DiagnosticCode.AS_EFF_005, List.of("Unknown"), "`%s` gained an unresolved call (Unknown) "
                            + "not in the baseline — a NEW blind spot (unknown-ratchet); resolve it, or regenerate "
                            + "the baseline to grandfather it", e.getKey());
                    v++;
                } else {
                    unknownOnly.add(e.getKey());
                }
                continue;
            }
            diag(DiagnosticCode.AS_EFF_005, gained, "`%s` gained effect { %s } not present in the baseline",
                    e.getKey(), String.join(", ", gained));
            v++;
        }
        if (!unknownOnly.isEmpty()) {
            List<String> shown = unknownOnly.subList(0, Math.min(3, unknownOnly.size()));
            String more = unknownOnly.size() > 3 ? " (+" + (unknownOnly.size() - 3) + " more)" : "";
            System.err.println("candor-java: note — " + unknownOnly.size() + " function(s) gained an "
                    + "unresolved call (Unknown) vs the baseline but no real effect — advisory, NOT a "
                    + "regression (Unknown is the §4 trust marker, dominated by resolution noise on version "
                    + "bumps): " + String.join(", ", shown) + more + ".");
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
        return checkPolicy(inferred, path, null);
    }

    /** As above, plus the {@code --gate-json} sink so a REFUSAL can still write its document (⟨0.24⟩ SPEC
     *  §3.1). Before this, a scan with a typo'd {@code --policy} path exited 2 having written NOTHING to
     *  the path CI reads — so the wrapper re-read the PREVIOUS run's green verdict as current. This is the
     *  scan-route half of the hazard {@code gate --report} closes; the two routes are the two ways a
     *  pipeline reaches a gate, so closing one of them is closing half of it. */
    static int checkPolicy(Map<String, EffectSet> inferred, String path, String gateJson) {
        if (!parsePolicy(path)) {
            // A SET-but-unreadable policy FAILS the run (exit 2) — it must never gate-pass: a
            // typo'd CANDOR_POLICY path otherwise runs gateless and green (spec §6.2). Found by
            // the spec review: this engine printed loudly but returned clean; the siblings exit 2.
            String why = policyFailure(path);
            System.err.println("candor-java: " + why);
            Candor.writeRefusedGateJson(gateJson, why, List.of());
            System.exit(2);
        }
        return gate(gateInputFromScan(inferred));
    }

    /**
     * ⟨0.24⟩ THE GATE'S INPUT — the seam between "what produced the signature" and "what §6.2 does with
     * it". Every field is ALREADY ACCUMULATED: the gate performs no fixpoint and consults no scan state,
     * so the same matching code serves both routes in.
     *
     * <p>{@link #gateInputFromScan} builds it from the classifier's per-scan direct maps (the fixpoints
     * that used to sit inline in {@code checkPolicy}); {@link #gateInputFromReport} builds it from a
     * WRITTEN report and nothing else. That is the whole point of SPEC §3.1 ⟨0.24⟩: until this split
     * existed, the gate was reachable only THROUGH the classifier, so a defect in the gate and a defect in
     * the classifier were indistinguishable from any end-to-end test. Do NOT re-implement the matching on
     * the report side — the §6.2 clause that mandates this verb was written about exactly that mistake
     * ("an open-coded second copy of the classification … drifting silently because nothing compared them").
     *
     * @param inferred          per fn, the TRANSITIVE effect set — the model's `S`, with candor's
     *                          {@code Unknown} marker carried as a member (the engine encoding of `D ≠ ∅`)
     * @param reasonClasses     per fn, the TRANSITIVE reason-class tokens — the model's `D` (§6.2 ⟨0.19⟩)
     * @param netClasses        per Net-bearing fn, its ⟨0.20⟩ destination classes, already derived
     * @param hosts/cmds/paths/tables  per fn, the TRANSITIVE literal surface for AS-EFF-008
     * @param surfaceIncomplete per fn, the effects whose literal surface is structurally incomplete
     *                          (the AS-EFF-008 fail-closed marker)
     * @param edges             the call graph AS-EFF-009 walks
     * @param synthetic         ⟨0.23⟩ the report entries that are NOT units — {@code interfaceUnion: true}.
     *                          They stay in {@code inferred}, so a `calls` edge naming one still propagates
     *                          its effects to a real caller, but they are never REPORTED as violators.
     *                          Always EMPTY on the scan route, which has no such entries. See {@link #gate}.
     */
    record GateInput(Map<String, EffectSet> inferred,
                     Map<String, TreeSet<String>> reasonClasses,
                     Map<String, List<String>> netClasses,
                     Map<String, TreeSet<String>> hosts,
                     Map<String, TreeSet<String>> cmds,
                     Map<String, TreeSet<String>> paths,
                     Map<String, TreeSet<String>> tables,
                     Map<String, TreeSet<String>> surfaceIncomplete,
                     Map<String, Set<String>> edges,
                     Set<String> synthetic) {}

    /** The scan route into the gate: accumulate the classifier's direct maps over the live call graph.
     *  Byte-for-byte the fixpoints {@code checkPolicy} used to run inline. */
    static GateInput gateInputFromScan(Map<String, EffectSet> inferred) {
        // Reason-scoped Unknown needs the reason CLASS to travel the same call graph the Unknown EFFECT does:
        // a fn that inherits Unknown from a reflect-caused callee is a reflect-class Unknown even though the
        // `reflect:*` reason was emitted DIRECTLY on the callee (unknownWhy is deliberately direct-only, for the
        // human "Unknown sources (direct)" summary). Without this a `deny E Unknown[reflect]` at the CALLER would
        // see no reason, default to `unresolved`, and NOT fire — a reflection-caused Unknown slipping the gate
        // (under-gating = a false all-clear). Propagate the class TOKENS transitively (the paper's `(S,D)` join:
        // D is componentwise-unioned over callees), mirroring literalFixpoint. Report output is unchanged.
        Map<String, TreeSet<String>> reasonClassDirect = new HashMap<>();
        for (var e : ctx().unknownWhy.entrySet()) {
            TreeSet<String> classes = new TreeSet<>();
            // Classify via the STRING path (`classify(ur.format())`), identical to rust/ts/swift — NOT the
            // structured `of(ur)` (Kind) path. The two agree on every prefix this build RECOGNIZES (pinned
            // by a test over `Kind.values()`), but `of()` can only ever recognize what this build's enum
            // lists, so an unlisted token (`closure:`, `missing-config`) down-classifies to `unresolved`
            // while `classify()` maps it correctly — a future/cross-report reason must not under-gate a
            // narrow `Unknown[reflect]` on the java engine alone (review-found parity hazard). ⟨0.24⟩
            // `ambiguous:` used to be in that unlisted set; it is now a canonical §4 kind and both paths
            // give `dispatch`, which is why the hazard is stated as structural, not as a list of tokens.
            for (UnknownReason ur : e.getValue()) classes.add(ReasonClass.classify(ur.format()).token());
            if (!classes.isEmpty()) reasonClassDirect.put(e.getKey(), classes);
        }
        Map<String, TreeSet<String>> reasonClassAcc = literalFixpoint(reasonClassDirect);
        // ⟨0.20⟩ Net destination-class filter (NET-DESTINATION-CLASS-DESIGN.md) needs the fn's (transitive)
        // destination classes — derived exactly like the report's `netClass` field (host fixpoint + the fail-
        // closed masked-surface rule), so the gate and the report agree on what an fn's Net reaches.
        Map<String, TreeSet<String>> netHostsAcc = literalFixpoint(ctx().hostsDirect);
        Map<String, TreeSet<String>> netIncompleteAcc = literalFixpoint(ctx().surfaceIncomplete);
        // Precomputed for every Net-bearing fn — the same set, computed by the same helper, the inline gate
        // used to ask for lazily. `netClassesOf` is only ever called for an fn that HAS Net (it is the `deny`
        // Net membership that triggers it), so materializing exactly those is behaviour-preserving.
        Map<String, List<String>> netClasses = new HashMap<>();
        for (var e : inferred.entrySet())
            if (e.getValue().contains(Effect.NET))
                netClasses.put(e.getKey(), netClassesOf(e.getKey(), netHostsAcc, netIncompleteAcc));
        return new GateInput(inferred, reasonClassAcc, netClasses,
                netHostsAcc,
                literalFixpoint(ctx().cmdsDirect),
                literalFixpoint(ctx().pathsDirect),
                literalFixpoint(ctx().tablesDirect),
                netIncompleteAcc,
                ctx().edges,
                Set.of());   // the scan gates BODIES; synthetic union entries exist only in a written report
    }

    /**
     * ⟨0.24⟩ SPEC §6.2 — THE reason-CLASS SET of a function, and the ONLY definition of it in this engine.
     * The gate reads it to decide whether a {@code deny E Unknown[c…]} rule fires; {@code candor unverified
     * --class} reads it to decide whether an entry is selected. §6.2: "THE GATE AND THE DISCLOSURE MUST
     * APPLY THE SAME RULE, AND SHOULD SHARE THE SAME CODE" — the clause was written about an engine that
     * had two copies, one of them right, "drifting silently because nothing compared them". This is the one
     * copy; a second one is the defect, not an optimisation.
     *
     * <p>Two properties, both normative and both invisible in the field the filter naively wants to read:
     * <ul>
     *   <li>TRANSITIVE. {@code gi.reasonClasses()} is already the fixpoint over the gate's own reach (§4
     *       makes {@code unknownWhy} direct-only — a reason names a site in the function's OWN body — so a
     *       function whose {@code Unknown} is purely INHERITED carries no reason of its own, and matching
     *       against the direct field answers a different question).</li>
     *   <li>FAIL-CLOSED. A function this cannot classify at all gets {@code {unresolved}}, so it is KEPT by
     *       a filter naming its own class and by {@code dynamic}, never silently dropped by every filter
     *       including the one that names it. This is the backstop, NOT the contribution: the contribution
     *       for a directly-raised, unnamed {@code Unknown} happens at the source (a scan records a reason
     *       beside every {@code Unknown} it raises; {@link #gateInputFromReport} contributes per ENTRY),
     *       because a set that has already been unioned over callees can no longer tell which member was
     *       unaccounted-for.</li>
     * </ul>
     * A token that names no class also reads {@code unresolved} rather than becoming a null member — a
     * null in the set is silently unmatchable by every filter, which is the drop this method exists to
     * refuse. (Unreachable today: every token here comes from {@code ReasonClass.classify().token()}.)
     */
    static Set<ReasonClass> reasonClassesOf(GateInput gi, String fn) {
        TreeSet<String> tokens = gi.reasonClasses().get(fn);
        if (tokens == null || tokens.isEmpty()) return Set.of(ReasonClass.UNRESOLVED);
        Set<ReasonClass> out = java.util.EnumSet.noneOf(ReasonClass.class);
        for (String t : tokens) {
            ReasonClass c = ReasonClass.fromToken(t);
            out.add(c == null ? ReasonClass.UNRESOLVED : c);
        }
        return out;
    }

    /** The key identifying one (rule, function) pair for the ⟨0.24⟩ unanswerability withholding. The rule
     *  is identified by its SOURCE LINE — the same string every refusal message quotes. Unambiguous
     *  because a method name holds no whitespace, so the last space is always the join. */
    static String unanswerableKey(PolicyRule.Deny r, String fn) {
        return r.src().trim() + " " + fn;
    }

    /** ⟨0.24⟩ SPEC §6.2 — THE match rule: a function is selected by a reason-class filter when its
     *  {@link #reasonClassesOf} set INTERSECTS the filter. A null filter is "no filter" (every function
     *  matches), which is how {@code --class '*'} and an absent flag are spelled. Shared by the gate's
     *  {@code Unknown[c…]} scoping and by {@code unverified --class}, for the same reason as above. */
    static boolean reasonClassMatches(GateInput gi, String fn, Set<ReasonClass> filter) {
        if (filter == null) return true;
        for (ReasonClass c : reasonClassesOf(gi, fn)) if (filter.contains(c)) return true;
        return false;
    }

    /**
     * ⟨0.24⟩ Apply the parsed §6.2 policy to an already-accumulated signature. THE ONLY matching code in
     * this engine — {@code scan --policy} and {@code gate --report} both land here, which is what makes
     * "the same verdict from the same signature" a property of the code rather than of two consistent
     * authors. Returns the violation count; the caller owns the exit code.
     */
    static int gate(GateInput gi) {
        return gate(gi, Set.of());
    }

    /** ⟨0.24⟩ The gate, with a set of (rule, function) pairs the caller has found UNANSWERABLE over this
     *  input — see {@link Query#unanswerableScopedFilters}. Keys come from {@link #unanswerableKey}. */
    static int gate(GateInput gi, Set<String> unanswerable) {
        int v = 0;
        Map<String, EffectSet> inferred = gi.inferred();
        Map<String, TreeSet<String>> reasonClassAcc = gi.reasonClasses();
        List<String[]> synthHits = new ArrayList<>();   // ⟨0.23⟩ union entries a rule matched — DISCLOSED below
        // AS-EFF-006: a method in scope must not perform (transitively) a denied effect.
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            for (PolicyRule.Deny r : ctx().denyRules) {
                if (!scopeMatches(fn, r.scope())) continue;
                // ⟨0.24⟩ A (rule, function) pair the caller has declared UNANSWERABLE is neither a
                // violation nor a pass — it is withheld, and disclosed as such (SPEC §3.1's per-(rule,
                // function) refusal granularity). Empty on the scan route, so nothing there moves.
                //
                // This is load-bearing rather than tidy. `reasonClassesOf` floors an empty class set at
                // `unresolved` — the right fail-closed default for a matcher — so once the refusal stopped
                // short-circuiting the run, `deny Unknown[unresolved]` over an INHERITED reasonless Unknown
                // began emitting a VIOLATION RECORD naming a class the report never asserted: a fabrication
                // in the direction opposite the one the refusal exists to prevent. §3.1's minimal-refusal
                // rule settles it — "the classes determinable from the entry ALONE" is EMPTY there, so the
                // filter does not yet fire and the missing datum could still make it, which is a refusal,
                // not a firing. A pair that fires only on the default for the absent datum has not fired.
                if (unanswerable.contains(unanswerableKey(r, fn))) continue;
                // pure rule (empty effects) ⇒ any effect except Unknown (handled by AS-EFF-003);
                // deny rule ⇒ the inferred effects that intersect the denied set. Test the EnumSet
                // directly; only materialize the sorted names on an actual violation (rare).
                EffectSet bad = r.effects().isEmpty()
                        ? e.getValue().without(Effect.UNKNOWN)
                        : e.getValue().intersect(r.effects());
                // Reason-scoped Unknown (REASON-SCOPED-UNKNOWN-DESIGN.md): a `deny E Unknown[classes]` rule
                // (non-empty filter) fires its Unknown part ONLY if the fn's Unknown reasons include one of
                // those classes. Concrete effects in `bad` are untouched — only the Unknown membership is scoped.
                if (bad.toNames().contains("Unknown") && !r.unknownClasses().isEmpty()) {
                    // THE SHARED §6.2 RULE — transitive, fail-closed, one definition (see #reasonClassesOf,
                    // which `candor unverified --class` calls too). An Unknown inherited from a
                    // reason-tagged callee is classified by that callee's reason, not defaulted to
                    // unresolved; a reasonless direct Unknown has already CONTRIBUTED `unresolved` at its
                    // source, so a fn reaching both a reasonless hole and a `dispatch:` one is caught by
                    // `[unresolved]` AND by `[dispatch]`.
                    if (!reasonClassMatches(gi, fn, r.unknownClasses()))
                        bad = bad.without(Effect.UNKNOWN);            // tolerated: wrong reason-class
                }
                // Net destination-class (NET-DESTINATION-CLASS-DESIGN.md): a `deny Net[dest…]` rule (non-empty
                // filter — e.g. `deny Net[unknown-host]`) fires its Net part ONLY if the fn reaches one of those
                // destination classes. Fail-closed: a masked surface OR a Net with no visible host is unknown-host,
                // so `deny Net[unknown-host]` bites anything candor can't positively identify as telemetry/partner.
                if (bad.toNames().contains("Net") && !r.netClasses().isEmpty()) {
                    List<String> fnNet = gi.netClasses().getOrDefault(fn, List.of());
                    boolean matched = fnNet.stream().anyMatch(r.netClasses()::contains);
                    if (!matched) bad = bad.without(Effect.NET);       // tolerated: only asserted-safe destinations
                }
                if (!bad.isEmpty()) {
                    // ⟨0.23⟩ A SYNTHETIC `interfaceUnion` ENTRY IS NOT A FUNCTION, so it cannot "perform"
                    // anything and must not become a violation ROW. Its `fn` names a BODILESS declaration
                    // (`lib.Store.save` on an interface, an abstract member); the effects under it are the
                    // CHA union over the package's implementers, published under that hash so a CHAINED
                    // CONSUMER's dispatch resolves across the scan boundary. Every one of those effects is
                    // already carried by the implementer's OWN entry in the same report — which IS a unit,
                    // and IS gated one loop iteration away.
                    //
                    // MEASURED: with CANDOR_WORKSPACE_CHAIN set, `scan --policy deny Net` over an interface
                    // + one Net implementer flags 1 violation while `gate --report` over the report that
                    // scan just wrote flagged 2, the extra row being the synthetic `app.api.Client.get`.
                    // That refutes §3.1's byte-equality MUST on the engine's OWN output — and it does it in
                    // the FABRICATION direction, so turning an opt-in PRODUCER rung on changed the
                    // producer's own gate verdict. It is disclosed, not dropped: the note below names each
                    // one and the rule it matched, so nothing the gate saw goes unsaid.
                    if (gi.synthetic().contains(fn)) {
                        synthHits.add(new String[]{fn, String.join(", ", bad.toNames()), r.src().trim()});
                        continue;
                    }
                    List<String> bn = bad.toNames();
                    // §6.2 ⟨0.19⟩: when Unknown is denied, record ALL reason classes on the fn (transitive) so a
                    // --gate-json consumer sees every reason the strict gate bit — not just the matched class.
                    List<String> reasonClass = bn.contains("Unknown")
                            ? new java.util.TreeSet<>(reasonClassAcc.getOrDefault(fn, new java.util.TreeSet<>())).stream().toList()
                            : java.util.List.of();
                    // ⟨0.20⟩ when Net is denied, record ALL of the fn's destination classes (transitive) so a
                    // --gate-json consumer sees which class the security gate bit — bare `deny Net` too.
                    List<String> netClass = bn.contains("Net")
                            ? gi.netClasses().getOrDefault(fn, List.of())
                            : java.util.List.of();
                    diag(DiagnosticCode.AS_EFF_006, bn, reasonClass, netClass, "`%s` performs { %s }, forbidden by policy%s: `%s`",
                            fn, String.join(", ", bn),
                            r.scope().isEmpty() ? "" : " (scope `" + r.scope() + "`)", r.src());
                    v++;
                }
            }
        }
        // ⟨0.23⟩ THE SYNTHETIC ENTRIES A RULE MATCHED — said out loud, on stderr, without moving the
        // verdict. A union entry is a republication of effects the implementers' own entries already
        // carry, so skipping the ROW loses no reach; skipping it SILENTLY would lose the one thing a
        // reader of a chained DEPENDENCY's report wants here, which is that the dependency publishes a
        // dispatch surface reaching a denied effect.
        if (!synthHits.isEmpty()) {
            System.err.println("candor: note — " + synthHits.size() + " ⟨0.23⟩ interfaceUnion entr"
                    + (synthHits.size() == 1 ? "y matches a policy rule and is NOT gated as a function"
                                             : "ies match a policy rule and are NOT gated as functions")
                    + ": the key names a BODILESS declaration, and the effects under it are the CHA union "
                    + "over implementers, each of which IS gated under its own entry.");
            for (String[] h : synthHits)
                System.err.println("    `" + h[0] + "`  { " + h[1] + " }  would have matched  `" + h[2] + "`");
        }
        // Provable-purity DISCLOSURE (advisory — NEVER a violation, so `v`/exit are untouched): methods in a
        // pure/deny scope that PASS but are Unknown (the Unknown could hide the forbidden effect — a
        // fn/closure-injected port). Surfaces the gap automatically (eval/fixloop/DISPATCH-NOTE.md).
        List<String[]> holes = new ArrayList<>();
        for (var e : new TreeMap<>(inferred).entrySet()) {
            // Same predicate + upgrade reconstruction as `candor unverified` (Query) — one source of truth.
            PolicyRule.Deny r = unverifiedHoleRule(e.getKey(), e.getValue(), ctx().denyRules);
            if (r != null) holes.add(new String[]{e.getKey(), ruleUpgrade(r)[1]});
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
        Map<String, TreeSet<String>> incomplete = gi.surfaceIncomplete();
        Map<String, TreeSet<String>> hostFixpoint = gi.hosts();
        v += checkAllowlist(inferred, "Net", hostFixpoint, incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> hostPart(a).equals(hostPart(reached))));
        // `Llm` ⟨0.13⟩ rides Net's host literal (SPEC §1) — `allow Llm <host…>` restricts which MODEL
        // hosts a scope may reach, matched by hostname like Net. The reached surface is the SAME hostsDirect
        // (an Llm host WAS captured as a Net host literal); the incompleteness gate keys off "Net" (a
        // runtime/masked host marks the Net surface incomplete → `allow Llm` fails closed too, so a benign
        // visible model host can't MASK an invisible forbidden one).
        v += checkAllowlist(inferred, "Llm", hostFixpoint, incompleteAsLlm(incomplete),
                (allowed, reached) -> allowed.stream().anyMatch(a -> hostPart(a).equals(hostPart(reached))));
        v += checkAllowlist(inferred, "Exec", gi.cmds(), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> cmdBase(a).equals(cmdBase(reached))));
        v += checkAllowlist(inferred, "Fs", gi.paths(), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> pathCovered(a, reached)));
        v += checkAllowlist(inferred, "Db", gi.tables(), incomplete,
                (allowed, reached) -> allowed.stream().anyMatch(a -> tableCovered(a, reached)));
        // AS-EFF-009: a method in scope A must not transitively reach into scope B (over the call graph).
        for (PolicyRule.Forbid r : ctx().forbidRules) {
            for (String fn : new TreeSet<>(gi.edges().keySet())) {
                if (!scopeMatches(fn, r.from())) continue;
                String hit = reachesScope(gi.edges(), fn, r.to());
                if (hit != null) {
                    diag(DiagnosticCode.AS_EFF_009, "`%s` reaches into a forbidden layer (via `%s`), "
                            + "violating policy: `forbid %s -> %s`", fn, hit, r.from(), r.to());
                    v++;
                }
            }
        }
        return v;
    }

    /**
     * ⟨0.24⟩ THE REPORT ROUTE INTO THE GATE (SPEC §3.1 `gate --report`) — a signature read from a written
     * report, with no scan and no classifier.
     *
     * <p><b>THE MUST NOT, and how this method satisfies it.</b> §3.1 ⟨0.24⟩: "An engine MUST NOT re-derive,
     * widen, or re-classify anything while serving this verb: it reads `S` and `D` from the report as given
     * … In particular a report entry that is ABSENT is absent — the ⟨0.21⟩ purity claim — and MUST NOT be
     * back-filled from a callgraph sidecar or a chained dep." So the ONLY input here is {@code fns} (the
     * report's own {@code functions} array) and {@code rawUnknownWhy} (the same array's {@code unknownWhy}
     * strings, read raw — see below). Concretely, and each of these is a thing this codebase's SCAN loader
     * does and this method does not:
     * <ul>
     *   <li>no {@code .callgraph.json} sidecar (unlike {@code callers}/{@code tour}/{@code whatif}/{@code
     *       fix}, which all call {@link Query#loadCallgraph}) — an fn absent from {@code functions} has NO
     *       entry here even if the sidecar names it;</li>
     *   <li>no {@code CANDOR_DEPS} / {@code .candor/config} dep chaining ({@link Loader}), no
     *       {@code .hierarchy.json}, no CHA, no κ ledger;</li>
     *   <li>no re-classification: {@code hosts}/{@code cmds}/{@code paths}/{@code tables} and
     *       {@code netClass} are taken VERBATIM (they are already transitive on the wire — see
     *       {@code ReportWriter#writeJson}, which writes the fixpointed accumulators), so no literal is
     *       re-matched and no host is re-mapped through THIS process's {@code net-partner} config.</li>
     * </ul>
     *
     * <p><b>{@code surfaceIncomplete} is left EMPTY, and that is why {@code gate --report} refuses every
     * AS-EFF-008 {@code allow} rule</b> ({@link Query#gate}). The marker does not ride the ⟨0.24⟩ wire in
     * any form. The first cut of this method reconstructed it for {@code Net} from
     * {@code netClass ∋ unknown-host}; the scan-vs-gate equivalence test refuted that in one run, because
     * {@code unknown-host} is OVERLOADED — {@link Literals#netDestClass} returns it for any host it does
     * not recognise, so a function with a perfectly visible {@code api.stripe.com} carries it too. Reading
     * it as "masked" flagged 2 functions the scan passes. The reconstruction was not merely imprecise, it
     * was reading a different predicate. Leaving the map empty would instead fail OPEN (a masked command
     * beside a benign literal would be CERTIFIED), so the rule is refused rather than evaluated.
     *
     * <p>The one thing that IS computed is the TRANSITIVE closure of the reason classes — because
     * {@code unknownWhy} is direct-only by contract (§4) while §6.2 requires the class set to resolve
     * "TRANSITIVELY, over the same reach the gate uses". It is computed by the SHARED
     * {@link Literals#literalFixpoint(Map, Map)} over the report's own {@code calls} edges: report data in,
     * report data out, and the same function the scan path uses, so the two cannot drift.
     *
     * @param rawUnknownWhy the report's {@code unknownWhy} strings, UNPARSED. {@link Effector#unknownWhy()}
     *        holds {@link UnknownReason}s, and {@code ReportJson.parseEntries} drops any tag with no colon
     *        ({@code UnknownReason.parse} returns null) — so a foreign engine's dot-free {@code
     *        missing-config} marker would vanish, taking a real disclosure out of `D` beside a surviving
     *        one. Since `D` is half the signature this verb exists to gate on, it is read raw. Pass an empty
     *        map to fall back to the parsed reasons.
     */
    static GateInput gateInputFromReport(List<Effector> fns, Map<String, List<String>> rawUnknownWhy) {
        Map<String, EffectSet> inferred = new HashMap<>();
        Map<String, Set<String>> edges = new HashMap<>();
        Map<String, TreeSet<String>> whyDirect = new HashMap<>();
        Map<String, List<String>> netClasses = new HashMap<>();
        Map<String, TreeSet<String>> hosts = new HashMap<>(), cmds = new HashMap<>(),
                paths = new HashMap<>(), tables = new HashMap<>(), incomplete = new HashMap<>();
        Set<String> synthetic = new HashSet<>(), real = new HashSet<>();
        for (Effector e : fns) {
            String fn = e.fn();
            // ⟨0.23⟩ An `interfaceUnion: true` entry is not a UNIT — it is a CHA union published under a
            // bodiless declaration's hash so a CHAINED CONSUMER's dispatch resolves across the scan
            // boundary (ReportWriter#appendInterfaceUnions). It records its effects and is tracked here so
            // the gate does not report it AS a function; a name that is ALSO carried by a real entry (a
            // duplicate `fn`) is real, and `real` wins below — never the other way round, or a marked
            // sibling could erase a genuine violator.
            if (e.interfaceUnion()) synthetic.add(fn); else real.add(fn);
            // JOIN on a repeated `fn` rather than overwrite: a duplicate key is malformed input, and taking
            // the union is the direction that cannot turn a violation into a pass.
            inferred.merge(fn, e.inferred(), EffectSet::join);
            edges.computeIfAbsent(fn, k -> new HashSet<>()).addAll(e.calls());
            if (!e.hosts().isEmpty()) hosts.computeIfAbsent(fn, k -> new TreeSet<>()).addAll(e.hosts());
            if (!e.cmds().isEmpty()) cmds.computeIfAbsent(fn, k -> new TreeSet<>()).addAll(e.cmds());
            if (!e.paths().isEmpty()) paths.computeIfAbsent(fn, k -> new TreeSet<>()).addAll(e.paths());
            if (!e.tables().isEmpty()) tables.computeIfAbsent(fn, k -> new TreeSet<>()).addAll(e.tables());
            if (!e.netClass().isEmpty())
                netClasses.computeIfAbsent(fn, k -> new ArrayList<>()).addAll(e.netClass());
            // `incomplete` stays empty — see the class note above. Every `allow` rule is refused upstream.
            List<String> raw = rawUnknownWhy.get(fn);
            if (raw == null || raw.isEmpty())
                raw = e.unknownWhy().stream().map(UnknownReason::format).collect(Collectors.toList());
            // Classify via the STRING path, identical to the scan route (which deliberately uses
            // `classify(ur.format())` rather than the structured `of(ur)`) and to rust/ts/swift.
            for (String why : raw)
                whyDirect.computeIfAbsent(fn, k -> new TreeSet<>()).add(ReasonClass.classify(why).token());
            // ⟨0.24⟩ SPEC §6.2 requirement (3), THE CONTRIBUTION, on the one route where the producer-side
            // repair cannot reach: a report is DATA, so `Loader#synthesizeReasonlessDepReasons` (which makes
            // the state unreachable in a report THIS engine writes) says nothing about a hand-authored or
            // foreign one. An entry that raises `Unknown` DIRECTLY and names no reason for it CONTRIBUTES
            // `unresolved` here, at the entry, BEFORE the fixpoint — which is what makes it compose: a
            // caller of one reasonless entry and one `dispatch:` entry accumulates {unresolved, dispatch}
            // and is caught by BOTH filters. Contributing at the JOIN instead (an empty-set default) cannot
            // do that: by then the two entries' sets have already been unioned, and the caller of both is
            // byte-identical to the caller of the reasoned one alone — the §6.2 counterexample in which
            // ADDING a call turned a red verdict green.
            //
            // GATED ON A DIRECT `Unknown` IT DID NOT NAME, never on the reason set being absent, because
            // absence is ALSO what an INHERITED `Unknown` looks like and marking those is the mirror
            // fabrication (measured elsewhere at 435 functions where the legitimate count is 0). An ABSENT
            // `direct` key reads as an empty EffectSet and therefore contributes NOTHING: it is a report
            // that did not carry the channel, not a claim of a direct `Unknown`. That case stays with the
            // fail-closed empty-set rule in `reasonClassesOf`, which keeps it rather than drops it.
            if (e.direct().hasUnknown() && raw.isEmpty())
                whyDirect.computeIfAbsent(fn, k -> new TreeSet<>()).add(ReasonClass.UNRESOLVED.token());
        }
        synthetic.removeAll(real);   // a name a REAL entry also claims is a real unit — see the note above
        return new GateInput(inferred, literalFixpoint(whyDirect, edges), netClasses,
                hosts, cmds, paths, tables, incomplete, edges, synthetic);
    }

    /** Re-key the surface-incompleteness map so an incomplete "Net" surface ALSO reads incomplete for
     *  "Llm" — `Llm` rides the Net host literal (SPEC §1 ⟨0.13⟩), so a runtime/masked host that makes the
     *  Net surface incomplete must fail-close `allow Llm …` identically (a benign visible model host must
     *  not certify a scope that also reaches a hidden one). */
    static Map<String, TreeSet<String>> incompleteAsLlm(Map<String, TreeSet<String>> incomplete) {
        Map<String, TreeSet<String>> out = new HashMap<>();
        for (var e : incomplete.entrySet())
            if (e.getValue().contains("Net")) out.put(e.getKey(), new TreeSet<>(Set.of("Llm")));
        return out;
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

    /**
     * ⟨0.24⟩ One token the policy names that this engine cannot honour — the token itself, the accepted
     * set, and the rule it appeared in. A RECORD rather than a formatted string because the two consumers
     * want different things out of it: the GATE wants one sentence to refuse with, and {@code parsepolicy}
     * (the §3.1 witness) has to put the token in its JSON, where a consumer reads it as data.
     */
    record PolicyTokenError(String kind, String token, List<String> accepted, String known, String rule) {
        /** The one-line diagnostic — the same words on the gate route and in the witness's `errors`. */
        String message() { return "unknown " + kind + " `" + token + "` (known: " + known + ")"; }
    }

    /**
     * ⟨0.24⟩ Non-empty when the policy was READ but CANNOT BE HONOURED AS WRITTEN (SPEC §6.2: an
     * unrecognised reason-class or Net destination-class token). Distinct from {@link #parsePolicy}
     * returning false for an unreadable FILE ({@link #policyUnreadable}); on the GATE routes the posture
     * is the same one — exit 2, policy NOT evaluated — but `parsepolicy` REPORTS it and exits 0 (§3.1).
     */
    static final List<PolicyTokenError> policyErrors = new ArrayList<>();

    /**
     * ⟨0.24⟩ True when {@link #parsePolicy} returned false because the FILE could not be read, so a caller
     * can tell "there is no parse to show you" from "here is the parse, and here is what I could not
     * honour". `parsepolicy` is the only caller that needs to: it refuses the first and reports the second.
     */
    static boolean policyUnreadable;

    /**
     * ⟨0.24⟩ SPEC §6.2 — <b>AN UNRECOGNISED CLASS TOKEN IS A POLICY ERROR, not a warning.</b> The clause
     * used to justify the query/policy asymmetry by asserting that dropping such a token on the policy side
     * can only WIDEN the rule, so the failure is loud. Measured four-way, it does both, and the second
     * direction is fail-open:
     * <ul>
     *   <li>{@code deny Unknown[corp]} — the ONLY token is unrecognised, the filter empties, and the rule
     *       widens to a bare {@code deny Unknown}. Merely surprising — except that this engine printed
     *       <i>"ignoring policy rule (unknown reason-class/alias `corp`)"</i> and then KEPT and re-scoped
     *       it. A FALSE DISCLOSURE, the {@code net-partner} class PART 13b already exists for.</li>
     *   <li>{@code deny Unknown[dispatch,nativ]} — a <b>typo among valid tokens</b>. It was silently
     *       dropped, the rule NARROWED to {@code [dispatch]}, and it no longer gated native-caused holes
     *       at all while the operator read a gate that looked armed. Fail-open, and it is the COMMON case:
     *       a typo lands beside correct tokens far more often than alone.</li>
     * </ul>
     * A policy that cannot be honoured as written is not silently rewritten into a different policy.
     *
     * <p>EVERY offending token is recorded, not just the first: {@code parsepolicy} has to name them all
     * (a witness that stops at the first one sends the operator round the loop once per typo), while the
     * gate refuses on the first — it does not matter which token defeated it.
     */
    static void policyError(String line, String kind, String token, List<String> accepted, String known) {
        policyErrors.add(new PolicyTokenError(kind, token, accepted, known, line));
    }

    /**
     * The exit-2 diagnostic for a policy {@link #parsePolicy} rejected, distinguishing UNREADABLE (the
     * file) from UNHONOURABLE (⟨0.24⟩ an unrecognised class token). One place, so all four GATE call
     * sites — the scan gate, {@code gate --report}, {@code whatif} and {@code fix-gate} — take the same
     * posture and print the same words. ({@code parsepolicy} shares the wording but NOT the posture: §3.1
     * ⟨0.24⟩ — the witness reports and exits 0, since a diagnostic that refuses to explain the thing being
     * diagnosed has inverted its purpose.)
     */
    static String policyFailure(String path) {
        return !policyErrors.isEmpty()
                ? "policy " + path + " cannot be honoured AS WRITTEN — "
                  + policyErrors.get(0).message() + " — in policy rule: " + policyErrors.get(0).rule()
                  + "\n        Refusing (exit 2), policy NOT evaluated: dropping the token would rewrite the "
                  + "policy into a DIFFERENT one. If it is the rule's only class token the rule WIDENS to the "
                  + "bare effect; if it sits beside valid tokens the rule NARROWS and stops gating what you "
                  + "spelled, while the gate still looks armed."
                  + "\n        Fix the spelling, or define it in `.candor/config` as "
                  + "`unknown-alias <name> = <class,…>`."
                : "policy file " + path + " could not be read — failing (exit 2), policy NOT evaluated";
    }

    /** Parse a CANDOR_POLICY file into deny/forbid rules. One rule per line; `#` comments + blanks
     *  ignored. Returns false if the file can't be read ({@link #policyUnreadable}), or (⟨0.24⟩) if a rule
     *  names a class token this engine does not recognise ({@link #policyErrors}). A GATE caller prints
     *  {@link #policyFailure} and exits 2; `parsepolicy` reports the errors beside the parse and exits 0. */
    static boolean parsePolicy(String path) {
        policyErrors.clear();
        policyUnreadable = false;
        ctx().vocabularyUsed.clear();   // ⟨0.24⟩ recomputed per parse — the disclosure is about THIS policy
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of(path));
        } catch (IOException e) {
            policyUnreadable = true;
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
                    // Reason-class filter on an `Unknown` membership (REASON-SCOPED-UNKNOWN-DESIGN.md): empty ⇒
                    // `Unknown[*]` (any reason — the bare form); non-empty ⇒ only those classes. `*` = all.
                    java.util.Set<ReasonClass> unknownClasses = new java.util.LinkedHashSet<>();
                    boolean unknownStar = false;
                    // Destination-class filter on a `Net` membership (NET-DESTINATION-CLASS-DESIGN.md): empty ⇒
                    // `Net[*]` (any destination — the bare form); non-empty ⇒ only a fn reaching one of these.
                    java.util.Set<String> netClasses = new java.util.LinkedHashSet<>();
                    boolean netStar = false;
                    String scope = "";
                    for (int i = 1; i < t.length; i++) {
                        String tok = t[i];
                        if (KNOWN_EFFECTS.contains(tok) || "Unknown".equals(tok)) {
                            effNames.add(tok);
                            if ("Unknown".equals(tok)) unknownStar = true;      // bare Unknown ⇒ all classes
                            if ("Net".equals(tok)) netStar = true;              // bare Net ⇒ all destinations
                        } else if (tok.startsWith("Net[") && tok.endsWith("]")) {
                            effNames.add("Net");
                            String inner = tok.substring("Net[".length(), tok.length() - 1);
                            for (String cn : inner.split(",")) {
                                cn = cn.trim();
                                if (cn.isEmpty()) continue;
                                if (cn.equals("*")) { netStar = true; continue; }
                                if (Literals.NET_DEST_CLASSES.contains(cn)) netClasses.add(cn);
                                // ⟨0.24⟩ a POLICY ERROR, not a warning — see #policyError. The Net
                                // destination-class token has the identical two directions as the reason
                                // class: `Net[unkown-host]` alone WIDENS to bare `Net`, and
                                // `Net[known-partner,unkown-host]` NARROWS and stops gating unknown hosts.
                                // MEASURED on this engine at 2cdc443: both printed "ignoring policy rule"
                                // and both kept a rewritten rule, exit 0.
                                else policyError(line, "Net destination-class", cn,
                                        List.of("known-telemetry", "known-partner", "unknown-host", "*"),
                                        "known-telemetry, known-partner, unknown-host, or *");
                            }
                        } else if (tok.startsWith("Unknown[") && tok.endsWith("]")) {
                            effNames.add("Unknown");
                            String inner = tok.substring("Unknown[".length(), tok.length() - 1);
                            for (String cn : inner.split(",")) {
                                cn = cn.trim();
                                if (cn.isEmpty()) continue;
                                if (cn.equals("*")) { unknownStar = true; continue; }
                                // Built-in alias `dynamic` = every GENUINE blind-spot class (excludes `setup`);
                                // the design's recommended usable strict gate. Includes `unresolved` (the catch-all),
                                // so `Unknown[dynamic]` never under-gates.
                                if (cn.equals("dynamic")) { unknownClasses.addAll(ReasonClass.dynamicSet()); continue; }
                                ReasonClass rc = ReasonClass.fromToken(cn);
                                // ⟨0.19⟩ a config `unknown-alias <name> = …` (SPEC §6.2) referenced explicitly.
                                java.util.Set<ReasonClass> alias = rc == null ? ctx().unknownAliases.get(cn) : null;
                                if (rc != null) unknownClasses.add(rc);
                                // ⟨0.24⟩ record the alias USE. A config file that supplied vocabulary a
                                // rule referenced PARTICIPATED IN THE VERDICT, and SPEC §3.1 requires the
                                // gate document to name it.
                                else if (alias != null) {
                                    unknownClasses.addAll(alias);
                                    ctx().vocabularyUsed.add(cn);
                                }
                                // ⟨0.24⟩ a POLICY ERROR, not a warning — see #policyError.
                                else policyError(line, "reason-class/alias", cn,
                                        List.of("reflect", "dispatch", "indirect", "native", "unresolved",
                                                "setup", "dynamic", "*"),
                                        "reflect, dispatch, indirect, native, unresolved, setup; "
                                        + "aliases: dynamic, *, or a config `unknown-alias`");
                            }
                        } else { scope = tok; break; }
                    }
                    if (effNames.isEmpty()) { warnPolicy(line, "names no known effect"); break; }
                    // `*` (or bare `Unknown`) means all classes ⇒ empty filter (matches any Unknown).
                    if (unknownStar) unknownClasses.clear();
                    // `*` (or bare `Net`) means all destinations ⇒ empty filter (matches any Net).
                    if (netStar) netClasses.clear();
                    // A2 under-gating lint: a narrowed scope that omits `unresolved` (the catch-all for holes an
                    // engine couldn't classify) may silently tolerate exactly those — flag it (advisory, not fatal).
                    // NOT via warnPolicy: the rule is KEPT (it still gates), so "ignoring policy rule" is wrong
                    // wording (the same fix applied in the rust/ts/swift A2 lints).
                    //
                    // ⟨0.24⟩ …and NOT at all once a class token has already failed: the advice would be about a
                    // rule the engine is refusing to run, and `deny Unknown[reflect,unresolvd]` would be told to
                    // "add `unresolved`" — which it plainly tried to. Advising on a rewritten rule is the shape
                    // of the false disclosure this rung exists to remove.
                    else if (policyErrors.isEmpty() && !unknownClasses.isEmpty()
                            && !unknownClasses.contains(ReasonClass.UNRESOLVED)) {
                        System.err.println("candor: policy rule narrows `Unknown[…]` but omits `unresolved` — may UNDER-gate on holes "
                                + "the engine couldn't classify; add `unresolved` (or use `dynamic`) to stay conservative: " + line);
                    }
                    ctx().denyRules.add(new PolicyRule.Deny(EffectSet.ofNames(effNames), scope, line, unknownClasses, netClasses));
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
                    if (!t[1].equals("Net") && !t[1].equals("Exec") && !t[1].equals("Fs")
                            && !t[1].equals("Db") && !t[1].equals("Llm")) {
                        // `Llm` ⟨0.13⟩ carries a literal surface — it rides Net's host literal, so a masked
                        // model host can't evade `allow Llm host` (the AS-EFF-008 fail-closed treatment).
                        warnPolicy(line, "allow supports only Net hosts / Llm hosts / Exec commands / Fs paths / Db tables");
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
        // ⟨0.24⟩ the rules PARSED, but at least one names a class token this engine cannot honour — a GATE
        // caller takes the unreadable-policy posture over it (exit 2), never the rewritten rule. The
        // `parsepolicy` witness instead REPORTS {@link #policyErrors} beside the parse and exits 0 (§3.1).
        return policyErrors.isEmpty();
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

    /** ⟨0.20⟩ The `Net` destination classes an fn reaches (transitive) — the SAME derivation as the report's
     *  `netClass` field: an exact host-literal match (Literals.netDestClass) for the visible hosts, plus the
     *  fail-closed `unknown-host` when the Net surface is masked (AS-EFF-008) OR carries no visible host (a
     *  runtime-computed endpoint). Call only for an fn known to have Net; returns a sorted list. */
    private static List<String> netClassesOf(String fn, Map<String, TreeSet<String>> hostsAcc,
                                             Map<String, TreeSet<String>> incompleteAcc) {
        java.util.TreeSet<String> classes = new java.util.TreeSet<>();
        TreeSet<String> hk = hostsAcc.get(fn);
        if (hk != null) for (String h : hk) classes.add(Literals.netDestClass(h, ctx().netPartners));
        TreeSet<String> inc = incompleteAcc.get(fn);
        if ((inc != null && inc.contains("Net")) || hk == null || hk.isEmpty()) classes.add("unknown-host");
        return new ArrayList<>(classes);
    }

    /** The single predicate for a provable-purity hole (eval/fixloop/DISPATCH-NOTE.md): a method that is
     *  Unknown, sits in a pure/deny scope, and PASSES that rule (carries none of its forbidden real effects)
     *  — so its compliance is asserted but not verified (the Unknown could hide the very effect the rule
     *  forbids; the classic case is a fn/closure-injected port). A *real* violation is the gate's job, not
     *  this. Returns the first governing rule under which the method is such a hole, or null. Shared by the
     *  gate note ({@link #checkPolicy}) and `candor unverified` (Query) so "what a hole is" has ONE
     *  definition — the two disclosure paths cannot drift (conformance PART 12d pins their agreement). */
    static PolicyRule.Deny unverifiedHoleRule(String fn, EffectSet inferred, List<PolicyRule.Deny> deny) {
        if (!inferred.toNames().contains("Unknown")) return null;
        for (PolicyRule.Deny r : deny) {
            if (!scopeMatches(fn, r.scope())) continue;
            boolean violates = r.effects().isEmpty()
                    ? !inferred.without(Effect.UNKNOWN).isEmpty()   // pure: any real effect is a violation
                    : !inferred.intersect(r.effects()).isEmpty();    // deny: a named effect is a violation
            if (!violates) return r;
        }
        return null;
    }

    /** Reconstruct a rule's source form and its `Unknown`-forbidding upgrade: `{source, upgrade}`. `pure
     *  <scope>` → {"pure <scope>", "deny Unknown <scope>"}; `deny <E…> <scope>` → {"deny <E…> <scope>",
     *  "deny <E…> Unknown <scope>"}. Shared so the gate note and `unverified` name the identical upgrade. */
    static String[] ruleUpgrade(PolicyRule.Deny r) {
        String suffix = r.scope().isEmpty() ? "" : " " + r.scope();
        if (r.effects().isEmpty())
            return new String[]{"pure" + suffix, "deny Unknown" + suffix};
        String effs = String.join(" ", r.effects().toNames());
        return new String[]{"deny " + effs + suffix, "deny " + effs + " Unknown" + suffix};
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

    /** Forward reachability over the project call graph: the NEAREST method `start` transitively reaches
     *  whose name matches `scope` (seeded from `start`'s direct callees, so `start` itself isn't a hit),
     *  or null. Used for AS-EFF-009 layering.
     *
     *  <p><b>The VERDICT never depended on the traversal; the WITNESS did.</b> {@code hit != null} is a set
     *  property — the walk visits the whole reachable set before returning null — so the violation, the
     *  count and the exit code are the same under any order. But the node returned is the one named in
     *  the diagnostic and in {@code --gate-json}'s machine-readable {@code detail}, and this used to be a
     *  DEPTH-FIRST walk over a stack seeded from a {@code HashSet}: the branch explored first was whichever
     *  bucket the set happened to hand over. Demonstrated — with two routes out of {@code app.A.run}, one
     *  crossing at 2 hops and one at 6, it named the 6-hop node; and two structurally identical siblings
     *  were resolved to different members of the same class.
     *
     *  <p>That is the shape {@code 9f8e71c} removed from four supertype walks ("walk an unordered set,
     *  return the first hit"), and the reason to remove it here too is that an arbitrary witness reads
     *  exactly like a chosen one. Breadth-first with a SORTED expansion makes it the nearest crossing —
     *  the boundary a reader would actually hoist — with ties broken by name, so the answer is a fact
     *  about the call graph rather than about string hashing. */
    static String reachesScope(Map<String, Set<String>> edges, String start, String scope) {
        Deque<String> q = new ArrayDeque<>(sortedCallees(edges, start));
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String n = q.poll();                       // poll, not pop: FIFO == nearest-first
            if (!seen.add(n)) continue;
            if (scopeMatches(n, scope)) return n;
            for (String cc : sortedCallees(edges, n)) if (!seen.contains(cc)) q.add(cc);
        }
        return null;
    }

    /** {@code fn}'s callees in a stable order. The graph's values are {@code HashSet}s, so this is
     *  the one place the ordering of a BFS layer is decided; sorting here keeps the tie-break a property of
     *  the NAMES rather than of their hash codes. Returns the shared empty list for a leaf, so the common
     *  case allocates nothing. */
    private static List<String> sortedCallees(Map<String, Set<String>> edges, String fn) {
        Set<String> cs = edges.get(fn);
        if (cs == null || cs.isEmpty()) return List.of();
        List<String> out = new ArrayList<>(cs);
        Collections.sort(out);
        return out;
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
