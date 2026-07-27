package io.poly.candor.model;

/**
 * The NORMATIVE projection of a raw {@code unknownWhy} reason onto a fixed, cross-engine reason CLASS
 * (candor-spec REASON-SCOPED-UNKNOWN-DESIGN.md §1). Reason-scoped policies (`deny E Unknown[class]`)
 * quantify over these classes, so the mapping MUST be identical in every engine — otherwise
 * `deny E Unknown[reflect]` would mean different things per engine and break the four-way contract.
 *
 * <p>The class set is CLOSED (six members). The raw→class map is grounded in the 2026-07-16 four-engine
 * `unknownWhy` audit; a raw reason matching no pinned prefix maps to {@link #UNRESOLVED} — conservative:
 * it stays in scope of any {@code Unknown[*]} / {@code Unknown[dynamic]} policy, never silently tolerated.
 */
public enum ReasonClass {
    /** reflection / metaprogramming: ts reflect:* / reflect_apply / reflect-metadata; swift reflecting / dynamicMemberLookup; (rust/java to emit). */
    REFLECT("reflect"),
    /** unresolved virtual/dynamic dispatch candor declined to resolve: dispatch:* ; ⟨0.24⟩ the canonical
     *  ambiguous:* (rust's same-name name-resolution ambiguity) projects here too — §6.2's normative table. */
    DISPATCH("dispatch"),
    /** callback / closure / function-value indirection: callback:* ; ts closure. */
    INDIRECT("indirect"),
    /** FFI / native boundary: native:* (JNI / C-interop / native addons as engines emit them). */
    NATIVE("native"),
    /** generic unresolvable call/import, the ⟨0.24⟩ registered dep:/dep-stale: dependency-boundary kinds,
     *  AND the catch-all for any unrecognized raw reason. */
    UNRESOLVED("unresolved"),
    /** the analysis is not wired up (fixable, not a real dynamic hole): missing-config / no-tsconfig. NOT emitted today — see design finding 1. */
    SETUP("setup");

    private final String token;
    ReasonClass(String token) { this.token = token; }

    /** The lowercase policy-facing token (`deny E Unknown[<token>]`). */
    public String token() { return token; }

    /** Parse a policy-facing token back to a class; null if it names no class. */
    public static ReasonClass fromToken(String t) {
        for (ReasonClass c : values()) if (c.token.equals(t)) return c;
        return null;
    }

    /** The {@code dynamic} alias: every GENUINE blind-spot class (excludes {@link #SETUP}), incl.
     *  {@link #UNRESOLVED} so {@code Unknown[dynamic]} never under-gates. Shared by the policy parser and
     *  the {@code unknown-alias} config expansion. */
    public static java.util.Set<ReasonClass> dynamicSet() {
        return java.util.EnumSet.of(REFLECT, DISPATCH, INDIRECT, NATIVE, UNRESOLVED);
    }

    /**
     * Map a java {@link UnknownReason} to its class via the structured {@link UnknownReason.Kind}. The
     * gate deliberately uses {@link #classify(String)} instead (four-way parity — see
     * {@code Policy.gateInputFromScan}); this typed path exists for callers that already hold a parsed
     * reason, and the two MUST agree on every recognized {@code Kind} (pinned by a test that iterates
     * {@code Kind.values()}). A reason whose prefix this build doesn't recognize → UNRESOLVED.
     */
    public static ReasonClass of(UnknownReason r) {
        UnknownReason.Kind k = r == null ? null : r.kind();
        if (k == null) return UNRESOLVED;
        return switch (k) {
            case REFLECT -> REFLECT;
            case NATIVE -> NATIVE;
            // ⟨0.24⟩ ambiguous = name resolution failed, no owner formed; §6.2 projects it to `dispatch`,
            // and reclassifying it to `indirect` was measured to delete `deny E Unknown[dispatch]` on rust.
            case DISPATCH, INDY, AMBIGUOUS -> DISPATCH; // invokedynamic = a dispatch candor couldn't resolve
            case CALLBACK, TASK_HANDOFF -> INDIRECT;    // callback / async continuation = function-value indirection
            case DEP, DEP_STALE -> UNRESOLVED;          // §4 ⟨0.24⟩ registered dependency-boundary kinds
        };
    }

    /**
     * Map a raw {@code unknownWhy} reason to its normative class. Prefix-based (raw reasons carry a
     * `kind:detail` shape, e.g. `dispatch:foo.Bar`), longest-specific first, unrecognized → UNRESOLVED.
     */
    public static ReasonClass classify(String why) {
        if (why == null) return UNRESOLVED;
        String w = why.trim().toLowerCase();
        // reflection family (ts reflect:* / reflect_apply / reflect-metadata; swift reflecting / dynamicMemberLookup)
        // `startsWith`, NOT `equals`. candor-swift emits this token in the normative `kind:detail` form —
        // `dynamicMemberLookup:<root>.<prop>` (CallCollector.swift), never bare — so an equality test can
        // NEVER match a real one and the token falls through to UNRESOLVED. Both classes are in the
        // `dynamic` set, so a bare `deny Unknown` is unaffected; what silently weakens is the
        // class-targeted `deny Unknown[reflect]`, which is how the reason ratchet is adopted. Found by the
        // swift sweep, where the same equality test made `Unknown[reflect]` unsatisfiable even in one tree.
        // Widening equality to a prefix can only ever move MORE tokens into REFLECT, never fewer.
        if (w.startsWith("reflect") || w.startsWith("dynamicmemberlookup")) return REFLECT;
        // FFI / native
        if (w.startsWith("native")) return NATIVE;
        // callback / closure / async-continuation indirection
        if (w.startsWith("callback") || w.startsWith("closure") || w.startsWith("task-handoff")) return INDIRECT;
        // unresolved dispatch / invokedynamic / ⟨0.24⟩ the canonical `ambiguous:` kind (name resolution
        // found two same-named local defs, so no owner was formed). §6.2 has ALWAYS projected it here.
        if (w.startsWith("dispatch") || w.startsWith("indy") || w.startsWith("ambiguous")) return DISPATCH;
        // §4 ⟨0.24⟩ REGISTERED dependency-boundary kinds. `unresolved` is ALSO the catch-all below, so
        // this branch changes no verdict — that is the point. Their class is a recorded decision, not an
        // accident of what the catch-all happens to be, so a future change to the catch-all cannot
        // silently re-class every chained dependency's Unknown.
        if (w.startsWith("dep:") || w.startsWith("dep-stale:")
                || w.equals("dep") || w.equals("dep-stale")) return UNRESOLVED;
        // setup markers (not emitted as unknownWhy today — design finding 1 — but pinned for when they are)
        if (w.startsWith("missing-config") || w.startsWith("no-tsconfig") || w.startsWith("no-node_modules")) return SETUP;
        // generic + the conservative catch-all
        return UNRESOLVED;
    }
}
