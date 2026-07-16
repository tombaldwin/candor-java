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
    /** unresolved virtual/dynamic dispatch candor declined to resolve: dispatch:* ; rust ambiguous:same-name. */
    DISPATCH("dispatch"),
    /** callback / closure / function-value indirection: callback:* ; ts closure. */
    INDIRECT("indirect"),
    /** FFI / native boundary: native:* (JNI / C-interop / native addons as engines emit them). */
    NATIVE("native"),
    /** generic unresolvable call/import, AND the catch-all for any unrecognized raw reason. */
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

    /**
     * Map a java {@link UnknownReason} to its class via the structured {@link UnknownReason.Kind} — the
     * robust path for this engine (ts/swift, which emit raw strings, use {@link #classify(String)}; the two
     * agree by construction — see the test). A reason whose prefix this build doesn't recognize → UNRESOLVED.
     */
    public static ReasonClass of(UnknownReason r) {
        UnknownReason.Kind k = r == null ? null : r.kind();
        if (k == null) return UNRESOLVED;
        return switch (k) {
            case REFLECT -> REFLECT;
            case NATIVE -> NATIVE;
            case DISPATCH, INDY -> DISPATCH;          // invokedynamic = a dispatch candor couldn't resolve
            case CALLBACK, TASK_HANDOFF -> INDIRECT;  // callback / async continuation = function-value indirection
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
        if (w.startsWith("reflect") || w.equals("dynamicmemberlookup")) return REFLECT;
        // FFI / native
        if (w.startsWith("native")) return NATIVE;
        // callback / closure / async-continuation indirection
        if (w.startsWith("callback") || w.startsWith("closure") || w.startsWith("task-handoff")) return INDIRECT;
        // unresolved dispatch / invokedynamic / same-name ambiguity
        if (w.startsWith("dispatch") || w.startsWith("indy") || w.startsWith("ambiguous")) return DISPATCH;
        // setup markers (not emitted as unknownWhy today — design finding 1 — but pinned for when they are)
        if (w.startsWith("missing-config") || w.startsWith("no-tsconfig") || w.startsWith("no-node_modules")) return SETUP;
        // generic + the conservative catch-all
        return UNRESOLVED;
    }
}
