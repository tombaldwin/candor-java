package io.poly.candor.model;

/**
 * Why a unit's body introduced {@code Unknown} directly — the {@code unknownWhy} wire tag
 * (candor-spec §4). A {@code prefix:detail} pair, e.g. {@code dispatch:Foo.bar}.
 *
 * <p>⟨0.24⟩ The spec's canonical code vocabulary is <b>five</b> kinds ({@code reflect}/{@code native}/
 * {@code dispatch}/{@code callback}/{@code ambiguous}), plus the two REGISTERED dependency-boundary
 * kinds {@code dep}/{@code dep-stale} (§4 ⟨0.24⟩ / §6.2). All seven are modelled in {@link Kind} —
 * candor-java is a CONSUMER of every one of them even where it is not a producer, because a chained
 * dependency's report contributes its reasons into this scan (Candor's {@code depTransitiveWhy}).
 *
 * <p>Separately, candor-java emits two MIGRATION kinds of its own, {@code task-handoff} and
 * {@code indy}, modelled so its wire round-trips byte-for-byte. Consolidating those two onto the
 * canonical five is a deliberate (byte-changing) task — tracked, not done here. {@code ambiguous},
 * {@code dep} and {@code dep-stale} are NOT migration kinds: they are permanent members of the
 * spec's vocabulary and are never to be reconciled away.
 *
 * <p>The raw {@code prefix} string is stored (not just the {@link Kind}) so a tag from ANY engine —
 * including a future or foreign prefix this build doesn't recognize — round-trips exactly; {@link #kind()}
 * gives typed access for the recognized kinds (or {@code null}).
 */
public record UnknownReason(String prefix, String detail) implements Comparable<UnknownReason> {

    /**
     * The prefixes this build RECOGNIZES. Membership is not "candor-java emits it" — it is "candor-java
     * has an opinion about what it means", which for a consumer of three other engines' reports is the
     * wider set. A prefix absent here is not rejected: it round-trips verbatim and classifies through the
     * conservative catch-all (§2 forward compatibility) — see {@link #fromPrefix}.
     */
    public enum Kind {
        // ── spec §4 canonical (five) ────────────────────────────────────────────────────────────────
        REFLECT("reflect"),
        NATIVE("native"),
        DISPATCH("dispatch"),
        CALLBACK("callback"),
        /** ⟨0.24⟩ the analyser's own NAME RESOLUTION was ambiguous (two same-named local definitions), so
         *  no owner could be formed at all. Not a {@link #DISPATCH} with a missing body (there an owner
         *  type WAS formed, and the detail is the normative {@code owner.member}); not a {@link #CALLBACK}
         *  (no function value is involved). candor-java's bytecode model does not produce it — a JVM
         *  invoke carries owner+name+descriptor, so name resolution is never ambiguous — but candor-rust
         *  emits it heavily and it reaches this engine over the dependency boundary. */
        AMBIGUOUS("ambiguous"),
        // ── spec §4 ⟨0.24⟩ REGISTERED dependency-boundary kinds (project to `unresolved`, §6.2) ───────
        /** an `Unknown`-bearing dependency ENTRY that accounts for none of its own `Unknown` (Loader). */
        DEP("dep"),
        /** ditto, where the producing report is §2.1 distrusted (stale). */
        DEP_STALE("dep-stale"),
        // ── candor-java MIGRATION kinds (off-vocabulary, to be reconciled onto the canonical five) ────
        TASK_HANDOFF("task-handoff"),
        INDY("indy");

        private final String prefix;

        Kind(String prefix) {
            this.prefix = prefix;
        }

        public String prefix() {
            return prefix;
        }

        /** The kind for a prefix, or {@code null} if it is not a recognized kind. */
        public static Kind fromPrefix(String prefix) {
            for (Kind k : values()) if (k.prefix.equals(prefix)) return k;
            return null;
        }
    }

    /** Build from a recognized kind. */
    public static UnknownReason of(Kind kind, String detail) {
        return new UnknownReason(kind.prefix(), detail);
    }

    /** The recognized kind, or {@code null} for a foreign/unrecognized prefix. */
    public Kind kind() {
        return Kind.fromPrefix(prefix);
    }

    /** The wire tag, e.g. {@code "dispatch:Foo.bar"} — or just the prefix for a DETAIL-LESS tag such as
     *  {@code missing-config}, which must NOT round-trip as {@code "missing-config:"}. */
    public String format() {
        return detail.isEmpty() ? prefix : prefix + ":" + detail;
    }

    /**
     * Parse a wire tag, splitting on the FIRST {@code ':'}. A tag with NO colon is a tag with no detail,
     * not a non-tag: it parses to an empty {@link #detail}. An unrecognized prefix is preserved verbatim
     * (round-trips), with {@link #kind()} returning {@code null}. {@code null} only for a blank string,
     * where there is nothing to record.
     *
     * <p><b>THIS RETURNED {@code null} FOR EVERY COLON-FREE TAG, AND THAT WAS A SILENT UNDER-REPORT.</b>
     * The doc here used to assert that a colon-free string was "not a tag" — the model was wrong, and the
     * spec says so: §6.2's projection table registers {@code missing-config}, {@code no-tsconfig} and
     * {@code no-node_modules}, all detail-less, all classed {@code setup}. {@code ReportJson.parseEntries}
     * maps every tag through here and drops the nulls, so those three were deleted on the way in and
     * {@code blindspots} could never list a setup-only source: 2 sources where the fixture has 3, and
     * {@code blindspots --class setup} returned nothing at all.
     *
     * <p>The UNFILTERED list was already wrong, so this is older than the ⟨0.24⟩ {@code --class} rung and
     * independent of it. {@code unverified --class} escaped only because it reads the RAW strings through
     * {@code readEnvelope} — a choice made for an unrelated reason that happened to route around this.
     *
     * <p>The shape to remember: <b>a parser that models {@code kind:detail} drops the token that has no
     * detail</b>, and the vocabulary it is parsing contains exactly such tokens.
     */
    public static UnknownReason parse(String tag) {
        if (tag == null || tag.isBlank()) return null;
        int i = tag.indexOf(':');
        if (i < 0) return new UnknownReason(tag, "");
        return new UnknownReason(tag.substring(0, i), tag.substring(i + 1));
    }

    /** Ordered by (prefix, detail) — consistent with the record's {@code equals} (so a {@code TreeSet}
     *  and a {@code HashSet} of reasons agree), and equal to wire-tag order whenever a detail has no
     *  inner colon (always, for candor's owner.member details). */
    @Override
    public int compareTo(UnknownReason o) {
        int c = prefix.compareTo(o.prefix);
        return c != 0 ? c : detail.compareTo(o.detail);
    }

    @Override
    public String toString() {
        return format();
    }
}
