package io.poly.candor.model;

/**
 * Why a unit's body introduced {@code Unknown} directly — the {@code unknownWhy} wire tag
 * (candor-spec §4). A {@code prefix:detail} pair, e.g. {@code dispatch:Foo.bar}.
 *
 * <p>The spec's canonical code vocabulary is four kinds ({@code reflect}/{@code native}/
 * {@code dispatch}/{@code callback}). candor-java additionally emits {@code task-handoff} and
 * {@code indy} today (see {@link Kind}); both are modelled so its wire round-trips byte-for-byte.
 * Consolidating those two into the canonical four is a separate, deliberate (byte-changing)
 * spec-conformance task — tracked, not done here.
 *
 * <p>The raw {@code prefix} string is stored (not just the {@link Kind}) so a tag from ANY engine —
 * including a future or foreign prefix this build doesn't recognize — round-trips exactly; {@link #kind()}
 * gives typed access for the recognized kinds (or {@code null}).
 */
public record UnknownReason(String prefix, String detail) implements Comparable<UnknownReason> {

    public enum Kind {
        REFLECT("reflect"),
        NATIVE("native"),
        DISPATCH("dispatch"),
        CALLBACK("callback"),
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

    /** The wire tag, e.g. {@code "dispatch:Foo.bar"}. */
    public String format() {
        return prefix + ":" + detail;
    }

    /**
     * Parse a wire tag, splitting on the FIRST {@code ':'}; {@code null} only if there is no colon
     * (not a tag). An unrecognized prefix is preserved verbatim (round-trips), with {@link #kind()}
     * returning {@code null}.
     */
    public static UnknownReason parse(String tag) {
        int i = tag.indexOf(':');
        if (i < 0) return null;
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
