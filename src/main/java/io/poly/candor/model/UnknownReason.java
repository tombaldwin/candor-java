package io.poly.candor.model;

/**
 * Why a unit's body introduced {@code Unknown} directly — the {@code unknownWhy} wire tag
 * (candor-spec §4). A {@code kind:detail} pair, e.g. {@code dispatch:Foo.bar}.
 *
 * <p>The spec's canonical code vocabulary is four kinds ({@code reflect}/{@code native}/
 * {@code dispatch}/{@code callback}). candor-java additionally emits {@code task-handoff} and
 * {@code indy} today; both are modelled here so the wire round-trips byte-for-byte. Consolidating
 * those two into the canonical four is a separate, deliberate (byte-changing) spec-conformance task —
 * tracked, not done here.
 */
public record UnknownReason(Kind kind, String detail) implements Comparable<UnknownReason> {

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

    /** The wire tag, e.g. {@code "dispatch:Foo.bar"}. */
    public String format() {
        return kind.prefix() + ":" + detail;
    }

    /**
     * Parse a wire tag (splitting on the FIRST {@code ':'}), or {@code null} if the prefix is not a
     * recognized kind (tolerant on read — a foreign engine's reason is simply ignored, matching the
     * old string-prefix consumers).
     */
    public static UnknownReason parse(String tag) {
        int i = tag.indexOf(':');
        if (i < 0) return null;
        Kind k = Kind.fromPrefix(tag.substring(0, i));
        if (k == null) return null;
        return new UnknownReason(k, tag.substring(i + 1));
    }

    /** Ordered by wire tag — matches the historical {@code TreeSet<String>} emission order. */
    @Override
    public int compareTo(UnknownReason o) {
        return format().compareTo(o.format());
    }

    @Override
    public String toString() {
        return format();
    }
}
