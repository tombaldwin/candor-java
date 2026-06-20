package io.poly.candor.model;

/**
 * What KIND of unit an {@link Effector} is, when it is not an ordinary function/method (candor-spec
 * §2, the {@code unitKind} wire field). {@link #FUNCTION} is the default and is omitted on the wire
 * (an absent {@code unitKind} means "function").
 *
 * <p>candor-java currently only produces {@code FUNCTION} and {@code INITIALIZER} (a JVM
 * {@code <clinit>}); the rest are the shared cross-engine vocabulary (the Swift accessor, the CJS
 * export, the agent-fleet kinds). The wire name stays {@code unitKind} for compatibility.
 */
public enum EffectorKind {
    FUNCTION(null),
    INITIALIZER("initializer"),
    ACCESSOR("accessor"),
    EXPORT("export"),
    AGENT("agent"),
    COMMAND("command"),
    SKILL("skill"),
    CRON("cron"),
    SESSION("session"),
    HOOKS("hooks");

    private final String wire;

    EffectorKind(String wire) {
        this.wire = wire;
    }

    /** The {@code unitKind} wire value, or {@code null} for {@link #FUNCTION} (omitted on the wire). */
    public String wireName() {
        return wire;
    }

    /** The kind for a {@code unitKind} value; tolerant — an unknown value reads as {@link #FUNCTION}
     *  (spec §2 forward compatibility). */
    public static EffectorKind fromWire(String wire) {
        if (wire == null) return FUNCTION;
        for (EffectorKind k : values()) if (wire.equals(k.wire)) return k;
        return FUNCTION;
    }
}
