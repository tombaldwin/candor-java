package io.poly.candor.model;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * An effect — an observable interaction with the world outside pure computation (candor-spec §1).
 * The closed vocabulary plus {@code Unknown}, which is NOT an effect but the trust marker the §4
 * contract turns on: a call the engine could not resolve.
 *
 * <p>Declared in alphabetical {@link #specName()} order so an {@link EnumSet} iterates in the exact
 * order the wire arrays are sorted today (the historical {@code TreeSet<String>} order). This is the
 * load-bearing byte-identity invariant — see {@link EffectSet#toNames()}.
 *
 * <p>This is the JVM realization of the spec's Effect noun; the other engines name the same closed
 * set. See candor-spec/MODEL.md.
 */
public enum Effect {
    CLIPBOARD("Clipboard"),
    CLOCK("Clock"),
    DB("Db"),
    ENV("Env"),
    EXEC("Exec"),
    FS("Fs"),
    IPC("Ipc"),
    LOG("Log"),
    NET("Net"),
    RAND("Rand"),
    UNKNOWN("Unknown");

    private final String specName;

    Effect(String specName) {
        this.specName = specName;
    }

    /** The spec §1 wire name ("Net", "Fs", … , "Unknown"). */
    public String specName() {
        return specName;
    }

    /** {@code Unknown} — not an effect, but the §4 disclosure marker for an unresolved call. */
    public boolean isTrustMarker() {
        return this == UNKNOWN;
    }

    /** A §6.1 boundary effect — one that should be contained in a dedicated layer (its dispersion is the
     *  architecture signal). The spec's §6.1 boundary set: {@code Db,Net,Exec,Fs,Ipc,Clipboard}.
     *  {@code Clipboard} is external-resource I/O — a boundary capability, so it is scored by containment
     *  (a peripheral class can no longer reach the system clipboard invisibly to the ratchet). */
    public boolean isBoundary() {
        return switch (this) {
            case DB, NET, EXEC, FS, IPC, CLIPBOARD -> true;
            default -> false;
        };
    }

    /** A §6.1 cross-cutting (ambient) effect — reported but not containment-scored. */
    public boolean isCrossCutting() {
        return switch (this) {
            case LOG, CLOCK, RAND, ENV -> true;
            default -> false;
        };
    }

    private static final Map<String, Effect> BY_NAME = new HashMap<>();

    static {
        for (Effect e : values()) BY_NAME.put(e.specName, e);
    }

    /** The effect for a spec name, or {@code null} if the name is not in the vocabulary. */
    public static Effect fromSpecName(String name) {
        return BY_NAME.get(name);
    }

    /** The §1 effect vocabulary — the ten effects, excluding the {@code Unknown} trust marker. */
    public static final Set<Effect> KNOWN =
            Collections.unmodifiableSet(EnumSet.complementOf(EnumSet.of(UNKNOWN)));

    /** AS-EFF-004 ambient authority — {@code 𝔼 \ {Log}} (§6, SEMANTICS §6). */
    public static final Set<Effect> AMBIENT_AUTHORITY = Collections.unmodifiableSet(
            EnumSet.of(NET, FS, DB, EXEC, ENV, CLOCK, RAND, IPC, CLIPBOARD));

    /** AS-EFF-007 injection-class effects — those whose caller-derived argument is an injection surface. */
    public static final Set<Effect> INJECTION =
            Collections.unmodifiableSet(EnumSet.of(FS, EXEC, DB, NET, ENV, IPC));
}
