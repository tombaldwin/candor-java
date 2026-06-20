package io.poly.candor.model;

/**
 * An analysis mode (candor-spec §3) — how a run is driven and what it emits. {@link #AUDIT} is the
 * default (report effects, no judgement); the gate modes are each selected by an environment variable
 * and raise the corresponding {@code AS-EFF} diagnostics. Several gate modes may be active at once.
 */
public enum Mode {
    AUDIT(null),
    CONFORMANCE("CANDOR_STRICT"),
    NO_AMBIENT("CANDOR_NO_AMBIENT"),
    BASELINE("CANDOR_BASELINE"),
    POLICY("CANDOR_POLICY"),
    TAINT("CANDOR_TAINT");

    private final String envVar;

    Mode(String envVar) {
        this.envVar = envVar;
    }

    /** The environment variable that selects this mode, or {@code null} for {@link #AUDIT}. */
    public String envVar() {
        return envVar;
    }
}
