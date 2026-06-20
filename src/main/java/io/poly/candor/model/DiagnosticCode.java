package io.poly.candor.model;

/**
 * A candor diagnostic code (candor-spec §6, the {@code AS-EFF-00x} family). The full vocabulary is
 * modelled (001–010); candor-java currently emits 001–009 — AS-EFF-010 (containment regression) is
 * defined for completeness but not yet emitted by this engine.
 *
 * <ul>
 *   <li>001 performs an undeclared effect · 002 declares an unused capability · 003 unresolved calls
 *       (conformance)
 *   <li>004 uses ambient authority directly (no-ambient)
 *   <li>005 gained an effect vs baseline (baseline guard)
 *   <li>006 transitively performs a forbidden effect · 008 reaches a literal outside the allowlist ·
 *       009 forbidden layer dependency (policy)
 *   <li>007 injection-class effect on caller-derived input (risk, advisory)
 * </ul>
 */
public enum DiagnosticCode {
    AS_EFF_001,
    AS_EFF_002,
    AS_EFF_003,
    AS_EFF_004,
    AS_EFF_005,
    AS_EFF_006,
    AS_EFF_007,
    AS_EFF_008,
    AS_EFF_009,
    AS_EFF_010;

    /** The spec code string, e.g. {@code "AS-EFF-006"}. */
    public String code() {
        return name().replace('_', '-');
    }

    /** The bracketed prefix as it appears in diagnostic output, e.g. {@code "[AS-EFF-006]"}. */
    public String bracket() {
        return "[" + code() + "]";
    }
}
