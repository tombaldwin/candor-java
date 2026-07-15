package io.poly.candor.model;

import java.util.List;

/**
 * ⟨0.15 staged⟩ The κ-coverage ledger as report data (candor-spec §2 / COVERAGE-DESIGN.md): the external
 * packages this code demonstrably calls where the classifier never fired — "what the scan couldn't see",
 * travelling WITH the report instead of evaporating on stderr. Same names and counts as the per-scan
 * stderr disclosure. Effects through these packages are INVISIBLE to the scan — absent from the report,
 * NOT a claim they're pure. Omitted from the wire entirely when nothing is uncovered, so a fully-covered
 * report is byte-identical to a pre-⟨0.15⟩ one.
 */
public record Coverage(List<Uncovered> uncovered) {

    /** One uncovered package: its dotted name and the number of calls the scan saw into it. */
    public record Uncovered(String name, int calls) {}
}
