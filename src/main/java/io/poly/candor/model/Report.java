package io.poly.candor.model;

import java.util.List;

/**
 * A candor report (candor-spec §2): the {@code candor} provenance header plus one {@link Effector}
 * entry per analyzed unit, scoped to the package(s) it covers. The interchange artifact a consumer
 * queries, gates, and chains across packages.
 *
 * <p>The JVM realization of the spec's Report envelope (Rust's {@code candor_report::Report}). The
 * wire envelope is {@code { candor, packages, coverage?, functions }} — {@code coverage} ⟨0.15 staged⟩
 * is the κ-coverage ledger as data, omitted (null or empty here) when nothing is uncovered so a
 * fully-covered report stays byte-identical to a pre-⟨0.15⟩ one.
 */
public record Report(Provenance candor, List<String> packages, Coverage coverage, List<Effector> functions) {}
