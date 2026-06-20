package io.poly.candor.model;

import java.util.List;

/**
 * A candor report (candor-spec §2): the {@code candor} provenance header plus one {@link Effector}
 * entry per analyzed unit, scoped to the package(s) it covers. The interchange artifact a consumer
 * queries, gates, and chains across packages.
 *
 * <p>The JVM realization of the spec's Report envelope (Rust's {@code candor_report::Report}). The
 * wire envelope is {@code { candor, packages, functions }}.
 */
public record Report(Provenance candor, List<String> packages, List<Effector> functions) {}
