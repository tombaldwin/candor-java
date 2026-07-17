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
public record Report(Provenance candor, List<String> packages, Coverage coverage,
                     Analyzed analyzed, List<UnanalyzedUnit> unanalyzed, List<Effector> functions) {
    /** ⟨0.21⟩ the analyzed-universe summary (COMPLETENESS-MANIFEST-DESIGN.md Gap 1): {@code count} = the
     *  functions candor formed an effect judgment for (effectful + pure), so a consumer reading the bare
     *  envelope computes {@code count − |functions|} = the pure count and distinguishes analyzed-pure from
     *  never-seen without loading the §2.2 sidecar; {@code digest} = an opaque within-engine-stable
     *  fingerprint of the sorted analyzed-qual set (re-scan agreement — compare same-engine only). */
    public record Analyzed(int count, String digest) {}
    /** ⟨0.21⟩ one unit of the TARGET's own source candor could NOT analyze (Gap 2) — a file that failed to
     *  read/parse. Its effects are absent NOT because pure but because the code was never seen; disclosed on
     *  stderr today but invisible to a machine reading the JSON. Distinct from {@code coverage} (an unmodeled
     *  dependency). */
    public record UnanalyzedUnit(String path, String reason) {}
}
