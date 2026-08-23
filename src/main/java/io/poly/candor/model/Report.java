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
                     Analyzed analyzed, List<UnanalyzedUnit> unanalyzed,
                     List<ExcludedClass> excluded, List<OutOfScope> outOfScope,
                     NetPartners netPartners,
                     List<Effector> functions) {

    /** ⟨0.31⟩ The ambient {@code net-partner} declaration that MOVED a {@code netClass} — the config file
     *  that declared it, and the declared hosts that actually PARTICIPATED in this scan.
     *
     *  <p>{@code hosts} is what participated, not what was declared: a config listing twenty partners of
     *  which one matched discloses the one, because a list of everything written down buries the line that
     *  moved the verdict. NULL (key omitted) when nothing participated, so a project declaring no partners
     *  — or declaring some that never matched — is byte-identical to a pre-rung report.
     *
     *  <p>Recorded by the PRODUCER because {@code gate --report} cannot compute it: {@code net-partner}
     *  anchors at the TARGET and that route has no target, so re-classifying through the consumer's own
     *  config would make a verdict depend on the reader's working directory — the re-derivation ⟨0.24⟩
     *  forbids. Both routes copy this one record, which is what makes §3.1's byte-equality hold. */
    public record NetPartners(String config, List<String> hosts) {}
    /** ⟨0.29⟩ THE SCOPE (candor-spec/FILE-SET-DESIGN.md): one class of file this scan chose not to OPEN,
     *  with a count and the engine's own reason. {@code unanalyzed} above names what was opened and could
     *  not be read; this names what was never opened at all, and a consumer could not tell the two apart,
     *  because {@code analyzed.count} is a numerator whose denominator — the file selector — is invisible.
     *
     *  <p>COUNTS, NEVER FILE LISTS: an excluded set that can hold a build tree is unbounded, and a gate
     *  that prints thousands of paths is one people scroll past.
     *
     *  <p>{@code peeked} is the load-bearing half of the pair with {@link OutOfScope}. An empty
     *  {@code outOfScope} says "I read the excluded files and none held an effect this policy denies" — a
     *  claim it may make only about the classes it actually read. candor-java reads BYTECODE, so it can
     *  peek an ARCHIVE and cannot peek a {@code .java} that was never compiled; without this flag the pair
     *  would answer {@code []} over files nobody opened, which is the ⟨0.26⟩ partial-manifest failure
     *  exactly — a partial answer being worse than an absent one. */
    /** ⟨0.32⟩ {@code judgedElsewhere} — the files of this class are COPIES of code this same scan
     *  already judged (a jar under build/ is a derived copy of the classes just analysed), so the class
     *  hides nothing and does not make the verdict INCOMPLETE. Only the PRODUCER may set it: a consumer
     *  cannot recover it from the class token, because those tokens are engine-chosen and the same
     *  concept is spelled `build-output-archive` here and `build-output` in rust and swift. */
    public record ExcludedClass(String cls, int count, boolean peeked, boolean judgedElsewhere,
                                String reason) {}
    /** ⟨0.29⟩ AN EFFECT FOUND IN A FILE THE GATE DID NOT JUDGE.
     *
     *  <p>Its own kind, beside {@code functions} and never inside it: folding these into the gate would
     *  move verdicts and make an exit code depend on a file the gate declined to judge, which is the
     *  opposite of what this rung promises. Emitted only when a policy is configured, and only for effects
     *  that policy DENIES — that bound is what keeps it from becoming the noise it would otherwise be. */
    public record OutOfScope(String fn, String path, List<String> effects, String cls, String reason) {}
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
