package io.poly.candor;

import java.util.ArrayList;
import java.util.List;
import io.poly.candor.model.EffectSet;

/** One chained dependency function (CANDOR_DEPS): effects + the four literal surfaces — the spec (§2)
 *  says a consumer inherits BOTH (effects alone made every chained `allow Db` fail the lits=∅ branch
 *  with an empty surface no rule could cover). A per-scan record held in {@link AnalysisContext#crossDeps};
 *  top-level so it is bare-visible across the package. */
final class DepFn {
    EffectSet effects = EffectSet.empty();
    List<String> hosts = new ArrayList<>(), cmds = new ArrayList<>(),
            paths = new ArrayList<>(), tables = new ArrayList<>();
    // ⟨0.20⟩ the dep's own Net destination-class tokens. Only `unknown-host` needs propagating: a dep whose
    // resolved hosts flow across (above) but that ALSO reached a masked/runtime host must taint the consumer
    // fail-closed — its unresolved host never appears in `hosts`, so without this the consumer under-reports.
    List<String> netClass = new ArrayList<>();
    /// ⟨0.19⟩ the dep's own `unknownWhy` tags. Without these an inherited `Unknown` reaches the consumer
    /// with NO reason class, so it classifies as bare `unresolved` and a reason-scoped gate —
    /// `deny Net Unknown[reflect]` — cannot bite across a scan boundary. Measured: the gate exits 1 on the
    /// dependency itself and 0 on a consumer that chains it, which is a fail-OPEN gate in precisely the
    /// place a consumer most needs one.
    List<String> unknownWhy = new ArrayList<>();
    /// ⟨0.24⟩ Whether this entry came from a report whose producing build could not be VERIFIED (§2.1), so
    /// its effects were downgraded to `Unknown` rather than read. It changes only how the SYNTHESIZED
    /// reason is spelled (`dep-stale:<pkg>` vs `dep:<hash>` — both project to `unresolved`); the two are
    /// distinguished because a reader deserves to know whether the hole is "this dependency classified
    /// nothing" or "this report is not the one this build produced, and re-running its scan fixes it".
    /// See {@link Loader#synthesizeReasonlessDepReasons}.
    boolean stale;
    /// The report QUAL this entry was written under (§2 `fn`), null for a report that omits it. It is the
    /// key the dependency's own `calls` array names, and so the only handle on the dep's INTERNAL call
    /// graph — which is where an INHERITED Unknown's reason lives, `unknownWhy` being direct-by-contract.
    /// See {@link Candor#depTransitiveWhy}.
    String fn;
}
