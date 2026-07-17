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
}
