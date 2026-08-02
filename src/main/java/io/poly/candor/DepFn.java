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

    /** Fold another entry loaded under the SAME {@code crossDeps} key into this one — the family-wide
     *  entry-collision rule (candor-spec/ENTRY-COLLISION-DECISION.md), replacing last-non-empty-wins.
     *
     *  <p>WHAT LAST-NON-EMPTY-WINS COST. The old rule was {@code if (!de.effects.isEmpty()) put(h, de)},
     *  and the {@code !isEmpty()} guard was read for a long time as a safety property: a pure claim
     *  ({@code []}) can never erase an effectful one, so the rule looked like a precision loss and never
     *  a purity claim. <b>{@code Unknown} IS NON-EMPTY.</b> §2.1's staleness downgrade turns every entry
     *  of an untrusted report into exactly {@code {Unknown}}, which sails through the guard and
     *  overwrites a trusted report's concrete effects — measured in both file orders, a trusted report
     *  carrying {@code Fs} plus a stale one for the same package gives the consumer {@code ['Unknown']}
     *  and {@code deny Fs} goes <b>exit 1 to exit 0</b>. A report the engine explicitly refused to trust
     *  got to erase a fact from one it does.
     *
     *  <p>AND IT WAS ORDER-DEPENDENT: the same two reports gave {@code ['Net']} as {@code a-Exec.json} +
     *  {@code z-Net.json} and {@code ['Exec']} as {@code z-Exec.json} + {@code a-Net.json}. Rename a
     *  file, change the effect. A union is commutative, associative and idempotent, so the index no
     *  longer depends on the order the reports happen to load in.
     *
     *  <p>THE RULE HAD BEEN DESCRIBED THREE TIMES AND WAS WRONG TWICE — reported as plain last-wins,
     *  corrected to last-non-empty-wins with the guard over-read as safety, and only a third review
     *  found the {@code Unknown} path through it. That history is itself part of the argument: a rule
     *  nobody can state correctly on three attempts is not one a policy gate should rest on. The union
     *  discards nothing, so there is no discard rule left to state wrongly.
     *
     *  <p>EVERY FIELD, not just {@code effects} — measured across three real dep trees, the coverage
     *  ledger and the call edges disagree far more often than the effects do, and a union that covered
     *  only effects would keep closing the gate flip while still dropping the disclosure.
     */
    void unionWith(DepFn other) {
        effects.addAll(other.effects);
        addAllMissing(hosts, other.hosts);
        addAllMissing(cmds, other.cmds);
        addAllMissing(paths, other.paths);
        addAllMissing(tables, other.tables);
        addAllMissing(netClass, other.netClass);
        addAllMissing(unknownWhy, other.unknownWhy);
        // STALE ONLY IF EVERY CONTRIBUTOR WAS. This flag decides how a synthesized reason is SPELLED
        // (`dep-stale:<pkg>` vs `dep:<hash>`; both project to `unresolved`, so no gate turns on it), and
        // once a trusted report has contributed to this entry, "this report is not the one this build
        // produced" is no longer the accurate thing to tell the reader about it.
        stale = stale && other.stale;
        if (fn == null) fn = other.fn;
    }

    /** Append without duplicating — these surfaces are Lists on the wire but sets in meaning, and the
     *  union must stay idempotent so that chaining one report twice is not observable. */
    private static void addAllMissing(List<String> into, List<String> from) {
        for (String s : from) if (!into.contains(s)) into.add(s);
    }
}
