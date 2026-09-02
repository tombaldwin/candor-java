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
    /// ⟨0.29⟩ SPEC §2 `incomplete` — the effects whose LOCATOR the dependency could not determine. §2's
    /// chained-join clause names it in the same breath as the four literal surfaces above: "a join that
    /// carries the effect and drops `incomplete` lets a benign literal in the consumer certify what the
    /// dependency declared uncertifiable". MEASURED before this field existed: a dep whose `Fs` path is a
    /// runtime value published nothing to say so, so a consumer that ALSO wrote one allowed literal
    /// joined `paths: ['/tmp/lit']` with no marker and `allow Fs /tmp/lit` answered `no violations` —
    /// a false all-clear on a configured gate, one package boundary along. `Net` already had its wire
    /// form in `netClass ∋ unknown-host`; the other three effects had none.
    List<String> incomplete = new ArrayList<>();
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
        addAllMissing(incomplete, other.incomplete);
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

    /** THE VALUE THE REFRESH DIGEST FOLDS IN (SOUNDNESS R151) — see {@link Refresh#wholeProgramDigest}.
     *
     *  <p><b>Why it exists.</b> The digest folded in {@code crossDeps.keySet()} and none of the VALUES,
     *  while {@link Candor#inheritDepFn} writes those values into per-class accumulators the cache
     *  stores. So a dependency function that kept its key and gained an effect was replayed from cache
     *  WITHOUT it. Measured on the published 0.34.0 jar: warm cache under a dep reporting {@code ['Db']},
     *  rerun under the same dep reporting {@code ['Db','Net']} with the same app bytecode and the same
     *  {@code deny Net} policy — exit 0, "no violations", "reused 1 of 1". Cold and fresh-cache controls
     *  both exit 1. Every field below reproduced the same way on its own axis ({@code allow Fs} certifying
     *  a different path, {@code allow Exec} a different command, {@code allow Db} a different table,
     *  {@code allow Net} a different host, and a reason-scoped {@code deny Net Unknown[reflect]} reading
     *  the previous run's reason class).
     *
     *  <p><b>REFLECTIVE, and it RAISES on a type it does not recognise</b>, for the reason the defect
     *  had: this record grew four fields after the digest was written ({@code netClass} ⟨0.20⟩,
     *  {@code unknownWhy} ⟨0.19⟩, {@code incomplete} ⟨0.29⟩, {@code fn} ⟨0.24⟩) and every one of them
     *  escaped it silently, because a hand-written rendering only covers the fields someone remembered.
     *  A field added after this comment is folded in automatically; one whose type is new fails the scan
     *  loudly rather than dropping out of the key. Same fact and same reason as
     *  {@link AnalysisContext#inputSizes} and {@link Refresh.Delta}.
     *
     *  <p>Collections are rendered SORTED. They are "Lists on the wire but sets in meaning" (see
     *  {@link #addAllMissing}) and their order follows the order {@code CANDOR_DEPS} reports happened to
     *  be walked in, which {@code Files.walk} does not fix — so rendering them in list order would make
     *  the digest flap between runs with identical inputs. That direction is safe (a miss is a full scan)
     *  but it would silently delete the feature, which is exactly how the ASM enum-encoding defect
     *  presented. */
    @SuppressWarnings("unchecked")
    void renderTo(StringBuilder sb) {
        for (java.lang.reflect.Field f : DIGEST_FIELDS) {
            Object v;
            try { v = f.get(this); }
            catch (IllegalAccessException e) { throw new IllegalStateException("DepFn." + f.getName() + ": " + e); }
            sb.append(f.getName()).append('=');
            if (v == null) sb.append("null");
            else if (v instanceof EffectSet es) sb.append(es.toNames());          // toNames() sorts, by contract
            else if (v instanceof java.util.Collection<?> c) {
                for (Object o : c)
                    if (!(o instanceof String)) throw new IllegalStateException("DepFn." + f.getName()
                            + " holds a " + (o == null ? "null" : o.getClass().getName()) + ", which the refresh"
                            + " digest cannot render value-based — render it structurally or the cache goes stale"
                            + " on it silently (SOUNDNESS R151)");
                // Sorted only when there is an order to disagree about. Nearly every one of these surfaces
                // is empty or a singleton on real reports, and a TreeSet per field per entry was the second
                // half of the digest's cost across 23,624 joined entries.
                sb.append(c.size() < 2 ? c : new java.util.TreeSet<>((java.util.Collection<String>) c));
            }
            else if (v instanceof String || v instanceof Boolean || v instanceof Number) sb.append(v);
            else throw new IllegalStateException("DepFn." + f.getName() + " is a " + v.getClass().getName()
                    + ", which the refresh digest cannot render value-based — a dependency value outside the"
                    + " digest is replayed from cache after it changes (SOUNDNESS R151)");
            sb.append('\u0002');
        }
    }

    /** This record's own fields, in name order so the rendering does not depend on the order the JVM
     *  hands them back. Computed once; {@code setAccessible} is a no-op for same-package access but
     *  keeps the loop honest if this class ever moves. */
    private static final java.lang.reflect.Field[] DIGEST_FIELDS;
    static {
        List<java.lang.reflect.Field> fs = new ArrayList<>();
        for (java.lang.reflect.Field f : DepFn.class.getDeclaredFields()) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) continue;
            f.setAccessible(true);
            fs.add(f);
        }
        fs.sort(java.util.Comparator.comparing(java.lang.reflect.Field::getName));
        DIGEST_FIELDS = fs.toArray(new java.lang.reflect.Field[0]);
    }
}
