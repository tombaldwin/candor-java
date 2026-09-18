package io.poly.candor.model;

import java.util.List;

/**
 * An <b>effector</b> — the smallest body the engine attributes effects to (candor-spec §2; the spec's
 * historical noun was "unit", and the wire field stays {@code fn}). For the JVM that is a method, a
 * static initializer ({@code <clinit>}), and so on; the family's effectors are wider (accessors,
 * exports, agent-fleet sessions/hooks — see {@link EffectorKind}).
 *
 * <p>The single per-unit report entry, unifying what used to be the write-side {@code LinkedHashMap}
 * and the read-side {@code Query.Fn}. Components are declared in wire order. Serialization is NOT done
 * by reflecting this record (a record can't express the conditional field omission the wire needs);
 * one explicit serializer maps an {@code Effector} to the exact JSON. See candor-spec/MODEL.md.
 *
 * <p>Optional/absent fields use empty collections / {@link EffectorKind#FUNCTION} / empty string
 * rather than null, mirroring the existing read-side normalization.
 */
public record Effector(
        String fn,
        String loc,
        EffectSet inferred,
        List<String> invisible,
        EffectSet direct,
        EffectSet declared,
        EffectSet undeclared,
        EffectSet overdeclared,
        boolean entryPoint,
        boolean unresolved,
        EffectorKind kind,
        List<UnknownReason> unknownWhy,
        String hash,
        List<String> calls,
        List<String> fs,
        List<String> hosts,
        List<String> cmds,
        List<String> paths,
        List<String> tables,
        List<String> netClass,
        /** ⟨0.29⟩ SPEC §2 `incomplete` — the effects whose LOCATOR this unit could not determine (its own
         *  `Fs` write whose path is a parameter, its own exec whose command is computed). Omitted when
         *  empty, so a scan that determined everything stays byte-identical to a pre-rung report.
         *
         *  <p>DISTINCT FROM an empty {@code paths}: absent `paths` is overloaded between "reaches no path"
         *  and "reaches a path I could not see", and this field is the only thing that separates them. It
         *  is what §2's chained-join clause requires a consumer to carry — "a join that carries the effect
         *  and drops `incomplete` lets a benign literal in the consumer certify what the dependency
         *  declared uncertifiable". This engine computed it internally and never published it, so a
         *  consumer chaining its reports had nothing to carry. */
        List<String> incomplete,
        boolean interfaceUnion,
        /** ⟨0.39⟩ SPEC §4 obligation 1 — the ABSTRACTION MEMBERS this unit dispatches on, TRANSITIVELY,
         *  each spelled exactly as this engine spells an entry {@code hash} for that member
         *  ({@code iface/Backend.size()I}). A JVM hash is already fully qualified in the OWNING package's
         *  namespace, so ⟨0.39⟩'s "an engine MUST NOT invent a second spelling for this key" costs this
         *  engine nothing: a consumer looks the key up in its {@code crossDeps} index directly, with no
         *  package prefixing and no second convention. (candor-scan spells the member in the producing
         *  crate's own namespace and has the consumer form {@code crate#member}; the property is the same,
         *  the arithmetic differs, and the ⟨0.23⟩ rule — fully qualified in the OWNING package's
         *  namespace, the same namespace that package's entry hashes use — is what both satisfy.)
         *
         *  <p><b>Carried EVEN WHEN THE ROW IS OTHERWISE PURE — the deliberate exception to §2 rule 3's
         *  "reports omit pure functions".</b> The defect is a toggle running the wrong way: a dispatching
         *  function whose only visible implementer happens to be pure is ABSENT from the report, and
         *  absence is a purity claim, so ADDING A PURE IMPLEMENTATION TO A LIBRARY DELETED A DISCLOSURE
         *  FROM EVERY CONSUMER OF IT (SOUNDNESS R475, measured live on ratatui). A pure function that
         *  dispatches is no longer a function about which there is nothing to say. */
        List<String> dispatchesOn) {

    /** The pre-⟨0.39⟩ arity: an entry naming no dispatched member. Keeps every hand-built
     *  {@code Effector} — the read side, the fix verbs, the tests — from restating the default. */
    public Effector(String fn, String loc, EffectSet inferred, List<String> invisible, EffectSet direct,
            EffectSet declared, EffectSet undeclared, EffectSet overdeclared, boolean entryPoint,
            boolean unresolved, EffectorKind kind, List<UnknownReason> unknownWhy, String hash,
            List<String> calls, List<String> fs, List<String> hosts, List<String> cmds,
            List<String> paths, List<String> tables, List<String> netClass, List<String> incomplete,
            boolean interfaceUnion) {
        this(fn, loc, inferred, invisible, direct, declared, undeclared, overdeclared, entryPoint,
                unresolved, kind, unknownWhy, hash, calls, fs, hosts, cmds, paths, tables, netClass,
                incomplete, interfaceUnion, List.of());
    }

    /** The pre-⟨0.23⟩ arity: an ordinary entry, never a synthetic {@code interfaceUnion} union. Keeps the
     *  read side and the tests that build an {@code Effector} by hand from restating the default. */
    public Effector(String fn, String loc, EffectSet inferred, List<String> invisible, EffectSet direct,
            EffectSet declared, EffectSet undeclared, EffectSet overdeclared, boolean entryPoint,
            boolean unresolved, EffectorKind kind, List<UnknownReason> unknownWhy, String hash,
            List<String> calls, List<String> fs, List<String> hosts, List<String> cmds,
            List<String> paths, List<String> tables, List<String> netClass) {
        this(fn, loc, inferred, invisible, direct, declared, undeclared, overdeclared, entryPoint,
                unresolved, kind, unknownWhy, hash, calls, fs, hosts, cmds, paths, tables, netClass,
                List.of(), false);
    }

    /**
     * Defensive copy on construction so an {@code Effector} is a true value: its accessors can't be used
     * to mutate it, and it never aliases the engine's live (mutable) {@link EffectSet}s / state maps
     * (which {@code resetState()} clears between scans). Effect sets are snapshotted via {@link EffectSet#copy()};
     * lists via {@link List#copyOf} (which also rejects nulls).
     */
    public Effector {
        inferred = inferred.copy();
        direct = direct.copy();
        declared = declared.copy();
        undeclared = undeclared.copy();
        overdeclared = overdeclared.copy();
        invisible = List.copyOf(invisible);
        unknownWhy = List.copyOf(unknownWhy);
        calls = List.copyOf(calls);
        fs = List.copyOf(fs);
        hosts = List.copyOf(hosts);
        cmds = List.copyOf(cmds);
        paths = List.copyOf(paths);
        tables = List.copyOf(tables);
        netClass = List.copyOf(netClass);
        incomplete = List.copyOf(incomplete);
        dispatchesOn = List.copyOf(dispatchesOn);
    }
}
