package io.poly.candor.model;

import java.util.Set;
import java.util.SortedSet;

/**
 * An architecture-as-code policy rule (candor-spec §6.2). The three rule kinds of the DSL, as a
 * sealed type so a consumer can exhaustively switch:
 *
 * <ul>
 *   <li>{@link Deny} — {@code deny <Effect…> [scope]} / {@code pure [scope]} (empty effect set ⇒ a
 *       {@code pure} rule). AS-EFF-006.
 *   <li>{@link Allow} — {@code allow <Effect> [in <scope>] <value…>} (effect ∈ {Net,Exec,Fs,Db}).
 *       AS-EFF-008.
 *   <li>{@link Forbid} — {@code forbid <A> -> <B>} (dependency-direction boundary). AS-EFF-009.
 * </ul>
 *
 * The JVM realization of the spec's policy rule kinds (Rust's {@code PolicyRule}/{@code AllowRule}/
 * {@code LayerRule}). {@code values} on {@link Allow} is a {@link SortedSet} — the wire surface order is
 * encoded in the type, not just promised in prose.
 */
public sealed interface PolicyRule permits PolicyRule.Deny, PolicyRule.Allow, PolicyRule.Forbid,
        PolicyRule.Only {

    /**
     * {@code deny <Effect…> [Unknown[<class…>]] [Net[<dest…>]] [scope]} / {@code pure [scope]}.
     * {@code unknownClasses} is the reason-class filter on an {@code Unknown} membership
     * (REASON-SCOPED-UNKNOWN-DESIGN.md): an EMPTY set means {@code Unknown[*]} — match any {@code Unknown}
     * regardless of reason (the bare, pre-rung form); a non-empty set matches only an {@code Unknown} whose
     * reason maps to one of these classes. {@code netClasses} is the analogous destination-class filter on a
     * {@code Net} membership (NET-DESTINATION-CLASS-DESIGN.md): EMPTY ⇒ {@code Net[*]} (any destination, the
     * bare form); a non-empty set (e.g. {@code {unknown-host}}) matches only a {@code Net} whose fn reaches one
     * of these destination classes. Concrete effects in {@code effects} are unaffected by either filter.
     */
    record Deny(EffectSet effects, String scope, String src, Set<ReasonClass> unknownClasses,
                Set<String> netClasses) implements PolicyRule {
        /** Bare form: {@code Unknown}/{@code Net} (if present) match any reason/destination — {@code [*]}. */
        public Deny(EffectSet effects, String scope, String src) { this(effects, scope, src, Set.of(), Set.of()); }
        /** Reason-scoped form without a Net destination filter. */
        public Deny(EffectSet effects, String scope, String src, Set<ReasonClass> unknownClasses) {
            this(effects, scope, src, unknownClasses, Set.of());
        }
    }

    record Allow(Effect effect, String scope, SortedSet<String> values, String src) implements PolicyRule {}

    /**
     * {@code forbid <A> -> <B>}. ⟨0.24⟩ {@code src} is the RAW policy line, exactly as {@link Deny} and
     * {@link Allow} carry theirs — SPEC §3.1 pins the {@code unevaluated} disclosure to one entry PER RULE
     * with the raw line verbatim, and while this field was missing the only thing {@code gate --report}
     * could say about the rules it cannot evaluate was a KIND AGGREGATE ({@code "forbid (× 2)"}), which
     * answers "how many" where the operator asked "which".
     */
    record Forbid(String from, String to, String src) implements PolicyRule {}

    /**
     * ⟨0.29⟩ {@code only <A> -> <B> [<C> …]} — the PERMISSION form (AS-EFF-009). A method in scope
     * {@code from} may reach {@code from} itself and the scopes in {@code to}, and NOTHING else.
     *
     * <p><b>{@link Forbid} FAILS OPEN; this FAILS SAFE, and that is the whole reason it exists.</b> A
     * dependency you forgot to prohibit is silently permitted, so "this package is a leaf" can only be
     * spelled by enumerating what it must not reach — a list that does not cover a package added
     * tomorrow, and nothing says so. That is the allowlist hazard candor refuses everywhere in the
     * analysis, living in the POLICY LANGUAGE instead. Found by pointing candor's own architecture gate
     * at candor: the natural {@code forbid io.poly.candor.model -> io.poly.candor} SELF-FIRES at 58
     * violations, because a scope matches a contiguous run of segments and {@code model} sits under the
     * prefix it is trying to protect itself from.
     *
     * <p>{@code to} is a LIST — every token after the arrow is a permitted scope — which is the one
     * ergonomic difference from {@link Forbid}, and the reason an empty tail is DROPPED rather than read
     * as "A may reach nothing".
     */
    record Only(String from, java.util.List<String> to, String src) implements PolicyRule {}
}
