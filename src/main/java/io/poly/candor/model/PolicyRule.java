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
public sealed interface PolicyRule permits PolicyRule.Deny, PolicyRule.Allow, PolicyRule.Forbid {

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

    record Forbid(String from, String to) implements PolicyRule {}
}
