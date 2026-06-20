package io.poly.candor.model;

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

    record Deny(EffectSet effects, String scope, String src) implements PolicyRule {}

    record Allow(Effect effect, String scope, SortedSet<String> values, String src) implements PolicyRule {}

    record Forbid(String from, String to) implements PolicyRule {}
}
