package io.poly.candor.model;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A set of {@link Effect}s — an element of the analysis lattice {@code 𝓛 = (𝒫(𝔼 ∪ {Unknown}), ⊆)}
 * with join {@code ⊔ = ∪} (candor-spec SEMANTICS §1). Backed by an {@link EnumSet} for cheap union
 * in the fixpoint hot path; the value candor attributes to an {@link Effector}'s {@code inferred} /
 * {@code direct} fields.
 *
 * <p>{@link #toNames()} is the single wire-serialization path and always emits in spec-name
 * alphabetical order — identical to the historical {@code TreeSet<String>} order. That, plus union
 * being order-independent, is what keeps the typed representation byte-identical to the strings it
 * replaces.
 */
public final class EffectSet {

    private final EnumSet<Effect> set;

    private EffectSet(EnumSet<Effect> set) {
        this.set = set;
    }

    public static EffectSet empty() {
        return new EffectSet(EnumSet.noneOf(Effect.class));
    }

    public static EffectSet of(Effect... effects) {
        EnumSet<Effect> s = EnumSet.noneOf(Effect.class);
        Collections.addAll(s, effects);
        return new EffectSet(s);
    }

    public static EffectSet copyOf(Collection<Effect> effects) {
        EnumSet<Effect> s = EnumSet.noneOf(Effect.class);
        s.addAll(effects);
        return new EffectSet(s);
    }

    /**
     * Build from spec-name strings. Names outside the §1 vocabulary (a hypothetical language-specific
     * effect on a foreign report) are skipped — candor-java only ever produces the standard vocabulary,
     * so this is exact for its own reports.
     */
    public static EffectSet ofNames(Collection<String> names) {
        EnumSet<Effect> s = EnumSet.noneOf(Effect.class);
        for (String n : names) {
            Effect e = Effect.fromSpecName(n);
            if (e != null) s.add(e);
        }
        return new EffectSet(s);
    }

    public boolean contains(Effect e) {
        return set.contains(e);
    }

    public boolean isEmpty() {
        return set.isEmpty();
    }

    public int size() {
        return set.size();
    }

    /** Mutating add (for in-place accumulation in {@code analyze()} / the fixpoint). */
    public boolean add(Effect e) {
        return set.add(e);
    }

    /** Mutating union (for in-place fixpoint propagation). */
    public boolean addAll(EffectSet other) {
        return set.addAll(other.set);
    }

    /** Non-mutating join {@code ⊔} (∪) — SEMANTICS §1. */
    public EffectSet join(EffectSet other) {
        EnumSet<Effect> s = EnumSet.copyOf(set);
        s.addAll(other.set);
        return new EffectSet(s);
    }

    public EffectSet copy() {
        return new EffectSet(EnumSet.copyOf(set));
    }

    /** {@code Unknown} ∈ this — i.e. the effect set is not provably complete (sets {@code unresolved}). */
    public boolean hasUnknown() {
        return set.contains(Effect.UNKNOWN);
    }

    public Set<Effect> effects() {
        return Collections.unmodifiableSet(set);
    }

    /** Spec-name strings in alphabetical (wire) order — the one serialization path. */
    public List<String> toNames() {
        return set.stream().map(Effect::specName).sorted().collect(Collectors.toList());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof EffectSet e && set.equals(e.set);
    }

    @Override
    public int hashCode() {
        return set.hashCode();
    }

    @Override
    public String toString() {
        return toNames().toString();
    }
}
