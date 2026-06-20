# Plan — sealed-type closed-hierarchy carve-out (bounded-CHA precision frontier)

Goal: reduce `dispatch:`-Unknown (the dominant Unknown driver on tangled OO, per the library dogfood) for the
ONE case where it can be reduced soundly+exactly — a **sealed** abstract type. Tom picked the bounded-CHA
frontier (2026-06-20) over more κ sweeping.

## The lever (and why it's the only sound one here)

Bounded CHA (Candor.java:2390): `broad = cha.size() > CHA_FANOUT_LIMIT(12) && !isClosedEnumOwner(min.owner)`.
A `broad` dispatch drops ALL implementors and emits `dispatch:` Unknown — to avoid SMEAR (one impl's effect
unioned onto every caller of the abstract method, even callers that only ever hit a pure impl). The bound is
honest for an OPEN hierarchy (an external/unseen subtype may exist → the visible set is incomplete).

The enum carve-out (0.7.1) already exempts enums: an enum's constant bodies are the WHOLE possible target set
(no external subtype can exist), so resolving all past the bound is sound + EXACT, not smear.

**Sealed types (Java 17+) are the exact generalization.** A `sealed` class/interface has a `permits` list (ASM
`ClassNode.permittedSubclasses`) that is the COMPLETE, finite, compiler-enforced set of direct subtypes — no
external subtype can exist. So a dispatch over a sealed type resolves to a known, finite set, exactly like an
enum. Resolving all of them past the bound is sound+exact. **Raising the bound for OPEN hierarchies stays
rejected** (memory: smear-risk, doesn't help reflection-heavy code) — this plan ONLY touches sealed/enum.

## The two soundness gates (get these wrong → silent-pure or smear)

A sealed type is a safe carve-out ONLY when BOTH hold; otherwise fall back to `broad` (Unknown, honest):

1. **Fully closed (no `non-sealed` escape hatch).** JLS lets a permitted subtype be `final`, `sealed`, OR
   `non-sealed`. A `non-sealed` subtype RE-OPENS the hierarchy below it (external code can extend it) → the
   target set is NOT complete → treating it as closed would SILENT-PURE an unseen external impl's effect.
   So: a type is closed iff it is sealed AND every transitively-permitted subtype is `final` or `sealed`
   (NONE `non-sealed`). Detect `non-sealed`: a permitted subtype whose own class is neither `final` nor
   sealed (no `ACC_FINAL`, no `permittedSubclasses`) is `non-sealed` → NOT closed.

2. **Fully visible (every permitted subtype is in `byName`).** Even with a complete `permits` list, if a
   permitted subtype's class is NOT on candor's analysis classpath (`byName` miss), candor cannot analyze
   that impl's effect — resolving "all visible" would MISS it → silent-pure. So: every transitively-permitted
   subtype must be present in `byName`. Any unseen permitted subtype → NOT a safe carve-out → stay Unknown.
   (This is stricter than enums, where the constant bodies are always in the same class file = always visible.)

If either gate fails, the dispatch stays `broad` → `dispatch:` Unknown (the current honest behavior). The
carve-out only ever turns a sound-Unknown into a sound-exact-resolution; it never introduces a silent-pure
(gate 2) or a smear (gate 1 — a fully-closed-visible set IS the exact target set, no over-approximation).

## Mechanism (small, localized)

1. Rename/generalize `isClosedEnumOwner(internal)` → `isClosedHierarchy(internal)`:
   - enum (existing: `ACC_ENUM` or superName `java/lang/Enum`) → true (unchanged), OR
   - `isFullyClosedSealed(internal)`: `cn.permittedSubclasses` non-empty AND `closedAndVisible(cn)` where
     `closedAndVisible` does a transitive walk of permittedSubclasses: for each, require it's in `byName`
     (gate 2) AND (it's `final` OR it's itself sealed-and-closed) (gate 1) — recurse into sealed children.
     Memoize per-owner (the walk is O(hierarchy) and called in the per-instruction hot loop — cache it).
2. Line 2390: `&& !isClosedEnumOwner(...)` → `&& !isClosedHierarchy(...)`. Nothing else changes — when the
   carve-out fires, `broad=false` so `targets=cha` (all visible impls) get edged, exactly as enums do today.
   chaTargets already enumerates the visible subtypes via subtypeIndex, so "resolve all" is free.

## Gates / verification

- New `SealedHierarchyTest` (JUnit): (a) a sealed interface with >12 final-permitted impls, one effectful →
  the dispatch surfaces the effect (not Unknown); (b) a sealed interface with a `non-sealed` permitted subtype
  → STAYS Unknown (gate 1); (c) a sealed type permitting an unseen subtype → STAYS Unknown (gate 2 — simulate
  by referencing a permits entry not compiled into the scan dir); (d) a >12 OPEN (non-sealed) hierarchy →
  STAYS Unknown (regression — bound still bites); (e) a pure sealed hierarchy stays pure-not-Unknown.
- Full soundness suite + fabrication probe + kappa_probe + kappa_libs + PetClinic byte-identical (the carve-out
  must not change PetClinic — it has no sealed >12 hierarchies; expect 0 delta).
- 4-engine conformance: this is a candor-java engine-internal precision change (Unknown→resolved on sealed),
  NO spec change, NO unknownWhy-vocabulary change. Conformance fixtures have no sealed >12 hierarchies → inert.
  Confirm the `dispatch:` frontier conformance (the §3.1 dispatch-broad fixture) still agrees — it uses an
  OPEN hierarchy (Base.op 13 impls, not sealed), so it must STILL be Unknown/frontier-listed (gate must not
  swallow it). This is the key conformance check.

## Honest value caveat (state it up front)

The measured dogfood libs (jsoup/gson/hikari) PREDATE sealed types → this will NOT move their Unknown numbers.
It's a sound precision win for MODERN Java (sealed + records = the idiomatic ADT/state-machine pattern, the
direct successor to the enum-state-machine case the enum carve-out targeted). Need a sealed-heavy fixture to
measure the win; without one, the value is "correct for modern code" not "moves the existing benchmark." If
the review or measurement says the win is too marginal to justify the soundness-gate complexity, the fallback
is to NOT ship it and leave bounded-CHA Unknown as the documented honest-irreducible (the project's prior
conclusion + the blindspots query that surfaces the sources).

## Build order (gate-first, incremental)

1. `isFullyClosedSealed` + memoized `closedAndVisible` walk + a unit test for the predicate in isolation
   (sealed-closed=true, sealed-with-non-sealed=false, sealed-with-unseen=false, enum=true, open=false).
2. Wire into line 2390; SealedHierarchyTest (a)-(e).
3. Full gate + conformance (esp. the open-hierarchy dispatch frontier still Unknown).
4. Measure on a sealed-heavy fixture (build one: a sealed `Shape`/`Expr` ADT with >12 permits, mixed effects);
   report the Unknown delta. Decide ship/no-ship against the value caveat.
