# Cross-organization corpus — findings

Engine: candor-java `-all.jar` sha256 `e60655c6…` (commit `8b5d0b0`). Per `PREREG.md`, findings here are
**recorded, not repaired**: no classifier change was made during or because of this run.

## Disposition of the HikariCP run — READ THIS FIRST

**HikariCP's result was obtained during FEASIBILITY PROBING, before `PREREG.md` was committed.** The probe
was intended to answer "does the harness work and is coverage achievable"; it also returned the outcome.
That makes HikariCP **outcome-known**, not outcome-blind, and it is labelled as such wherever it is
reported — the same distinction the paper already draws between the frozen *replication* (outcome-known,
reproduced R8) and the *fresh-draw* (outcome-unknown). `gson` and `jgit` remain outcome-blind at the time
of pre-registration and carry the stronger evidential status. Presenting HikariCP as a blind confirmatory
catch would be exactly the kind of quiet retrofit this corpus exists to rule out.

## Result: 2 false all-clears on held-out, cross-organization code

`HikariCP-5.1.0` (brettwooldridge — an organization no candor classifier fix was developed against),
its own suite driven single-JVM, `--scope all`:

| metric | value |
|---|---|
| analyzed functions | 1180 |
| executed + checked | 74 (**coverage 6.3%**) |
| sound-complete (`D = ∅`) frames | 25 |
| disclosed-partial | 47 |
| **cardinal-sin violations** | **2** |
| `honestyInvariantHolds` | **false** |
| attributionComplete | true |

Both violations, identical shape:

| function | inferred | observed | escaped |
|---|---|---|---|
| `com.zaxxer.hikari.util.ConcurrentBag.remove` | `[Log]` | `[Clock]` | `Clock` |
| `com.zaxxer.hikari.util.ConcurrentBag.unreserve` | `[Log]` | `[Clock]` | `Clock` |

### The vein: an effect reached through an IMPLICIT `toString()` over a generic-bounded type parameter

```java
public class ConcurrentBag<T extends IConcurrentBagEntry> { ...
   public boolean remove(final T bagEntry) {
      ...
      LOGGER.warn("Attempt to remove an object ... : {}", bagEntry);   // <- implicit bagEntry.toString()
```
and the concrete `T` is `PoolEntry`:
```java
public String toString() {
   final var now = currentTime();                                      // <- Clock
   return connection + ", accessed " + elapsedDisplayString(lastAccessed, now) + " ago, " + stateToString();
}
```

candor resolved the `LOGGER.warn` call itself (hence the inferred `Log`) but did **not** follow the
*implicit* `toString()` the logging call performs on its argument, whose receiver type is the generic
parameter `T` bounded by a project interface. So the frame read `(S = {Log}, D = ∅)` — sound-complete and
wrong — while the run charged it `Clock`. That is a false all-clear in the strict sense: a `D = ∅`
signature whose executed effect escaped its declared set.

This is a **classifier vein, not a model boundary**: it is not any of the eight open R-class residuals,
not the (A0) enumeration-gap class, and not the cross-thread handoff boundary (the effect fires on the
same thread, inside the frame's own extent). It is resolvable in principle — the receiver's bound is a
visible project interface with a visible implementor — so it earns **no §8.5 carve-out**.

### Why this matters more than one more catch

The mechanism family is one candor has closed repeatedly in *other* engines — generic-bound dispatch
(rust R37b, swift R39) — but the trigger here is the **implicit** call: no `toString()` appears in the
source, the JVM inserts it at the string-concatenation/logging boundary. An analysis that models explicit
dispatch and forgets compiler-inserted dispatch will read exactly this shape as pure. The Apache Commons
corpora never surfaced it because their logging idiom differs; a different organization's house style
found it in the first repository tried. That is the cross-organization argument in one datapoint, and it
is evidence *for* the method and *against* the current headline rate.

### Effect on the paper's claims

- The confirmatory false-all-clear rate must now be stated over a corpus that includes this run. The
  previously reported `0/25` and `1/112` are **in-family** numbers and must be labelled as such.
- §6.3's conceded threat ("the confirmatory holds are anti-conservative on in-family code — the classifier
  was patched on the neighbours") is no longer a conceded *risk*; it is a **measured** result.
- The honest headline becomes: the falsifier catches real false all-clears on code from organizations the
  classifier was never tuned against — which is what a falsifier is *for* — and the invariant does not
  hold unconditionally on such code.

### Coverage: the second W2 goal was NOT met here

6.3% of analyzed functions were executed and checked — the same order as the corpora §6.2 already
concedes. HikariCP's suite is thorough for a pool but touches a small fraction of the analyzed surface.
The >50% target is **not** achieved by this repo and is not claimed. Whether `gson` (117 test classes over
223 analyzed) or `jgit` reach it is an open question at pre-registration time.

---

# Complete cross-org corpus result (all three repos)

| repo | org | outcome-blind? | analyzed | checked | coverage | falsifiable (`D=∅`) | violations | verdict |
|---|---|---|---|---|---|---|---|---|
| HikariCP | brettwooldridge | **no** (feasibility probe) | 1180 | 74 | 6.3% | 25 | **2** | **VIOLATION** |
| gson | Google | yes | 386 | 0 | 0.0% | 0 | 0 | vacuous |
| jgit | Eclipse | yes | 7615 | 1541 | **20.2%** | **36** | 0 | held |

## What each row actually supports

**HikariCP — 2 false all-clears, but outcome-known.** The implicit-stringification vein
(`candor-spec/SOUNDNESS-VEIN-implicit-stringify.md`), silent in all four engines. Seen during feasibility
probing before pre-registration, so it does **not** carry blind-confirmatory status; it is a genuine
catch on cross-org code, reported with that caveat.

**gson — vacuous, and a SELECTION ERROR we own.** The suite ran; **no in-scope effect ever executed**
(`checked = 0`). gson was chosen for dynamic-feature density (reflective type adapters) and it has that —
but it is effect-*poor*: pure serialization, no `Net`/`Fs`/`Db`/`Clock` in its hot path. `PREREG.md` names
the criterion as "dynamic-feature density **AND** effect class"; we satisfied the first and not the
second. This row is **not a hold** and must never be counted as one — a corpus with no effect surface
cannot falsify H.

**jgit — the strongest row methodologically, and weaker than it first reads.** Outcome-blind, effect-rich
(Fs + Net), **20.2% coverage — 3× the best of any prior confirmatory corpus** (§6.2 concedes 0–6.3%), 1541
functions checked, attribution complete, **0 violations, H holds.** But the falsifiable denominator is
**36**: of 1541 executed-and-checked functions, 1505 were **disclosed-partial**, where H is *vacuous by
construction*. So the hold rests on 36 sound-complete frames, not on 1541. candor disclosed `Unknown` on
**98% of executed jgit functions** — the disclosure posture working exactly as designed (never silently
pure), but leaving H with very little to bite on. A reader must not convert "1541 checked, 0 violations"
into confidence proportional to 1541.

## Against the two W2 goals

1. **Cross-organization holdout: ACHIEVED.** Three organizations, none of which authored code any candor
   classifier fix was developed against. And it did what a fair test is supposed to do — it found a
   defect the in-family corpora never surfaced, in the first repository with a real effect surface.
2. **>50% coverage: NOT ACHIEVED.** Best is jgit at 20.2%. Better than the 0–6.3% the paper concedes, and
   materially so, but not the target. The claim stands as measured; the target is not quietly restated
   downward.

## The honest headline for the paper

The cross-organization corpus **did not confirm the in-family rate — it broke it.** On the first repo with
a genuine effect surface, the frozen engine issued two false all-clears via a vein that is silent in all
four engines. The one clean hold (jgit) is real, outcome-blind, and at the best coverage yet, but rests on
36 falsifiable frames. §6.3's conceded threat — "the confirmatory holds are anti-conservative on in-family
code; the classifier was patched on the neighbours" — is now a **measured result rather than a risk**, and
the `0/25` / `1/112` rates must be labelled in-family wherever they appear.
