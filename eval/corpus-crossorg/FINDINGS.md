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
