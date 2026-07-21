# Flag-adjudication rule (held-out confirmatory runs, all four arms)

This is the rule by which a raw oracle **flag** on a held-out confirmatory run (§7.1/§8.5 of the paper) is
adjudicated to either a **violation** (a false all-clear that falsifies the honesty claim) or an **over-flag**
(an instrument artifact in the safe direction). It governs the JVM (`corpus-confirmatory`,
`corpus-confirmatory-freshdraw`), Node (`candor-ts/soundness/confirmatory`), and syscall
(`candor-{rust,swift}/soundness/confirmatory`) arms alike. Every adjudication publishes its per-flag trace
in the arm's `FINDINGS.md`, so which way a flag falls is checkable, not asserted.

## Provenance, stated honestly

The rule went through **two forms**. The **final form (v2)** below is the published, authoritative one
(this file is its committed artifact; its git history is its timestamp). The **earlier form (v1)** was *not*
separately committed at the time — it lived in the run's design notes — so it is **reconstructed here**, not
presented as a retained independent artifact. The one thing that matters for the paper's non-post-hoc claim
is verifiable from the reconstruction: **v2 differs from v1 only in the dismissal-*narrowing* direction** —
it removed a clause that would have laundered a genuine miss and added a guard that routes an unverifiable
case to a fail-closed verdict. Every amendment moved *against* the tool's interest. R8 and the two
JVM/Node over-flag dispositions are invariant across v1 and v2; only `node-tar` changes disposition (v1
would have wrongly dismissed it; v2 stands it as a violation).

## v2 — the final, authoritative rule

A flag **stands as a violation** unless one of the following holds (trace published in every case):

- **(i) foreign-source, no undisclosed dynamic site.** Its charged effect source-traces to code *outside the
  library under test*, **and** the flagged frame reaches that effect through *no undisclosed
  dynamically-bound site* — no higher-order invocation, virtual/interface/override dispatch, or reflection
  that candor left undisclosed. (If any such site is on the path, the `(∅,∅)` is a genuine (A1)/(A3) miss,
  not an artifact, even though the effect's ultimate source is test code.)
- **(ii) outside dynamic extent, callee-disclosed, no async edge.** Its charged effect source-traces to a
  callee *outside the flagged frame's own dynamic extent* whose effect the analyzed callee already discloses,
  **and** no async-submission (cross-thread) edge from the flagged frame reaches it. A flag whose effect
  crosses a thread boundary is **not** dismissed here — it routes to the fail-closed **exit-2**
  (attribution-incomplete) disposition, because the oracle cannot witness the handoff and dismissing it would
  launder the async blind region (§8.2).
- **(iii) uncovered reach, receipt-disclosed.** Its charged effect reaches *only* through an **uncovered**
  package that the flagged frame's coverage-envelope receipt actually discloses (§3.4 covered-set scoping).
- **(iv) out-of-scope frame (scanner-scoping error).** The flagged frame lies **outside the library-under-test's
  claimed analyzed scope** — e.g. a test-harness file that should not have been scanned at all. This is a
  *scanner-scoping* error, tabulated as its **own disposition**, not a library false all-clear and not a
  clean over-flag; the remedy is to fix the scan's input set, not the classifier. (This is the clause that
  stands behind the `get-port` disposition: its flagged frame is the *test file's own* `<module>`, which the
  scan should not have included.)

A frame **candor never emitted a signature for does NOT earn dismissal** under (i)–(iii): under
`absent ⇒ (∅,∅)` (§3.2) an un-enumerated *in-scope* frame *reads as provably pure*, so a flag on it is a
genuine (A0) consumer-level false all-clear, not an artifact. (This is the clause that stands `node-tar` —
distinct from clause (iv), which is about a frame that should never have been in the analyzed set at all.)

## Frame accounting (how flagged D=∅ frames are tallied)

The runners' `sound_complete` column counts only D=∅ frames the oracle checked and found **clean**. A
**flagged** D=∅ frame (one the oracle charged an effect against) is tallied in the **`violations`** column,
*additional to* `sound_complete` — so a dismissed over-flag on a D=∅ frame is **not** inside the
`sound_complete` denominator. This matters for the confirmatory rate (§8.5): the "0 violations on 25
sound-complete frames" counts the 25 **clean** frames; the two dismissed Node over-flags (`get-port`,
`proper-lockfile`) are D=∅ frames flagged-then-dismissed that sit *outside* the 25, so the strictest reading
that refuses to dismiss them is **1/26** (proper-lockfile, the unambiguous in-scope library frame) or **2/27**
(also counting get-port's out-of-scope frame per clause (iv)); the R8 event is likewise a flagged D=∅ frame
outside the 86 replication `sound_complete`, so the pooled descriptive figure is **1/112**, not 1/111.

## v1 — the earlier form (reconstructed)

v1 was the same three-disjunct shape with two weaker points, both of which v2 tightened:

1. **Disjunct (i) was narrower.** v1 exempted a foreign-source effect reached through a *higher-order
   callback* only; it did not name virtual/interface/override dispatch or reflection as blocking dynamic
   sites. v2 generalized the block to *any* undisclosed dynamically-bound site (an adversarial-review catch:
   an open-world subclass-overridden hook — R8's own family — could otherwise be dismissed merely because
   the effect source-traced to test code).
2. **v1 carried an un-emitted-frame dismissal clause.** v1 would have treated a flag on a frame candor never
   emitted a signature for as an over-flag ("we made no claim there"). v2 **removed** this: under
   `absent ⇒ (∅,∅)` such a frame reads pure, so the flag is a real (A0) miss. This is the single
   disposition change between the versions — `node-tar` falls to *over-flag* under v1 and *stands as a
   violation* under v2.
3. v1 had **no async guard** on disjunct (ii); v2 added the cross-thread → exit-2 routing.

All three v1→v2 changes narrow what may be dismissed. There is no change that *widened* dismissal.

## The five held-out flags under v2

| flag | arm | disposition | why |
|---|---|---|---|
| R8 (`AbstractMapDecorator.equals` → `Clock`) | JVM | **violation** | reach is inside `equals`'s dynamic extent, through *covered* (modelled JDK `HashMap.equals`) code; `equals` carries a real `D=∅` signature. Not dismissible under (i)/(ii)/(iii). |
| `node-tar` (`WriteEntrySync.constructor` Env/Fs) | Node | **violation** | un-emitted, undisclosed constructor → reads pure under `absent ⇒ (∅,∅)`. The removed v1 clause is what would have laundered it. |
| `get-port` (`ava` snapshot `Fs`) | Node | over-flag (scanner-scope) | flagged frame is the *test file's own* `<module>` — outside the library-under-test's claimed scope (clause iv), not a library false all-clear. |
| `proper-lockfile` (module-init `Fs`) | Node | over-flag | effect fired *outside* the module-init frame's dynamic extent, disclosed on the functions that perform it (disjunct ii). |
| `Path.swift next@Net` | Swift | over-flag | `-k` leaf-name collision (`next` iterator ≠ networking); XCTest socket mis-attributed by leaf name (instrument artifact, safe direction). |

Held-out **oracle flag precision** is therefore **2 of 5** (R8, `node-tar` are real; three are over-flags) —
a tiny sample (Wilson 95% ≈ [12%, 77%]); a third-party re-adjudication of these five is a camera-ready
commitment (§8.5).
