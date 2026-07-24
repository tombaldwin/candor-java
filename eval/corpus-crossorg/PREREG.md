# Pre-registration — CROSS-ORGANIZATION high-coverage confirmatory corpus (RQ1)

This file, `manifest.tsv`, and `run.sh` are committed **before** the run. Their git commit is the
pre-registration timestamp. Whatever the run reports is the result: **reported, not repaired.**

## What this run exists to answer

The existing confirmatory evidence (`eval/corpus-confirmatory`, `eval/corpus-confirmatory-freshdraw`,
`eval/transitive-reconcile`) has two conceded weaknesses that a reviewer can, correctly, refuse to look
past:

1. **In-family corpus.** Every fix-driving repository and most held-out ones are **Apache Commons**. The
   frozen engine embeds five classifier fixes tuned on *sibling* libraries of that same house style, so
   the confirmatory holds are **anti-conservative on in-family code** — the classifier was patched on the
   neighbours. §8.3/§6.3 concedes this and names a cross-organization slice as the honest generalization.
2. **Low coverage.** H is only checked on *executed* functions, and the reported per-function coverage runs
   as low as **0–6.3%** on single-entrypoint targets. A hold at 6% coverage is a weak claim: it says almost
   nothing about the 94% never run.

This corpus attacks **both** at once. It is drawn from organizations that authored **none** of the code any
candor classifier fix was developed against, and it is scored on **coverage as a first-class result**, not
as a footnote.

## The discipline (what makes this confirmatory)

1. **Frozen engine, pinned by binary hash.** candor-java `-all.jar`, sha256
   `e60655c680409516570160d68a5c1871af6aa31dabccdaa29e33dd73a76d9028`, built from commit `8b5d0b0`.
   `run.sh` verifies the hash and **aborts on mismatch**. No classifier change is made during or because
   of this run. A silent under-report surfaced here is **recorded as a violation**, not fixed-then-rerun;
   any fix is a separate, later effort with its own separate result and does not amend this table.
2. **Pre-registered corpus.** Repositories and refs are fixed in `manifest.tsv` before the run. Each ref is
   a release tag; the runner resolves it to a commit SHA and locks it in `results/SHALOCK.tsv`.
3. **Cross-organization, held out by ORG not merely by repository.** The developmental and prior
   confirmatory sets are Apache Commons plus `zip4j`/`jsoup`/`joda-time`/`jackson-*`/`nanohttpd`. This
   corpus excludes **every one of those, and their organizations**. See `manifest.tsv`'s `org` column: no
   Apache Commons, and no repo whose idioms a candor fix was tuned against.
4. **Coverage is a reported result, not a filter.** Every repo runs its OWN test suite single-process
   (JUnit `ConsoleLauncher`, one JVM, so the `-javaagent` sees every frame — `mvn test` forks per class and
   fragments the capture). `results/SUMMARY.tsv` reports `analyzed`, `checked`, and the **coverage
   percentage** per repo. A low-coverage repo is reported as low-coverage; it is not dropped, and its hold
   is explicitly labelled weak.
5. **Selection criterion: dynamic-feature density AND effect class.** A corpus with no reflection/DI/
   dynamic dispatch cannot falsify H. Additionally, §6.2 concedes the confirmatory corpora are
   *synchronous library test suites* and names a **`Net`/`Db`, pooled/threaded** run as the untested
   regime — so this corpus deliberately includes a connection pool whose suite is multi-threaded.

## What would count as what

- **Violation (a false all-clear).** An executed function with `D = ∅` whose `charged` set exceeds its
  declared `S`. This is the outcome the corpus is built to find. Recorded per-function with its frame.
- **Hold.** `H` held on the executed subset — reported **with** its coverage percentage. A hold at high
  coverage is meaningful evidence; a hold at low coverage is reported as the weak result it is.
- **Attrition.** Build failure, unresolvable deps, or a suite that cannot run single-process is tabulated
  as attrition with its cause. Attrition is **not** silently dropped: an omitted repo with no disposition
  row is a reporting defect.
- **Incomplete attribution.** The oracle exits 2 (fail-closed) rather than certifying a bogus green; that
  disposition is reported as `incomplete`, never folded into the holds.

## Stated in advance: the ways this run could embarrass us

We name these now so that finding them later is not presented as foresight.

- Coverage may **not** reach the >50% target on every repo; suites vary. The result stands as reported.
- A cross-org corpus is exactly where classifier veins tuned on Apache idioms are most likely to **miss**.
  Finding violations here is the *expected* outcome of a fair test, not a surprise, and would be reported
  as such — it strengthens the method's credibility while weakening the current headline rate.
- The engine carries **eight open R-class residuals** and the (A0) enumeration-gap class (`node-tar`);
  a violation landing in one of those is a *known* subtraction, not a new discovery, and will be labelled.
