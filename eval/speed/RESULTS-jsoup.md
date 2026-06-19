# Results — token/speed batch 2 (jsoup, a real 306-class codebase)

Run per [PREREG-jsoup.md](PREREG-jsoup.md). N=6/arm = 12 trials, Opus-class both arms, identical
question except the tool clause, on jsoup (306 classes / 1502 functions). Target:
`org.jsoup.nodes.Element.select(String)`. Pre-registration + ground-truth set committed before any
batch-2 trial (`e2b2aa5`). Per-trial numbers in `runs/metrics-jsoup.tsv`.

## Headline — cost (the primary metric)

| metric (median) | control (trace source) | treatment (candor query) | ratio |
|---|---:|---:|---:|
| wall-clock | **184 s** (~3 min) | **13 s** | **14.1×** |
| tool calls | **21** | **1** | **21×** |
| tokens | **47,328** | 22,253 | **2.1×** |

This is the batch-1 floor lifted by scale, exactly as pre-registered. On a real 306-class codebase a
control agent spends ~3 minutes and ~20 tool calls reading across the `nodes` / `helper` / `select` /
`examples` packages to trace the graph by hand; the treatment runs **one** `candor callers` query and
answers in 13 seconds. The cost claim's falsification bar (treatment ≥ control tokens) did not fire,
and unlike batch 1 the magnitude is large — because the control trace cost scales with the codebase
while the query is O(1) in the agent's effort.

## Completeness — neither is perfectly sound on real OO code (the honest part)

This is the secondary metric, and the divergence is the interesting result. The query returned **one
deterministic 34-function set in 13 s**. The six control agents returned **six different 17–18-method
sets** — they disagreed with candor *and with each other*. Adjudicated against source:

- **candor caught 4 real callers every control agent missed:** `Document.forms`, `expectForm`,
  `charset`, `ensureMetaCharsetElement` — all call `select(...)` via the inherited `Element.select`
  (Document.java:173, 185, 311). Hand-tracers systematically missed that `Document extends Element` and
  its own methods call `select`.
- **control listed `DataUtil.detectCharset` (+ its `streamParser` chain), which candor's `callers` set
  did not.** detectCharset calls `doc.select(metaCharset)` (DataUtil.java:276). But candor does **not**
  report detectCharset as pure: it carries `inferred = { Clock, Unknown }` — i.e. it is **flagged
  Unknown**, not silently dropped. So this is not the cardinal sin. The `callers` query lists candor's
  *confirmed* reachers; detectCharset carries an unresolved (`Unknown`) call, so it isn't asserted as a
  confirmed caller even though it is disclosed as effect-uncertain in the per-function report. Whether
  the specific `doc.select` edge is a resolution miss or folded into detectCharset's existing `Unknown`
  is **unverified** — I am not claiming a specific bug here.

So ~14 of the union's ~22 distinct methods are common, with the differences being (a) candor catching
inherited-`select` callers all six tracers missed and (b) candor disclosing `Unknown` where a tracer
asserted a concrete edge. The honest reading is **not** "candor is complete" and **not** "candor
under-reports" — it is the project's stated contract: candor is **instant, deterministic, surfaces real
callers humans miss, and discloses `Unknown` rather than guess**. "Disclosure, not a completeness proof,"
on real code. (An earlier draft called the detectCharset difference a candor precision bug; that was
unverified and overstated — detectCharset is `Unknown`-flagged, not silent.)

## What this supports

- **A real, large cost result on the bytecode engine**: ~14× faster, ~21× fewer tool calls, ~2× fewer
  tokens, on a genuine 306-class library — the scaling the batch-1 floor predicted.
- It does **not** support "candor finds everything" on CHA/inheritance-heavy code — and we don't claim
  it; the both-ways divergence is reported in full.

## Threats / honesty

- Wall-clock absolutes are noisy under concurrent trial load; the *ratio* (and the tool-call ratio,
  which is load-independent) is the statistic. The 21× tool-call gap (1 vs ~20) is the cleanest.
- The completeness divergence means the recall metric is not a clean "candor = truth"; that is why cost
  is primary and completeness is reported descriptively with source adjudication, per the
  pre-registration.
- One target, one codebase, N=6/arm.
