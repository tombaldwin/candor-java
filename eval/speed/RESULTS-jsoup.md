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
- **control caught 1 (+3 transitive) real caller candor missed:** `DataUtil.detectCharset` calls
  `doc.select(metaCharset)` (DataUtil.java:276), reached transitively via `detectCharsetForStreamParser`
  / `streamParser` / `HttpConnection$Response.streamParser`. candor's caller set omits these — a real
  resolution gap on an **explicit-receiver call to an inherited method** (it resolves the implicit-`this`
  inherited `select` in `Document.forms`, but missed `doc.select` where `doc` is a `Document` local).

So ~14 of the union's ~22 distinct methods are common, with ~4 gaps **each way**. The honest reading is
**not** "candor is complete" — it is the project's stated contract: candor is **instant, deterministic,
and surfaced real callers that all six expert tracers missed**, while having its own disclosed gap. That
is "disclosure, not a completeness proof," demonstrated on real code. (The `detectCharset` miss is a
genuine candor-java precision bug worth a follow-up sweep: explicit-receiver dispatch to an inherited
method.)

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
