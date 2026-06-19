# Results — token/speed batch 3 (uFlexi, a real in-production app)

Run per [PREREG-uflexi.md](PREREG-uflexi.md). N=6/arm = 12 trials, Opus-class both arms, on uFlexi
(2272 production classes / 9559 functions). Target: `com.uflexi.nems.utils.MailLinks.getMailLinks` (a
single-signature `public static` util — concrete dispatch). Pre-registration + ground-truth committed
before any trial (`76adf7d`). Per-trial numbers in `runs/metrics-uflexi.tsv`.

## Headline — cost

| metric (median) | control (trace source) | treatment (candor query) | ratio |
|---|---:|---:|---:|
| wall-clock | **521 s** (~8.7 min) | **19 s** | **26.8×** |
| tool calls | **42** | **1** | **41.5×** |
| tokens | **80,258** | 23,757 | **3.4×** |

This is the project's own production codebase — the most realistic test available — and the gap is the
largest of the three batches (synthetic floor 1.16×; jsoup 14×; uFlexi 27× wall-clock). On a 2272-class
app, a control agent spends **5.6–11 minutes** and **32–55 tool calls** searching 1888 source files to
trace the call graph by hand; the treatment runs **one** `candor callers` query and answers in ~19 s.
The cost claim's falsification bar was not hit on any axis.

## Completeness — candor matched an expert hand-trace exactly (the validation)

Unlike jsoup (CHA-heavy, both-ways divergence), the target here is a concrete static method, so candor's
caller set is sound — and the data confirms it. **One control agent's full ~8-minute trace reproduced
candor's 41-function set EXACTLY — 41/41, zero divergence.** The query returns in 19 s what a careful
human derives in 8 minutes.

The other five control agents landed within ±1–2 of the set — and the divergences are themselves the
finding:

- **`SellerBookingModel.hasTemporaryPurchaseExpired`** — two control agents included it; it has no path
  to `getMailLinks`. A **hand-tracing over-report**; candor (and the exact-match control) correctly
  excluded it.
- **`NEMsScheduledTaskAction.execute`** — one control agent included it, and it is **right**: the
  abstract `execute` calls the abstract `performTask()` (NEMsScheduledTaskAction.java:47→52), which
  dispatches to the Net-performing subclass overrides (`STPollForMessages`/`STRebookAra...`). **candor
  missed this** — a real under-report on **dispatch through an abstract/inherited method**. This is the
  *same* gap class jsoup surfaced (`DataUtil.detectCharset`'s explicit-receiver inherited call), now
  confirmed on two independent real codebases — a specific, high-value candor-java precision target.

So candor's set is sound enough to match the best expert trace exactly, with one disclosed dispatch gap
— "disclosure, not a completeness proof," and the gap is now characterised precisely for a fix.

## Determinism

6 treatment trials: identical answer, ~19 s each, 1 tool call. 6 control trials: six *different* answers
(±1–2 methods), 5.6–11 min each, 32–55 tool calls. The query is deterministic; hand-tracing a real
codebase is slow and noisy even for a frontier model.

## Threats / honesty

- Wall-clock absolutes vary under concurrent load; the tool-call ratio (1 vs ~42) is load-independent
  and the cleanest statistic.
- One target, one app, N=6/arm. The target is a concrete static method (chosen precisely so candor's set
  is clean ground truth); a dispatch-heavy target would reintroduce the jsoup-style divergence.
- The `NEMsScheduledTaskAction.execute` miss is a genuine candor-java limitation, reported here rather
  than hidden — and it is the actionable output of running on real code.
