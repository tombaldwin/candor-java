# Results — candor-java token/speed eval

Run per [PREREG.md](PREREG.md). N=8/arm = 16 trials, Opus-class agent both arms, identical prompt
except the tool clause. All 16 returned a parseable 16-function list. Pre-registration committed before
any trial (`git log` — `eceb60d`). Raw per-trial numbers in `runs/metrics.tsv`.

## Headline — a soft positive, reported as the floor it is

| metric (median) | control | treatment | ratio |
|---|---:|---:|---:|
| tokens | 25,545 | 21,953 | **1.16×** |
| wall-clock | 24.4s | 18.0s | **1.35×** |
| tool calls | 3 | 3 | **1.0×** |
| completeness | **16/16** | **16/16** | 1.0 |

**The direction holds — treatment is cheaper and faster at identical, perfect completeness — but the
magnitude is small, and we report it as the floor it is.** The pre-registered falsification bars did
not fire (treatment tokens < control; treatment faster; neither arm is "fast but wrong" — both are
16/16). But this is a much smaller effect than the value proposition claims on real codebases, for
reasons the pre-registration anticipated:

1. **The fixture is small and the model is strong.** 10 classes, a 16-function radius, on a frontier
   model. Opus traces this whole graph from source in ~3 reads; there is little for a query to save.
   Token/tool savings scale with codebase size and closure depth — this fixture is a floor, not a
   headline.
2. **Treatment voluntarily double-checked.** Most treatment agents ran *two* queries (`callers` then
   `whatif` to cross-check) plus the prompt read — 3 tool calls, the same as a control agent batch-
   reading 3 source files. The tool-call advantage that drove the Rust study's ratio (treatment = 1
   call) washed out here because the agents chose to verify. That is sound behaviour; it just erases
   the headline on a fixture this small.
3. **Fixed per-agent overhead dominates.** ~20k of each trial's tokens is harness/boilerplate; the
   marginal cost of the question (the part candor actually reduces) is a small slice of the total, so
   the end-to-end ratio compresses (the marginal ratio is larger but not what this harness isolates).

The mean (not pre-registered as primary) is slightly kinder to candor — control mean tool calls = 6
(two agents traced file-by-file, 13 calls each) vs treatment 3, and control mean tokens 25,471 vs
21,954 — i.e. control's *variance* is higher (some agents trace inefficiently). But the median is the
honest statistic and it says: on a small, clean graph a frontier model barely needs the tool.

## What this does and doesn't support

- **Supports:** candor-java's query returns the complete blast radius and the agent that uses it is no
  worse off — equal completeness, modestly fewer tokens, modestly faster — replicating the *direction*
  of the Rust speed study (1.52×/1.81×) on the bytecode engine, at smaller magnitude.
- **Does NOT support** a large token-savings headline *on a fixture this size with a frontier model*.
  The token-savings claim's real evidence is on larger codebases (the Rust `EVAL.md` batches, and the
  per-question marginal `eval/token-cost`); this small Java fixture understates it. **We therefore do
  not put a Java token-savings number on the site** — the boundary and completeness panels are the
  Java-measured wins; the token panel stays scoped to the engine where the larger-codebase measurement
  lives.

## Threats / honesty

- One small fixture, one frontier model, N=8/arm. A weaker model (the Rust cross-tier study found
  Sonnet ~6× and dropping callers) or a much larger graph would widen the gap — but chasing a bigger
  number by switching the model post-hoc is exactly the over-claiming this project guards against, so
  the pre-registered Opus-class result stands as run.
- `subagent_tokens` is the harness per-trial total; input/output split not isolated. Reported with the
  tool-call and wall-clock numbers so no single instrument carries the claim.
