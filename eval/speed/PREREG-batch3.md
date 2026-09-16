# Pre-registration — token/speed eval, batch 3: a real production app

> **REDACTION NOTE — 2026-09-16.** The subject of this batch is a private, in-production client
> codebase. Its project name, package root, class/method names and source paths have been replaced
> with described placeholders. **No claim, threshold, count, arm definition or falsification bar in
> this document has been altered** — this pre-registration's value is that it was fixed before the
> trials ran, and an edit that changed what it predicted would destroy that. Only the subject's
> identity is removed, and the subject's SCALE figures are rounded (exact class/function/file
> counts joined with a public case study would re-identify the codebase). The original, with exact
> figures and real identifiers, was committed at `76adf7d`, before any trial.

Committed **before any batch-3 trial runs** (see git history). Batch 1 was a synthetic floor (1.16×);
batch 2 (jsoup, 306 classes) lifted it to ~14× wall-clock / ~21× tool-calls. Batch 3 runs the same
protocol on **batch 3** — a real, in-production Spring/Struts JVM application (the project's own
dogfood), the largest and most realistic target.

## Target

Production classes (the app's compiled output, **over 2,000 classes**) scanned by
candor-java → **~9,500 functions**, report written to a local path. Source for the control arm:
the app's `src/main/java` (**~1,900 files**).

Question function: **a single-signature `public static` utility method** (2-arg) — a **single-
signature `public static`** utility (no overload to conflate; concrete dispatch, so candor's caller
set is not subject to the CHA over-approximation that complicated the jsoup batch). candor computes
**42 transitive callers** (41 distinct `Class.method`; `batch3_truth.txt` / `batch3_truth_norm.txt`)
spread across the `actions.*` Struts layer. Tracing that by hand means searching ~1,900 source files;
one candor query returns it.

## Arms, metrics, sample size — identical to batch 2

- Read-only analysis; both arms share the one tree. **control** = "work from source at
  the app's `src/main/java`"; **treatment** = `candor callers <report>
  '<the question function>'`.
- **PRIMARY = cost**: `subagent_tokens`, `tool_uses`, `duration_ms`; median(control)/median(treatment).
- **SECONDARY = completeness**: overlap with candor's 41 distinct `Class.method`; any divergence
  adjudicated against source and reported (not auto-scored as a control error). Because the target is a
  concrete static method, less divergence is expected than jsoup.
- **N = 6 per arm** (12 trials), Opus-class both arms. Cost claim refuted if median(treatment tokens) ≥
  median(control tokens).

## Why this matters

Batch 3 is the most honest test available: a large, real, in-production codebase the project's authors
actually maintain. If the cost gap holds here it is not a fixture artifact.
