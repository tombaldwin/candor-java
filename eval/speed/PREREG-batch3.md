# Pre-registration — token/speed eval, batch 3: a real production app (the field case)

Committed **before any batch-3 trial runs** (see git history). Batch 1 was a synthetic floor (1.16×);
batch 2 (jsoup, 306 classes) lifted it to ~14× wall-clock / ~21× tool-calls. Batch 3 runs the same
protocol on **the field case** — a real, in-production Spring/Struts JVM application (the project's own
dogfood), the largest and most realistic target.

## Target

the field case production classes (`~/git/the field case/out/production/classes`, **2272 classes**) scanned by
candor-java → **9559 functions**, report at `/tmp/field_case_report.json`. Source for the control arm:
`~/git/the field case/src/main/java` (**1888 files**).

Question function: **`<the question function>(String, Job)`** — a **single-
signature `public static`** utility (no overload to conflate; concrete dispatch, so candor's caller
set is not subject to the CHA over-approximation that complicated the jsoup batch). candor computes
**42 transitive callers** (41 distinct `Class.method`; `batch3_truth.txt` / `batch3_truth_norm.txt`)
spread across the `actions.*` Struts layer. Tracing that by hand means searching 1888 source files;
one candor query returns it.

## Arms, metrics, sample size — identical to batch 2

- Read-only analysis; both arms share the one tree. **control** = "work from source at
  `~/git/the field case/src/main/java`"; **treatment** = `candor callers /tmp/field_case_report.json
  '<the question function>'`.
- **PRIMARY = cost**: `subagent_tokens`, `tool_uses`, `duration_ms`; median(control)/median(treatment).
- **SECONDARY = completeness**: overlap with candor's 41 distinct `Class.method`; any divergence
  adjudicated against source and reported (not auto-scored as a control error). Because the target is a
  concrete static method, less divergence is expected than jsoup.
- **N = 6 per arm** (12 trials), Opus-class both arms. Cost claim refuted if median(treatment tokens) ≥
  median(control tokens).

## Why this matters

the field case is the most honest test available: a large, real, in-production codebase the project's authors
actually maintain. If the cost gap holds here it is not a fixture artifact.
