# Pre-registration — frozen confirmatory corpus (RQ1)

This file, the manifest (`manifest.tsv`), and the runner (`run_corpus.sh`) are committed **before** the
run. Their git commit is the pre-registration timestamp. The point is to convert the paper's
*developmental* corpus evidence (find→fix→re-verify, where a classifier fix rides along with the run that
found it) into a **confirmatory** result: a fixed engine, a fixed corpus, one run, and whatever it reports
is the result — reported, not repaired.

## The discipline (what makes this confirmatory, not developmental)

1. **Frozen engine.** The engine is the candor-java `0.23.1` `-all.jar` (spec floor 0.23), pinned
   **by the sha256 of the binary itself** — `bf572eb32db56ef419c8ad7d8f118cfe225f859320252c6969299434263e10d8`,
   which `run_frozen.sh` verifies and **aborts on mismatch**. The matching `-all.jar` is also published as the
   **`v0.23.1` GitHub release asset** (tag `v0.23.1`, 2026-07-20), so the pin is a durable release artifact —
   but the *load-bearing* anchor is the sha256, not the tag (a tag can be moved; the hash cannot), which is
   why the runner gates on the hash. No classifier change is made during or because of this run. If the run surfaces
   a silent under-report, it is **recorded as a violation**, not fixed-then-rerun. Any fix is a *separate,
   later* effort with its own separate result; it does not amend this table.
2. **Pre-registered corpus.** The repositories and their refs are fixed in `manifest.tsv` before the run.
   Each ref is a release tag; the runner resolves it to a commit SHA on first clone and writes the resolved
   SHA into `results/<repo>.json` and `results/SHALOCK.tsv`, which lock the corpus for reproduction.
3. **Held out from development.** The corpus deliberately **excludes** every repository already used to
   *drive a fix* (`commons-io`, `commons-compress`, `commons-vfs2`, `commons-dbcp2`, `commons-exec`,
   `commons-configuration2`, `zip4j`, `jsoup`) — see `EXCLUDED.md`. Those are the developmental set; this
   is a fresh set the classifier has not been tuned against.
4. **Selection criterion is dynamic-feature density, not popularity.** A corpus with no reflection / DI /
   dynamic proxies / annotation-driven dispatch / service loading cannot falsify H (it has no (A3) surface).
   Every repo is chosen because it exercises at least one such mechanism; `manifest.tsv`'s `why` column
   names it. This over-samples the exact shapes where a false all-clear lives.

## Protocol (per repository, executed by `run_corpus.sh`)

1. `git clone --branch <ref> --depth 1 <url>`; record `git rev-parse HEAD` as the pinned SHA.
2. Build to bytecode (`build_cmd` — Maven/Gradle compile + test-compile).
3. **Static:** `candor-java <classes> --json report.json` → per-function `(S, D)`, `analyzed`, coverage.
4. **Dynamic:** `candor-java verify <classes> --run "<test_cmd>" --report report.json --json` — the
   transitive `-javaagent` records every effect while each analyzed frame is on the stack and
   `HonestyCheck` compares it to the static claim. Verdict ∈ {clean, disclosed-partial, **violation**,
   incomplete(fail-closed)}.
5. Record one row: `{repo, sha, analyzed, executed, coverage, unknown_rate, verdict, violations[],
   disposition}`. `disposition` ∈ {suite (real test suite ran in-process), exerciser (API driver — a lower
   coverage floor), build-failed, suite-forks (capture fragmented — reported, not a clean verdict)}.

## Two repo roles (a `checked=0` row is a result, not a gap)

The smoke run surfaced a selection distinction that the manifest now encodes in each repo's `role`:

- **H-test repos** perform effects *in their own functions* — they open sockets/files, spawn processes, or
  call `Instant.now()` themselves (`commons-net`, `commons-pool2`, `commons-dbutils`, `commons-email2`, …).
  Their suites drive `executedFunctionsChecked > 0`; they test the honesty invariant directly (does a
  `D=∅` function's runtime effect exceed `S`?).
- **Fabrication-control repos** only *transform caller-supplied* streams/objects (`commons-csv`,
  `commons-cli`, `commons-codec`, `commons-lang3`, `gson`, …). By candor's charge-at-creation stance the
  file/socket `open` is the *caller's*, so these libraries have no effect site of their own and correctly
  show `checked=0`. That is **not** a coverage failure — it is the *fabrication mirror*: `analyzed > 0`
  with `violations = 0` **and** a near-empty determined set is evidence the classifier did **not**
  over-report effects onto a pure transformer. A fabrication-control that suddenly showed a *concrete*
  effect it does not perform would fail this role.

Both roles are reported; the summary distinguishes them so "checked=0" is never read as "clean coverage."

## Acceptance criterion (stated before the run)

The confirmatory claim is **"zero *undisclosed* violations across the corpus, on executed paths"** — i.e.
every effect a run performs on an analyzed frame is either in that frame's determined set `S` or covered by
a disclosure in `D`. A **disclosed-partial** verdict (`Unknown` present) is a *pass*, by design. A
**violation** (a `D=∅` frame whose runtime effect exceeds `S`) is a **false all-clear** and falsifies the
claim; we would report the count and the named sites, per the Blame corollary, rather than suppress them.
Coverage is reported as-measured; a low `executed/analyzed` on a funnel-shaped library is a property of the
metric (§7.1), not a failure — but it *is* reported, so "zero violations" is never read as "full coverage."

## What this run is NOT

It is not whole-program soundness (Rice); it is H falsified on executed paths, scoped to the analyzed set,
with coverage disclosed. It is the JVM arm only (the reference engine, strongest oracle); the Rust
(`strace`), Node (`verify-core`), and Swift (`strace`) arms have their own pre-registered manifests as the
cross-ecosystem extension (`manifest.rust.tsv` etc., to be added the same way — committed before running).
