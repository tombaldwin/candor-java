# FROZEN pre-registration — the genuinely-frozen run

The first confirmatory slice (FINDINGS.md) was **disclosed adaptivity against a frozen classifier**, not a
clean pre-registration: the corpus was amended once for driver feasibility, and the verify oracle's recall
was widened (the Db mapping), both *after* the initial protocol commit. A referee rightly flagged that the
prose claimed a stricter discipline than the git history supported.

This file fixes that. It pins **everything** — manifest, classifier, **and** oracle binary — in one commit,
*before* the run. The commit that adds this file is the pre-registration timestamp; the run is executed
against exactly the artifact hashed below and its results reported afterwards, no fixes and no corpus/oracle
edits riding along.

## What is frozen (all as of this commit)

- **Engine binary (classifier + verify oracle):** `candor-java-0.23.1-all.jar`,
  **sha256 `bf572eb32db56ef419c8ad7d8f118cfe225f859320252c6969299434263e10d8`**, built at source commit
  `e2d93ed9f9fddd6e5e667cfcd8f0234d8da0f034`. `run_frozen.sh` **aborts** if the jar on the runner does not
  match this hash — so the "frozen binary" claim is machine-enforced, not asserted.
- **Corpus:** the 12 rows of `manifest.tsv` as of this commit — the complete set, *including* the repos that
  will build-fail or exercise no in-scope effect. Every one gets a disposition row (per PREREG's protocol);
  attrition is tabulated, not narrated.
- **Effect scope:** `--scope all` (Net/Fs/Exec/Env/Clock/Rand/Db).
- **Acceptance criterion:** unchanged from PREREG.md — zero *undisclosed* violations on executed paths;
  disclosed-partial is a pass; any violation is reported (per Blame), not repaired.

## Reporting discipline

`run_frozen.sh` (a thin wrapper over `run_corpus.sh` that first enforces the jar hash) writes
`results/FROZEN-SUMMARY.tsv` with **one row per manifest repo**, disposition ∈ {checked / disclosed-partial /
**violation** / no-in-scope-effect / build-failed / clone-failed / timeout}, plus the sound-complete vs
disclosed-partial split. Because the corpus and binary are frozen in *this* commit, the resulting numbers are
a genuine confirmatory datapoint — whatever they are, including a repeat of the R8 catch or a build-failure
tally that is simply reported.

## Result (run executed 2026-07-20, binary hash verified)

215 functions checked across the frozen manifest on **held-out** code; **86 sound-complete** (`D = ∅`, the
falsifiable frames); effect classes `Fs`/`Db`/`Clock`. **H held on every library that exercised effects
except one**, where the oracle **caught a false all-clear** — the R8 catch, reproduced under the frozen binary.

| repo | disposition | analyzed | checked | sound-complete | disclosed | violations |
|---|---|---|---|---|---|---|
| zt-zip | disclosed-partial | 251 | 110 | 25 | 85 | 0 |
| commons-dbutils | disclosed-partial | 195 | 39 | 25 | 14 | 0 |
| commons-lang3 | disclosed-partial | 1297 | 26 | 22 | 4 | 0 |
| commons-collections4 | **VIOLATION** | 2826 | 18 | 7 | 10 | **1** (R8) |
| commons-codec | disclosed-partial | 142 | 11 | 3 | 8 | 0 |
| commons-text | disclosed-partial | 187 | 10 | 4 | 6 | 0 |
| commons-imaging | disclosed-partial | 756 | 1 | 0 | 1 | 0 |
| commons-net | no-in-scope-effect | 803 | 0 | 0 | 0 | 0 |
| commons-pool2 | no-in-scope-effect | ? | 0 | 0 | 0 | ? |
| zt-exec | no-in-scope-effect | 145 | 0 | 0 | 0 | 0 |
| commons-cli | no-in-scope-effect | 230 | 0 | 0 | 0 | 0 |
| gson | build-failed | – | – | – | – | – |

**Totals: 215 checked, 86 sound-complete, 1 violation** (the R8 false all-clear, reported not fixed).

**Attrition, tabulated not hidden:** `gson` build-failed (multi-module `-pl` under the plain runner);
`commons-pool2` **hung** — its concurrency/timing suite spawns non-daemon threads that ignored the runner's
`timeout` SIGTERM, so it was SIGKILL'd manually and recorded `no-in-scope-effect` (partial JSON); the runner
now uses `timeout -s KILL` so this is reproducible without intervention (a harness fix — the frozen binary,
manifest, and scope are unchanged). `commons-net`/`zt-exec`/`commons-cli` exercised no in-scope effect
(mocked sockets / skipped process suite / pure parser) — valid fabrication-mirror rows.
