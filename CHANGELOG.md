# Changelog

All notable changes to candor-java are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); candor-java is pre-1.0, so minor versions may
include behavioural changes (always in the soundness-increasing direction — the §4 trust contract).
**⚠ marks a verdict-affecting change** — a gate/guard/report that was green may read differently
after upgrading; review policies and regenerate baselines with the new build.

## [0.8.9] — 2026-07-11

### `fix`/`fix-gate`: the higher-hoist trade-off (FIX-SPEC's last refinement)

Each remedy gains `hoistHigher` beside `hoistTo`: the allowed-layer transitive callers of the minimal
frontier that also route the effect — the places you could originate it *further up*. The text surfaces the
trade-off (hoisting higher keeps the frontier pure too, threading through more signatures). `hoistTo` (the
minimal fix) is unchanged. Byte-for-byte identical to candor-query/ts/swift, pinned by conformance PART 12b.
Read-only, additive; no report/verdict change.

## [0.8.8] — 2026-07-11

### ✨ `fix` / `fix-gate` — the boundary fix reaches the JVM reference engine (FIX-SPEC P3)

The remedial capability shipped in candor-query (candor fix) now has a native candor-java port — the
reference engine, where the layer model is richest. When a method performs an effect its architecture layer
forbids, `fix <report> <method> <Effect> [policy]` computes the *architectural remedy*: the direct call site
to hoist, the forbidden-layer methods that become pure and thread the value, and the nearest allowed-layer
caller to perform the effect — plus the policy-relax alternative. `fix-gate <report> [policy]` does it for
every deny/`pure` (AS-EFF-006) crossing at once, collapsing the inheritors of one root cause to a single
plan. Text or `--json`. Byte-for-byte the same remedy shape as candor-query, verified on real JVM bytecode.

The cut is **site-anchored**: it walks *up* from the direct effect site through the denied layer, so the
pure span is the same regardless of which inheriting method triggered it (root-independent) — the two domain
methods of a crossing collapse to one identical remedy. `integrations/claude-code/candor-review.sh` (the JVM
edit-time loop) now folds the plan into the block message: on an AS-EFF gate failure with a policy set, it
calls `$CANDOR fix-gate` and appends the remedy under the finding, so the agent self-corrects toward the
right architecture. Read-only, no report-byte or verdict change; advisory (the gate re-scan stays the ground
truth). Six tests in `FixGateTest` pin the collapse, the single-method cut, the clean case, and the
fail-loud policy contracts.

## [0.8.7] — 2026-07-10

Documentation-and-identity release; no report-byte or verdict changes.

- The embedded agent contract (AGENTS.md, served by `--agents`) now documents `--gate-json`,
  `.candor/config`, the $-scope-segment rule, pure-vs-Unknown, and the diff/gains exit contract;
  version examples became placeholders so they cannot drift.
- README: candor-java correctly self-identifies as the family's reference engine (the header
  wrongly deferred to a "Rust reference"); install block hoisted to the first screen; smoke gains
  five identity drift-gates (incl. a ban on the string "Rust reference").
- Tests renamed by feature (KappaBatch24/28-31 → Hibernate/LegacyEnterprise/Utility/Jackson/LongTail
  — provenance kept in javadocs); the fabrication probe's header follows the family cardinal-sin
  ruling (the silent under-report owns the term).

## [0.8.6] — 2026-07-09

- ⚠ **Policy scope segments now split on the `$` nested-type boundary** (the family §6.2 ruling,
  matching the query name ladder): `deny Net client` / `forbid app -> repo` now bite JVM nested
  classes (`Outer$client`). A scope name that previously matched only packages may now match
  nested types — review policies on upgrade.
- ⚠ **`CANDOR_STRICT` gate fix (AS-EFF-001/002/003)**: `checkConformance` lacked SPEC §6's
  program-entry-point exemption, so AS-EFF-001 fired on the composition root (`main` legitimately
  mints the capability bundle). Found by the first-ever coverage measurement — the gate had zero
  test coverage in any harness; it now has 12 JUnit pins + a smoke section.
- ⚠ **`diff`/`gains` exit parity**: `diff` exits 1 on a gained effect when baseline/engine
  producing versions match (a mismatch discloses and exits 0), matching candor-ts.
- **Structural — byte-identical** (996-file corpus-proven, *not* verdict-affecting): `analyze()`
  decomposed into per-instruction-kind handlers with explicit context threading; rule tables in
  `Rules.java`; one `TestCompiler`; review-round test files renamed by feature; dead code removed.
- Coverage-wave pins: taint at control-flow joins, ~500 classifier table rows with
  anti-fabrication twins, `--help`/`--version`, stdout report purity, hostile dep-report shapes.

## [0.8.5] — 2026-07-09

- ⚠ **Fail-closed sweep** — previously-green failure paths now exit 2 (intentional): an unwritable
  `--gate-json` verdict path fails the run; a `CANDOR_DEPS` entry naming no readable file, an
  unwalkable deps dir, or an unparseable dep report fails the run (was: every call into the dep
  silently read pure); an unwritable `--json` report path prints one diagnostic line and exits 2.
- **Performance**: the classifier's single ~27KB method exceeded HotSpot's JIT limit, so the
  hottest path in every scan ran interpreted; now a per-package dispatch — verified
  **byte-identical** by a 19.5M-triple differential oracle plus a 330-jar corpus; ~16% faster
  full-corpus scans.
- **Spec §2.1 / §3.4 parity**: `diff`/`gains` disclose a producing-version mismatch
  (`baseline_version`/`engine_version` + a stderr warning) and still answer; relative
  `.candor/config` values resolve against the config's home directory, never the CWD; the CWD
  discovery fallback is gone.
- Tests/CI: `--parallel` smoke coverage; report/verdict schema-shape tests; the kappa_libs +
  mutation probes run weekly (the mutation probe had rotted to 3/14 — re-anchored, 14/14).
  Conformance: all 16 cross-engine parts MATCH.

## [0.8.4] — 2026-07-08

- ⚠ **Soundness patch — six cardinal-sin regressions in 0.8.3's κ batches 28–31** (found by a
  high-effort code review; 0.8.3 users should upgrade). Fabrications removed (false effect on pure
  code): AWS `AmazonS3URI` accessors, Redisson pure members, commons-io pure path helpers, jjwt
  no-arg `parser()` factories, `StopWatch.create()`. Silent-pure removed: the blanket
  `com.amazonaws` coverage grant silenced unmodeled v1 facades (`DynamoDBMapper.save` read pure) —
  unmodeled AWS/commons-io members now disclose `invisible`.
- ⚠ **Baseline guard fail-closed**: a corrupt/unparseable baseline now fails the run (exit 2)
  instead of silently disabling the guard.
- Every fix has an anti-fabrication test twin; jsoup/gson reports byte-identical to 0.8.3 (the
  carve-outs only move the buggy members).

Older releases: see [GitHub releases](https://github.com/tombaldwin/candor-java/releases).
