# Changelog

All notable changes to candor-java are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); candor-java is pre-1.0, so minor versions may
include behavioural changes (always in the soundness-increasing direction — the §4 trust contract).
**⚠ marks a verdict-affecting change** — a gate/guard/report that was green may read differently
after upgrading; review policies and regenerate baselines with the new build.

## [0.12.0] — 2026-07-14

### spec 0.12 — the gains `origin` rung (current floor)

candor-java now declares **spec `0.12`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
0.12 is a **tier-2 (pinned-tool-surface) rung** (candor-spec §"Conformance tiers"): no report-schema or
verdict change — a 0.11 report/verdict is byte-identical under 0.12 — but the **gains `origin` surface**
is now pinned contract: every `gains --json` `byFunction` entry carries `origin` —
`"existing"` (the function was in the baseline report, or is a node of a baseline callgraph sidecar —
shipped effect-free, now reaches Net: the supply-chain alarm), `"new"` (in neither, under a COMPLETE
graph — a feature, a different alarm), or `"unknown"` (existence undecidable — disclosed, never guessed).
Reports omit effect-free functions (SPEC §2), so existence is keyed on the baseline **callgraph
sidecars** — gains unions EVERY report the baseline locator matched, and a sidecar that is absent, or
that exists but fails to read/parse (partial graph), yields `unknown` rather than a false `new`: dropped
evidence must never downgrade "existing function gained an effect" to "new feature". The JSON keeps the
`baseline_version`/`engine_version` provenance fields and discloses an engine-version mismatch (a
"gained capability" may be the engine reclassifying). The human `fn\teffect` TSV is byte-stable.
Mirrors candor-rust `cmd_gains`; pinned four-way by conformance PART 5b (including the partial-sidecar
case). **⚠ the `spec` string changed** — a consumer pinning `spec == "0.11"` must accept `0.12`.

### Changed

- **⚠ Corrupt-report diagnostics for `gains`/`diff`/`containment` moved from stdout to stderr.** All
  three printed `cannot read baseline …` on STDOUT, polluting the `--json` stream (and leaving stderr
  empty). They now relay `load()`'s reason via stderr at exit 2 with stdout untouched, mirroring the
  scan-path relay. A consumer that parsed the diagnostic off stdout must read stderr; a stdout-JSON
  consumer now gets a clean channel (empty on failure) plus the exit code.

## [0.11.0] — 2026-07-13

### spec 0.11 — the surprising-reach opener rung

candor-java now declares **spec `0.11`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
0.11 is a **tier-2 (pinned-tool-surface) rung** (candor-spec §"Conformance tiers"): no report-schema or
verdict change — a 0.10 report/verdict is byte-identical under 0.11 — but the **surprising-reach surface**
is now pinned contract: the scan-time opener (the single most surprising transitive reach — a benign-named
function inheriting a boundary effect a few hops away — with a ready-to-run `candor path`), the
`candor tour [N]` verb (the top-N ranked list over a saved report, human + `--json`), the shared salience
floor (Clock/Log/Rand never surface as "surprising"; boundary Net/Exec/Db/Ipc rank above Fs/Env), and
test-code exclusion by the shared module-segment rule (never drops a production `test_connection`, always
drops `*Tests`). Deterministic — same lexicons, scoring, and tie-breaks as the Rust reference, so a
parallel fixture yields the same opener in every language; pinned four-way by conformance PARTs 4f–4j.
**⚠ the `spec` string changed** — a consumer pinning `spec == "0.10"` must accept `0.11`.

### Changed

- **⚠ A corrupt report fails loud, never "nothing hidden".** A bare junk array (`[1,2,3]` — valid JSON,
  wrong shape) used to be parsed as a legacy report, every entry dropped for a missing `fn`, and the empty
  result read as an all-clear at exit 0. `load()` now throws (→ exit 2) whenever a NON-EMPTY report array
  yields zero usable functions, and an unparseable report was already loud. A well-formed empty report
  (`[]` / `"functions": []`) stays a valid pure report at exit 0. Parity with rust/ts/swift; gated
  four-way by conformance PART 4k.
- **`tour` header honours the plural `packages` envelope this engine's own scan emits.** `tour` on a
  candor-java report printed the raw filename in the header because it read only the singular `package`
  key. The plural list now labels the header: one entry verbatim, several by their longest common dotted
  prefix, none shared → basename. Pinned by the conformance 4g addendum.
- **The coverage-ledger marker ships: `classifier doesn't cover`.** The de-κ rewording of the per-scan
  ledger line (documented under 0.10.0 below) landed after the v0.10.0 tag was cut, so this is the first
  release whose binary emits the new marker. Scan-tooling grepping the old `κ doesn't know` line must
  switch.

## [0.10.0] — 2026-07-12

### spec 0.10 — the §3.3.1 canonical query grammar

candor-java now declares **spec `0.10`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
The family floor ratchets to 0.10 with the landing of the candor-spec **§3.3.1 canonical query grammar**:
report discovery + the `--report`, `--json`, and `--policy` flags are the pinned invocation surface; the
old positional report/policy forms are **deprecated-but-accepted** (still parsed, no behaviour change).
0.10 is a **tier-2 (pinned-tool-surface) rung** (candor-spec §"Conformance tiers"): no report-schema or
verdict change — a 0.9 report/verdict is byte-identical under 0.10 — but the query grammar is now the
pinned §3.3.1 contract, required of a 0.10-conformant engine and cross-checked by conformance **PART 17**.
Reference engine: candor-java leads the rung. **⚠ the `spec` string changed** — a consumer pinning
`spec == "0.9"` must accept `0.10`; report/verdict bytes are otherwise unchanged.

### Changed

- **Coverage-ledger disclosure reworded — no more Greek `κ` in user/agent-facing output.** The per-scan
  stderr line that names uncovered external packages now reads
  `candor-java: candor's classifier doesn't cover N packages this code calls into — their effects are
  INVISIBLE to the scan (absent from the report, NOT a claim they're pure): …`. The shared machine marker
  is now **`classifier doesn't cover`** (the other engines emit the same marker); the old `κ doesn't know`
  wording is gone from stderr, README, and AGENTS.md. `κ` remains only as internal maintainer vocabulary
  (code identifiers, `soundness/kappa_probe.py`, and this changelog's history). No report/verdict bytes
  change — scan-tooling that grepped the old line must switch to the new marker.

## [0.9.0] — 2026-07-11

### spec 0.9 — the remedial-loop rung

candor-java now declares **spec `0.9`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
0.9 is a **tier-2 (pinned-tool-surface) rung** (candor-spec §"Conformance tiers"): no report-schema or
verdict change — a 0.8 report/verdict is byte-identical under 0.9 — but the remedial loop (`fix`/`fix-gate`,
`unverified`, and the gate auto-disclosure below) is now the pinned §3.1/§3.3 contract, required of a
0.9-conformant engine. Reference engine: candor-java leads the rung. **⚠ the `spec` string changed** —
a consumer pinning `spec == "0.8"` must accept `0.9`; report/verdict bytes are otherwise unchanged.

### ✨ Gate scans auto-disclose the provable-purity gap (no need to know to run `unverified`)

A policy scan now emits the `unverified` disclosure automatically as a stderr note: after the gate verdict,
any method in a `pure`/`deny <E>` scope that PASSES but is `Unknown` (an unresolvable call — the classic
fn/closure-injected "port", e.g. a `LongSupplier` domain) is named, with the `deny <E> Unknown <scope>` upgrade
that makes the layer PROVABLY clean. Closes the discovery gap — an author learns their "pure" layer isn't
*provably* pure without knowing the `unverified` command exists. **Advisory only**: a note, never a violation,
so the exit code, gate verdict, and `--gate-json` are untouched. Emitted from `Policy.checkPolicy` after the
AS-EFF-006 loop. Mirrors candor-scan/ts/swift (four-engine parity). Existing gate/smoke tests unchanged.
The gate note and `unverified` share ONE predicate (`Policy.unverifiedHoleRule` + `Policy.ruleUpgrade`) — a
single definition of a hole, so the two disclosure paths cannot drift (PART 12d pins it).

## [0.8.14] — 2026-07-11

### ✨ `unverified` — the provable-purity disclosure ported here (four-engine parity)

Ports candor-query's `unverified` (candor-query 0.8.10): a `pure`/`deny <E>` layer PASSES a function that has
no such effect — but if that function is `Unknown` (an unresolvable call, e.g. a fn/closure-injected port), the
pass is UNVERIFIED. Discloses each such function in a governed layer + the `deny <E> Unknown <scope>` upgrade
that makes the layer PROVABLY clean. `--strict` → exit 1. JSON `{ok, unverified[]}`. Byte-for-byte the same
disclosure as the other engines, pinned four-way by conformance PART 12c. Read-only; gate verdict untouched.

## [0.8.13] — 2026-07-11

### `fix`: the no-clean-hoist advice names the port purity hierarchy (soundness investigation)

Following the fix-loop eval's finding that models reach for a TRAIT port (which candor's gate rejects — it
resolves the dispatch back to the effect-performing impl), an empirical investigation (eval/fixloop/DISPATCH-
NOTE.md) confirmed candor's behaviour is CORRECT (accepting a trait port would silently under-report the effect
the layer reaches at runtime — the cardinal sin), and pinned the three fix shapes' distinct classifications:
trait dispatch → the effect (resolved); fn/closure value → Unknown; plain data → pure. The no-clean-hoist
advice now names the hierarchy: (a) hoist + thread DATA = provably pure (recommended); (b) fn/closure injection
clears `deny E` but leaves an Unknown hole a `deny E Unknown` policy would flag; (c) a trait port doesn't clear
the gate. Text-only; no gate change (the resolution is sound). A candor-scan test guards the classification.

## [0.8.12] — 2026-07-11

### `fix`: no-clean-hoist advice rewritten (eval-driven — the remedy was steering agents wrong)

The fix-loop eval (candor-rust/eval/fixloop) measured that on the no-clean-hoist case candor's remedy did NOT
help and HURT weaker models (fable 60% vs control 100%): agents followed the literal "introduce a PORT (a
trait)" advice and wrote a trait port, which candor's OWN gate then rejected — it resolves the trait dispatch
back to the effect-performing impl, so the layer still violates. And "NO CLEAN HOIST" was computed on the
existing graph, so it wrongly declared impossible the simplest valid fix (add a thin composition root above
the layer). The advice now (a) LEADS with the composition-root hoist, and (b) recommends fn/closure injection
with candor's trait-dispatch caveat ("a trait port whose impl performs the effect still trips the gate").
Text-only (the cut/JSON is unchanged; conformance PART 12b still MATCHES). Re-running the eval: the fixed
remedy recovers the treatment arm to 100% across all four models (fable 60% → 100%). See eval/fixloop/RESULTS.md.

## [0.8.11] — 2026-07-11

### `fix`: the sandwiched-layer case is now handled (last correctness gap closed)

When an ALLOWED layer is CALLED BY a forbidden one (`D1 → A → D2 → site`, deny on the D layer), hoisting the
effect to the nearest allowed frontier `A` would leave `D1` still inheriting it. `cleanHoist` is now `false`
in that case (a forbidden fn calls into the frontier), with a message that names the sandwich and offers the
port/relax options — instead of a misleading "hoist to A". Detected in the same upward climb that gathers
`hoistHigher`; identical across all four engines, pinned four-way by conformance PART 12b's sandwiched
sub-check. Read-only; additive.

## [0.8.10] — 2026-07-11

### `fix`: cross-engine parity fixes (from a high-effort /code-review)

- **Start resolution** now prefers a name match that PERFORMS the effect (so `fix save Net` resolves to the
  effectful `Repo.save`, not a pure `Cache.save`) — matching the other engines; previously a false "nothing
  to hoist" all-clear was possible.
- **Inline-`calls` fallback**: when the `.callgraph.json` sidecar is absent (stdout report, hand-authored,
  cleaned), `fix`/`fix-gate` now fall back to the report entries' inline `calls` (via the new `fixGraph`
  helper) instead of computing over an empty graph and emitting a degenerate "no clean hoist" — matching
  candor-query/swift and the sibling `callers` command.
- **`byName`-absent caller** in the up-walk is now skipped (a pure callgraph-only node never routes the
  effect), matching candor-swift.

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
