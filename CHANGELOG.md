# Changelog

All notable changes to candor-java are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); candor-java is pre-1.0, so minor versions may
include behavioural changes (always in the soundness-increasing direction — the §4 trust contract).
**⚠ marks a verdict-affecting change** — a gate/guard/report that was green may read differently
after upgrading; review policies and regenerate baselines with the new build.

## Unreleased

## [0.28.2] — 2026-08-15

_A cardinal-sin fix. 0.28.1's body-less-declaration pass reopened, in two shapes, the hole it was
written to close — both found by a max-effort review of that patch, both live on npm and crates.io
until this release. The spec floor is unchanged at 0.28._

- **The self-gate's exit-2 branch is gated on the Exec verdict.** It fired before the subprocess check
  was reported, so an ESTABLISHED violation was announced as "could not evaluate" and the FAILED line
  below it was unreachable — the could-not-evaluate collapse this release fixed, inverted.

- **Version-aligned only, no functional change.** The cardinal-sin fix this release carries is in
  candor-ts; `release-preflight` [4] requires every engine's build version to agree, so this arm
  moves with the family. The spec floor is unchanged at 0.28.

## [0.28.1] — 2026-08-15

_Post-release review fixes. 0.28.0 shipped, then a high-effort review of that work found
defects in it — three of them a defect of the same class as the fix that introduced them. The
spec floor is UNCHANGED at 0.28: no contract moved, so this is a build-version patch._


- **jbang catalog pinned to v0.28.1** — it names a published artifact, so it moves after the release exists.
- **The README-version gate fired on the very next release, which is the point of it.** `release-stage.sh` bumped `build.gradle.kts` to 0.28.1 and left `## Status` at 0.28.0 — the same
  drift that reached `v0.19.x`, caught this time in CI instead of nine releases later. The umbrella's
  `release-stage.sh` now stages that line too, so the gate is the backstop rather than the process.

- **Review follow-ups on the self-gate.** Five, none of them green-when-it-should-be-red, all of them
  the gate misreporting or resolving the wrong thing: the jar was picked **newest-by-mtime** across
  every version in `build/libs`, so a refreshed older `-all.jar` would have run a STALE ANALYZER over
  fresh classes (now named from the project version); **exit 2 was reported as a violation** and
  collapsed to exit 1, when it is the ⟨0.21⟩ *could not evaluate* verdict and this codebase treats that
  distinction as load-bearing (preserved as 2 — and the same collapse was in candor-ts's and
  candor-swift's self-gates, fixed there too); the advisory trim `^    \`` also swallowed the ⟨0.23⟩
  **`interfaceUnion` rows**, which name synthetic entries that MATCHED a policy rule, so a chained-dep
  dispatch surface reaching a denied effect reached CI as a bare count; a declared method that gains an
  **overload** becomes parameter-qualified and was reported as STALE with the opposite remedy; and the
  workflow's block comment still described the excluded-package arrangement this rework deleted.

- **`## Status` in the README said `v0.19.x`** — nine releases stale, because every bump edited the
  spec number on that exact line and nothing gated the version half. Now `v0.28.0`, and `test/smoke.sh`
  derives the expected version from `build.gradle.kts` so it cannot rot again (falsified).

## [0.28.0] — 2026-08-14

- **jbang catalog pinned to v0.28.0** — the `script-ref` names a published release artifact, so it moves
  after the release exists, never with the version bump.

- **Self-gate: the two subprocess METHODS are declared, not the package they live in.** The old half (1)
  proved the analyzer core clean by copying `build/classes` and DELETING `io/poly/candor/verify` — carving
  the Exec exemption out a whole PACKAGE at a time, so every class in it sat outside the Exec gate while
  half (2) asked only about Net/Db/Ipc. Now the whole tool is scanned with nothing excluded under
  `deny Net Db Ipc`, plus an assertion that the Exec methods are exactly `Candor.main` and
  `verify.VerifyCli.main`. A new subprocess anywhere fails, and so does a declared entry that STOPS
  performing Exec — a stale exemption is a gate that has quietly stopped asserting. The policy string got
  weaker and the gate got stronger: a policy is only as strong as the scope it is evaluated over.
- **AGENTS.md points at the umbrella**, with the jar's embedded copy re-synced in the same commit.

- **⟨0.28⟩ the third row is not the first row: `noManifest`** (SPEC §2, *"AND THE THIRD ROW IS NOT THE
  FIRST ROW — measured, two engines report it as one"*). §2's ⟨0.24⟩ table has THREE rows, and this
  engine filed the third under the first's name. MEASURED on the jar built before this change, over
  `{"candor":…,"functions":[]}` with **no `analyzed` key at all** (a pre-⟨0.21⟩ producer): `where`,
  `map`, `blindspots`, `reachable`, `tour`, `containment`, `show`, `unverified`, `fix-gate` and `gains`
  all emitted `judgedNothing: ["<path>"]`, and the `gate --report` note said the report *"declare[s]
  `analyzed.count: 0`, i.e. they JUDGED NOTHING"*. **The report declares nothing.** The hedge is the
  right DIRECTION — row 3's own instruction is *no manifest, no claim* — but the disclosure was false,
  and this family rates a false disclosure worse than a missing one (§3.4's `net-partner` finding: an
  engine reported "ignoring unknown config key" *while honouring it*). It was also a hole in ⟨0.28⟩'s
  own pin, which defines `judgedNothing` as *reports declaring `analyzed.count: 0`*: filing row 3 there
  made one key mean two things and lost the distinction the table exists to draw.

  Row 3 now carries its own SPEC-pinned key, `noManifest: ["<report path>", …]`, everywhere the caveat
  rides — `ReportCompleteness.writeJson` (so every descriptive verb, the Rung A caveat document, the
  advisory verbs and `gains`' `baselineNoManifest` get it from one place), its own clause in the
  `⚠ INCOMPLETE` banner, its own per-report line, its own `advisoryJudgedNothingNote` paragraph with
  `ok` still withdrawn, and its own `gate --report` NOTE. It raises `incomplete` like its siblings, is
  omitted when empty, and — like `judgedNothing` — reaches `mustHedge()` and **not** `incomplete()`, so
  no exit code moves. The stopgap wording that made the old sentence merely *truthful*
  (*"`analyzed.count: 0`, or no manifest at all"*) is gone: row 1's note is back to the precise claim it
  can support, and row 3 has its own.

  **THE SPLIT ADDS A PREDICATE, IT DOES NOT INVERT ONE.** `Loader.claimsToHaveJudgedNothing` is not only
  a disclosure predicate: `Loader.loadCrossDeps` reads it to decide COVERAGE (`depCoveredPkgs`, the set
  that silences the κ ledger's `invisible` hedge) and `gate --report` reads it through
  `Query.Envelope`. An absent manifest must keep granting NONE — that is row 3's own instruction — so
  making it answer `false` for a manifest-less report to fix the LABEL would have turned every
  pre-⟨0.21⟩ report into a covered one: a silent under-report introduced by a disclosure fix. A second,
  disclosure-only `Loader.hasNoManifest` chooses the KEY for a hedge that was already happening, and a
  test asserts the coverage predicate is unmoved (the mutant that inverts it fails there, in
  `StaleDepTrustTest`'s shape table, and in the legacy-bare-array row).

  **BOTH CONTROLS ARE ASSERTED.** Row 1 (`analyzed.count: 0`) keeps `judgedNothing` and never becomes
  `noManifest` — the split goes both ways or it is a rename. Row 2 (`count: 7`, `functions: []`) is a
  legitimate all-pure claim §2 rule 3 requires a consumer to BELIEVE and MUST NOT hedge; a fix that
  hedges all three has disabled the feature rather than implemented the rule (over 1997 JVM dependency
  jars, a predicate keyed on `functions` being empty withdraws 104 real claims to catch 6). Four new
  JUnit tests and seven new `test/smoke.sh` rows; measured before/after across ten verb invocations per
  row, the row-2, manifest-less-with-entries and intact-report output is **byte-identical**, and row 1
  changes only in the tightened prose.

- **⟨0.28⟩ the BASELINE locator's expansion is guarded on the scan side, and the report sink's OWN
  sidecar writes are part of the sink** (SPEC §3.3.1 (3), *"AND AN INPUT LOCATOR NAMES A SET — COMPARE
  THE EXPANSION, NEVER THE TOKEN"* / *"THE SIDECARS EXPAND TOO"*). Two measured defects, both live at
  HEAD on 2026-08-12. (1) `checkBaseline` answers the ⟨0.16⟩ pure→effectful ratchet FROM the baseline's
  `.callgraph.json` sidecar while `runInputs` registered only the token the operator typed — so
  `CANDOR_BASELINE=base.json candor cls --json base.callgraph.json` wrote the report OVER the ratchet's
  sidecar (98 → 1180 bytes), read the wreckage back and blamed it ("corrupt/unreadable") at exit 2;
  the `.candor/config` `baseline` spelling destroyed it identically through `--gate-json` (98 → 326,
  the armed verdict where the callgraph belongs). `runInputs` now registers each report-shaped input
  (baseline and deps, both spellings) with its on-disk §2.2 sidecars via `Loader.reportSidecarSegments`
  — the `gate` exclusion rides along, so `<stem>.gate.json` stays a permitted sink. (2) A file-mode
  `--json <stem>` also WRITES `<stem>.callgraph.json`/`<stem>.hierarchy.json`, and only the token was
  compared — so `CANDOR_BASELINE=base.json … --json base` replaced the ratchet's sidecar with the
  CURRENT call graph at a success exit (the exact defect candor-scan fixed as `baseline_artifact_files`,
  one spelling over): the next run gates against a baseline half it never produced.
  `refuseJsonOverAnyInput` now compares the sink's full write set. Four `SinkArmingIntegrityTest` rows
  pin it on bytes (three fail at the parent commit; the drifted-code fixture exists because an
  identical tree made the byte assertion vacuous — measured on this test's first draft).

- **⟨0.28⟩ `containment` emits `layerPrefix` when, and only when, a prefix was actually collapsed**
  (SPEC §6.1, *"`layerPrefix` IS THE ONE THAT MUST CHANGE"*). The key was emitted UNCONDITIONALLY —
  `"layerPrefix": ""` when nothing was collapsed — while the other three engines emit no such key at
  all: a divergence a consumer sees, and the present-but-always-empty shape `field_audit.py`'s header
  documents. Absence now means no prefix was collapsed (§2's omit-rather-than-guess); the field still
  carries the collapsed root verbatim whenever there is one, where it is load-bearing (`owner` and
  `placement` are layer names relative to it). A run that collapses a prefix is byte-identical to
  before. Pinned by conformance PART 45 (both directions, plus the answered-document control) and
  `LayerPrefixConditionalTest`.

- **⟨0.28⟩ `unverified`/`fix-gate` answer a judged-nothing report with the pinned caveat, not
  `{"ok": true}`** (SPEC §2, *"AND HERE IS WHAT THE TRAVELLING CAVEAT IS CALLED"*). Measured via
  candor-spec's key-shape harvest over a ⟨0.21⟩ Row-1 report (`functions: []`, `analyzed.count: 0` —
  the facade artifact): both verbs answered `ok: true` at exit 0, stdout `"… PROVABLY clean ✓"` / `"no
  … crossings ✓"`, while this engine's own `where`/`map`/`blindspots` hedged over the same bytes and
  rust/ts/swift all withdraw `ok` there. `advisoryAnswer` now reads the whole `ReportCompleteness`
  (count-0 and unreadable-sibling causes included): `ok` is omitted, `incomplete: true` +
  `judgedNothing` (an ARRAY of report paths) ride the document through the same `writeJson` the
  descriptive verbs use, the ✓ ticks are withdrawn on the human channel, and `whatif` takes the same
  arm. Exit codes are UNCHANGED (⟨0.24⟩: count-0 is *"a disclosure, not an exit code"*) — byte-verified
  old-jar-vs-new over intact and armed states in every mode; an intact report's output is
  byte-identical. Also: a locator-rule-2 path that does not exist on disk is the pre-scan case, not an
  `unreadable` report — absent input no longer hedges an answer the caller already fails loudly on.

- **⟨0.28⟩ `gate --report`: the input guard covers what the locator EXPANDS to** (SPEC §3.3.1 (3),
  *"AND AN INPUT LOCATOR NAMES A SET — COMPARE THE EXPANSION, NEVER THE TOKEN"*). The guard compared
  `--gate-json` against the raw `--report` token while the loader reads the token's expansion, so
  `gate --report r --policy P --gate-json r.app.jvm.json` destroyed the operator's report at exit 2 —
  measured, with the diagnostic blaming the report ("object has no 'functions' array") for the
  corruption the run inflicted — and the no-`--report` discovery spelling destroyed the discovered
  `.candor/` report identically. The §2.2 sidecars are covered too: `--gate-json <the callgraph>` wrote
  a REAL verdict over the pair's other half at a success exit. `Query.gateReportInputFiles` enumerates
  the exact files by the loader's own rule (`locatorReportSet` + `Loader.reportSidecarSegments`), kept
  adjacent so guard and loader cannot drift; `<stem>.gate.json` stays a permitted sink (the
  beside-the-report verdict layout), pinned by the control test.

- **⟨0.28⟩ `gains` carries the ⟨0.21⟩ completeness manifest too, on BOTH SIDES** (SPEC §2, *"AND THE SAME
  MUST CARRIES THE ⟨0.21⟩ MANIFEST, WHICH IS THE STRONGER CAVEAT AND THE ONE THAT DOES NOT TRAVEL"*). This
  verb has carried the current report's `coverage` ledger since ⟨0.15⟩, for the reason §2 gives — a *no
  gains* over an uncovered dep reads clean with false confidence. Measured, the same verb, on the same
  report, in the same output, dropped `unanalyzed`: `coverage.uncovered` says *I could not see into this
  dependency*, `unanalyzed` says *I could not read this file of your own code*, and `analyzed.count: 0`
  says *I judged nothing at all*. The mechanism was already here and pointed at the weaker field, so this
  reuses the one completeness reader the descriptive and advisory verbs share. **Both sides, disclosed
  separately**, because a gains answer rests on two reports that fail differently: an incomplete CURRENT
  (`incomplete` + `unanalyzed`/`judgedNothing`) means the `gained` set may be **short** — new capability
  the reader is not being told about; an incomplete BASELINE (`baselineIncomplete` +
  `baselineUnanalyzed`/`baselineJudgedNothing`) means the comparison **floor** is soft, so the
  existing-vs-new `origin` split this verb exists for is unreliable. One combined flag would say
  *something here is incomplete* and leave a supply-chain reviewer unable to act; the prefixed names are
  candor-rust's (fe5d831), and the shape mirrors the one already used for the weaker caveat (`coverage`
  for the current, `coverageDelta` for the difference). **JSON-only and verdict-preserving**: the human
  `fn\teffect` TSV is a pinned consumer surface and stays byte-stable, exit codes do not move anywhere
  (`--strict` still keys on the gained set alone), and two INTACT reports produce byte-identical output —
  the control that caught candor-rust's BTreeMap re-sort and this engine's own `Map.of` salting. Closes
  the last open cell of the §2 re-disclosure MUST here (conformance PART 39 (ii): candor-java SKIP → PASS).
- **⚠ ⟨0.28⟩ the DESCRIPTIVE query verbs carry the ⟨0.21⟩ completeness manifest too** (SPEC §2, which
  widens the re-disclosure MUST from *"a verb whose VERDICT could change"* to **"any verb whose output
  could be read as a negative finding about the code — a verdict, an empty result set, or a zero
  count"**). The engine's completeness reader was written for the narrow reading and only the
  `ok`-answering advisory verbs were ever sent back for it. Measured on the previous build, over a report
  declaring `analyzed.count: 0` and a non-empty `unanalyzed` — the standard post-failure artifact since
  the arming rung, i.e. what is on disk after a failed run — `blindspots` answered
  `{"sources":[],"totalUnknown":0}`, `map` `{}`, `where Fs` `{"directly":[],"inherited":[]}`, `reachable`
  `{"entryPoints":0,"effects":{}}`, `containment` `{"contained":[],"ambient":{}}` and `tour`
  `{"reaches":[]}`, all at exit 0 with no hedge on either channel: *no blind spots*, out of a report whose
  own manifest names a file it could not read. A consumer could not tell *nobody performs `Fs`* from
  *nothing was examined*. All six now carry `incomplete: true` + the manifest on `--json` and an
  `⚠ INCOMPLETE` note above the answer on stdout, and the reassuring sentences that ARE the all-clear in
  English ("no blind spots", "nothing hidden", "no regressions ✓") are withdrawn with them. **Exit codes
  are unchanged everywhere** — this is a caveat, not a refusal (verified over 440 (state × verb × mode)
  cells). Two additions make it work: `analyzed.count: 0` is now a SECOND trigger beside `unanalyzed` (a
  report that judged nothing carries no manifest — there is no unread FILE to name — so the reader saw a
  complete report and every verb answered over it just the same), decided by the SHARED
  `Loader.claimsToHaveJudgedNothing` that the chained-dep join and now the `gate --report` route both use;
  and it reaches the two DISCLOSURE channels only — ⟨0.24⟩ ruled count-0 explicitly the other way for exit
  codes, so `unverified --strict` / `fix-gate --strict` are untouched over a facade report, and the note
  says so rather than sending the reader to a CI job that will pass. `containment <baseline>` folds in the
  BASELINE's manifest as well: its answer is a difference, unsound if either side is partial and in
  opposite directions (a missed leak vs a fabricated one, at exit 1). **`show` is deliberately NOT
  hedged** — its document is a top-level JSON array with nowhere to carry a key, and fixing only its human
  channel would move the false all-clear rather than remove it; it needs a shape ruling.
- **`containment <baseline> --json` has a stable key order.** It was built with `Map.of`, whose iteration
  order is salted per JVM: eight runs of the identical command gave `{cleanups,leaks}` six times and
  `{leaks,cleanups}` twice. A machine document whose key order changes between runs cannot be diffed. Now
  `leaks` then `cleanups`, matching candor-rust.
- **⚠ ⟨0.28⟩ `callers` discloses unanswerability in the MACHINE channel, not just in stdout prose**
  (SPEC §3.3.1). Over an armed pair — report armed, sidecars deleted by the rung below — `callers <f>
  --json` printed `{}` at exit 0 while the human arm correctly said "no call graph in the report".
  Human-fine, machine-silent, which is the split that makes a defect a cardinal sin. A consumer reading
  `direct`, or defaulting it (the fail-open idiom ⟨0.24⟩ names on every key in this format), was told
  NOBODY CALLS this function: a blast radius of "safe to edit" over a pair whose honest answer is "this
  run judged nothing". The sidecar rung did not create the hole — an absent sidecar has always answered
  this way — it aimed traffic at it, by making no-sidecar the standard state after a failed run. Both
  channels now fail closed: the document carries `{"of": […], "unanswerable": "<why>"}` **and** the exit
  is 2. §3.3.1 permits either, but each alone leaves a naive reader exposed — the key alone still lets
  `d.get("direct", [])` read as a determined negative, and the exit alone leaves a JSON consumer holding
  `{}`. **Only "no graph at all" is unanswerable**: a function with genuinely no callers over a complete
  graph still answers `direct: []` at exit 0 (a determined negative — withdrawing it would be the mirror
  defect), and a name absent from a real graph is still the `no function matching` error at exit 2. The
  MCP surface inherits it: `run_query` sets `isError` on exit ≥ 2. Conformance PART 37 (e).
- **⚠ ⟨0.28⟩ the §2.2 sidecars go with the armed report — deleted, not emptied** (SPEC §3.3.1). Arming a
  `--json <file>` report left `<stem>.callgraph.json` and `<stem>.hierarchy.json` live beside it: a pair
  that contradicts itself, with no provenance on the sidecar to arbitrate. Not decorative here, because
  `callers`/`whatif`/`rewire` are answered FROM the callgraph — a currently-pure function is absent from
  the report by §2 rule 3, so only the sidecar records it. Measured: baseline `f` pure, reached by `g` and
  `main`; the new version gives `f` an effect and adds a caller `h`; the run exits 2 on an unknown flag —
  and `callers f` answered *"reached by 2 function(s) (the blast radius if it gained an effect): g, main"*,
  exit 0, with `h` missing. Confident, labelled the blast radius, and wrong; an agent reads it as
  safe-to-edit. It now discloses "no call graph in the report", and a recovering run answers all three.
  Deleted rather than `{}` because ⟨0.24⟩ has already ruled empty ≡ absent ≡ unparseable for a sidecar,
  so `{}` is a file this family has declared meaningless. **`<stem>.gate.json` is deliberately NOT taken**
  — it is the verdict sink's own document, separately armed, and a consumer that reads a missing verdict
  as "nothing to report" goes green. The input exemption covers the sidecars too: one that names a
  `CANDOR_DEPS` report, a `--policy` or the discovered config is left in place and disclosed. Conformance
  PART 37 (d).
- **⚠ ⟨0.28⟩ never reached the `gate --report` verb.** The rung landed on the scan CLI and nowhere else, so
  the route a CI job uses when it scans once and gates many times kept last-wins: `gate … --gate-json A
  --gate-json B` exited 1, wrote the red verdict to B, and left A holding a pre-seeded `{"ok": true}`.
  Found by a release panel the same day the rung was written. Conformance PART 36 (b21) pins it, with a
  firing control so the row cannot pass vacuously.
- **⚠ The §3.3.1 (2) input exemption took the whole run down.** Refusing a sink that names an input having
  written nothing is right for THAT PATH — but every other named sink still has a reader, and a `-` among
  them has no input to destroy. Measured: exit 2, the policy correctly intact, and an innocent second sink
  still publishing a previous run's green. The exemption is now scoped to the offending path (b22).
- The duplicate case is decided BEFORE the single-sink guard, which acts on the last sink alone and was
  exiting on it before the stream could be told anything (measured: exit 2, stdout zero bytes).

- **⟨0.28⟩ a repeated `--gate-json` is refused, and every path named gets the refusal** (SPEC §3.3.1).
  Before this rung the last sink won and the first was left exactly as found, so a previous run's
  `{"ok": true}` survived a gate that FIRED — the ⟨0.27⟩ stale green reached by a spelling nobody had
  considered, and worse than the case arming was built for: the run did not fail, the gate did fire, and
  the operator's own command named the path that lies. Two spellings of one path stay ONE sink, and a sink
  that is an input is still refused having written nothing.
- **The mostly-Unknown note stops naming a cause it cannot know.** `tour --report R` reads a report it did
  not produce, so "missing project config" was a guess about a build it never ran; it now points at the
  reasons the report records. Four-way, pinned by conformance PART 4l — which until now checked the COUNTS
  only, which is how all four engines drifted here without anything noticing.
## [0.27.0] — 2026-08-07

- **The jbang catalog pin moves to 0.27.0**, after the release it names exists. 0.24 shipped a jbang
  pin to a release that did not — which is why the pins move in a separate, later step.





- **…and the guard now enumerates a dep directory exactly as the LOADER does.** The first repair
  registered the directory's files with a FLAT read beside a RECURSIVE loader walk, so a report one
  level down stayed unguarded — and for `--deps`, which writes one subdirectory per `name@version`, the
  nested layout is the ORDINARY one. A guard that enumerates differently from the loader guards a
  different set of files. One enumeration now serves both.
- **⚠ A `--gate-json` sink INSIDE a `deps` DIRECTORY destroyed the operator's dep report.** `deps`
  accepts a directory — `--workspace` writes `.candor/deps/` and hands that back, so it is the common
  spelling — and the loader walks it and reads each report inside. The §3.3.1 sink-over-input guard
  registered only the DIRECTORY, which never equals a file within it, so `--gate-json <depdir>/lib.json`
  was unguarded: arming destroyed the report, the run chained the wreckage and exited 0 with `ok: true`
  written over the input. All four engines. The FILE spelling of this channel had been guarded for a
  release; the directory spelling had not, and no row posed it. Now pinned by conformance PART 36 (b14),
  which asserts both the refusal AND that nothing was written.
- **The `gate` verb arms its `--gate-json -` stream sink, and one sink is written once.** Arming was
  wired into the SCAN pre-pass only, so on the supply-chain surface an exit-2 during argument parsing
  left stdout EMPTY while the same verb refusing later streamed the document — one operator mistake,
  two answers, decided by how early it was caught. Separately, `--json --gate-json -` names ONE artifact
  twice and both were written, putting two concatenated JSON objects on a stream SPEC §3.1 requires to
  carry the fail-closed document "exactly once, as the streams only content". Both fixed; conformance
  PART 36 gained rows (b4)-(b6), which is why they were found at all.
- **⟨0.27⟩ The three verdict-document cells (SPEC §3.1/§4, conformance PART 36).** (1) The composed
  document no longer carries `refused`/`reason` beside `violations` — the refusal document's
  discriminator must not ride a verdict; the disclosure is `unevaluated` (this engine already listed
  every rule; an unreadable policy now gets one whole-file entry instead of an empty list). (2) The
  stream sink: `--gate-json -` gains a shutdown-hook analog of arming, so ANY exit-2 cause (an unknown
  flag, a broken config, a crash) leaves the fail-closed refusal as stdout's only content instead of an
  empty stream. (3) `zeroMatch`: the §4 zero-match list now rides the verdict document on BOTH routes,
  code-point sorted (`Query.BY_CODE_POINT`) and deduplicated; it was stderr-only.

- **⚠ `"(?U)\\s+"` written as `"(?U)\\s+"` — one backslash — made the sink guard blind to a TAB.** In a
  Java string literal `\\s` is JEP-368's SPACE escape, so the guard's regex was `(?U) +`. A
  `policy\\tgate.policy` config was read fine by the real loader and not recognised by the guard, so
  `--gate-json <that policy>` destroyed it and the run exited **0 with `"ok": true"`** while the gate was
  live. The `deps` split had the same escape and covered no dep after the first.
- **The guard now calls the engine's own config loader instead of re-deriving it.** That is the fix for
  the class rather than for the three instances: the hand-written pre-pass also computed the config's
  home directory as parent-of-parent unconditionally (the loader only steps out of a trailing `.candor/`
  segment, so an out-of-tree `CANDOR_CONFIG` anchored one level too high and the guard protected a path
  the run never reads), and split `deps` on the path separator alone. A second parser is a second set of
  holes.
- **⚠ The `gate` verb never read the config-declared `policy` at all** — rust, ts and swift all do, so a
  checked-in `policy` key gated in three engines and refused with "a policy is required" here: a 3-vs-1
  split on the family's own "one config, one meaning" claim, on the supply-chain surface. Caught by a
  new conformance row whose *control* — assert the config policy GATES before asserting anything about
  the sink — is what found it.
- **`trimUnicode` named U+00A0 and missed the rest of `\\p{Zs}`.** `policy gate.policy\\u202F` refused at
  exit 2 here while four engines trimmed it and ran; and a LEADING no-break space left an empty first
  token, so the key became `''` and the whole line vanished as "unknown config key" — a `policy` line
  silently dropped and a MISMATCHED `engine` pin silently passed. Now the whole space-separator category.
- **The scan target may appear anywhere in argv**, matching the other three engines.

- **⚠ The `gate` verb got none of the ⟨0.27⟩ guard, so the reference engine still reproduced §3.3.1's own
  worked example.** `gate --report R --policy P --gate-json P` exited **0 with `"ok": true`** after
  overwriting `P` (control, separate sink: exit 1) — the supply-chain surface, the one a consumer points
  at a report someone else produced. The sweep touched `Candor.java` and skipped `Query.java`. It also
  still armed mid-flag-loop, so an unknown flag BEFORE `--gate-json` left the previous run's green while
  the same mistake spelled the other way wrote a refusal.
- **⚠ The collision guard keyed on the FLAG, so a policy from `.candor/config` was invisible to it** —
  the checked-in form, i.e. the one CI actually uses. `--gate-json <that policy>` destroyed it and exited
  0 with `"ok": true`, in all four engines. `Config`'s own ⟨0.24⟩ note forty lines away says exactly this:
  *"a policy does not change what it is according to how the operator handed it over."* The guard now
  enumerates every channel — flag, env, the config's `policy`/`baseline`/`deps`, `CANDOR_DEPS`, and the
  config file itself — reading the config leniently so it cannot pre-empt the real load's refusal.
- **⚠ `--gate-json` before the target left a stale green.** `rejectUnknownFlag(args[0], …)` ran before the
  pre-pass and java's grammar forced the target into `args[0]`, so `candor --gate-json G <target>` exited
  2 as an "unknown flag" with yesterday's verdict still at `G`. The target may now appear anywhere in
  argv, matching rust, ts and swift — one contract, four grammars is what this family exists not to be.
- **The `(?U)` whitespace fix stopped one line short and became a FALSE REFUSAL.** `engine<NBSP>java<NBSP>v0.27.0`
  — a correct qualified pin — still reached `addEnginePin` as one token and failed MALFORMED, so this
  engine exited 2 where the other four exited 0; the same for a trailing NBSP on any value, since
  `String.strip()` uses `Character.isWhitespace`, which excludes U+00A0 by definition. Fixing a fail-open
  by breaking a working config is the mirror defect, not a stricter reading. `deps` values stay
  ASCII-split: those are PATHS, and a path may legitimately contain a non-breaking space.

- **The gate verdict could be written over the gate's own inputs.** `--policy P --gate-json P` armed the
  refusal over `P`; the now-JSON policy parsed as zero rules and a run that exits 1 on the same code
  exited **0 with `"ok": true`** — an all-clear produced by deleting the question. The reference engine
  had no guard for this at all. Now refused (exit 2, nothing written), with sameness resolved as
  artifacts (device+inode, symlinks, `./` spellings) rather than path strings, and `.candor/config`
  refused as a sink by shape wherever it is.
- **Arming depended on argv ORDER.** It happened mid-flag-loop, so `--gate-json G --frobnicate` wrote a
  refusal into `G` and `--frobnicate --gate-json G` left the previous run's green there — the operator's
  intent identical in both. A pre-pass now learns the sink before anything can exit or write.
- **A NO-BREAK SPACE hid a config key.** `String.split("\\s+")` is ASCII-only in Java, so
  `engine\u00A00.26.0` became one token, was reported as an "unknown config key 'engine '", and the pin
  went silently unenforced while a MISMATCHED version passed at exit 0 — a false disclosure over a
  fail-open. Now `(?U)\\s+`, matching the other four engines.
- **A chained dep report with no `functions` was skipped in silence** — it grants no coverage, so every
  call into that dep reads pure, and the operator who configured it saw no sign. Now named on stderr
  (sidecars, which legitimately have none, stay silent).


- **The reference engine was the sole non-conformer on the pin, 5-to-1.** `engine 0.26.0 oops` beside a
  valid `engine java v0.27.0` exited 0 here and 2 everywhere else: precedence returned the qualified pin
  without ever looking at the unreadable unqualified line, so its malformedness never reached a verdict.
  §3.4 says an unqualified line "is yours to read, and MUST be MALFORMED if it is unreadable" —
  precedence decides which *version* applies, not whether a line you were supposed to read parses.

- **A baseline DECLARED in `.candor/config` but missing is now exit 2, not a green pass.** An adopter
  review measured this as the second-likeliest first-commit mistake (`.candor/` committed, the baseline
  not) and found every engine printing a note and exiting **0** — the gate quietly not gating. The split
  is by SOURCE, because the same absence means two different things: `CANDOR_BASELINE` is set
  unconditionally by the adopt workflow, so a path that is not there means "the ratchet is not adopted
  yet" and stays a note; a checked-in `baseline` line DECLARES that this repo has one, so an absent file
  was deleted or never committed. Verified four-way: config-declared → 2, env-named → 0.


### ⚠ ⟨0.27⟩ `engine` — the engine↔baseline coupling, enforced instead of hoped for

`.candor/config` gains an `engine [<impl>] <version>` key (SPEC §3.4). A build that is not the pinned
one FAILS with **exit 2** rather than producing a verdict it cannot stand behind. Marked ⚠ because a
repo that adopts the key can now fail a run that previously passed — which is the point.

**What this adds over what already existed**, stated precisely because the first draft of this entry
overclaimed. The AS-EFF-005 path ALREADY refuses when the baseline's producing build differs from the
running one — *"an engine swap is baseline-invalidating"* — so it is not true that nothing enforced the
coupling. Three things it cannot do:

- It compares the §2.1 provenance **build id**, a git hash like `b8589ac`. A human cannot pin that, and
  there was nowhere to declare an intended version at all; a mismatch is discovered only after running
  the wrong engine.
- It lives **inside the baseline path**, so a policy-only gate — or any scan with no `baseline` wired —
  had no coupling check at all. That is the gap this closes.
- It can only **detect**. A declared pin is also an instruction: `.candor/run` and the generated CI step
  read this same key to decide which engine to *fetch*, which is what collapses the version to one place
  instead of restating it in CI YAML beside a baseline it is married to.

The two are complementary, and the pin runs **first** — at config load, before the scan — so a wrong
engine costs a message rather than a full analysis followed by a refusal.

**Two of the five verdicts must not change the exit code, and that is the design.** No pin, or a pin
naming another implementation, behaves exactly as before — the key is opt-in by construction. A pin the
running build cannot check, because a source build does not know its own release version, is
UNANSWERABLE: ⟨0.24⟩ §3.1's rule is that such a condition is disclosed and never scored, *including as
satisfied*. Failing there would break every developer on a source build; passing silently would delete
the pin exactly where nobody is watching for it.

Exit **2**, not 1: the run is unevaluable, not violating, and a machine consumer must not read "I could
not trust this result" as "your code broke a rule".

An unreadable pin (`engine latest`, a bare `engine`) also exits 2 rather than being skipped as a
malformed line. **This is the one place the §6.2 warn-and-skip posture inverts**, and getting it wrong
was the first defect here: every other malformed line in this file warns and skips, which is right for a
key that ADDS something — a bad `net-partner` costs one host's classification. Skipping a PIN hands the
enforcement site "absent", and absent passes, so a pin the operator could not spell would have become a
guard they believed was on. The parser's first draft made it worse: `engine 0.26.0 oops` was keyed on an
implementation named `0.26.0`, where this engine never looks.

**Two more ways a written pin could stop being a pin, found by adversarial review after the above:**
duplicate lines for the same key were plain last-wins, so `engine java 0.26.0` followed by
`engine java 0.27.0` discarded the operator's first line and exited 0 MATCH; and trailing junk was
dropped in the *qualified* arm only, so `engine java 0.26.0 0.27.0` silently pinned 0.26.0 while the
unqualified spelling of the same mistake correctly refused. Conflicting duplicates are now MALFORMED
(quoting both lines back — two lines disagreeing about which engine to run is not a preference to
resolve), and trailing junk is MALFORMED in both arms. An identical repeat stays a harmless no-op.

**A limitation the pin cannot see, stated rather than implied:** `build.gradle.kts` bakes
`release = project.version` into *every* build, so a jar built from an unreleased working tree reports
the release version and satisfies a pin naming it. The pin therefore distinguishes RELEASES, not builds;
the §2.1 provenance build id is what separates those, and the AS-EFF-005 path already compares it. An
earlier draft of this entry claimed source builds land in UNDETERMINED — they do not.

**`gate --report` discloses the pin without enforcing it.** It applies a policy to a report it did not
produce, so refusing because this build is not the pinned one would fail a valid evaluation. But policy
semantics move with engine versions (⟨0.24⟩ could turn a green gate red), so a mismatch now prints one
line saying the verdict stands while the semantics applied are this build's. Same posture as the
UNDETERMINED pin: say it once, change nothing.

The qualified form (`engine java v0.27.0`) exists because the family versions as a LADDER, not in
lockstep — one engine may lead a rung, so a bare version in a polyglot repo would fail whichever engine
had not caught up. A pin qualified for another implementation is ignored: one config serves the family.

There is deliberately no `CANDOR_ENGINE` env var and no `--ignore-engine-pin`. Every other key
configures what the run *does*; this one asserts what the run *is*, and an assertion an ambient
environment can switch off is not one. The deliberate act is editing the pin, in the same change that
regenerates the baseline — which is the discipline being enforced.


### ⟨0.27⟩ `resolves` — declare which optional refinement surfaces this producer computes

SPEC §2's optional per-function fields are omitted when the engine cannot determine an answer, which
means absence carries two different meanings that a consumer cannot tell apart: *"I looked and the
answer is undetermined"* and *"I do not compute this field at all"*. `resolves` is a top-level envelope
array naming the surfaces this producer DOES compute, so absence under a listed surface is a real
undetermined and absence under an unlisted one is a capability gap. Same construction as `extensions`,
different scope. A producer MUST NOT list a surface it does not compute.

### SPEC §2 `fs` — kinds travel the call graph, and one undetermined contributor suppresses the field

`fs` refines an `Fs` effect into `read` / `write`. The kinds now PROPAGATE over call edges, so a function
that reaches a writer three frames down reports `["write"]` rather than nothing. The rule that makes that
safe is the poison marker: if ANY contributing `Fs` had an undetermined kind, the whole field is
suppressed rather than emitted partially. §2 is explicit about why — *"an empty or partial `fs` would be
read as a positive claim (reads but never writes)"* — and a partial answer here is worse than none.

The recording site previously poisoned only on a cross-jar `Fs`. A LOCAL mode-dependent verb recorded
nothing at all, so a function mixing a determined write with an undetermined read reported `["write"]`:
a positive claim that it never reads, from evidence that could not support it. Now an empty kind set
poisons like an unknown one.

Pinned four-way by conformance PART 31.


## [0.26.0] — 2026-08-04 ⟨spec 0.26⟩

### the S3 Fs rule gates on the CLIENT, not the package — the first version fabricated

Review of the rule below, same day. It gated on the s3 PACKAGE, so a pure VALUE TYPE taking a `File`
matched: `PutObjectRequest.withFile(f)` is a builder that performs nothing, and it reported `Fs`
(measured: `build() -> [Fs]`). The Net rule directly above it had already learned this exact lesson —
its comment records fabricating Net on `AmazonS3URI.getBucket` — and the fix is to mirror its gate:
`Client`/`TransferManager` owners only. Pinned by a regression test.

### ⚠ κ breadth: an S3 transfer naming a LOCAL FILE is `Fs` as well as `Net`

`s3.getObject(request, File)` WRITES that file; `putObject(bucket, key, File)` READS it. The AWS service
rule returns `Net` and `Classifier.classify` returns ONE effect, so the Fs half had nowhere to go — a
`deny Fs` gate over an S3 archival path saw nothing.

**This is not the "bytes through a caller-opened handle" caveat** that keeps `serde_json::from_reader`
and `tracing_subscriber`'s File writer uncharged. That caveat holds because the caller's own `open`
already carries the Fs. `new java.io.File(path)` OPENS NOTHING in Java — it is a path wrapper, and candor
rightly treats it as pure — so the write happens ONLY inside the SDK, and charging nobody loses it.

Co-emitted the way `Llm` co-emits `Net`: `dir` is a set, so the Fs is ADDITIVE and the service rule's Net
is never displaced. Gated on the s3 service packages plus a `File`/`Path` in the DESCRIPTOR, so a
metadata call keeps its Net alone and a pure same-named value type (`AmazonS3URI.getBucket`) cannot match.

    download(c.getObject("r", new File(…)))   Net  ->  Fs + Net
    upload(c.putObject("b","k", new File(…))) Net  ->  Fs + Net
    meta(c.getBucketLocation("b"))            Net  ->  Net        (CONTROL — no File, no Fs)

commons-io was on the same filing and needed nothing: `org.apache.commons.io` already carries the
source/sink descriptor stance (File/Path → Fs, URL/URI → Net) with the pure path-arithmetic helpers
carved out.


### ⟨0.26⟩ THE HIERARCHY SIDECAR'S KEY SET IS ITS MANIFEST — both halves

SPEC §2.2 `78aad6d`. PRODUCER: `ReportWriter` emits a key for every indexed type, `[]` included.
CONSUMER: `Query.subtypeOf` is three-valued (`YES`/`NO`/`UNANSWERABLE`), and `isSubtypeOf` collapses
UNANSWERABLE to true — disclose, never drop. `getOrDefault(t, List.of())` had read an unindexed type as
"has no supertypes", a positive claim about a type nobody analysed.

MEASURED with only the sidecar doctored: one entry removed → `[]`; the whole sidecar removed → correct.
Partial information was worse than none. candor-ts behaved identically, which is evidence about the
FORMAT rather than either engine — neither had a third answer available.

## [0.25.0] — 2026-08-02

⟨spec 0.25⟩ **Floor bump only — no behaviour change in this engine.** SPEC §2 chaining rule 1 now states
that an ambiguous join key is UNIONED rather than dropped; this engine already implemented the union
(conformance PARTs 25/26 pin it four-way), so 0.25 records the contract catching up with the code. See
candor-spec/CHANGELOG.md for the measurement and the reversal note.


- **⟨0.24⟩ ⚠ …AND IT BINDS THE WITHHELD-RULE TRIGGER TOO: `ok` IS OMITTED, NOT `false`** (SPEC §3.2,
  ruled in candor-spec `142740a`). The entry below closed the INCOMPLETENESS trigger; this closes its twin.
  `4fd140c` argued the `false` deliberately and it was wrong by its own reasoning one paragraph earlier: on
  an ADVISORY verb `ok: false` asserts *"a hole exists, here it is"* — and where a rule was WITHHELD **no
  hole was found; the question was declined.** That is the fabrication mirror, which is precisely why the
  incompleteness trigger omits the field. The two triggers are the same shape and take the same answer;
  they looked different only because they were ruled in two clauses a day apart.

  **MEASURED four-way on a jar built from the previous commit**, on a report carrying `Net` + `hosts` with
  **no** `netClass` beside an `Unknown` hole, under `deny Net[unknown-host] app`, `unverified --json`:

  | engine | `ok` |
  |---|---|
  | rust | *omitted* |
  | **java** | **`false`** |
  | ts | *omitted* |
  | swift | *omitted* |

  A 1-against-3 split against a clause shipping in 0.24 — the sibling of the 2-against-2 split the entry
  below spent a round closing. (The `candor-query` on `PATH` is a 20 Jul build and still answers `false`;
  the rust engine's own tree does not — measure the tree, not the installed binary.)

  | verb (java, that fixture) | before | after |
  |---|---|---|
  | `unverified --json` | `{"ok": false, "unverified": […], "unevaluated": […]}` | `ok` OMITTED, both arrays unchanged |
  | `fix-gate --json` | `{"ok": false, "remedies": [], "unevaluated": […]}` | `ok` OMITTED, both arrays unchanged |
  | either, `--strict` | exit 2 | unchanged |
  | either, no `--strict` | exit 0 | unchanged |
  | *(prose)* | tick already withdrawn | + the sentence naming the omission |

  **ONE PATH, REUSED — `Query#advisoryAnswer` now decides BOTH triggers and writes `unevaluated` itself**,
  rather than each caller putting the disclosure in its body while the omission rule lives elsewhere. A
  trigger whose disclosure is emitted in one place and whose consequence is decided in another is exactly
  how these two clauses drifted apart: `whatif` held the first rule inline and its siblings never got it.
  `unjudged` is non-empty only when `unevaluated` is (one producer emits the per-function and the per-rule
  form), so the scoped and rule-kind refusals reach the same answer by construction.

  **THE MIRROR WAS WRITTEN AND RUN FIRST**, because the way to get a field-omitting repair wrong is to omit
  the field ALWAYS — and every absence-assert in the new class would still pass. Over a complete report
  under a fully evaluated policy both verbs still carry `ok`, in **both polarities**: `true` with nothing
  to find (exit 0) and `false` with a real hole/remedy (exit 1 under `--strict`). Asserting only the clean
  polarity cannot see a repair that deletes the field wherever a finding exists, which is the shape of the
  defect being fixed. Of the 3 new tests and 3 amended assertions, 5 fail on the previous commit; the
  mirror passes on both, which is its job. Everything else is unchanged: `unevaluated` still ships, the
  `unverified` array still names both the genuine hole and the unjudged function, `--strict` still exits 2.
  Suite 654 → 657 pass, smoke 444/444, four-way conformance OK (PART 27 R11 `advisory-bound` and
  `advisory-incomplete` OK on all four engines; R10 waived as before).

- **⟨0.24⟩ ⚠ THE OMIT-`ok` RULE BINDS EVERY ADVISORY VERB, AND THE DISCLOSURE REACHES EVERY CHANNEL**
  (SPEC §3.2, ruled in candor-spec `ec1a441`, resting on `93cef40`). `0075987` ruled it for `whatif` and
  this engine implemented it for `whatif`; `unverified`, `fix-gate` and `fix` never got it. MEASURED here
  on a jar built from the previous commit, over a release reviewer's fixture — one report declaring a
  single `unanalyzed` unit, **no holes at all**, and a `deny Net app` that nothing violates:

  | verb | before | after |
  |---|---|---|
  | `gate --report` | exit **2**, `ok:false`, `incomplete:true` + the manifest | unchanged ← already right |
  | `unverified --strict` | exit **0**, `{"ok": true, "unverified": []}` | exit **2**, `ok` OMITTED, `incomplete:true` + the manifest |
  | `fix-gate --strict` | exit **0**, `{"ok": true, "remedies": []}` | exit **2**, `ok` OMITTED, `incomplete:true` + the manifest |
  | *(prose)* | `every function in a pure/deny layer is PROVABLY clean ✓` | the tick is WITHDRAWN; the unread unit is named with its reason |

  That fixture is the sharp one and no existing test had an analogue: every prior incompleteness fixture
  pairs the unread file with something the verb DOES find, so the behaviour on *"nothing to report, but I
  could not see everything"* — the only shape where the false all-clear is the whole output — was never
  exercised. `unverified` is the sharpest verb in the family for the same reason: **it exists to say "your
  green gate is not provably green", and it was certifying a set it knows it cannot see all of.** A
  function in an unparsed file is absent from `functions`, so it cannot be enumerated as an unverified
  pass — and that absence is exactly what the verb would have to report.

  **`ok: false` is NOT the repair**, for the reason §3.2 gives in `whatif`: on an ADVISORY verb `false`
  asserts *"a hole exists, here it is"* beside an empty array — the fabrication mirror, worse than the
  silence it replaces. So `ok` is omitted, `incomplete:true` + the manifest take its place, `if (r.ok)`
  fails safe, and the verb's own array still ships (a partial answer that says it is partial beats a
  refusal). One producer for all four verbs — `Query#advisoryAnswer` — because a copy of the rule sitting
  inline in `whatif` is precisely why the siblings did not have it.

  **THE PROSE TICK IS THE PROSE `ok: true`**, and the clause requires both channels because a test that
  reads one channel is evidence about one channel: candor-rust built a mutant keeping the whole JSON fix
  and deleting only the printed line, and it survived that engine's entire suite. `fix` carries neither
  `ok` nor `--strict`, so what it withdraws is the sentence — `no policy forbids it there — nothing to
  fix` — and its hoist frontier is disclosed as the lower bound it is.

  **AND THE MANIFEST IS READ OVER THE REPORT SET THE LOCATOR NAMES**, not the one file `expandPrefix`
  picks (`93cef40`: the advisory verb's incompleteness verdict must be at least as pessimistic as the
  gate's **over the same bytes**). Measured: two sibling reports under one prefix with the manifest in the
  second — `gate --report <prefix>` exits 2 while `unverified --strict` answered clean, the same
  under-report one resolution step out. The ELEMENT rule was already right here (a member counts the
  moment it is an object, so one with no `path` still trips it) and is now pinned.

  ⚠ marks the exit code: a `--strict` CI step on `unverified`/`fix-gate` over a partially-parsed tree now
  exits 2 where it read green. That is the clause working — the green was the defect.

- **⟨0.24⟩ ⚠ AN ADVISORY VERB MAY BE LESS CERTAIN THAN THE GATE, NEVER MORE** (SPEC §3.2, ruled in
  candor-spec `4fd140c`; conformance PART 27 row **R11**). Where `gate --report` REFUSES for want of
  evidence, `unverified` now NAMES the function, `fix-gate` offers no remedy, both carry the gate's own
  `unevaluated: [{rule, why}]`, and `--strict` exits **2** to match the gate. MEASURED on this engine
  against a jar built from the previous commit, two mechanisms:

  | report | policy | `gate --report` | before | after |
  |---|---|---|---|---|
  | `hosts`, **no `netClass`** | `deny Net[unknown-host] app` | exit 2 — cannot judge `app.noClass` | `unverified` names a *different* hole and clears it | names `app.noClass` as **UNJUDGED** |
  | `Unknown` **inherited**, no reason | `deny Unknown[unresolved] app` | exit 2 — cannot judge `app.inherits` | `unverified` `ok:true`, list **empty**; `fix-gate --strict` **exit 1 + a full hoist plan** | names it; no remedy; exit 2 |

  The second row names the mechanism. There was no single bug — there was no QUESTION. The hole predicate
  asks *"does the gate PASS this while it is Unknown?"*, and both halves assume the gate reached a verdict:
  `app.noClass` carries no `Unknown` so it was never a candidate, and `app.inherits` had its narrowing FIRE
  on `reasonClassesOf`'s fail-closed `unresolved` floor — **a class derived from the very field the gate
  refused to read**. A hedge does beat a hole; a derivation is not a hedge. The reason recorded is the
  ABSENT FIELD, never the class it would have held.

  **AT SCALE, on an external corpus** — `aws-java-sdk-s3-1.12.395` (2157 entries; 696 `Net`-bearing, **689
  of them carrying `hosts`**; 821 `Unknown`-bearing), re-served with one channel dropped as a pre-rung or
  foreign producer writes it. Population = in-scope functions carrying an effect the rule names; each must
  land in exactly one of three channels, and a function in none is one nothing said anything about:

  | report | rule | | VIOLATION | UNVERIFIED pass | UNJUDGED | **in NO channel** |
  |---|---|---|---|---|---|---|
  | `netClass` present | `deny Net[unknown-host]` | before / after | 696 / 696 | 0 / 0 | 0 / 0 | **0 / 0** ← the mirror |
  | `netClass` stripped | `deny Net[unknown-host]` | before → after | 0 → 0 | 686 → 0 | 0 → **696** | **10 → 0** |
  | `netClass` stripped | `deny Net` (control) | before / after | 696 / 696 | 0 / 0 | 0 / 0 | **0 / 0** ← unmoved |
  | reason present | `deny Unknown[dispatch,unresolved]` | before / after | 693 / 693 | 128 / 128 | 0 / 0 | **0 / 0** ← the mirror |
  | reason stripped | `deny Unknown[dispatch,unresolved]` | before → after | 0 → 0 | 0 → 0 | 0 → **821** | **821 → 0** |
  | reason stripped | `deny Unknown` (control) | before / after | 821 / 821 | 0 / 0 | 0 / 0 | **0 / 0** ← unmoved |

  The 686 were not a silence but a **misattribution** — filed as passing a rule that was never evaluated.
  The 821-row is the defect with nothing left to hide behind: a whole corpus in no channel at all. The
  unnarrowed CONTROLS do not move over the same stripped bytes, so what moved is the NARROWING, not the
  stripping. **Every gate verdict is byte-identical across the change** — this moves what is disclosed,
  never what is decided.

  ⚠ marks the exit code: a `--strict` CI step on `unverified`/`fix-gate` that read green (or amber at 1)
  over a report `gate --report` refuses now exits 2. That is the row working — the green was the defect.

- **⟨0.24⟩ `whatif` QUOTES THE OPERATOR'S OWN RULE, AND NAMES THE NARROWING IT COULD NOT EVALUATE**
  (SPEC §3.1, candor-spec `6f30540` + its correction `901f14d`). `whatif` REBUILT the rule it printed, from
  `scope` plus the effect being ASKED ABOUT rather than the rule's own set. MEASURED on this engine, and
  every row names a rule nobody wrote:

  | written | printed back |
  |---|---|
  | `deny Unknown[reflect] app` | `deny Unknown app` |
  | `deny Net[unknown-host] app` | `deny Net app` |
  | `deny Net Db  app  # keep the app pure` | `deny Net app` |

  The first two are the sharp ones — **a NARROWED rule shown as the WIDE one, in the verb an agent reads
  BEFORE editing**, so the operator's own scoping is invisible at exactly the moment they are deciding
  whether it protects them. The third has no filter in sight and the same root cause: rebuilding from the
  question dropped the operator's other denied effect too.

  **AND THE ORDER MATTERED, which is why the second half is not optional.** Quoting the raw line while the
  verdict stayed filter-blind would be *worse than the bug* — the same unconditional "WOULD VIOLATE", now
  attributed to the narrowed line, reading as though candor had evaluated a filter it did not. `whatif` asks
  about an effect the code **does not have yet**, so a `Net[dest…]`/`Unknown[class…]` filter quantifies over
  the class of something that does not exist: there is nothing to match and the question is genuinely
  unanswerable. §3.1's rule for exactly this shape is that **an unanswerable condition is DISCLOSED, never
  scored as a failed one** — so the verdict stays fail-closed (a pre-edit gate must not guess which class the
  edit lands in) and the condition rides beside it, per-violation, in **both** channels:

  ```
  [AS-EFF-006] `app.nat`  (rule: `deny Net[unknown-host] app`)
      …IF the `Net` you introduce reaches destination class unknown-host.
  ```
  ```json
  "violations": [{"fn": "app.nat", "rule": "deny Net[unknown-host] app",
                  "conditional": "the `Net` you introduce reaches destination class unknown-host"}]
  ```

  This does **not** reuse the `classNarrowingFires` predicate the sibling fix above shares: `unverified` and
  `fix-gate` read a signature that EXISTS, so their filter has something to match. `Policy#narrowingCondition`
  is the sibling for the case where it does not. **`conditional` is OMITTED when the rule does not narrow** —
  one on every violation would train the reader to ignore it — and it keys on the effect being INTRODUCED,
  never on the rule merely carrying a bracket (`deny Net[unknown-host] Fs app` asked about `Fs` charges `Fs`
  unconditionally). Verified against **candor-rust's emitted JSON**, which is the normative form here: 10
  rule/effect shapes, `rule` and `conditional` byte-identical in both the JSON and the prose channel,
  mirrors included. Pinned by `WhatifConditionalTest`.

- **⟨0.24⟩ A NARROWED RULE IS A NARROWER RULE FOR `unverified` AND `fix-gate` TOO** (SPEC §6.2, "THE GATE
  AND THE DISCLOSURE MUST APPLY THE SAME RULE, AND SHOULD SHARE THE SAME CODE"). `deny E Unknown[c…]` and
  `deny Net[dest…]` carry a class filter the gate has always honoured; the two advisory verbs beside it
  computed from the EFFECT SET ALONE. MEASURED over a report whose only hole is `native:dlopen`, under
  `deny Unknown[reflect,unresolved] app` — a layer the gate PASSES:

  | verb | before | |
  |---|---|---|
  | `gate --report` | exit 0 | correct — the class is excluded |
  | `fix-gate --strict` | exit 1 + a remedy naming it | a red CI check and a hoist instruction for a boundary the policy does not draw |
  | `unverified --strict` | exit 0, `ok:true` | the under-report, and the worse half |

  **The under-report is the half that matters.** The layer passes while carrying an `Unknown`, so it is
  exactly a PASS-but-Unknown hole — and `unverified`, the verb whose whole job is *"your green gate is not
  provably green"*, certified it clean. Its hole predicate asked `inferred ∩ rule.effects() ≠ ∅`, saw the
  rule name `Unknown` and the function carry `Unknown`, and concluded the gate would catch this one; the
  gate, applying the filter, did not. **Both halves are one defect and are fixed in one change** — the
  narrowing is hoisted out of the gate into `Policy#classNarrowingFires` and all three call sites share it.
  MEASURED AT SCALE on this engine's own 407-function report (72 `Unknown`-bearing functions), where the two
  channels must PARTITION that set — a function either violates the rule, or passes it while `Unknown`:

  ```
  deny Unknown[reflect,unresolved]    gate 44 + unverified  0 = 44  →  44 + 28 = 72
  deny Unknown[indirect,unresolved]   gate 34 + unverified  0 = 34  →  34 + 38 = 72
  deny Unknown[dispatch,unresolved]   gate  0 + unverified  0 =  0  →   0 + 72 = 72
  ```

  The last row is the defect in one line: a wholly green gate over 72 unproven `Unknown`s, with not one word
  said about any of them. **The gate verdict is byte-identical across the change** (44/44, 34/34, 0/0) — this
  moves what is DISCLOSED, never what is decided; unfiltered rules and the `Unknown[*]`/`Unknown[dynamic]`
  forms do not move at all. `fix` shares the denied-layer predicate and moves with it. Two adjacent repairs
  fall out: the disclosure now quotes the rule WITH its filter (`deny Unknown[reflect,unresolved] app`, not
  `deny Unknown app` — a rule nobody wrote, and one that would not have passed), and the upgrade for an
  already-narrowed rule WIDENS the filter by the class that got through rather than appending a second bare
  `Unknown` to a rule that already names it. Pinned by `NarrowedRuleAdvisoryVerbTest` (9 tests; the mirrors —
  a policy whose classes DO cover the hole, and every unfiltered rule — assert the disclosure is still named,
  byte-for-byte).

- **⟨0.21⟩ THE COMPLETENESS MANIFEST NOW REACHES THE AGENT ACROSS THE MCP SURFACE.** candor-ts found its
  MCP `candor_gate` implementing no ⟨0.21⟩ incompleteness rule — `{"ok":true}` over a report declaring
  `unanalyzed` where the CLI exits 2. **This server exposes no gate tool at all** (four read-only queries;
  `tools/list` now asserts it), so there was no `ok` to be wrong. The sibling defect it did have is a
  silently short ANSWER: measured, two classes — one performing `Fs`, one performing `Net` with its
  bytecode major version bumped past what ASM reads — and `candor_where(effect="Net")` replied
  `{"directly": [], "inherited": []}` with `isError` unset. *Nobody performs Net*, confidently, over a
  report that names the `Net`-performing class as unread. The report already held the answer; the verb
  dropped it. Every tool response now carries the manifest as a SECOND content block (so `content[0].text`
  stays exactly the payload an agent may parse), and **not** as `isError` — a partial answer that says it
  is partial beats a refusal, and these verbs are consulted before an edit. A complete report is unchanged:
  one block, no claim. `candor_whatif` inherits the `ok`-omission below for free, since these tools shell
  out to the real CLI. `ensure_report()`'s stale-artifact rule re-verified end-to-end and holds.

- **⚠ ⟨0.24⟩ `whatif` OVER AN INCOMPLETE REPORT OMITS `ok` — it does not answer `true`, and it does not
  answer `false` either** (SPEC §3.2, candor-spec `0075987`). Measured independently by candor-rust and this
  engine: `whatif` returned `ok: true` over a report declaring `unanalyzed` units. Its `affected` set is a
  transitive-CALLER closure, so a caller in a file nothing parsed is invisible to it — the blast radius is a
  LOWER BOUND. `whatif` is not a gate, but **its `ok` reads as one**. Neither boolean is honest here:
  `ok: true` asserts nothing touched is denied over a knowingly partial set, and `ok: false` would assert a
  violation the analysis never found (the fabrication mirror). So the field is **omitted**, and
  `incomplete: true` + the `unanalyzed` manifest take its place — `if (r.ok)` gets a falsy value and fails
  safe. Deliberately NOT the gate verdict's shape (`ok:false` + `incomplete:true`), where `ok:false` is
  *true* because the gate did not certify. `affected`/`violations` still ship and the EXIT CODE is unchanged
  (0/1 on the violations actually found — a question this run can still answer). The prose channel carries
  the same limit: the `✓ within policy` all-clear is replaced by a line naming the unanalyzed units, since
  closing the JSON channel and leaving the identical claim standing in the human one closes nothing.
  Alongside it, `whatif` now **fails loud (exit 2) on a report that does not parse**: it reads only the
  call-graph sidecar, so it was answering a pre-edit all-clear over a report nothing had opened.

- **⟨0.24⟩ `policyVocabulary.aliases` IS AN OBJECT `{alias: [classes…]}`, NOT AN ARRAY OF NAMES**
  (SPEC §3.1, candor-spec `7f5b5ba`). This engine shipped `["corp"]`; candor-ts shipped
  `{"corp": ["reflect"]}` and won the shape argument against three engines by quoting §3.1's own reasoning
  back at it, not on a headcount. §3.1 rejects `configSources: [path]` because *a disclosure that names the
  source but not the content leaves the reader knowing they were affected and not how* — and
  `aliases: ["corp"]` fails that test one level down. **`corp = reflect` and `corp = reflect,native` gate
  DIFFERENTLY under one unchanged policy line**, and under the array both runs disclosed the byte-identical
  `["corp"]`: the alias NAME is precisely the part that did not change, so it cannot be the part that tells
  the reader which gate ran. The object is a strict superset (`Object.keys` recovers the array). Class
  tokens are sorted, so declaration order cannot change the bytes; `config` keeps its position — the content
  is disclosed in addition to the source, never instead of it.

- **⟨0.24⟩ `errors[].kind` NORMALISED ONTO THE CLOSED FIVE — `forbid form`/`allow values` → `rule-form`**
  (SPEC §3.1, candor-spec `f735b16`). The pinned set gained a fifth member, `rule-form`, because it had been
  closed over its author's sample rather than over the domain: this engine emitted two rows for a rule whose
  KIND is recognised (`forbid`, `allow`) but whose FORM is malformed, and none of the four values described
  them. Reporting them under their own spellings rather than folding them into `rule-kind` was the right
  call — `rule-kind` on `forbid glued->arrow` tells a consumer that `forbid` is not a known rule kind, which
  is false — but the spellings were unhyphenated and outside the set, so no consumer could compare them with
  another engine's answer. **The hyphen is not decoration**: it is what makes the value machine-comparable.
  `rule-form` did NOT swallow `rule-kind` — `frobid a -> b` names no rule at all and still reports
  `rule-kind`, because respelling the head token and fixing the line's shape are different remedies. (The
  three space-spelled values `effect name` / `allow effect` / `rule kind` were normalised at `74fd040`;
  these two were the remainder.)

- **⚠ ⟨0.24⟩ PRECEDENCE BINDS THE VERDICT, NOT THE POLICY GATE — a certain BASELINE regression was deleted
  from the machine channel by an unrelated policy refusal** (SPEC §3.1, candor-spec `4c79958`). Measured, a
  pure function gaining an `Fs` call against a frozen baseline: `CANDOR_BASELINE=b --gate-json g` → exit 1
  with `violations: ["AS-EFF-005"]`; add `--policy P` carrying a bad class token → **exit 2 and no
  `violations` key at all**. The `[AS-EFF-005]` line still printed on stderr, so the human kept the
  regression and CI lost it — a typo in a policy token downgraded "your change added an effect" to "could
  not evaluate". The AS-EFF-005 ratchet is a violation PRODUCER that runs before the policy gate by design
  and records into the same verdict; the earlier precedence repair was scoped to the policy gate's own
  list. The refusal is now weighed by the caller, and the arm is keyed on *"this run evaluated nothing"*,
  never on *"this run ended refused"*. **Verdict-affecting**: such a run now exits **1**, not 2, and the
  document carries the violation PLUS `refused`/`reason`/`unevaluated` (every rule of the refused policy,
  not only the offending one). A refusal with nothing standing above it is unchanged: exit 2,
  `refused: true`, no `violations` key.

- **⟨0.24⟩ THE STALE-DOCUMENT RULE, OVER ITS CONDITION RATHER THAN ITS EXIT SITES** (SPEC §3.1,
  `1503368` + `901f14d`). Found while checking the mirror of the fix above. `1503368` made a refusal write
  its document and `901f14d` generalised that over machine output paths — both implemented at the exit
  sites that had been measured. On a `--gate-json` path a clean run had left `ok: true`: a baseline with no
  provenance header → **exit 2, the path still reads `ok: true`**; an unreadable scan target → **exit 2,
  the path still reads `ok: true`**. Two unrelated causes, one stale green, and a CI wrapper reading that
  path unconditionally passes. Threading the sink into each of the ~20 `System.exit(2)` sites is the fix
  scoped to the POSITION and still misses every site nobody enumerated (a crash, an OOM, a kill), so the
  path is now **armed fail-closed when the flag is PARSED** — `ok:false, refused:true` with a reason saying
  the run never completed — and every normal path overwrites it, leaving a completed run's bytes unchanged.
  `-` (stdout) is excluded: that stream carries exactly one document, and its own test pins that.

- **⚠ ⟨0.24⟩ THE POLICY-VOCABULARY ANCHOR KEYED ON THE `--policy` FLAG, so `CANDOR_POLICY` gate-PASSED
  silently** (SPEC §3.1, candor-spec `99eb4e9`). `unknown-alias` resolves relative to the policy file's
  directory — but this engine tested `policyArg != null`, so a policy supplied through `CANDOR_POLICY` (CI's
  primary channel) or the config `policy` key fell back to the TARGET's config and expanded its aliases
  there. Measured, one policy and one target, the target defining `corp = native` and the policy's config
  `corp = reflect`, over a reflect-caused `Unknown`: `--policy <file>` → exit 1, `gate --report` → exit 1,
  **`CANDOR_POLICY=<file>` → exit 0, `ok: true`**. The anchor is now the RESOLVED policy path however it was
  supplied, resolved once so the anchor and the gate cannot disagree. Target-scoped keys (`net-partner`,
  `deps`) still anchor at the target, and that half has its own test.

- **⟨0.24⟩ `unevaluated` was a KIND AGGREGATE and lost WHICH rules** (SPEC §3.1, candor-spec `fc4b5f6`;
  candor-ts is the reference shape). `gate --report` emitted `{"rule": "forbid (× 2)"}` for two distinct
  `forbid` lines and `{"rule": "allow Fs/Net"}` for every `allow` — answering *how many* where the operator
  asked *which*, so a consumer could not tell which of their boundaries went unchecked. Now one entry per
  rule with the RAW policy line verbatim, and each `why` about its own rule. `PolicyRule.Forbid` gained the
  `src` field its `Deny`/`Allow` siblings already carried.

- **⚠ ⟨0.24⟩ A TYPO'D EFFECT NAME DELETED THE RULE SILENTLY** (SPEC §6.2, candor-spec `1e1748a`). Measured:
  `deny Nett app` → exit **0**, `allow Nett host.example` → exit **0** — the operator reads an armed gate
  that does not exist. Both are now policy errors (exit 2): `allow`'s effect position is a fixed, closed
  set with no scope reading available in it, and a `deny` whose effect list is EMPTY after scope-splitting
  is malformed under either reading. **The genuinely ambiguous middle stays permissive by design** —
  `deny Net Exex app` still parses with `Exex` as the scope, with its own control test — and form failures
  (a value-less `allow`, a malformed `forbid`) stay dropped-and-reported. **Verdict-affecting**: a policy
  carrying either typo now refuses instead of running gateless.

- **⟨0.24⟩ `errors[].accepted` + the closed `kind` set pinned** (SPEC §3.1, candor-spec `901f14d`).
  `accepted` was already an array of tokens here and the field names were already the pinned ones; both are
  now held by a test rather than by luck. `rule kind` → `rule-kind` and `effect name`/`allow effect` →
  `effect-name`, completing the closed set. **Reported, not papered over**: two rows report a FORM failure
  (malformed `forbid`, value-less `allow`) and the closed set has no member for them; they are deliberately
  NOT mapped into `rule-kind`, since `accepted: ["<scope> -> <scope>"]` there would tell a consumer that
  `forbid` is not a known rule kind, which is false.

- **⟨0.24⟩ THE MCP SERVER ANSWERED FROM THE PREVIOUS RUN'S REPORT AFTER A SCAN THAT FAILED** (SPEC §3.1's
  stale-document rule, `1503368` generalised over output paths by `901f14d`). `ensure_report()` discarded
  the scan's result and returned `os.path.exists(REPORT)`. Measured: a good jar scanned, the same path then
  replaced by a corrupt one; the scan exits 2, and `candor_effects` kept returning the old jar's
  `Net`/`hosts`/`netClass` for bytecode that was no longer there. The check is now on the invariant (the
  report must be at least as new as the newest class) rather than on the exit code — exit 1 is a gate
  VIOLATION and writes a perfectly good report. `isError` is set on exit ≥ 2 only. candor-java ships no LSP
  surface, and its MCP has no `candor_gate` tool; every tool shells out to the real CLI, so there is no
  second evaluator to skip a withhold path.

- **⟨0.24⟩ `parsepolicy` MUST NOT REFUSE — implementing the class-token rung in the PARSER took the whole
  four-way differential offline** (SPEC §3.1, candor-spec `6929dce`). The refusal below was right for the
  gate and wrong here: this engine put it in `parsePolicy`, so `parsepolicy` exited 2 with **empty stdout**
  on the conformance battery — which carries such tokens deliberately — and the suite **HALTED at PART 4**
  ("FAIL: candor-java parsepolicy errored on the battery"). candor-ts did the same; rust and swift did not.

  The refusal belongs to the gate, which must not enforce a policy it cannot honour as written. It does not
  belong to the witness, whose job is to answer *what did this engine make of my policy?* — most valuable
  exactly when the answer is "not what you meant". So `parsepolicy` now emits its parse **plus an `errors`
  list** naming each unrecognised token, its `kind`, the `accepted` set, and the rule it appeared in, and
  **exits 0** (stderr additionally says the gate will still refuse, so the 0 is not read as a green light).
  The token APPEARS there rather than being dropped: a diff that cannot tell "dropped" (pre-⟨0.24⟩) from
  "rejected" cannot pin this rung. The key is omitted when empty, so a clean dump is byte-identical.

  **The gate is unchanged and that is the risk this carries**, since moving a refusal out of a parser is
  exactly the edit that re-opens the fail-open. Verified after: `gate --report`, `scan --policy`, `whatif`,
  `fix`, `fix-gate` and `unverified` all still exit 2 on `deny Unknown[dispatch,nativ]` and
  `deny Net[known-partner,unkown-host]`, naming the token and the accepted set. An unreadable policy FILE
  still exits 2 from `parsepolicy` too — there is no parse to report. The pair (witness 0, gate 2 on the
  same file) is one test, with a mutation control on each half. 604 tests pass; PART 4 now MATCHes four-way.

- **⚠ ⟨0.24⟩ A certain violation now DOMINATES a refusal — a refusal standing beside a firing rule was
  deleting the violation from the verdict document** (SPEC §3.1). Three outcomes can be live at once and
  the order is **violation (1) > refusal (2) > incomplete (2)**, forced by Lemma 2 rather than chosen: a
  rule that FIRES on evidence the report carries rejects the policy, and `Reject` being upward-closed, no
  resolution of the unanswerable rule could un-reject it. Measured here on a report with one `Fs` unit and
  one inherited reasonless `Unknown`: `deny Fs app` alone gave exit 1 with a document naming the violation;
  `deny Fs app` **plus** `deny Unknown[dispatch] app` gave **exit 2 and no document at all**. Four-way
  agreement, and four-way wrong.

  Rules that cannot be evaluated are now WITHHELD per (rule, function) rather than short-circuiting the
  run, and disclosed on stderr AND in the verdict document under a new **`unevaluated`** key (omitted when
  empty, so every other verdict is byte-identical). The withholding is load-bearing, not tidy:
  `reasonClassesOf` floors an empty class set at `unresolved`, so once the refusal stopped short-circuiting,
  `deny Unknown[unresolved]` over an inherited reasonless `Unknown` began emitting a violation record for a
  class the report never asserted — a fabrication reachable only through this change, and closed by §3.1's
  own minimal-refusal rule. Three rows in `GateReportVerbTest` flip to exit 1, all correctly.

- **⚠ ⟨0.24⟩ A REFUSAL now writes its `--gate-json` document — it used to write nothing, so CI re-read the
  PREVIOUS run's verdict as current** (SPEC §3.1). Measured with a green verdict already at the path: all
  six refusal routes (unanswerable scoped `deny`, `forbid`, `allow`, unreadable policy, unreadable report,
  and the SCAN route's unreadable policy) exited 2 leaving the file untouched. A green file from
  yesterday's clean run is how a refusal becomes an all-clear; deleting the path is not the fix either,
  since a consumer treating a missing file as "nothing to report" fails open by another route.

  The document is fail-closed to a NAIVE reader — `"ok": false` plus `"refused": true` and the reason —
  and it carries **no `violations` key at all**, not an empty array: the gate is making no claim about
  violations, and `[]` is precisely the claim it cannot make. A usage error still writes nothing (the
  command was never a gate invocation).

- **⚠ ⟨0.24⟩ An unrecognised reason-class or Net destination-class token in a policy is now a POLICY ERROR
  (exit 2), not a warning-and-rewrite** (SPEC §6.2). The clause used to justify drop-with-warning on the
  policy side by asserting a dropped token can only WIDEN the rule. Measured, it does both:
  `deny Unknown[corp]` widened to a bare `deny Unknown` **while printing "ignoring policy rule"** — a false
  disclosure — and `deny Unknown[dispatch,nativ]`, a typo BESIDE valid tokens, silently NARROWED to
  `[dispatch]` and stopped gating native-caused holes while the gate still looked armed. That half is
  **fail-open** and it is the common case. End to end, `gate --report` gave **exit 0** on the narrowing
  form and exit 1 on the widening one — two wrong answers from two rewrites of the same one-line policy.

  Both class vocabularies take the rule (the ruling names the reason class; the Net destination class was
  measured to have the identical defect). The diagnostic names the token, lists the accepted set and points
  at `unknown-alias`, from one `Policy.policyFailure` shared by every GATE call site. (`parsepolicy` shares
  the wording but not the posture — see the §3.1 entry above.)

- **⚠ ⟨0.24⟩ POLICY VOCABULARY now anchors at the `--policy` file's directory on BOTH routes — a third file
  could otherwise flip the verdict** (SPEC §3.1). The gate verbs anchored `.candor/config` discovery at the
  policy file while the scan route anchored at the target, so with the policy filed outside the scan tree
  the same rule expanded differently. Measured with `unknown-alias corp = native` beside the policy and
  none beside the target: `scan --policy P` **exit 1** (alias unresolved → rule widened to bare
  `deny Unknown`) vs `gate --report R --policy P` **exit 0** (alias resolved → no match). §3.1's
  byte-equality MUST broken by a file that is neither the report nor the policy; now 0 and 0.

  Target-scoped keys (`deps`, `net-partner`, scan settings) keep anchoring at the target. **`whatif` and
  `fix-gate` never loaded `unknown-alias` at all** and now do, so the pre-edit verbs and the gate cannot
  read the same rule two ways. And the ambience is DISCLOSED: the verdict document carries
  **`policyVocabulary: {config, aliases}`** naming the file whenever a rule referenced a config-supplied
  alias — on a reference, not only on a firing, because the measured harm was a GREEN verdict a vocabulary
  file made green. Omitted when unused.

- **⟨0.24⟩ The `scan --policy` ≡ `gate --report` equivalence test is now a real BYTE comparison.** It
  compared only the violation count and the exit code, which is the weakest reading of a MUST that names
  `analyzed.count`, `reasonClass`, `netClass` and the coverage advisory — and this is the reference engine,
  so those fields were pinned by the newer engines' suites rather than by java's own. Both documents are
  now compared as bytes over 12 policies, with a mutation control inside the test, non-vacuity assertions
  (≥ 4 failing policies; `reasonClass` and `netClass` present in the compared bytes), and verification
  against a real injected drift that the old test passed cleanly. Confirmed byte-equal on a 1432-function
  corpus (candor-java's own fat jar) across 6 policies.

- **⚠ ⟨0.24⟩ A chained dep report with `analyzed.count: 0` no longer buys COVERAGE — "I judged nothing"
  must not read as full coverage** (SPEC §2). A report carrying `functions: []` and `analyzed.count: 0`
  was strictly MORE confident than not chaining the package at all: its caller dropped out of `functions`
  entirely, which under ⟨0.21⟩ is a positive purity claim, with no `invisible`, no `coverage.uncovered`
  and no line on stderr — while the same scan with `CANDOR_DEPS` unset disclosed both. Measured here on a
  two-caller fixture: report entries **2 → 0**, `coverage` **present → absent**, and `deny Fs` **exit 1
  (trusted) → exit 0**. A silent under-report, found four-way by conformance PART 26.

  **The rule lives in `Loader.loadCrossDeps`, beside the §2.1 staleness and ⟨0.21⟩ incompleteness gates**,
  as a third conjunct on the `depCoveredPkgs` registration — the κ-ledger's "whose silence do we trust"
  set, and the one place coverage is granted. It is not in the gate: a gate reads its verdict off a
  coverage decision already made, so putting it there would mean repeating it per verb.

  **The second row is the control, and it is why this is not a one-liner.** `functions: []` is equally the
  shape of an all-pure dependency, whose empty report SPEC §2 chaining rule 3 requires a consumer to
  BELIEVE. Only ⟨0.21⟩'s `analyzed.count` tells the two apart, so the predicate is keyed on that integer
  and never on the emptiness of `functions`; a count > 0 report is untouched, unhedged, still exit 0.
  Blast radius measured over **1997 JVM dependency jars** (deduplicated `~/.m2`): 79 (4.0%) emit
  `count: 0`, of which only **6** actually granted coverage — the other 73 carry no `packages` at all
  (POM-aggregator starters, native-binary and webjar artifacts) — while **104** reports are the legitimate
  all-pure kind and every one of those carries packages. A fix keyed on emptiness would have withdrawn 104
  real claims to catch 6.

  What is withheld is the report's SILENCE, never its entries: a count-0 report has none to withhold, and
  the strictly-additive posture is asserted on an arm that does. `depChainedPkgs` is deliberately NOT
  gated, for the reason recorded at its own registration. Row 3 of the spec's table is a behaviour
  **change**: a manifest-less empty report (a pre-⟨0.21⟩ producer) now falls back to the unchained reading
  too, since nothing on its wire says whether it judged anything. Rows in `StaleDepTrustTest` (both
  controls plus their divergence, mutation-verified in three directions) and `test/smoke.sh`; PART 26's
  CONTROL SEPARATION for java moves from INDISTINGUISHABLE to **SEPARATED on 56/80 cells**, and its
  `empty_zero` waiver from 72 ABSENT cells down to 16.

- **⟨0.24⟩ `--class` now has a VALUE GRAMMAR, and refuses a filter it cannot honour (exit 2)** (SPEC §6.2).
  `--class <c>[,<c>…]` takes ONE comma-separated list and is **not repeatable**; an **unrecognised token**
  is a usage error naming the token and listing the accepted set. Previously `candor unverified --class
  dyanmic` printed "ignores unknown reason-class" to stderr and **exited 0 with an answer document** —
  and so did a repeated `--class`, which silently meant "the last one".

  **Why exit 2 and not the policy side's drop-with-warning, which is where that behaviour came from.**
  The two invert. On the policy side a dropped token leaves a **wider** rule standing, so the gate can
  only over-fire and the failure is loud. Here it leaves a **narrower filter**, so `--class dyanmic`
  silently answers a question the user did not ask, **with a smaller number** — on the one verb whose job
  is to name the holes a green gate is hiding, where a smaller number is indistinguishable from a real
  all-clear. That is the same fail-open the transitive/fail-closed repair above closes, one exit code
  away. A query flag that cannot be honoured is refused, not approximated.

  Parsed once in the argument loop, so it applies to **every** verb taking `--class` (`unverified`,
  `blindspots`) by construction rather than per call site. `dynamic` and `*` are accepted (the diagnostic
  §6.2 prescribes uses `dynamic`, so it must be); an empty value (`--class ""`, `--class ,`) is refused
  too — it names no class, so it selects nothing, which is the narrowest wrong answer of all. Controls in
  `test/smoke.sh` assert both directions per verb: the typo and the repeat exit 2 and NAME what was
  wrong, and `dynamic`, `*` and a comma list still exit 0, so the refusal has not swallowed the values it
  exists to protect. Conformance PART 27 row R5 `value-grammar`.

- **⚠ ⟨0.24⟩ `unverified --class` resolves the reason class TRANSITIVELY and FAILS CLOSED — it used to
  under-report the holes it exists to surface, and under-report MORE the more you narrowed** (SPEC §6.2).
  The filter tested `unknownWhy`, the DIRECT field, which is the wrong field for this question twice over.
  §4 makes `unknownWhy` direct-only *by design* — a reason names a site in the function's own body — so a
  function whose `Unknown` is purely INHERITED carried no reason of its own and matched **no filter at
  all**; and an entry the filter could not classify was DROPPED by every filter, including one naming its
  own class. Measured on the conformance fixture (7 Unknown-bearing entries, hand-written report):
  `--class unresolved` selected **0, now 3**; `--class dispatch` **1, now 3**; `--class reflect` **1, now
  2**; `--class dynamic` — which aliases every genuine class and must therefore exclude nothing on a
  setup-free report — **2, now 7**.

  **The repair is structural, and that is the point.** `unverified` carried an OPEN-CODED SECOND COPY of a
  classification the gate beside it already did correctly, which is the exact defect §6.2 was written
  about ("two implementations of one rule inside one engine, one of them correct, drifting silently
  because nothing compared them"). There is now one: `Policy.reasonClassesOf` / `Policy.reasonClassMatches`
  over `Policy.gateInputFromReport`, called by BOTH the gate's `Unknown[c…]` scoping and this verb. A
  disclosure that contradicts the gate beside it is worse than either being wrong alone — it says your
  gate is green *and* under-reports why you should not believe it.

  **`blindspots --class` is deliberately NOT changed and shares no part of the fix.** §3.1 makes
  `blindspots` the SOURCE view: a unit whose `Unknown` is purely inherited is *defined out of it*, so
  every entry it filters carries a direct reason by construction and the direct-only read is CORRECT
  there. Resolving transitively would pull in exactly the units the verb exists to exclude, turning a
  ranked worklist of root causes into a list of everything downstream of them. One verb's definition is
  the other verb's bug; a shared code path here would have been a shared defect. Measured unchanged on
  the same fixture (2 sources; `--class dispatch` → 1, `--class reflect` → 1).

  **⚠ The verdict change is on `gate --report`, and it is an equivalence repair.** §6.2 requirement (3)
  says a reasonless `Unknown` CONTRIBUTES `unresolved` — gated on the function having a DIRECT `Unknown`
  IT DID NOT NAME, never on its reason set being absent (absence is also what an INHERITED `Unknown`
  looks like, and marking those is the mirror fabrication). `gateInputFromReport` now applies that per
  ENTRY, before the fixpoint, which is what makes it compose: a caller of one reasonless entry and one
  `dispatch:` entry accumulates `{unresolved, dispatch}` and is caught by BOTH filters — the counter-
  example in which ADDING a call turned a red verdict green. Consequence on a hand-authored or foreign
  report: an entry with `direct: ["Unknown"]` and no `unknownWhy` now makes `deny Unknown[unresolved]`
  FIRE (was exit 2, refused) and `deny Unknown[native]` TOLERATE (was exit 2) — which is what
  `scan --policy` already did over the same signature, so refusing had become a divergence between the
  two routes. The answerability REFUSAL is unchanged for the case it was measured on — an INHERITED
  `Unknown` with no `calls` edge to a reason, where nothing in the report bears on the class — and that
  row is now pinned with a fixture that actually builds one (it said INHERITED in a comment while the
  report it wrote said `direct: ["Unknown"]`).

  Both halves verified BY MUTATION: contributing `unresolved` unconditionally turns exactly the two
  mirror-fabrication controls red (an inherited-but-classified caller, and the caller of a reasoned
  source) plus both gate refusal rows; dropping the fixpoint turns exactly the four transitive rows red.
  Note that `--class dynamic` alone survives BOTH mutations — a repair that merely made it converge, by
  keeping everything, would look done — which is why the discrimination control is not optional.
  Regressions: `test/smoke.sh` "== --class reason-class filter (§6.2) ==" (driven through the shipped
  launcher and PARSED — the contract here is an exit code and a JSON document, and a unit test can agree
  with a binary that prints something else),
  `GateReportVerbTest.aReasonlessDirectUnknownContributesUnresolvedRatherThanBeingRefused`, and
  conformance PART 27 rows R1 / R5.

- **⟨0.24⟩ `ambiguous:` is now the FIFTH canonical §4 `unknownWhy` kind, and candor-java recognizes it as
  one** — the analyser's own NAME RESOLUTION was ambiguous (two same-named local definitions), so no owner
  could be formed at all. It is not a `dispatch:` with a missing body (there an owner type *was* formed, and
  the detail is the normative `owner.member`) and not a `callback:` (no function value is involved).
  **No verdict changes**: §6.2 has always projected `ambiguous:*` to class `dispatch`, and this engine's
  gate has always classified it through the string path, so a CONSUMER was already correct — which is
  exactly why nobody noticed the vocabulary it drew from did not contain the kind. What was non-conforming
  was the *typed* half: `UnknownReason.Kind` listed only the old canonical four plus java's two migration
  kinds, so `ambiguous:` read as a foreign prefix, `kind()` was `null`, and `ReasonClass.of` handed back
  `unresolved` where §6.2 says `dispatch`. `AMBIGUOUS` is now a first-class `Kind`, not a tolerated
  exception, and explicitly NOT a migration kind — migration kinds are the ones being reconciled away
  (java's own `task-handoff:`/`indy:`); this one is permanent. `dep:`/`dep-stale:`, which §4 ⟨0.24⟩ now
  REGISTERS, are promoted the same way: `Kind` members with an explicit `classify` branch pinning them to
  `unresolved`, rather than reaching that class by falling through the catch-all.

  candor-java **emits none of the five's `ambiguous:`** — a JVM invoke carries owner+name+descriptor, so
  bytecode name resolution is never ambiguous — but it **consumes** them: a chained dependency's report
  contributes its reasons into this scan (`depTransitiveWhy`), so a candor-rust `ambiguous:` both gates
  here and is relayed into this engine's own `unknownWhy`.

  The control is pinned in both directions: an off-vocabulary `banana:whatever` is still foreign — no
  `Kind`, and the conservative `unresolved` catch-all under §2 forward compatibility — asserted through
  the model *and* end-to-end through `gate --report`, so "learned a fifth kind" cannot be confused with
  "stopped classifying kinds". Regressions: `ReasonClassTest.theFiveCanonicalKindsAndTheTwoRegisteredOnesAreRecognized`,
  `ReasonClassTest.anOffVocabularyKindIsStillForeign`,
  `GateReportVerbTest.anOffVocabularyKindStillClassifiesUnresolvedNotAsTheNewCanonicalOne`.

- **✨ ⟨0.24⟩ `gate --report <locator> --policy <file>` — apply a policy to an EXISTING report, with no
  scan** (SPEC §3.1). Exit codes and `--gate-json` verdict are exactly `candor <classes> --policy <file>`'s;
  the only difference is that `S` and `D` are READ from the report rather than recomputed from bytecode.
  `--json` is `--gate-json -`. Two things this buys, and the second is why the spec makes it a MUST.

  *The supply-chain verb.* Gating a dependency's published report is what an adopter actually wants and
  could not previously express without re-analysing code they do not have.

  *It makes the gate reachable as a function of a GIVEN signature.* `scan --policy` recomputes the effect
  set from source, so the classifier is always in the loop; `whatif` reports only what a hypothetical
  INTRODUCES (a report already carrying `Net` under `deny Net` answers `ok: true`, by design). So a defect
  in the GATE and a defect in the CLASSIFIER were indistinguishable from any test that could be written.

  **The seam.** `Policy.checkPolicy` split into `gateInputFromScan` (the fixpoints that used to sit inline)
  and `Policy.gate(GateInput)` — the only §6.2 matching code in the engine. The report route
  (`gateInputFromReport`) builds the same record from a written report. There is deliberately no second
  copy of the matching: §6.2's ⟨0.24⟩ clause exists because an open-coded copy drifted from the gate
  silently, "because nothing compared them".

  **It reads the report file and NOTHING else** — no `.callgraph.json`, no chained dep, no `.hierarchy.json`,
  no re-classification of hosts/literals through this machine's config. An entry the report OMITS is pure
  (the ⟨0.21⟩ claim), and the test that proves it puts a sidecar naming the absent function AND a chained-dep
  report supplying it AND a `.candor/config` wiring that dep into the one directory the verb does open —
  with the positive control beside it, since a verdict that never fires would pass the negative half alone.
  Verified by mutation: back-filling from the sidecar fails both halves.

  **A rule whose evidence the wire does not carry is REFUSED (exit 2), naming it — never approximated.**
  Approximating always fails OPEN here, and a gate that passes for lack of evidence is the failure the gate
  exists to prevent. Three cases, each measured:
  - `forbid A -> B` needs the full call graph, and a report's `calls` is effect-relevant, so a crossing into
    a wholly PURE unit is invisible in it.
  - `allow <E>` needs the AS-EFF-008 surface-completeness marker, which rides the wire for no effect at all.
    `netClass: unknown-host` LOOKS like it for `Net` and is a different predicate (`netDestClass` returns it
    for any unrecognised host, so a fully-visible `api.stripe.com` carries it). The first cut of this verb
    did reconstruct it that way and the scan-vs-gate equivalence test refuted it in one run: 2 functions
    flagged that the scan passes.
  - ⚠ **A CLASS-SCOPED `deny` over an entry whose evidence is absent.** `deny Net[unknown-host]` reads
    `netClass`; `deny Unknown[dispatch]` reads a reason class resolved transitively over `calls`. Both are
    OPTIONAL wire fields. When absent, the matcher sees an empty set, nothing matches, and the effect is
    **dropped from the violation** — the narrowing succeeds precisely BECAUSE the evidence is missing.
    MEASURED, one function per row: a `Net` entry with no `netClass` gave `deny Net[unknown-host]` **exit 0**
    while bare `deny Net` gave exit 1; an inherited `Unknown` with no `calls` gave `deny Unknown[dispatch]`
    **exit 0** while bare `deny Unknown` gave exit 1. An absence-keyed relaxation of a fail-closed gate,
    inside the newest verb — the exact class ⟨0.24⟩ exists to remove. Now exit 2. Refusing costs nothing on
    a report this engine wrote: `netClass` is emitted for every `Net`-bearing entry and is never empty (the
    derivation floors it at `unknown-host`), and an inherited `Unknown` always has its callee in `calls`
    (the callee carries `Unknown`, so it is effectful). The check is per (rule, function), so a scoped rule
    whose own matches carry their evidence still evaluates.

  Each refusal names exactly what a future format rung must add.

  **Equivalence, measured.** On candor's own 970-function report across 13 policies (6 failing, up to 113
  violations), and on a second fixture built to make the scoped arms non-vacuous across 12 more
  (`Net[unknown-host]` 3, `Net[known-telemetry]` 2, `Unknown[reflect]` 2, `Unknown[dispatch]` 0 —
  discriminating, not blanket), the two routes produce **byte-identical `--gate-json` verdict documents**,
  including `analyzed.count`, `reasonClass`, `netClass` and the coverage advisory. The spec's "a consumer
  must not be able to tell the two apart from the output alone" holds literally, on all 25 rows.

  **Differential against the reference model** (`candor-spec/reference/policy_model.py`), 256 signatures ×
  7 verbs = 1792 rows: `deny Fs`, `deny Fs Unknown[reflect,unresolved]`, `deny Exec Unknown[native]` and
  `pure` agree **exactly** (0 disagreements over 256 points each). Every one of the 100 remaining
  disagreements is a single family — a signature containing `Db`, under a `deny Net` — where the model
  applies PAPER3 Definition 4's refinement preorder (`Db ⊑ₑ Net`) and the engine intersects the denied set
  with `inferred`. Direction is uniform: model REJECT, engine pass. SPEC §6.2's normative `deny` grammar
  has no refinement clause, so this is a MODEL-vs-CONTRACT divergence rather than an engine defect;
  reported upstream, and pinned in both directions here rather than patched, since making `deny Net` fire
  on `Db` would silently tighten every existing policy in the family.
- **⟨0.24⟩ The report-locator globs exclude ALL of §2.2's reserved sidecar segments, from ONE list**
  (`Loader.isSidecarName`, `Query`). This engine carved out `.callgraph.json` and `.hierarchy.json`;
  candor-ts carved out six; the spec now enumerates seven family-wide (`callgraph`, `hierarchy`,
  `calibrated`, `layerreach`, `locs`, `gate`, and the `encountered-*` family) precisely because the engines
  were drifting and nothing said they should not. Cross-engine reading is not hypothetical — the
  conformance frontier differential has one engine produce and another consume — so the drift was a live
  loss, not a spurious warning. MEASURED on a directory holding one real report and two foreign sidecars:
  `candor map` disclosed *"locator … matches 3 reports; using report.asm.gate.json"* — a false ambiguity —
  then picked the sidecar (`gate` sorts before `jvm`, and the resolver takes the lexicographically first
  hit) and REFUSED every query with *"not a candor report: object has no 'functions' array"*, about a file
  the user never named, while the report it wanted sat beside it. Exit 2 and no answer over intact data.
  The reference engine's other two consequences do NOT apply here: this engine reads provenance from the
  report it resolved rather than from the first file by sorted path, and it has no `reports` verb to
  mislist. It stays a DENYLIST over the reserved segment — the inversion (accept only known backends) is an
  allowlist, and a report whose type segment nobody anticipated would become silently invisible to every
  query, a false all-clear; a denylist can only be incomplete, and incompleteness here is loud. The word is
  reserved in the sidecar SEGMENT POSITION, not banned from the name: `report.hierarchy.jvm.json` — a
  package legitimately named `hierarchy` — still resolves, and that control is pinned. Segment COUNT is
  explicitly not the discriminator (it would exclude this engine's own 3-segment sidecars and not a
  2-segment one from another producer); a stale comment claiming it was has been corrected. Both globs plus
  the CANDOR_DEPS directory walk now ask the one predicate, so no two lists can drift apart again.
- **⚠ ⟨0.24⟩ A reasonless `Unknown` CONTRIBUTES `unresolved` to a function's reason-class set — and the
  contribution is made where the `Unknown` is CREATED, not where the gate matches** (`Loader`, `DepFn`,
  `Policy`). The old §6.2 rule keyed on ABSENCE: an empty class set was read as `{unresolved}`. Absence is
  not upward-closed, so acquiring a second, classifiable reason REMOVED the default — and under
  `deny E Unknown[unresolved]` a function calling one reasonless dependency was rejected, a function
  calling one reasoned dependency correctly was not, and **a function calling BOTH was not**. Adding a call
  turned a red verdict green: the silent relaxation `reference/policy_model.py` Lemma 2 forbids. No
  rewriting of the emptiness test could have separated those last two — their class sets were identical, so
  the missing information was not in the class set at all. Reproduced on this engine before it was changed.
  Every in-scan site already records an `unknownWhy` beside the `Unknown` it raises, so the one route that
  reached the state was the DEPENDENCY boundary: a §2.1 distrusted report (effects downgraded to `Unknown`,
  its `fn`/`calls`/`unknownWhy` never even parsed) and any entry whose `Unknown` neither its own tags nor
  its published `calls` chain accounts for. Those entries now carry a synthesized reason of their own —
  `dep:<hash>`, or `dep-stale:<pkg>` for the distrusted producer — recorded per dependency ENTRY at load,
  both projecting to `unresolved` (§6.2's conservative catch-all). Because the reason rides the entry rather
  than the consuming function, a caller of a reasonless entry and a reasoned one accumulates
  `{unresolved, reflect}` with no join-time special case, and the reason travels on to anyone who chains
  THIS report. candor-swift reached the same shape independently; SPEC §6.2 ⟨0.24⟩ now names it normative.
  **Verdict impact, measured, because it is the adoption cost.** With TRUSTED dep reports nothing moves:
  0 class sets changed and 0 verdicts flipped on both measured targets. Under a §2.1 STALE report the new
  rule matches a strict superset — on candor-java's own tree (asm+gson chained, staled) 130 of 145
  `Unknown`-bearing functions' class sets changed and **52 flipped `deny E Unknown[unresolved]` from pass to
  reject**; on asm-commons (asm+asm-tree chained, staled) 311 of 311 changed and 2 flipped. Those flips are
  the counterexample row: a function that already carried a classified reason and ALSO reached an
  unaccounted-for `Unknown`. The condition is what makes this a fix and not a flood — contributing on the
  presence of an `Unknown` rather than on the absence of an accounting flips 96 of 141 and 211 of 211 on the
  same two targets with FRESH reports, where the correct rule flips none. Both directions are pinned
  (`ReasonlessUnknownContributesTest`), including a fresh-dep arm whose `Unknown` the dependency's report
  explains — through its own tag and through a `calls` edge — and which must NOT be marked.
- **⟨0.24⟩ The frontier's `viaDispatchOn` join sorts by UNICODE CODE POINT, not by UTF-16 code unit**
  (`Query`). One function carrying several `dispatch:` reasons gets one entry whose `viaDispatchOn` is the
  sorted, deduplicated, comma-joined union of the dispatched members and the raw dot-free details — and the
  spec pins the collation, because the natural implementation differs per language and two engines must not
  drift on a field neither of them re-parses. Rust's `BTreeSet<&str>` gives code-point order for free;
  java's `TreeSet` used NATURAL String ordering, which is `String.compareTo` — UTF-16 code unit — agreeing
  on ASCII and disagreeing above the BMP, where a supplementary character sorts as if it were below every
  BMP character from `U+E000` up. Reachable rather than theoretical: the dotted form is `<owner>.<member>`
  built from user identifiers, and all four analysed languages permit non-ASCII ones. Now an explicit
  code-point comparator. Deliberately NOT `getBytes(UTF_8)` compared unsigned, which is the shorter spelling
  of the same order but is lossy on an unpaired surrogate (all of them encode to `?`) — a `TreeSet` reads
  `compare == 0` as a duplicate, so two distinct details would silently collapse to one, reintroducing the
  drop class this rung exists to close. Both hazards pinned: the ordering test uses `U+1D400` against
  `U+FB00` (the two orders disagree, so it fails under natural ordering) and the collapse test fails under
  the byte comparator. All-ASCII output is byte-identical.
- **⟨0.24⟩ A DOT-FREE `dispatch:` detail is DISCLOSED on the `callers --include-unknown` frontier, not
  dropped** (`Query`). A detail with no dot (candor-rust emits `dispatch:untyped cross-package receiver`
  when no owner type could be formed at all) names no `OWNER` and no `M`, so condition (3) — "is a
  confirmed reacher an override of `OWNER.M`?" — is UNANSWERABLE. `simpleMethod`/`declaringType` both fall
  back to the whole string when there is no dot, so the lookup missed and the entry vanished. MEASURED on
  a report carrying one dotted and one dot-free source: the frontier listed only the dotted one, in BOTH
  the hierarchy and the no-hierarchy arm, with no diagnostic naming the dropped one. An unanswerable
  condition must not be scored as a failed one — the entry is now listed with `viaDispatchOn` set to the
  RAW DETAIL verbatim, the same direction the no-hierarchy fallback already takes one rung up. Detected
  structurally (no dot before any descriptor), not by matching a known wording: an allowlist of strings
  would silently drop every wording it did not enumerate, which is the defect itself. The frontier
  over-lists by construction and asserts nothing into `transitive`, so a spurious entry costs precision
  while a dropped one is a false all-clear on the query.
- **⟨0.7⟩ An EMPTY hierarchy sidecar is now the same input as an ABSENT one** (`Query`). The guard was
  `hier == null`, so a sidecar that exists and parses to `{}` was honoured as a real hierarchy:
  `isSubtypeOf` then failed for every type, condition (3) failed for every dotted source, and the whole
  frontier collapsed to `[]`. MEASURED on the same report: sidecar absent → one entry disclosed, sidecar
  `{}` → nothing disclosed at all. `{}` is not the claim "no type has a supertype" — it is the hierarchy
  pass finding nothing, not running, or writing a stub — so scoring condition (3) as failed on it turns a
  disclosed over-list into a silent empty answer a consumer reads as "no function may reach the target
  through an unresolved dispatch". candor-rust (`has_hier`) and candor-ts (`hasHier`) already treated empty
  as absent; java now agrees. Both rungs pinned by `QueryIncludeUnknownTest`, with controls: a dotted
  dispatch that genuinely fails the subtype test, and a function carrying no dispatch reason, must both
  still be OUT.
- **⚠ ⟨0.7⟩ The type-hierarchy sidecar records WHICH supertype is the superclass** (`ReportWriter`,
  `Loader`, `Cha`, `Query`). `writeHierarchy` wrote a sorted set and threw the kinds away, so a chain lying
  ENTIRELY inside a chained dependency stayed depth-ordered at the consumer and the JLS 15.12.2.5 / 8.4.8
  rule `9f8e71c` implemented — a concrete method inherited from a superclass beats an interface `default`
  at any depth — could not be applied to it. A dep interface `default` therefore shadowed a dep superclass
  body two hops up: both halves of the honesty invariant at once, the real effect dropped AND the
  interface's charged in its place. The sidecar now also carries `"@superclass"`, a sibling key holding a
  FLAT `[type, superclass, …]` array; its PRESENCE is what tells a consumer the kinds are known, and a
  sidecar without it keeps exactly the depth-ordered answer that shipped rather than a guess — reading an
  unmarked list as all-interfaces would push a real superclass below an interface and manufacture the very
  under-report the ordering exists to close. No version gate on either side. ⚠ a chained consumer may newly report the
  superclass body's effects instead of an interface default's — an effect can APPEAR (the under-report) and
  one can DISAPPEAR (the fabrication that replaced it). Measured on 7 chained real jar pairs: 125 of 2 702
  dependency-hierarchy resolution orders change (4.6%; logback-classic 65, httpclient 23, httpclient5 21,
  spring-beans 16) and 2 214 dep types load with a known split — with **0 report changes**: 0 gains, 0
  losses, identical entry and Unknown counts, every dep report byte-identical apart from its build id. The
  fixture is the evidence and the corpus is the fabrication control. `Query.loadHierarchy` was the SECOND
  reader of this file and did NOT skip non-array values — it threw, swallowed it into `return null`, and
  discarded the whole hierarchy, dropping the dispatch frontier to a simple-name match. Fixed with it.
- **⚠ The sidecar's compatibility rule is now a WRITER constraint: every value in it is an ARRAY of
  strings, metadata lives under a `@`-prefixed key, and a metadata key is never the file's only key**
  (`ReportWriter`, `Loader`, `Query`; SPEC §2.2 restated with it). The rung above shipped `"@superclass"`
  as an OBJECT on a reader-side argument, and that argument was false of TWO of the sidecar's three
  readers. The third is in another language and had not been looked for: candor-rust's
  `candor-query::load_hierarchy` deserializes the whole file as `BTreeMap<String, Vec<String>>` in one
  typed call and DROPS IT ENTIRELY when that fails — a strictly typed reader cannot skip anything, and
  `--report <a java report>.json` is a supported route into it. Measured on 7 chained real jar pairs: **0
  of 18 sidecars parsed there** before, **18 of 18** now (3 553 type keys), and over 28 real
  `callers --include-unknown` targets the disclosed frontier falls **1 086 → 983** as the precise subtype
  test comes back. Both marker shapes are read, so a 0.23.1-written dep sidecar keeps its split.
  Separately, the key was written UNCONDITIONALLY, so a sidecar that serialized as `{}` became
  `{"@superclass":{}}` — and candor-ts (`Object.keys(h).length > 0`) and candor-rust (`!hier.is_empty()`)
  both take the PRECISE dispatch frontier iff the map is non-empty, so a key carrying nothing flipped them
  off the documented over-listing fallback onto a walk over an empty hierarchy and withdrew a disclosure.
  It is now omitted iff the sidecar names no type — where a consumer reads it exactly zero times — and
  never merely because it holds no pair, which is a fact a consumer needs. 0 gains / 0 losses / identical
  entry and Unknown counts on both A/Bs; the split count (1 128 dep types) is identical under both
  encodings read by one consumer, which is what says the re-encoding is lossless rather than inert.
- **⚠ ⟨0.21⟩ A chained report that DECLARES ITSELF INCOMPLETE no longer grants coverage** (`Loader`).
  SPEC §2 rule 3 turns a report's silence into a purity claim; a report carrying a non-empty `unanalyzed`
  has just said it never read some of its own source, so its silence about that source answers nothing —
  and it was still registering full coverage for its packages. Chaining it was strictly WORSE than not
  chaining it: the dependency's own scan refuses to certify a gate over unanalyzed code (exit 2) and the
  consumer certified one on its behalf. The same door `7e41327` closed for a report failing the §2.1
  version check, with a different key; candor-ts closed it first (`21277eb`) and this is the JVM half.
  The TREATMENT differs from staleness and that difference is the point: a stale report's entries are
  assertions from a build we do not trust and are downgraded to `Unknown`; an incomplete report's entries
  were derived from source it DID read and are kept **unchanged**. Only the silence hedges — strictly
  additive, no effect is ever removed, and the half-1 `Unknown[dispatch:…]` disclosure still fires
  alongside the ledger hedge rather than being replaced by it. An absent or explicitly empty `unanalyzed`
  is a completeness claim; anything else, including a malformed value, fails closed. The reason is
  printed on stderr. ⚠ a chained consumer may newly carry `invisible: [pkg]` where a dependency's report
  is incomplete, and functions that were absent from the report may appear carrying only that hedge;
  regenerate baselines.

- **⚠ A dep report ENTRY's package was parsed out of the method DESCRIPTOR** (`Loader.entryPackage`). The
  entry-level fallback — the only package registration a chained report with no `package`/`packages`
  envelope gets — took the last `/` in the whole hash, and this engine's hash is
  `owner/Class.method(Ljava/lang/String;)V`, so for every method taking or returning a reference type that
  last `/` landed inside the descriptor: `com.example.Svc.save(Ljava.lang`. It could not FABRICATE
  coverage (the bogus name necessarily contains the descriptor's `(`, which no package name can, so it
  matched nothing), but the registration that never happened cost a disclosure: `depChainedPkgs` is
  conjunct 3 of the half-1 unanswerable-key rung, so an INVOKEINTERFACE into a chained dependency whose
  implementation candor cannot name read as a confident purity claim and `deny Fs Unknown[dispatch]` sat
  at exit 0 against a single-tree control that is exit 1 in both arms. The `pkg#qual` (Rust/TS) branch of
  the same two lines was always exact, so this makes one hash form behave like the other rather than
  introducing a policy. ⚠ a chained consumer of a package-field-less report may newly disclose
  `Unknown[dispatch:…]`, and may stop emitting `invisible` for a package that report does cover.

## [0.23.1] — 2026-07-20

A performance + classifier-soundness patch (spec unchanged at **0.23**). The analysis engine loses two
super-linear cliffs (both output-preserving), a model-SDK over-classification is fixed, and a follow-up
review closed a silent under-report that the first cut of that fix had opened.

- **Performance — the analyze pass is no longer super-linear in class count.** `Cha.chaTargets`
  (class-hierarchy dispatch resolution) is a pure function of the fixed post-load hierarchy, but it was
  recomputed from scratch at every call site that dispatches a given method on a given declared type —
  so its cost (CHA fan-out × superchain walk) compounded as both call sites and hierarchy depth grew.
  Memoizing it by `(owner,name,desc)` flattens the curve from ~2.7 ms/class to ~1.0 ms/class: a
  4585-class corpus scans in 4.4s vs 12.5s (**2.85× faster**), with report output verified byte-for-byte
  identical (it is a cache, not a semantic change). Interactive edit-time scans were already fast; this
  is the batch/large-repo lane. Only the `java -jar`/native analyze pass — no gate or report change.
  A follow-up pass on the reporting stage (`Surface.nearestSource` BFS: pre-sort each function's callees
  once instead of at every BFS node; `HashSet` for the visited set) takes the same corpus to 3.3s —
  **3.77× over the original** end-to-end — again byte-for-byte identical.

- **Performance — the propagation fixpoint is no longer O(V²) on deep call chains.** `computeFixpoint`
  re-swept every caller on every pass, so its pass count equalled the longest back-to-front call chain —
  O(V²) on deep whole-program graphs (a controller→service→repo→… layering, or generated code). Replaced
  the sweep with a worklist over a callee→callers reverse index: a function is reprocessed only when a
  callee actually gained an effect. Same monotone least fixpoint → **output byte-for-byte identical**
  (verified across the library corpora and a 4000-deep synthetic chain; `FixpointTest` + full suite green).
  ~1.8× on a 12000-deep chain, growing with depth; shallow corpora unaffected. Mirrors the equivalent
  worklist fix in the Rust engine.

- **⚠ Llm model-SDK precision — a builder/constructor no longer fabricates `Llm`+`Net`, WITHOUT opening an
  under-report.** The ⟨0.13⟩ model-SDK surface fired on *any* call into a curated provider package, which
  over-classified pure construction (`new OpenAiService(...)`, Spring AI's fluent `cc.prompt().user(..)`
  read `['Llm','Net']` though they dispatch no request). A constructor (`<init>`) is now excluded, and the
  Spring AI ChatClient fluent *builders* are carved out by a **denylist** (`SPRING_AI_CHATCLIENT_BUILDERS`)
  layered over the retained `org.springframework.ai.` blanket — so every real dispatch (chat, **streaming
  terminal**, **`EmbeddingModel.call`**, and anything not explicitly listed as a pure builder) still
  classifies `Llm`+`Net`; a builder we forget to list merely over-reports (safe), never silently drops an
  effect. (The first cut narrowed dispatch to an allowlist and silently under-reported streaming/embedding
  calls — caught in review and corrected before release; regression anchors `springAiChatClientStream` +
  `springAiEmbeddingCall` now pin it.) Closes the two `kappa_libs_probe` fabrications
  (`openaiServiceBuilderPure`, `springAiPromptBuilderPure`).

## [0.23.0] — 2026-07-20

Spec floor → **0.23** (the cross-package interface-dispatch rung; report/verdict schema unchanged). This
release folds in a large classifier-soundness wave driven by the *reconcile-against-reality* loop — running
the transitive `candor verify` oracle against Apache commons-`dbcp2`/`compress`/`vfs2` to surface real silent
under-reports on code we did not write, then fixing the classifier — plus a value-provenance precision layer
and an oracle refinement. All changes are soundness-increasing (§4 trust contract) and regression-gated.

- **⚠ super-call through a generic intermediate superclass** now propagates the inherited method's effect
  (was silently dropped — dbcp2 pool-lifecycle `Clock`).
- **⚠ opaque callback → synchronous invoking HOF** (`forEach`/`forEachRemaining`/`ifPresent`, matched
  owner-agnostically so `List.forEach` is covered) discloses `Unknown` — the four-way sync-callback rung
  (conformance `sync_callback_opaque`).
- **⚠ filter/buffered stream `read`/`write`/`skip`/`flush`/`close`** that delegates to a wrapped sink of
  unknown type discloses `Unknown` (compress/vfs2 Monitor/Filter streams).
- **⚠ `AccessController.doPrivileged(action)`** now runs its `PrivilegedAction`/`PrivilegedExceptionAction`'s
  `run()` — the wrapped effect no longer orphaned (vfs2 `PrivilegedFileReplicator`).
- **⚠ value provenance**: a stream-consuming utility (`IOUtils.read`/`copy`/…, Guava streams) that reads a
  stream the method did not itself open discloses `Unknown`; whole-program, a project stream field proven
  bound only to in-scope concrete opens stays precise (construction-carried suppression). Closes the
  `readFully` class as honest disclosure without abandoning the source/sink stance.
- **`candor verify` oracle — coverage crediting**: transitive attribution stops once the stack walk crosses
  an *unanalyzed* frame, so it no longer false-positives on a library's unmodelled-dependency effects (sound,
  zero masking — keys on analyzed-set membership, not string prefixes; a credited frame is disclosed via the
  coverage envelope, not a silent green).
- **cross-package interface dispatch** (interfaceUnion, spec 0.23): a chained interface method resolves to the
  impl's effect across packages.
- Four soundness bugs in the new analysis code, found by adversarial code review, fixed + regression-pinned.

## [0.22.0] — 2026-07-18

Spec floor → **0.22** (the `verify` oracle rung; report/verdict schema unchanged from 0.21). candor-java folds in
a `candor verify` (JVM `-javaagent`) fix: the agent's overload-key pre-pass no longer counts compiler-generated
**synthetic bridge** methods, so a generic/covariant override (e.g. `executeTask(T)` beside the erased
`executeTask(Object)` bridge) keys the same bare name the report uses — closing a spurious cardinal-sin
false-positive that misfired on any generic task/visitor/callable/comparator override. Found on the public corpus
(zip4j's integration suite). Verify-only; report and verdict bytes are unchanged.

⚠ **`candor verify` agent transparency fix — the instrument no longer perturbs the program under test.** The
`-javaagent`'s `EffectTransformer` built its `ClassWriter` with `COMPUTE_FRAMES`, whose `getCommonSuperClass`
resolves supertypes by **class-loading the application's types mid-transform**; force-loading a class whose
supertype is being defined on the same loader raises `LinkageError: attempted duplicate class definition`. On
Apache **commons-io**'s `FileUtilsTest` this broke **194/195** tests — the oracle crashing the code it is meant to
observe. The `Trace.emit` injection is frame-**neutral** (it pushes two constants and pops them via the call — no
branch target, no local), so the javac-emitted stack-map frames stay valid and need no recomputation: the writer
now uses `COMPUTE_MAXS` only, eliminating all mid-transform class-loading. This is strictly better than both prior
states (no crash, and no silent skip of classes an earlier `getCommonSuperClass` couldn't resolve). Found while
measuring the agent's runtime overhead on a real suite (≈1.02× / +2.4 % on commons-io's filesystem tests);
regression-gated by `VerifyOracleTest.agentDoesNotBreakClassLoadingViaFrameRecomputation` (a fixture whose
control-flow merge is over its own subclasses — the minimal reentrancy trigger, confirmed to fail under the old
`COMPUTE_FRAMES` build). Verify-only; report and verdict bytes are unchanged.

⚠ **Classifier: a java.io FILTER-stream `close`/`flush` no longer reads silent-pure** — the runtime oracle found this on Apache commons-compress. A `FilterOutputStream`/`FilterInputStream`/`FilterReader`/`FilterWriter` `close`/`flush` DELEGATES to a wrapped stream of unknown concrete type (reached e.g. via `super.close()` from a filter subclass), performing the actual write/close syscall on a sink candor cannot resolve — so it now reads **`Unknown`** (disclose, never fabricate `Fs`: the wrapped sink may be in-memory). candor already caught the file *open* at the concrete ctor (`new FileOutputStream`); this closes the deferred-*close* half. Conformance-clean; +10 `Unknown` on commons-compress (modest — the pattern is filter-subclass-close, not ubiquitous). Resolves 2 of the 4 commons-compress finds (`CompressFilterOutputStream.close`, `ZipArchiveOutputStream.destroy`). Regression: `StructuralDispatchTest.filterStreamCloseDelegatesToUnknownWrappedSink`.

⚠ **Classifier: an OPAQUE callback handed to a SYNCHRONOUS invoking HOF (`Iterator.forEachRemaining`, `Stream.forEach`, `Optional.ifPresent`, `Iterable`/`Collection`/`Map.forEach`) no longer reads silent-pure** — the runtime oracle found this on Apache commons-compress. candor already disclosed `Unknown` for an opaque task handed to an *executor* (`es.submit(param)`), and edged an *inline* lambda/method-ref (its body captured at the indy) — but an opaque (field/param) `Consumer` handed to a *synchronous* invoking HOF was neither edged nor disclosed → the caller read pure though the HOF invokes the callback for its effect. The `opaqueTaskHandoff` disclosure now also fires for these synchronous invokers (`Rules.SYNC_CALLBACK_INVOKERS`), covering the JDK types and commons-io's `IOIterator.forEachRemaining(IOConsumer)` / `IOStream.forEach` (the exact shape `ArchiveInputStream.forEach` uses). Only OPAQUE args are affected — an inline lambda or a freshly-constructed impl keeps its edged effect (no over-disclosure); full conformance suite green. Regression: `StructuralDispatchTest.syncCallbackInvokerOpaqueArgReadsUnknown`. ⚠ may add `Unknown` to a function passing an opaque callback to such a HOF.

⚠ **Classifier: a `super.method()` call to an effect through a GENERIC intermediate superclass no longer reads silent-pure** — the runtime oracle found this cardinal-sin vein on Apache commons-dbcp2. A super-call compiles to `INVOKESPECIAL owner=<direct superclass>`; when that class does not *declare* the method (it is inherited from higher up — e.g. `PoolableConnection extends DelegatingConnection<Connection> extends AbandonedTrace`, `super.setLastUsed()` → owner `DelegatingConnection`, which inherits `setLastUsed` from `AbandonedTrace` where `Instant.now()` is the `Clock` leaf), candor edged to `owner.method` — a **non-existent node** — so the callee's effect was silently lost and the caller read `pure` (not even `Unknown`). The special/static edge now resolves to the nearest superclass that actually declares the method (via `nearestConcreteSuper`, the same resolution the virtual path uses), falling back to the raw owner when it declares the method itself or the target is external. Fixed 5 of 7 silent Clock under-reports the `candor verify` oracle caught on commons-dbcp2 (the remaining 2 are the harder `_pool.borrowObject → activateObject` framework-callback (A3) class). Regression: `StructuralDispatchTest.superCallThroughGenericIntermediateSuperclassPropagatesEffect`. ⚠ may add a previously-missed effect to a function that made such a super-call.

⚠ **`candor verify` now attributes effects TRANSITIVELY — the oracle falsifies candor's core (transitive) claim, not only leaf classifications.** candor's report is transitive (a function that *reaches* an effect is effectful); the shipped oracle, however, attributed each runtime effect only to the *direct* enclosing method (`Trace.emit(enclosing-fn, effect)`, a transform-time constant). It was therefore **structurally blind to a transitive cardinal sin**: a caller that reaches an effect through a dropped/dynamic edge and is reported `pure` was never tested (the effect landed on the leaf; the caller's observed set was empty ⇒ vacuously held). Demonstrated minimally — seed `middle` (a caller of an `Fs` leaf) as pure and the old oracle reported **0 violations, holds**. `Trace.emit(effect)` now walks the live stack and attributes the effect to the enclosing method **and every analyzed caller on it**, exactly matching candor's transitive report, so a caller-level miss is caught (`app.Main.middle: ran {Fs} but declared {pure}`). Overload-correct: `EffectTransformer` registers each analyzed method's runtime stack key (`owner#name#descriptor` → candor qual) at transform time, since a bare stack frame carries no overload descriptor for the qual. Effect: on Apache commons-io's filesystem suite the oracle now checks **133 functions (was 30)** — the transitive callers, not just the I/O primitives — and still holds with **0 cardinal-sin violations, attribution-complete**. This reintroduces a per-leaf stack walk (the transform-time constant is gone), so verify's runtime overhead rises above the direct mode's ≈1.02×; verify is a test/CI-time falsifier, so correctness (testing the claim candor actually makes) is the right trade. Regression-gated by `VerifyOracleTest.transitiveCallerMissIsCaught`.

⚠ **`candor verify` fails closed on a non-clean `--run`.** A `--run` command that exits non-zero (a crash, or a
failing test suite) may have produced a *partial* trace, so a clean all-clear cannot be certified over it: verify
now adds it to the attribution-gap set (`attributionComplete=false`, **exit 2**), the same posture already used for
a torn trace or a missing callgraph — no more green `exit 0` over a run that did not complete. The honesty invariant
still HOLDS on what *was* witnessed; only completeness is withheld. New **`--allow-run-failure`** flag opts out for a
suite with *expected* failures (effects still fully exercised): the verdict is kept and the non-zero exit only
disclosed (`programExitCode` in `--json`). Previously the child exit was disclosed but never affected the verdict.
Regression-gated by `VerifyOracleTest.nonZeroRunExitFailsClosedUnlessAllowed`.

## [0.19.0] — 2026-07-17

Reason-scoped `Unknown` policies (SPEC §6.2, the reference): `deny E Unknown[reflect,dispatch,indirect,native,unresolved,setup]`
narrows the `Unknown` part of a deny to a fixed reason-class vocabulary (`model.ReasonClass`) projecting the §4
`unknownWhy` reasons, with the `dynamic`/`*` aliases and config `.candor/config` `unknown-alias <name> = <class…>`
names. Bare `deny E Unknown` is unchanged (`Unknown[*]`); an unrecognized reason maps to `unresolved`; the class
propagates transitively (the gate classifies via the string `classify(format())` path, four-way-identical). An
AS-EFF-006 `--gate-json` verdict whose `effects` include `Unknown` carries a **`reasonClass`** array. Report
bytes unchanged. Also ships the **disclosure-completeness battery** (`DisclosureCompletenessTest`) — one fixture
per edge kind asserting resolve-or-disclose (never silently pure). Conformance PART 4 + PART 12 pin it four-way.

## [0.18.0] — 2026-07-16

### spec 0.18 — the trust-trio

candor-java now declares **spec `0.18`** (`SPEC_VERSION`). A pinned-tool-surface rung (no report/verdict
change), closing three ways the tool could quietly mislead — all pinned four-way in the conformance suite:

- **`--strict` advisory-verb CI gate**: `fix-gate`, `gains`, `unverified` are advisory (exit 0); `--strict`
  makes each a CI gate (exit 1 while a finding remains). `gains` rejects a swallowed `--policy` (exit 2),
  naming the scan-time `deny <E> gained` gate (`AS-EFF-005`).
- **mostly-Unknown disclosure**: the scan opener + `tour` never say "nothing hidden" over a ≥⅓-Unknown graph;
  `tour --json` carries an additive `unknown: {count, total}`.
- Hardening from a Fable-model code review: `rejectUnknownFlag` now rejects single-dash typos (`-strict`),
  matching the other engines.

## [0.16.0] — 2026-07-16

### spec 0.17 — the callgraph-aware baseline guard

candor-java now declares **spec `0.16`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
The ⟨0.16⟩ rung closes the sharpest supply-chain shape in the baseline regression guard and softens the
Unknown trust marker from a regression into an advisory.

- **⚠ Callgraph-aware existence — pure→effectful is now caught.** Reports OMIT pure functions (§2), so a
  formerly-PURE function that turns effectful used to read as "new code" and escape the guard. The guard
  now keys existence on the baseline CALLGRAPH sidecar (§2.2 — it lists pure leaves), exactly as `gains
  --json`'s `origin` does: a fn that is a graph node (even with an empty baseline effect set) and now
  performs ANY effect is a GAIN → AS-EFF-005 violation (exit 1). A fn genuinely absent from the graph is
  real new code → exempt. **Verdict-affecting**: a baseline whose sidecar is present may now fail a gate
  that previously passed — regenerate baselines (a file-mode `--json` emits the `.callgraph.json` sidecar)
  and review policies.
  - **Sidecar ABSENT** → the guard degrades to report-only existence (the pre-⟨0.16⟩ semantics: a
    formerly-pure fn reads as new; widening on already-effectful fns is still caught), disclosed once on
    stderr. Never a silent narrowing — you are told the guard is weaker.
  - **Sidecar PRESENT-but-corrupt** → fail closed (exit 2), same as a corrupt baseline report: a broken
    sidecar must not silently narrow the guard.
- **Unknown-only gain is advisory, not a regression.** A function whose ONLY gain vs the baseline is
  `Unknown` (the §4 trust marker, not an effect) is dominated by resolution noise on real dependency bumps
  (dispatch-resolution variance; positional `$N` anonymous-class names differ across versions —
  SOUNDNESS-LOG 2026-07-16), so it is collected and disclosed once, never raising AS-EFF-005 or exit 1. A
  mixed real+Unknown gain still fires on the REAL boundary effect, and the violation reports the
  Unknown-filtered gained set (so `Unknown` never surfaces in a violation).

## [0.15.0] — 2026-07-15

### spec 0.15 — the coverage envelope

candor-java now declares **spec `0.15`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
The ⟨0.15⟩ rung is the COVERAGE-DESIGN.md surface, reference-implemented here: the κ-coverage ledger —
"what the scan couldn't see" — now travels WITH the artifacts instead of evaporating on stderr, computed
the ONE shared way (`Candor.kappaUncovered`) feeding stderr, envelope, and gate so the surfaces can never
disagree. Pinned by conformance PART 4s.

- **Report envelope `coverage` field** (§2, additive): `"coverage": { "uncovered": [ { "name", "calls" },
  … ] }` — the same names and counts as the per-scan stderr disclosure (which is unchanged). **Omitted
  entirely when nothing is uncovered**, so a fully-covered report is byte-identical to one from a prior
  jar (verified against the 0.13 build). Per-function `invisible` now derives from the same ledger, so
  the envelope and the per-function view can never disagree either.
- **`--gate-json` coverage advisory**: the verdict gains an OPTIONAL `"coverage": { "uncovered": N,
  "packages": […] }` when the ledger is non-empty. **VERDICT-PRESERVING** (the ⟨0.9⟩ provable-purity
  auto-disclosure precedent): `ok`/`violations`/exit are untouched — uncovered deps never fail a gate;
  `deny Unknown` remains the opt-in strict posture. Omitted when fully covered.
- **`gains` re-disclosure**: `gains --json` carries the CURRENT report's envelope `coverage` verbatim
  when present, plus `"coverageDelta": { "nowUncovered", "noLongerUncovered" }` when the baseline's
  uncovered NAME set differs (a dep becoming uncovered between scans is itself a signal) — the reference
  shape for the family. JSON-only — the human TSV is a pinned consumer surface and stays byte-stable;
  exit still always 0.

### Literal-head host extraction from runtime concat

A URL built by RUNTIME string concatenation whose literal LEFT completes the authority
(`new URL("https://api.openai.com/v1/" + p)`) now recovers the host from the bytecode and fires the §1
Llm/Db/Net refinement (was bare Net). Handles both javac concat shapes: `makeConcatWithConstants` (the
indy recipe's literal prefix) and the classic StringBuilder append chain. (`static final String` consts
were already inlined by javac, so those were already sound.) Sound boundaries: a split authority, an
interpolated port, or a dynamic head stay bare Net — no fabrication. Pinned by conformance PART 4r.
**⚠ a refinement-affecting change** — a runtime-concat model/db URL that previously read bare `Net` may
now read `Llm+Net`/`Db+Net`; a policy denying those boundaries can newly fire (in the
soundness-increasing direction).

## [0.14.0] — 2026-07-14

### spec 0.14 — floor alignment (the top-level-initializer rung)

candor-java now declares **spec `0.14`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
This is a **floor-alignment-only** bump — **no engine behaviour change**. The ⟨0.14⟩ rung is a
cardinal-sin fix in the ts/swift engines: a module's **top-level / static-initializer effects were
silently dropped as false-pure**. candor-java is the **REFERENCE** for this rung and is already sound —
it attributes a static initializer's effects to a `<clinit>` unit (and constructor effects to `<init>`)
with `unitKind: "initializer"`, which is exactly the fixture behaviour candor-spec's conformance PART 4p
pins. So candor-java needs no code change; it raises its declared `spec` string to keep the family floor
uniform. **Reports and `--gate-json` verdicts are byte-identical to 0.13** — only the `spec` field reads
`0.14`. See the candor-spec `0.14` entry for the rung. **⚠ the `spec` string changed** — a consumer
pinning `spec == "0.13"` must accept `0.14`.

## [0.13.0] — 2026-07-14

### spec 0.13 — the `Llm` effect

candor-java now declares **spec `0.13`** (`SPEC_VERSION`; the envelope + `--gate-json` verdict carry it).
0.13 is a **tier-2 (pinned-tool-surface) rung** (candor-spec §"Conformance tiers"), and this is the
**REFERENCE implementation of the `Llm` effect** — the reference engine leads the rung; the family floor
rises as the siblings land it. `Llm` is a **§6.1 boundary effect that refines `Net`** the way `Db` does: a
model-provider call IS network I/O, so it keeps `Net` and adds `Llm` on top — it contains (via
`isBoundary`), scores in the effect breakdown and salience (the sharp 5-set), and takes policy verbs like
any boundary. Two classification sources feed it:

- **A shared model-host table (`Literals`).** A `Net` call whose host is a known model endpoint is refined
  to `Llm+Net`. The table is hooked into all three host-capture points; it includes the major hosted
  providers and Ollama on loopback `:11434` (a model host on `localhost`/`127.0.0.1`/`::1` only — a plain
  host on that port is not assumed to be a model). Host-predicate rules are first-label matched, not
  substring (e.g. Bedrock matches the `bedrock-runtime`/`bedrock-agent-runtime` inference services, not an
  unrelated host that merely contains the string `bedrock`).
- **A curated JVM model-SDK surface (`Rules`).** The client entry points of the mainstream JVM model SDKs
  — AWS Bedrock runtime (v1 + v2), langchain4j, openai-java, Spring AI, and Vertex AI / GenAI — classify to
  `Llm+Net` at the call.

The policy grammar gains `Llm` as a first-class token: **deny `Llm`** gates a layer off model access,
**allow `Llm`** certifies it against the host literal, and a **masked / non-literal model host fails
closed** (AS-EFF-008) — a model call reached through an opaque host cannot certify. New `LlmEffectTest`
plus `ModelTest` count bumps; the effect enum, containment, salience, and policy paths are all covered.
**⚠ the `spec` string changed** — a consumer pinning `spec == "0.12"` must accept `0.13`. The report
schema is otherwise unchanged: a codebase with no model calls produces a byte-identical report under 0.13.

### Changed

- **The `gains` baseline union is engine-owned.** `resolveReportLocatorAll` now filters sibling expansion
  to `.jvm.json` (plus the exact `<prefix>.json` single-file form), so a FOREIGN engine's callgraph sidecar
  can no longer serve as existence evidence and mint `origin: "new"` where `"unknown"` is correct (a
  foreign engine's quals are systematically absent from a JVM graph). The empty-union fallback that could
  have resurrected a foreign base path is gone.

## [0.12.0] — 2026-07-14

### spec 0.12 — the gains `origin` rung

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
