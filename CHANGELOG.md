# Changelog

All notable changes to candor-java are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); candor-java is pre-1.0, so minor versions may
include behavioural changes (always in the soundness-increasing direction — the §4 trust contract).
**⚠ marks a verdict-affecting change** — a gate/guard/report that was green may read differently
after upgrading; review policies and regenerate baselines with the new build.

## [Unreleased]

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
