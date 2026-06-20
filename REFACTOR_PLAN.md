# Plan — refactor candor-java's monolith into a navigable model

`Candor.java` is **6522 lines / 220 static methods / ~50 shared mutable static fields** (+ `Query.java` 1193).
Two giants dominate: `classify()` (1800 lines — the κ effect-leaf table) and `analyze()` (790 lines — the core
per-method dataflow loop). The κ sweep is mined out (table stable) → **now is the right time** (no active κ
churn to collide with).

## The hard constraint (read first)

candor has a **binary-identity self-guard**: CI scans candor ITSELF and requires an in-process re-scan to be
byte-identical to a fresh-process scan (`ci.yml:49`); PetClinic must stay byte-identical; the build bakes a
git-hash build-id. **Every refactor step must be provably BEHAVIOR-PRESERVING** — same effects, same map/output
ordering (TreeMap/TreeSet are load-bearing), same JSON bytes. The refactor's safety net = the existing gates,
which are also its tripwire.

THE REGRESSION ORACLE (the green bar every phase must hold, no exceptions):
`./gradlew test` + `bash soundness/run.sh` (fuzzer + fabrication + entrypoint + sam + smear + kappa_probe) +
`CJ=… kappa_libs_probe.py` (440 leaves) + PetClinic byte-identical + jsoup/gson Unknown unchanged + the CI
self-scan byte-identical + 4-engine conformance (inert — engine-internal, no spec change, but run it once).

## The cohesion seams (what's actually in the file)

| Cluster | lines (approx) | state coupling | extract risk |
|---|---|---|---|
| **κ classifier** `classify()` + 4 pure helpers (isConventionallyPure, isAwsPureClientGetter, isLogEmitVerb, isPureHandleAccessor) | ~1800 | **NONE** (review-verified: ZERO state refs in the body — the apparent `ALL`/`direct` are comment text; references no shared constants; single caller `analyze()` @2023/2635; helpers all package-private pure switches) | **LOW (cleanest in the file)** |
| **ASM interpreters** Taint/Prov Value+Interpreter | ~250 | Taint self-contained; **Prov is NOT** (review: ProvInterpreter.naryOperation→indyLambdaTarget reads `projectClasses`; ProvValue ctor→declTypeOf) → must follow state-centralization | LOW (but after P6) |
| **Literal extraction** host/cmd/path/table/url (netHostLiteral, urlTerminalHost, constStringLocals, tablesInSql, cmdBase, pathCovered…) | ~470 | mostly pure (bytecode→strings) | LOW |
| **CHA / dispatch** chaTargets, isClosedHierarchy/sealed family, isChaExemptMethod, subtypeIndex | ~360 | reads byName/subtypeIndex | LOW-MED |
| **Policy / gate** checkPolicy, parsePolicy, scopeMatches, checkAllowlist/NoAmbient/Taint/Baseline, rules | ~520 | reads result state + rules | MED |
| **Report output** writeJson, writeCallgraph + invisible/blindspots | ~280 | reads ALL result state | MED |
| **Loading / indexing** load, collectClasses, computeSpringTypes, indexes | ~120 | populates byName/indexes | LOW-MED |
| **Core loop** `analyze()` + deferred/lambda/forwarding helpers | ~1100 | **writes ~all state** (the heart) | **HIGH** |
| **CLI / orchestration** main, runScan, resetState, checkConformance | ~300 | wires everything | (stays) |
| **annotation helpers** annoPresent/annoMeta… | ~120 | reads byName | LOW |

Mechanical enabler: everything is package-private, so sibling classes in `io.poly.candor` can reference each
other's package-private statics directly (`Classifier.classify(…)`, `State.direct`) — no `public` churn needed.

## Two ambition levels (the modeling decision)

**Level A — modularize, keep static-global state centralized (RECOMMENDED, the concrete plan).**
Split the clusters into cohesive sibling files; move the ~50 shared mutable fields into ONE `AnalysisState`
holder class (referenced as `State.direct` etc.). The static-global model REMAINS, but it's NAMED and
centralized instead of smeared across one 6.5k-line class. Delivers ~all the "nice model" value — navigable,
cohesive, each unit independently readable/testable — at LOW behavioral risk (pure code motion, gated).

**Level B — instance analysis context (OPTIONAL, separate go/no-go, NOT required for "nice model").**
Convert `AnalysisState`'s statics into an instance threaded through (each scan = an `AnalysisContext`; methods
take/hold it; no `resetState`; thread-safe; per-scan testable). The "proper" OO model. HIGH risk/effort —
touches all 220 methods' call sites, and the byte-identity self-guard makes any subtle ordering slip a
regression. **Recommend deferring** unless concurrent/embedded multi-scan or per-scan unit testing becomes a
real need. The Level-A `AnalysisState` holder is the seam that makes Level B *possible later* without re-doing
the file-split.

## Phasing — risk-ascending, each phase independently shippable + fully gated

- **P0 — lock the oracle.** Capture baseline outputs (self-scan JSON, PetClinic, jsoup/gson, the probe counts).
  A tiny `refactor-check.sh` that runs the whole oracle + diffs the captured baselines → the one command each
  phase must pass. No code change.
- **P1 — extract `Classifier.java`** (classify + its pure helpers + κ constant sets). ~1800 lines out (-28%),
  ~pure, lowest risk. Thread out the 2 incidental state touches (pass as args or read a final constant). This
  alone is the biggest readability win and de-risks the rest (the κ table stops drowning the file).
- **P3 — extract `Literals.java`** (host/cmd/path/table/url). Mostly pure.
- **P4 — extract `Cha.java`** (dispatch resolution + the sealed/enum closed-hierarchy family — incl. the only 2
  `private static` methods in the file, `permitClosureHasUnseen`/`closedAndVisible`, which move together) and
  `Annotations.java`. Low-med.
- **P6 — centralize state → `AnalysisState.java`** (the ~50 fields; `resetState` → `State.reset()`). **MUST be an
  AST/IDE semantic rename-symbol, NEVER a text find/replace** — the field names collide as SUBSTRINGS:
  `loc`⊂local/Clock/block/allocation, `direct`⊂direction/directory/redirect, `edges`⊂ledger/edged, `ALL`⊂CALL/
  ALLOWLIST/INSTALLED. A text replace silently corrupts unrelated code. Also patch the NON-resetState clear
  sites: `main()`'s parsepolicy branch @388 clears denyRules/allowRules/forbidRules — and **Query.java** reads
  denyRules/allowRules/forbidRules/KNOWN_EFFECTS too (must update Query in this phase). Highest byte-identity slip
  risk → gate hardest. **Pulled BEFORE P2/P5** (both read state).
- **P2 — extract ASM interpreters** (TaintInterpreter self-contained; ProvInterpreter cleanly references
  `State.projectClasses` now that P6 is done).
- **P5 — extract `Policy.java`, `Report.java`, `Loader.java`** (read `State`; Policy move also updates Query.java's
  7 reach-ins: denyRules/allowRules/forbidRules/KNOWN_EFFECTS/parsePolicy/scopeMatches/rejectUnknownFlag).
- **P7 — `analyze()` internal split (CAREFUL, optional).** The 790-line hot loop → extract the per-instruction
  handlers (the MethodInsn/InvokeDynamic/TypeInsn branches) into named private methods on `Analyzer`. Higher
  risk (it's the heart); behavior-preserving extraction only, no logic change. Could be skipped — a long but
  cohesive method is acceptable; the file-split already delivers the model.
- **P8 — (optional) Level B**, only if greenlit separately.

CORRECTED ORDER (review): **P0 → P1 → P3 → P4 → P6 → P2 → P5 → P7/P8**. P1/P3/P4 are pure/near-pure (safest,
biggest reduction, do first); P6 (state) is pulled BEFORE P2 and P5 because ProvInterpreter and Policy/Query
both read state — centralizing it first lets them cleanly reference `State.*`. P7/P8 risky core, last/optional.

## Risks / honest caveats

1. **Byte-identity is the tripwire.** The win is "navigable code," NOT behavior change — if ANY phase shifts
   an effect, a map ordering, or a JSON byte, it's a regression the oracle catches. Keep TreeMap/TreeSet,
   output formatting, and method-resolution order identical. **THE SINGLE BIGGEST RISK: P6's rename of the
   collision-prone short field names** (`loc`/`direct`/`edges`/`ALL`) — AST/IDE rename-symbol ONLY, never text.
   **Second invariant (review): `ALL` is populated in `Files.walk` order (unsorted, @1807) and writeJson
   iterates it directly (@6250/6262/6392)** — no phase may swap an `ALL`-list iteration for a HashMap/HashSet
   keyset iteration (would silently break JSON ordering). The static-init block @3553 (ROOT_ANNOTATIONS from
   List.of constants) must move ATOMICALLY with its inputs (or stay co-located) — avoid a `<clinit>` cycle.
   Also confirm no `soundness/*.sh` greps stderr text (43 System.err/out sites scatter across clusters).
2. **Value is maintainability, not capability.** This adds zero soundness/precision — it's a bet that the next
   year of κ/engine work is cheaper in a modular file. Worth it given the file's growth rate (one session
   added ~440 κ rules), but it's not user-facing. Frame expectations accordingly.
3. **`analyze()` and the static-state model are the real complexity** — P1-P6 make the file navigable but the
   core loop + global state remain; P7/P8 are where the deep model lives and where the risk concentrates.
   Recommend stopping after Level A (P1-P6) unless P7/P8 earn their risk.
4. **Don't refactor + change behavior in the same commit.** Each phase: pure code motion, gated green,
   committed alone. The git-hash build-id changing per commit is expected.
5. **`Query.java` (1193) is NOT cleanly out of scope** — it reaches into 7 Candor statics (denyRules,
   allowRules, forbidRules, KNOWN_EFFECTS, parsePolicy, scopeMatches, rejectUnknownFlag). P6 (state) and P5
   (Policy) MUST update Query's references in the same phase, else it won't compile. (Level B would let it stop
   reaching in entirely.)

## Recommendation

Do **Level A** in the review-corrected order (**P0 → P1 → P3 → P4 → P6 → P2 → P5**), each gated by the P0 oracle
and committed alone — starting with **P1 (Classifier)**, the safest, highest-value single move (review-confirmed:
1800 lines / -28%, ZERO state coupling, single caller, no access-widening). Treat **P7 (analyze split)** and
**P8 (instance context)** as separate, optional, individually-justified follow-ups. The binary-identity
self-guard proves behavior is unchanged at every step.

**Review verdict: PLAN-NEEDS-FIXES → fixed (no fatal flaw).** P1 is sound and the right start; the four
corrections (classify is fully pure not "2 touches"; ProvInterpreter reads state→after P6; P6 is an AST rename
not text, +the @388 clear site +Query.java; P6 before P2/P5) are folded in above.
