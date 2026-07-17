<!-- MAINTAINERS: this is the canonical doc. After editing it, re-sync the embedded jar copy in the SAME commit or CI's drift gate (test/smoke.sh) fails: cp AGENTS.md src/main/resources/AGENTS.md -->
# Using candor-java (instructions for an AI coding agent)

candor-java — the family's reference engine (spec 0.20) — reports, for every method in a JVM codebase
(Java, Kotlin, Scala, Groovy — it reads bytecode), which side effects it performs, transitively. The language-agnostic consumption contract is
[candor-spec/AGENTS.md](https://github.com/tombaldwin/candor-spec/blob/main/AGENTS.md); this file is
the JVM-specific production + query surface.

> **This document ships inside the jar.** `java -jar candor-java-*-all.jar --agents` prints the
> contract for the *installed* build — always prefer that over a vendored or fetched copy, which
> can describe a different candor-java than the one you are running.

A static initializer (`Type.<clinit>`) is its own unit and carries `unitKind: "initializer"`
(spec 0.7, informative) — it runs at class load, with no call site; ordinary methods omit
the field.

## Produce a report

```sh
# zero-install (the fat jar). No jbang? curl -Ls https://sh.jbang.dev | bash -s - app setup
mkdir -p .candor
jbang candor@tombaldwin/candor-java <classes-dir-or-jar> --json .candor/report.json
# or: java -jar candor-java-<ver>-all.jar <classes-dir-or-jar> --json .candor/report.json
```

Point it at **compiled output** (`build/classes/java/main`, a jar) — build first. If the build
won't cooperate (toolchain demands, broken snapshot), candor analyzes **any** compiled classes or
jar — a release jar fetched from Maven Central is a fine substitute for building the repo. Analyze
`main`, not test, classes (test code describes the harness). `--json` writes the report **and**
`.candor/report.callgraph.json` (every method's direct callees, pure ones included — the blast-radius
input). Method names are dot-separated: `com.example.Svc.save`.

**Report shape:** entries live in `.functions[]`, keyed **`fn`** (the method name — e.g.
`jq -r '.functions[] | select(.unresolved) | .fn' .candor/report.json`), with `inferred` / `direct` /
`unresolved` / `unknownWhy` / `entryPoint` alongside. **Only effectful-or-unresolved methods appear
in the report; pure methods are omitted** — a method present in the callgraph sidecar but absent
from `.functions[]` is pure (as far as the engine resolved). In *neither* file = never analyzed;
conclude nothing.

## Already installed? Report the version and ask before upgrading — before you scan

If this project already has candor-java (a `.candor/` report directory, or the fat jar /
`jbang candor@tombaldwin/candor-java` available), do this **first**, before scanning:

1. **Tell the user which version they're on.** Run the offline version flag and state it plainly —
   e.g. *"This project is on candor-java <version> (spec 0.20)."*
   ```sh
   candor --version        # i.e. java -jar candor-java-*-all.jar --version — offline, no network
   ```
   On a build too old for the flag, read `candor.version` / `candor.spec` from an existing
   `.candor/report*.json` instead.
2. **Check whether it's current.** candor-java never phones home — it analyzes for the `Net` effect
   and must not perform it, so the version check is *your* job, not the tool's: you have network
   access, it doesn't. Compare the installed RELEASE semver against the latest GitHub release tag:
   ```sh
   curl -s -H 'User-Agent: candor-version-check' \
     https://api.github.com/repos/tombaldwin/candor-java/releases/latest \
     | grep -o '"tag_name": *"[^"]*"'                                    # latest -> "tag_name":"v<version>" (compact)
   ```
3. **If it's behind, *ask* before upgrading.** Say e.g. *"candor-java <latest> is available (you're on
   <installed>) — upgrade before I scan?"* and run `jbang --fresh candor@tombaldwin/candor-java` only if the
   user agrees. Never upgrade silently: an analysis tool's version is part of its result's provenance,
   so the user decides when it changes.

If it's already current (or the user declines), just proceed. If candor-java isn't installed at all,
skip this and install per *Produce a report* above.

`candor --version` prints the clean RELEASE semver `<ver>` (the GitHub-tag / jar-filename axis) and the
contract `<spec>`, then `upgrade: jbang --fresh candor@tombaldwin/candor-java`. (The report envelope's
`.candor.version` is still the engine **build hash** — a git short-hash for provenance, not a semver —
while `.candor.spec` is the contract version, `0.16`.)

`jbang candor@tombaldwin/candor-java` resolves the jar from this repo's `jbang-catalog.json`, which
pins a release tag — so you get whatever that catalog points at. To pick up a newer release, run
`jbang cache clear` (forces jbang to re-read the catalog) or pin a specific jar explicitly:
`jbang https://github.com/tombaldwin/candor-java/releases/download/<tag>/candor-java-<ver>-all.jar …`.
PROVE-IT.md requires **0.3.2 or later** (earlier published builds have since-fixed resolution bugs).

## Query it (same names/shapes as the Rust engine — candor-spec §3.1)

The jbang alias works for every query too — `jbang candor@tombaldwin/candor-java show …` — you
never need the jar's path:

```sh
java -jar candor.jar show     .candor/report.json <method> [--json]   # a method's effects
java -jar candor.jar where    .candor/report.json Db [--json]         # direct sources vs inheritors
java -jar candor.jar callers  .candor/report.json <method> [--json] [--include-unknown]  # the BLAST RADIUS (works for pure methods)
java -jar candor.jar whatif   .candor/report.json <method> Net [policy] [--json]  # pre-edit gate verdict
java -jar candor.jar fix      .candor/report.json <method> Net [policy] [--json]  # the boundary FIX: where the effect belongs + the hoist refactor
java -jar candor.jar fix-gate .candor/report.json [policy] [--json]               # a fix for EVERY boundary crossing (the loop's block-message remedy)
java -jar candor.jar unverified .candor/report.json [policy] [--strict] [--json]  # pure/deny layers that PASS but are Unknown (not PROVABLY clean)
java -jar candor.jar diff     .candor/report.json baseline.json [--json]
java -jar candor.jar tour     .candor/report.json [N] [--json]                    # the N most surprising transitive reaches (default 10)
java -jar candor.jar map|containment|reachable|path|impact|blindspots .candor/report.json …
```

Name queries resolve exact > segment-suffix (`Svc.save` matches `com.example.Svc.save`, never
`Svc.save_all`) > substring — same ladder as the Rust engine.

- **Blast radius of editing a method** → `callers <method>` (NOT its `inferred`, which is what the
  method itself does). Works pre-edit for a still-pure method. The transitive set is candor's
  *confirmed* reachers; add **`--include-unknown`** to also disclose the *unresolved-dispatch frontier*
  — functions that MAY reach the method through a `dispatch:` candor declined to resolve. Resolved
  precisely against the `<report>.hierarchy.json` sidecar (a confirmed reacher that is an override of the
  dispatched method); a lower-bound disclosure, labelled "cannot confirm", never asserted.
- **Decide BEFORE you edit** → `whatif <method> <Effect> [policy]` — every transitive caller gains the
  effect; crossed with `CANDOR_POLICY` it returns which functions would violate.
- **Fix a boundary crossing** → `fix <method> <Effect> [policy]` — the remedial inverse of `whatif`: when a
  method performs an effect its layer forbids, candor computes *where the effect belongs* (hoist it to the
  nearest allowed-layer caller) and which methods become pure and thread the value, plus the policy-relax
  alternative. `fix-gate [policy]` does the same for every crossing at once — the shape the edit-time loop
  folds into its block message. Advisory: candor names the structure, you write the code; the gate re-scan
  verifies. Needs a policy (the fix is defined relative to the boundary it crosses).
- **Enforce in CI** → `--policy <file>` (or `CANDOR_POLICY`) (candor-spec §6.2: `deny`/`pure`/`allow`/`forbid`) +
  `CANDOR_BASELINE` (regression guard). Deterministic — not an LLM opinion.
- **Gate semantics to know**: scopes match by dotted segment, and the `$` nested-type boundary is a
  segment split too — a JVM nested class is a scope segment, so `deny Net client` bites
  `Outer$client` (the family §6.2 ruling). `pure` forbids every *effect*; `Unknown` (the §4 trust
  marker) is not an effect, so an Unknown-only method trips neither `pure` nor `deny Net` —
  `deny Unknown <scope>` is the explicit strictness knob. `diff` exits 1 on a gained effect when the
  baseline and engine producing versions match; a mismatch is disclosed (`baseline_version`/
  `engine_version` + a stderr warning) with exit 0 (`gains` always exits 0).
- **Machine verdict** → add `--gate-json <file|->` (candor-spec §3.3): the structured verdict
  `{ spec, ok, violations:[{rule,fn,effects,detail}] }` from the same check that sets the exit code —
  what the PR-native SARIF Action consumes (`--gate-json - | candor-sarif`; with `-` the human gate
  lines move to stderr, stdout stays pure JSON). Exit semantics: violation → 1 (verdict written);
  a gate that could not run (unreadable policy/config, unwritable verdict path) → **2 with NO verdict
  file** — never read a missing verdict as green. A clean run writes `ok: true, violations: []`.
- **Check the wiring in** → `.candor/config` (candor-spec §3.4), one `key value` line each:
  `policy` / `baseline` / `deps` / `strict` / `no-ambient` / `closed-world` / `taint` (all seven
  implemented; keys map 1:1 to the `CANDOR_*` env vars; precedence CLI flag → env → config).
  Discovered by walking UP from the scan target (`CANDOR_CONFIG` overrides; no CWD fallback);
  relative paths resolve against the config's home directory — the one containing `.candor/` —
  never the CWD. Fail-closed: an unusable config exits 2; unknown keys warn.
- **An engine swap is baseline-invalidating — and the guard fails closed on it.** Coverage batches
  change what the engine sees (a coverage batch can unmask hundreds of previously-invisible effects), so a
  baseline is comparable only to reports from its own producing build (spec §2.1). When the builds
  differ the guard does NOT evaluate (a stale comparison is semi-garbage in both directions) and fails
  the run (exit 2, the unreadable-policy class) with the one-command fix. After upgrading candor:
  regenerate the baseline with the new build in the same change — review the effect delta while you do
  (`diff` shows it, with a provenance warning) rather than waving it through.

## JVM-specific things to know

- **Spring is read declaratively**: `@Transactional`/Spring-Data repos → `Db`; `RestTemplate`/
  `WebClient`/Feign → `Net`; `@*Mapping`/`@Scheduled`/listeners/lifecycle hooks → **entry points**
  (`entryPoint: true`, runtime-invoked roots — their effects are never orphaned even with no
  in-project caller). `reachable` unions effects over the entry points.
- **Runtime-invoked bodies** (Runnable/Callable tasks, `finalize`, servlet methods, Ktor route
  handlers) are entry points too; a *scheduled* task's effects also attribute to the scheduling
  method (lambdas + anonymous/local classes are edged at their creation site).
- **Multi-module**: set `CANDOR_DEPS=dep-report.json:…` so calls into separately-analyzed modules
  inherit their effects instead of reading pure; or analyze app + deps on one classpath for full CHA.
- **Whole-app precision**: set `CANDOR_CLOSED_WORLD=1` to assert the scanned classes are the COMPLETE
  world — a broad (>12-impl) dispatch over a *project-defined* type then resolves to the exact union of
  its impls instead of dropping to `Unknown` (e.g. a 40-enum `IdentifiableEnum::getId` → pure, not a
  smeared Unknown). Off by default (sound/conservative); only assert it for an app you fully scan, never
  for a library whose interfaces consumers extend. External/library interfaces stay bounded regardless.
  Caveat (same limit as narrow CHA): a project impl that INHERITS its body from an UNSCANNED external base
  still isn't resolved — pair with `CANDOR_DEPS` for those.
- **The pure-exempt dispatch set** (toString/equals/hashCode/compareTo; Kotlin/Scala/Groovy
  function-interface dispatch; Runnable/Callable on the external interface) is documented in
  [README](README.md) — an effectful override of those is not attributed at the dispatch site.

## The trust rule — do not skip this

`inferred` is authoritative for what candor-java resolved. When `unresolved` is true (or `Unknown` is
present — reflection, `native` bodies, Groovy metaclass dispatch, a project interface with no visible
impl), the set may be incomplete: read the source before relying on it. `unknownWhy` tells you whether
the opacity is irreducible (`reflect:`/`native:`) or fixable by widening the analyzed classpath
(`dispatch:`). **`unknownWhy` appears only on the ROOT entries** — the methods whose own bodies hit
the opaque call; methods that merely *inherit* `Unknown` carry it in `inferred` with no why. To find
what taints an inheritor, follow its `calls` edges down (or `where Unknown` and intersect) to the
root. Never conclude a method is pure while it is marked unresolved.

`invisible` is the other incompleteness flag, and it qualifies `inferred` the same way: it lists the
external packages a method (transitively) calls into where candor's classifier could not see — effects
through them are NOT in `inferred`. So `inferred: []` with a non-empty `invisible` means **"pure as far
as candor could analyse, but it could not see through these packages"** — not "pure". Treat an effect
claim on any method carrying `invisible` as a lower bound, and read the source (or model those packages)
before relying on it. The per-scan coverage-ledger line on stderr (marker: `classifier doesn't cover`)
is the same disclosure aggregated.
