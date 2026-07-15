# candor-java

<p align="center"><img src="https://raw.githubusercontent.com/tombaldwin/candor/main/assets/beaky.svg" alt="Beaky, the candor canary" width="180"></p>

**Enforce the architectural boundaries that AI-generated JVM code silently crosses — as a CI gate you
can trust.** candor-java reads compiled bytecode via [ASM](https://asm.ow2.io/) and knows which methods
reach the network, filesystem, a database, a subprocess, the environment — *transitively* — then turns
invariants like *"the domain layer does no I/O"* or *"domain must not depend on infra"* into a
`CANDOR_POLICY` that **fails the build** when an edit breaks them (`deny`/`pure`/`allow`/`forbid`, AS-EFF-006/008/009).
The family's **reference engine** for [candor-spec](https://github.com/tombaldwin/candor-spec); sibling of
[candor-rust](https://github.com/tombaldwin/candor-rust) — the deep Rust engine + the stable syntactic
floor — same classifier ideas, the JVM's grain (bytecode + Spring).

**Install & run** (details in [Build & run](#build--run) below):

```sh
# zero-install via jbang (https://www.jbang.dev) — no clone, no Gradle:
jbang candor@tombaldwin/candor-java build/classes/java/main --json .candor/report.json  # scan → report
jbang candor@tombaldwin/candor-java build/classes/java/main --policy .candor/policy \
  --gate-json verdict.json     # CI gate: exit 1 on a violation, 2 if the gate could not run
```

**Site:** [candor.poly.io](https://candor.poly.io) — the measured case in five minutes: the
exhibits, the pre-registered evals, and the prove-it-on-your-own-repo path.

**Any JVM language — Java, Kotlin, Scala, Groovy.** Because it reads *bytecode*, candor-java is
language-agnostic: all four lower to the same `.class` files it analyses, use the same JDK I/O APIs the
classifier knows (`java.net`/`java.nio`), the same Spring annotations, and the same JVM-level
`Runnable`/`main`. Java is the most battle-tested (a real 2,257-class Spring app + hundreds of library
jars). **Kotlin, Scala and Groovy are validated on real bytecode:** Kotlin (okhttp, ktor,
kotlinx-coroutines) detects the network I/O and flags `Runnable`-based dispatchers as entry points;
Scala (scala-library, cats) and Groovy (groovy runtime, groovy-json) parse without crashing, attribute
real effects to their genuine sources (`scala.sys.process` → Exec, `Source.fromURL` → Net), and land
the dynamic surface (Scala's broad collection dispatch, Groovy's MOP/metaclass) in disclosed `Unknown`
rather than silently passing. *(That validation pass fixed two real engine bugs — `System.getProperty`
was miscounted as `Env`, and CHA over a deep hierarchy fanned out unbounded; both now correct, with
the bounded-CHA `≤12`-or-`Unknown` discipline applied to all dispatch.)* Caveat: an interface-heavy
*library analysed in isolation* (the stdlib/runtime itself) can over-report via class-init chains (see
**Not yet** below) — a real *app*, with the runtime as an unanalysed dependency, doesn't (cats analysed
clean: all-`Unknown` typeclass dispatch, zero fabricated effects).

**A gate is only worth trusting if it never lies.** candor-java surfaces what it can't see — reflection,
a `native` body, dispatch over an unknown impl — as `Unknown`, never a silent "pure." That contract is
held by an adversarial [soundness fuzzer](soundness/) in CI that threads a known effect through every
JVM call form (direct / lambda / method-ref / constructor / static-init / interface dispatch / anon
class) and fails if any reachable method comes back pure. So when candor-java certifies a layer clean,
you can act on it.

**It maps, too** — a per-method effect audit and instant `show`/`where`/`callers`/`map`/`diff`/
`containment`/`reachable`/`path`/`impact` queries over the report, for an agent or a human navigating unfamiliar code.

## Status: beta (v0.15.x, spec 0.15 — the family's reference engine)

Validated on a real 2,257-class Spring application and on real Kotlin/Scala/Groovy bytecode; holds
the spec's cross-engine conformance suite (same fixtures and expected effect sets as the Rust
engine, in CI); guarded by an adversarial soundness fuzzer, a ~446-anchor real-library leaf probe,
a runtime ground-truth oracle (JFR + bytecode agent), and a mutation probe over the gates
themselves. Beta because the classifier and the framework surface keep growing — the trust
contract (§4: never silently pure) is not where the immaturity lives.

Release history: [CHANGELOG.md](CHANGELOG.md) — **⚠ marks a verdict-affecting change** (review
policies / regenerate baselines on upgrade).

**Works:** audit mode — resolves each call, classifies it against the effect table (matching the I/O
boundary, not the package), and propagates transitively to a fixpoint over the call graph. Emits the
**v0.2 self-describing report** — a `{ candor, functions }` envelope whose header carries the engine
build id (the git short hash, baked into the jar at build time so it reflects the *binary that ran*)
and toolchain (candor-spec §2/§2.1). Readers still accept the legacy v0.1 bare array (the baseline
guard loads both). Each entry also carries the effect-relevant **`calls`** graph — its effectful
local callees — so a consumer can answer "who calls X?" from the report without re-analysis.

**Spring-aware.** Spring hides effects in framework-woven/generated code (`@Transactional`'s
transaction lives in a runtime proxy; Spring Data repository impls are synthesized at runtime) and
breaks the call graph (controllers/listeners are invoked reflectively). Pure bytecode tracing misses
all of it — so candor-java reads Spring's **declarations** instead:

- `@Transactional` (method or class) → `Db`
- Spring Data repositories (`extends CrudRepository`/`JpaRepository`) → calls to them are `Db`
- `RestTemplate` / `WebClient` / `@FeignClient` → `Net`; `JdbcTemplate` / `EntityManager` → `Db`;
  `JmsTemplate` / `KafkaTemplate` → `Net`; `Environment.getProperty` → `Env`
- **Entry points** (runtime-invoked roots, no project call site): `@*Mapping`, `@Scheduled`,
  `@*Listener`/`@EventListener`; bean lifecycle `@PostConstruct`/`@PreDestroy` + `InitializingBean`/
  `DisposableBean` + `CommandLineRunner`/`ApplicationRunner`; servlets/filters/listeners; JPA entity
  callbacks (`@PrePersist`/…); `Runnable`/`Thread`/`Callable` task bodies; `finalize()`; and **Ktor**
  route handlers (a Kotlin `SuspendLambda` whose receiver is a `RoutingContext`/`PipelineContext` — the
  `get("/x") { … }` body Ktor invokes from its pipeline). The `reachable` query unions effects over these
  to show what the app does at runtime.

On `spring-sample/`, `register()` (a `@Transactional` method calling a Spring Data repo + a
`RestTemplate`) correctly infers `{ Db, Net }`, and the `@GetMapping` controller inherits
`{ Db*, Net* }` and is flagged `[entry]` — effects that live in no method body candor could see.

**Trust contract (candor-spec §4).** candor-java surfaces what it can't see as `Unknown`
(`unresolved: true`), never silent-pure:
- **Reflection / dynamic invocation** (`Method.invoke`, `Constructor.newInstance`,
  `Class.forName`/`newInstance`, `MethodHandle.invoke`, `Proxy.newProxyInstance`) → `Unknown` — and
  Groovy's metaclass dispatch (`MetaClass`/`GroovyObject.invokeMethod`, `GroovyShell.evaluate`),
  which IS reflection, likewise → `Unknown`.
- **`native` methods** — a JNI body candor can't see could perform any effect, so it's `Unknown`
  (and its callers inherit it), never the no-op an empty bytecode body would otherwise look like.
- **Class Hierarchy Analysis** resolves interface/virtual dispatch over project types to their
  implementations, so effects propagate *through* dispatch (a call on a `Greeter` interface inherits
  the union of its impls' effects). Dispatch over a **project interface/abstract with no visible
  impl** (DI-wired, external, strategy) → `Unknown`.

CHA is done with the class hierarchy ASM already gives us — no WALA/SootUp needed.

**The pure-exempt dispatch set (candor-spec §4 requires this be documented).** Three dispatch shapes
are deliberately *not* CHA-fanned-out, because over them every (or nearly every) class in the jar is a
candidate target and one effectful override would smear across the whole report:

- `toString()` / `hashCode()` / `equals(Object)` / `compareTo(Object)` — the conventionally-pure
  `Object` surface (the same trade the Rust engine makes for `dyn Display`/`Error` formatting).
  *The documented caveat:* an override of these that performs real I/O is not attributed at the
  dispatch site (its own method entry still carries the effect).
- `kotlin.jvm.functions.FunctionN.invoke`, `scala.FunctionN`/`PartialFunction` `apply`, and
  `groovy.lang.Closure.call` — every Kotlin/Scala/Groovy lambda or closure is a class implementing
  these; the body is instead attributed at its **creation site** (precise-by-construction).
- `java.lang.Runnable.run` / `Callable.call` on the external interface — task bodies are **entry
  points** (the runtime invokes them), so their effects are never orphaned; an event loop's
  `task.run()` is not charged with every task in the jar.

All other dispatch — including over external interfaces with project impls (`java.util.Iterator`) —
is still CHA-resolved.

**Cross-jar (multi-module).** Each entry carries a stable, descriptor-bearing `hash`
(`owner/Class.method(desc)ret` — the exact ref a call site uses), so a dependent module can inherit a
dependency's effects across the jar boundary (candor-spec §2). Point `CANDOR_DEPS` at the
dependencies' reports (a path list, or a directory of `*.json`); a call into a separately-analyzed
dependency then inherits its recorded effects instead of being assumed pure. **Version-aware trust
(§2.1):** effects from a report produced by a *different* engine version are downgraded to `Unknown`
rather than silently trusted.

```sh
CANDOR_DEPS="/path/to/dep-report.json:/path/to/more" \
  gradle run --args="/path/to/app-classes --json /tmp/app.json"
```

**One-command dep scan — `./candor --deps <classpath> <app-classes>`.** Rather than scan each
dependency jar by hand, point `--deps` at the classpath (a `:`-separated list of jars, or a directory
of jars): the wrapper scans each into a sibling report under `.candor/deps/`, then runs the app scan
chained over them — the JVM half of the dep-scan endgame (a dependency's effects derive from *its* calls
into the JDK frontier, so the curated classifier shrinks toward builtins-only). Cached: an unchanged
jar's report is reused. The *shell* fans out the scans, so the engine itself never spawns a process
(its own boundary is Fs/Env only, spec §7.12).

```sh
./candor --deps libs/ build/classes/java/main --json /tmp/app.json   # scan libs/*.jar, then the app
```

*Resolution depth:* a concrete-typed cross-jar call resolves by `hash` directly; an **interface**-typed
call whose impl lives in the dependency can't be devirtualized from the report alone (a report carries
no class hierarchy). For full resolution across a boundary, analyze the app **and** its deps *together*
(one classpath) — then local CHA sees through the dispatch. `CANDOR_DEPS` is the mode for when you only
have a dependency's *report*, not its bytecode.

**Not yet (known gaps, disclosed — PRINCIPLES #7):**
- dispatch over **non-project (JDK/library) types** that the classifier doesn't recognise is assumed
  pure rather than `Unknown` — otherwise every `list.add()` floods the report (the calibration the
  Rust impl learned). Known-effectful libraries are caught by the classifier; the rest is a
  documented residual gap.
- a **cross-jar** `<clinit>` (a static initializer in a *dependency*, reached only through the report)
  isn't attributed — the local trigger-edges below need the dependency's bytecode on the classpath.
- **CHA over a universal interface method floods on interface-heavy libraries.** A call on an
  interface-typed receiver (`Iterator.next`, `Function.apply`) is resolved by Class Hierarchy Analysis
  to *every* impl in the analysed set — sound (any impl could be there), but when one impl does I/O and
  the method is called pervasively, the effect floods. Self-analysing `scala-library` reports ~74% of
  functions as `Net`/`Fs` because a single URL-reading `Iterator` impl is CHA-reachable from every
  iterator traversal. The Rust impl avoids this by *devirtualizing* to the concrete type (the compiler
  gives it the monomorphized receiver); bytecode CHA has no equivalent without type-flow analysis. In
  practice it's bounded: a real Scala/Kotlin *app* has the stdlib as an unanalysed dependency, so those
  calls are `Unknown`, not a flood — it bites library *self*-analysis. (Counts being misleading here is
  exactly why candor reports a structure, not a "score" — see `containment`.)

**Constructors, static initializers & lambdas/method references** *are* handled — an effectful one
propagates to its use site instead of looking pure:
- a **constructor** (`<init>`) body's effects reach every `new X()` site;
- a **static initializer** (`<clinit>`) body's effects reach every site that triggers the class-load —
  a `new C`, a static method call, or a static field access on `C` (the JVM runs `<clinit>` once, on
  first use; candor edges to it from each trigger, over-approximating soundly);
- a **lambda / method reference**'s impl method (a project `lambda$…` synthetic or a referenced method)
  is edged from the enclosing method, so an effectful `() -> …` or `Foo::bar` propagates its effects.

The deepest JVM ceiling is what even declarations + CHA don't capture: **custom** AOP aspects
(`@Aspect`/`@Around`) and beans wired by reflection (`getBean`). The heavyweight route to those is
Spring Boot 3 **AOT metadata** (Spring's own ahead-of-time processing resolves bean wiring, proxies,
and reflection at build time). See candor-spec CLASSIFIER.md.

## Build & run

**Zero-install (recommended):** the release fat-jar via [jbang](https://www.jbang.dev) — no clone,
no Gradle:

```sh
jbang candor@tombaldwin/candor-java /path/to/classes-or-jar --json /tmp/report.json
```

**AI agent?** Point it at [AGENTS.md](AGENTS.md) — the self-contained produce/query/trust
instructions. **Sceptical?** [PROVE-IT.md](PROVE-IT.md) is the 15-minute self-experiment your own
agent runs on your own codebase.

**Version & updates:**

```sh
candor --version        # prints: candor-java <ver> (spec <spec>) + the upgrade line — no network
```

candor never phones home (it audits the `Net` effect and must not perform it), so checking for a newer
release is the **agent's** job: read the installed `<ver>` from `--version`, compare it to the latest
GitHub release tag yourself, then `jbang --fresh candor@tombaldwin/candor-java` if it's behind.

**Staying current:** check your installed version and upgrade — [candor/AGENTS.md §2a](https://github.com/tombaldwin/candor/blob/main/AGENTS.md#2a-staying-current--check-the-version-upgrade). `candor --version` prints the build, the spec, and the upgrade one-liner (offline; candor never phones home).

From source: requires JDK 21 + Gradle.

```sh
# compile the code you want to analyze to a directory of .class files (or point at a jar), then:
gradle run --args="/path/to/classes --json /tmp/report.json"

# …or the ./candor convenience wrapper (builds once, self-heals when the source changes):
./candor /path/to/classes --json /tmp/report.json   # analyze
./candor show /tmp/report.json myMethod             # query a report
```

It prints a per-method effect audit and writes a candor JSON report. `bash test/smoke.sh` runs the
behavioural suite, and `bash soundness/run.sh` runs the [adversarial soundness fuzzer](soundness/) —
which threads a known effect through every JVM call form (direct / lambda / method-ref / constructor /
static-init / interface dispatch / anon class) and asserts candor-java never reports a reachable method
pure (effect-or-`Unknown` only). Both run in CI; the fuzzer is teeth-verified (reverting a fix fails
its form's lane).

## Queries (read-only, over a written report)

Once you've written a report (`--json report.json`), answer questions about it **without
re-analyzing** — the sibling of the Rust impl's `candor-query`. They read the report's own fields
(`inferred`/`direct`, and the `calls` effect graph), plus the full call-graph **sidecar**
(`report.callgraph.json`, written automatically beside the report) for the pre-edit blast radius:

```sh
gradle run --args="show    report.json <fn-substring>"  # a function's effects (* = own body; Fs(read,write) detail)
gradle run --args="where   report.json <Effect>"        # who performs an effect (direct vs inherited)
gradle run --args="callers report.json <fn-substring>"  # the blast radius: who TRANSITIVELY calls a fn —
                                                        #   works for ANY fn incl. PURE ones (pre-edit:
                                                        #   "who is affected if I add an effect here?")
gradle run --args="map     report.json"                 # class → effects overview, most-effectful first
gradle run --args="diff    report.json <baseline.json>" # per-function effect delta (+gained / -lost)
gradle run --args="containment report.json [baseline.json]"  # effect-leakage diagnostic + a ratchet
gradle run --args="reachable report.json"               # what the app DOES at runtime (union over entry points)
gradle run --args="path report.json <fn> <Effect>"     # the call chain by which a fn comes to perform an effect
gradle run --args="impact report.json <fn>"            # blast radius: transitive callers + downstream entry points
gradle run --args="whatif report.json <fn> <Effect> [policy]"  # PRE-EDIT verdict: if I add <Effect> here, what
                                                        #   propagates AND does it break the deny/pure gate? (exit 1 if so)
gradle run --args="rewire report.json <baseline-report.json>"  # DE-WIRING: which methods dropped a call vs the
                                                        #   baseline — catch a 'fix' that games the gate by disconnecting
```

`diff` doubles as a same-build ratchet: it exits **1** when a function *gained* an effect and the two
reports' producing versions match; on a version mismatch it **discloses** (`baseline_version`/
`engine_version` in the JSON + a stderr warning) and exits 0 — a cross-build comparison is
half-garbage in both directions, so it is never silently enforced. (`gains` always exits 0; the
exit-1 contract belongs to `diff` alone — candor-ts parity.)

> A green effect-gate is not a green feature — it can be satisfied by *disconnecting* functionality. Run
> `rewire` alongside the policy gate: a passing gate **plus** a clean `rewire` means the boundary was
> respected *without* gutting the feature. (See candor's `eval/whatif-behavior` for the eval that found this.)

Add `--json` to any query for machine-readable output — the form an AI agent / MCP server consumes,
identical in shape to the Rust engine (SPEC §3.1): `show`→`[{fn,inferred,direct,unresolved,fs?,hosts?}]`,
`where`→`{effect,directly,inherited}`, `callers`→`{of,direct,transitive}`,
`map`→`{module:{effects,functions}}`, `diff`→`{changes:[{fn,gained,introduced,inherited,lost,status}]}`,
`whatif`→`{of,effect,affected,violations,ok}`, `rewire`→`{dropped:[{caller,no_longer_calls}]}`.

### `containment` — an architecture-quality signal that isn't a "score"

Raw effect *counts* are domain-dependent (a database app has lots of `Db` — that's not a defect), so
there is no single "candor score". But the **dispersion** of a boundary effect across layers *is* a
domain-independent signal: a DB-heavy app with all `Db` in `dao` is well-architected; one with `Db`
smeared across `model`, `actions`, *and* `dao` is leaky — regardless of how much DB it does.
`containment` measures exactly that — for each *boundary* effect (`Db`/`Net`/`Exec`/`Fs`/`Ipc`), the
share that lives in its dominant layer (`Log`/`Clock` are ambient — reported, not scored). Layers are
inferred from the package after the common root, no config:

```text
  effect  contained  layers   owner  ← leaked into
  Db            49%       4   model (838)  ← dao:833, spring:6, actions:1   # ← half the DB is in `model`, not `dao`
  Exec         100%       1   utils (1)
```

Given a **baseline** it's a *ratchet* — gate on things getting **worse**, note when they get **better**:

```text
[containment] a boundary effect leaked into a layer it wasn't in:   ← exit 1, fail the PR
  Db → actions
✓ improved — a boundary effect left a layer:                        ← informational
  Db ⊘ legacy
```

Deliberately a **diagnostic + ratchet, not a single grade** — the absolute level is domain-dependent
and gameable, but the trend (did a boundary effect leak into a new layer?) is a real, enforceable
quality gate. Pair it with `cargo candor snapshot`-style baselines in CI.

## Modes

| Mode | How | Output |
|---|---|---|
| **audit** (default) | `gradle run --args="<classes>"` | per-method effect map |
| **JSON** | add `--json <file>` | the candor JSON report — per method: `inferred`, `direct`, and **conformance** (`declared`/`undeclared`/`overdeclared`, projected from the class's injected deps) so an agent can consume conformance, not just the diagnostics |
| **regression guard** | `CANDOR_BASELINE=<saved.json> gradle run --args="<classes>"` | `AS-EFF-005` + **exit 1** if any function gained an effect vs the snapshot |
| **no-ambient** | `CANDOR_NO_AMBIENT=1` (or a name prefix) | `AS-EFF-004` for direct ambient-authority use (route it through an injected collaborator) |
| **conformance** | `CANDOR_STRICT=1` (or a class-name prefix) | `AS-EFF-001/002/003` — a class performs an effect no injected dependency provides (or injects one it never uses) |
| **policy** | add `--policy <file>` (or `CANDOR_POLICY=<file>`) | `AS-EFF-006/008/009` + **exit 1** — architecture-as-code: a method violates a `deny`/`pure`/`allow`/`forbid` boundary (transitively) |
| **gate verdict** | add `--gate-json <file>` (or `-` for stdout) | the structured verdict `{ spec, ok, violations:[{rule,fn,effects,detail}] }` from the *same* check that sets the exit code — the input to CI annotations and the [SARIF reporter](https://github.com/tombaldwin/candor/tree/main/integrations/github) |
| **taint** (advisory) | `CANDOR_TAINT=1` | `AS-EFF-007` — an injection-class effect (`Exec`/`Fs`/`Db`/`Net`/`Env`/`Ipc`) on a **caller-derived** argument (command/path/SQL injection, SSRF). Intraprocedural taint dataflow; heuristic, never fails CI |

### Policy: architecture-as-code (`--policy` / `CANDOR_POLICY`)

The enforcement that earns its keep as models get better at local reasoning: a model advises, but only
a tool holding the whole effect graph *blocks the PR*. A policy file declares invariants; candor-java
flags any **transitive** violation (the cause may live in another method or layer a local diff hides):

```text
# .candor/policy
deny Net Db Fs  domain          # the domain layer must reach no I/O — even through a helper
pure            parse           # parsing must be side-effect-free
deny Exec                       # nothing may spawn a subprocess (no scope = whole project)
allow Net in billing  api.stripe.com   # billing may reach the network — but ONLY Stripe
allow Exec in build   git              # the build layer may run subprocesses — but ONLY git
allow Fs  in config   /etc/app         # config code may read the filesystem — but ONLY under /etc/app
allow Db  in billing  ledger.*         # billing may touch the database — but ONLY the ledger schema
forbid domain -> infra          # the domain layer must not depend on the infrastructure layer
```

```text
[AS-EFF-006] `app.domain.Checkout.run` performs { Fs }, forbidden by policy (scope `domain`): `deny Net Db Fs domain`
[AS-EFF-008] `billing.Pay.leak` reaches { metrics.growthtracker.io } outside the allowlist, forbidden by policy (scope `billing`): `allow Net … api.stripe.com`
[AS-EFF-009] `app.domain.Order.place` reaches into a forbidden layer (via `app.infra.Repo.save`), violating policy: `forbid domain -> infra`
```

- **`deny` / `pure`** (`AS-EFF-006`) — *what* a layer may do. A method need not perform the effect
  directly; candor flags it reaching the effect through any callee. `pure` forbids every effect —
  and `Unknown` (the §4 trust marker) is not an effect, so an Unknown-only method does not trip
  `pure` (or `deny Net`); where a boundary must also exclude uncertainty, `deny Unknown <scope>`
  is the explicit knob.
- **`allow <Effect> in <scope> <value…>`** (`AS-EFF-008`) — *which literals* an effect may reach, across
  the **transitive** surface (the literal often lives in a deep callee). For `Db` tables the surface is
  fed two ways: table-position identifiers in SQL string literals, **and JPA's declarations** — a
  literal `@Table(name = "users")` on an entity plus the repository's generic signature
  (`extends CrudRepository<User, Long>`) carries `users` into every Spring-Data call's `tables`, no
  SQL string anywhere (a bare `@Entity` is naming-strategy-dependent and contributes nothing — never
  a guess). The supply-chain boundary a
  model can't self-check. Four effects carry a literal surface: `Net` hosts ("billing may only talk to
  Stripe", matched by hostname), `Exec` commands ("build may only run git", by program basename),
  `Fs` paths ("config may only read /etc/app", by path-prefix at a boundary), and `Db` tables
  ("billing may only touch `ledger.*`", by qualified table name from SQL string literals). Certifies the *visible*
  surface only — a literal is read from the call that carries it (the `ProcessBuilder`/`exec` program,
  the `Path.of`/`File`/stream-ctor path, a scheme-URL/`host:port`/IP host); a runtime-computed value is
  disclosed as invisible, never over-claimed (validated on a real Spring app — the extractor takes the
  *first* arg, so a `ProcessBuilder("git","clone")` is `git` and a `RandomAccessFile(path,"r")` mode is
  never mistaken for a path).
- **`forbid <A> -> <B>`** (`AS-EFF-009`) — *who* a layer may depend on. A method in scope A must not
  *transitively* reach a method in scope B (reverse-reachability over the call graph).

Scopes match by dotted **segment** (so `domain` matches `app.domain.Svc.handle` and the `domain_logic`
package, but not `subdomain`) — the same rule as the Rust impl's `scope_matches`. A JVM **nested type**
is a scope segment too: segments also split on the `$` nested-type boundary (the family §6.2 ruling,
matching the query name ladder), so `deny Net client` bites `com.app.Outer$client.fetch`. A
set-but-unreadable policy fails **loud** ("policy NOT enforced"), never silently green.

### Machine-readable verdict — `--gate-json` (candor-spec §3.3)

The gate's verdict as JSON, from the *same* check that sets the exit code, for CI annotations and
the PR-native SARIF pipeline
([candor/integrations/github](https://github.com/tombaldwin/candor/tree/main/integrations/github) —
`candor … --gate-json - | candor-sarif` turns violations into PR-inline annotations):

```sh
./candor build/classes/java/main --policy .candor/policy --gate-json verdict.json
# → { "spec": "0.15", "ok": false, "violations": [ { "rule": "AS-EFF-006", "fn": "…", "effects": ["Db"], "detail": "…" } ] }
```

`-` streams the verdict to stdout (the human gate lines move to stderr so the stream stays pure JSON).
A clean run still writes `ok: true, violations: []`. **Exit semantics are pinned:** violation → `1`
(verdict written); a gate that could not run to completion — unreadable policy, unusable config,
unwritable verdict path — → `2` with **no** verdict file, so a pipeline can never read a stale or
clean-looking verdict as a pass. (`0` = evaluated, clean; `1` = evaluated, violations; `2` = **not
evaluated**, fail-closed.)

### `.candor/config` — check in the configuration

One checked-in file replaces the `CANDOR_*` env wiring (candor-spec §3.4), so CI is "point at the
repo" and the configuration travels with the code. Discovered by walking **up from the scan target**
(`CANDOR_CONFIG` overrides discovery); precedence, highest first: CLI flag → the matching `CANDOR_*`
env var → config → default:

```text
# .candor/config
policy   .candor/policy         # → CANDOR_POLICY  (the §6.2 gate)
baseline .candor/baseline.json  # → CANDOR_BASELINE (the regression guard)
deps     .candor/deps           # → CANDOR_DEPS (whitespace-separated paths, or a directory)
strict   1                      # → CANDOR_STRICT; likewise: no-ambient, closed-world, taint
```

candor-java implements all seven keys (`policy` / `baseline` / `deps` / `strict` / `no-ambient` /
`closed-world` / `taint`). A relative path value resolves against the config's **home directory** —
the one containing `.candor/` — never your shell's CWD. Fail-closed: an unusable config, or a
`policy` line with no value, exits `2` (a silently dropped config could be a silently dropped gate);
unknown keys warn (typo protection), never silently ignored.

### Conformance: dependency injection *is* a capability system

candor's Rust impl declares effects via capability tokens (`&Fs`). The Java idiom is **dependency
injection**: a bean's injected collaborators (its fields) are the capabilities it holds. So:

- **declared(class)** = effects its field types can supply (`RestTemplate` → `Net`, `@Repository` →
  `Db`, an injected project service → that service's effects).
- **performed(class)** = effects across its own methods.
- **`AS-EFF-001`** — performs an effect *no* injected dependency provides → it reached for ambient
  authority instead of receiving it. **`AS-EFF-002`** — injects a collaborator it never uses.
  **`AS-EFF-003`** — `Unknown` present, can't certify.

On `conf-sample/`: `GoodService` (holds + uses a `RestTemplate`) is conformant; `LeakyService` calls
ambient `Files.readString` with no Fs dependency → `AS-EFF-001`; `IdleService` injects a `RestTemplate`
it never calls → `AS-EFF-002`. The check is a class's signature (its dependencies) telling you its
effect surface — exactly candor's thesis, in Java's grain.

### CI regression guard (the lowest-friction adoption)

No declarations, no rewrite — snapshot the effect surface, commit it, fail PRs that grow it:

```sh
# once, on a known-good build — commit the snapshot:
gradle run --args="build/classes/java/main --json .candor/baseline.json"

# in CI:
CANDOR_BASELINE=.candor/baseline.json gradle run --args="build/classes/java/main"
# exits non-zero (AS-EFF-005) if a function gained an effect; a missing/garbled baseline
# fails LOUD ("guard is NOT active") rather than passing silently.
```

### Try the samples

```sh
# plain Java
javac -d /tmp/s sample/Sample.java && gradle run --args="/tmp/s"

# Spring (dependency-free: minimal stubs with Spring's real FQNs; candor matches by name)
javac -d /tmp/spring $(find spring-sample -name '*.java')
gradle run --args="/tmp/spring/com/example"
```

## How it works

ASM reads each `.class` into a node tree; for every method, each resolved call (`MethodInsnNode`) is
classified by its target's class + method name; calls to project methods become call-graph edges; a
fixpoint unions callee effects into callers. Same architecture as the Rust engine, deliberately —
and it has grown along the same path: `Unknown` (the §4 trust contract), CHA over project types,
Spring's declarative surface, the policy gate, and the read-only queries are all in (see above).

## Development

```sh
./gradlew installDist        # build the CLI → build/install/candor-java/bin/candor-java
./gradlew test               # native unit tests (JUnit 5): the pure helpers + the propagation fixpoint
bash test/smoke.sh           # end-to-end behavioural tests (report schema, queries, the gate, cross-jar)
bash soundness/run.sh        # the §7.13 soundness fuzzer (every reachable method effect-or-Unknown, never silently pure)
bash soundness/reentrancy.sh # proves the engine is reentrant — no static-state leak across in-process scans
CJ=build/install/candor-java/bin/candor-java python3 soundness/fabrication_probe.py   # the never-fabricate probe
```

Compilation is gated by `-Xlint:all -Werror` (`build.gradle.kts`) — javac warnings are build errors.
The analysis core is reentrant: every scan starts from a clean slate (`resetState()` in `runScan`).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
