# candor-java

**Enforce the architectural boundaries that AI-generated JVM code silently crosses — as a CI gate you
can trust.** candor-java reads compiled bytecode via [ASM](https://asm.ow2.io/) and knows which methods
reach the network, filesystem, a database, a subprocess, the environment — *transitively* — then turns
invariants like *"the domain layer does no I/O"* or *"domain must not depend on infra"* into a
`CANDOR_POLICY` that **fails the build** when an edit breaks them (`deny`/`pure`/`allow`/`forbid`, AS-EFF-006/008/009).
A [candor-spec](https://github.com/tombaldwin/candor-spec) implementation; sibling of the Rust reference
[candor](https://github.com/tombaldwin/candor) — same classifier ideas, the JVM's grain (bytecode + Spring).

**A gate is only worth trusting if it never lies.** candor-java surfaces what it can't see — reflection,
a `native` body, dispatch over an unknown impl — as `Unknown`, never a silent "pure." That contract is
held by an adversarial [soundness fuzzer](soundness/) in CI that threads a known effect through every
JVM call form (direct / lambda / method-ref / constructor / static-init / interface dispatch / anon
class) and fails if any reachable method comes back pure. So when candor-java certifies a layer clean,
you can act on it.

**It maps, too** — a per-method effect audit and instant `show`/`where`/`callers`/`map`/`diff`/
`containment`/`reachable`/`path`/`impact` queries over the report, for an agent or a human navigating unfamiliar code.

## Status: early prototype (v0)

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
  callbacks (`@PrePersist`/…); `Runnable`/`Thread`/`Callable` task bodies; and `finalize()`. The
  `reachable` query unions effects over these to show what the app does at runtime.

On `spring-sample/`, `register()` (a `@Transactional` method calling a Spring Data repo + a
`RestTemplate`) correctly infers `{ Db, Net }`, and the `@GetMapping` controller inherits
`{ Db*, Net* }` and is flagged `[entry]` — effects that live in no method body candor could see.

**Trust contract (candor-spec §4).** candor-java surfaces what it can't see as `Unknown`
(`unresolved: true`), never silent-pure:
- **Reflection / dynamic invocation** (`Method.invoke`, `Constructor.newInstance`,
  `Class.forName`/`newInstance`, `MethodHandle.invoke`, `Proxy.newProxyInstance`) → `Unknown`.
- **`native` methods** — a JNI body candor can't see could perform any effect, so it's `Unknown`
  (and its callers inherit it), never the no-op an empty bytecode body would otherwise look like.
- **Class Hierarchy Analysis** resolves interface/virtual dispatch over project types to their
  implementations, so effects propagate *through* dispatch (a call on a `Greeter` interface inherits
  the union of its impls' effects). Dispatch over a **project interface/abstract with no visible
  impl** (DI-wired, external, strategy) → `Unknown`.

CHA is done with the class hierarchy ASM already gives us — no WALA/SootUp needed.

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

*Resolution depth:* a concrete-typed cross-jar call resolves by `hash` directly; an **interface**-typed
call whose impl lives in the dependency can't be devirtualized from the report alone (a report carries
no class hierarchy). For full resolution across a boundary, analyze the app **and** its deps *together*
(one classpath) — then local CHA sees through the dispatch. `CANDOR_DEPS` is the mode for when you only
have a dependency's *report*, not its bytecode.

**Not yet (deferred honestly — PRINCIPLES #7):**
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

Requires JDK 21 + Gradle.

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
(`inferred`/`direct`, and the `calls` effect graph for `callers`):

```sh
gradle run --args="show    report.json <fn-substring>"  # a function's effects (* = own body; Fs(read,write) detail)
gradle run --args="where   report.json <Effect>"        # who performs an effect (direct vs inherited)
gradle run --args="callers report.json <fn-substring>"  # who calls a function (inverts the `calls` graph)
gradle run --args="map     report.json"                 # class → effects overview, most-effectful first
gradle run --args="diff    report.json <baseline.json>" # per-function effect delta (+gained / -lost)
gradle run --args="containment report.json [baseline.json]"  # effect-leakage diagnostic + a ratchet
gradle run --args="reachable report.json"               # what the app DOES at runtime (union over entry points)
gradle run --args="path report.json <fn> <Effect>"     # the call chain by which a fn comes to perform an effect
gradle run --args="impact report.json <fn>"            # blast radius: transitive callers + downstream entry points
```

Add `--json` to any query for machine-readable output — the form an AI agent / MCP server consumes
(`show`→`[{fn,inferred,direct,fs,unresolved}]`, `where`→`{effect,directly,inherited}`,
`callers`→`{callee:[callers]}`, `map`→`{class:{effects,functions}}`, `diff`→`[{fn,gained,lost,status}]`).

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
| **policy** | `CANDOR_POLICY=<file> gradle run --args="<classes>"` | `AS-EFF-006/008/009` + **exit 1** — architecture-as-code: a method violates a `deny`/`pure`/`allow`/`forbid` boundary (transitively) |

### Policy: architecture-as-code (`CANDOR_POLICY`)

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
forbid domain -> infra          # the domain layer must not depend on the infrastructure layer
```

```text
[AS-EFF-006] `app.domain.Checkout.run` performs { Fs }, forbidden by policy (scope `domain`): `deny Net Db Fs domain`
[AS-EFF-008] `billing.Pay.leak` reaches { metrics.growthtracker.io } outside the allowlist, forbidden by policy (scope `billing`): `allow Net … api.stripe.com`
[AS-EFF-009] `app.domain.Order.place` reaches into a forbidden layer (via `app.infra.Repo.save`), violating policy: `forbid domain -> infra`
```

- **`deny` / `pure`** (`AS-EFF-006`) — *what* a layer may do. A method need not perform the effect
  directly; candor flags it reaching the effect through any callee. `pure` forbids every effect.
- **`allow <Effect> in <scope> <value…>`** (`AS-EFF-008`) — *which literals* an effect may reach, across
  the **transitive** surface (the literal often lives in a deep callee). The supply-chain boundary a
  model can't self-check. Three effects carry a literal surface: `Net` hosts ("billing may only talk to
  Stripe", matched by hostname), `Exec` commands ("build may only run git", by program basename), and
  `Fs` paths ("config may only read /etc/app", by path-prefix at a boundary). Certifies the *visible*
  surface only — a literal is read from the call that carries it (the `ProcessBuilder`/`exec` program,
  the `Path.of`/`File`/stream-ctor path, a scheme-URL/`host:port`/IP host); a runtime-computed value is
  honestly invisible, never over-claimed (validated on a real Spring app — the extractor takes the
  *first* arg, so a `ProcessBuilder("git","clone")` is `git` and a `RandomAccessFile(path,"r")` mode is
  never mistaken for a path).
- **`forbid <A> -> <B>`** (`AS-EFF-009`) — *who* a layer may depend on. A method in scope A must not
  *transitively* reach a method in scope B (reverse-reachability over the call graph).

Scopes match by dotted **segment** (so `domain` matches `app.domain.Svc.handle` and the `domain_logic`
package, but not `subdomain`) — the same rule as the Rust impl's `scope_matches`. A set-but-unreadable
policy fails **loud** ("policy NOT enforced"), never silently green.

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
fixpoint unions callee effects into callers. Same architecture as candor's first Rust version —
deliberately, so it grows along the same path (next: `Unknown`, then CHA).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
