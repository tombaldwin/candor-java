# candor-java

A [candor-spec](https://github.com/tombaldwin/candor-spec) implementation for the JVM. Reports, per
method, which side effects it performs (transitively) — Fs, Net, Db, Exec, Env, Clock, Rand, Log… —
read from compiled bytecode via [ASM](https://asm.ow2.io/). Sibling of the Rust reference
implementation, [candor](https://github.com/tombaldwin/candor).

## Status: early prototype (v0)

**Works:** audit mode — resolves each call, classifies it against the effect table (matching the I/O
boundary, not the package), and propagates transitively to a fixpoint over the call graph. Emits the
candor JSON report.

**Spring-aware.** Spring hides effects in framework-woven/generated code (`@Transactional`'s
transaction lives in a runtime proxy; Spring Data repository impls are synthesized at runtime) and
breaks the call graph (controllers/listeners are invoked reflectively). Pure bytecode tracing misses
all of it — so candor-java reads Spring's **declarations** instead:

- `@Transactional` (method or class) → `Db`
- Spring Data repositories (`extends CrudRepository`/`JpaRepository`) → calls to them are `Db`
- `RestTemplate` / `WebClient` / `@FeignClient` → `Net`; `JdbcTemplate` / `EntityManager` → `Db`;
  `JmsTemplate` / `KafkaTemplate` → `Net`; `Environment.getProperty` → `Env`
- `@GetMapping`/`@*Mapping`, `@Scheduled`, `@KafkaListener`/`@*Listener` → marked as **entry points**

On `spring-sample/`, `register()` (a `@Transactional` method calling a Spring Data repo + a
`RestTemplate`) correctly infers `{ Db, Net }`, and the `@GetMapping` controller inherits
`{ Db*, Net* }` and is flagged `[entry]` — effects that live in no method body candor could see.

**Trust contract (candor-spec §4).** candor-java surfaces what it can't see as `Unknown`
(`unresolved: true`), never silent-pure:
- **Reflection / dynamic invocation** (`Method.invoke`, `Constructor.newInstance`,
  `Class.forName`/`newInstance`, `MethodHandle.invoke`, `Proxy.newProxyInstance`) → `Unknown`.
- **Class Hierarchy Analysis** resolves interface/virtual dispatch over project types to their
  implementations, so effects propagate *through* dispatch (a call on a `Greeter` interface inherits
  the union of its impls' effects). Dispatch over a **project interface/abstract with no visible
  impl** (DI-wired, external, strategy) → `Unknown`.

CHA is done with the class hierarchy ASM already gives us — no WALA/SootUp needed.

**Not yet (deferred honestly — PRINCIPLES #7):**
- dispatch over **non-project (JDK/library) types** that the classifier doesn't recognise is assumed
  pure rather than `Unknown` — otherwise every `list.add()` floods the report (the calibration the
  Rust impl learned). Known-effectful libraries are caught by the classifier; the rest is a
  documented residual gap.
- lambdas/callbacks via functional interfaces, and constructors (`<init>`/`<clinit>`).

The deepest JVM ceiling is what even declarations + CHA don't capture: **custom** AOP aspects
(`@Aspect`/`@Around`) and beans wired by reflection (`getBean`). The heavyweight route to those is
Spring Boot 3 **AOT metadata** (Spring's own ahead-of-time processing resolves bean wiring, proxies,
and reflection at build time). See candor-spec CLASSIFIER.md.

## Build & run

Requires JDK 21 + Gradle.

```sh
# compile the code you want to analyze to a directory of .class files (or point at a jar), then:
gradle run --args="/path/to/classes --json /tmp/report.json"
```

It prints a per-method effect audit and writes a candor JSON report.

## Modes

| Mode | How | Output |
|---|---|---|
| **audit** (default) | `gradle run --args="<classes>"` | per-method effect map |
| **JSON** | add `--json <file>` | the candor JSON report — per method: `inferred`, `direct`, and **conformance** (`declared`/`undeclared`/`overdeclared`, projected from the class's injected deps) so an agent can consume conformance, not just the diagnostics |
| **regression guard** | `CANDOR_BASELINE=<saved.json> gradle run --args="<classes>"` | `AS-EFF-005` + **exit 1** if any function gained an effect vs the snapshot |
| **no-ambient** | `CANDOR_NO_AMBIENT=1` (or a name prefix) | `AS-EFF-004` for direct ambient-authority use (route it through an injected collaborator) |
| **conformance** | `CANDOR_STRICT=1` (or a class-name prefix) | `AS-EFF-001/002/003` — a class performs an effect no injected dependency provides (or injects one it never uses) |

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
