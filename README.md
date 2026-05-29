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

**Trust contract (candor-spec §4) — partial.** Reflection / dynamic invocation
(`Method.invoke`, `Constructor.newInstance`, `Class.forName`/`newInstance`, `MethodHandle.invoke`,
`Proxy.newProxyInstance`) is reported as **`Unknown`** with `unresolved: true`, never silently
assumed pure — it could call anything. So a consumer knows exactly where to stop trusting the report.

**Not yet (deferred honestly — PRINCIPLES #7):**
- `Unknown` for the **broader unresolvable dispatch** (interface/virtual dispatch to an unknown impl,
  lambdas/callbacks) — this needs **CHA** to first resolve what it *can*, else it floods (the same
  calibration the Rust impl learned); CHA is the next rung, on a WALA/SootUp substrate;
- **conformance / no-ambient / baseline** modes and the `declared`/`undeclared` fields;
- constructors (`<init>`/`<clinit>`) are skipped for now.

The honesty ceiling on the JVM is what even declarations don't capture: **custom** AOP aspects
(`@Aspect`/`@Around`), reflection / `getBean`, and multi-impl DI where the wired implementation is
unknown statically. Those should surface as `Unknown` once the trust contract lands; the
heavyweight route to resolving them is Spring Boot 3 **AOT metadata** (Spring's own ahead-of-time
processing resolves bean wiring, proxies, and reflection at build time). See candor-spec CLASSIFIER.md.

## Build & run

Requires JDK 21 + Gradle.

```sh
# compile the code you want to analyze to a directory of .class files (or point at a jar), then:
gradle run --args="/path/to/classes --json /tmp/report.json"
```

It prints a per-method effect audit and writes a candor JSON report.

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
