# candor-java

A [candor-spec](https://github.com/tombaldwin/candor-spec) implementation for the JVM. Reports, per
method, which side effects it performs (transitively) — Fs, Net, Db, Exec, Env, Clock, Rand, Log… —
read from compiled bytecode via [ASM](https://asm.ow2.io/). Sibling of the Rust reference
implementation, [candor](https://github.com/tombaldwin/candor).

## Status: early prototype (v0)

**Works:** audit mode — resolves each call, classifies it against the effect table (matching the I/O
boundary, not the package), and propagates transitively to a fixpoint over the call graph. Emits the
candor JSON report.

**Not yet (deferred honestly — candor-spec PRINCIPLES #7):**
- the **trust contract's `Unknown`** for unresolvable dispatch (interface/virtual dispatch to unknown
  impls, lambdas/`invokedynamic`, reflection) — v0 reports *resolved* effects only;
- **dispatch resolution** (CHA/RTA over the class hierarchy) — the substrate for that is WALA/SootUp;
- **conformance / no-ambient / baseline** modes and the `declared`/`undeclared` fields;
- constructors (`<init>`/`<clinit>`) are skipped for now.

The honesty ceiling on the JVM is reflection / AOP / proxies (Spring) — exactly what defeats static
call graphs. Those will surface as `Unknown` once the trust contract lands.

## Build & run

Requires JDK 21 + Gradle.

```sh
# compile the code you want to analyze to a directory of .class files (or point at a jar), then:
gradle run --args="/path/to/classes --json /tmp/report.json"
```

It prints a per-method effect audit and writes a candor JSON report.

### Try the sample

```sh
javac -d /tmp/s sample/Sample.java
gradle run --args="/tmp/s"
```

## How it works

ASM reads each `.class` into a node tree; for every method, each resolved call (`MethodInsnNode`) is
classified by its target's class + method name; calls to project methods become call-graph edges; a
fixpoint unions callee effects into callers. Same architecture as candor's first Rust version —
deliberately, so it grows along the same path (next: `Unknown`, then CHA).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
