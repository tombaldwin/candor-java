# GraalVM native-image — a fast-startup `candor` binary

candor's analysis is fast (~1.4ms/class, linear) but the JVM costs **~70ms of fixed startup** per
invocation — and candor's flagship use is a **CI gate on every push** (plus agent loops), where that
startup is paid constantly and is ~half the wall time on a small repo. A GraalVM native binary cuts
startup to **~5–10ms** with no JVM warmup.

## Build

```
./gradlew nativeCompile          # -> build/native/nativeCompile/candor
```

Gradle auto-provisions a GraalVM toolchain via the foojay resolver (`settings.gradle.kts`), so no manual
GraalVM install is needed. The build takes a few minutes and a few GB of RAM (native-image is
AOT-compiling the whole closure). `clang`/Xcode CLT (macOS) or gcc (Linux) must be present.

Run it like the jar:

```
./build/native/nativeCompile/candor <dir-or-jar> --json out.json
./build/native/nativeCompile/candor --parallel out/ a.jar b.jar c.jar
```

## The one real native-image hazard: candor reads external bytecode at runtime

candor resolves JDK/library class hierarchies by reading their `.class` **bytes off its runtime
classpath** (`Cha.externalSupers`, via ASM `ClassReader` — e.g. to learn that some type extends
`java.io.InputStream`). On the JVM those JDK classes are on the classpath; **a native image carries no
`.class` files** (everything is AOT-compiled), so that read fails and candor would silently
**UNDER-report** effects — a soundness regression, and the dangerous direction. (Discovered exactly this
way: a first native build diverged from the jar on jsoup/gson — dropping `Clock`/`Unknown` on
`DataUtil.readToByteBuffer` — while petclinic, whose effects don't need external-supertype resolution,
matched.)

**Fix — a bundled JDK supertype index.** A build-time task (`generateJdkSupertypes`) walks the build
JDK's `jrt:/` modules and records each class's direct super + interfaces into a gzipped resource
(`candor/jdk-supertypes.idx.gz`, ~270KB, ~32k classes). `Cha.externalSupers` consults it **only when
`ClassReader` can't read the bytes** — so the JVM/jar path is unchanged (ClassReader succeeds there, the
index is never touched), and the native image resolves the same JDK hierarchies the JVM does. Result:
**native reports are byte-identical to the jar** (verified on pc/jsoup/gson/hikari).

Otherwise candor needs almost no native-image config:
- **No reflection on analysed code** — ASM reads bytecode as bytes; no `Class.forName` over scanned classes.
- **Serialization is manual** — `ReportJson` builds `LinkedHashMap`s / parses `JsonObject`s by hand; Gson
  is used only for generic Map/List formatting and ships its **own** native-image metadata in its jar.
- **Bundled resources** read via `getResourceAsStream`, included via `-H:IncludeResources`: `AGENTS.md`,
  `candor/build-info.properties`, and the JDK index `candor/jdk-supertypes.idx.gz`.

`--no-fallback` makes any missing config a hard build error rather than a silent JVM-fallback image. If a
future change adds reflection, regenerate metadata with the GraalVM tracing agent
(`-agentlib:native-image-agent=config-output-dir=...`) over the test suite and commit the `*-config.json`.

## Distribution

The jar (jbang) stays the primary, portable artifact. Native binaries are **per-platform** (macOS
arm64/x64, Linux x64/arm64), built in CI on release (`.github/workflows/native.yml`) and attached to the
GitHub release. Pick the binary when startup latency matters (CI gate, agent loops); use the jar when you
want one portable artifact.

## Parity is gated, not just hoped

The index fallback in `Cha.externalSupers` is **gated to native only** (`IN_NATIVE_IMAGE`, read from the
`org.graalvm.nativeimage.imagecode` property): on the JVM the only behavior is `ClassReader`-or-empty, so
the index can't make the JVM's output host-dependent and isn't even loaded there. In native, the fallback
resolves JDK supers from the bundled index (generated with the *same* ASM `ClassReader` the JVM path uses,
so super/interface semantics match exactly).

Because native and jar still resolve from different *sources*, `native.yml` runs a **parity gate**: it
builds both, scans candor's own classes with each, and fails the build if `functions[]` differ. After any
change touching reflection/resources/serialization/the index, that gate (or a local
`./build/native/nativeCompile/candor <target> --json` vs the jar) must stay green before the binary is
trusted — reports must be byte-identical to the jar's.
