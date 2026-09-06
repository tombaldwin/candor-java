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

## The second hazard, and it is the one that actually shipped: reflection ON CANDOR'S OWN CLASSES

⟨0.32⟩'s refresh overlay derives its accumulator set from `AnalysisContext.class.getDeclaredFields()` —
the `final`-means-output inversion that makes a new field merged-by-default. **`getDeclaredFields()` does
not fail when reflection metadata is missing; it returns a ZERO-LENGTH ARRAY.** Measured on GraalVM CE
21.0.2: 5 fields on the JVM, 0 in a `--no-fallback` image, no exception. So `mergeInto`'s loop ran zero
times, every class's per-class delta was dropped, and the v0.32.0 native binary reported **`0 functions
reach effects`** over a tree the jar found 210 in — a false all-clear, exit 0, nothing on stderr. The
release's parity gate is the only thing that caught it, which is exactly its job.

Two fixes, because either alone is a single point of failure:
- `src/main/resources/META-INF/native-image/io.poly.candor/candor-java/reflect-config.json` registers
  `io.poly.candor.AnalysisContext` with `allDeclaredFields`, so the image can enumerate them.
- `AnalysisContext.outputFields()` **refuses an empty field set** rather than merging nothing — a broken
  instrument must not be indistinguishable from an empty delta. `runScan` asks it once, before the first
  class is analysed, so the failure is one sentence with a remedy rather than 542 swallowed ones.

Adding a config file is not enough on its own: a config file is the kind of thing that goes stale
silently. Keep the refusal.

Otherwise candor needs almost no native-image config:
- **No reflection on analysed code** — ASM reads bytecode as bytes; no `Class.forName` over scanned
  classes. (Note the scope of that sentence: candor reflects on *itself*, see above.)
- **Serialization is manual** — `ReportJson` builds `LinkedHashMap`s / parses `JsonObject`s by hand; Gson
  is used only for generic Map/List formatting and ships its **own** native-image metadata in its jar.
- **Bundled resources** read via `getResourceAsStream`, included via `-H:IncludeResources`: `AGENTS.md`,
  `candor/build-info.properties`, and THREE build-time JDK indexes — `candor/jdk-supertypes.idx.gz`
  (§ above), `candor/jdk-sams.idx.gz` (SOUNDNESS R191) and `candor/jdk-hof-invokes.idx.gz` (R237).
  **This list was stale for two of the three until 2026-09-06**, which is the whole shape of R249: the
  list of what must be bundled lived in three places (this doc, the build file, nobody's gate) and only
  the build file was ever right.

`--no-fallback` makes any missing REFLECTION config a hard build error rather than a silent JVM-fallback
image. If a future change adds reflection, regenerate metadata with the GraalVM tracing agent
(`-agentlib:native-image-agent=config-output-dir=...`) over the test suite and commit the `*-config.json`.

**It says nothing about a missing RESOURCE, and reading it as though it did is how R249 happened.** Drop
an `-H:IncludeResources` line and the build succeeds; the binary then answers exactly what it answered
before that index existed — exit 0, nothing on stderr, rows simply gone from `functions[]`. Two gates now
cover that, and both are described in `ci/native-parity.py`:

- `./gradlew verifyNativeImageResources` (no GraalVM needed, runs in `ci.yml` and as a `processResources`
  finalizer) — every built resource must be named by an `-H:IncludeResources` pattern, and every pattern
  must match a resource. A dropped line, a mistyped one, a resource that stopped being generated, or a
  NEW resource added with no line: all four fail here.
- `native.yml`'s parity check now scans a second target, `src/nativeParity` — a fixture built so each
  index changes a named row — and asserts those rows on BOTH legs before comparing envelopes. Before
  this, the parity gate's only target was `build/classes/java/main`, where stripping any of the three
  indexes left 610 functions / 1,397 analyzed and a byte-identical envelope.

## Distribution

The jar (jbang) stays the primary, portable artifact. Native binaries are **per-platform** (macOS
arm64/x64, Linux x64/arm64), built in CI (`.github/workflows/native.yml`) and attached to the GitHub
release. Pick the binary when startup latency matters (CI gate, agent loops); use the jar when you want
one portable artifact.

**The build runs on every push to `main` and on every pull request, not only on a release.** It used to
run only on `release: published`, which meant the parity gate below first looked at a native binary
*after* the artifacts were public — see the ⟨0.32⟩ failure above, where it correctly withheld two
binaries but only once v0.32.0 already existed without them, costing a second family cut to repair. The
release event still builds and still checks; the only thing it does that `main` does not is **upload**.
Measured cost of the `main` build: 2m47s (linux-x64) / 3m40s (macos-arm64), in parallel, free runners.

## Parity is gated, not just hoped

The index fallback in `Cha.externalSupers` is **gated to native only** (`IN_NATIVE_IMAGE`, read from the
`org.graalvm.nativeimage.imagecode` property): on the JVM the only behavior is `ClassReader`-or-empty, so
the index can't make the JVM's output host-dependent and isn't even loaded there. In native, the fallback
resolves JDK supers from the bundled index (generated with the *same* ASM `ClassReader` the JVM path uses,
so super/interface semantics match exactly).

Because native and jar still resolve from different *sources*, `native.yml` runs a **parity gate**: it
builds both, scans candor's own classes with each, and fails the build if the reports differ. After any
change touching reflection/resources/serialization/the index, that gate (or a local
`./build/native/nativeCompile/candor <target> --json` vs the jar) must stay green before the binary is
trusted — reports must be byte-identical to the jar's.

The gate compares the **whole envelope**, not just `functions[]`, and it **refuses to run vacuously**.
Both were learned from the ⟨0.32⟩ failure above: that defect moved `functions` to 0 *and*
`analyzed.count` from 1329 to 0 *and* removed `coverage`, so a divergence confined to `analyzed`,
`excluded`, `outOfScope` or `netPartners` — every one of which a consumer's verdict reads — would have
passed a `functions`-only comparison. And because the gate is an *equality*, two empty reports are equal:
it now asserts the jar leg found something before their agreement is allowed to mean anything.
