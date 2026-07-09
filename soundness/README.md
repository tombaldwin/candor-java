# soundness — adversarial fuzzer

Makes candor-java's trust contract ("never silently pure — report the effect or `Unknown`") a *tested
gate*, not a hope. Sibling of the [Rust impl's `soundness/`](https://github.com/tombaldwin/candor-rust/tree/main/soundness).

`gen.py <seed> <dir>` emits a compilable `Gen.java` that threads a **known** effect (`Fs`/`Net`/`Exec`/
`Env`) from a `sink` method up through a random chain, where each call edge uses a randomly chosen
**JVM call form** — the ways an effect can reach a method on the JVM:

- `direct` — a static call (`invokestatic`),
- `lambda` — `Runnable r = () -> callee();` (the body is a `lambda$` synthetic, edged via the
  `invokedynamic` bootstrap handle),
- `methodref` — `Runnable r = Gen::callee;` (a method-reference handle),
- `ctor` — the effect lives in a constructor (`<init>`), reached by `new Ctor()`,
- `clinit` — the effect lives in a **static initializer** (`<clinit>`), reached by a static call /
  field access that triggers the class-load,
- `iface` — interface dispatch, resolved by CHA to the concrete impl,
- `anon` — an anonymous class implementing `Runnable`, resolved by CHA.

Every emitted method transitively reaches the effect, so candor-java must report each `Gen.fNN` / `sink`
/ `main` with that effect **or** `Unknown`. A method reported PURE — or omitted (candor omits pure
methods) — is a SILENT UNDER-REPORT, the bug class this hunts. `Unknown` is a PASS: this tests
**soundness** (never silent-pure), not precision.

```sh
bash soundness/run.sh [N]                          # fuzz the first N seeds (default 40)
SEEDS="1 2 99" bash soundness/run.sh               # specific seeds
CANDOR_FUZZ_FORMS="ctor clinit" bash soundness/run.sh   # restrict to chosen forms
CANDOR_FUZZ_EFFECTS="Fs Net" bash soundness/run.sh      # restrict to chosen effects
```

**Teeth-verified:** reverting a fix makes the matching form's lane fail — e.g. neutering the
`<clinit>` trigger-edges makes every `clinit`-form chain come back `pure/omitted`.

Why the JVM has fewer hiding places than Rust HIR: bytecode is already *lowered* — every call is an
explicit `invoke*` instruction, so there is no operator-overload / `?` / `.await` desugar that can hide
a call. The remaining surface is dispatch (CHA), the synthesized forms (lambdas, anon classes), and the
implicit bodies (`<init>`, `<clinit>`, `native`) — which this fuzzer (and the smoke suite, for
`native`) covers.

## Probe inventory (the full soundness battery in this directory)

The fuzzer above is one instrument of several. Direction key: **under-report** = a real effect reads
silent-pure (candor's cardinal sin); **over-report** = a pure member is minted effectful (fabrication —
the opposite, precision failure); **meta** = does the battery itself still have teeth.

| probe | direction guarded | CI cadence |
|---|---|---|
| `gen.py` + `check.py` (chain fuzzer, via `run.sh`) | under-report: a known effect threaded through the JVM call forms must read effect-or-`Unknown`, never pure | every push/PR (`ci.yml`, 40 seeds) |
| `fabrication_probe.py` | over-report: pure accessors/factories of effect-bearing owners must stay pure (+ LOST-CONTROL twin: the effectful member must stay effectful) | every push/PR (inside `run.sh`) |
| `entrypoint_probe.sh` | under-report from the root walk: runtime-invoked callbacks (`readObject`/`finalize`/…) must be rooted `entryPoint:true` (+ no-fabrication twin on unrelated classes) | every push/PR (inside `run.sh`) |
| `functional_sam_probe.sh` | under-report: lambda-only SAM dispatch must read `Unknown`, never pure (+ no-flood twin: `List.size` stays pure) | every push/PR (inside `run.sh`) |
| `smear_probe.py` | over-report: an escaped-uninvoked lambda's effect must not smear via `<clinit>` onto unrelated methods | every push/PR (inside `run.sh`) |
| `kappa_probe.py` | under-report at the leaf: the common JDK effect leaves classify, all 10 effects | every push/PR (inside `run.sh`) |
| `kappa_libs_probe.py` | under-report at the leaf, third-party: ~440 real library effect leaves + ~160 anti-fabrication pure anchors | weekly (`soundness-weekly.yml`) |
| `mutation_probe.sh` | meta: 14 injected known soundness bugs must each turn a probe red (a suite that only passes proves nothing) | weekly (`soundness-weekly.yml`) |
| `dynamic/` (JFR oracle + bytecode agent + `corpus.sh`) | shared blindness: a runtime-observed effect candor neither predicts nor discloses fails the run — ground truth, catches what all static probes share | every push/PR (`ci.yml` dynamic-oracle job) |
| `reentrancy.sh` | over-report: static analysis state leaking across in-process scans (a dirty first scan must not shift the second's report) | every push/PR (`ci.yml`) |
| `run_kotlin.sh` (+ `KotlinProbe.kt`) | under-report via Kotlin bytecode shapes: suspend/CPS state machines, invokedynamic lambdas, companion `<clinit>`, inline fns | every push/PR (`ci.yml` kotlin job) |
