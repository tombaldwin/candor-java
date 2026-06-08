# soundness — adversarial fuzzer

Makes candor-java's trust contract ("never silently pure — report the effect or `Unknown`") a *tested
gate*, not a hope. Sibling of the [Rust impl's `soundness/`](https://github.com/tombaldwin/candor/tree/main/soundness).

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
