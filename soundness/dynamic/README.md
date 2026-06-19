# Dynamic differential — the real-world soundness oracle

Static fixtures and the fuzzer (`../gen.py`, `../smear_probe.py`) can only plant effect leaves candor
**already knows**, so they cannot find *model gaps* — an effect that genuinely happens at runtime through
a path candor doesn't connect. This tool closes that hole with a **true oracle**: it runs a real program
under **JDK Flight Recorder** (built in — no agent), which records actual File/Socket I/O **with stack
traces**, maps each event's project frames to the effect, and diffs the observed per-method effects
against candor's **static** report. An effect observed on a method that candor reports pure (no effect,
no `Unknown`) is a **confirmed under-report**.

This is a **developer discovery tool**, run manually over real programs/corpora — not a deterministic CI
gate (it needs a runnable program and real I/O). The deterministic gates are the fuzzer + the probes in
`../`.

## Usage

```sh
# 1. produce candor's static report for the classes under test
java -jar build/libs/candor-java-*-all.jar <classes-or-jar> --json report.json
# 2. run the program under JFR and diff
soundness/dynamic/jfr_diff.py --cp "<classpath>" --main <MainClass> --report report.json --pkg <frame-prefix>
```

Self-test (validates the harness end-to-end on java.io + a loopback socket):

```sh
javac -d /tmp/st soundness/dynamic/SelfTest.java
java -jar build/libs/candor-java-*-all.jar /tmp/st --json /tmp/st.json
soundness/dynamic/jfr_diff.py --cp /tmp/st --main SelfTest --report /tmp/st.json --pkg SelfTest
# -> CLEAN (candor predicts every File/Socket effect the run performs, incl. the accept-thread lambda)
```

## Coverage

- **Sees:** `jdk.{File,Socket}{Read,Write}` → `Fs`/`Net`. This covers `java.io` *and* NIO reads that flow
  through a `java.io` stream wrapper (`BufferedInputStream` over a channel — the common real case).
- **Does not see:** pure-NIO channel I/O with no `java.io` wrapper, `Exec`, `Env`, `Db`, `Clock`, `Rand`.
  For full-spectrum coverage a custom leaf-instrumenting Java agent is the next step; JFR is the
  zero-setup 80%.

## Methodology gotchas (each a real false-positive source — handled in `jfr_diff.py`)

1. **Class-load noise.** The JVM reads the program's own jar/class files; those `FileRead` events carry
   the triggering *app* frames, falsely attributing `Fs` to whatever was loading a class. The tool drops
   events whose path is a `.jar`/`.class`/JDK-runtime file and keeps only genuine data files.
2. **Stack truncation.** `jfr print` truncates stacks unless `--stack-depth` is large; the deep project
   frames (below the JDK I/O frames) get cut. The tool uses depth 128.
3. **`Unknown` is a PASS.** candor disclosing `Unknown` is sound; only a silent effect-free report on an
   observed-effectful method is a bug.

## First real finding (2026-06-19)

Run against jsoup parsing a local file, the oracle surfaced a genuine under-report that ~95 fixtures, 3000
fuzzer chains, and the κ-leaf audit all missed: jsoup's **streaming parser** (`CharacterReader.bufferUp`
and its callers `TreeBuilder.parse` / `Parser.parseInput` / `*.initialiseParse`) reads the file *during*
parsing through an **abstract `java.io.Reader` field** (`bufferUp → reader.read()`), behind JDK wrapper
layers (`BufferedReader → InputStreamReader → StreamDecoder → ControllableInputStream → FileChannel`).
candor cannot trace the concrete file-backed reader behind the abstract `Reader` type, so it reports the
parser **pure**. This is the **abstraction-boundary κ-gap** — the effect leaf is reached through an
external abstract supertype whose concrete impl candor can't pin. It is exactly the model-gap class only a
real-execution oracle can find. (Fix is a design choice: fail-closed `Unknown` for `.read()`/`.write()` on
the abstract `java.io` I/O supertypes — sound but noisier — vs deeper field-concrete-type data flow.)
