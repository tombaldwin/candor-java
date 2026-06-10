# Prove it on *your* JVM repo — a 15-minute self-experiment

The Rust engine's [PROVE-IT](https://github.com/tombaldwin/candor-rust/blob/main/PROVE-IT.md) explains the
protocol and why it's fair (manual answer committed first; every claimed miss verified by you at a
file:line; the negative result is in-scope and reported). This is the JVM variant — works on **Java,
Kotlin, Scala, or Groovy** code, since candor-java reads bytecode.

**Requirements:** a built JVM project (compiled classes or a jar), `jbang` (or just `java`), any
agentic coding tool.

**Paste this prompt into your agent at the repo root:**

---

```text
We're testing whether a static effect-analysis tool (candor-java) tells me things about MY codebase
that you'd otherwise miss or take longer to find. Follow these steps IN ORDER — the order is the
experiment's integrity (your manual answer must be committed before the tool's answer exists).

STEP 1 — Pick the target. Choose ONE method in this project's PRODUCTION code (main source set — not
tests) that performs I/O (network, filesystem, database, subprocess) and is called from more than one
place — ideally one I care about changing. If I named a method in my message, use that. State your
choice as a fully-qualified name (com.example.Type.method).

STEP 2 — MANUAL TRACE (commit before looking at any tool output). From source alone, answer: "Which
methods in this project would be affected if <target> changed its behavior — i.e. every TRANSITIVE
caller, across all files and call layers?" Work as you normally would (grep, read). Write the complete
list to /tmp/candor-manual.txt — one fully-qualified method per line. Note roughly how many
file-reads/searches it took.

STEP 3 — Build if needed, then run candor-java on the compiled MAIN classes:
  jbang candor@tombaldwin/candor-java <classes-dir-or-jar> --json /tmp/candor-report.json
(or java -jar candor-java-*-all.jar …). This also writes /tmp/candor-report.callgraph.json — every
method's direct callees, pure ones included.

STEP 4 — Compute the tool's answer from the callgraph sidecar (plain JSON — no magic): a ~10-line
script that loads it, builds the reverse edge map, and BFS's from the target to collect every
transitive caller. Save to /tmp/candor-tool.txt.

STEP 5 — Diff and VERIFY. Compare the lists.
- For each method candor found that your manual trace MISSED: reconstruct the call chain from the
  callgraph (target ← caller ← …) and open ONE file per missed method to confirm the call site is
  real, quoting the file:line. Real, verifiable edges — not tool assertions. (Note: a lambda or
  anonymous-class body attributes to the method that CREATES it; Spring `@Transactional`/repository
  effects come from declarations — both are explained in AGENTS.md if a chain surprises you.)
- For each method YOU listed that candor did not: a real caller candor missed is worth reporting at
  https://github.com/tombaldwin/candor-java/issues (reflection-driven calls are the documented
  honest-Unknown territory) — or it's a trace mistake.

STEP 6 — Scorecard. Report honestly:
- target method + the size of its true radius
- manual trace: N of M found, the specific misses with verified file:line evidence, and the
  reads/searches it took
- candor-java: one analysis + one script, complete set
- AND if the result is unflattering to candor-java, say so plainly: shallow radius / distinctive
  names → "on this codebase its value is speed/CI-gating, not completeness." Real candor misses
  (reflection-heavy dispatch is the documented blind spot — reported as Unknown, not silently) →
  report as the tool's limitation.

Do not soften either direction. The point is what's true on THIS repo.
```
