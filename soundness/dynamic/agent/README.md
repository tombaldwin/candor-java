# Leaf-instrumenting agent — the Exec/Db dynamic differential

The JFR oracle (`../jfr_diff.py`) is the zero-setup 80%: it diffs candor's static report against actual
`File`/`Socket` I/O recorded by JDK Flight Recorder. But JFR only emits `jdk.{File,Socket}{Read,Write}`
events, so it is **blind to Exec and Db** (and Env/Clock/Rand). This directory is the "custom
leaf-instrumenting agent" the JFR README names as the next step — a runtime oracle for the **non-Fs/Net**
effects.

A `-javaagent` rewrites application bytecode to call `EffectRecorder.record(effect)` immediately before
every genuine effect-**leaf** call (the `LEAVES` table in `EffectAgent.java`). At runtime that records the
**actual** effect with the live Java call stack, attributing it to every project frame on the stack —
independent of how candor's static analysis reaches (or fails to reach) the leaf. `agent_diff.py` then
diffs the observed per-method effects against candor's static `inferred`: an observed effect that the
static set lacks **and** that is not disclosed `Unknown` is a confirmed model-gap under-report.

## Files

- `EffectRecorder.java` — runtime sink. `record(String effect)` walks `Thread.getStackTrace()` and adds
  the effect to every project frame; a shutdown hook writes a JSON map `{"Class.method":["Exec",...]}` to
  `-Dcandor.agent.out` (default `./agent-observed.json`). On the **system** classpath (see below).
- `EffectAgent.java` — `premain`. Appends the agent jar to the system classloader search
  (`appendToSystemClassLoaderSearch`) so instrumented app classes can resolve the `INVOKESTATIC`
  `EffectRecorder.record` target, then installs the ASM `ClassFileTransformer`. Holds the editable
  `LEAVES` table.
- `StubDriver.java`, `AgentSelfTest.java` — the end-to-end self-test.
- `agent_diff.py` — runs the program under the agent and diffs observed vs candor static.
- `build.sh` — pure `javac` + `jar` build (NOT wired into candor's gradle). `lib/` holds ASM 9.8
  (asm, asm-tree, asm-commons), copied from the gradle cache; they are unpacked into the agent jar so ASM
  resolves from the system classloader at premain time.

## Build + run

```sh
cd soundness/dynamic/agent
./build.sh                                   # -> build/candor-agent.jar

# self-test
rm -rf build/st && mkdir -p build/st
javac -d build/st AgentSelfTest.java StubDriver.java
java -jar ../../../build/libs/candor-java-*-all.jar build/st --json build/st.json
./agent_diff.py --cp build/st --main AgentSelfTest --report build/st.json --pkg AgentSelfTest
```

General use (any runnable program):

```sh
./agent_diff.py --cp "<classpath>" --main <MainClass> --report <candor.json> --pkg <frame-prefix> \
                [--args -- <program args>]
```

## Leaf table (editable in `EffectAgent.java`)

- **Exec**: `java/lang/ProcessBuilder.start`, `java/lang/Runtime.exec` (all overloads, by name).
- **Db**: `java/sql/{Statement,PreparedStatement}.execute*`, `java/sql/Connection.{prepareStatement,
  prepareCall,createStatement}`. The `java.sql.*` types are interfaces; the `INVOKEINTERFACE` owner in
  bytecode is the static interface type, so matching the static owner catches every driver impl.

## Limitations (honest)

1. **Bootstrap classes are not instrumented.** The transformer skips `java/`, `jdk/`, `sun/`,
   `com/sun/`. The leaves themselves live there, but we instrument the **call site** in app code, not the
   leaf — so an app method that *contains* the leaf call is caught. **Reflection moves the leaf invocation
   out of app bytecode:** `Method.invoke(...)` dispatches the real `ProcessBuilder.start` from JDK
   reflection internals, so the app's `reflectiveExec` frame is NOT at an instrumented call site and the
   agent does **not** record it (see self-test result below). This is the inverse of candor's static blind
   spot. Dynamic dispatch / interface calls (e.g. the JDBC `Db` case) keep the call site in app bytecode
   and ARE captured.
2. **Leaf-table-bound.** Finds *path losses* for the KNOWN leaves in the table (an effect that reaches a
   modelled leaf through a path candor's static analysis drops). It cannot find an *unmodelled* leaf —
   one not in the table. Extending coverage = adding rows.
3. **Performance.** Every loaded non-infra class is parsed + (if it contains a leaf call) rewritten with
   `COMPUTE_MAXS` at load time; `record` walks the full stack on each leaf hit. Fine for discovery runs,
   not for hot production paths.
4. **Per-frame attribution.** An effect is attributed to *every* project frame on the stack, matching
   candor's transitive `inferred` semantics. Synthetic `$$Lambda`/`$$` bridge frames are skipped (same as
   `jfr_diff.py`).

## Self-test result (JDK 21, macOS, this machine)

`agent_diff.py` on the self-test:

```
agent-diff: 3 project method(s) observed effectful (after --pkg filter)
  AgentSelfTest.directExec: observed ['Exec']; candor static ['Exec'] -> Exec=CLEAN(static)
  AgentSelfTest.main:       observed ['Db', 'Exec']; candor static ['Db', 'Exec', 'Unknown'] -> Db=CLEAN, Exec=CLEAN
  AgentSelfTest.stubDb:     observed ['Db']; candor static ['Db', 'Unknown'] -> Db=CLEAN(static)
agent-diff: CLEAN — every observed effect was statically predicted (effect or Unknown)
```

Interpretation:

- **`directExec` is CLEAN** — the agent recorded the real `Exec` at runtime; candor saw it statically
  (`inferred:["Exec"]`). Agreement.
- **`stubDb` Db is CLEAN** — the agent recorded `Db` fired through the **`java.sql` interface** call sites
  (proving interface-owner leaf matching works) and attributed it to `stubDb`; candor reported `Db` (plus
  `Unknown` for the proxy reflection). Agreement.
- **`reflectiveExec`** runs the same `ProcessBuilder.start` via `Method.invoke`. Candor was **sound**
  here: it statically resolved the reflective call to `Exec` and *also* disclosed `Unknown`
  (`unknownWhy: ["reflect:java.lang.reflect.Method.invoke"]`). The agent did **not** record this exec —
  because the real `start()` invocation happens inside JDK reflection internals, not at an instrumented
  app call site (limitation #1). So this case demonstrates candor sound, and the agent's known reflection
  blind spot, rather than a surfaced gap.

A negative control (doctoring the candor report to mark `stubDb` pure) makes `agent_diff.py` correctly
emit `UNDER-REPORT: AgentSelfTest.stubDb ran Db, candor static = PURE/absent` and exit 1 — confirming the
under-report detection path, not just the clean path.
```
