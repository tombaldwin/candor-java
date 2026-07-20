# Confirmatory-corpus run — findings (first attempt)

Recorded honestly against the pre-registration (`PREREG.md`). The harness ran; the result is instructive
but **not** a confirmatory H-result yet, and this file says exactly why.

## What ran, and the numbers

Engine frozen at v0.23.1 (classifier unchanged). 10 held-out JVM repos built and were verified via
`candor verify … --run "mvn test"`; 2 failed to build (gson multi-module `-pl`, commons-fileupload-1.5).

**Across ~7,000 analyzed functions in the 10 built repos: 0 cardinal-sin violations, 0 fabrications — but
`executedFunctionsChecked = 0` on every repo.** The honesty invariant was therefore exercised on **zero**
functions. As-run this is a *fabrication-mirror* result (no over-report on held-out code), **not** an
H-confirmation.

## Why `checked=0` — three compounding causes, each verified

1. **The `-javaagent` does not reach `mvn`'s forked test JVMs (the dominant cause).** Diagnostic: the
   *known-good* developmental repo `commons-io` (which yielded 258 checked functions via the JUnit
   Platform **ConsoleLauncher** in a single JVM) gives **`checked=0`** when driven through this harness's
   `mvn test`. The verify stderr shows `Picked up JAVA_TOOL_OPTIONS` **once** — only the outer `mvn` JVM is
   instrumented; Surefire forks the test JVMs and the agent env does not propagate into them. `-DforkCount=0`
   did **not** fix it (still `checked=0`). So `mvn test` is the wrong driver; the working driver is the
   ConsoleLauncher with a per-repo test classpath, single JVM (what the developmental runs used).
2. **Effect delegation.** Even instrumented, many libraries perform their effects in the *JDK or a
   dependency*, not their own functions: `commons-imaging` reads via `InputStream`/classpath resources
   (not `new FileInputStream` in its code); `commons-email` delegates the socket to `javax.mail.Transport`;
   CSV/codec/lang transform *caller-opened* streams (charge-at-creation → the caller's effect). `commons-io`
   is productive precisely because it is a *thin I/O wrapper* whose own functions call `new FileInputStream`.
3. **Mocked/absent effects in unit suites.** `commons-net` socket tests need live servers (skip/mock);
   `commons-dbutils` tests largely mock JDBC rather than hit a DB.

## What was fixed / improved along the way (kept)

- **Oracle scope widened (`--scope all`) + a Db mapping added to `EffectMap`** (JDBC `execute*` / `commit`
  / `getConnection` → `Db`, high-precision, independent of candor's `Rules`). Clock was already covered
  (`System.currentTimeMillis`/`nanoTime`/`Instant.now`). This is a genuine oracle-recall improvement; it did
  not light up this corpus only because of causes (1)–(3), not because the mapping is wrong.
- **Runner hardened:** `git clean -fdxq` before each build (our own report/log artifacts were tripping the
  repos' Apache-RAT license check on re-runs); build logs written outside the repo tree; python-free parsing.
- **Manifest tags corrected** (imaging `1.0.0-alpha6`, fileupload drops the `rel/` prefix, email2→email).

## The honest status, and the remaining work

The pre-registered harness's **static + fabrication-mirror** arms work at scale (0 fabrications on ~7,000
held-out functions is real). The **H arm needs a different suite driver**: a ConsoleLauncher launched in one
JVM with a per-repo test classpath (`mvn dependency:build-classpath` + `test-classes` + the
`junit-platform-console-standalone` jar), and a corpus curated toward **thin-I/O-wrapper** libraries whose
own functions perform `Fs`/`Net`/`Exec` and whose suites do real in-process I/O — a smaller, harder-won set
than "popular dynamic-feature-rich libraries." That is the concrete next step; it is real infrastructure,
not a flag.

**Do not cite this run as an H-confirmation.** It confirms the fabrication mirror at scale and documents,
with a clean diagnostic, why confirmatory H-testing on frozen third-party library code is hard — which is
itself the honest reason the paper marks the at-scale H-corpus as pending.
