# Confirmatory-corpus run — findings

Recorded against the pre-registration (`PREREG.md`). Engine frozen at v0.23.1 (classifier unchanged; the
runtime *oracle* was improved — see below — which is a stronger falsifier, not a changed classifier).

## The result

Driving each held-out repo's suite through the **JUnit Platform ConsoleLauncher in one JVM** (see "Driver"
below) with `--scope all`, on code the classifier was **not** tuned against:

| repo | ref | analyzed | checked | sound-complete | disclosed-partial | **violations** | H |
|---|---|---|---|---|---|---|---|
| zt-zip (Fs) | zt-zip-1.17 | 251 | **110** | 25 | 85 | 0 | holds |
| commons-dbutils (Db) | 1.8.1 | 195 | **39** | 25 | 14 | 0 | holds |
| commons-codec | 1.17.1 | 142 | **11** | 3 | 8 | 0 | holds |
| commons-collections4 | 4.5.0 | 2826 | 18 | 7 | 10 | **1** | **VIOLATED** |
| commons-cli (control) | 1.9.0 | 230 | 0 | 0 | 0 | 0 | holds (vacuous) |
| zt-exec | zt-exec-1.12 | 145 | 0 | 0 | 0 | 0 | holds (vacuous) |

Also (separate, un-timed run): **commons-net** — 803 analyzed, **28 checked** (Net, socket clients), 0
violations, H holds. Excluded from the table because its suite connects to *real* external FTP/SMTP servers
and is timing-flaky (28 when it completes, 0 when the 8-min cap truncates it) — not reproducible enough to
pin.

So on held-out code the run exercised **~160 functions against real runtime effects across Fs / Db / Net**
(zt-zip 110 + dbutils 39 + codec 11 + net 28), H holds on all of them — and it **caught one false
all-clear**.

## The false all-clear it caught (reported, NOT fixed — per the pre-registration)

`org.apache.commons.collections4.map.AbstractMapDecorator.equals` — **observed `Clock`, inferred `[]`**
(candor declared it sound-complete/pure), `escaped: [Clock]`. Mechanism: `equals` is
`return decorated().equals(object)`; when the compared `object` is a `PassiveExpiringMap` (a time-expiring
map), the JDK's `HashMap.equals` calls back into that map's overridden accessors, which read the clock to
evict expired entries. candor analysed the delegating `decorated().equals(object)` — an interface call whose
target is argument-dependent — as **pure**, rather than disclosing `Unknown`. That is a genuine
missing-disclosure of the same class as the developmental synchronous-opaque-callback / dynamic-dispatch
finds (an **(A3)** reach under the collapsed call relation of §3.4): candor's overridden `PassiveExpiringMap`
methods correctly carry `[Clock, Unknown]` (rows in the verify JSON), but the *inherited* `equals` does not.
Per the pre-registration this is **recorded, not repaired**; a minimal repro to convert "flagged by the
confirmatory oracle" into a gated classifier fix is the natural (separate) follow-up.

## What made this work (vs. the first attempt's `checked=0` everywhere)

The first attempt drove suites with `mvn test` and got `checked=0` on everything — Surefire *forks* the test
JVMs and the `-javaagent` (wired via `JAVA_TOOL_OPTIONS`) does not propagate into the forks (proven: the
known-good commons-io gives `checked=0` through `mvn test`, `checked=217` through the ConsoleLauncher). Fixes
that got real coverage:

- **Driver:** run the whole suite via the JUnit **ConsoleLauncher in the single JVM the agent attaches to**
  (`run_corpus.sh` builds each repo's test classpath: main+test classes + test-scope deps + the
  console-standalone jar), not `mvn test`.
- **Oracle scope:** `--scope all` (covers `Clock`/`Db`/`Env`/`Rand`), and a new **Db mapping** in
  `EffectMap` (JDBC `execute*`/`commit`/`getConnection`). Without these, dbutils (Db) and the collections4
  Clock miss are invisible. The Db/Clock coverage is what surfaced *both* the dbutils hold **and** the
  collections4 violation.
- **Corpus selection:** libraries whose *own* functions perform effects with **deterministic local** I/O —
  zt-zip (files), dbutils (in-memory h2), zt-exec (processes) — not delegation libraries (imaging via
  InputStream, email via javax.mail) or pure transformers, and not network libraries that need live servers
  (commons-net's flakiness).
- **Robustness:** per-suite 8-min timeout (pool2's timing/concurrency tests hang the single JVM otherwise),
  `git clean` before each build (our artifacts tripped Apache-RAT), a pom `<source>1.6/1.7>`→`8` compat bump
  for pre-JDK-8 libraries.

## Honest scope

This is a *first* confirmatory slice, not the full pre-registered corpus at scale: 6 repos in the pinned
table + net, deterministic-local-effect libraries, JVM arm only. `zt-exec` and `commons-cli` are `checked=0`
(a process suite that skips in the container; a pure arg-parser) — valid fabrication-mirror datapoints (no
over-report), not H-tests. But it is a **real** confirmatory result: on held-out code the honesty invariant
held on ~160 effect-exercising functions and the oracle **caught a real false all-clear** — the falsifier
doing exactly what the paper claims, on code we did not write and did not tune against.
