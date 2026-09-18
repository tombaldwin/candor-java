# κ coverage census — is a COVERED-PREFIX grant still true?

**SOUNDNESS R492.** A prefix in `Rules.KAPPA_COVERED_PREFIXES` suppresses the `invisible` disclosure and
the coverage advisory for its whole namespace. That is an **unqualified purity claim over every unmodelled
member of it** — so a member the classifier does not name is not merely unknown, it is silently certified.
This census enumerates which members still need modelling, so the grant does not outlive the survey that
justified it.

## Why this is NOT a second copy of `soundness/kappa_libs_probe.py`

They answer different questions and **must not be unified** — the difference is the point:

| | `kappa_libs_probe.py` | this census |
|---|---|---|
| member set | a **CURATED** list of known effect leaves | **EXHAUSTIVE** over a jar's members |
| asks | does this leaf classify? | which members with a concrete effect does κ **fail** to classify? |
| fails when | a modelled leaf regresses | a grant covers a member nobody surveyed |

A hand list cannot find what nobody thought to list, and that is exactly the failure R492 records: the
`org.apache.commons.csv` grant reads *"CSV stacks (pure-relative over caller sources)"* and the package
holds **zero** rules, while its `File`/`URL` overloads open the resource themselves. `com.sun` was written
for the JDK and silently extends to **JNA**, whose entire purpose is loading native code. Generated
enumeration beats a hand list — the family has measured that before.

## What it measures, and the two deliberate choices

1. **`direct`, not `inferred`.** An `Unknown` inside a library body is the engine saying *"I cannot see
   in"*, not a coverage claim about a capability. Restricting to concrete `direct` effects took groovy
   from 10,764 candidate NULLs to 336 usable ones.
2. **`KappaQuery.java` queries the κ NAME TABLE directly** — no scan, no bodies. κ is name-based, so the
   library's own bytecode is needed only to enumerate candidates, never to classify them.

## The known false-positive mode — declared, not discovered later

**The owner in a library's own bytecode is not always the owner a consumer's call site emits.** Kotlin
multifile facades are the case in hand: the jar defines `PathsKt__PathUtilsKt` while kotlinc emits
`kotlin/io/path/PathsKt`, which *is* classified. **So every hit is a CANDIDATE, and must be confirmed on a
COMPILED CONSUMER before it is called a finding.** Every R492 finding met that bar; R493's did not, and is
filed as INFERRED for exactly that reason.

## Running it

    python3 soundness/kappa_census/map_prefixes.py          # which covered prefixes have a jar in soundness/lib
    CJ_ALL=build/libs/candor-java-<v>-all.jar PROBE=<dir with KappaQuery.class> \
      python3 soundness/kappa_census/census.py <report.json> <prefix,prefix,…>

Compile the harness into `$PROBE` first (`javac -cp $CJ_ALL -d $PROBE KappaQuery.java`).

## Scope already covered, so it is not re-derived

Measured clean **with evidence**: jackson, twilio, commons-lang3, guava `base`/`math`,
`com.google.maps.model` (0 concrete-effect members), the three scoped `org.hibernate.*` prefixes, and
kotlin/kotlinx once the facade artefact above was accounted for.

Deliberately **not** examined: `java`/`jdk`/`sun` (κ's designed builtin frontier — `kappa_probe.py` is the
standing instrument there) and `javax`/`jakarta` (only API jars here: interfaces with no bodies, so a
body-based census **cannot fail** and would be a vacuous gate).

## The sweep is COMPLETE (SOUNDNESS R493, 2026-09-18)

R493's two headline prefixes were **INFERRED**; they are now **MEASURED**, and worse than the row said —
on a consumer compiled against the real jars, `org.jetbrains`/Exposed and `io.ktor`/server were absent
from `functions` ENTIRELY with `coverage: null`, which under ⟨0.21⟩ is a certified purity claim, and
`deny Db` / `deny Net` both exited 0. Every covered prefix that has a fetchable jar has now been
censused; the jars are in `soundness/lib` (untracked).

**Do not re-derive the boundary.** Of 52 prefixes: 46 measured, and the SIX that are not, each for a
stated reason —

| not measured | why |
|---|---|
| `java`, `jdk`, `sun` | κ's designed builtin frontier; `kappa_probe.py` is the standing instrument |
| `javax`, `jakarta` | API jars only: interfaces with no bodies, so a body-based census **cannot fail** |
| `org.xml.sax` | ships in the JDK's `java.xml` module and is interfaces — the `javax` case exactly |

`org.hibernate.criterion` was measured against hibernate-core **5.6.15** (the package was removed in 6.x,
which is why `soundness/lib`'s 6.5.2 jar showed no classes for it) and is **clean: 0 concrete-effect
members**.

**Two residuals left OPEN rather than closed, both CANDIDATES that this census found and no compiled
consumer has confirmed** — the bar R493 exists to enforce:

- `org.apache.struts` — `RequestProcessor.doForward`/`doInclude` (63 census NULLs, mostly `Net`). An app
  SUBCLASSES RequestProcessor, so these are consumer-reachable, but confirming one needs a servlet
  container on the compile path.
- `org.displaytag` — `ExportDelegate.writeExport` / `TableTag.doEndTag` → `Net`, same obstacle.

**One deliberate NON-finding, recorded so it is not re-opened:** `org.threeten.extra.AmountFormats.wordBased`
and `org.joda.time.format.PeriodFormat.buildWordBased` read a `ResourceBundle` off the CLASSPATH. Measured
absent, and left that way: a classpath bundle lookup is not a filesystem disclosure in candor's model, and
charging it would put `Fs` on every localized format call in every library.

## The inverse: `weaker_claim_census.py` (SOUNDNESS R494, R496)

This census asks *"κ says NULL — is the grant certifying an unmodelled member?"*. Its sibling asks the
opposite: **"κ gave a CONCRETE answer — is that answer WRONG in the dangerous direction?"**

That direction had **no instrument at all** until R494, and the reason it hid is structural: an ABSENT
member floors to `invisible` and discloses itself; an OVER-charge is loud and the A/B's ADDED column
catches it. But a member classified to a weaker-but-plausible effect emits a positive, confident answer
that satisfies **every** disclosure channel the engine has.

It reads `inferred`, not `direct` — the opposite choice from this file, deliberately: the whole class is
about REACH, where the classified method performs the effect through a callee. Reading `direct` would
miss every instance.

**Its first real run found four candidates that R494's fix did not reach** (R496), including
`DefaultCredentialsProvider.resolveCredentials` — κ `Env`, body reaching `Exec`. All four were real and
were later confirmed on a compiled consumer.

> ### CORRECTION — the lesson first written here was WRONG, and the instrument was broken
>
> This section originally said: run against the pre-fix and post-fix classifiers the census printed
> IDENTICAL output, which "reads like a calibration failure and was not — the identity WAS the finding".
>
> **The identity was a BUG IN THIS INSTRUMENT.** `KappaQuery` printed the Java enum constant (`ENV`)
> while the report carries the spec name (`Env`), so `body − {κ answer}` never subtracted anything:
> **every classified member with any reach was reported as a hit, each one listing κ's own answer as
> "missing". The oracle could not return a negative.**
>
> The four candidates were genuine, but they arrived in a report that could not have said otherwise —
> which is not evidence, it is a coincidence. And the failure is the exact rule this project already
> holds: *"0 violations is not evidence until the oracle is PROVEN able to fail"*. I broke it **inside
> the instrument written to enforce that discipline**, and then drew a confident lesson from the
> symptom rather than testing whether the tool could produce a negative at all.
>
> **The correct lesson: when a before/after run does not discriminate, the FIRST question is whether the
> instrument can return a negative — not whether the rows are insensitive.** Prove the negative before
> interpreting the positive. Fixed by asking the authority (`Effect.specName()`) rather than spelling a
> second copy of the table in the reader — a second copy is how the two names diverged in the first place.

**Second declared defect: the census is blind to CO-EMITTED effects.** It queries `Classifier.classify`,
which is the κ table, not what the engine actually charges at a call site — so any rule that co-emits
(`Llm`+`Net`, the S3 `Fs` rule, R496's own fix) is invisible to it, and the five AWS owners still appear
as hits *after* being fixed. The remedy is one `coEmittedEffects(owner, method, desc)` authority called by
both `handleMethodInsn` and `KappaQuery`, so the reader cannot drift from the writer.

### R496 closed the four, and the full-corpus sweep priced the instrument

**R496 is FIXED** (see `Candor.handleMethodInsn`'s AWS co-emit block): the delegating resolvers —
`DefaultCredentialsProvider`, `ProfileCredentialsProvider`, `AwsCredentialsProviderChain`,
`internal.LazyAwsCredentialsProvider`, and the `AwsCredentialsProvider` INTERFACE every real consumer
actually calls — now carry `Env+Fs+Net+Exec`. `WebIdentityTokenFileCredentialsProvider`'s `Exec` was
**refused** on `javap` evidence and the refusal is asserted by a test.

**Two defects in this instrument were found by running it, and both are fixed here:**

1. **`KappaQuery` printed the ENUM CONSTANT (`ENV`), not the spec name (`Env`)**, so
   `body_effects - {kappa_answer}` never subtracted anything: **every classified member with any concrete
   reach was a hit**, and every hit listed κ's own answer under `missing`. The oracle could not return a
   negative — the calibration rule, broken inside the instrument written to enforce it.
2. **It queries the κ NAME TABLE, so it cannot see a CO-EMIT.** `Llm`+`Net`, the S3 `Fs` rule and now the
   AWS chain rule all add effects at the CALL SITE in `handleMethodInsn`, never in `Classifier.classify`.
   The five AWS owners therefore still appear in this census **after** the fix. Declared, not discovered
   later — and the fix that would close it is one authority (`coEmittedEffects(owner,method,desc)`) called
   by both `handleMethodInsn` and `KappaQuery`.

**The sweep — every jar in `soundness/lib`, 371 reports (grpc-context has no classes):**

    members-with-reach 414,439   kappa-classified 16,496   WEAKER-CLAIM 7,982  (48.4%)
    worst missing effect:  Exec 146   Net 2,006   Fs 4,170   Db 3   Env 1,611   Llm 46

**At 48% it is NOT a standing gate as written, and the reason is one mechanism.** Of the 42 distinct
Exec-missing candidates, **33 reach the fork only through a functional-interface hop** — `Runnable.run`,
`Closeable.close`, a `Handler` lambda — i.e. CHA resolving an interface call to every implementor, so a
jar holding ONE forking `Runnable` smears `Exec` across everything that touches a `Runnable`. Traced by
hand to a forking `Runnable.run`: liquibase (`ExecuteShellCommandChange$2.run`), kafka
(`Shell$ShellTimeoutTimerTask.run`), vert.x (`Watcher.executeUserCommand`), zookeeper
(`ClientCnxn$SendThread.run`). The remaining **9 are DIRECT chains**: the five AWS members (fixed), and —

| candidate | status |
|---|---|
| `org.eclipse.jgit.api.Git.open` → `FS.readPipe` (`javap`: `new ProcessBuilder(String[]).start()`) | **CANDIDATE** — real fork, platform-selected `FS` impl; no compiled consumer yet |
| `org.rocksdb.RocksDB.open`/`openReadOnly` | **UNTRACED** — `path` resolved a different overload |
| `org.apache.commons.exec.environment.EnvironmentUtils.getProcEnvironment` | **REFUTED** — declared FP mode 1. κ says `Env`; the body's `Exec` is candor's OWN over-charge of `DefaultProcessingEnvironment.getProcEnvironment`, which in commons-exec **1.4.0** only calls `System.getenv()` (`javap`: no `Runtime`/`ProcessBuilder` in the class) |

**What would make it a gate**, in the order that buys the most:

1. **Discount a hit whose path to the effect source crosses a functional-interface hop.** The callgraph
   sidecar already holds the path; this one filter removes 33 of the 42 Exec candidates.
2. **Ask what the ENGINE charges at a call site, not what the table says** — defect 2 above.
3. **Ratchet rather than threshold.** A clean absolute state is not reachable, and does not need to be:
   gate on *no NEW weaker-claim OWNER appears*, the shape the unknown-ratchet already uses. That makes the
   instrument usable today, at 48% noise, as a regression gate.
