# κ coverage census — is a COVERED-PREFIX grant still true?

**SOUNDNESS R492.** A prefix in `Rules.KAPPA_COVERED_PREFIXES` suppresses the `invisible` disclosure and
the coverage advisory for its whole namespace. That is an **unqualified purity claim over every unmodelled
member of it** — so a member the classifier does not name is not merely unknown, it is silently certified.
This census enumerates which members still need modelling, so the grant does not outlive the survey that
justified it.

## Why this is NOT a second copy of `soundness/kappa_libs_probe.py` (nor of `rule_fires.py`)

They answer different questions and **must not be unified** — the difference is the point:

| | `kappa_libs_probe.py` | this census | `rule_fires.py` |
|---|---|---|---|
| member set | a **CURATED** list of known effect leaves | **EXHAUSTIVE** over a jar's members | **EXHAUSTIVE** over a jar's members |
| version | the pinned jar | the pinned jar | the **LATEST PUBLISHED** release |
| asks | does this leaf classify? | which members with a concrete effect does κ **fail** to classify? | do these rules still MATCH ANYTHING? |
| fails when | a modelled leaf regresses | a grant covers a member nobody surveyed | the library MOVED and every rule now misses |

`rule_fires.py` is the R509 instrument and is described in its own docstring and in
`soundness/rule_fires.sh`. Run it with `bash soundness/rule_fires.sh`; prove it can still fail with
`bash soundness/rule_fires.sh --calibrate`. It is deliberately **not** a version sweep: the R508 sweep
argued against making this census read N jars per prefix — that multiplies an exhaustive enumeration by
N and answers a question no single user has — so `rule_fires.py` asks ONE question of ONE jar instead,
and the only signal it reads is the match count going to **zero**.

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

## The third instrument: `rule_fires.py` — "does the rule still FIRE?" (SOUNDNESS R508/R509)

This census asks *"κ says NULL — is the grant certifying an unmodelled member?"*, and
`weaker_claim_census.py` asks *"κ gave a concrete answer — is it wrong in the dangerous direction?"*.
Neither can see R509, and the reason is structural: **both read the ONE jar that happens to sit in
`soundness/lib`.** R509 was a rule that was correct for that jar and matched nothing at all in the
library's current release — Exposed 1.0.0 moved `org.jetbrains.exposed.sql.QueriesKt` to
`org.jetbrains.exposed.v1.jdbc.QueriesKt`, every `owner.equals` missed, the block fell to `return null`,
and `org.jetbrains` is κ-COVERED, so that null was a certified purity claim. Its **corpus reach was
ZERO** — no jar of 372 references `org/jetbrains/exposed/v1` — so the A/B could not have found it either.

    bash soundness/rule_fires.sh              # the probe
    bash soundness/rule_fires.sh --calibrate  # prove it can FIRE and can be SILENT
    bash soundness/rule_fires.sh --offline    # re-probe what is already downloaded

**Scope is the κ-COVERED prefixes and no further.** On a non-covered prefix a rename floors the call to
`invisible` and is DISCLOSED — loud. Coverage is the only place a rename is a cardinal sin.

**In scope = a jar in `soundness/lib` whose members already match ≥1 rule** (84 of the 372). That is the
authority-derived spelling of *"this prefix has owner rules"*: a prefix that is pure by grant has a
baseline of 0 and cannot raise a phantom. `probe_coords.json` maps each in-scope jar to its Maven
coordinate; entries without a single `META-INF/maven/**/pom.properties` are filled by hand and every one
resolves (`--check-coords`).

**Jars land in `kappa_census/latest_jars/`, NOT in `soundness/lib`** — gitignored, and separate on
purpose: two versions of one library on `kappa_libs_probe`'s shared compile classpath is the
shared-instrument contamination `CLAUDE.md` warns about, and a previous agent had to move a second
hibernate out of that directory for exactly this reason.

**Where it belongs: a scheduled or pre-release sweep, not a blocking PR gate.** Cost is small — 40s and
83 MB over 71 downloads cold, 18s warm — but the run is **not hermetic**: its verdict depends on what
Maven Central published today, not on the commit under test. A red lands independently of any change,
and a PR gate that reddens for reasons the PR did not cause is the shape that gets switched off.

**Adjudicated zeros live in `ADJUDICATED` in `rule_fires.py`, as a DENYLIST with the evidence in each
entry**, never as a threshold. Two exist, both module consolidations: `exposed-core` (1.x is the pure
AST; the execution surface moved to `exposed-jdbc`, which matches 239) and `ktor-server-host-common-jvm`
(3.6.0 is a one-class compatibility stub, `StubKt.stub(); 0: return`, after Ktor 3 folded it into
`ktor-server-core`). Both name the SIBLING artifact that still carries the rules, so the entry cannot
quietly cover a real regression there.

**A version note in a comment is not the mechanism.** R508 added those deliberately — they record which
versions were checked so the next agent does not re-derive a clean negative — but a comment cannot
notice a rename that happens after it was written. This probe is the mechanism.

## `javap_calls.py` — the carve-out derivation tool, with the defect it had

Every `javap`-derived carve-out in `Classifier.java` (R480, R486, R487, R493, R508 and the ehcache gap
above) was derived by reading a method's call targets out of `javap -c`. That was a fresh ad-hoc pipeline
each time, which is §G of the corpus brief — *fifteen paths computing one fact* — so it is a file now:

    python3 soundness/kappa_census/javap_calls.py <jar> '<class-path-regex>'

One line per member: `<class>#<javap member line>` then its call/allocation targets. **Method-scoped, so
a reference in a DIFFERENT member cannot be misread as this one's** — which is the whole reason to run
this rather than `javap -c … | grep ProcessBuilder`.

**The defect it shipped with, recorded so the next hand-rolled copy does not reintroduce it:** the member
regex matched only method-SHAPED lines, so javap's `static {};` did not reset the current member and a
class initializer's calls were attributed to the accessor printed above it. That falsely flagged
`net.bramp.ffmpeg.FFmpeg.getPath()` in 0.3/0.4/0.5 as reading `System.getenv` — javap shows it as
`aload_0; getfield path; areturn`, and the `getenv` belongs to `static {}` initialising `DEFAULT_PATH`.
**Every line javap prints at indent 2 ending in `;` is a member boundary**, fields and `static {}`
included.

And when a sweep with it comes back clean: **point it at a member you KNOW is effectful first.** On
ffmpeg the six carved-out pure types flag 0 targets while `FFcommon`/`FFmpeg`/`RunProcessFunction` on the
same jars flag 9/28, 22/71 and 30/85 — that contrast is what makes the zero a measurement.
