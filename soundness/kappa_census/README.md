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
`DefaultCredentialsProvider.resolveCredentials` — κ `Env`, body reaching `Exec`. Worth recording how that
looked: run against the pre-fix and post-fix classifiers it printed IDENTICAL output, which reads like a
calibration failure and was not. **The identity WAS the finding** — those rows are unfixed in both. The
lesson generalises: when a before/after run fails to discriminate, establish whether the rows are
insensitive to the change before concluding the instrument is.
