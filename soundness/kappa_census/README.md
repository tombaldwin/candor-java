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

**Unmeasured and highest-risk: the 25 covered prefixes with no jar in `soundness/lib`.** `org.jetbrains`
(zero owner literals in the classifier, and the prefix covers `org.jetbrains.exposed`, a SQL framework) and
`io.ktor` (3 owners, all client-side) are R493. Fetch the jars and run this rather than reasoning about it.
