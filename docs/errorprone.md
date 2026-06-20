# Error Prone — compile-time bug-pattern detection

[Error Prone](https://errorprone.info) is wired in as a javac plugin (`net.ltgt.errorprone`). It catches
bug *patterns* at compile time — reference-equality on objects, locale-dependent `toUpperCase`,
surprising `String.split`, format-string mismatches, ignored returns — many with a suggested fix. It
complements the existing `-Xlint -Werror` gate (deeper checks) and OpenRewrite (it *finds*; OpenRewrite
*rewrites at scale*).

## Off by default — advisory opt-in

Error Prone is **disabled** in normal builds, so `./gradlew build`/`test`/`shadowJar` and every gate are
byte-for-byte unchanged. Enable an advisory run with `-Perrorprone`:

```
./gradlew clean compileJava -Perrorprone     # `clean` (or a source change) — javac caches, so an
                                             #  UP-TO-DATE compile re-emits nothing
```

When enabled, findings print as **warnings** and `-Werror` is dropped for that invocation, so they never
block. This is the same "advisory before `-Werror`" posture used for `-Xlint`. The intended lifecycle:
run advisory → triage → fix or suppress (`@SuppressWarnings("CheckName")` with a why) → once a check is
clean, promote it to an error (`options.errorprone.error("CheckName")` in `build.gradle.kts`) so it can't
regress.

## Why advisory, not blocking (yet)

The first run surfaces a mix: real soundness-relevant smells worth fixing (locale-dependent case
conversion in type/host classification; reference-equality comparisons; `String.split` trailing-empty
behavior; Javadoc blocks silently dropped because two `/** */` precede one element) alongside
modernization/style noise (`StatementSwitchToExpressionSwitch`, `MissingOverride`, `NonApiType`). Turning
on `-Werror` for all of it at once would block the build on style. Triage first; promote per-check.

## Promoting a check to blocking

In `build.gradle.kts`, inside the `tasks.withType<JavaCompile>` block (when `errorproneOn`):

```kotlin
options.errorprone.error("ReferenceEquality", "StringCaseLocaleUsage")   // fail the build on these
options.errorprone.disable("StatementSwitchToExpressionSwitch")          // opt out of style noise
```

Then drop the `-Werror` exclusion for those once clean, or run them in CI behind `-Perrorprone`.

## Note for an agent working here

Error Prone is a fast, machine-readable second opinion the agent can run in a loop: `compileJava
-Perrorprone`, read the `[CheckName]` findings, apply fixes, re-run. It catches a class of bug that neither
grep nor a single compile surfaces (locale bugs, == vs equals, format-string drift) — directly aligned
with candor's soundness focus.
