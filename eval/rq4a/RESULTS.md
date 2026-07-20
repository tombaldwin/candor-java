# RQ4a — architecture-conformance baseline vs. candor

**Claim (the motivating example of §2, run on code):** an import/package-dependency gate (ArchUnit —
the archetype of DSM/reflexion architecture conformance) passes **green** on exactly the boundary
candor fires **red**, because the guarded effect reaches the guarded layer through an injected port the
import graph cannot see through.

Both tools run against **the same compiled `.class` files**. Reproduce with `bash run.sh`
(JDK 21 + jbang + the candor-java fat jar; jbang fetches ArchUnit 1.3.0 from Maven Central once).

## The fixture

A ports-and-adapters slice of the `eval/gate` pricing fixture. The domain `pricing.Pricing.quote`
needs a live FX rate. It gets one through a `pricing.RateSource` **port** (an interface the domain
owns); the concrete `infra.HttpRateSource` adapter does the TCP fetch (`java.net.Socket`) and is
injected by the `app.Main` composition root. The policy is `pure pricing` — the domain performs no
effects. This is ordinary hexagonal wiring, and it is exactly the wiring that hides the domain's
network reach from a dependency-graph check.

A **control** (`control-inline/`) inlines the same `Socket` call directly into `pricing.Pricing`, so
the domain names `java.net` itself.

## Result (2×2, both gates on the same classes)

| Domain version                              | ArchUnit           | candor              |
|---------------------------------------------|--------------------|---------------------|
| **Ported** (`java.net` behind injected port) | 🟢 **GREEN**        | 🔴 **RED** (`Net`)  |
| **Inline** (direct `java.net` dependency)   | 🔴 RED              | 🔴 RED (`Net`)      |

- **Ported / ArchUnit GREEN:** both rules pass — `pricing` depends on neither `java.net..` nor
  `infra..`. Its import graph is genuinely I/O-free; the reach is behind the port.
- **Ported / candor RED:** `[AS-EFF-006] pricing.Pricing.quote performs { Net }, forbidden by policy`.
  A **determined** effect (not `Unknown`): candor resolves the `RateSource.current` call to its single
  in-project implementor `HttpRateSource.current`, follows the edge to `java.net.Socket`, and
  propagates `Net` transitively back to `quote`.
- **Inline / ArchUnit RED:** the control shows the ArchUnit rule **has teeth** — a *direct* `java.net`
  dependency is caught (5 violation lines). So the green on the ported version is the DI indirection,
  not a toothless rule.

## Why this is the §2 claim, not a strawman

The ArchUnit rule enforces the *same* boundary as the candor policy ("the pricing domain performs no
network I/O"), expressed the only way a dependency-graph tool can express it — a ban on depending on
`java.net`/`infra`. It is a faithful, idiomatic ArchUnit rule (the exact `noClasses().that()
.resideInAPackage("pricing..").should().dependOnClassesThat().resideInAnyPackage("java.net..")` form
in ArchUnit's own docs). It is not weakened to lose: it catches the inline control. It is blind to the
ported version because an import edge is neither necessary nor sufficient for effect reachability —
which is the paper's point. candor gates on *reachability*, so the port does not hide the effect.

This is the **determined** half of RQ4a (candor beats the baseline by *naming* an effect it is blind
to). The **disclosure** half — candor beating the baseline by *disclosing an Unknown* where the
baseline reports clean — is the Spring PetClinic datapoint (`../rq4a-petclinic/`).
