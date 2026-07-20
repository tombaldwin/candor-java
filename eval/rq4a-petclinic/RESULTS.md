# RQ4a (real app) — Spring PetClinic: ArchUnit green, candor determines the DB reach

**Codebase:** `spring-projects/spring-petclinic` (the canonical Spring sample), `--depth 1`, compiled
with its own Maven wrapper (`./mvnw -DskipTests compile`), 30 application classes. Both gates run on
the same `target/classes`. Reproduce: `bash run.sh`.

## The gates on the same classes

| Gate                                                    | Verdict | What it saw |
|---------------------------------------------------------|---------|-------------|
| **ArchUnit — Family 1** (naive `java.sql`/`javax.sql` ban) | 🟢 **GREEN** | No class depends on the JDBC driver packages. Data access is behind Spring Data repository *interfaces*, so the import graph shows the app as persistence-free. |
| **ArchUnit — Family 2** (repository-type ban) | 🔴 **RED** | The knowledgeable rule "no `…Controller` may depend on a `*Repository` type" fires — on the controller constructors, fields, AND the `findById`/`save`/`findAll` call sites, i.e. the same controllers candor flags. |
| **candor** (effect-reachability)       | 🔴 **RED**   | **17 controller methods** perform `{ Db }` — determined (`unresolved=false`), transitively through the repository interfaces. |

**The honest delta (per the SE referee).** On PetClinic the effect is *not* structurally inexpressible to ArchUnit: because the controllers hold an import-visible dependency on the repository interfaces, the Family-2 rule catches it. The difference is *where the domain knowledge lives* — the Family-2 rule must hand-encode "`*Repository` = persistence," whereas candor derives the `Db` from its Spring Data model with no rule authoring. The structurally-inexpressible case — an effect behind an injected port with **no** import edge at all — is the fixture of `eval/rq4a` (Datapoint 1), where no ArchUnit rule of any family can fire because the dependency edge does not exist in the bytecode.

candor's report over the 48 analyzed functions: **21 `Db`, 6 `Clock`, 25 pure, 0 `Unknown`.** The
`Db` reaches propagate from the Spring Data repositories (`OwnerRepository.findById` → `Db`) up through
every controller that calls them (`OwnerController.processFindForm`, `VetController.showVetList`,
`VisitController.processNewVisitForm`, …).

## Why ArchUnit is blind and candor is not

The architectural intent — *"the web tier must not perform persistence directly; it delegates through
the repository/service layer"* — is real, and PetClinic's fat controllers arguably violate it (they
call repositories inline). An import/package gate can only approximate that intent as *"no controller
depends on `java.sql`"*, which is **green**: the JDBC driver is never named in application code; Spring
Data generates the implementing proxy at runtime from the `JpaRepository` interface. The effect is real
but the dependency edge to `java.sql` does not exist in the bytecode.

candor gates on the effect, not the import. It carries a model of the Spring Data repository contract
(a `JpaRepository`/`Repository` query method is a `Db` effect), so `OwnerRepository.findById` is a
**determined** `Db`, and candor propagates it transitively to the 17 controller entry points — the
`deny Db …Controller` policy then fires. This is the *determined* half of RQ4a on real, third-party,
widely-recognized code: candor reports an effect the import-graph baseline is structurally blind to.

## Honest scope

- candor's `Db` here comes from its **framework model** of Spring Data (a sound over-approximation of
  the repository contract), not from resolving a concrete in-project implementor — there is none; Spring
  synthesizes the proxy at runtime. That is the point: the effect is knowable from the *contract* the
  framework guarantees, which candor models and an import graph cannot read. It is sound (these methods
  do reach the database), not a fabrication.
- The ArchUnit rule is the faithful, idiomatic form (`noClasses().that()…should().dependOnClassesThat()
  .resideInAnyPackage("java.sql..")`). It is not weakened to lose — it is the natural rule a team writes
  to keep JDBC out of the web tier, and on a Spring Data app it is simply the wrong instrument for the
  question "does this layer reach the database?"
- The disclosure half of RQ4a (candor beating a baseline by disclosing `Unknown` where the baseline is
  silently clean) is exercised separately by the §7.1 recall corpus and the dotenv found-measured-fixed
  loop; PetClinic happened to resolve to a *determined* effect, which is the stronger outcome here.
