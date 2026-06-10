# Using candor-java (instructions for an AI coding agent)

candor-java reports, for every method in a JVM codebase (Java, Kotlin, Scala, Groovy — it reads
bytecode), which side effects it performs, transitively. The language-agnostic consumption contract is
[candor-spec/AGENTS.md](https://github.com/tombaldwin/candor-spec/blob/main/AGENTS.md); this file is
the JVM-specific production + query surface.

## Produce a report

```sh
# zero-install (the fat jar):
jbang candor@tombaldwin/candor-java <classes-dir-or-jar> --json /tmp/report.json
# or: java -jar candor-java-<ver>-all.jar <classes-dir-or-jar> --json /tmp/report.json
```

Point it at **compiled output** (`build/classes/java/main`, a jar) — build first. Analyze
`main`, not test, classes (test code describes the harness). `--json` writes the report **and**
`/tmp/report.callgraph.json` (every method's direct callees, pure ones included — the blast-radius
input). Method names are dot-separated: `com.example.Svc.save`.

## Query it (same names/shapes as the Rust engine — candor-spec §3.1)

```sh
java -jar candor.jar show     /tmp/report.json <method> [--json]   # a method's effects
java -jar candor.jar where    /tmp/report.json Db [--json]         # direct sources vs inheritors
java -jar candor.jar callers  /tmp/report.json <method> [--json]   # the BLAST RADIUS (works for pure methods)
java -jar candor.jar whatif   /tmp/report.json <method> Net [policy] [--json]  # pre-edit gate verdict
java -jar candor.jar diff     /tmp/report.json baseline.json [--json]
java -jar candor.jar map|containment|reachable|path|impact /tmp/report.json …
```

Name queries resolve exact > segment-suffix (`Svc.save` matches `com.example.Svc.save`, never
`Svc.save_all`) > substring — same ladder as the Rust engine.

- **Blast radius of editing a method** → `callers <method>` (NOT its `inferred`, which is what the
  method itself does). Works pre-edit for a still-pure method.
- **Decide BEFORE you edit** → `whatif <method> <Effect> [policy]` — every transitive caller gains the
  effect; crossed with `CANDOR_POLICY` it returns which functions would violate.
- **Enforce in CI** → `CANDOR_POLICY` (candor-spec §6.2: `deny`/`pure`/`allow`/`forbid`) +
  `CANDOR_BASELINE` (regression guard). Deterministic — not an LLM opinion.

## JVM-specific things to know

- **Spring is read declaratively**: `@Transactional`/Spring-Data repos → `Db`; `RestTemplate`/
  `WebClient`/Feign → `Net`; `@*Mapping`/`@Scheduled`/listeners/lifecycle hooks → **entry points**
  (`entryPoint: true`, runtime-invoked roots — their effects are never orphaned even with no
  in-project caller). `reachable` unions effects over the entry points.
- **Runtime-invoked bodies** (Runnable/Callable tasks, `finalize`, servlet methods, Ktor route
  handlers) are entry points too; a *scheduled* task's effects also attribute to the scheduling
  method (lambdas + anonymous/local classes are edged at their creation site).
- **Multi-module**: set `CANDOR_DEPS=dep-report.json:…` so calls into separately-analyzed modules
  inherit their effects instead of reading pure; or analyze app + deps on one classpath for full CHA.
- **The pure-exempt dispatch set** (toString/equals/hashCode/compareTo; Kotlin/Scala/Groovy
  function-interface dispatch; Runnable/Callable on the external interface) is documented in
  [README](README.md) — an effectful override of those is not attributed at the dispatch site.

## The trust rule — do not skip this

`inferred` is authoritative for what candor-java resolved. When `unresolved` is true (or `Unknown` is
present — reflection, `native` bodies, Groovy metaclass dispatch, a project interface with no visible
impl), the set may be incomplete: read the source before relying on it. `unknownWhy` tells you whether
the opacity is irreducible (`reflect:`/`native:`) or fixable by widening the analyzed classpath
(`dispatch:`). Never conclude a method is pure while it is marked unresolved.
