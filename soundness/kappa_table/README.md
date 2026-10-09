# The generated framework table — SOUNDNESS R492 / R727

`Rules.KAPPA_COVERED_PREFIXES` grants ~51 namespaces: a call into one that the classifier does not name
was certified pure. For language runtimes that is defensible; for frameworks it silenced real I/O
(groovy `deleteDir`, commons-csv `parse(File)`, Spring `FileSystemResource`, JNA `loadLibrary`, …).
This directory replaces the grant's blanket claim for the **surveyed** frameworks with two generated
resources:

| resource | what a line says |
|---|---|
| `src/main/resources/candor/framework-reach.tsv` | `owner.name+desc → effects`: the body the JVM resolves for that call reaches, along statically resolved edges, a body this engine's own scan charged with those effects (`direct`, concrete only). |
| `src/main/resources/candor/framework-hedge.tsv` | the RESIDUE: `A` — a member with no surveyed body (abstract/interface/native) some surveyed implementer of which is charged or unreadable, or which has none; `U` — every resolved body is one the scan read only as `Unknown`; `S` — a surveyed framework class (a class under a framework prefix and NOT listed is unsurveyed, `X`); `J` — a JDK package (keeps the grant). |

A member in neither file was **examined and found pure**: its silence is now a measurement.

    bash soundness/kappa_table/derive.sh build/libs/candor-java-*-all.jar          # regenerate
    bash soundness/kappa_table/derive.sh --check build/libs/candor-java-*-all.jar  # weekly CI

Inputs are `sources.tsv` (Maven coordinate + SHA-256 per jar; a mismatch is refused), `derive.sh`,
`FrameworkReachGen.java` and the engine jar (scanning with `-Dcandor.frameworkReach=off`, so the table
never feeds itself). Same inputs → byte-identical outputs. `KappaFrameworkReachTest` checks the content
and generator checksums on every push. `witness.tsv` (gitignored) gives every charge's path to its body.

## The named miss — the JDK is OPAQUE, framework bodies are TRANSPARENT

The closure stops at the JDK: there are no JDK bodies here, only the classifier's name rules. A framework
member whose effect happens inside a JDK body the classifier leaves uncharged is missed exactly as a
direct call to that JDK member is. R814 (`KappaJdkSinks`) is that frontier; this table does not move it.

## What it costs, measured (823-jar corpus vs published v0.40.1)

* **Charges are hub-shaped, not uniform.** 55,229 rows newly carry a concrete effect; **51.8% gain only
  cross-cutting effects** (Clock/Log/Rand — reported, not scored, SPEC §6.1). The hubs:
  * geode-core **16,224** rows from **5** `com.sun.jna.Native.register` call sites (Native's static
    initialiser loads the native library: Exec/Fs/Env — genuine, once per JVM);
  * `new ObjectMapper()` → **Clock** (`ByteQuadsCanonicalizer.createRoot` seeds from the clock):
    adyen 3,923 rows, kubernetes-model 1,609;
  * jna-platform `Structure.<init>` → **Log** (JUL warnings in `Native.getCharset`): ~2,200 rows per
    jna-platform jar;
  * groovy `ScriptBytecodeAdapter.castToType` → [Clock, Fs, Log, Net] — the largest PRECISION cost: its
    row is the union over Groovy's whole type ladder (`asCollection → ResourceGroovyMethods.readLines(File)`,
    SAM coercion → `ProxyGenerator`). `Candor.groovyCastArm` takes the ladder arm when the class argument
    is an `ldc` of `Object`/`String`/`Character`/`Boolean`/`Class` (javap-derived, sound); that removed
    812 of rest-assured's 1,802 flips. Casts to other classes keep the full row.
* **A correct scoped `allow` can go red.** A side charge with no captured locator marks the surface
  `incomplete` (`allow Fs in f /real/path` then fails): **21 strict rows** that had a captured locator for
  the effect (bcjmail ×15, spring-beans ×6), **1,883 Fs / 132 Net / 3 Exec loose** rows. A call whose
  File/Path operand IS a captured locator (`deleteDir(new File("/tmp/x/sub"))`) is judged by it instead.
* **The residue hedge** puts `Unknown` on **31,520** analysed units (**0.79%** of 3,976,208; 18,379 of
  them `Unknown`-only, the rest already effectful) — `deny Unknown` flips on those scopes, nothing else.
  Its imprecision is the library scan's own: `U` inherits every `Unknown` that scan reported, e.g.
  Spring `StringUtils.cleanPath` (it iterates a `Collection`).
* **Version drift.** A charge is a claim about the surveyed version. Measured against a second version:
  minor/patch 0 of 877 pairs differ; major 3.9% (groovy 3→4) / 8.7% (spring-core 5.3→6.1) — always an
  over-charge on the other version, never a purity claim. Charges in only one of two surveyed versions
  (61, all struts 1.2.9 vs 1.3.10) are made nowhere.

## Inherited, not introduced

Three over-charges ride through the table from LEAF rules that already fire at a direct call on v0.40.1
(SOUNDNESS R1052): `URL.openStream` is charged `Net` whatever its scheme (class-path config reads); a
whole-owner rule fires on its owner's own PRIVATE helpers (`RestTemplate.<init>(List)` →
`validateConverters` → Net); Spring AI's blanket model-SDK rule charges getters `Llm`.
