# Minimal repro — the R8 (container-erased equals reentry) false all-clear

Confirms the `commons-collections4` violation the confirmatory oracle caught (FINDINGS.md) is a **real
candor miss**, not an oracle artifact, and pins it to the documented **R8** soundness boundary
(candor-spec/SOUNDNESS.md).

- `ClockMap` — a `Map` whose `get`/`entrySet` read the wall clock (the `PassiveExpiringMap` expiry-on-access
  shape). candor correctly infers these as `Clock`.
- `Decorator.equals` — `return decorated().equals(object)` (the `AbstractMapDecorator.equals` shape). candor
  infers it **PURE** (absent from the effectful report), yet at runtime `decorated().equals(clockMap)` reaches
  `Clock` because the JDK `HashMap.equals` calls `clockMap.get(k)`.

Reproduce:
    javac -d out $(find src -name '*.java')
    candor-java out --json out/report.json        # Decorator.equals is NOT listed => inferred pure

Root cause: candor is modular (no whole-program points-to), so at `decorated().equals(object)` it cannot
recover the erased concrete type of `object`. The sound-but-imprecise alternative — disclose `Unknown` for
every `.equals`/`.compareTo` on a non-final receiver — floods, so per candor's no-flood ethos this is a
**documented boundary (R8)**, not a code fix. The confirmatory oracle validated that R8 occurs in the wild.
