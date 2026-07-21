# Fresh-draw confirmatory run — JVM arm (genuinely-unknown outcome)

The replication run next door (`../corpus-confirmatory`) is a *frozen replication* of the already-caught R8
slice: its value is the machine-enforced no-adaptivity and the reproduced-not-fixed catch, **not** an unknown
outcome. This directory closes that gap: the **same frozen classifier** (candor-java `0.23.1`, jar
`sha256 = bf572eb32db56ef419c8ad7d8f118cfe225f859320252c6969299434263e10d8`) run on a **new held-out corpus
whose outcome nobody knew at freeze time**.

## Freeze discipline (committed before the run)

- **Classifier:** the identical `0.23.1` -all.jar, pinned by `sha256`. `run_frozen.sh` aborts on a hash
  mismatch — "frozen binary" is machine-enforced, not asserted. No classifier change rides along; a violation
  is **reported, not repaired**.
- **Corpus:** `manifest.tsv`, 8 repositories, each version-pinned to a release tag. **Held-out twice over**:
  none appears in the replication manifest (`../corpus-confirmatory/manifest.tsv`) and none in the
  developmental set (`../corpus-confirmatory/EXCLUDED.md`). The classifier was never tuned against any of them.
- **Protocol:** identical to the replication runner — clone@tag → build (`process-test-resources
  test-compile`, JDK-8 source/target compat bump only) → static scan → dynamic `verify` driving the repo's
  **own** test suite through the JUnit ConsoleLauncher in the **single agent JVM** (`--scope all`). Per-repo
  disposition, attrition tabulated not narrated.
- **Acceptance / falsification:** a repo row is a **VIOLATION** iff an executed function with `D=∅` is charged
  an effect its inferred set omits (a false all-clear). Disclosed `Unknown` is a pass; `checked=0` on a
  fab-control is the fabrication-mirror pass (charge-at-creation, no over-report), not a coverage claim.

## Corpus design (pre-registered intent)

Three **H-test** repos exercise a real effect in their *own* functions, one per class — Fs (`commons-csv`),
Clock (`joda-time`), Net (`nanohttpd`) — so H is *falsifiable* on executed frames. Five **fab-control** repos
are dynamic/reflective code that must **not** fabricate an effect (`jackson-core`, `commons-beanutils`,
`commons-validator`, `commons-jexl`, `commons-digester3`) — the over-report mirror. Selection over-samples
dynamic-feature density (reflection, opaque dispatch, streaming over caller-supplied I/O), the shapes where a
false all-clear or a fabrication would live, not "popular repos."

## Result

Filled in from `results/FROZEN-SUMMARY.tsv` after the run. The outcome was unknown at freeze.
