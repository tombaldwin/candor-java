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

## Result (2026-07-21; `results/FROZEN-SUMMARY.tsv`)

The `sha256` gate verified the frozen `0.23.1` binary, then the full manifest ran once. **41 functions checked
against real execution, 20 sound-complete (`D=∅`, the falsifiable frames), 0 false all-clears — H held on the
genuinely-unknown-outcome corpus.** A clean fresh-draw: unlike the replication slice, no violation surfaced
(no fresh R8-class catch), which is the honest outcome, not a strengthened claim.

| repo | disposition | analyzed | checked | sound-complete | disclosed | violations |
|---|---|---|---|---|---|---|
| commons-csv | disclosed-partial | 231 | 5 | 0 | 5 | 0 |
| joda-time | no-in-scope-effect-executed | 3167 | 0 | 0 | 0 | 0 |
| nanohttpd | disclosed-partial | 69 | 16 | 9 | 7 | 0 |
| jackson-core | disclosed-partial | 737 | 14 | 11 | 3 | 0 |
| commons-beanutils | no-in-scope-effect-executed | 733 | 0 | 0 | 0 | 0 |
| commons-validator | no-in-scope-effect-executed | 100 | 0 | 0 | 0 | 0 |
| commons-jexl | disclosed-partial | 1588 | 6 | 0 | 6 | 0 |
| commons-digester3 | **build-failed** | – | – | – | – | – |

**Read it honestly.** The falsifiable content is the 20 `D=∅` frames (nanohttpd 9, jackson-core 11), all held;
the disclosed-partial frames (`commons-csv`, `commons-jexl`, part of nanohttpd) are passes *by disclosure*, H
vacuous there. Two H-test intents under-fired: `commons-csv` charged its Fs frames as disclosed rather than
sound-complete, and **`joda-time` exercised no in-scope Clock frame** (`checked=0`) under the ConsoleLauncher
driver — a coverage gap, tabulated not narrated. The five fab-controls produced **no fabrication** (the ones
that ran clean at `checked=0` are the charge-at-creation mirror). So the fresh-draw is a *clean hold with
modest falsifiable coverage*, weaker in surfaced-content than the replication (which caught R8) but stronger
in outcome-unknownness — the two are complementary.

### Deviations (recorded, not narrated away)
- **`commons-digester3` build-failed** (`maven-compiler-plugin:2.1`, `source/target 5`): the source level is
  inherited from the downloaded `commons-parent` POM, not an in-tree pom, so the in-tree compat bump cannot
  reach it. Rescuing it would mean editing the frozen `build_cmd`; per the freeze discipline it is left as
  tabulated attrition (one of five fab-controls; its loss changes no result).
- **Build-compat bump broadened, post-freeze, classifier untouched.** The runner's source/target→8 bump was
  widened to cover bare `5`/`6`/`7` and the property form, and made `perl`-based for macOS/Linux portability
  (BSD `sed -i` was silently no-op'ing). This recovered `nanohttpd` (the Net H-test: 16 checked, 9
  sound-complete, 0 violations). Source level sets only the classfile version, not the bytecode effects candor
  reads, so this is pure build feasibility — the same deviation class the replication run recorded, and the
  `0.23.1` jar hash is unchanged (gate re-verified each run).
