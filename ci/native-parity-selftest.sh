#!/usr/bin/env bash
# SOUNDNESS R249 — WATCH THE PARITY GATE FAIL, ON A MACHINE WITH NO GRAALVM.
#
# A gate nobody has watched fail is not a gate. `native.yml`'s parity check went two releases comparing
# a native binary against the jar over a target that could not move when ANY of the three bundled
# classifier indexes went missing: 610 functions / 1,397 analyzed and a byte-identical envelope with
# `candor/jdk-hof-invokes.idx.gz`, `candor/jdk-sams.idx.gz` or `candor/jdk-supertypes.idx.gz` stripped.
# Its non-vacuousness control passed throughout, because it proves the SCAN found something, not that a
# RESOURCE was consulted.
#
# WHAT THIS RUNS, AND WHY IT IS ENOUGH TO BE WORTH RUNNING. The parity verdict reads two JSON documents;
# the ~4-minute `nativeCompile` that produces one of them is upstream of the comparison, not part of it
# (corpus brief §M). So the whole verdict is exercised here by handing it a WHOLE jar's report as one leg
# and a STRIPPED jar's report as the other — the same asymmetry a native image built without an
# `-H:IncludeResources` line produces, reached without a native-image toolchain.
#
# WHAT IT CANNOT REACH, SAID PLAINLY. `Cha.JdkSupers` is consulted ONLY when `ClassReader` throws, which
# on the JVM it never does — so no jar-side experiment can move the `superWalkList`/`superWalkMap` rows,
# and this script asserts that no-op explicitly rather than letting a future reader mistake it for
# coverage. That arm's sensitivity was measured once (2026-09-06) in a throwaway worktree patched to
# force the ClassReader read to fail, and thereafter it is gated by two things this script does not run:
# `native.yml`'s real native leg, and `./gradlew verifyNativeImageResources`, which catches a dropped
# `-H:IncludeResources` line locally.
#
# EVERY WRITE GOES INTO ONE mktemp DIRECTORY THIS SCRIPT CREATED, and the trap removes only that. A test
# in this repo once cleaned up `cls.getParent().getParent()` and took the system temp directory with it.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$ROOT/build/classes/java/nativeParity"

# The jar is named from the PROJECT VERSION, never picked newest-by-mtime: a bump leaves the previous
# `-all.jar` in build/libs, and `ls -t` would hand this gate a stale analyzer the moment that older
# file's mtime got refreshed. Same rule as ci/self-gate.sh, for the same reason.
if [ -n "${CANDOR_JAVA_JAR:-}" ]; then JAR="$CANDOR_JAVA_JAR"; else
  GV="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$ROOT/build.gradle.kts" | head -1)"
  [ -n "$GV" ] || { echo "native-parity-selftest: cannot read the project version from build.gradle.kts"; exit 2; }
  JAR="$ROOT/build/libs/candor-java-$GV-all.jar"
fi
[ -f "$JAR" ] || { echo "native-parity-selftest: $JAR is not built (run \`./gradlew shadowJar\`)"; exit 2; }
[ -d "$FIXTURE" ] || { echo "native-parity-selftest: no fixture classes at $FIXTURE (run \`./gradlew nativeParityClasses\`)"; exit 2; }

WS="$(mktemp -d "${TMPDIR:-/tmp}/candor-native-parity-selftest.XXXXXX")"
trap 'rm -rf "$WS"' EXIT

fail() { echo "native-parity-selftest: FAIL — $*" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------------
# [1] §E3 — GROUND TRUTH EXECUTED, BEFORE ANY ROW BELOW IS BELIEVED.
#
# Every marker this gate keys on is an ABSENCE claim in disguise: the row disappears when its index is
# missing. An omitted pure method and an omitted effectful one are the same bytes, so the fixture has to
# be shown to really perform its effects first — otherwise a fixture that quietly stopped doing anything
# would keep reading as coverage. Five arms, one append each.
# ---------------------------------------------------------------------------------------------------
WITNESS="$WS/witness.txt"
java -Dcandor.nativeparity.witness="$WITNESS" \
     -cp "$FIXTURE" io.poly.candor.nativeparity.Drive || fail "the fixture's Drive.main did not run"
[ -f "$WITNESS" ] || fail "Drive.main ran but wrote no witness file — the fixture performs no effect"
N_WRITES=$(wc -c < "$WITNESS" | tr -d ' ')
[ "$N_WRITES" = "5" ] || fail "expected 5 witness appends (one per arm), got $N_WRITES — the fixture is \
not the program the marker rows describe"
echo "native-parity-selftest [1] executed: 5/5 fixture arms really performed their effect"

# ---------------------------------------------------------------------------------------------------
# [2] The baseline: the whole jar over the fixture.
# ---------------------------------------------------------------------------------------------------
java -jar "$JAR" "$FIXTURE" --json "$WS/full.json" >/dev/null 2>&1
[ -s "$WS/full.json" ] || fail "the whole jar produced no report over the fixture"

# GREEN CONTROL, and it runs FIRST: a checker that fails on everything would pass every red assertion
# below while asserting nothing.
python3 "$ROOT/ci/native-parity.py" --jar "$WS/full.json" --native "$WS/full.json" --profile fixture \
  || fail "the checker rejects a report compared against ITSELF — it fails on everything, so its \
failures below say nothing"
echo "native-parity-selftest [2] green control: identical legs pass"

# ---------------------------------------------------------------------------------------------------
# [3] THE FALSIFICATION. Strip each jar-testable resource in turn; the checker must go RED and must NAME
#     the resource. `native-parity.py` owns the list, so the two files cannot drift about which claim is
#     measurable on a jar.
# ---------------------------------------------------------------------------------------------------
RESOURCES=$(python3 -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('np', '$ROOT/ci/native-parity.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(' '.join(m.JAR_TESTABLE_RESOURCES))
")
[ -n "$RESOURCES" ] || fail "native-parity.py named no jar-testable resource — zero cases is not zero failures"

for RES in $RESOURCES; do
  BASE="$(basename "$RES" .idx.gz)"
  cp "$JAR" "$WS/no-$BASE.jar"
  ( cd "$WS" && zip -q -d "no-$BASE.jar" "$RES" ) || fail "could not strip $RES from a jar copy"
  # PROVE THE FIXTURE REACHED THE CODE: a strip that silently did nothing would make every assertion
  # below pass for the wrong reason.
  # `unzip -Z1` lists ENTRY NAMES only. `unzip -l` prints the archive's own path as its first line, so a
  # grep over it can match the jar's filename and report a resource still present that is not — measured,
  # on this script's first draft.
  if unzip -Z1 "$WS/no-$BASE.jar" | grep -qx "$RES"; then
    fail "$RES is still present in the stripped jar — the experiment did not happen"
  fi
  java -jar "$WS/no-$BASE.jar" "$FIXTURE" --json "$WS/no-$BASE.json" >/dev/null 2>&1
  [ -s "$WS/no-$BASE.json" ] || fail "the jar stripped of $RES produced no report"

  OUT="$WS/no-$BASE.verdict"
  python3 "$ROOT/ci/native-parity.py" --jar "$WS/full.json" --native "$WS/no-$BASE.json" \
      --profile fixture --native-label "jar-stripped-of-$BASE" >"$OUT" 2>&1
  RC=$?
  [ "$RC" -ne 0 ] || fail "the parity checker PASSED a report produced without $RES. That is exactly \
R249: the gate cannot see the resource go missing. Verdict was: $(cat "$OUT")"
  grep -q "$RES" "$OUT" || fail "the checker went red for $RES but its message never names the \
resource — a reader cannot act on it. Verdict was: $(cat "$OUT")"
  echo "native-parity-selftest [3] $RES: stripped -> checker RED, message names the resource"
done

# ---------------------------------------------------------------------------------------------------
# [4] THE NO-OP THIS SCRIPT REFUSES TO LET ANYONE MISREAD.
#
# `candor/jdk-supertypes.idx.gz` is consulted ONLY in a native image (`Cha.IN_NATIVE_IMAGE`), so
# stripping it from a jar changes nothing — and a reader who saw the loop above skip it might conclude
# the gate covers it. It does not, on this leg. Assert the no-op, so the day this index starts being
# read on the JVM this script is what says so.
# ---------------------------------------------------------------------------------------------------
cp "$JAR" "$WS/no-supers.jar"
( cd "$WS" && zip -q -d "no-supers.jar" "candor/jdk-supertypes.idx.gz" ) \
  || fail "could not strip candor/jdk-supertypes.idx.gz from a jar copy"
java -jar "$WS/no-supers.jar" "$FIXTURE" --json "$WS/no-supers.json" >/dev/null 2>&1
if ! cmp -s "$WS/full.json" "$WS/no-supers.json"; then
  echo "native-parity-selftest: NOTE — stripping candor/jdk-supertypes.idx.gz now CHANGES the jar leg's" >&2
  echo "  report. That index was documented as native-image-only (Cha.JdkSupers is gated behind" >&2
  echo "  IN_NATIVE_IMAGE); if the JVM now reads it, this script can and should gate it like the other" >&2
  echo "  two — move it out of the native-only case in ci/native-parity.py." >&2
  fail "the documented native-only invariant for candor/jdk-supertypes.idx.gz no longer holds"
fi
echo "native-parity-selftest [4] candor/jdk-supertypes.idx.gz: byte-identical on the jar leg, as \
documented — its teeth are native.yml's native leg plus \`./gradlew verifyNativeImageResources\`"

echo "native-parity-selftest: OK"
