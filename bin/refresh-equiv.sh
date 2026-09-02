#!/usr/bin/env bash
# THE REPORT-REFRESH ACCEPTANCE ORACLE.
#
# The refresh's entire safety case is one sentence: a refreshed report must be BYTE-IDENTICAL to the
# full scan it replaces. A cache that is merely "close" is a silent under-report wearing a normal
# report's shape — this project's cardinal sin — so equality is checked on BYTES, across the report
# AND every sidecar the scan writes, never on a summary or a violation count. The sidecars matter
# on their own account: the callgraph and hierarchy documents are exactly what a per-class cache
# reconstructs, and a stale one is invisible in the main document.
#
# Two arms, and BOTH are load-bearing:
#
#   EQUIVALENCE  cold scan vs refreshed scan of the same tree   → must be IDENTICAL
#   CONTROL      perturb one class, refresh again              → must DIFFER, and must equal a
#                cold scan of the perturbed tree
#
# The control is not decoration. The equivalence arm alone is passed perfectly by a "refresh" that
# ignores its input and replays the previous report — the strongest imaginable cache and a totally
# blind one. The control is what gives the equality its meaning, and it is checked against a cold
# scan of the SAME perturbed tree so that "it changed" cannot be satisfied by changing WRONGLY.
#
# A perturbation that moves no report is reported INCONCLUSIVE and does not count as coverage. A
# control that cannot fail must never be reported as a control that passed.
#
# Usage: refresh-equiv.sh <jar> <target>...        (targets: class dirs or .jar files)
set -uo pipefail

JAR="${1:?usage: refresh-equiv.sh <candor-jar> <target>...}"; shift
[ $# -gt 0 ] || { echo "refresh-equiv: no targets given" >&2; exit 2; }
[ -f "$JAR" ] || { echo "refresh-equiv: no such jar: $JAR" >&2; exit 2; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0; checked=0; controls=0

# Concatenate the report and every sidecar written at a prefix, in a stable order, with the file
# name in the stream — so a diff names the document that moved rather than just a byte offset.
snap() {  # snap <dir>
  ( cd "$1" && find . -type f -name '*.json' | LC_ALL=C sort | while read -r f; do
      printf '=== %s\n' "$f"; cat "$f"; printf '\n'
    done )
}

# One scan. The cache is addressed by CANDOR_REFRESH: unset/0 = disabled (the cold reference path),
# a directory = use it as the per-class cache. CANDOR_DEPS is passed through so the dependency axis
# below can vary it; it is empty for every other arm, which is what the engine sees when unset.
scan() {  # scan <cache-spec> <target> <out-prefix> <log> [deps]
  local cache="$1" target="$2" prefix="$3" log="$4" deps="${5:-}"
  mkdir -p "$(dirname "$prefix")"
  CANDOR_REFRESH="$cache" CANDOR_DEPS="$deps" java -jar "$JAR" "$target" --json "$prefix.json" >"$log" 2>&1
  return $?
}

# The reuse count the engine disclosed on stderr, or empty when it disclosed none.
reuse_of() {  # reuse_of <log>
  sed -n 's/^candor-java: refresh — reused \([0-9]*\) of \([0-9]*\) .*/\1/p' "$1" | tail -1
}

for target in "$@"; do
  name="$(basename "$target" .jar)"
  d="$WORK/$name"; mkdir -p "$d"
  printf '── %-22s' "$name"

  # A private copy of the tree, so the perturbation arm never touches the caller's files. A jar is
  # expanded, because the control needs to rewrite ONE class and a jar entry cannot be perturbed in
  # place without rewriting the archive (which would change every class's bytes and prove nothing).
  tree="$d/tree"; mkdir -p "$tree"
  if [ -d "$target" ]; then cp -R "$target/." "$tree/"
  else ( cd "$tree" && unzip -qq -o "$target" ) || { echo "FAIL — cannot expand $target"; fail=1; continue; }
  fi

  scan 0 "$tree" "$d/cold/report" "$d/cold.log";  ccold=$?
  scan "$d/cache" "$tree" "$d/prime/report" "$d/prime.log" >/dev/null 2>&1
  scan "$d/cache" "$tree" "$d/warm/report"  "$d/warm.log";  cwarm=$?
  checked=$((checked+1))

  if [ "$ccold" != "$cwarm" ]; then
    echo "FAIL — exit differs: cold=$ccold warm=$cwarm"; fail=1; continue
  fi
  snap "$d/cold" >"$d/a"; snap "$d/warm" >"$d/b"
  if ! diff -u "$d/a" "$d/b" >"$d/diff" 2>&1; then
    echo "FAIL — refreshed report differs from the cold scan"
    sed 's/^/     /' "$d/diff" | head -40
    fail=1; continue
  fi

  # THE WARM RUN MUST PROVE IT TOOK THE REFRESH PATH. Without this the whole harness is vacuous:
  # against a build that ignores CANDOR_REFRESH entirely, every arm above is a cold scan compared
  # with a cold scan, and it reports OK while measuring nothing. So the engine discloses its reuse
  # on stderr and the harness REQUIRES a non-zero one — the oracle has to be able to fail before a
  # pass from it is worth anything.
  read -r rn rtot < <(sed -n 's/^candor-java: refresh — reused \([0-9]*\) of \([0-9]*\) .*/\1 \2/p' "$d/warm.log" | tail -1)
  if [ -z "${rn:-}" ]; then
    echo "FAIL — the warm run disclosed no refresh reuse (the cache never engaged; the comparison above is vacuous)"
    fail=1; continue
  fi
  if [ "$rn" = 0 ]; then
    echo "FAIL — the warm run reused 0 of $rtot classes (nothing was cached; the comparison above is vacuous)"
    fail=1; continue
  fi

  # THE CONTROL. REMOVE a class from the tree, then refresh against the cache primed on the tree
  # that still had it. The refresh must land exactly where a cold scan of the reduced tree lands.
  #
  # Deletion rather than a byte-append, and the reason is a measurement: ASM's ClassReader parses a
  # classfile by internal offsets, so trailing garbage is simply never read. Appending a byte moves
  # the file's hash — so a content-addressed cache dutifully re-analyses the class — and produces a
  # byte-identical analysis, leaving the report unmoved and the control permanently INCONCLUSIVE. It
  # would have looked like a control for as long as nobody checked which half of it was working.
  #
  # A deletion is the strongest cheap perturbation because it must move BOTH halves: the class's own
  # functions leave the report, and every caller's transitive closure has to be recomputed without
  # them. The narrower case — a method body edited while the signature set is unchanged, where the
  # refresh must re-analyse exactly one class and reuse the rest — needs a recompile, so it lives in
  # the JUnit fixture test where javac is on hand.
  victim="$(find "$tree" -name '*.class' | LC_ALL=C sort | head -1)"
  if [ -z "$victim" ]; then echo "equivalence OK · control SKIP (no .class to perturb)"; continue; fi
  rm -f "$victim"
  scan 0 "$tree" "$d/pcold/report" "$d/pcold.log"
  scan "$d/cache" "$tree" "$d/pwarm/report" "$d/pwarm.log"
  snap "$d/pcold" >"$d/pa"; snap "$d/pwarm" >"$d/pb"

  if diff -q "$d/a" "$d/pa" >/dev/null 2>&1; then
    echo "equivalence OK · control INCONCLUSIVE (perturbation moved no report — not counted)"
    continue
  fi
  if diff -u "$d/pa" "$d/pb" >"$d/pdiff" 2>&1; then
    controls=$((controls+1))
    echo "equivalence OK · control OK"
  else
    echo "equivalence OK · FAIL control — after perturbation the refresh left the cold scan"
    sed 's/^/     /' "$d/pdiff" | head -40
    fail=1
  fi
done

# ── THE CANDOR_DEPS AXIS (SOUNDNESS R151) ────────────────────────────────────────────────────────
#
# WHY IT IS HERE. Every arm above varies the SCANNED TREE. `CANDOR_DEPS` is the scan's other content
# input — a chained dependency's effects and literal surfaces are folded into the consuming class's
# accumulators by Candor#inheritDepFn, and those accumulators are exactly what this cache stores. The
# harness described itself as "the refresh's entire safety case" and never once perturbed that input,
# so it was blind on the axis that failed: measured on 0.34.0, a warm cache primed under a dep
# reporting ['Db'] and rerun under the SAME dep reporting ['Db','Net'] replayed the consumer without
# Net — `deny Net` exit 1 to exit 0, "reused 1 of 1", same bytecode, same policy, same jar. The digest
# folded in the chained-dep KEY SET and none of the VALUES. A safety case that cannot vary an input is
# not a safety case for that input.
#
# It builds its OWN two-package fixture rather than perturbing the caller's targets, because the
# perturbation has to travel through a real cross-jar JOIN: an arbitrary target does not call into an
# arbitrary dependency report, and an arm whose perturbation cannot reach the consumer is the vacuous
# pass this file already refuses elsewhere. The fixture is COMPILED and its two dep reports are
# GENERATED by this same jar — no hand-written JSON — so the arm exercises the report writer and the
# report reader on the shape they actually produce.
#
# Four runs, and each one is load-bearing:
#   coldA / coldB   cold scans of the consumer under dep v1 and v2 — must DIFFER, or the
#                   perturbation never reached the consumer and everything below is vacuous
#   sameA           second warm run under the UNCHANGED dep — must reuse > 0, or the cache never
#                   engaged on this fixture and the arm proves nothing about the cache
#   warmB           warm run under the CHANGED dep — must equal coldB on bytes
javac_bin="$(command -v javac || true)"
if [ -z "$javac_bin" ]; then
  # A loud skip that reaches the exit code. A silent one would leave the axis unmeasured while the
  # script still printed OK, which is the aggregation failure this family keeps finding.
  echo "refresh-equiv: CANNOT ARM the CANDOR_DEPS axis — no javac on PATH (the fixture must compile)"
  fail=1
else
  D="$WORK/depaxis"; mkdir -p "$D/a/lib" "$D/b/lib" "$D/app/app"
  cat > "$D/a/lib/Repo.java" <<'JAVA'
package lib;
import java.nio.file.*;
public class Repo { public void go() throws Exception { Files.readAllBytes(Path.of("/tmp/alpha")); } }
JAVA
  cat > "$D/b/lib/Repo.java" <<'JAVA'
package lib;
import java.nio.file.*; import java.net.*;
public class Repo { public void go() throws Exception {
  Files.readAllBytes(Path.of("/tmp/beta"));
  new URL("http://dep.example.com/x").openConnection().getInputStream().close();
} }
JAVA
  cat > "$D/app/app/Main.java" <<'JAVA'
package app;
public class Main { public static void main(String[] a) throws Exception { new lib.Repo().go(); } }
JAVA
  depfail=0
  javac -nowarn -d "$D/ca" "$D/a/lib/Repo.java" >"$D/javac.log" 2>&1 || depfail=1
  javac -nowarn -d "$D/cb" "$D/b/lib/Repo.java" >>"$D/javac.log" 2>&1 || depfail=1
  javac -nowarn -cp "$D/ca" -d "$D/capp" "$D/app/app/Main.java" >>"$D/javac.log" 2>&1 || depfail=1
  if [ "$depfail" != 0 ]; then
    echo "refresh-equiv: CANNOT ARM the CANDOR_DEPS axis — the fixture did not compile:"
    sed 's/^/     /' "$D/javac.log" | head -20
    fail=1
  else
    # The dependency's own reports, written by the jar under test.
    scan 0 "$D/ca" "$D/depa/report" "$D/depa.log"
    scan 0 "$D/cb" "$D/depb/report" "$D/depb.log"

    scan 0        "$D/capp" "$D/coldA/report" "$D/coldA.log" "$D/depa/report.json"
    scan 0        "$D/capp" "$D/coldB/report" "$D/coldB.log" "$D/depb/report.json"
    scan "$D/dc"  "$D/capp" "$D/prime/report" "$D/prime.log" "$D/depa/report.json"
    scan "$D/dc"  "$D/capp" "$D/sameA/report" "$D/sameA.log" "$D/depa/report.json"
    scan "$D/dc"  "$D/capp" "$D/warmB/report" "$D/warmB.log" "$D/depb/report.json"

    snap "$D/coldA" >"$D/xa"; snap "$D/coldB" >"$D/xb"; snap "$D/warmB" >"$D/xw"
    dn="$(reuse_of "$D/sameA.log")"
    printf -- '── %-22s' "CANDOR_DEPS axis"
    if diff -q "$D/xa" "$D/xb" >/dev/null 2>&1; then
      echo "CANNOT ARM — the dep perturbation moved no report (the join never happened)"
      fail=1
    elif [ -z "$dn" ] || [ "$dn" = 0 ]; then
      echo "CANNOT ARM — the unchanged-dep rerun reused ${dn:-no} class(es); the cache never engaged"
      fail=1
    elif diff -u "$D/xb" "$D/xw" >"$D/xdiff" 2>&1; then
      controls=$((controls+1))
      echo "dep-value axis OK (cache engaged: reused $dn on the unchanged rerun)"
    else
      echo "FAIL — a CHANGED dependency report was replayed from cache"
      echo "     the dep function kept its key and changed its value; the refreshed consumer is not"
      echo "     the cold consumer. This is SOUNDNESS R151 and it is a silent under-report."
      sed 's/^/     /' "$D/xdiff" | head -40
      fail=1
    fi
  fi
fi

# ── THE FIELD-LAMBDA BINDING AXIS (SOUNDNESS R163) ───────────────────────────────────────────────
#
# WHY IT IS HERE, AND WHY THE ARMS ABOVE CANNOT SEE IT. Every arm above perturbs a class by DELETING
# it — which moves that class's structural digest, and the whole-program digest with it. ⟨0.35⟩ added
# a whole-program pre-pass index (`fieldLambdaBindings`) built from every method's INSTRUCTIONS and
# read during another class's analyze, so a class's BODY can change what a DIFFERENT class analyses
# to while its STRUCTURE — and therefore the digest — holds perfectly still. Measured on the pre-fix
# HEAD: `Widget.bindSecondary()` goes from a no-op to `this.task = Effector::act` (a bound METHOD
# REFERENCE, so javac emits no new synthetic member and `javap -p Widget` is identical either way),
# and the warm rerun replays `Caller.go` as PURE — byte-identical to the cold v1 report, "reused 3 of
# 4", `pure Caller.go` exit 1 -> 0, over a program that really does write the file.
#
# Same construction as the CANDOR_DEPS axis: its own compiled fixture, because the perturbation has to
# travel through a real field dispatch and an arbitrary target does not contain one; and the same
# refusal to report a pass it could not have failed — the perturbation must move a COLD report and the
# cache must be shown to engage, or the axis reports CANNOT ARM and that reaches the exit code.
if [ -z "$javac_bin" ]; then
  echo "refresh-equiv: CANNOT ARM the field-binding axis — no javac on PATH (the fixture must compile)"
  fail=1
else
  F="$WORK/fieldaxis"; mkdir -p "$F/src" "$F/v1" "$F/v2"
  cat > "$F/src/Caller.java" <<'JAVA'
public class Caller { public void go(Widget w) { if (w.task != null) w.task.run(); } }
JAVA
  cat > "$F/src/Effector.java" <<'JAVA'
import java.nio.file.*;
public class Effector {
  public static void act() {
    try { Files.write(Path.of("/tmp/candor-r163-witness"), "L2 ran\n".getBytes(),
            StandardOpenOption.CREATE, StandardOpenOption.APPEND); }
    catch (Exception e) { throw new RuntimeException(e); }
  }
}
JAVA
  cat > "$F/src/Main.java" <<'JAVA'
public class Main {
  public static void main(String[] a) {
    Widget w = new Widget(); w.bindPrimary(); w.bindSecondary(); new Caller().go(w);
  }
}
JAVA
  # Same field, same two methods, same descriptors — only bindSecondary's BODY differs.
  cat > "$F/v1/Widget.java" <<'JAVA'
public class Widget {
  public Runnable task;
  public void bindPrimary() { this.task = () -> { int z = 1 + 1; }; }
  public void bindSecondary() { int noop = 0; }
}
JAVA
  cat > "$F/v2/Widget.java" <<'JAVA'
public class Widget {
  public Runnable task;
  public void bindPrimary() { this.task = () -> { int z = 1 + 1; }; }
  public void bindSecondary() { this.task = Effector::act; }
}
JAVA
  ffail=0
  javac -nowarn -d "$F/ca" "$F/src"/*.java "$F/v1/Widget.java" >"$F/javac.log" 2>&1 || ffail=1
  javac -nowarn -d "$F/cb" "$F/src"/*.java "$F/v2/Widget.java" >>"$F/javac.log" 2>&1 || ffail=1
  if [ "$ffail" != 0 ]; then
    echo "refresh-equiv: CANNOT ARM the field-binding axis — the fixture did not compile:"
    sed 's/^/     /' "$F/javac.log" | head -20
    fail=1
  else
    # ONE VARIABLE. Only Widget may differ between the arms; if anything else moved, a difference in
    # the reports below would not be attributable to the binding set at all.
    onevar=1
    for c in Caller.class Effector.class Main.class; do
      cmp -s "$F/ca/$c" "$F/cb/$c" || onevar=0
    done
    cmp -s "$F/ca/Widget.class" "$F/cb/Widget.class" && onevar=0
    wt="$F/tree"; mkdir -p "$wt"
    cp "$F/ca"/*.class "$wt/"
    scan 0       "$wt" "$F/coldA/report" "$F/coldA.log"
    scan "$F/fc" "$wt" "$F/prime/report" "$F/prime.log"
    scan "$F/fc" "$wt" "$F/sameA/report" "$F/sameA.log"
    cp "$F/cb/Widget.class" "$wt/Widget.class"          # the BODY changes; the structure does not
    scan 0       "$wt" "$F/coldB/report" "$F/coldB.log"
    scan "$F/fc" "$wt" "$F/warmB/report" "$F/warmB.log"

    snap "$F/coldA" >"$F/fa"; snap "$F/coldB" >"$F/fb"; snap "$F/warmB" >"$F/fw"
    fn="$(reuse_of "$F/sameA.log")"
    printf -- '── %-22s' "field-binding axis"
    if [ "$onevar" != 1 ]; then
      echo "CANNOT ARM — the two arms differ in more than Widget's body (or not at all)"
      fail=1
    elif diff -q "$F/fa" "$F/fb" >/dev/null 2>&1; then
      echo "CANNOT ARM — the body change moved no cold report (the field binding never reached the dispatch)"
      fail=1
    elif [ -z "$fn" ] || [ "$fn" = 0 ]; then
      echo "CANNOT ARM — the unchanged rerun reused ${fn:-no} class(es); the cache never engaged"
      fail=1
    elif diff -u "$F/fb" "$F/fw" >"$F/fdiff" 2>&1; then
      controls=$((controls+1))
      echo "field-binding axis OK (cache engaged: reused $fn on the unchanged rerun)"
    else
      echo "FAIL — a class whose BODY changed the field-lambda binding set was replayed from cache"
      echo "     Widget's structure held still, so the whole-program digest did not move and Caller's"
      echo "     delta was replayed under the old binding set. This is SOUNDNESS R163 and it is a"
      echo "     silent under-report: Caller.go comes back PURE over a program that writes a file."
      sed 's/^/     /' "$F/fdiff" | head -40
      fail=1
    fi
  fi
fi

echo
if [ "$fail" != 0 ]; then
  echo "refresh-equiv: FAILED — see the diffs above"
  exit 1
fi
if [ "$controls" = 0 ]; then
  # Every equivalence arm passing with no armed control is the exact shape a blind replay produces.
  echo "refresh-equiv: INCONCLUSIVE — $checked target(s) equivalent, but NO control was armed."
  echo "  A refresh that replays the previous report unconditionally passes every arm above."
  exit 2
fi
echo "refresh-equiv: OK — $checked target(s), refreshed == cold on bytes; $controls control(s) armed and tracking"
exit 0
