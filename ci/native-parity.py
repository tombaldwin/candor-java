#!/usr/bin/env python3
"""SOUNDNESS R249 — the native/jar parity verdict, as a file you can attack without GraalVM.

WHY THIS IS A FILE AND NOT A HEREDOC IN native.yml. Its verdict reads two JSON documents and nothing
else; the ~4-minute `nativeCompile` that produces one of them is UPSTREAM of the comparison, so the
comparison's cost is not the build's cost (corpus brief §M). Inline in the workflow it could only ever
be exercised by a full CI run on a machine with a GraalVM toolchain — which is why the gate it replaces
went two releases without anyone watching it fail. `ci/native-parity-selftest.sh` now feeds it a whole
jar's report against a stripped jar's report and requires RED, on any machine, in seconds.

WHAT WAS WRONG WITH THE GATE THIS REPLACES. It compared the WHOLE ENVELOPE — right — and carried a
non-vacuousness control requiring the jar leg to find >=100 functions / >=500 analyzed — also right, and
it is kept below. But that control proves the SCAN found something, not that any bundled RESOURCE was
consulted. Measured over its target (`build/classes/java/main`), stripping `candor/jdk-hof-invokes.idx.gz`,
`candor/jdk-sams.idx.gz` or `candor/jdk-supertypes.idx.gz` left 610 functions / 1,397 analyzed and a
byte-identical envelope in every case. Three `-H:IncludeResources` lines, and deleting any of them was
invisible to the one gate that exists to compare the two artifacts.

THE `fixture` PROFILE IS THE ANSWER: a target (`src/nativeParity`) built so each index changes a NAMED
ROW, plus MARKER assertions checked on BOTH LEGS. The markers are not decoration — they are what makes
the equality mean something:

  * on the JAR leg they prove the resource is in the jar AND was really consulted (a generator that
    stopped, a loader reading the wrong key, a truncated gzip all fail here, not silently);
  * on the NATIVE leg they prove the same of the binary, and they name the missing resource in the
    failure message rather than leaving a reader to infer it from a diff of absent rows.

Absence is the signature of the sin these markers watch for: every one of them DISAPPEARS from
`functions[]` when its index is missing — the row does not go wrong, it stops existing.
"""

from __future__ import annotations

import argparse
import json
import sys

PKG = "io.poly.candor.nativeparity"

# (resource, fn, effect that must be inferred, unknownWhy reason that must be present or None)
#
# EVERY ROW HERE IS MEASURED, 2026-09-06, by stripping the named resource from the shipped fat jar and
# re-scanning `build/classes/java/nativeParity` — see `ci/native-parity-selftest.sh`, which re-runs that
# measurement rather than trusting this comment. The one exception is stated where it applies.
MARKERS = [
    # SOUNDNESS R237. `Optional.orElseGet` and `Objects.requireNonNullElseGet` are not in
    # `Candor.isInvokingHof`'s hand-written name list; only the swept index reaches them. Both rows
    # vanish from `functions[]` with the resource stripped.
    ("candor/jdk-hof-invokes.idx.gz", f"{PKG}.HofArm.hofOrElseGet",
     "Unknown", "callback:java.util.function.Supplier.get"),
    ("candor/jdk-hof-invokes.idx.gz", f"{PKG}.HofArm.hofRequireNonNullElseGet",
     "Unknown", "callback:java.util.function.Supplier.get"),
    # SOUNDNESS R191, and the interface had to be `java.lang.Iterable`. `IntSupplier::getAsInt` — the
    # obvious spelling — is NOT index-sensitive, because `isJdkFunctionalSam` short-circuits every
    # `java/util/function/` owner through the hand-written `FUNCTION_PKG_SAM` set; `Comparator` is one of
    # the eighteen entries in `SAM_OF`, which `samNameOf` consults first. `Iterable` is in neither, so
    # the index is its only answer, and this row vanishes without it.
    ("candor/jdk-sams.idx.gz", f"{PKG}.SamArm.samViaIterable",
     "Unknown", "callback:java.lang.Iterable.iterator"),
    # THE ONE THAT ONLY THE NATIVE LEG CAN GATE, AND SAYING SO IS THE POINT. `Cha.JdkSupers` is read
    # ONLY when `ClassReader` throws, which on the JVM it never does — the class is not even loaded from
    # the jar, so no jar-side experiment can move these rows. Their sensitivity was measured once, on
    # 2026-09-06, in a throwaway worktree whose `Cha.externalSupersSplit` was patched to force the
    # ClassReader read to fail for every external name (the native image's real condition): WITH the
    # index bundled the report was byte-identical to the jar's; WITHOUT it, `superWalkList` and
    # `superWalkMap` both left `functions[]` and nothing else moved. That patch is not in this repo and
    # is not reproducible by the selftest, so on the jar leg these two rows assert only that the ARM IS
    # LIVE — necessary for the native leg to be able to differ, not sufficient. The teeth are the native
    # leg's own marker check plus `./gradlew verifyNativeImageResources`, which catches a dropped
    # `-H:IncludeResources` line with no GraalVM at all.
    ("candor/jdk-supertypes.idx.gz", f"{PKG}.SuperArm.superWalkList", "Fs", None),
    ("candor/jdk-supertypes.idx.gz", f"{PKG}.SuperArm.superWalkMap", "Fs", None),
]

# The resources whose absence a JAR-side experiment really can demonstrate — everything except the
# native-image-only supertype index. `ci/native-parity-selftest.sh` reads this so the two files cannot
# drift about which claim is measurable where.
JAR_TESTABLE_RESOURCES = sorted({r for r, _, _, _ in MARKERS if r != "candor/jdk-supertypes.idx.gz"})


def rows(report: dict) -> dict:
    return {f["fn"]: f for f in report.get("functions", [])}


def check_markers(report: dict, leg: str, jar_leg: bool) -> list[str]:
    """Every marker row must be present, carrying its effect and its reason. Returns failure lines."""
    by_fn = rows(report)
    out = []
    for resource, fn, effect, why in MARKERS:
        f = by_fn.get(fn)
        native_only = resource == "candor/jdk-supertypes.idx.gz"
        if f is None:
            out.append(
                f"  [{leg}] {fn} is ABSENT from functions[].\n"
                f"      That row exists ONLY when {resource} is bundled and consulted"
                + ("" if not (jar_leg and native_only) else
                   " (on the jar leg this index is never read — an absence here means the fixture arm\n"
                   "      itself stopped working, not that the resource is missing)")
                + f".\n      Fix: check the `-H:IncludeResources={resource}` line in build.gradle.kts, and that\n"
                f"      the resource is still generated (`./gradlew verifyNativeImageResources`).",
            )
            continue
        inferred = f.get("inferred") or []
        if effect not in inferred:
            out.append(
                f"  [{leg}] {fn} is present but inferred={inferred}, expected to contain '{effect}'.",
            )
        if why is not None and why not in (f.get("unknownWhy") or []):
            out.append(
                f"  [{leg}] {fn} does not carry the reason '{why}' (got {f.get('unknownWhy')}).\n"
                f"      The reason is what identifies {resource} as the answer's source rather than some\n"
                f"      other route to the same effect label.",
            )
    return out


def check_not_vacuous(jar: dict, min_fns: int, min_analyzed: int) -> list[str]:
    """THE CONTROL, AND IT IS NOT OPTIONAL. This gate is an EQUALITY, and two empty documents are equal —
    so a defect that zeroes BOTH legs passes it while measuring nothing."""
    n = len(jar.get("functions", []))
    count = jar.get("analyzed", {}).get("count", 0)
    if n < min_fns or count < min_analyzed:
        return [
            f"  PARITY VACUOUS: the jar leg found {n} function(s) / {count} analyzed, below the "
            f"{min_fns}/{min_analyzed} floor — this gate would be comparing two nearly empty reports. "
            f"Fix the scan, not the gate.",
        ]
    return []


def check_envelope(jar: dict, nat: dict) -> list[str]:
    """THE WHOLE ENVELOPE, not just `functions`. ⟨0.32⟩ shipped a native image whose per-class delta
    merge folded nothing: `functions` went to 0, AND `analyzed.count` 1329 -> 0, AND `coverage` vanished.
    `functions` caught that one — but a divergence confined to `analyzed`, `excluded`, `outOfScope` or
    `netPartners` would have passed a functions-only gate, and a consumer's verdict reads every one."""
    bad = [k for k in sorted(set(jar) | set(nat))
           if jar.get(k, "<ABSENT>") != nat.get(k, "<ABSENT>")]
    if not bad:
        return []
    out = [f"  PARITY FAILED: native report differs from jar on {bad}"]
    for k in bad:
        a, b = jar.get(k, "<ABSENT>"), nat.get(k, "<ABSENT>")
        if k == "functions" and isinstance(a, list) and isinstance(b, list):
            an, bn = rows(jar), rows(nat)
            out.append(f"    functions: jar {len(an)} vs native {len(bn)}")
            for fn in sorted(set(an) ^ set(bn))[:10]:
                out.append(f"      only in {'jar' if fn in an else 'native'}: {fn}")
            for fn in sorted(set(an) & set(bn)):
                if an[fn] != bn[fn]:
                    out.append(f"      differs: {fn}\n        jar   : {an[fn]}\n        native: {bn[fn]}")
                    break
        else:
            out.append(f"    {k}:\n      jar   : {json.dumps(a)[:300]}\n      native: {json.dumps(b)[:300]}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jar", required=True, help="report JSON from the jar leg")
    ap.add_argument("--native", required=True, help="report JSON from the native leg")
    ap.add_argument("--profile", required=True, choices=("main", "fixture"),
                    help="`main`: scale non-vacuousness over candor's own classes. "
                         "`fixture`: the R249 marker control over src/nativeParity.")
    ap.add_argument("--min-functions", type=int, default=100)
    ap.add_argument("--min-analyzed", type=int, default=500)
    ap.add_argument("--jar-label", default="jar", help="what to call the first leg in messages")
    ap.add_argument("--native-label", default="native", help="what to call the second leg in messages")
    a = ap.parse_args()

    with open(a.jar) as fh:
        jar = json.load(fh)
    with open(a.native) as fh:
        nat = json.load(fh)

    problems: list[str] = []
    if a.profile == "main":
        problems += check_not_vacuous(jar, a.min_functions, a.min_analyzed)
    else:
        # The fixture is small by design, so the scale floor would be meaningless here; the marker rows
        # ARE its non-vacuousness control, and they are strictly stronger — they name which resource was
        # consulted rather than counting rows.
        problems += check_markers(jar, a.jar_label, jar_leg=True)
        problems += check_markers(nat, a.native_label, jar_leg=False)
    problems += check_envelope(jar, nat)

    if problems:
        print(f"native-parity [{a.profile}]: FAILED", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        return 1

    if a.profile == "main":
        n = len(jar.get("functions", []))
        count = jar.get("analyzed", {}).get("count", 0)
        print(f"native-parity [main]: OK — native report == jar, whole envelope "
              f"({n} functions, {count} analyzed)")
    else:
        resources = sorted({r for r, _, _, _ in MARKERS})
        print(f"native-parity [fixture]: OK — native report == jar, whole envelope, and all "
              f"{len(MARKERS)} marker row(s) are present on BOTH legs, covering {len(resources)} "
              f"bundled resource(s): {', '.join(resources)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
