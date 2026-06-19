#!/usr/bin/env python3
"""Smear probe for candor-java — the deferred/stored-lambda FABRICATION guard.

candor edges a created lambda to its CREATION site (so an effect passed to a consumer that RUNS it —
forEach/submit/stream — propagates). That rule misfires for a lambda that ESCAPES UNINVOKED: stored into
a field, a collection, a deferred container (`by lazy` / `ThreadLocal.withInitial`), or RETURNED by a
factory. Such a lambda does NOT run at its creation site; attributing its effect there — and, since any
static touch of a class triggers `<clinit>`, SMEARING it onto every method that touches the class — is a
fabrication (a false positive that would spuriously fail a `deny` gate on unrelated code). This was the
dominant class found by the Kotlin/field soundness sweep (fixed via `lambdaEscapesUninvoked`).

This probe pins that down in BOTH directions, across all the escape mechanisms:
  SMEAR    — a clean neighbour that merely TRIGGERS the class's <clinit> must stay PURE. If it inherits the
             stored lambda's effect => FABRICATION (the bug this probe exists to catch). The class's
             <clinit> itself must also not carry the effect (it stores the lambda, it never runs it).
  DISCLOSE — the lambda's eventual INVOCATION site (field-/collection-/return-value SAM, or the deferred
             force) must still report the effect OR `Unknown`. A silent-pure there is an UNDER-report —
             the other failure direction. (`Unknown` is a PASS: an unpinned SAM is honestly unresolvable.)

It compiles each fixture, scans it with the installed candor-java launcher, and exits non-zero on ANY
smear or ANY under-report — so it gates CI.

Usage:  smear_probe.py                       # build (if needed), run, gate
        CJ=/path/to/candor-java smear_probe.py   # use a prebuilt launcher (skip the gradle build)
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

EFFECTS = {
    "Net": 'try { new java.net.Socket("h", 80); } catch (Exception __e) {}',
    "Fs":  'try { new java.io.FileOutputStream("f").write(1); } catch (Exception __e) {}',
}

# Each escape mechanism: given an index i and the planted-effect snippet, returns
#   (member_decls, invoker_method_name, invoker_decl)
# member_decls stores an EFFECTFUL lambda WITHOUT running it (in <clinit>/<init>); invoker runs it later.
def mechanisms(i, eff):
    return [
        # 1. plain static field holding a lambda (created in <clinit>)
        ("static_field",
         [f"static Runnable R{i} = () -> {{ {eff} }};"],
         f"inv{i}", f"static void inv{i}() {{ R{i}.run(); }}"),
        # 2. deferred container — ThreadLocal.withInitial (runs at .get(), not at creation)
        ("threadlocal",
         [f"static ThreadLocal<String> TL{i} = ThreadLocal.withInitial(() -> {{ {eff} return \"x\"; }});"],
         f"inv{i}", f"static void inv{i}() {{ TL{i}.get(); }}"),
        # 3. collection store — Map.put (stores, never invokes)
        ("map_store",
         [f"static java.util.Map<String,Runnable> M{i} = new java.util.HashMap<>();",
          f"static {{ M{i}.put(\"k\", () -> {{ {eff} }}); }}"],
         f"inv{i}", f"static void inv{i}() {{ M{i}.get(\"k\").run(); }}"),
        # 4. collection store — List.add
        ("list_add",
         [f"static java.util.List<Runnable> L{i} = new java.util.ArrayList<>();",
          f"static {{ L{i}.add(() -> {{ {eff} }}); }}"],
         f"inv{i}", f"static void inv{i}() {{ L{i}.get(0).run(); }}"),
        # 5. factory that RETURNS a lambda, called from <clinit>
        ("factory_return",
         [f"static Runnable F{i} = mk{i}();",
          f"static Runnable mk{i}() {{ return () -> {{ {eff} }}; }}"],
         f"inv{i}", f"static void inv{i}() {{ F{i}.run(); }}"),
        # 6. instance field holding a lambda (created in <init>)
        ("instance_field",
         [f"Runnable IR{i} = () -> {{ {eff} }};"],
         f"inv{i}", f"void inv{i}() {{ IR{i}.run(); }}"),
    ]

def build_fixture(eff_snippet):
    """One class: every escape mechanism storing an effectful lambda, a clean neighbour, the invokers.
    Group i uses mechanism i (names carry index i, so all six are distinct in one class)."""
    members, invokers, names = [], [], []
    for i in range(6):
        _kind, decls, invname, invdecl = mechanisms(i, eff_snippet)[i]
        members += decls
        invokers.append(invdecl)
        names.append(invname)
    body = "\n  ".join(
        ["static int PURE_CONST = 7;",
         "static void touch() { int __x = PURE_CONST; }",
         "static void cleanNeighbor() { touch(); }"]            # triggers <clinit>; MUST stay pure
        + members + invokers)
    return "public class Gen {\n  " + body + "\n}\n", names

def scan(cj, src, work):
    d = os.path.join(work, "f"); os.makedirs(os.path.join(d, "cls"), exist_ok=True)
    open(os.path.join(d, "Gen.java"), "w").write(src)
    r = subprocess.run(["javac", "-d", os.path.join(d, "cls"), os.path.join(d, "Gen.java")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, "GENERATOR BUG — does not compile: " + r.stderr.strip()[:300]
    subprocess.run([cj, os.path.join(d, "cls"), "--json", os.path.join(d, "r.json")],
                   capture_output=True, text=True)
    p = os.path.join(d, "r.json")
    if not os.path.exists(p):
        return None, "NO REPORT"
    rep = json.load(open(p))
    return {f["fn"]: set(f.get("inferred", [])) for f in rep["functions"]}, None

def main():
    cj = os.environ.get("CJ")
    if not cj:
        gradle = os.path.join(ROOT, "gradlew")
        gradle = gradle if os.path.exists(gradle) else "gradle"
        subprocess.run([gradle, "-q", "installDist"], cwd=ROOT, capture_output=True)
        cj = os.path.join(ROOT, "build", "install", "candor-java", "bin", "candor-java")
    if not os.path.exists(cj):
        print("smear-probe: FAIL — no launcher at", cj); sys.exit(1)

    failures = []
    checked = 0
    with tempfile.TemporaryDirectory() as work:
        for effname, eff in EFFECTS.items():
            src, invokers = build_fixture(eff)
            got, err = scan(cj, src, os.path.join(work, effname))
            if err:
                failures.append(f"[{effname}] {err}"); continue
            # SMEAR guard: the clean neighbour and <clinit> must NOT carry the planted effect.
            for fn in ("Gen.cleanNeighbor", "Gen.<clinit>"):
                checked += 1
                if effname in got.get(fn, set()):
                    failures.append(f"[{effname}] SMEAR: {fn} fabricated {effname} (stored lambda leaked via <clinit>)")
            # DISCLOSE guard: each invocation site must report the effect OR Unknown (never silent-pure).
            for inv in invokers:
                checked += 1
                g = got.get("Gen." + inv, set())
                if not (effname in g or "Unknown" in g):
                    failures.append(f"[{effname}] UNDER-REPORT: Gen.{inv} is silent-pure (want {effname} or Unknown)")

    if failures:
        print(f"smear-probe: {len(failures)} FAILURE(S) of {checked} checks:")
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print(f"smear-probe: OK — {checked} checks across {len(EFFECTS)} effects "
          "× 6 escape mechanisms (static-field/ThreadLocal/Map/List/factory-return/instance-field): "
          "no <clinit> smear, every invocation discloses")

if __name__ == "__main__":
    main()
