#!/usr/bin/env python3
"""Check one generated crate's candor-java report against its truth.json.

Prints `OK` if every method the generator knows reaches the effect is reported with that effect OR with
`Unknown` (a sound over-approximation). Otherwise prints `FAIL <effect> :: <offenders> :: forms`. A
reachable method reported PURE — or omitted from the report (candor omits pure methods) — is a SILENT
UNDER-REPORT, the failure this harness hunts. `Unknown` is a PASS (soundness, not precision).

Usage:  check.py <crate-dir>
"""
import json
import sys


def main():
    d = sys.argv[1]
    truth = json.load(open(d + "/truth.json"))
    effect = truth["effect"]
    expect = set(truth["expect"])

    report = json.load(open(d + "/report.json"))
    fns = report.get("functions", report) if isinstance(report, dict) else report
    inferred = {e["fn"]: e.get("inferred", []) for e in fns if isinstance(e, dict)}

    bad = []
    for fn in sorted(expect):
        inf = inferred.get(fn)
        if inf is None:  # omitted => candor judged it pure
            bad.append(fn + "(pure/omitted)")
        elif effect not in inf and "Unknown" not in inf:  # present but neither the effect nor Unknown
            bad.append(fn + "{" + ",".join(inf) + "}")

    if bad:
        print("FAIL " + effect + " :: " + " ".join(bad) + " :: forms=" + json.dumps(truth["forms"]))
    else:
        print("OK")


if __name__ == "__main__":
    main()
