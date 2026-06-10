#!/usr/bin/env python3
"""Property-test candor-java's queries against ground truth recomputed from its raw report+callgraph."""
import json, subprocess, sys, collections, glob, os, tempfile

JAR = "/Users/tom/git/candor-java/build/libs/candor-java-0.3.0-all.jar"
TARGETS = [p for pat in [
    "~/.gradle/caches/modules-2/files-2.1/commons-fileupload/**/commons-fileupload-1.5.jar",
    "~/.gradle/caches/modules-2/files-2.1/commons-validator/**/commons-validator-1.7.jar",
    "~/.gradle/caches/modules-2/files-2.1/commons-chain/**/commons-chain-1.2.jar",
    "~/.gradle/caches/modules-2/files-2.1/org.vafer/**/jdependency-2.13.jar",
    "~/.gradle/caches/modules-2/files-2.1/commons-codec/**/commons-codec-1.15.jar",
    "~/.gradle/caches/modules-2/files-2.1/org.hamcrest/**/hamcrest-2.2.jar",
] for p in glob.glob(os.path.expanduser(pat), recursive=True)]

def jq(*args):
    r = subprocess.run(["java", "-jar", JAR, *args], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr

fails = []
def fail(t, prop, detail):
    fails.append((t, prop, detail)); print(f"  FAIL {t}: {prop} — {detail[:200]}")

total = 0
for jar_path in TARGETS:
    name = os.path.basename(jar_path)
    work = tempfile.mkdtemp()
    rpt = f"{work}/r.json"
    rc, out, err = jq(jar_path, "--json", rpt)
    if not os.path.exists(rpt):
        fail(name, "analyze", f"rc={rc} err={err[:150]}"); continue
    cgp = f"{work}/r.callgraph.json"
    rj = json.load(open(rpt)); fns = rj["functions"] if isinstance(rj, dict) else rj
    by_name = {e["fn"]: e for e in fns}
    cg = json.load(open(cgp)) if os.path.exists(cgp) else {}
    rev = collections.defaultdict(set)
    for caller, callees in cg.items():
        for c in callees: rev[c].add(caller)
    def closure(t):
        seen, stack = set(), [t]
        while stack:
            n = stack.pop()
            for c in rev.get(n, ()):
                if c not in seen: seen.add(c); stack.append(c)
        return seen
    n = 0
    # P0 §2.2 completeness: every report fn is a callgraph key
    miss = [e["fn"] for e in fns if e["fn"] not in cg]
    if miss: fail(name, "sidecar completeness", f"{len(miss)} report fns not keys e.g. {miss[:3]}")
    n += 1
    # P1 diff(self) == empty
    rc, out, _ = jq("diff", rpt, rpt, "--json")
    try:
        dd = json.loads(out)
        if dd.get("gained") or dd.get("lost"): fail(name, "diff(self)!=empty", out[:160])
    except Exception as ex:
        fail(name, "diff(self) unparseable", f"rc={rc} {out[:120]}")
    n += 1
    # P2 callers == closure (3 most-called)
    for t in sorted(rev, key=lambda k: -len(rev[k]))[:3]:
        rc, out, _ = jq("callers", rpt, t, "--json")
        try:
            cd = json.loads(out)
            got = set(cd.get("transitive", [])) | set(cd.get("direct", []))
            want = closure(t)
            if got != want: fail(name, f"callers({t})", f"missing={sorted(want-got)[:3]} extra={sorted(got-want)[:3]}")
        except Exception: fail(name, f"callers({t}) unparseable", f"rc={rc} {out[:100]}")
        n += 1
    # P3 where partition
    present = sorted({x for e in fns for x in e.get("inferred", []) if x != "Unknown"})
    for E in present[:3]:
        rc, out, _ = jq("where", rpt, E, "--json")
        try:
            wd = json.loads(out)
            want_d = {e["fn"] for e in fns if E in e.get("direct", [])}
            want_i = {e["fn"] for e in fns if E in e.get("inferred", []) and E not in e.get("direct", [])}
            if set(wd.get("directly", [])) != want_d or set(wd.get("inherited", [])) != want_i:
                fail(name, f"where({E})", f"d^={set(wd.get('directly',[]))^want_d} i^={set(wd.get('inherited',[]))^want_i}")
        except Exception: fail(name, f"where({E}) unparseable", f"rc={rc} {out[:100]}")
        n += 1
    # P4 path: real edges, terminus direct (2 per effect, 2 effects)
    for E in present[:2]:
        for t in [e["fn"] for e in fns if E in e.get("inferred", []) and E not in e.get("direct", [])][:2]:
            rc, out, _ = jq("path", rpt, t, E, "--json")
            try:
                pd = json.loads(out)
                raw = pd.get("path") or []
                chain = [x["fn"] if isinstance(x, dict) else x for x in raw]
                if not chain: fail(name, f"path({t},{E}) empty", out[:120]); n += 1; continue
                bad = next((i for i in range(len(chain)-1) if chain[i+1] not in cg.get(chain[i], [])), None)
                if bad is not None: fail(name, f"path({t},{E}) fake edge", f"{chain[bad]}->{chain[bad+1]}")
                if E not in by_name.get(chain[-1], {}).get("direct", []):
                    fail(name, f"path({t},{E}) terminus not direct", f"term={chain[-1]}")
            except Exception: fail(name, f"path({t},{E}) unparseable", f"rc={rc} {out[:100]}")
            n += 1
    # P5 whatif affected == closure+self
    if rev:
        t = max(rev, key=lambda k: len(rev[k]))
        rc, out, _ = jq("whatif", rpt, t, "Net", "--json")
        try:
            wd = json.loads(out)
            got, want = set(wd.get("affected", [])), closure(t) | {t}
            if got != want: fail(name, f"whatif({t})", f"missing={sorted(want-got)[:3]} extra={sorted(got-want)[:3]}")
        except Exception: fail(name, "whatif unparseable", f"rc={rc} {out[:100]}")
        n += 1
    # P6 rewire(self) == no drops
    rc, out, _ = jq("rewire", rpt, rpt, "--json")
    try:
        rd = json.loads(out)
        if rd.get("dropped"): fail(name, "rewire(self)!=[]", str(rd.get("dropped"))[:140])
    except Exception: fail(name, "rewire(self) unparseable", f"rc={rc} {out[:100]}")
    n += 1
    total += n
    print(f"  ok {name}: {n} props ({len(fns)} effectful fns)")

print(f"\n{total} property checks; {len(fails)} FAILURES")
for t, p, _ in fails: print(f"  {t}: {p}")
sys.exit(1 if fails else 0)
