#!/usr/bin/env python3
"""Same as audit.py but restricted to CONCRETE effects (Unknown-only rows dropped: an Unknown inside a
library body is the engine saying 'I cannot see in', not a coverage claim about a capability), and it
prints the member names so each hit can be ground-truthed with javap."""
import json, subprocess, sys, os, collections
report, prefixes = sys.argv[1], sys.argv[2].split(",")
want = set((sys.argv[3].split(",") if len(sys.argv) > 3 else
            ["Exec","Net","Fs","Db","Env","Proc","Llm","Clipboard"]))
CJ = os.environ["CJ_ALL"]; PROBE = os.environ["PROBE"]
d = json.load(open(report))
rows = []
for f in d.get("functions", []):
    inf = set(f.get("direct") or [])
    conc = inf & want
    if not conc: continue
    h = f.get("hash") or ""
    if "(" not in h: continue
    sig, desc = h.split("(", 1); desc = "(" + desc
    owner, method = sig.rsplit(".", 1); owner = owner.replace("/", ".")
    if not any(owner == p or owner.startswith(p + ".") for p in prefixes): continue
    rows.append((owner, method, desc, tuple(sorted(conc))))
uniq = sorted(set(rows))
inp = "\n".join(f"{o}\t{m}\t{de}" for o, m, de, _ in uniq)
out = subprocess.run(["java","-cp",PROBE+":"+CJ,"io.poly.candor.KappaQuery"],
                     input=inp, capture_output=True, text=True).stdout.splitlines()
kappa = {tuple(l.split("\t")[:3]): l.split("\t")[3] for l in out}
nulls = [(o,m,de,e) for o,m,de,e in uniq if kappa.get((o,m,de)) == "NULL"]
cls   = len(uniq) - len(nulls)
print(f"== {os.path.basename(report)} [{','.join(prefixes)}]  concrete-effect members={len(uniq)}  kappa-classified={cls}  kappa-NULL={len(nulls)}")
byowner = collections.defaultdict(list)
for o,m,de,e in nulls: byowner[o].append((m,e))
for o in sorted(byowner, key=lambda k: -len(byowner[k])):
    ms = byowner[o]
    effs = sorted({x for _,e in ms for x in e})
    names = sorted({m for m,_ in ms})
    print(f"  {len(ms):4d} {o}  {effs}")
    print(f"        {', '.join(names[:24])}{' …' if len(names)>24 else ''}")
