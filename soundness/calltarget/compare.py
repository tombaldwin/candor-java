#!/usr/bin/env python3
"""compare.py <base.jsonl> <cand.jsonl> : per (cell, arm) verdict transitions, base -> candidate.
Held constant: the cells (same compiled build/ dirs), the JDK (21) for compile, execute and engine, the policy.
Only the engine jar differs."""
import json, sys, collections
base = {json.loads(l)['id']: json.loads(l) for l in open(sys.argv[1])}
cand = [json.loads(l) for l in open(sys.argv[2])]
RANK = {'SILENT': 0, 'DISCLOSED': 1, 'CHARGED': 2, 'OK': 0, 'OVERDISCLOSED': 1, 'FABRICATED': 2}
tr = collections.Counter(); ex = collections.defaultdict(list); rowchg = 0
for r in cand:
    if 'error' in r or r['id'] not in base: continue
    b = base[r['id']]
    for a, x in r['arms'].items():
        y = b['arms'][a]
        if x['row'] != y['row']: rowchg += 1
        if x['verdict'] != y['verdict']:
            k = f"{y['verdict']} -> {x['verdict']}"
            tr[k] += 1; ex[k].append(f"{r['id']}:{a}")
print(f'cells compared: {len(cand)}; (cell,arm) rows changed: {rowchg}')
for k, c in tr.most_common():
    neg = 'NEGATIVE-CONTROL ' if any(base[e.split(":")[0]]['meta']['negative'] for e in ex[k]) else ''
    print(f'{c:4d}  {neg}{k}   e.g. ' + ', '.join(ex[k][:8]))
