#!/usr/bin/env python3
"""verdicts.py <out.tsv> <results.jsonl>... : one line per (cell, arm): id, arm, verdict (scan route), report-route
verdict. Exits 1 on an instrument fault: a compile/producer error, a positive cell that did not execute its effect,
a control that did, or a scan-route vs report-route difference. Those make the table not a measurement."""
import json, sys
out, paths = sys.argv[1], sys.argv[2:]
lines, faults = [], []
for p in paths:
    for l in open(p):
        r = json.loads(l)
        if 'error' in r:
            faults.append(f"{r['id']}: {r['error']}"); continue
        neg = r['meta']['negative']
        if r['happened'] == neg:
            faults.append(f"{r['id']}: ground truth (negative={neg}, executed={r['happened']})")
        for a, x in sorted(r['arms'].items()):
            if x['verdict'] != x['rverdict']:
                faults.append(f"{r['id']}:{a}: scan route {x['verdict']} vs report route {x['rverdict']}")
            lines.append(f"{r['id']}\t{a}\t{x['verdict']}\t{x['rverdict']}")
lines.sort()
open(out, 'w').write('\n'.join(lines) + '\n')
print(f'{len(lines)} (cell, arm) verdicts -> {out}; {len(faults)} instrument fault(s)')
for f in faults: print('  FAULT', f)
sys.exit(1 if faults else 0)
