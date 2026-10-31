#!/usr/bin/env python3
"""gate.py <baseline.tsv> <candidate.tsv> : (cell, arm) verdict transitions baseline -> candidate.
FAILS (exit 1) on any transition TOWARD silence (CHARGED/DISCLOSED -> SILENT, CHARGED -> DISCLOSED), any NEW
FABRICATED (or OK -> OVERDISCLOSED on a control, reported separately as cost), or a (cell, arm) present in the
baseline and missing from the candidate. Improvements are listed, never failed: the baseline is updated by
committing the candidate table beside the change that moved it."""
import sys, collections
def load(p):
    d = {}
    for l in open(p):
        if l.strip():
            i, a, v, rv = l.rstrip('\n').split('\t')
            d[(i, a)] = v
    return d
b, c = load(sys.argv[1]), load(sys.argv[2])
POS = {'SILENT': 0, 'DISCLOSED': 1, 'CHARGED': 2}
NEG = {'OK': 0, 'OVERDISCLOSED': 1, 'FABRICATED': 2}
tr = collections.Counter(); ex = collections.defaultdict(list); bad = []
for k, v in sorted(b.items()):
    if k not in c:
        bad.append(f'missing in candidate: {k[0]}:{k[1]}'); continue
    w = c[k]
    if v == w: continue
    t = f'{v} -> {w}'; tr[t] += 1; ex[t].append(f'{k[0]}:{k[1]}')
    if v in POS and w in POS and POS[w] < POS[v]: bad.append(f'toward silence: {k[0]}:{k[1]} {t}')
    if w == 'FABRICATED': bad.append(f'new fabrication: {k[0]}:{k[1]} {t}')
new = sorted(set(c) - set(b))
for k in new:
    if c[k] == 'FABRICATED': bad.append(f'new cell FABRICATED: {k[0]}:{k[1]}')
import os
lic = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'licensed.tsv')
if os.path.exists(lic):
    for l in open(lic):
        if l.strip() and not l.startswith('#'):
            i, a, v, why = l.rstrip('\n').split('\t')
            ks = [k for k in c if k[0] == i and (a == '*' or k[1] == a)]
            for k in ks: print(f'  licensed: {k[0]}:{k[1]} {c[k]} ({why})')
print(f'baseline {len(b)} (cell,arm), candidate {len(c)}, {len(new)} new; transitions:')
for t, n in tr.most_common():
    print(f'{n:5d}  {t}   e.g. ' + ', '.join(ex[t][:6]))
tot = lambda d: collections.Counter(d.values())
print('baseline totals ', dict(sorted(tot(b).items())))
print('candidate totals', dict(sorted(tot(c).items())))
for x in bad: print('  FAIL', x)
print('GATE: ' + ('FAIL' if bad else 'OK'))
sys.exit(1 if bad else 0)
