#!/usr/bin/env python3
"""decorprice.py <root> <post-arm> <decor-dir> : an OFFLINE price for closing the decorator-delegate residual two ways,
over the post arm's own call graph (standalone corpus). R (resolution): a unit with an unnamed-delegate decorator call
(System.out/err/in excluded) is charged the effects of every project stream body of the delegate's base, and callers
inherit them. H (hedge): such a unit gains Unknown when some candidate carries an effect it lacks; callers inherit.
Counts rows whose set changes, of all analysed units (rows + the call-graph sidecar's pure units are not visible here:
the denominator is the analysed-unit count corpus-ab prints). An estimate of reach, not a measurement of the change."""
import json, sys, collections, os
R, POST, D = sys.argv[1:4]
STREAM = {'read', 'write', 'flush', 'close', 'skip', 'append', 'transferTo', 'ready', 'available', 'mark', 'reset', 'skipNBytes', 'readNBytes', 'readAllBytes'}
def rows(p):
    try: return json.load(open(p)).get('functions', [])
    except Exception: return []
tot = collections.Counter(); per = []
for e in open('/Users/tom/candor-handoff/javaab-a/entries.txt'):
    n = e.strip().rsplit('/', 1)[-1][:-4]
    rs = rows(f'{R}/rep/{POST}/{n}.json')
    p = f'{D}/{n}.tsv'
    if not rs or not os.path.exists(p): continue
    F = {r['fn']: r for r in rs}; H = {r.get('hash'): r['fn'] for r in rs if r.get('hash')}
    eff = {f: set(r.get('inferred') or []) for f, r in F.items()}
    sites = collections.defaultdict(set); subs = collections.defaultdict(set)
    for l in open(p):
        x = l.rstrip('\n').split('\t')
        if x[0] == 'SUB':
            m = x[2][x[2].rfind('.', 0, x[2].index('(')) + 1:x[2].index('(')]
            if m in STREAM: subs[x[1]].add(x[2])
        elif len(x) >= 4 and x[3] == 'unnamed': sites[x[0]].add(x[2])
    seedR, seedH = collections.defaultdict(set), set()
    for h, bases in sites.items():
        f = H.get(h)
        if f is None: continue   # a pure unit: not a row (it would become one)
        cand = set()
        for b in bases:
            for s in subs.get(b, ()):
                g = H.get(s)
                if g: cand |= eff[g] - {'Unknown'}
        if cand - eff[f]: seedR[f] |= cand - eff[f]; seedH.add(f)
    callers = collections.defaultdict(set)
    for f, r in F.items():
        for v in r.get('calls') or []: callers[v].add(f)
    gainR = collections.defaultdict(set); q = list(seedR)
    for f in seedR: gainR[f] |= seedR[f]
    while q:
        v = q.pop()
        for c in callers.get(v, ()):
            new = gainR[v] - eff[c] - gainR[c]
            if new: gainR[c] |= new; q.append(c)
    gainH = set(f for f in seedH if 'Unknown' not in eff[f]); q = list(gainH)
    while q:
        v = q.pop()
        for c in callers.get(v, ()):
            if c not in gainH and 'Unknown' not in eff[c]: gainH.add(c); q.append(c)
    tot['entries'] += 1; tot['seed units'] += len(seedR); tot['R rows changed'] += len(gainR); tot['H rows newly Unknown'] += len(gainH)
    per.append((len(gainR), len(gainH), n))
for k, v in tot.items(): print(k, v)
for x in sorted(per, reverse=True)[:12]: print('  ', *x)
