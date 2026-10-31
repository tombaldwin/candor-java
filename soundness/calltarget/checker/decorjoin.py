#!/usr/bin/env python3
"""decorjoin.py <root> <pre-arm> <post-arm> <decor-dir> [-v] : for every (unit, concrete effect) the post arm no longer
carries (standalone), is there a path the post arm still does not charge — the unit, or a unit it reaches in the post
call graph, calls a JDK stream DECORATOR whose delegate it cannot name (CheckAdded --decor), and some project stream of
that delegate's base carries the effect on the post arm? Then the removal uncovered a delegate path: a POSSIBLE LOSS
(the 0.40.0 R976 shape), not a proof of purity. Otherwise the removed charge had no such path (by this detector)."""
import json, sys, collections, os
R, PRE, POST, D = sys.argv[1:5]
V = '-v' in sys.argv
def rows(p):
    try: return {x['fn']: x for x in json.load(open(p)).get('functions', [])}
    except Exception: return {}
STREAM = {'read', 'write', 'flush', 'close', 'skip', 'append', 'transferTo', 'ready', 'available', 'mark', 'reset', 'skipNBytes', 'readNBytes', 'readAllBytes'}
eff = lambda r: set((r or {}).get('inferred') or [])
st = collections.Counter(); out = []
for e in open('/Users/tom/candor-handoff/javaab-a/entries.txt'):
    n = e.strip().rsplit('/', 1)[-1][:-4]
    A, B = rows(f'{R}/rep/{PRE}/{n}.json'), rows(f'{R}/rep/{POST}/{n}.json')
    if not A or not B: continue
    lost = [(f, E) for f, r in A.items() for E in eff(r) - eff(B.get(f)) if E != 'Unknown']
    if not lost: continue
    sites = collections.defaultdict(set); subs = collections.defaultdict(set)
    p = f'{D}/{n}.tsv'
    if os.path.exists(p):
        for l in open(p):
            x = l.rstrip('\n').split('\t')
            if x[0] == 'SUB':
                m = x[2][x[2].rfind('.', 0, x[2].index('(')) + 1:x[2].index('(')]
                if m in STREAM: subs[x[1]].add(x[2])   # the members a decorator body calls on its delegate
            elif len(x) >= 3: sites[x[0]].add((x[1], x[2]))
    byhash = {r.get('hash'): r for r in B.values() if r.get('hash')}
    for f, E in lost:
        seen, q, hit = {f}, [f], None
        while q and not hit:
            u = q.pop(0); r = B.get(u) or A.get(u)
            if not r: continue
            for (dm, base) in sites.get(r.get('hash'), ()):
                c = [s for s in subs.get(base, ()) if E in eff(byhash.get(s))]
                if c: hit = (u, dm, base, c[:2]); break
            for v in (B.get(u) or {}).get('calls') or []:
                if v not in seen and len(seen) < 400: seen.add(v); q.append(v)
        post = B.get(f)
        k = ('POSSIBLE-LOSS delegate path' if hit else 'no delegate path', 'post keeps Unknown' if 'Unknown' in eff(post) else 'post has no Unknown')
        st[k] += 1
        if hit: out.append((n, f, E, k[1], hit))
for k, v in sorted(st.items()): print(v, *k, sep='\t')
rows_hit = collections.Counter((x[0], x[1]) for x in out)
print('rows with a possible delegate loss:', len(rows_hit), 'entries:', len({x[0] for x in out}))
if V:
    for x in out: print('  ', *x, sep='\t')
