#!/usr/bin/env python3
"""edgeset.py <out.tsv> <pre.json> <post.json> [--seeds N]: the REMOVED edges behind every removed (unit, effect) — a call
the unit no longer makes whose callee carries the lost effect in BOTH arms (a callee that merely went pure is not listed
in `calls` and is not a removed edge) — as (caller-hash, callee-hash, real); seeds: N kept post edges (seed-kept)."""
import json, sys, random
out, pre, post = sys.argv[1:4]
N = int(sys.argv[sys.argv.index('--seeds') + 1]) if '--seeds' in sys.argv else 0
def rows(p):
    try: return json.load(open(p)).get('functions', [])
    except Exception: return []
P = {r['fn']: r for r in rows(pre)}; Q = {r['fn']: r for r in rows(post)}
eff = lambda r: set(r.get('inferred') or [])
lines = set()
for f, r in P.items():
    q = Q.get(f); lost = eff(r) - (eff(q) if q else set())
    if not lost or not r.get('hash'): continue
    for v in set(r.get('calls') or []) - set((q or {}).get('calls') or []):
        pv, qv = P.get(v), Q.get(v)
        if pv and qv and pv.get('hash') and lost & eff(pv) & eff(qv): lines.add((r['hash'], pv['hash'], 'real'))
kept = [(r['hash'], Q[v]['hash']) for f, r in Q.items() if r.get('hash') for v in (r.get('calls') or []) if v in Q and Q[v].get('hash') and eff(Q[v])]
random.Random(1441).shuffle(kept)
for a, b in kept[:N]: lines.add((a, b, 'seed-kept'))
open(out, 'w').write(''.join('\t'.join(x) + '\n' for x in sorted(lines)))
