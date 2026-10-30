#!/usr/bin/env python3
"""cascade.py S|C <root> <pre-arm> <post-arm> <added.out> : the residue of CheckAdded's UNEXPLAINED real charges split
by one more question that needs no engine model: does the unit reach the effect through a call edge it ALREADY had on
the published arm (listed in its `calls` on both arms) whose callee now carries the effect? Then the change did not make
the edge — the charge is a cascade from the callee, whose own gain is checked as a row of its own. The rest is read by
hand."""
import json, sys, os, collections
M, R, PRE, POST, F = sys.argv[1:6]
def rows(p):
    try: return {x['fn']: x for x in json.load(open(p)).get('functions', [])}
    except Exception: return {}
cache = {}
def arm(n, a):
    k = (n, a)
    if k not in cache:
        cache[k] = rows(f'{R}/rep/{a}/{n}.json') if M == 'S' else rows(f'{R}/repC/{a}/{n}/consumer.json') | rows(f'{R}/repC/{a}/{n}/lib.json')
    return cache[k]
st = collections.Counter(); rest = []
for l in open(F):
    p = l.rstrip('\n').split('\t')
    if len(p) < 5 or p[1] != 'UNEXPLAINED' or p[2] != 'real': continue
    n, h = p[0], p[3]
    effs = [e.strip() for e in p[4].strip('[]').split(',')]
    A, B = arm(n, PRE), arm(n, POST)
    u = next((r for r in B.values() if r.get('hash') == h), None)
    a = A.get(u['fn']) if u else None
    if not u: st['unit not found'] += 1; rest.append((n, h, effs, 'unit?')); continue
    both = set(u.get('calls') or []) & set((a or {}).get('calls') or [])
    left = [E for E in effs if not any(E in (B.get(v, {}).get('inferred') or []) for v in both)]
    if not left: st['cascade via a published edge'] += 1
    else: st['residue'] += 1; rest.append((n, h, left, sorted(set(u.get('calls') or []) - both)[:4]))
print(dict(st))
for x in rest: print('  RESIDUE', *x)
