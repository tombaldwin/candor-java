#!/usr/bin/env python3
"""slot.py S|C <root> <pre-arm> <post-arm> <edges.out> : every (unit, effect) the post arm no longer carries — each one a
`deny E` (or `deny Unknown`) 1->0 flip at the unit — classed by CAUSE and then by the truth-monotone SLOT it can claim.
Causes: EDGE (a call the unit no longer makes to a callee carrying E in both arms; its truth is CheckAdded --edges'),
CASCADE (a callee the unit still calls, or called, lost E — the slot is the callee's), DIRECT (the unit's own direct set
lost E), WHY (Unknown only: a reason in unknownWhy was dropped). Slots: (a) the Unknown was replaced by concrete charges;
(b) needs proof of purity — met for EDGE by every removed edge FALSE; (d) a concrete loss where the unit keeps an Unknown
(a hedge, which counts only if it covers the lost site — read by hand)."""
import json, sys, collections
M, R, PRE, POST, EO = sys.argv[1:6]
L = '/Users/tom/candor-handoff/javaab-a/entries.txt' if M == 'S' else '/Users/tom/candor-handoff/javaab-a/chained-full/entries-built.txt'
def rows(p):
    try: return {x['fn']: x for x in json.load(open(p)).get('functions', [])}
    except Exception: return {}
verdict = {}
for l in open(EO):
    p = l.rstrip('\n').split('\t')
    if len(p) >= 5 and p[2] == 'real': verdict[(p[0], p[3], p[4])] = p[1]
eff = lambda r: set((r or {}).get('inferred') or [])
st = collections.Counter(); detail = []
for e in open(L):
    n = e.strip().rsplit('/', 1)[-1][:-4]
    if M == 'S': A, B = rows(f'{R}/rep/{PRE}/{n}.json'), rows(f'{R}/rep/{POST}/{n}.json')
    else:
        A = rows(f'{R}/repC/{PRE}/{n}/consumer.json'); B = rows(f'{R}/repC/{POST}/{n}/consumer.json')
    if not A or not B: continue
    for f, r in A.items():
        q = B.get(f)
        for E in sorted(eff(r) - eff(q)):
            causes = set(); vs = []
            pc, qc = set(r.get('calls') or []), set((q or {}).get('calls') or [])
            for v in pc - qc:
                pv, qv = A.get(v), B.get(v)
                if pv and qv and E in eff(pv) and E in eff(qv):
                    causes.add('EDGE'); vs.append(verdict.get((n, r.get('hash'), pv.get('hash')), '?'))
            for v in pc:
                if E in eff(A.get(v)) and E not in eff(B.get(v)): causes.add('CASCADE')
            if E in set(r.get('direct') or []) and E not in set((q or {}).get('direct') or []): causes.add('DIRECT')
            if E == 'Unknown' and set(r.get('unknownWhy') or []) - set((q or {}).get('unknownWhy') or []): causes.add('WHY')
            if not causes: causes.add('OTHER')
            if E == 'Unknown': slot = '(a) resolved-charged' if eff(q) - eff(r) else '(b)? hedge removed'
            elif 'Unknown' in eff(q): slot = '(d)? keeps Unknown'
            else: slot = '(b)? pure for E'
            if 'EDGE' in causes and causes <= {'EDGE', 'CASCADE'} and vs and all(v == 'FALSE' for v in vs):
                slot = '(b) removed edges FALSE'   # a hedge left on the row does not matter: the removed edge never ran
            elif causes == {'CASCADE'}:
                slot = '(cascade) ' + slot
            k = ('Unknown' if E == 'Unknown' else 'concrete', '+'.join(sorted(causes)), slot, 'TRUE' if 'TRUE' in vs else '')
            st[k] += 1; detail.append((n, f, E, k, sorted(set((q or {}).get('unknownWhy') or []))[:3], vs[:4]))
# resolve every pure-CASCADE pair to its roots: the slots of the callee pairs (callee, E) that lost E, transitively
slotof = {(d[0], d[1], d[2]): d[3][2] for d in detail}
callees = {}
for e2 in open(L):
    n = e2.strip().rsplit('/', 1)[-1][:-4]
    A = rows(f'{R}/rep/{PRE}/{n}.json') if M == 'S' else rows(f'{R}/repC/{PRE}/{n}/consumer.json')
    for f, r in A.items(): callees[(n, f)] = r.get('calls') or []
def root(n, f, E, seen):
    sl = slotof.get((n, f, E))
    if sl is None: return set()
    if not sl.startswith('(cascade)'): return {sl}
    if (n, f, E) in seen: return {'(cycle)'}
    seen.add((n, f, E)); out = set()
    for v in callees.get((n, f), []): out |= root(n, v, E, seen)
    return out or {'(cascade, no root)'}
res = collections.Counter()
for d in detail:
    if d[3][2].startswith('(cascade)'):
        rs = root(d[0], d[1], d[2], set())
        res[' + '.join(sorted(rs))] += 1
for k, v in sorted(st.items()): print(v, *k, sep='\t')
print('-- pure cascades resolved to their roots:')
for k, v in sorted(res.items()): print(v, k, sep='\t')
if '-v' in sys.argv:
    for d in detail: print('  ', *d, sep='\t')
