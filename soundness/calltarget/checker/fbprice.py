#!/usr/bin/env python3
"""fbprice.py <root> <base-arm> : the §1.4 table for the disclosure fallback, options A and B (CANDOR_SITE_FALLBACK).
(1) recognised hook-sites by class and state, from the SITEFB lines of the <base>-fbA arm; (3) rows newly carrying
Unknown base -> fbA / fbB, absolute and % of analysed units; (4) `deny Unknown` 0->1 at those rows, and whether any
concrete set moved (a disclosure-only switch must move none — checked, not assumed)."""
import json, os, sys, collections
R, BASE = sys.argv[1:3]
ES = '/Users/tom/candor-handoff/javaab-a/entries.txt'; EC = '/Users/tom/candor-handoff/javaab-a/chained-full/entries-built.txt'
def load(p):
    try: return json.load(open(p))
    except Exception: return {}
for mode, ents in (('standalone', ES), ('chained', EC)):
    states = collections.Counter(); classes = collections.Counter()
    for e in open(ents):
        n = os.path.basename(e.strip())[:-4]
        f = f'{R}/rep/{BASE}-fbA/{n}.sitefb' if mode == 'standalone' else f'{R}/repC/{BASE}-fbA/{n}/app.sitefb'
        if os.path.exists(f):
            for l in open(f):
                p = l.rstrip('\n').split('\t')
                if len(p) >= 7: classes[p[5]] += 1; states[(p[5], p[6])] += 1
    print(f'== {mode}: recognised hook-sites (one per hook of each recognised call), by class and state')
    for k, v in classes.most_common():
        print(f'   {k:9s} {v:9d}  ' + '  '.join(f'{s}={states[(k, s)]}' for s in ('resolved', 'jdk-only', 'untyped', 'pastbound')))
    for opt in ('A', 'B'):
        newU = moved = tot = ent = 0
        for e in open(ents):
            n = os.path.basename(e.strip())[:-4]
            b, x = ((f'{R}/rep/{BASE}/{n}.json', f'{R}/rep/{BASE}-fb{opt}/{n}.json') if mode == 'standalone'
                    else (f'{R}/repC/{BASE}/{n}/consumer.json', f'{R}/repC/{BASE}-fb{opt}/{n}/consumer.json'))
            B, X = load(b), load(x)
            if not B or not X: continue
            ent += 1; tot += (X.get('analyzed') or {}).get('count') or 0
            bm = {(r.get('hash') or r['fn']): r for r in B.get('functions', [])}
            for r in X.get('functions', []):
                q = bm.get(r.get('hash') or r['fn'])
                if 'Unknown' in (r.get('inferred') or []) and not (q and 'Unknown' in (q.get('inferred') or [])): newU += 1
                if set(r.get('inferred') or []) - {'Unknown'} != set((q or {}).get('inferred') or []) - {'Unknown'}: moved += 1
        print(f'   option {opt}: {ent} entries, {tot} analysed units; rows newly Unknown = deny Unknown 0->1: {newU} '
              f'({100.0 * newU / tot if tot else 0:.4f}%); rows whose concrete set moved: {moved}')
