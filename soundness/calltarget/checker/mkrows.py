#!/usr/bin/env python3
"""mkrows.py <out-dir> <pre.json> <post.json> [<post-dep.json>...] : rows.tsv (unit hash -> concrete effects, every post
report given) and added.tsv (units whose CONCRETE effects grew pre -> post, matched by unit hash)."""
import json, sys, os
out, pre, posts = sys.argv[1], sys.argv[2], sys.argv[3:]
def rows(p):
    try: return json.load(open(p)).get('functions', [])
    except Exception: return []
conc = lambda r: {e for e in (r.get('inferred') or []) if e != 'Unknown'}
os.makedirs(out, exist_ok=True)
A = {r.get('hash') or r['fn']: conc(r) for r in rows(pre)}
with open(os.path.join(out, 'rows.tsv'), 'w') as f:
    for p in posts:
        for r in rows(p): f.write(f"{r.get('hash') or r['fn']}\t{','.join(sorted(conc(r)))}\n")
n = 0
with open(os.path.join(out, 'added.tsv'), 'w') as f:
    for r in rows(posts[0]):
        k = r.get('hash') or r['fn']
        g = conc(r) - A.get(k, set())
        if g: f.write(f"{k}\t{','.join(sorted(g))}\n"); n += 1
print(n, 'added rows')
