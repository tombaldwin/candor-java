#!/usr/bin/env python3
"""poscal.py <mx-dir> <pre-tag> <post-tag> <out-dir> <classes-jar-dir>: POSITIVE calibration on the executed call-target
matrix — every (cell, arm) SILENT/DISCLOSED -> CHARGED is a real added charge (ground truth executed); CheckAdded must
explain app.Main.go's from bytecode + rows alone."""
import json, os, sys, subprocess, glob
MX, PRE, POST, OUT, CK = sys.argv[1:6]
J = '/opt/homebrew/opt/openjdk@21/bin/java'
os.makedirs(OUT, exist_ok=True)
def res(tag):
    r = {}
    for m in ('m', 'm3', 'm2'):
        p = f'{MX}/{m}/results-{tag}.jsonl'
        if os.path.exists(p):
            for l in open(p):
                x = json.loads(l)
                if 'error' not in x: r[x['id']] = (m, x)
    return r
a, b = res(PRE), res(POST)
cases = [(m, cid, arm) for cid, (m, x) in b.items() if cid in a for arm, v in x['arms'].items()
         if v['verdict'] == 'CHARGED' and a[cid][1]['arms'].get(arm, {}).get('verdict') in ('SILENT', 'DISCLOSED')]
stats = {}; bad = []
for m, cid, arm in cases:
    d = f'{MX}/{m}/cells/{cid}'
    deps = [p for p in sorted(glob.glob(f'{d}/o-{POST}/deps/*.json')) if not p.endswith(('.callgraph.json', '.hierarchy.json'))]
    w = f'{OUT}/{cid}.{arm}'
    subprocess.run(['python3', '-I', f'{CK}/mkrows.py', w, f'{d}/o-{PRE}/{arm}/r.json', f'{d}/o-{POST}/{arm}/r.json'] + (deps if arm not in ('one', 'scan') else []), capture_output=True)
    lines = [l for l in open(f'{w}/added.tsv') if l.startswith('app/Main.go(')]
    open(f'{w}/added.tsv', 'w').writelines(lines)
    if not lines: stats['no-added-row'] = stats.get('no-added-row', 0) + 1; bad.append((cid, arm, 'no added row')); continue
    cp = ':'.join(x for x in (f'{d}/build/app', f'{d}/build/dep', f'{d}/build/dep2') if os.path.isdir(x))
    o = subprocess.run([J, '-cp', f'{CK}/cls:{CK}/lib/*', 'CheckAdded', f'{w}/rows.tsv', f'{w}/added.tsv', cp], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout
    k = 'UNEXPLAINED' if 'UNEXPLAINED' in o else 'explained'
    stats[k] = stats.get(k, 0) + 1
    if k != 'explained': bad.append((cid, arm, o.strip().splitlines()[0] if o.strip() else ''))
print(len(cases), 'real added charges (matrix, executed):', stats)
for x in bad[:40]: print('  ', *x)
