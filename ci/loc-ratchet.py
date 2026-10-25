#!/usr/bin/env python3
"""LOC / complexity RATCHET for the engine source (Phase D Stage 0, history/BACKLOG-2026-07-to-09.md ~:4048).

Nothing measured file size before this, which is how Candor.java went 5,678 -> 12,899 lines unremarked. This is a
RATCHET against a recorded baseline, never a threshold: a file may not GROW (lines, or decision points) past the
number recorded in ci/loc-baseline.tsv unless the same change records the new number. Growth is allowed; growth
nobody wrote down is not.

  python3 ci/loc-ratchet.py            # check: exit 1 if any file grew past its baseline, or is new and unrecorded
  python3 ci/loc-ratchet.py --update   # re-record the baseline (commit it with the change that moved it)

Decision points are a cheap cyclomatic proxy counted on comment- and string-stripped source: if / for / while /
case / catch / && / || / ?: (a ternary). It moves with branching, not with prose, which is the half LOC cannot see.
Not wired into per-commit CI; the coordinator decides that."""
import os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'src', 'main', 'java')
BASE = os.path.join(ROOT, 'ci', 'loc-baseline.tsv')
STRIP = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)
DEC = re.compile(r'\b(?:if|for|while|case|catch)\b|&&|\|\||\?(?![.:])')

def measure():
    out = {}
    for d, _, fs in os.walk(SRC):
        for f in fs:
            if not f.endswith('.java'): continue
            p = os.path.join(d, f)
            txt = open(p, encoding='utf-8').read()
            code = STRIP.sub(lambda m: '\n' * m.group(0).count('\n') if m.group(0).startswith('/') else '""', txt)
            out[os.path.relpath(p, ROOT)] = (txt.count('\n'), len(DEC.findall(code)))
    return out

def main():
    cur = measure()
    if '--update' in sys.argv:
        with open(BASE, 'w') as fh:
            fh.write('# file\tlines\tdecisions  (ci/loc-ratchet.py --update)\n')
            for k in sorted(cur): fh.write(f'{k}\t{cur[k][0]}\t{cur[k][1]}\n')
        print(f'loc-ratchet: recorded {len(cur)} files, {sum(v[0] for v in cur.values())} lines, '
              f'{sum(v[1] for v in cur.values())} decision points')
        return 0
    base = {}
    for l in open(BASE):
        if l.startswith('#') or not l.strip(): continue
        k, a, b = l.rstrip('\n').split('\t'); base[k] = (int(a), int(b))
    bad = []
    for k, (ln, dc) in sorted(cur.items()):
        if k not in base: bad.append(f'{k}: new file ({ln} lines, {dc} decisions) not in the baseline'); continue
        bl, bd = base[k]
        if ln > bl: bad.append(f'{k}: lines {bl} -> {ln} (+{ln - bl})')
        if dc > bd: bad.append(f'{k}: decisions {bd} -> {dc} (+{dc - bd})')
    shrunk = [k for k in cur if k in base and (cur[k][0] < base[k][0] or cur[k][1] < base[k][1])]
    gone = [k for k in base if k not in cur]
    for x in bad: print('  GREW', x)
    if shrunk or gone: print(f'  (shrank: {len(shrunk)}, removed: {len(gone)} — `--update` locks the gain in)')
    print('loc-ratchet: ' + ('FAIL — record the growth with --update in the same change' if bad else 'OK'))
    return 1 if bad else 0

sys.exit(main())
