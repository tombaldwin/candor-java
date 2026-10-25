#!/usr/bin/env python3
"""Run the call-target matrix: compile, EXECUTE (ground truth), scan every arm, gate the caller.

usage: run.py <out-dir> <engine-jar> <tag> [--jobs 2] [--only substr]
Writes <out>/results-<tag>.jsonl (one line per cell) and per-cell arm outputs under cells/<id>/o-<tag>/.
"""
import json, os, sys, subprocess, shutil, glob, concurrent.futures as cf

OUT, JAR, TAG = sys.argv[1], sys.argv[2], sys.argv[3]
JOBS = int(sys.argv[sys.argv.index('--jobs') + 1]) if '--jobs' in sys.argv else 2
ONLY = sys.argv[sys.argv.index('--only') + 1] if '--only' in sys.argv else None
JH = os.environ.get('CT_JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home')
JAVA, JAVAC = f'{JH}/bin/java', f'{JH}/bin/javac'
ENV = dict(os.environ, JAVA_HOME=JH, PATH=f'{JH}/bin:' + os.environ['PATH'])
ENV.pop('CANDOR_DEPS', None); ENV.pop('CANDOR_POLICY', None); ENV.pop('CANDOR_REPORT', None)

def sh(cmd, env=None, timeout=120, cwd=None):
    p = subprocess.run(cmd, env=env or ENV, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    return p.returncode, p.stdout + p.stderr

def compile_cell(d):
    b = os.path.join(d, 'build')
    if os.path.exists(os.path.join(b, '.ok')):
        return True, ''
    shutil.rmtree(b, ignore_errors=True)
    srcs = sorted(glob.glob(os.path.join(d, 'src', '**', '*.java'), recursive=True))
    allc = os.path.join(b, 'all')
    os.makedirs(allc)
    rc, out = sh([JAVAC, '-nowarn', '-d', allc] + srcs)
    if rc != 0:
        return False, out
    # class -> group from the source layout, PER SOURCE FILE: a split package (one runtime package compiled in two
    # groups, e.g. x_pkgpriv_same) must keep each class in its own group
    for s in srcs:
        rel = os.path.relpath(s, os.path.join(d, 'src')).split(os.sep)
        g, pkgpath, simple = rel[0], rel[1:-1], rel[-1][:-len('.java')]
        srcdir = os.path.join(allc, *pkgpath)
        dst = os.path.join(b, g, *pkgpath)
        os.makedirs(dst, exist_ok=True)
        for f in glob.glob(os.path.join(srcdir, simple + '.class')) + glob.glob(os.path.join(srcdir, simple + '$*.class')):
            shutil.copy(f, dst)
    open(os.path.join(b, '.ok'), 'w').write('ok')
    return True, ''

def execute(d, meta):
    b = os.path.join(d, 'build')
    cp = ':'.join(os.path.join(b, g) for g in ('app', 'dep', 'dep2', 'hid') if os.path.isdir(os.path.join(b, g)))
    cp = ':'.join([cp] + meta.get('extra_cp', []))
    res = []
    for spec in meta['runs']:
        mk = os.path.join(d, 'marker')
        if os.path.exists(mk):
            os.remove(mk)
        try:
            rc, out = sh([JAVA, '-cp', cp, 'app.Main', spec, mk], timeout=30)
        except subprocess.TimeoutExpired:
            rc, out = 'timeout', ''
        res.append(dict(spec=spec, rc=rc, happened=os.path.exists(mk), out=out[-400:] if rc else ''))
    return res

def gate_row(rep, fn):
    try:
        r = json.load(open(rep))
    except Exception as e:
        return None, f'unreadable: {e}'
    rows = [f for f in r.get('functions', []) if f.get('fn') == fn]
    if not rows:
        return None, 'absent'
    f = rows[0]
    keep = {k: f.get(k) for k in ('inferred', 'invisible', 'incomplete', 'unknownWhy', 'calls', 'dispatchesOn') if f.get(k)}
    return keep, 'present'

def violations(gj, fn):
    try:
        g = json.load(open(gj))
    except Exception:
        return None
    effs = set()
    for v in g.get('violations', []):
        if v.get('fn') == fn:
            effs.update(v.get('effects', []))
    return sorted(effs)

def scan_arm(d, adir, target, deps, pol, fn):
    os.makedirs(adir, exist_ok=True)
    env = dict(ENV)
    if deps:
        env['CANDOR_DEPS'] = deps
    rep = os.path.join(adir, 'r.json')
    rc, out = sh([JAVA, '-jar', JAR, target, '--json', rep, '--policy', pol, '--gate-json', os.path.join(adir, 'g.json')], env=env)
    open(os.path.join(adir, 'scan.log'), 'w').write(out)
    rc2, out2 = sh([JAVA, '-jar', JAR, 'gate', '--policy', pol, '--report', rep, '--gate-json', os.path.join(adir, 'g2.json')])
    open(os.path.join(adir, 'gate.log'), 'w').write(out2)
    row, st = gate_row(rep, fn)
    return dict(scan_exit=rc, rep_exit=rc2, scan_viol=violations(os.path.join(adir, 'g.json'), fn),
                rep_viol=violations(os.path.join(adir, 'g2.json'), fn), row=row, row_state=st)

def merge_dirs(dst, srcs):
    os.makedirs(dst, exist_ok=True)
    for s in srcs:
        if os.path.isdir(s):
            shutil.copytree(s, dst, dirs_exist_ok=True)

def verdict(arm, effect, happened):
    sv = arm['scan_viol'] or []
    row = arm['row'] or {}
    disclosed = ('Unknown' in sv) or arm['scan_exit'] == 2 or bool(row.get('invisible')) \
        or ('Unknown' in (row.get('inferred') or []))
    if happened:
        if effect in sv:
            return 'CHARGED'
        return 'DISCLOSED' if disclosed else 'SILENT'
    if effect in sv:
        return 'FABRICATED'
    return 'OVERDISCLOSED' if disclosed else 'OK'

def route_verdict(arm, effect, happened):
    a = dict(arm)
    a['scan_viol'] = arm['rep_viol']
    a['scan_exit'] = arm['rep_exit']
    return verdict(a, effect, happened)

def run_cell(cid):
    d = os.path.join(OUT, 'cells', cid)
    meta = json.load(open(os.path.join(d, 'cell.json')))
    ok, err = compile_cell(d)
    if not ok:
        return dict(id=cid, meta=meta, error='compile', detail=err[-1500:])
    ex = execute(d, meta)
    happened = any(r['happened'] for r in ex)
    o = os.path.join(d, f'o-{TAG}')
    shutil.rmtree(o, ignore_errors=True)
    os.makedirs(o)
    pol = os.path.join(o, 'pol')
    fn = meta['gated']
    ge = 'Fs' if meta['effect'] == 'FsHid' else meta['effect']
    open(pol, 'w').write(f'deny {ge} {fn}\ndeny Unknown {fn}\n')
    b = os.path.join(d, 'build')
    arms = {}
    if not meta['chained']:
        arms['scan'] = scan_arm(d, os.path.join(o, 'scan'), os.path.join(b, 'app'), None, pol, fn)
    else:
        one = os.path.join(o, 'one-classes')
        merge_dirs(one, [os.path.join(b, g) for g in ('app', 'dep', 'dep2')])
        arms['one'] = scan_arm(d, os.path.join(o, 'one'), one, None, pol, fn)
        deps = os.path.join(o, 'deps')
        os.makedirs(deps)
        rc, out = sh([JAVA, '-jar', JAR, os.path.join(b, 'dep'), '--json', os.path.join(deps, 'dep.json')])
        open(os.path.join(o, 'prod-dep.log'), 'w').write(out)
        if os.path.isdir(os.path.join(b, 'dep2')):
            tmp = os.path.join(o, 'deps2tmp')
            os.makedirs(tmp)
            env = dict(ENV, CANDOR_DEPS=deps)
            rc, out = sh([JAVA, '-jar', JAR, os.path.join(b, 'dep2'), '--json', os.path.join(tmp, 'dep2.json')], env=env)
            open(os.path.join(o, 'prod-dep2.log'), 'w').write(out)
            for f in glob.glob(os.path.join(tmp, '*')):
                shutil.copy(f, deps)
        arms['chain'] = scan_arm(d, os.path.join(o, 'chain'), os.path.join(b, 'app'), deps, pol, fn)
        for arm, pat in (('nohier', '*.hierarchy.json'), ('nocg', '*.callgraph.json')):
            dd = os.path.join(o, 'deps-' + arm)
            shutil.copytree(deps, dd)
            for f in glob.glob(os.path.join(dd, pat)):
                os.remove(f)
            arms[arm] = scan_arm(d, os.path.join(o, arm), os.path.join(b, 'app'), dd, pol, fn)
    if meta['chained'] and os.path.isdir(os.path.join(b, 'dep2')) and not os.path.exists(os.path.join(deps, 'dep2.json')):
        return dict(id=cid, meta=meta, error='producer-dep2', detail=open(os.path.join(o, 'prod-dep2.log')).read()[-800:])
    if meta['chained'] and not os.path.exists(os.path.join(deps, 'dep.json')):
        return dict(id=cid, meta=meta, error='producer-dep', detail=open(os.path.join(o, 'prod-dep.log')).read()[-800:])
    eff = 'Fs' if meta['effect'] == 'FsHid' else meta['effect']
    for a in arms.values():
        a['verdict'] = verdict(a, eff, happened)
        a['rverdict'] = route_verdict(a, eff, happened)
    return dict(id=cid, meta={k: meta[k] for k in ('kind', 'family', 'place', 'n', 'effect', 'chained', 'negative')},
                executed=ex, happened=happened, arms=arms)

def main():
    man = json.load(open(os.path.join(OUT, 'manifest.json')))
    ids = [i for i in man['ids'] if not ONLY or ONLY in i]
    res = os.path.join(OUT, f'results-{TAG}.jsonl')
    done = set()
    if os.path.exists(res):
        for l in open(res):
            try:
                done.add(json.loads(l)['id'])
            except Exception:
                pass
    todo = [i for i in ids if i not in done]
    print(f'{len(todo)} to run ({len(done)} done)', flush=True)
    with open(res, 'a') as fh, cf.ThreadPoolExecutor(JOBS) as ex:
        for n, r in enumerate(ex.map(run_cell, todo)):
            fh.write(json.dumps(r) + '\n'); fh.flush()
            if n % 50 == 0:
                print(n, r['id'], flush=True)
    print('=== done ===', flush=True)

main()
