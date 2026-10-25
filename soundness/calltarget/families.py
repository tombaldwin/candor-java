#!/usr/bin/env python3
"""Assign every SILENT / FABRICATED (cell, arm) to a mechanism family, from the measured verdicts only.
The PRIMARY arm is 'scan' (in-scan cells) or 'chain' (chained cells, full sidecars). Degraded arms (nohier, nocg)
are reported separately, as are cells silent in the one-tree reference too.
usage: families.py <results.jsonl>..."""
import json, sys, collections
rows = [json.loads(l) for p in sys.argv[1:] for l in open(p)]
rows = [r for r in rows if 'error' not in r]
HOOK_STR = {'h_concat', 'h_valueof', 'h_sb', 'h_format', 'h_println', 'h_exccause', 'h_hashmap', 'h_equals', 'h_treeset', 'h_sort'}
JDKCB = {'h_skel_contains', 'h_skel_tostr', 'h_skel_mapget', 'h_thread', 'h_serial', 'x_thread_opaque', 'k_fnvalue', 'x_hof_indirect'}

def fam(r, arm, v):
    m = r['meta']; k, p, n = m['kind'], m['place'], m['n']
    A = r['arms']
    if v == 'FABRICATED':
        if k == 'c_pkgpriv': return 'FAB jvm-override: package-private member treated as overridden across packages'
        if k == 'c_private': return 'FAB jvm-override: private member treated as virtually dispatched'
        if k in ('c_sibling', 'c_final'): return 'FAB R868-licensed (SPEC 0.40): pure override at the static owner charged the ancestor union'
        return 'FAB other'
    if arm in ('nohier', 'nocg') and A['chain']['verdict'] != 'SILENT':
        return f'DEGRADED {arm}: chain answers, sidecar-deleted arm silent (R1377/R1333)'
    ref = A.get('one') or A.get('scan')
    if p in ('unseen', 'depunseen') and (ref['verdict'] == 'SILENT'):
        return 'OPEN-WORLD: only implementor outside every scanned/chained tree (SPEC 4 accepted trade)'
    if p in ('unseen', 'depunseen') and arm == 'chain':
        if k == 'd_tl_own': return 'SEAM-LOSES-INVISIBLE: one-tree invisible:[hid] absent chained (R1362)'
        return 'SEAM-LOSES-HEDGE: one-tree hedges an open dispatch, chained reads pure (unfiled)'
    if k == 'd_tl_own' and p == 'deph_appwf': return 'IMPOSSIBLE LAYOUT (dep class references a consumer class) - excluded'
    if m['effect'] == 'FsHid':
        if k == 'h_sort': return 'INVISIBLE-AS-PURE: ElementFlow/compareTo hedge fires on concrete effects only; [] + invisible leaf reads pure (R1361 class)'
        if arm == 'scan' or ref['verdict'] == 'SILENT':
            if k not in JDKCB: return 'INVISIBLE-AS-PURE: past-bound floor counts [] + invisible override as pure (R1361)'
        elif arm == 'chain' and k not in JDKCB:
            return 'SEAM-LOSES-INVISIBLE: one-tree discloses invisible leaf, chained absent (R1362)'
    if k in JDKCB: return 'JDK-BODY-CALLBACK: JDK/runtime body calls an override; no site generated (R1242 + unfiled)'
    if k in ('d_tl_local', 'd_tl_param', 'k_lazy_local'): return 'DEFERRED: container not bound to own-class field (R1394)'
    if arm == 'scan':
        if k == 'op_hash_inh' and n == 13: return 'IN-SCAN BOUND: explicit hashCode past the bound, no hedge (unfiled; R1205 residual)'
        return 'IN-SCAN other'
    # chained, full sidecars, one-tree not silent
    if ref['verdict'] == 'SILENT':
        if k == 'op_hash_inh' and n == 13: return 'IN-SCAN BOUND: explicit hashCode past the bound, no hedge (unfiled; R1205 residual)'
        return 'SILENT IN ONE-TREE TOO (other)'
    if p == 'cbthird': return 'PRODUCER-NAMING-THIRD: dep call site, implementor in a third chained package (R1316; R1317 for concrete)'
    if p == 'callback': return 'PRODUCER-NAMING: dep call site on a concrete/inherited member not named in dispatchesOn (R1317)'
    if k == 'op_tostr_iface' and p in ('dep', 'third'): return 'CONSUMER-DOWN: Object member via dep INTERFACE receiver (R1379)'
    if k in HOOK_STR and p in ('dep', 'third'): return 'CONSUMER-DOWN: implicit hook on dep-typed receiver walks UP only (unfiled)'
    if k in HOOK_STR and p in ('appimpl', 'split2'): return 'CONSUMER-OWN: implicit hook, consumer implementors (unfiled)'
    if k.startswith('op_') and p in ('appimpl', 'split2'): return "CONSUMER-OWN: Object member on dep class, consumer's own overrides not joined (unfiled)"
    if k == 'fn_own' and p == 'split2': return "CONSUMER-OWN: consumer's own lambda implementors of a dep SAM, dep union pure (unfiled)"
    return f'CHAINED other ({k},{p})'

prim = collections.Counter(); prim_cells = collections.defaultdict(list)
deg = collections.Counter(); fab = collections.defaultdict(list)
for r in rows:
    for arm, x in r['arms'].items():
        v = x['verdict']
        if v not in ('SILENT', 'FABRICATED'): continue
        f = fam(r, arm, v)
        if v == 'FABRICATED': fab[f].append(f"{r['id']}:{arm}"); continue
        if f.startswith('DEGRADED'): deg[f] += 1; continue
        if arm in ('scan', 'chain'):
            prim[f] += 1; prim_cells[f].append(r['id'])
        elif arm == 'one':
            prim_cells['(one-tree arm silent) ' + f].append(r['id'])
print('## SILENT, primary arm (scan for in-scan cells, chain for chained cells): cells per family')
for f, c in prim.most_common():
    ids = prim_cells[f]
    print(f'{c:4d}  {f}')
    print('      e.g. ' + ', '.join(sorted(ids)[:6]))
print('total primary-arm silent cells:', sum(prim.values()))
print('\n## SILENT only in a degraded arm')
for f, c in deg.most_common(): print(f'{c:4d}  {f}')
print('\n## FABRICATED (cell:arm)')
for f, l in fab.items(): print(f'{len(l):4d}  {f}: ' + ', '.join(l))
pos = sum(1 for r in rows if not r['meta']['negative'])
neg = sum(1 for r in rows if r['meta']['negative'])
print(f'\ncells: {len(rows)} ({pos} positive, executed effect; {neg} controls, effect never executed)')
