import re,collections,sys
# gen.py reach.tsv typeRegex -> handle types (wire share >= 1/2) and per-type PURE names
# (every overload local AND none returns a lazy handle). NOIMPL members of a *Reactive/*Rx type take the
# verdict of the sync/async twin; with no twin they count as wire.
path,rxs=sys.argv[1],sys.argv[2]
entries=sys.argv[3].split(',')
rows=[l.rstrip('\n').split('\t') for l in open(path)]
rows=[r+['']*(6-len(r)) for r in rows if re.match(rxs,r[0])]
tn=collections.defaultdict(list)
import os
supmap=collections.defaultdict(set)
for l in open(os.path.join(os.path.dirname(path),'super.tsv')):
    if l.startswith('#SUPER'):
        _,t0,ss=l.rstrip('\n').split('\t'); supmap[t0].update(x for x in ss.split(',') if x)
def supers(t):
    out=set(); q=[t]
    while q:
        x=q.pop()
        for y in supmap.get(x,()):
            if y not in out: out.add(y); q.append(y)
    return out
wire_types=collections.Counter(t for t,nd,cls,v,p,lz in rows if v=='WIRE')
for t,nd,cls,v,p,lz in rows:
    r=nd[nd.index(')')+1:]
    # A builder step that hands back the SAME handle or a supertype of it (`FindIterable.limit(n)`,
    # `AggregateIterable.batchSize` through MongoIterable) creates no new lazy handle: the one it returns
    # was disclosed where it was made.
    if lz and r.startswith('L') and (r[1:-1]==t or r[1:-1] in supers(t)): lz=''
    # A family type that implements Iterable but has no wire member of its own is a VALUE
    # (`CommandArguments`), not a handle: returning one creates nothing to consume later.
    if lz=='LAZY' and r.startswith('L') and not wire_types.get(r[1:-1]): lz=''
    tn[(t,nd.split('(')[0])].append((v,lz,cls))
def base(vs):
    s={v for v,_,_ in vs}
    if s=={'local'}: return 'local'
    if 'WIRE' in s: return 'wire'
    if s=={'NOIMPL'}: return 'NOIMPL'
    return 'wire'
ver={k:base(v) for k,v in tn.items()}
def twin(t,n):
    for suf in ('Reactive','Rx'):
        if t.endswith(suf):
            b=t[:-len(suf)]
            for c in ((b,n),(b+'Async',n+'Async'),(b+'Async',n)):
                if c in ver and ver[c]!='NOIMPL': return ver[c]
    return None
final={}
for k,x in ver.items():
    if x=='NOIMPL': x=twin(*k) or ('wire' if k[0].endswith(('Reactive','Rx')) else 'NOIMPL')
    lazy=any(lz for _,lz,_ in tn[k])
    if x=='local' and lazy: x='lazy'
    final[k]=x
types=collections.defaultdict(collections.Counter)
for (t,n),x in final.items(): types[t][x]+=1
# THE HANDLE GRAPH: types reachable from the client's entry types through the return types of their public
# members, inside the family's package, keeping only types with at least one measured wire member.
rets=collections.defaultdict(set)
from re import findall
for t,nd,cls,v,p,lz in rows:
    r=nd[nd.index(')')+1:]
    if r.startswith('L'): rets[t].add(r[1:-1])
seen=set(); q=list(entries)
while q:
    t=q.pop()
    if t in seen or not re.match(rxs,t): continue
    seen.add(t)
    q.extend(rets.get(t,()))
# …and every family SUPERTYPE of a reached type: javac names the static type the caller holds, and a caller
# may hold `UnifiedJedis` as `JedisCommands` or an `RMap` as `RMapAsync`.
sup=collections.defaultdict(set)
import os
sp=os.path.join(os.path.dirname(path),'super.tsv')
for l in open(sp):
    if l.startswith('#SUPER'):
        _,t,ss=l.rstrip('\n').split('\t'); sup[t].update(x for x in ss.split(',') if x)
q=list(seen)
while q:
    t=q.pop()
    for x in sup.get(t,()):
        if x not in seen and re.match(rxs,x): seen.add(x); q.append(x)
handles={t for t in seen if types[t]['wire']>0}
import os
if os.environ.get('DUMP_FINAL'):
    with open(os.environ['DUMP_FINAL'],'w') as fh:
        for (t,n),x in sorted(final.items()): fh.write(f"{t.replace('/','.')}.{n}\t{x}\n")
for t in sorted(handles):
    pure=sorted(n for (tt,n),x in final.items() if tt==t and x=='local')
    c=types[t]
    print(f"{t}\t{c['wire']}\t{c['lazy']}\t{c['local']}\t{c['NOIMPL']}\t{','.join(pure)}")
