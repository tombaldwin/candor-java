"""method_code_sizes.py <Foo.class> [limit] — print each method's Code-attribute length (largest
first); with a limit, exit 1 if any method meets/exceeds it. Used by test/smoke.sh to gate the
Classifier.classify() bucket split: HotSpot's DontCompileHugeMethods threshold is 8000 bytes of
bytecode — a method at/over it runs INTERPRETED forever, which is how the old single-cascade
classify() (~27KB) made the hottest path of every scan ~20%% slower. javap -c can't be used for
this: its printed offsets are unreliable for sizing (lookupswitch hash labels dwarf real offsets)."""
import struct, sys
data = open(sys.argv[1], 'rb').read()
def u2(o): return struct.unpack_from('>H', data, o)[0]
def u4(o): return struct.unpack_from('>I', data, o)[0]
o = 8
cp_count = u2(o); o += 2
consts = {}
i = 1
while i < cp_count:
    tag = data[o]; o += 1
    if tag == 1:
        ln = u2(o); consts[i] = data[o+2:o+2+ln].decode('utf-8', 'replace'); o += 2 + ln
    elif tag in (7, 8, 16, 19, 20): o += 2
    elif tag == 15: o += 3
    elif tag in (3, 4, 9, 10, 11, 12, 17, 18): o += 4
    elif tag in (5, 6): o += 8; i += 1
    i += 1
o += 6  # access, this, super
o += 2 + 2 * u2(o)  # interfaces
fc = u2(o); o += 2
for _ in range(fc):
    o += 6
    ac = u2(o); o += 2
    for _ in range(ac):
        o += 2; o += 4 + u4(o)
mc = u2(o); o += 2
rows = []
for _ in range(mc):
    name = consts[u2(o+2)]; o += 6
    ac = u2(o); o += 2
    for _ in range(ac):
        an = consts[u2(o)]; o += 2
        alen = u4(o); o += 4
        if an == 'Code':
            rows.append((u4(o+4), name))
        o += alen
limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
bad = 0
for sz, name in sorted(rows, reverse=True):
    flag = ""
    if limit is not None and sz >= limit:
        flag = f"  OVER LIMIT {limit}"
        bad += 1
    print(sz, name, flag)
sys.exit(1 if bad else 0)
