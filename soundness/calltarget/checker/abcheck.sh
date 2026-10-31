#!/bin/bash
# abcheck.sh S|C <reports-root> <pre-arm> <post-arm> <out> : over every corpus entry, (1) ADDED concrete charges -> CheckAdded
# (with --seed 3 per entry that has added rows), (2) REMOVED edges behind removed effects -> CheckAdded --edges (+3 kept seeds).
# Report layout: S = <root>/rep/<arm>/<n>.json ; C = <root>/repC/<arm>/<n>/{consumer,lib}.json
here=$(cd "$(dirname "$0")" && pwd)
M=$1; R=$2; PRE=$3; POST=$4; OUT=$5; mkdir -p $OUT; : > $OUT/added.out; : > $OUT/edges.out
if [ $M = S ]; then L=/Users/tom/candor-handoff/javaab-a/entries.txt; else L=/Users/tom/candor-handoff/javaab-a/chained-full/entries-built.txt; fi
while read -r e; do n=$(basename $e .jar)
  if [ $M = S ]; then a=$R/rep/$PRE/$n.json; b=$R/rep/$POST/$n.json; extra=""; cp=$e
  else a=$R/repC/$PRE/$n/consumer.json; b=$R/repC/$POST/$n/consumer.json; extra=$R/repC/$POST/$n/lib.json; cp=/Users/tom/candor-handoff/javaab-a/chained-full/c/$n/cls:$e; fi
  [ -s $a ] && [ -s $b ] || continue
  python3 -I $here/mkrows.py $OUT/$n $a $b $extra > /dev/null
  if [ -s $OUT/$n/added.tsv ]; then bash $here/run.sh added $OUT/$n/rows.tsv $OUT/$n/added.tsv "$cp" --seed 3 > $OUT/$n/added.txt 2>&1; sed "s|^|$n\t|" $OUT/$n/added.txt >> $OUT/added.out; fi
  [ -n "${ABCHECK_NO_EDGES:-}" ] && continue
  python3 -I $here/edgeset.py $OUT/$n/edges.tsv $a $b --seeds 3
  if grep -q real $OUT/$n/edges.tsv; then bash $here/run.sh edges $OUT/$n/edges.tsv "$cp" > $OUT/$n/edges.txt 2>&1; sed "s|^|$n\t|" $OUT/$n/edges.txt >> $OUT/edges.out; fi
done < $L
python3 - $OUT <<'PY'
import sys,collections,os
for f in ('added.out','edges.out'):
    c=collections.Counter()
    for l in open(os.path.join(sys.argv[1],f)):
        p=l.rstrip('\n').split('\t',1)
        if len(p)>1 and p[1].startswith('STATS'):
            for kv in p[1][7:-1].split(', '):
                if '=' in kv: k,v=kv.rsplit('=',1); c[k]+=int(v)
    print(f, dict(sorted(c.items())))
PY
