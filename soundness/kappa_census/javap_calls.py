#!/usr/bin/env python3
"""javap -c WITH METHOD CONTEXT (never a filtered grep) — enumerate each method's call targets.

Usage: javap_calls.py <jar> <class-path-regex> [--json]

Prints one line per member:  <class>#<javap member line>\t<TAB/pipe-joined call targets>

The parse is member-scoped: a target is attributed to the member whose `Code:` block it appears in.
EVERY line javap prints at indent 2 ending in `;` is a member boundary -- methods, constructors, plain
FIELD declarations, and `static {};`.  Matching only method-SHAPED lines was a real defect here: the
class initializer did not reset the current member, so FFmpeg 0.3/0.4/0.5's `static {}` (which reads
`System.getenv("FFMPEG")`) was attributed to the `getPath()` accessor printed just above it, and three
versions were falsely flagged.  javap shows `getPath()` as `aload_0; getfield path; areturn`.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile

JAR, PAT = sys.argv[1], sys.argv[2]
AS_JSON = "--json" in sys.argv

zf = zipfile.ZipFile(JAR)
names = [n for n in zf.namelist() if n.endswith(".class") and re.match(PAT, n)]
if not names:
    print(f"javap_calls: NO CLASSES matched {PAT} in {os.path.basename(JAR)}", file=sys.stderr)
    sys.exit(3)

tmp = tempfile.mkdtemp(prefix="javapcalls-")
paths = []
for n in names:
    zf.extract(n, tmp)
    paths.append(os.path.join(tmp, n))

MSIG = re.compile(r"^  (\S.*);$")
CALL = re.compile(r"^\s+\d+: (invoke\w+|new|getstatic|putstatic|getfield|putfield)\s+#\d+\s+// (.*)$")
# javap's class/interface/enum header, at indent 0, ending in `{`.
CLS = re.compile(r"^[\w$ .]*\b(?:class|interface|enum|record)\s+([\w$.]+)")

out = {}
BATCH = 200
for i in range(0, len(paths), BATCH):
    p = subprocess.run(["javap", "-p", "-c"] + paths[i:i + BATCH], capture_output=True, text=True)
    if p.returncode != 0 and not p.stdout:
        print(f"javap failed: {p.stderr[:300]}", file=sys.stderr)
        continue
    cls, cur = "?", None
    for line in p.stdout.splitlines():
        if line and not line.startswith(" ") and line.rstrip().endswith("{"):
            m = CLS.match(line)
            if m:
                cls, cur = m.group(1), None
                continue
        m = MSIG.match(line)
        if m:
            cur = f"{cls}#{m.group(1)};"
            out.setdefault(cur, [])
            continue
        c = CALL.match(line)
        if c and cur:
            out[cur].append(c.group(2).strip())

if AS_JSON:
    print(json.dumps(out, indent=1))
else:
    for k in sorted(out):
        print(k + "\t" + " | ".join(sorted(set(out[k]))))
