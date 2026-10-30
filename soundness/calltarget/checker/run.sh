#!/usr/bin/env bash
# The independent checker (call-target round 2). Shares no engine code.
#   bash soundness/calltarget/checker/run.sh build                      # compile against the pinned ASM jars
#   bash soundness/calltarget/checker/run.sh added <rows> <added> <cp> [--seed N]
#   bash soundness/calltarget/checker/run.sh edges <edges.tsv> <cp>
#   python3 soundness/calltarget/checker/poscal.py <mx> <pre> <post> <out> <this-dir>   # positive calibration
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
JH=${CT_JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}
ASM=${CT_ASM_DIR:-$here/../../jdk_index/images}
if [ "$1" = build ]; then
  mkdir -p "$here/lib" "$here/cls"; cp "$ASM"/asm-9.8.jar "$ASM"/asm-tree-9.8.jar "$ASM"/asm-analysis-9.8.jar "$here/lib/"
  "$JH/bin/javac" -nowarn -cp "$here/lib/*" -d "$here/cls" "$here/CheckAdded.java"; exit 0
fi
cmd=$1; shift
if [ "$cmd" = edges ]; then exec "$JH/bin/java" -Xmx3g -cp "$here/cls:$here/lib/*" CheckAdded --edges "$@" < /dev/null; fi
exec "$JH/bin/java" -Xmx3g -cp "$here/cls:$here/lib/*" CheckAdded "$@" < /dev/null
