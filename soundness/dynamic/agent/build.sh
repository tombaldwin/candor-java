#!/usr/bin/env bash
# Build the candor leaf-instrumenting agent jar (pure javac + jar; NOT wired into candor's gradle).
set -euo pipefail
cd "$(dirname "$0")"

LIB="lib/asm-9.8.jar:lib/asm-tree-9.8.jar:lib/asm-commons-9.8.jar"
OUT=build
rm -rf "$OUT"
mkdir -p "$OUT/classes"

echo "== compiling agent =="
javac -cp "$LIB" -d "$OUT/classes" EffectAgent.java EffectRecorder.java

echo "== unpacking ASM into agent jar (so ASM resolves from the system classloader at premain) =="
( cd "$OUT/classes" && for j in ../../lib/*.jar; do jar xf "$j"; done; rm -rf META-INF module-info.class )

echo "== building candor-agent.jar =="
jar cfm "$OUT/candor-agent.jar" manifest.txt -C "$OUT/classes" .

echo "== done: $OUT/candor-agent.jar =="
jar tf "$OUT/candor-agent.jar" | grep -E '^(EffectAgent|EffectRecorder)\.class$'
