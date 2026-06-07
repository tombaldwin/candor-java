#!/usr/bin/env bash
# smoke.sh — behavioural tests for candor-java. Builds the app once (installDist) then drives the
# launcher over small fixtures, asserting real output. No JUnit harness: the tool is a CLI over
# bytecode + JSON, so end-to-end assertions are the honest test. Mirrors the Rust impl's
# tests/integration.sh. Run: `bash test/smoke.sh` (needs JDK 21 + Gradle).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "building candor-java (installDist)…"
GRADLE="./gradlew"; [ -x "$GRADLE" ] || GRADLE="gradle"   # prefer the wrapper (CI has no system gradle)
"$GRADLE" -q installDist >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }
CJ="$ROOT/build/install/candor-java/bin/candor-java"
[ -x "$CJ" ] || { echo "FAIL: no launcher at $CJ"; exit 1; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

pass=0; fail=0
want()   { if printf '%s' "$2" | grep -qF -- "$3"; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1 — missing: $3"; echo "        in: $2"; fail=$((fail+1)); fi; }
absent() { if printf '%s' "$2" | grep -qF -- "$3"; then echo "  FAIL $1 — unexpected: $3"; fail=$((fail+1)); else echo "  ok   $1"; pass=$((pass+1)); fi; }

# ── fixtures ──────────────────────────────────────────────────────────────────────────────────────
mkdir -p "$W/src"
cat > "$W/src/Fx.java" <<'J'
import java.nio.file.*;
public class Fx {
  static void reads()  { try { Files.readAllBytes(Path.of("/tmp/x")); } catch (Exception e) {} }
  static void writes() { try { Files.writeString(Path.of("/tmp/x"), "y"); } catch (Exception e) {} }
  static void both()   { reads(); writes(); }
  static void spawn()  { try { new ProcessBuilder("x").start(); } catch (Exception e) {} }
  static void dyn()    { try { Class.forName("X"); } catch (Exception e) {} }
  public static void main(String[] a) { both(); spawn(); }
}
J
javac -d "$W/cls" "$W/src/Fx.java"

echo "== audit + v0.2 report =="
"$CJ" "$W/cls" --json "$W/r.json" >/dev/null 2>&1
rep="$(cat "$W/r.json")"
want "report is the v0.2 envelope"            "$rep" '"candor"'
want "envelope carries a version"             "$rep" '"version"'
want "envelope carries a toolchain"           "$rep" '"toolchain"'
want "functions array present"               "$rep" '"functions"'
want "reads performs Fs"                      "$rep" '"Fx.reads"'
want "dyn is Unknown (reflection, trust §4)"  "$rep" '"Unknown"'

echo "== entry schema: hash, calls, fs =="
want "hash is the descriptor-bearing ref"     "$rep" 'Fx.reads()V'
want "calls effect graph emitted"             "$rep" '"calls"'
want "fs read detail"                         "$rep" '"read"'
want "fs write detail"                        "$rep" '"write"'

echo "== queries =="
want "show: Fs(read,write) on both"           "$("$CJ" show "$W/r.json" both)"     'Fs(read,write)'
want "where Fs: direct source reads"          "$("$CJ" where "$W/r.json" Fs)"      'Fx.reads'
want "callers: who calls reads (from calls)"  "$("$CJ" callers "$W/r.json" reads)" 'Fx.both'
want "map: class overview"                     "$("$CJ" map "$W/r.json")"           'candor map'

echo "== baseline guard (AS-EFF-005) =="
# a baseline where reads had no Fs → guard must flag the gain
python3 - "$W/r.json" "$W/base.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for e in d['functions']:
    if e['fn']=='Fx.reads': e['inferred']=[]
json.dump(d,open(sys.argv[2],'w'))
PY
g="$(CANDOR_BASELINE="$W/base.json" "$CJ" "$W/cls" 2>&1)"
want "AS-EFF-005 flags reads gaining Fs"      "$g" '[AS-EFF-005] `Fx.reads`'

echo "== cross-jar inheritance (CANDOR_DEPS) =="
mkdir -p "$W/app"
echo 'public class App { public void run() { Fx.reads(); } }' > "$W/app/App.java"
javac -cp "$W/cls" -d "$W/acls" "$W/app/App.java"
bare="$("$CJ" "$W/acls" --json "$W/a0.json" 2>/dev/null; cat "$W/a0.json")"
absent "consumer is pure without CANDOR_DEPS" "$bare" '"App.run"'
dep="$(CANDOR_DEPS="$W/r.json" "$CJ" "$W/acls" --json "$W/a1.json" 2>/dev/null; cat "$W/a1.json")"
want "consumer inherits Fs across the jar"    "$dep" '"App.run"'
# version-trust: a dep report from a different engine → inherited effect downgraded to Unknown
python3 - "$W/r.json" "$W/stale.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['candor']['version']='deadbee'
json.dump(d,open(sys.argv[2],'w'))
PY
stale="$(CANDOR_DEPS="$W/stale.json" "$CJ" "$W/acls" --json "$W/a2.json" 2>/dev/null; cat "$W/a2.json")"
want "stale-engine dep -> inherited Unknown"  "$(python3 -c "import json;print(next(e['inferred'] for e in json.load(open('$W/a2.json'))['functions'] if e['fn']=='App.run'))")" 'Unknown'

echo
echo "smoke: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
