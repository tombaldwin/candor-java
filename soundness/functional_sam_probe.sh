#!/usr/bin/env bash
# Functional-interface SAM dispatch probe. A JDK functional interface (Runnable/Callable/
# java.util.function.*) invoked on an UNPINNED receiver whose ONLY implementors are lambdas/method-refs
# (empty CHA) can't resolve a body from the call site — the lambda may perform any effect, so the
# invoking method must read Unknown, NEVER silently pure. The chain fuzzer is BLIND here: the lambda's
# body is also captured at its FIELD-INIT/creation site (the constructor), so a chain check sees the
# effect via that path and never notices the INVOKER is pure. This probe asserts the invoker itself
# carries Unknown. Teethed: FAILS on a build that lets the lambda-only functional dispatch go pure.
# Also guards against a flood: a non-functional stdlib dispatch (List.size) must stay pure (no Unknown).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAR="$(ls "$ROOT"/build/libs/candor-java-*-all.jar 2>/dev/null | sort | tail -1)"
[ -n "${JAR:-}" ] || { echo "functional-sam-probe: no built jar (run gradle shadowJar first)"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/FS.java" <<'EOF'
import java.io.*;
import java.util.*;
import java.util.function.*;
public class FS {
  static void io() { try { new FileInputStream("/x").read(); } catch (Exception e) {} }
  // FIELD-stored lambda/method-ref invoked in a SEPARATE method → unpinned Runnable.run, empty CHA.
  static class Field { Runnable cb = FS::io; void fire() { cb.run(); } }
  // PARAMETER receiver → same.
  static void dispatch(Runnable h) { h.run(); }
  // Supplier SAM via a field.
  static class Sup { Supplier<Integer> s = () -> { io(); return 1; }; int get() { return s.get(); } }
  // CONTROL: a non-functional stdlib dispatch must NOT be smeared with Unknown (no flood).
  static int size(List<String> l) { return l.size(); }
  public static void main(String[] a) { new Field().fire(); dispatch(() -> {}); new Sup().get(); size(List.of()); }
}
EOF
javac -d "$TMP/out" "$TMP/FS.java" 2>/dev/null || { echo "functional-sam-probe: GENERATOR BUG — fixture does not compile"; exit 1; }
java -jar "$JAR" "$TMP/out" --json "$TMP/r.json" >/dev/null 2>&1 || { echo "functional-sam-probe: scan FAILED on the fixture"; exit 1; }
python3 - "$TMP/r.json" <<'PY'
import json, sys
fns = {f["fn"]: set(f.get("inferred", [])) for f in json.load(open(sys.argv[1]))["functions"]}
# the invoker of an unpinned lambda-only functional SAM must carry Unknown (or the real effect) — never pure
must_unknown = ["FS$Field.fire", "FS.dispatch", "FS$Sup.get"]
bad = []
for n in must_unknown:
    got = fns.get(n, set())
    if "Unknown" not in got and not got:
        bad.append(f"{n} read PURE — lambda-only functional-interface dispatch went silent (must be Unknown)")
# the non-functional stdlib control must NOT have gained a spurious Unknown (no flood)
if "Unknown" in fns.get("FS.size", set()):
    bad.append("FS.size gained Unknown — the functional-SAM rule flooded a plain stdlib dispatch")
if bad:
    print("functional-sam-probe: FAIL")
    for b in bad: print("  " + b)
    sys.exit(1)
print("functional-sam-probe: OK — lambda-only functional-interface dispatch reads Unknown; stdlib dispatch unflooded")
PY
