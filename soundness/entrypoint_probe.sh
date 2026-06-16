#!/usr/bin/env bash
# Runtime-invoked-callback ENTRY-POINT probe. Serialization callbacks (readObject/writeObject/readExternal/
# writeExternal/readResolve/writeReplace/readObjectNoData) and finalize() are invoked by the JVM runtime
# with NO in-project call site, so their effects (a stream opened on (de)serialization, a resource freed on
# finalize) are orphaned from every reachability root — a "what does this program perform from main" walk
# silently misses them unless they are ROOTED as entry points. This asserts they are entryPoint:true on
# Serializable/Externalizable classes, and that a same-named method on an UNRELATED class is NOT fabricated
# as an entry point. Teethed: FAILS on a build that doesn't root them (the silent-pure-from-root hole).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAR="$(ls "$ROOT"/build/libs/candor-java-*-all.jar 2>/dev/null | sort | tail -1)"
[ -n "${JAR:-}" ] || { echo "entrypoint-probe: no built jar (run gradle shadowJar first)"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/EP.java" <<'EOF'
import java.io.*;
public class EP {
  static class S implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException { in.defaultReadObject(); new FileOutputStream("/tmp/candor_ep").close(); }
    private void writeObject(ObjectOutputStream out) throws IOException { out.defaultWriteObject(); System.getenv("X"); }
    Object readResolve() { System.currentTimeMillis(); return this; }
    @Override protected void finalize() { new java.util.Random().nextInt(); }
  }
  static class X implements Externalizable {
    public void readExternal(ObjectInput in) { System.getenv("Y"); }
    public void writeExternal(ObjectOutput out) { System.currentTimeMillis(); }
  }
  // NON-serializable decoy: same method names + signatures must NOT be rooted (no fabrication).
  static class D {
    private void readObject(ObjectInputStream in) { try { new FileOutputStream("/tmp/candor_ep_d").close(); } catch (Exception e) {} }
    Object readResolve() { System.getenv("Z"); return null; }
  }
  public static void main(String[] a) { new S(); new X(); new D(); }
}
EOF
javac -d "$TMP/out" "$TMP/EP.java" 2>/dev/null || { echo "entrypoint-probe: GENERATOR BUG — fixture does not compile"; exit 1; }
java -jar "$JAR" "$TMP/out" --json "$TMP/r.json" >/dev/null 2>&1 || { echo "entrypoint-probe: scan FAILED on the fixture"; exit 1; }
python3 - "$TMP/r.json" <<'PY'
import json, sys
fns = {f["fn"]: f for f in json.load(open(sys.argv[1]))["functions"]}
ep  = lambda n: fns.get(n, {}).get("entryPoint", False)
must_root = ["EP$S.readObject", "EP$S.writeObject", "EP$S.readResolve", "EP$S.finalize",
             "EP$X.readExternal", "EP$X.writeExternal"]
must_not  = ["EP$D.readObject", "EP$D.readResolve"]
bad = []
for n in must_root:
    if n not in fns:   bad.append(f"{n} MISSING from report (its effect went silent)")
    elif not ep(n):    bad.append(f"{n} entryPoint=false — orphaned from roots (should be a runtime root)")
for n in must_not:
    if ep(n):          bad.append(f"{n} entryPoint=true — FABRICATED root on a non-serializable class")
if bad:
    print("entrypoint-probe: FAIL")
    for b in bad: print("  " + b)
    sys.exit(1)
print("entrypoint-probe: OK — serialization/finalize callbacks rooted; non-serializable decoy not fabricated")
PY
