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
wantnot(){ if printf '%s' "$2" | grep -qF -- "$3"; then echo "  FAIL $1 — unexpected: $3"; echo "        in: $2"; fail=$((fail+1)); else echo "  ok   $1"; pass=$((pass+1)); fi; }
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
  static void netcmd()   { try { new ProcessBuilder("curl", "https://x").start(); } catch (Exception e) {} }
  static void auditcmd() { try { new ProcessBuilder("candor-scan", ".").start(); } catch (Exception e) {} }
  static void dbcmd()    { try { Runtime.getRuntime().exec("/usr/local/bin/psql -c x"); } catch (Exception e) {} }
  // FABRICATION TRAPS (argv[0] gate): the program is a runtime VARIABLE; the literal "curl"/"psql" is a
  // trailing ARGUMENT, not the program — refining off it would fabricate Net/Db (§1 under-report).
  static void varhead(String t) { try { new ProcessBuilder(t, "curl").start(); } catch (Exception e) {} }
  static void arrhead(String t) { try { Runtime.getRuntime().exec(new String[]{t, "psql"}); } catch (Exception e) {} }
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
# DERIVED from the engine's own constant, not hardcoded. The literal form broke on the 0.27 bump — a
# version-coupled assertion whose fix each release is to re-edit a literal, which is the class that has now
# cost an edit in every repo in the family.
SPEC_DECLARED="$(grep -oE 'SPEC_VERSION = "[0-9.]+"' "$ROOT/src/main/java/io/poly/candor/Candor.java" | grep -oE '[0-9]+\.[0-9]+')"
want "envelope declares the spec contract $SPEC_DECLARED" "$rep" "\"spec\": \"$SPEC_DECLARED\""
want "functions array present"               "$rep" '"functions"'
want "reads performs Fs"                      "$rep" '"Fx.reads"'
want "dyn is Unknown (reflection, trust §4)"  "$rep" '"Unknown"'

echo "== atomic write (temp + move, no half-written report for a concurrent reader) =="
# the report + callgraph land whole; the temp file is moved into place, never left behind.
tmpleft="$(find "$W" -name '*.tmp*' 2>/dev/null)"
absent "atomic write leaves no .tmp file behind"  "$tmpleft" "$W"
want   "report parses as whole JSON (python round-trips it)" "$(python3 -c 'import json,sys; json.load(open(sys.argv[1])); print("WHOLE")' "$W/r.json" 2>/dev/null)" 'WHOLE'
want   "callgraph parses as whole JSON"           "$(python3 -c 'import json,sys; json.load(open(sys.argv[1])); print("WHOLE")' "$W/r.callgraph.json" 2>/dev/null)" 'WHOLE'

echo "== Exec-cliff refinement by known sub-command head (spec §4 ⟨0.5⟩) =="
want    "curl head refines the cliff: + Net"        "$("$CJ" show "$W/r.json" netcmd)"   'Net'
want    "curl head keeps Exec (never dropped)"      "$("$CJ" show "$W/r.json" netcmd)"   'Exec'
want    "psql head (Runtime.exec line) refines: + Db" "$("$CJ" show "$W/r.json" dbcmd)"  'Db'
want    "candor head is Fs/Env (spec §7.12 supplied)" "$("$CJ" show "$W/r.json" auditcmd)" 'Env'
wantnot "an unknown head 'x' stays the bare Exec cliff (no fabricated Net)" "$("$CJ" show "$W/r.json" spawn)" 'Net'
wantnot "variable program head + trailing 'curl' literal does NOT fabricate Net (argv[0] gate)" "$("$CJ" show "$W/r.json" varhead)" 'Net'
wantnot "variable array head + element-1 'psql' literal does NOT fabricate Db (argv[0] gate)"   "$("$CJ" show "$W/r.json" arrhead)" 'Db'
want    "both traps keep the bare Exec cliff"        "$("$CJ" show "$W/r.json" varhead)" 'Exec'
# The verdict-flipping case: a trailing-argument literal must not populate `cmds` either — else
# `allow Exec curl` would spuriously certify a DYNAMIC head (candor-scan correctly fails it).
want    "a literal HEAD captures cmds"               "$("$CJ" show "$W/r.json" netcmd --json)"  '"curl"'
absent  "a dynamic head with trailing 'curl' captures NO cmds (no verdict flip)" "$("$CJ" show "$W/r.json" varhead --json)" '"cmds"'
printf 'allow Exec curl\n' > "$W/excurl.pol"
ldv="$(CANDOR_POLICY="$W/excurl.pol" "$CJ" "$W/cls" 2>&1)"
want "allow Exec curl does NOT certify the dynamic-head spawn (uncertified, AS-EFF-008)" "$ldv" '`Fx.varhead` performs Exec with no visible literal'

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
want "queries emit --json (agent/MCP form)"    "$("$CJ" show "$W/r.json" both --json)" '"inferred"'
want "where --json: structured result"         "$("$CJ" where "$W/r.json" Fs --json)"  '"directly"'

echo "== tour: the top-N surprising reaches (SURFACE-BEST-FIND-DESIGN P2) =="
# `both` inherits Fs 1 hop down via `reads` — a valid inherited reach for the tour to surface.
tj="$("$CJ" tour --report "$W/r.json" 2>&1)"
want   "tour lists the surprising reaches"       "$tj" 'most surprising reach'
want   "tour names a ready-to-run path command"  "$tj" 'candor path'
# --json emits reach objects with ALPHABETICAL keys (effect,fn,hops,loc,score,source) — Rust/Swift parity.
tjs="$("$CJ" tour --report "$W/r.json" --json 2>&1)"
want   "tour --json emits a reaches array"        "$tjs" '"reaches"'
want   "tour --json keys are alphabetical (effect before fn)" "$tjs" '"effect":'
# GRAMMAR: N must be a positive integer ≥ 1. `tour 0` must NEVER print the false all-clear "nothing hidden"
# over an effectful crate (the §4 cardinal sin) — it's a usage error, exit 2.
t0="$("$CJ" tour 0 --report "$W/r.json" 2>&1)"; t0c=$?
want   "tour 0 → usage error, not a false all-clear"  "$t0" 'positive integer'
absent "tour 0 does NOT print the 'nothing hidden' all-clear" "$t0" 'nothing hidden'
if [ "$t0c" -eq 2 ]; then echo "  ok   tour 0 exits 2"; pass=$((pass+1));
else echo "  FAIL tour 0 — got exit $t0c"; fail=$((fail+1)); fi
tneg="$("$CJ" tour -1 --report "$W/r.json" 2>&1)"; [ "$?" -eq 2 ] && { echo "  ok   tour -1 exits 2"; pass=$((pass+1)); } || { echo "  FAIL tour -1 did not exit 2"; fail=$((fail+1)); }
tnan="$("$CJ" tour abc --report "$W/r.json" 2>&1)"; [ "$?" -eq 2 ] && { echo "  ok   tour <non-int> exits 2"; pass=$((pass+1)); } || { echo "  FAIL tour abc did not exit 2"; fail=$((fail+1)); }

echo "== corrupt call-graph sidecar is DISCLOSED, never silently dropped (§4) =="
# A sidecar that EXISTS but fails to parse (corrupt/truncated) → the fallback graph is strictly smaller,
# so a silent drop would let a verdict under-report. Disclose on stderr before falling back. (A genuinely
# MISSING sidecar stays silent — falling back to the report's inline `calls` is correct.)
cp "$W/r.json" "$W/corrupt.json"; cp "$W/r.callgraph.json" "$W/corrupt.callgraph.json"
printf 'this is not json {' > "$W/corrupt.callgraph.json"
cdis="$("$CJ" tour --report "$W/corrupt.json" 2>&1 1>/dev/null)"; cdc=$?
want   "corrupt sidecar prints a disclosure line"     "$cdis" 'call graph may be incomplete'
want   "corrupt sidecar names the falling-back path"  "$cdis" 'falling back'
if [ "$cdc" -eq 0 ]; then echo "  ok   tour still succeeds (exit 0) on the inline fallback"; pass=$((pass+1));
else echo "  FAIL tour on corrupt sidecar — got exit $cdc"; fail=$((fail+1)); fi
# A MISSING sidecar (no file) stays SILENT — falling back to inline `calls` is correct, no warning.
cp "$W/r.json" "$W/nosidecar.json"  # deliberately no .callgraph.json beside it
nodis="$("$CJ" tour --report "$W/nosidecar.json" 2>&1 1>/dev/null)"
absent "a MISSING sidecar prints NO disclosure (silent fallback is correct)" "$nodis" 'call graph may be incomplete'

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

# INTERFACE/SUPERTYPE-typed dep call must inherit too: `Iface x = new DepImpl(); x.m()` compiles to
# INVOKEINTERFACE on the iface, but the dep report keys the body by its CONCRETE owner. Without the
# monomorphic-receiver retry the caller read SILENTLY PURE though the dep writes a file.
mkdir -p "$W/depi/lib" "$W/iapp/iapp"
cat > "$W/depi/lib/Store.java"     <<'J'
package lib; public interface Store { void save(String s); }
J
cat > "$W/depi/lib/FileStore.java" <<'J'
package lib; import java.nio.file.*;
public class FileStore implements Store { public void save(String s){ try{ Files.writeString(Path.of("/tmp/x"),s);}catch(Exception e){} } }
J
javac -d "$W/depicls" "$W/depi/lib/Store.java" "$W/depi/lib/FileStore.java"
"$CJ" "$W/depicls" --json "$W/depi.json" >/dev/null 2>&1
cat > "$W/iapp/iapp/IApp.java" <<'J'
package iapp; import lib.*;
public class IApp {
  void viaConcrete(){ new FileStore().save("x"); }            // INVOKEVIRTUAL on FileStore
  void viaIface(){ Store s = new FileStore(); s.save("x"); }  // INVOKEINTERFACE on Store
}
J
javac -cp "$W/depicls" -d "$W/iappcls" "$W/iapp/iapp/IApp.java"
idep="$(CANDOR_DEPS="$W/depi.json" "$CJ" "$W/iappcls" --json "$W/ia.json" 2>/dev/null; cat "$W/ia.json")"
want "concrete-typed dep call inherits Fs"                "$("$CJ" show "$W/ia.json" IApp.viaConcrete 2>/dev/null)" 'Fs'
want "INTERFACE-typed dep call inherits Fs (mono-recv retry)" "$("$CJ" show "$W/ia.json" IApp.viaIface 2>/dev/null)" 'Fs'

echo "== lambdas / method refs =="
cat > "$W/src/Lam.java" <<'J'
import java.nio.file.*;
public class Lam {
  static void run() { Runnable r = () -> { try { Files.writeString(Path.of("/tmp/x"),"y"); } catch (Exception e) {} }; r.run(); }
}
J
javac -d "$W/lcls" "$W/src/Lam.java"
"$CJ" "$W/lcls" --json "$W/l.json" >/dev/null 2>&1
want "lambda body effect reaches the enclosing fn" "$(cat "$W/l.json")"            '"Lam.run"'
want "enclosing inherits the lambda's Fs(write)"   "$("$CJ" show "$W/l.json" Lam.run)" 'Fs(write)'

echo "== constructors =="
cat > "$W/src/Ct.java" <<'J'
import java.nio.file.*;
public class Ct {
  static class L { L() { try { Files.readAllBytes(Path.of("/tmp/x")); } catch (Exception e) {} } }
  static void build() { new L(); }
  static class P { P() {} }
  static void pure() { new P(); }
}
J
javac -d "$W/ctcls" "$W/src/Ct.java"
"$CJ" "$W/ctcls" --json "$W/ct.json" >/dev/null 2>&1
want   "effectful constructor reaches its new X() site" "$("$CJ" show "$W/ct.json" Ct.build)" 'Fs'
absent "a pure constructor stays pure"                  "$(cat "$W/ct.json")"                 '"Ct.pure"'

# ── System.getProperty is JVM config, NOT the OS environment (the scala-library validation fix) ──
echo "== env vs system properties =="
cat > "$W/src/EnvProp.java" <<'J'
public class EnvProp {
  static String prop() { return System.getProperty("os.name"); }       // JVM property — NOT Env
  static String env()  { return System.getenv("HOME"); }               // OS env var — Env
}
J
javac -d "$W/epcls" "$W/src/EnvProp.java" 2>/dev/null
EP=$("$CJ" "$W/epcls" --json "$W/ep.json" >/dev/null 2>&1; cat "$W/ep.json")
absent "System.getProperty is NOT Env (JVM config, not OS environment)" "$EP" '"EnvProp.prop"'
want   "System.getenv IS Env"                                           "$("$CJ" show "$W/ep.json" EnvProp.env 2>/dev/null)" 'Env'

# ── bounded CHA (SPEC §4): a dispatch over a project abstraction with >12 impls reads Unknown ─────
echo "== bounded CHA fan-out =="
mkdir -p "$W/cha"
{ echo "public class ChaTest {"
  echo "  interface Op { void run(); }"
  for i in $(seq 1 14); do echo "  static class Op$i implements Op { public void run() {} } "; done
  echo "  static void dispatch(Op o) { o.run(); }"   # 14 impls > 12 -> Unknown, not 14 edges
  echo "}"; } > "$W/cha/ChaTest.java"
javac -d "$W/chacls" "$W/cha/ChaTest.java" 2>/dev/null
CHA=$("$CJ" "$W/chacls" 2>/dev/null | grep 'ChaTest.dispatch')
want "a >12-impl dispatch reads Unknown (bounded CHA), not all-edges" "$CHA" 'Unknown'
# and a NARROW dispatch (≤12) still resolves precisely
mkdir -p "$W/chan"
{ echo "public class ChaNarrow {"
  echo "  interface Op { void run(); }"
  echo "  static class A implements Op { public void run() { try { java.nio.file.Files.readString(java.nio.file.Path.of(\"/x\")); } catch (Exception e) {} } }"
  echo "  static class B implements Op { public void run() {} }"
  echo "  static void dispatch(Op o) { o.run(); }"
  echo "}"; } > "$W/chan/ChaNarrow.java"
javac -d "$W/chancls" "$W/chan/ChaNarrow.java" 2>/dev/null
want "a ≤12-impl dispatch still resolves to its impls (A's Fs)" "$("$CJ" "$W/chancls" 2>/dev/null | grep 'ChaNarrow.dispatch')" 'Fs'

echo "== static initializers (<clinit>) =="
cat > "$W/src/Ci.java" <<'J'
import java.nio.file.*;
public class Ci {
  static class Cfg {
    static final byte[] DATA;
    static { byte[] d = new byte[0]; try { d = Files.readAllBytes(Path.of("/etc/cfg")); } catch (Exception e) {} DATA = d; }
    static int size() { return DATA.length; }
  }
  static void viaStaticCall()  { int n = Cfg.size(); }   // INVOKESTATIC triggers <clinit>
  static void viaStaticField() { byte[] b = Cfg.DATA; }  // GETSTATIC triggers <clinit>
  static class Pure { static { int x = 1; } static int f() { return 2; } }
  static void pure() { int n = Pure.f(); }               // pure <clinit> → caller stays pure
  static class Helper { Helper() { read(); }
    void read() { try { Files.readAllBytes(Path.of("/x")); } catch (Exception e) {} } } // Fs in a METHOD
  static class Deep { static final Helper H = new Helper(); // <clinit> CONSTRUCTS Helper — Fs is TRANSITIVE
    static int g() { return 1; } }
  static void viaDeep() { int n = Deep.g(); }            // triggers Deep.<clinit>; the Fs is transitive
}                                                         // (via the Helper ctor) → soundly attributed to viaDeep
J
javac -d "$W/cics" "$W/src/Ci.java"
"$CJ" "$W/cics" --json "$W/ci.json" >/dev/null 2>&1
ci="$(cat "$W/ci.json")"
# the audit output prints the fn name unescaped (the JSON escapes `<clinit>` as <…)
want   "static initializer's Fs is captured"               "$("$CJ" "$W/cics" 2>/dev/null)" 'Ci$Cfg.<clinit> '
want   "static CALL triggers <clinit> (Fs propagates)"     "$("$CJ" show "$W/ci.json" Ci.viaStaticCall)"  'Fs'
want   "static FIELD access triggers <clinit>"             "$("$CJ" show "$W/ci.json" Ci.viaStaticField)" 'Fs'
absent "a pure static initializer doesn't flood callers"   "$ci" '"Ci.pure"'
# A <clinit> trigger propagates the static initializer's FULL transitive effects (spec §5): touching the
# class runs its <clinit>, which here CONSTRUCTS a Helper whose ctor reaches Fs — so the trigger CAN reach
# Fs (sound "can reach"). The §7.13 fuzzer caught the prior direct-only narrowing dropping exactly this.
want   "transitive <clinit> Fs (via a constructed object) IS attributed to the trigger" "$("$CJ" show "$W/ci.json" Ci.viaDeep)" 'Fs'
want   "the <clinit> itself keeps its own transitive Fs"   "$("$CJ" show "$W/ci.json" 'Ci$Deep.<clinit>')" 'Fs'
want   "a <clinit> unit carries unitKind initializer (spec 0.5 draft)" \
       "$(python3 -c "import json;print([e.get('unitKind','') for e in json.load(open('$W/ci.json'))['functions'] if e['fn'].endswith('.<clinit>')][0])")" 'initializer'

echo "== java.util container dispatch DOES fan out — a custom iterator's effect reaches the loop (sound) =="
cat > "$W/src/Cd.java" <<'J'
import java.util.*;
public class Cd {
  // a custom iterator whose next() performs Fs
  static class FsIter implements Iterator<Integer> {
    public boolean hasNext() { return false; }
    public Integer next() {
      try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/x")); } catch (Exception e) {}
      return 1;
    }
  }
  static class Bag implements Iterable<Integer> { public Iterator<Integer> iterator() { return new FsIter(); } }
  // for-each over a custom Iterable — at runtime reaches FsIter.next -> Fs; must NOT be silently pure.
  // (Iterator.next() dispatch fans out over the project's Iterator impls; the over-approximation that
  // can smear a sibling iterator's effect onto an unrelated loop is sound "can reach", not fabrication.)
  static void forEach(Bag b) { for (Integer x : b) {} }
}
J
javac -d "$W/cd" "$W/src/Cd.java"
"$CJ" "$W/cd" --json "$W/cd.json" >/dev/null 2>&1
want   "for-each over a custom Iterable inherits the iterator's effect (sound — no silent-pure)" "$("$CJ" show "$W/cd.json" Cd.forEach)" 'Fs'
want   "the custom iterator's own next() carries its effect"  "$("$CJ" show "$W/cd.json" 'Cd$FsIter.next')" 'Fs'

echo "== native methods (invisible JNI body → Unknown) =="
cat > "$W/src/Nat.java" <<'J'
public class Nat {
  static native void doNative();
  static void caller() { doNative(); }
  static int purePlain() { return 1; }
}
J
javac -d "$W/ncls" "$W/src/Nat.java"
"$CJ" "$W/ncls" --json "$W/n.json" >/dev/null 2>&1
want   "a native method is Unknown, not silent-pure"  "$("$CJ" show "$W/n.json" Nat.doNative)" 'Unknown'
want   "a caller of native inherits Unknown"          "$("$CJ" show "$W/n.json" Nat.caller)"   'Unknown'
absent "a plain pure method stays pure"               "$(cat "$W/n.json")"                     '"Nat.purePlain"'

echo "== CHA: dispatch resolving to a GRANDPARENT's concrete impl (the AbstractBase pattern) =="
# Interface Svc; Base implements act() concretely; Impl extends Base WITHOUT redeclaring act. A call on
# an Svc-typed receiver must resolve to Base.act (gaining its Net), not a false Unknown — the impl is
# reached by going DOWN to Impl then UP to its grandparent Base. (The byte-buddy MethodList.filter case.)
cat > "$W/src/Gp.java" <<'J'
public class Gp {
  interface Svc { void act(); }
  static abstract class Base implements Svc { public void act() { try { new java.net.Socket("h",1); } catch (Exception e) {} } }
  static class Impl extends Base {}
  static void use(Svc s) { s.act(); }
  public static void main(String[] a) { use(new Impl()); }
}
J
javac -d "$W/gcls" "$W/src/Gp.java" 2>/dev/null
"$CJ" "$W/gcls" --json "$W/g.json" >/dev/null 2>&1
want   "grandparent-inherited dispatch resolves (gains Net)"   "$("$CJ" show "$W/g.json" 'Gp.use')" 'Net'
absent "…and is NOT a false Unknown"                           "$("$CJ" show "$W/g.json" 'Gp.use')" 'Unknown'

# ── monomorphic-receiver narrowing (SOUNDNESS): a dispatch on a PROVABLE single `new T` resolves to the
# one method T invokes, NOT its CHA siblings — so a pure receiver doesn't fabricate an effectful sibling's
# effect. The genuinely-polymorphic receivers (param / field / branch-merged) MUST still keep the CHA. ──
echo "== monomorphic-receiver narrowing (no sibling-effect fabrication) =="
mkdir -p "$W/mono"
cat > "$W/mono/Mono.java" <<'J'
public class Mono {
  static class Base { int compute() { return 41; } }                                   // PURE
  static class Dirty extends Base {                                                     // effectful sibling
    int compute() { try { new java.net.Socket("1.2.3.4", 80); } catch (Exception e) {} return 1; } }
  Base field;
  int callMonoBase()  { Base b = new Base();  return b.compute(); }   // provable new Base  → PURE
  int callMonoDirty() { Base b = new Dirty(); return b.compute(); }   // provable new Dirty → {Net}
  int callParam(Base b) { return b.compute(); }                      // PARAM  receiver → CHA → {Net}
  int callField()       { return field.compute(); }                  // FIELD  receiver → CHA → {Net}
  int callReturn()      { return make().compute(); }                 // RETURN receiver → CHA → {Net}
  Base make() { return new Dirty(); }
  int callMerge(boolean c) {                                         // BRANCH-merged new → CHA → {Net}
    Base b; if (c) b = new Base(); else b = new Dirty(); return b.compute(); }
}
J
javac -d "$W/monocls" "$W/mono/Mono.java" 2>/dev/null
"$CJ" "$W/monocls" --json "$W/mono.json" >/dev/null 2>&1
absent "a provably new-Base receiver is PURE (no fabricated sibling Net)" "$(cat "$W/mono.json")" '"Mono.callMonoBase"'
want   "a provably new-Dirty receiver resolves to Dirty's real Net"       "$("$CJ" show "$W/mono.json" Mono.callMonoDirty)" 'Net'
want   "a PARAM receiver keeps the CHA (Dirty's Net must NOT vanish)"        "$("$CJ" show "$W/mono.json" Mono.callParam)"  'Net'
want   "a FIELD receiver keeps the CHA"                                      "$("$CJ" show "$W/mono.json" Mono.callField)"  'Net'
want   "a RETURN-value receiver keeps the CHA"                               "$("$CJ" show "$W/mono.json" Mono.callReturn)" 'Net'
want   "a BRANCH-merged new (Base|Dirty) keeps the CHA"                      "$("$CJ" show "$W/mono.json" Mono.callMerge)"  'Net'
want   "the effectful sibling's own compute still carries Net"               "$("$CJ" show "$W/mono.json" 'Mono$Dirty.compute')" 'Net'

echo "== NIO channels are classified (SocketChannel→Net, FileChannel→Fs) =="
# NIO networking/file I/O was a silent under-report — every NIO stack (Netty, async/reactive) was pure.
# The concrete channel types ARE the I/O boundary; a plain ByteBuffer must stay pure (no false positive).
cat > "$W/src/Nio.java" <<'J'
import java.nio.channels.*; import java.net.*;
public class Nio {
  static void net()  throws Exception { SocketChannel.open(new InetSocketAddress("h", 1)); }
  static void srv()  throws Exception { ServerSocketChannel.open().bind(new InetSocketAddress(80)); }
  static void file() throws Exception { FileChannel.open(java.nio.file.Path.of("/tmp/x")); }
  static void pure() { java.nio.ByteBuffer.allocate(8).flip(); }
}
J
javac -d "$W/iocls" "$W/src/Nio.java" 2>/dev/null
"$CJ" "$W/iocls" --json "$W/io.json" >/dev/null 2>&1
want   "SocketChannel → Net (was a silent under-report)"  "$("$CJ" show "$W/io.json" 'Nio.net')"  'Net'
want   "ServerSocketChannel → Net"                        "$("$CJ" show "$W/io.json" 'Nio.srv')"  'Net'
want   "FileChannel → Fs"                                 "$("$CJ" show "$W/io.json" 'Nio.file')" 'Fs'
absent "a plain ByteBuffer is NOT classified (no false positive)" "$(cat "$W/io.json")" '"Nio.pure"'

echo "== finalize() is a runtime (GC) entry point — the implicit-Drop analog =="
# A finalize() override is run by the GC's finalizer thread with NO bytecode caller. Its effect must
# not be orphaned out of the reachability roots; mark it an entry point so a from-entry-points walk
# sees it. A PURE finalize must not be given a phantom effect.
cat > "$W/src/Fin.java" <<'J'
public class Fin {
  static class Loud  { protected void finalize() throws Throwable { new java.net.Socket("10.0.0.2", 9); } }
  static class Quiet { protected void finalize() throws Throwable {} }
  public static void main(String[] a) { System.out.println(new Loud()); }
}
J
javac -d "$W/fcls" "$W/src/Fin.java" 2>/dev/null
"$CJ" "$W/fcls" --json "$W/f.json" >/dev/null 2>&1
frep="$(cat "$W/f.json")"
want   "effectful finalize is reported (Net seen in its body)"  "$("$CJ" show "$W/f.json" 'Fin$Loud.finalize')" 'Net'
want   "finalize is flagged a runtime entry point"              "$frep" '"Fin$Loud.finalize"'
want   "  …with entryPoint=true (a GC-invoked root)"            "$(python3 -c "import json;print(next(e['entryPoint'] for e in json.load(open('$W/f.json'))['functions'] if e['fn']=='Fin\$Loud.finalize'))")" 'True'
want   "a pure finalize gets no phantom effect (empty inferred)" "$(python3 -c "import json;print(next(e['inferred'] for e in json.load(open('$W/f.json'))['functions'] if e['fn']=='Fin\$Quiet.finalize'))")" '[]'

echo "== Runnable/Thread/Callable task body is a runtime entry point =="
# run()/call() of a Runnable/Thread/Callable is invoked by an executor or the thread scheduler — the
# launch site is `submit(r)`/`start()`, whose invocation of run() is in non-project JDK code. Same
# orphaned-effect shape as finalize. Must be an entry point; a coincidental run() on a NON-task class
# must NOT be (precision — uflexi has such a method and it stays a normal method).
cat > "$W/src/Tk.java" <<'J'
import java.util.concurrent.*;
public class Tk {
  static class Task implements Runnable { public void run(){ try { new java.net.Socket("10.0.0.2",9); } catch(Exception e){} } }
  static class Job  implements Callable<Integer> { public Integer call() throws Exception { new java.io.FileOutputStream("/tmp/x").close(); return 1; } }
  static class NotATask { public void run(){} }   // run() but not Runnable/Thread → NOT an entry point
  public static void main(String[] a){ Executors.newFixedThreadPool(1).submit(new Task()); }
}
J
javac -d "$W/tcls" "$W/src/Tk.java" 2>/dev/null
"$CJ" "$W/tcls" --json "$W/t.json" >/dev/null 2>&1
ep() { python3 -c "import json;print(next((e.get('entryPoint') for e in json.load(open('$W/t.json'))['functions'] if e['fn']=='$1'), 'absent'))"; }
want   "Runnable.run() task body is an entry point (gains Net)"   "$("$CJ" show "$W/t.json" 'Tk$Task.run')" 'Net'
want   "  …Runnable.run() entryPoint=true"                        "$(ep 'Tk$Task.run')"  'True'
want   "Callable.call() task body is an entry point"              "$(ep 'Tk$Job.call')"  'True'
want   "a run() on a NON-task class is NOT a task entry point"    "$(ep 'Tk$NotATask.run')" 'absent'

echo "== reachable: runtime effect surface from entry points =="
# Union of `inferred` over entry points = what the program performs when the runtime drives it. The Tk
# fixture's roots are Task.run (Net) + Job.call (Fs); NotATask.run is not a root.
rch="$("$CJ" reachable "$W/t.json")"
want   "reachable: surfaces the task's Net"            "$rch" 'Net'
want   "reachable: surfaces the Callable's Fs"         "$rch" 'Fs'
want   "reachable: reports the entry-point union"      "$rch" 'union over'
rjson="$("$CJ" reachable "$W/t.json" --json)"
want   "reachable --json: structured effect surface"   "$rjson" '"entryPoints"'

echo "== overload disambiguation: a pure overload never unions an effectful sibling's effect =="
# candor keys a report node by class.method — descriptor-LESS. Overloaded methods (same name, different
# params) would collapse into ONE node whose effects are the UNION of every overload, so a PURE overload
# inherits an effectful sibling's effect — the cardinal sin (commons-codec: a pure `hmac(byte[])` reported
# as a filesystem read, borrowed from `hmac(File)`). FIX: an OVERLOADED name gets a readable param-type
# suffix per overload; a UNIQUE name keeps the bare class.method (so conformance leaf-name matching and
# every non-overloaded method are unchanged). Here `digest(byte[])` is pure and `digest(File)` is Fs:
# they must be TWO distinct entries with their OWN correct effects, and `solo()` (unique) stays bare.
cat > "$W/src/Ov.java" <<'J'
import java.io.*;
public class Ov {
  // overloaded: one pure (in-memory), one effectful (reads a File) — SAME name `digest`
  static int digest(byte[] b) { int h=0; for (byte x: b) h=h*31+x; return h; }        // PURE
  static int digest(File f) throws IOException { return new FileInputStream(f).read(); } // Fs
  static int solo(byte[] b) { return digest(b); }   // UNIQUE name -> bare class.method, must stay pure
  public static void main(String[] a) throws IOException { digest(new byte[0]); digest(new File("x")); solo(new byte[0]); }
}
J
javac -d "$W/ovcls" "$W/src/Ov.java" 2>/dev/null
"$CJ" "$W/ovcls" --json "$W/ov.json" >/dev/null 2>&1
# Node ids live in the callgraph (the report's `functions` omits pure methods); assert the id FORMS there.
ovcg="$(cat "$W/ov.callgraph.json")"
# Two DISTINCT nodes exist for the overloaded name `digest`, each with its OWN param-typed id.
want   "the effectful overload is its own node Ov.digest(File)"   "$ovcg" '"Ov.digest(File)"'
want   "the pure overload is a SEPARATE node Ov.digest(byte[])"   "$ovcg" '"Ov.digest(byte[])"'
# The effectful overload carries Fs; the pure overload does NOT inherit it (the cardinal-sin guard).
want    "  …the File overload carries Fs"                         "$("$CJ" show "$W/ov.json" 'Ov.digest(File)')" 'Fs'
wantnot "  …the byte[] overload does NOT inherit the sibling's Fs" "$("$CJ" show "$W/ov.json" 'Ov.digest(byte[])')" 'Fs'
# A UNIQUE method keeps the BARE class.method id (NOT disambiguated) and stays pure — the conformance
# leaf-name contract: disambiguation must touch ONLY overloaded names.
want    "a unique method keeps the bare class.method id"          "$ovcg" '"Ov.solo"'
wantnot "  …the bare unique id is NOT disambiguated"              "$ovcg" '"Ov.solo('
wantnot "  …and the unique pure method has no fabricated effect"  "$("$CJ" show "$W/ov.json" 'Ov.solo')" 'Fs'

echo "== path: effect provenance (the chain to the source) =="
# A 3-deep Net chain: handle -> mid -> leafNet. `path` traces it to the direct source.
cat > "$W/src/Pp.java" <<'J'
public class Pp {
  static void leafNet() { try { new java.net.Socket("h", 1); } catch (Exception e) {} }
  static void mid()    { leafNet(); }
  static void handle() { mid(); }
  public static void main(String[] a) { handle(); }
}
J
javac -d "$W/pcls" "$W/src/Pp.java" 2>/dev/null
"$CJ" "$W/pcls" --json "$W/p.json" >/dev/null 2>&1
pth="$("$CJ" path "$W/p.json" handle Net)"
want   "path: traces the chain through the middle fn"  "$pth" 'Pp.mid'
want   "path: marks the direct source"                 "$pth" 'Net source'
want   "path: names the leaf source"                   "$pth" 'Pp.leafNet'
want   "path --json: structured steps with source flag" "$("$CJ" path "$W/p.json" handle Net --json)" '"source": true'
want   "path: honest when the fn doesn't perform the effect" "$("$CJ" path "$W/p.json" handle Db)" 'does not perform Db'

echo "== impact: blast radius (transitive callers + downstream entry points) =="
# In the Pp fixture, main -> handle -> mid -> leafNet. impact(leafNet) finds the transitive callers and
# the one downstream entry point (main).
imp="$("$CJ" impact "$W/p.json" leafNet)"
want   "impact: counts transitive callers"               "$imp" 'transitively call it'
want   "impact: surfaces the downstream entry point (main)" "$imp" 'Pp.main'
want   "impact: labels entry points downstream"          "$imp" 'entry point'
want   "impact --json: structured blast radius"          "$("$CJ" impact "$W/p.json" leafNet --json)" '"affectedCount"'
want   "impact --json: the affected LIST, not just a count (SPEC §3.1)" "$("$CJ" impact "$W/p.json" leafNet --json)" '"affected"'
want   "impact --json: the affected list names a transitive caller"     "$("$CJ" impact "$W/p.json" leafNet --json)" 'Pp.mid'

echo "== gains: supply-chain alarm UNION-merges same-fn rows (no phantom gain) =="
# A hand-merged/cross-jar baseline can repeat a fn. Keep-first would DROP a row's effects and report
# a FALSE gain; union (mirrors Rust load_fninfo / TS effectsByFn) keeps both. base A.foo = Net⊔Fs.
printf '{"functions":[{"fn":"A.foo","inferred":["Net"]},{"fn":"A.foo","inferred":["Fs"]}]}\n' > "$W/gbase.json"
printf '{"functions":[{"fn":"A.foo","inferred":["Net","Fs"]}]}\n' > "$W/gcur_same.json"
absent "gains: dup-baseline rows union, cur == their union → no phantom gain" "$("$CJ" gains "$W/gcur_same.json" "$W/gbase.json" --json)" '"effect"'
# a genuine new effect (Db) is still reported, exactly once even when cur repeats the fn
printf '{"functions":[{"fn":"A.foo","inferred":["Net","Db"]},{"fn":"A.foo","inferred":["Db"]}]}\n' > "$W/gcur_dup.json"
printf '{"functions":[{"fn":"A.foo","inferred":["Net"]}]}\n' > "$W/gbase1.json"
gj="$("$CJ" gains "$W/gcur_dup.json" "$W/gbase1.json" --json)"
want   "gains: a genuine new effect is still reported"   "$gj" '"Db"'
want   "gains: dup cur rows do not double-count byFunction" "$(printf '%s' "$gj" | grep -c '"effect"')" '1'

echo "== ⟨0.28⟩ gains carries the ⟨0.21⟩ MANIFEST, on BOTH SIDES, disclosed separately (SPEC §2) =="
# §2's re-disclosure MUST is stated over `coverage` and was implemented over `coverage` alone. The SAME
# verb, on the SAME report, dropped `unanalyzed` — the stronger caveat: `coverage.uncovered` says "I could
# not see into this dependency", `unanalyzed` says "I could not read this file of your OWN code", and
# `analyzed.count: 0` says "I judged nothing at all". BOTH SIDES SEPARATELY because a gains answer rests
# on two reports that fail differently — an incomplete CURRENT means the gained set may be SHORT, an
# incomplete BASELINE means the comparison floor is soft, so the existing-vs-new `origin` split is
# unreliable. Every row asserts the OTHER side is silent: one combined flag would pass a one-sided check.
gm_report() { # $1 out ; $2 effect ; $3 analyzed.count ; $4 unanalyzed json or -
  printf '{"candor":{"version":"t1","toolchain":"jvm","spec":"test"},"packages":["app"],"analyzed":{"count":%s},%s"functions":[{"fn":"app.A.f","inferred":["%s"],"direct":["%s"],"hash":"h"}]}\n' \
    "$3" "$([ "$4" = - ] || printf '"unanalyzed":%s,' "$4")" "$2" "$2" > "$1"
}
GM_UNREAD='[{"path":"src/Broken.java","reason":"parse error"}]'
gm_report "$W/gm_base.json" Fs  3 "$GM_UNREAD"
gm_report "$W/gm_cur.json"  Net 3 -
gmb="$("$CJ" gains "$W/gm_cur.json" "$W/gm_base.json" --json)"
want   "gains: an incomplete BASELINE is disclosed"                "$gmb" '"baselineIncomplete": true'
want   "gains: …naming the file the baseline could not read"       "$gmb" 'src/Broken.java'
want   "gains: …under the baseline's own key"                      "$gmb" '"baselineUnanalyzed"'
absent "gains: …and NOT as the current's (a whole current stays silent)" "$gmb" '"incomplete"'
want   "gains: the verdict body is untouched beside the caveat"    "$gmb" '"Net"'
gm_report "$W/gm_base2.json" Fs  3 -
gm_report "$W/gm_cur2.json"  Net 3 "$GM_UNREAD"
gmc="$("$CJ" gains "$W/gm_cur2.json" "$W/gm_base2.json" --json)"
want   "gains: an incomplete CURRENT is disclosed (the gained set may be SHORT)" "$gmc" '"incomplete": true'
want   "gains: …with the manifest rows"                            "$gmc" '"unanalyzed"'
absent "gains: …and NOT as the baseline's (a whole baseline stays silent)" "$gmc" '"baselineIncomplete"'
# ⟨0.24⟩'s SECOND cause: `analyzed.count: 0` carries NO `unanalyzed` — there is no unread FILE to name —
# so a consumer keyed on the array alone reads a report that judged nothing as complete.
gm_report "$W/gm_base3.json" Fs  0 -
gm_report "$W/gm_cur3.json"  Net 0 -
gmz="$("$CJ" gains "$W/gm_cur3.json" "$W/gm_base3.json" --json)"
want   "gains: a JUDGED-NOTHING current discloses"                 "$gmz" '"judgedNothing"'
want   "gains: a JUDGED-NOTHING baseline discloses under its key"  "$gmz" '"baselineJudgedNothing"'
absent "gains: count-0 names no unread file — the array is omitted, not invented" "$gmz" '"unanalyzed"'
# CONTROL: two INTACT reports disclose NOTHING — an ordinary run is byte-identical to a pre-⟨0.28⟩ one.
gm_report "$W/gm_base4.json" Fs  3 -
gm_report "$W/gm_cur4.json"  Net 3 -
gmi="$("$CJ" gains "$W/gm_cur4.json" "$W/gm_base4.json" --json)"
absent "gains: two whole reports disclose nothing at all"          "$gmi" 'ncomplete'
absent "gains: …not even an empty manifest"                        "$gmi" 'nalyzed'
# CONTROL: the exit code does not move. `--strict` keys on the GAINED SET, which this does not touch.
"$CJ" gains "$W/gm_cur3.json" "$W/gm_base3.json" --json --strict >/dev/null 2>&1; rc=$?
want   "gains --strict: an incomplete pair WITH a gain still exits 1" "$rc" '1'
"$CJ" gains "$W/gm_base3.json" "$W/gm_base3.json" --json --strict >/dev/null 2>&1; rc=$?
want   "gains --strict: an incomplete pair with NO gain still exits 0" "$rc" '0'
# the human TSV is a pinned consumer surface (whole-line matched by candor-run.sh's dedup)
want   "gains: the human TSV is byte-stable under the manifest" \
       "$("$CJ" gains "$W/gm_cur3.json" "$W/gm_base3.json" 2>/dev/null)" 'app.A.f	Net'
absent "gains: …carrying no caveat lines"                          "$("$CJ" gains "$W/gm_cur3.json" "$W/gm_base3.json" 2>/dev/null)" 'ncomplete'

echo "== diff/gains: §2.1 stale-baseline DISCLOSURE (queries answer + warn; only the GUARD fails closed) =="
# a baseline from a DIFFERENT producing build: the delta may be the ENGINE reclassifying, not the code.
# candor-ts is the reference: unconditional baseline_version/engine_version JSON fields ("" when unknown),
# one stderr ⚠ line ONLY when both versions are known and differ — and the query still answers.
python3 - "$W/r.json" "$W/qstale.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['candor']['version']='deadbee'
json.dump(d,open(sys.argv[2],'w'))
PY
dv="$("$CJ" diff "$W/r.json" "$W/qstale.json" --json 2>"$W/dverr")"
want   "diff json carries the baseline build"        "$dv" '"baseline_version": "deadbee"'
want   "diff json carries the engine build"          "$dv" '"engine_version"'
want   "diff still answers (changes present)"        "$dv" '"changes"'
want   "diff warns on the version mismatch (stderr)" "$(cat "$W/dverr")" '⚠ baseline @deadbee ≠ engine @'
want   "…and names the consequence"                  "$(cat "$W/dverr")" 'baseline-invalidating'
dm="$("$CJ" diff "$W/r.json" "$W/r.json" --json 2>"$W/dmerr")"
want   "matched pair: fields still present (unconditional)" "$dm" '"baseline_version"'
absent "matched pair: no ⚠ warning"                  "$(cat "$W/dmerr")" '⚠'
gv2="$("$CJ" gains "$W/r.json" "$W/qstale.json" --json 2>"$W/gverr")"
want   "gains json carries the provenance fields"    "$gv2" '"baseline_version": "deadbee"'
want   "gains warns with the reclassification caveat" "$(cat "$W/gverr")" 'may be the engine reclassifying'
# a legacy bare-array baseline has NO version header: fields are "" and no warning (nothing to compare)
printf '[{"fn":"Fx.reads","inferred":["Fs"]}]\n' > "$W/qbare.json"
db="$("$CJ" diff "$W/r.json" "$W/qbare.json" --json 2>"$W/dberr")"
want   "versionless baseline: empty provenance field, still answers" "$db" '"baseline_version": ""'
absent "versionless baseline: no ⚠ (nothing to compare)" "$(cat "$W/dberr")" '⚠'

echo "== diff exit parity (candor-ts query.mjs): exit 1 on a gain ONLY when the builds match =="
# The same-build ratchet convenience: a gained effect exits 1 iff the baseline came from THIS engine
# build. Under a version mismatch the "gain" may be the engine reclassifying (unmasking, not
# regression) — that signal is bogus as a CI failure, so exit 0 and the stderr ⚠ informs instead.
printf '{"candor":{"version":"vX"},"functions":[{"fn":"A.foo","inferred":["Net","Db"]}]}\n' > "$W/xcur.json"
printf '{"candor":{"version":"vX"},"functions":[{"fn":"A.foo","inferred":["Net"]}]}\n' > "$W/xbase_same.json"
printf '{"candor":{"version":"vY"},"functions":[{"fn":"A.foo","inferred":["Net"]}]}\n' > "$W/xbase_other.json"
"$CJ" diff "$W/xcur.json" "$W/xbase_same.json" --json >/dev/null 2>&1; rc=$?
want   "diff: gain + matched builds → exit 1 (the same-build ratchet)" "$rc" '1'
"$CJ" diff "$W/xcur.json" "$W/xbase_other.json" --json >/dev/null 2>"$W/xdoerr"; rc=$?
want   "diff: gain + MISmatched builds → exit 0 (unmasking, not regression)" "$rc" '0'
want   "…and the ⚠ disclosure names the mismatched baseline" "$(cat "$W/xdoerr")" '⚠ baseline @vY'
"$CJ" diff "$W/xcur.json" "$W/xcur.json" --json >/dev/null 2>&1; rc=$?
want   "diff: no gain → exit 0" "$rc" '0'
# the contract rides the verdict, not the output format
"$CJ" diff "$W/xcur.json" "$W/xbase_same.json" >/dev/null 2>&1; rc=$?
want   "diff: text mode exits 1 on a matched-build gain too" "$rc" '1'
# a LOST-only delta is not a gain
printf '{"candor":{"version":"vX"},"functions":[{"fn":"A.foo","inferred":["Net"]}]}\n' > "$W/xcur_lost.json"
printf '{"candor":{"version":"vX"},"functions":[{"fn":"A.foo","inferred":["Net","Db"]}]}\n' > "$W/xbase_more.json"
"$CJ" diff "$W/xcur_lost.json" "$W/xbase_more.json" --json >/dev/null 2>&1; rc=$?
want   "diff: lost-only delta → exit 0" "$rc" '0'
# gains ALWAYS exits 0 — in candor-ts the exit-1 contract belongs to diff alone (pure disclosure here)
"$CJ" gains "$W/xcur.json" "$W/xbase_same.json" --json >/dev/null 2>&1; rc=$?
want   "gains: a gained effect still exits 0 (disclosure, not a gate)" "$rc" '0'

echo "== query loader: a malformed-shape report FAILS LOUD, never silently 'all pure' =="
# An object with no `functions` key (a half-written / foreign file) was read as List.of() → silent
# under-report (show said 'no effects', gains alarmed on everything). Now it fails loud (exit 2).
printf '{"fn":"x","inferred":["Net"]}\n' > "$W/obj.json"
oj="$("$CJ" show "$W/obj.json" x 2>&1)"; ojc=$?
want "loader: object-without-functions fails loud (not silent-empty)" "$oj" 'cannot read report'
want "loader: object-without-functions exits 2" "$ojc" '2'
# the same malformed file as a gains BASELINE must not read as empty → maximal false alarm
printf '{"candor":{},"functions":[{"fn":"a","inferred":["Net"]}]}\n' > "$W/gcur.json"
want "loader: malformed gains baseline fails loud (no phantom all-gained)" "$("$CJ" gains "$W/gcur.json" "$W/obj.json" 2>&1)" 'cannot read baseline'
# an entry with an empty/absent fn is not addressable (every query keys/sorts/formats by fn) — the
# loader drops it loudly rather than crash show with a %-0s MissingFormatWidthException
printf '[{"inferred":["Db"]}]\n' > "$W/emptyfn.json"
want "loader: an empty-fn entry is dropped loudly, no %-0s crash" "$("$CJ" show "$W/emptyfn.json" '' 2>&1)" "report entr"
# a legitimately-empty report (functions:[]) is STILL a clean pure report, not an error
printf '{"candor":{"version":"x"},"functions":[]}\n' > "$W/empty.json"
want "loader: a legit empty report is clean-pure (not an error)" "$("$CJ" show "$W/empty.json" x 2>&1)" 'pure functions are omitted'

echo "== @PostConstruct/@PreDestroy lifecycle callbacks are entry points =="
# Container-invoked init/shutdown hooks — no project call site, so an init that reads config or a
# @PreDestroy that flushes/closes does orphaned I/O. The substring match covers javax/ and jakarta/.
# Isolated dir/package (NOT $W/lsrc — the AS-EFF-009 test compiles that whole tree).
mkdir -p "$W/lifesrc/jakarta/annotation" "$W/lifesrc/jakarta/persistence" "$W/lifesrc/bean"
printf 'package jakarta.annotation; import java.lang.annotation.*;\n@Retention(RetentionPolicy.RUNTIME)@Target(ElementType.METHOD) public @interface PostConstruct {}\n' > "$W/lifesrc/jakarta/annotation/PostConstruct.java"
printf 'package jakarta.annotation; import java.lang.annotation.*;\n@Retention(RetentionPolicy.RUNTIME)@Target(ElementType.METHOD) public @interface PreDestroy {}\n' > "$W/lifesrc/jakarta/annotation/PreDestroy.java"
printf 'package jakarta.persistence; import java.lang.annotation.*;\n@Retention(RetentionPolicy.RUNTIME)@Target(ElementType.METHOD) public @interface PrePersist {}\n' > "$W/lifesrc/jakarta/persistence/PrePersist.java"
cat > "$W/lifesrc/bean/Bean.java" <<'J'
package bean; import jakarta.annotation.*; import jakarta.persistence.*;
public class Bean {
  @PostConstruct public void warm(){ try { new java.io.FileInputStream("/tmp/cfg").close(); } catch(Exception e){} }
  @PreDestroy public void shutdown(){ try { new java.net.Socket("10.0.0.2",9).close(); } catch(Exception e){} }
  @PrePersist public void stamp(){ try { new java.io.FileOutputStream("/tmp/audit").close(); } catch(Exception e){} }
}
J
javac -d "$W/lifecls" $(find "$W/lifesrc" -name '*.java') 2>/dev/null
"$CJ" "$W/lifecls/bean" --json "$W/l.json" >/dev/null 2>&1
lep() { python3 -c "import json;print(next((e.get('entryPoint') for e in json.load(open('$W/l.json'))['functions'] if e['fn']=='$1'), 'absent'))"; }
want   "@PostConstruct init is an entry point (gains Fs)"  "$("$CJ" show "$W/l.json" 'bean.Bean.warm')" 'Fs'
want   "  …@PostConstruct entryPoint=true"                 "$(lep 'bean.Bean.warm')"     'True'
want   "@PreDestroy shutdown is an entry point (gains Net)" "$("$CJ" show "$W/l.json" 'bean.Bean.shutdown')" 'Net'
want   "  …@PreDestroy entryPoint=true"                    "$(lep 'bean.Bean.shutdown')" 'True'
want   "@PrePersist JPA entity callback is an entry point" "$(lep 'bean.Bean.stamp')"    'True'

echo "== interface-based runtime overrides (Spring lifecycle, servlet) are entry points =="
# Hierarchy-based, via transSupers: an InitializingBean/DisposableBean hook or a servlet doGet has no
# project call site (Spring/the container invokes it). Stubs stand in for the framework types.
mkdir -p "$W/rsrc/org/springframework/beans/factory" "$W/rsrc/jakarta/servlet/http" "$W/rsrc/app"
printf 'package org.springframework.beans.factory; public interface InitializingBean { void afterPropertiesSet() throws Exception; }\n' > "$W/rsrc/org/springframework/beans/factory/InitializingBean.java"
printf 'package org.springframework.beans.factory; public interface DisposableBean { void destroy() throws Exception; }\n' > "$W/rsrc/org/springframework/beans/factory/DisposableBean.java"
printf 'package jakarta.servlet.http; public abstract class HttpServlet { protected void doGet(Object q, Object r){} }\n' > "$W/rsrc/jakarta/servlet/http/HttpServlet.java"
cat > "$W/rsrc/app/Comp.java" <<'J'
package app; import org.springframework.beans.factory.*; import jakarta.servlet.http.HttpServlet;
public class Comp {
  public static class Init implements InitializingBean { public void afterPropertiesSet(){ try { new java.io.FileInputStream("/tmp/c").close(); } catch(Exception e){} } }
  public static class Disp implements DisposableBean { public void destroy(){ try { new java.net.Socket("10.0.0.2",9).close(); } catch(Exception e){} } }
  public static class Srv extends HttpServlet { protected void doGet(Object q, Object r){ try { new java.net.Socket("10.0.0.3",8).close(); } catch(Exception e){} } }
}
J
javac -d "$W/rcls" $(find "$W/rsrc" -name '*.java') 2>/dev/null
"$CJ" "$W/rcls/app" --json "$W/rr.json" >/dev/null 2>&1
rep2() { python3 -c "import json;print(next((e.get('entryPoint') for e in json.load(open('$W/rr.json'))['functions'] if e['fn']=='$1'), 'absent'))"; }
want   "InitializingBean.afterPropertiesSet is an entry point" "$(rep2 'app.Comp$Init.afterPropertiesSet')" 'True'
want   "DisposableBean.destroy is an entry point"              "$(rep2 'app.Comp$Disp.destroy')" 'True'
want   "servlet HttpServlet.doGet is an entry point"           "$(rep2 'app.Comp$Srv.doGet')" 'True'

echo "== Ktor route handlers (Kotlin suspend-lambda with a RoutingContext) are entry points =="
# A Ktor `get(\"/\") { … }` handler compiles to a SuspendLambda whose invoke bridge takes a
# RoutingContext — Ktor invokes it from its pipeline (no project call site). Stubs stand in for the
# Kotlin/Ktor types. A SuspendLambda WITHOUT a RoutingContext (a normal coroutine lambda) must NOT be
# marked — precision (else every coroutine lambda floods the roots).
mkdir -p "$W/ksrc/kotlin/coroutines/jvm/internal" "$W/ksrc/io/ktor/server/routing" "$W/ksrc/app"
printf 'package kotlin.coroutines.jvm.internal; public class SuspendLambda {}\n' > "$W/ksrc/kotlin/coroutines/jvm/internal/SuspendLambda.java"
printf 'package io.ktor.server.routing; public class RoutingContext {}\n' > "$W/ksrc/io/ktor/server/routing/RoutingContext.java"
cat > "$W/ksrc/app/Handlers.java" <<'J'
package app;
import kotlin.coroutines.jvm.internal.SuspendLambda; import io.ktor.server.routing.RoutingContext;
public class Handlers {
  // A Ktor route handler: extends SuspendLambda, invoke() takes a RoutingContext. Body does Fs.
  public static class Route extends SuspendLambda {
    public Object invokeSuspend(Object o){ try { new java.io.FileInputStream("/tmp/x").close(); } catch(Exception e){} return null; }
    public Object invoke(RoutingContext ctx, Object cont){ return invokeSuspend(null); }
  }
  // A normal coroutine lambda: extends SuspendLambda but NO RoutingContext → not a Ktor handler.
  public static class Plain extends SuspendLambda {
    public Object invokeSuspend(Object o){ try { new java.net.Socket("h",1); } catch(Exception e){} return null; }
    public Object invoke(Object a, Object cont){ return invokeSuspend(null); }
  }
}
J
javac -d "$W/kcls" $(find "$W/ksrc" -name '*.java') 2>/dev/null
"$CJ" "$W/kcls/app" --json "$W/k.json" >/dev/null 2>&1
kep() { python3 -c "import json;print(next((e.get('entryPoint') for e in json.load(open('$W/k.json'))['functions'] if e['fn']=='$1'), 'absent'))"; }
want   "Ktor handler invokeSuspend is an entry point (gains Fs)" "$("$CJ" show "$W/k.json" 'app.Handlers$Route.invokeSuspend')" 'Fs'
want   "  …Ktor handler entryPoint=true"                        "$(kep 'app.Handlers$Route.invokeSuspend')" 'True'
want   "a normal coroutine lambda is NOT a Ktor entry point"    "$(kep 'app.Handlers$Plain.invokeSuspend')" 'False'

echo "== program entry (main) + jar input (validation regressions) =="
# main() is the JVM-invoked program entry — a reachability root, like the Rust impl's `fn main`.
want   "public static void main is an entry point" \
       "$(python3 -c "import json;print(next((e.get('entryPoint') for e in json.load(open('$W/r.json'))['functions'] if e['fn']=='Fx.main'), 'absent'))")" 'True'
# A .jar is an archive, not a directory: walking it finds no .class entries, so candor used to return a
# SILENTLY EMPTY report for a jar despite advertising jar input. Must mount + analyse the archive.
jar cf "$W/fx.jar" -C "$W/cls" . 2>/dev/null
"$CJ" "$W/fx.jar" --json "$W/jar.json" >/dev/null 2>&1
want   "jar input is analysed, not silently empty"  "$(cat "$W/jar.json")" '"Fx.reads"'
want   "jar input resolves effects (Fs from the jar)" "$("$CJ" show "$W/jar.json" reads 2>/dev/null)" 'Fs'

echo "== policy: deny / pure (AS-EFF-006) =="
# $W/cls holds Fx (reads/writes/both → Fs; spawn → Exec; dyn → Unknown).
printf 'deny Fs Fx\n' > "$W/pol-deny"
pdeny="$(CANDOR_POLICY="$W/pol-deny" "$CJ" "$W/cls" 2>&1)"
want   "AS-EFF-006 flags a denied (transitive) Fs in scope"      "$pdeny" '[AS-EFF-006] `Fx.both`'
absent "deny Fs does not flag a non-Fs (Exec) method"           "$pdeny" 'Fx.spawn'
printf 'pure Fx\n' > "$W/pol-pure"
ppure="$(CANDOR_POLICY="$W/pol-pure" "$CJ" "$W/cls" 2>&1)"
want   "pure forbids ANY effect (Exec flagged too)"             "$ppure" '`Fx.spawn`'
printf 'deny Fs Other\n' > "$W/pol-oos"
poos="$(CANDOR_POLICY="$W/pol-oos" "$CJ" "$W/cls" 2>&1)"
absent "an out-of-scope deny does not fire (segment match)"      "$poos" 'AS-EFF-006'
want   "a clean policy reports no violations"                    "$poos" 'no violations'
u="$(CANDOR_POLICY="$W/no-such.policy" "$CJ" "$W/cls" 2>&1)"; urc=$?
want   "an unreadable policy fails LOUD, not silent"             "$u" 'could not be read'
if [ "$urc" -eq 2 ]; then echo "  ok   an unreadable policy FAILS the run (exit 2, spec §6.2)"; pass=$((pass+1));
else echo "  FAIL an unreadable policy FAILS the run — got exit $urc"; fail=$((fail+1)); fi

echo "== crash-safety: an unreadable scan target exits 2 with a clean message =="
# nonexistent path, corrupt/empty jar, and an uppercase non-zip .JAR must not dump a stack trace + exit 1
np="$("$CJ" "$W/no-such-path-xyz" 2>&1)"; npc=$?
want "scan target nonexistent → clean message"                  "$np" 'no such path'
if [ "$npc" -eq 2 ]; then echo "  ok   nonexistent scan target exits 2"; pass=$((pass+1));
else echo "  FAIL nonexistent scan target — got exit $npc"; fail=$((fail+1)); fi
absent "nonexistent scan target dumps no stack trace"           "$np" 'at candor.'
head -c 200 /dev/urandom > "$W/garbage.jar"
gj="$("$CJ" "$W/garbage.jar" 2>&1)"; gjc=$?
want "corrupt jar → clean 'cannot read scan target'"            "$gj" 'cannot read scan target'
if [ "$gjc" -eq 2 ]; then echo "  ok   corrupt jar exits 2"; pass=$((pass+1));
else echo "  FAIL corrupt jar — got exit $gjc"; fail=$((fail+1)); fi
absent "corrupt jar dumps no stack trace"                       "$gj" 'at candor.'
printf 'not a zip' > "$W/NOTAZIP.JAR"
nz="$("$CJ" "$W/NOTAZIP.JAR" 2>&1)"; nzc=$?
want "uppercase non-zip .JAR → clean message"                   "$nz" 'cannot read scan target'
if [ "$nzc" -eq 2 ]; then echo "  ok   uppercase non-zip .JAR exits 2"; pass=$((pass+1));
else echo "  FAIL uppercase non-zip .JAR — got exit $nzc"; fail=$((fail+1)); fi

echo "== classify() stays JIT-compilable: no Classifier method at/over HotSpot's huge-method limit =="
# The κ cascade is split into per-package-segment buckets precisely so the hottest path of every scan
# compiles (DontCompileHugeMethods = 8000 bytes). A new rule batch that pushes a bucket over the limit
# silently returns the whole scan to interpreted classify — gate it (7500 = headroom below 8000).
CLSF="$ROOT/build/classes/java/main/io/poly/candor/Classifier.class"
if [ -f "$CLSF" ] && python3 "$ROOT/test/method_code_sizes.py" "$CLSF" 7500 >/dev/null; then
  echo "  ok   every Classifier method is under 7500 bytes of bytecode"; pass=$((pass+1))
else
  echo "  FAIL a Classifier method is at/over 7500 bytes (runs interpreted at 8000) — re-chunk the bucket:"
  python3 "$ROOT/test/method_code_sizes.py" "$CLSF" 7500 2>/dev/null | head -3 | sed 's/^/        /'
  fail=$((fail+1))
fi

echo "== fail-closed outputs + deps: unwritable --json/--gate-json and a typo'd CANDOR_DEPS exit 2 =="
# an unwritable --json report path: one-line diagnostic + exit 2 (was: raw stack trace, exit 1)
uw="$("$CJ" "$W/cls" --json "$W/no-such-dir-xyz/r.json" 2>&1)"; uwc=$?
want   "unwritable --json → clean 'cannot write report'"        "$uw" 'cannot write report'
absent "unwritable --json dumps no stack trace"                 "$uw" 'at io.poly.candor'
if [ "$uwc" -eq 2 ]; then echo "  ok   unwritable --json exits 2"; pass=$((pass+1));
else echo "  FAIL unwritable --json — got exit $uwc"; fail=$((fail+1)); fi
# an unwritable --gate-json verdict on a CLEAN gate: the CI consumer reads the verdict FILE — exit 0
# with no file written is a gateless green (the SARIF reporter sees nothing and passes). Exit 2.
gw="$("$CJ" "$W/cls" --gate-json "$W/no-such-dir-xyz/gate.json" 2>&1)"; gwc=$?
want "unwritable --gate-json is loud"                           "$gw" 'could not write --gate-json'
if [ "$gwc" -eq 2 ]; then echo "  ok   unwritable --gate-json (clean gate) exits 2"; pass=$((pass+1));
else echo "  FAIL unwritable --gate-json (clean gate) — got exit $gwc"; fail=$((fail+1)); fi
# …but a REAL violation still outranks the write failure: exit 1 (CI stays red on the violation).
gv="$(CANDOR_POLICY="$W/pol-deny" "$CJ" "$W/cls" --gate-json "$W/no-such-dir-xyz/gate.json" 2>&1)"; gvc=$?
want "write failure stays loud alongside a violation"           "$gv" 'could not write --gate-json'
if [ "$gvc" -eq 1 ]; then echo "  ok   a violation outranks the write failure (exit 1)"; pass=$((pass+1));
else echo "  FAIL violation + unwritable --gate-json — got exit $gvc (want 1)"; fail=$((fail+1)); fi
# a typo'd CANDOR_DEPS token: every call into that dep would read PURE — exit 2, the CANDOR_CONFIG posture
dt="$(CANDOR_DEPS="$W/no-such-deps.json" "$CJ" "$W/cls" 2>&1)"; dtc=$?
want "typo'd CANDOR_DEPS names the bad token"                   "$dt" 'not a readable file or directory'
if [ "$dtc" -eq 2 ]; then echo "  ok   typo'd CANDOR_DEPS exits 2"; pass=$((pass+1));
else echo "  FAIL typo'd CANDOR_DEPS — got exit $dtc"; fail=$((fail+1)); fi
# a corrupt (unparseable) dep report: the §2.1 'corrupt report ≠ pure' rule, enforced at the file level
printf '{ not json' > "$W/corrupt-dep.json"
dc="$(CANDOR_DEPS="$W/corrupt-dep.json" "$CJ" "$W/cls" 2>&1)"; dcc=$?
want "corrupt dep report is named"                              "$dc" 'unreadable or not valid JSON'
if [ "$dcc" -eq 2 ]; then echo "  ok   corrupt dep report exits 2"; pass=$((pass+1));
else echo "  FAIL corrupt dep report — got exit $dcc"; fail=$((fail+1)); fi
# the query loader's precise failure reason is RELAYED ("cannot read report <path> (<why>)"), not discarded
qd="$("$CJ" show "$W/no-such-report.json" x 2>&1)"
want "query relays the load-failure reason in parens"           "$qd" "($W/no-such-report.json)"

# ── ⟨0.28⟩ SPEC §3.3.1: THE §2.2 SIDECARS GO WITH THE ARMED REPORT ────────────────────────────────
# An armed report beside a LIVE sidecar is a pair that contradicts itself. It is not decorative on this
# engine: `callers` is answered FROM the callgraph sidecar (a pure fn is absent from the report by §2
# rule 3), so the stale half answers confidently and wrongly. Measured before the fix — baseline `f`
# pure reached by `g`+`main`; the new version gives `f` an effect and adds `h`; the run exits 2 on an
# unknown flag — `callers f` said "reached by 2 function(s) (the blast radius…): g, main", exit 0, with
# `h` missing. An agent reads that as safe-to-edit. The cardinal sin, through the half report-arming
# did not touch.
echo "== ⟨0.28⟩ the §2.2 sidecars are removed with the armed report (and the VERDICT beside it is not) =="
mkdir -p "$W/sc/src" "$W/sc/cls"
cat > "$W/sc/src/Sc.java" <<'J'
public class Sc { static void f() {} static void g() { f(); } public static void main(String[] a) { g(); } }
J
javac -d "$W/sc/cls" "$W/sc/src/Sc.java" 2>/dev/null
"$CJ" "$W/sc/cls" --json "$W/sc/rep.json" --gate-json "$W/sc/rep.gate.json" >/dev/null 2>&1
cp "$W/sc/rep.callgraph.json" "$W/sc/cg0" 2>/dev/null; cp "$W/sc/rep.hierarchy.json" "$W/sc/h0" 2>/dev/null
if [ -f "$W/sc/rep.callgraph.json" ] && [ -f "$W/sc/rep.hierarchy.json" ]; then
  echo "  ok   the clean run wrote both sidecars (the premise this row needs)"; pass=$((pass+1))
else
  echo "  FAIL a clean --json run wrote no sidecar — the rows below would pass vacuously"; fail=$((fail+1))
fi
"$CJ" "$W/sc/cls" --json "$W/sc/rep.json" --gate-json "$W/sc/rep.gate.json" --zzz-not-a-flag >/dev/null 2>&1
for seg in callgraph hierarchy; do
  if [ -e "$W/sc/rep.$seg.json" ]; then
    echo "  FAIL rep.$seg.json still sits beside an ARMED report — the contradicting pair"; fail=$((fail+1))
  else echo "  ok   rep.$seg.json was removed with the armed report"; pass=$((pass+1)); fi
done
# …AND `<stem>.gate.json` IS NOT ONE OF THEM. It is the VERDICT sink's own document, separately armed;
# deleting it from the report sink is §3.3.1's measured cross-sink harm, and a consumer that reads a
# missing verdict as "nothing to report" goes green.
if [ -e "$W/sc/rep.gate.json" ]; then
  echo "  ok   the .gate.json VERDICT beside it survived (a report sink must not delete a verdict)"; pass=$((pass+1))
else
  echo "  FAIL the armed report deleted rep.gate.json — the verdict sink's document, which fails OPEN when absent"; fail=$((fail+1))
fi
# THE BLAST-RADIUS QUERY DISCLOSES instead of answering from the stale half.
br="$("$CJ" callers --report "$W/sc/rep.json" Sc.f 2>&1)"; brc=$?
want "callers over an armed report discloses rather than answering" "$br" 'no call graph in the report'
absent "…and does NOT name a blast radius from the stale sidecar"   "$br" 'blast radius'
# ── ⟨0.28⟩ …AND THE DISCLOSURE REACHES THE MACHINE CHANNEL. Deleting the sidecar removes the confidently
# WRONG answer; it does not by itself produce an honest one. `callers --json` printed `{}` at exit 0 here
# while the human arm above said "no call graph in the report" — human-fine, machine-silent, the split
# that makes a defect a cardinal sin. A consumer reading `direct`, or DEFAULTING it (the fail-open idiom
# ⟨0.24⟩ names on every key in this format), is told NOBODY CALLS `Sc.f`: "safe to edit" over a pair whose
# honest answer is "this run judged nothing". SPEC §3.3.1 permits an `unanswerable` key OR a non-zero exit;
# both are asserted, because each alone leaves a naive reader exposed — the key alone still lets
# `d.get("direct", [])` read as a determined negative, the exit alone leaves a JSON consumer holding `{}`.
brj="$("$CJ" callers --report "$W/sc/rep.json" Sc.f --json 2>&1)"; brjc=$?
want   "callers --json over an armed pair carries the \`unanswerable\` key" "$brj" '"unanswerable"'
absent "…and emits NO \`direct\` key a consumer could read as a negative"   "$brj" '"direct"'
if [ "$brjc" != 0 ]; then echo "  ok   …and exits non-zero ($brjc), so an exit-only consumer fails closed too"; pass=$((pass+1))
else echo "  FAIL callers --json over an armed pair exited 0 — the machine channel says the query succeeded"; fail=$((fail+1)); fi
if [ "$brc" != 0 ]; then echo "  ok   the human arm exits non-zero too ($brc) — one verdict, both channels"; pass=$((pass+1))
else echo "  FAIL the human arm disclosed but exited 0 — the exit code still reads as a successful query"; fail=$((fail+1)); fi
# RECOVERY: the next clean run brings the pair back, byte-identical.
"$CJ" "$W/sc/cls" --json "$W/sc/rep.json" >/dev/null 2>&1
if cmp -s "$W/sc/rep.callgraph.json" "$W/sc/cg0" && cmp -s "$W/sc/rep.hierarchy.json" "$W/sc/h0"; then
  echo "  ok   a recovering run restores both sidecars byte-identically"; pass=$((pass+1))
else
  echo "  FAIL the recovering run did not restore the sidecars to their previous bytes"; fail=$((fail+1))
fi
# THE CONTROLS ON THE RECOVERED PAIR, and they are the load-bearing half of the row above: ONLY "no graph
# at all" is unanswerable. A fn that really has no callers over a COMPLETE graph must still answer
# `direct: []` at exit 0 — that is a DETERMINED negative and withdrawing it would be the mirror defect —
# and a name absent from a real graph must still be the "no function matching" error, because a graph WAS
# read. Without these three rows the fix above is indistinguishable from `callers` refusing everything.
ok0="$("$CJ" callers --report "$W/sc/rep.json" Sc.main --json 2>&1)"; ok0c=$?
want   "CONTROL: over an INTACT pair a callerless fn still answers \`direct: []\`" "$ok0" '"direct": []'
absent "…and is NOT relabelled unanswerable"                                       "$ok0" 'unanswerable'
if [ "$ok0c" = 0 ]; then echo "  ok   …at exit 0 (a determined negative, not a refusal)"; pass=$((pass+1))
else echo "  FAIL a determined negative over a complete graph exited $ok0c — the mirror defect"; fail=$((fail+1)); fi
ok1="$("$CJ" callers --report "$W/sc/rep.json" Sc.f --json 2>&1)"
want "CONTROL: over an INTACT pair the real blast radius still answers" "$ok1" '"Sc.g"'
nf="$("$CJ" callers --report "$W/sc/rep.json" zzzNoSuchFn --json 2>&1)"; nfc=$?
want   "CONTROL: a nonexistent fn over a REAL graph is still the match error"      "$nf" 'no function matching'
absent "…not the unanswerable disclosure (a graph WAS read; the name is not in it)" "$nf" 'unanswerable'
if [ "$nfc" = 2 ]; then echo "  ok   …at exit 2"; pass=$((pass+1))
else echo "  FAIL a nonexistent fn over a real graph exited $nfc, not 2"; fail=$((fail+1)); fi

echo "== ⟨0.28⟩ SPEC §2: the DESCRIPTIVE verbs carry the ⟨0.21⟩ manifest too =="
# The re-disclosure MUST binds "any verb whose output could be read as a NEGATIVE FINDING about the code
# — a verdict, an empty result set, or a zero count", not only the `ok`-answering advisory verbs. Over an
# ARMED report (`functions: []`, `analyzed.count: 0`, a non-empty `unanalyzed`) — the standard
# post-failure artifact, i.e. what is on disk after a failed run — every one of these answered flat at
# exit 0 with no hedge on either channel: `blindspots` said `{"sources":[],"totalUnknown":0}`, i.e. NO
# BLIND SPOTS, over a report whose own manifest names a file it could not read. A consumer could not tell
# *nobody performs Fs* from *nothing was examined*.
"$CJ" "$W/sc/cls" --json "$W/sc/darm.json" >/dev/null 2>&1
"$CJ" "$W/sc/cls" --json "$W/sc/darm.json" --zzz-not-a-flag >/dev/null 2>&1
want "the armed report is the premise these rows need" "$(cat "$W/sc/darm.json")" '"unanalyzed"'
for v in "where Fs" "map" "blindspots" "blindspots --stats" "reachable" "containment" "tour"; do
  dj="$("$CJ" $v --report "$W/sc/darm.json" --json 2>/dev/null)"; djc=$?
  # `"incomplete"` and not `"incomplete": true` — `tour --json` is COMPACT (it mirrors the Rust
  # reference's to_string, not to_string_pretty), so the spaced form matches six verbs and misses one.
  want "\`$v --json\` over an armed report carries \`incomplete\`" "$dj" '"incomplete"'
  want "…and names WHICH unit went unread (the ⟨0.21⟩ manifest)"   "$dj" '"unanalyzed"'
  dh="$("$CJ" $v --report "$W/sc/darm.json" 2>/dev/null)"
  want "…and the HUMAN channel carries it too (both, or the fix is half)" "$dh" '⚠ INCOMPLETE'
  if [ "$djc" = 0 ]; then echo "  ok   …at an UNCHANGED exit 0 — this rung adds a caveat, it does not refuse"; pass=$((pass+1))
  else echo "  FAIL $v --json over an armed report exited $djc — the caveat became a refusal"; fail=$((fail+1)); fi
done
# THE SENTENCES THAT *ARE* THE ALL-CLEAR are withdrawn: dropping the key while leaving the prose standing
# MOVES the false all-clear rather than removing it ("no blind spots" IS the empty JSON pair, in English).
absent "…\`blindspots\` no longer claims every call resolved" \
  "$("$CJ" blindspots --report "$W/sc/darm.json" 2>/dev/null)" 'every call resolved'
absent "…\`tour\` no longer prints the unqualified 'nothing hidden'" \
  "$("$CJ" tour --report "$W/sc/darm.json" 2>/dev/null)" 'nothing hidden — every effect'
# THE MIRROR, and it is the load-bearing half: over the INTACT report (restored above) this rung is a
# NO-OP. An implementation that hedges unconditionally passes every row above and destroys the ordinary
# answer. `Sc` is effect-free, so this is also the ⟨0.24⟩ row that separates the two count-0 SHAPES: an
# all-pure package (`functions: []`, count > 0) is a CLAIM chaining rule 3 requires a consumer to believe,
# NOT a blind spot — the trigger is keyed on the ⟨0.21⟩ COUNT and never on the emptiness of `functions`.
for v in "where Fs" "map" "blindspots" "reachable" "containment" "tour"; do
  ij="$("$CJ" $v --report "$W/sc/rep.json" --json 2>/dev/null)"
  absent "CONTROL: \`$v --json\` over the INTACT report says nothing about completeness" "$ij" 'incomplete'
done
# …and `show`, whose document is a top-level JSON ARRAY, is deliberately NOT hedged: an array has nowhere
# to hang a key, and fixing only its human channel would MOVE the false all-clear. It needs a shape ruling.
absent "show --json stays a bare array (the one exempt verb, pending a shape ruling)" \
  "$("$CJ" show Sc.f --report "$W/sc/darm.json" --json 2>/dev/null)" 'incomplete'

# THE INPUT EXEMPTION COVERS THE SIDECARS TOO — never touch a path this run READS, whatever it is named.
# ⟨0.28⟩ contract upgrade (2026-08-12): this used to arm the report and have the sidecar REMOVER leave
# the input in place with a disclosure — which protected the arming deletion and left the SUCCESS path
# to destroy the dep (writeCallgraph writes `<stem>.callgraph.json` unconditionally on a clean run).
# The sink is a SET, so a sink whose own sidecar write names an input is now REFUSED up front, exit 2,
# having written NOTHING (§3.3.1 (3): the exemption is asked first).
cp "$W/sc/rep.callgraph.json" "$W/sc/cg1"
cp "$W/sc/rep.json" "$W/sc/rj1"
ie="$(CANDOR_DEPS="$W/sc/rep.callgraph.json" "$CJ" "$W/sc/cls" --json "$W/sc/rep.json" --zzz-not-a-flag 2>&1)"; iec=$?
want "a sink whose OWN sidecar names an INPUT is refused, naming both" "$ie" 'destroy the input this run reads'
if [ "$iec" = 2 ]; then echo "  ok   …at exit 2"; pass=$((pass+1)); else echo "  FAIL refusal exited $iec, want 2"; fail=$((fail+1)); fi
if cmp -s "$W/sc/rep.callgraph.json" "$W/sc/cg1" && cmp -s "$W/sc/rep.json" "$W/sc/rj1"; then
  echo "  ok   …and BOTH halves are byte-identical on disk (nothing was written, not even the arm)"; pass=$((pass+1))
else
  echo "  FAIL a file in the refused sink's set was written or destroyed"; fail=$((fail+1))
fi

echo "== .candor/config: target-anchored discovery + config-anchored relative paths (spec §3.4) =="
# a checked-in config with a RELATIVE policy path, scanned from a foreign CWD: discovery walks UP from
# the TARGET, and the relative `policy .candor/arch.policy` resolves against the repo root holding
# .candor/ — never against the launch directory.
mkdir -p "$W/cfgrepo/.candor" "$W/elsewhere"
cp -r "$W/cls" "$W/cfgrepo/build-cls"
printf 'policy .candor/arch.policy\n' > "$W/cfgrepo/.candor/config"
printf 'deny Fs Fx\n' > "$W/cfgrepo/.candor/arch.policy"
cfg="$(cd "$W/elsewhere" && "$CJ" "$W/cfgrepo/build-cls" 2>&1)"; cfgrc=$?
want "config discovered from the TARGET's tree, run from elsewhere" "$cfg" '[AS-EFF-006]'
if [ "$cfgrc" -eq 1 ]; then echo "  ok   the checked-in gate bites (exit 1) regardless of CWD"; pass=$((pass+1));
else echo "  FAIL config gate from foreign CWD — got exit $cfgrc (want 1)"; fail=$((fail+1)); fi
# NO CWD FALLBACK (the family's spec-§3.4 fix): a .candor/config in the LAUNCH directory must not
# apply to a scan of an unrelated target — that applied a foreign repo's gates to this scan.
mkdir -p "$W/foreignwd/.candor"
printf 'policy .candor/deny-all.policy\n' > "$W/foreignwd/.candor/config"
printf 'pure Fx\n' > "$W/foreignwd/.candor/deny-all.policy"
fwd="$(cd "$W/foreignwd" && "$CJ" "$W/cls" 2>&1)"; fwdrc=$?
absent "the CWD's unrelated config does NOT apply to the scan"   "$fwd" 'AS-EFF-006'
if [ "$fwdrc" -eq 0 ]; then echo "  ok   no CWD fallback (exit 0 — target has no config)"; pass=$((pass+1));
else echo "  FAIL CWD-fallback still applies a foreign config — exit $fwdrc"; fail=$((fail+1)); fi

echo "== policy: layering forbid A -> B (AS-EFF-009) =="
mkdir -p "$W/lsrc/app/domain" "$W/lsrc/app/infra"
cat > "$W/lsrc/app/infra/Repo.java" <<'J'
package app.infra;
import java.nio.file.*;
public class Repo { public void save() { try { Files.writeString(Path.of("/tmp/x"),"y"); } catch (Exception e) {} } }
J
cat > "$W/lsrc/app/domain/Order.java" <<'J'
package app.domain;
public class Order {
  public void place(app.infra.Repo r) { r.save(); }  // domain → infra (forbidden)
  public int total() { return 1 + 2; }               // pure, no dependency
}
J
javac -d "$W/lcls2" $(find "$W/lsrc" -name '*.java')
printf 'forbid domain -> infra\n' > "$W/pol-layer"
lay="$(CANDOR_POLICY="$W/pol-layer" "$CJ" "$W/lcls2" 2>&1)"
want   "AS-EFF-009 flags domain reaching into infra"   "$lay" '[AS-EFF-009] `app.domain.Order.place`'
want   "the violation names the laundering callee"     "$lay" 'app.infra.Repo.save'
printf 'forbid infra -> domain\n' > "$W/pol-rev"
rev="$(CANDOR_POLICY="$W/pol-rev" "$CJ" "$W/lcls2" 2>&1)"
absent "the reverse direction is clean (no false fire)" "$rev" 'AS-EFF-009'

echo "== policy: host allowlist (AS-EFF-008) =="
mkdir -p "$W/bsrc/billing"
cat > "$W/bsrc/billing/Pay.java" <<'J'
package billing;
import java.net.*;
public class Pay {
  public void charge() { try { new URL("https://api.stripe.com/v1/charges").openStream(); } catch (Exception e) {} }
  public void leak()   { try { new URL("https://metrics.growthtracker.io/track").openStream(); } catch (Exception e) {} }
  public void deep()   { send(); }
  void send() { try { new URL("https://api.stripe.com/internal").openStream(); } catch (Exception e) {} }
}
J
javac -d "$W/bcls" $(find "$W/bsrc" -name '*.java') 2>/dev/null
printf 'allow Net in billing api.stripe.com\n' > "$W/pol-allow"
al="$(CANDOR_POLICY="$W/pol-allow" "$CJ" "$W/bcls" 2>&1)"
want   "AS-EFF-008 flags a host outside the allowlist"      "$al" '[AS-EFF-008] `billing.Pay.leak`'
want   "the off-allowlist host is named"                    "$al" 'metrics.growthtracker.io'
absent "an allowed host (api.stripe.com) is not flagged"    "$al" 'Pay.charge'
absent "a TRANSITIVE allowed host is not flagged (propagated)" "$al" 'Pay.deep'
printf 'allow Net in billing api.stripe.com metrics.growthtracker.io\n' > "$W/pol-allow2"
al2="$(CANDOR_POLICY="$W/pol-allow2" "$CJ" "$W/bcls" 2>&1)"
want   "adding the host to the allowlist clears it"         "$al2" 'no violations'
# precision: a Net method full of dotted NON-host strings (property/message keys) must not report them.
cat > "$W/bsrc/billing/Mix.java" <<'J'
package billing;
public class Mix {
  public void f() {
    String a = System.getProperty("os.name");        // dotted property key, NOT a host
    String b = "terms.agency"; String c = "page.html";// message key / filename, NOT hosts
    try { new java.net.URL("https://real.example.com/x").openStream(); } catch (Exception e) {}
  }
}
J
javac -d "$W/bcls" $(find "$W/bsrc" -name '*.java') 2>/dev/null
mix="$("$CJ" "$W/bcls" --json "$W/mix.json" >/dev/null 2>&1; python3 -c "import json;print(next((e.get('hosts',[]) for e in json.load(open('$W/mix.json'))['functions'] if e['fn']=='billing.Mix.f'),[]))")"
want   "the real URL host is extracted"                     "$mix" 'real.example.com'
absent "a dotted property key is NOT a host"                "$mix" 'os.name'
absent "a message key is NOT a host"                         "$mix" 'terms.agency'
# a two-arg Socket(String host, int port) names the host as argv[0] — extract it (candor-scan does too).
cat > "$W/bsrc/billing/Sk.java" <<'J'
package billing;
import java.net.*;
public class Sk {
  public void two()  throws Exception { new Socket("api.stripe.com", 443).close(); }   // host as argv[0]
  public void dyn(String h) throws Exception { new Socket(h, 443).close(); }            // dynamic head: no host
}
J
javac -d "$W/bcls" $(find "$W/bsrc" -name '*.java') 2>/dev/null
"$CJ" "$W/bcls" --json "$W/sk.json" >/dev/null 2>&1
sktwo="$(python3 -c "import json;print(next((e.get('hosts',[]) for e in json.load(open('$W/sk.json'))['functions'] if e['fn']=='billing.Sk.two'),[]))")"
skdyn="$(python3 -c "import json;print(next((e.get('hosts',[]) for e in json.load(open('$W/sk.json'))['functions'] if e['fn']=='billing.Sk.dyn'),[]))")"
want   "two-arg Socket(host,port) extracts the host"        "$sktwo" 'api.stripe.com'
absent "a dynamic Socket host is honestly invisible"        "$skdyn" 'stripe'
# MASKING evasion (the round-15 HIGH): a method with a benign ALLOWED host AND an invisible Net reach (a
# RUNTIME-host Socket / a host-less Net owner) must NOT be certified by the benign literal — the invisible
# forbidden endpoint would otherwise slip through. The surface is INCOMPLETE → "cannot be certified".
cat > "$W/bsrc/billing/Mask.java" <<'J'
package billing;
import java.net.*;
public class Mask {
  // benign allowed host (api.stripe.com) + a RUNTIME-host socket (invisible endpoint) → must NOT certify
  public void mask(String evil) throws Exception {
    new URL("https://api.stripe.com/x").openStream();
    new Socket(evil, 9000).close();
  }
  // only the allowed literal host → certifies cleanly
  public void clean() throws Exception { new URL("https://api.stripe.com/y").openStream(); }
}
J
javac -d "$W/bcls" $(find "$W/bsrc" -name '*.java') 2>/dev/null
mk="$(CANDOR_POLICY="$W/pol-allow" "$CJ" "$W/bcls" 2>&1)"
want   "masking: a benign host does NOT certify an invisible runtime-host reach" "$mk" '`billing.Mask.mask` performs Net with no visible literal'
absent "masking: a clean literal-only method still certifies"                    "$mk" 'Mask.clean'

echo "== policy: Exec command + Fs path allowlists (AS-EFF-008) =="
mkdir -p "$W/asrc/svc"
cat > "$W/asrc/svc/Ops.java" <<'J'
package svc;
import java.nio.file.*;
public class Ops {
  public void run()   throws Exception { new ProcessBuilder("git","clone","https://x").start(); }
  public void shell() throws Exception { Runtime.getRuntime().exec("curl http://evil"); }
  public void read()  throws Exception { Files.readString(Path.of("/etc/app/cfg")); }
  public void write() throws Exception { Files.write(Path.of("/var/data"), "SECRET".getBytes()); }
}
J
javac -d "$W/acls" $(find "$W/asrc" -name '*.java') 2>/dev/null
"$CJ" "$W/acls" --json "$W/a.json" >/dev/null 2>&1
aj="$(cat "$W/a.json")"
# extraction precision (the spec forbids over-claiming)
want   "Exec cmd = the program (git), not an arg"   "$aj" '"git"'
absent "a ProcessBuilder ARG is not a command"      "$aj" '"clone"'
want   "Fs path from Path.of"                        "$aj" '/var/data'
absent "Files.write DATA is not a path"             "$aj" 'SECRET'
# enforcement
printf 'allow Exec in svc git\nallow Fs in svc /etc/app\n' > "$W/apol"
ax="$(CANDOR_POLICY="$W/apol" "$CJ" "$W/acls" 2>&1)"
want   "AS-EFF-008 flags an off-allowlist command"  "$ax" '[AS-EFF-008] `svc.Ops.shell`'
want   "AS-EFF-008 flags an off-allowlist path"     "$ax" '[AS-EFF-008] `svc.Ops.write`'
absent "an allowed command (git) is not flagged"    "$ax" 'Ops.run'
absent "an allowed path prefix is not flagged"      "$ax" 'Ops.read'

echo "== containment (effect-leakage diagnostic + ratchet) =="
mkdir -p "$W/csrc/dao" "$W/csrc/model"
cat > "$W/csrc/dao/Repo.java" <<'J'
package dao;
public class Repo { public void load() throws Exception { java.sql.DriverManager.getConnection("x"); } }
J
cat > "$W/csrc/model/Order.java" <<'J'
package model;
public class Order { public void save() throws Exception { java.sql.DriverManager.getConnection("y"); } }
J
javac -d "$W/ccls" $(find "$W/csrc" -name '*.java') 2>/dev/null
"$CJ" "$W/ccls" --json "$W/c.json" >/dev/null 2>&1
# §3.3.1: containment's single positional is the BASELINE (ratchet), never the report — the report-mode
# diagnostic takes the report via --report (a bare `containment <report.json>` now discovers + ratchets).
cont="$("$CJ" containment --report "$W/c.json" 2>&1)"
want   "containment reports Db across 2 layers"   "$cont" 'Db'
want   "containment names the leaked-into layer"  "$cont" 'model:1'
# ratchet: a baseline where Db lived only in dao → current (dao+model) is a regression
python3 -c "
import json
d=json.load(open('$W/c.json'))
d['functions']=[e for e in d['functions'] if e['fn'].split('.')[0]!='model']
json.dump(d,open('$W/cbase.json','w'))
"
reg="$("$CJ" containment "$W/c.json" "$W/cbase.json" 2>&1)"; rc=$?
want   "ratchet FLAGS a new leak (Db -> model)"   "$reg" 'Db → model'
[ "$rc" = "1" ] && echo "  ok   ratchet exits 1 on regression" && pass=$((pass+1)) || { echo "  FAIL ratchet exit on regression ($rc)"; fail=$((fail+1)); }
# ratchet vs itself → no regression, exit 0
unchg="$("$CJ" containment "$W/c.json" "$W/c.json" 2>&1)"; rc=$?
want   "ratchet vs itself: unchanged"             "$unchg" 'unchanged'
[ "$rc" = "0" ] && echo "  ok   ratchet exits 0 when clean" && pass=$((pass+1)) || { echo "  FAIL ratchet clean exit ($rc)"; fail=$((fail+1)); }
# improvement: a baseline with an extra Db layer that's since gone → positive note
python3 -c "
import json
d=json.load(open('$W/c.json'))
d['functions'].append({'fn':'legacy.Old.q','direct':['Db'],'inferred':['Db']})
json.dump(d,open('$W/cimp.json','w'))
"
imp="$("$CJ" containment "$W/c.json" "$W/cimp.json" 2>&1)"
want   "ratchet NOTES an improvement (Db left legacy)" "$imp" 'improved'

echo "== dispatch resolution: inherited-concrete vs genuine abstraction =="
# A concrete effectful method in a project SUPERclass, called on a SUBclass-typed receiver (so the
# bytecode owner is the subclass, which does not itself declare the method). candor must resolve it
# UP the hierarchy — propagating the real effect — instead of mislabelling it Unknown. A genuine
# project interface with no impl must STILL be Unknown (honest opacity, SPEC §4).
mkdir -p "$W/isrc"
cat > "$W/isrc/Inh.java" <<'J'
public class Inh {
  interface Strategy { void apply(); }                  // project iface, no impl anywhere
  static abstract class Base {
    void touch() { try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/tmp/x")); } catch (Exception e) {} }
  }
  static class Sub extends Base {}                       // inherits touch, does NOT override
  static void caller(Sub s) { s.touch(); }               // owner=Sub, touch inherited from Base -> Fs
  static void strat(Strategy s) { s.apply(); }           // unresolved project iface -> Unknown
  public static void main(String[] a) { caller(new Sub()); strat(null); }
}
J
javac -d "$W/icls" "$W/isrc/Inh.java"
"$CJ" "$W/icls" --json "$W/r2.json" >/dev/null 2>&1
rep2="$(cat "$W/r2.json")"
want   "inherited-concrete dispatch resolves to the superclass effect" \
       "$("$CJ" show "$W/r2.json" caller 2>/dev/null)" 'Fs'
absent "inherited-concrete call is NOT mislabelled Unknown" \
       "$("$CJ" show "$W/r2.json" caller 2>/dev/null)" 'Unknown'
want   "genuine project-iface dispatch stays Unknown"  "$("$CJ" show "$W/r2.json" strat 2>/dev/null)" 'Unknown'
want   "Unknown carries a why-tag"                     "$rep2" '"unknownWhy"'
want   "why-tag names the unresolved iface method"     "$rep2" 'dispatch:Inh$Strategy.apply'

echo "== JDK effect APIs: DNS resolution + concurrent PRNGs (probe-found gaps) =="
# A controlled JDK-effect probe found these unclassified despite being clear in-vocab effects:
# InetAddress DNS lookups (Net) and ThreadLocalRandom/SplittableRandom (Rand, like java.util.Random).
# getByAddress(byte[]) builds from raw bytes with NO lookup → must stay pure (precision).
cat > "$W/src/Jdk.java" <<'J'
import java.net.InetAddress;
import java.util.concurrent.ThreadLocalRandom;
public class Jdk {
  static void dns()       { try { InetAddress.getByName("example.com"); } catch (Exception e) {} }
  static void localHost() { try { InetAddress.getLocalHost(); } catch (Exception e) {} }
  static void byAddr()    { try { InetAddress.getByAddress(new byte[4]); } catch (Exception e) {} }
  static void tlr()       { int n = ThreadLocalRandom.current().nextInt(); }
  static void split()     { long n = new java.util.SplittableRandom().nextLong(); }
}
J
javac -d "$W/jcls" "$W/src/Jdk.java" 2>/dev/null
"$CJ" "$W/jcls" --json "$W/jdk.json" >/dev/null 2>&1
jdk="$(cat "$W/jdk.json")"
want   "InetAddress.getByName (DNS) is Net"          "$("$CJ" show "$W/jdk.json" 'Jdk.dns')"       'Net'
want   "InetAddress.getLocalHost is Net"             "$("$CJ" show "$W/jdk.json" 'Jdk.localHost')" 'Net'
absent "InetAddress.getByAddress (no lookup) is pure" "$jdk"                                       '"Jdk.byAddr"'
want   "ThreadLocalRandom is Rand"                   "$("$CJ" show "$W/jdk.json" 'Jdk.tlr')"       'Rand'
want   "SplittableRandom is Rand"                    "$("$CJ" show "$W/jdk.json" 'Jdk.split')"     'Rand'

echo "== JDK effect APIs: JNDI/RMI/HttpServer (Net), archive readers (Fs) — probe-found gaps =="
# JNDI lookup is the Log4Shell network-egress vector; RMI + the JDK HttpServer bind/contact sockets;
# ZipFile/JarFile read an archive off disk. Precision: ZipEntry (pure data) + a non-lookup naming method
# must stay pure.
cat > "$W/src/Jdk2.java" <<'J'
import java.nio.file.*;
public class Jdk2 {
  static void jndi()      { try { new javax.naming.InitialContext().lookup("ldap://x"); } catch (Exception e) {} }
  static void rmi()       { try { java.rmi.Naming.lookup("rmi://x/y"); } catch (Exception e) {} }
  static void httpServer(){ try { com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0); } catch (Exception e) {} }
  static void zip()       { try { new java.util.zip.ZipFile("/tmp/x.zip").entries(); } catch (Exception e) {} }
  static void jar()       { try { new java.util.jar.JarFile("/tmp/x.jar").entries(); } catch (Exception e) {} }
  static void zipEntry()  { java.util.zip.ZipEntry z = new java.util.zip.ZipEntry("n"); long s = z.getSize(); } // pure
}
J
javac -d "$W/jcls2" "$W/src/Jdk2.java" 2>/dev/null
"$CJ" "$W/jcls2" --json "$W/jdk2.json" >/dev/null 2>&1
jdk2="$(cat "$W/jdk2.json")"
want   "JNDI InitialContext.lookup is Net (Log4Shell vector)" "$("$CJ" show "$W/jdk2.json" 'Jdk2.jndi')"       'Net'
want   "RMI Naming.lookup is Net"                             "$("$CJ" show "$W/jdk2.json" 'Jdk2.rmi')"        'Net'
want   "JDK HttpServer.create is Net"                         "$("$CJ" show "$W/jdk2.json" 'Jdk2.httpServer')" 'Net'
want   "ZipFile read is Fs"                                   "$("$CJ" show "$W/jdk2.json" 'Jdk2.zip')"        'Fs'
want   "JarFile read is Fs"                                   "$("$CJ" show "$W/jdk2.json" 'Jdk2.jar')"        'Fs'
absent "ZipEntry data type stays pure"                        "$jdk2"                                          '"Jdk2.zipEntry"'

echo "== Clipboard effect (spec §1 vocabulary parity; Rust had it, candor-java did not) =="
# Clipboard is one of the 10 spec effects (𝔼); candor-java never emitted it. AWT Toolkit hands out the
# system clipboard; Clipboard get/setContents read/write it. DataFlavor (pure data) must stay pure. And
# Clipboard must be an AMBIENT authority (𝔼 \ {Log}) so CANDOR_NO_AMBIENT/AS-EFF-004 flags a direct reach.
cat > "$W/src/Clip.java" <<'J'
import java.awt.*; import java.awt.datatransfer.*;
public class Clip {
  static void get() { try { Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor); } catch (Exception e) {} }
  static void set() { Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection("x"), null); }
  static void flavor() { DataFlavor f = DataFlavor.stringFlavor; }   // pure data type
}
J
javac -d "$W/clcls" "$W/src/Clip.java" 2>/dev/null
"$CJ" "$W/clcls" --json "$W/clip.json" >/dev/null 2>&1
clip="$(cat "$W/clip.json")"
want   "clipboard read is Clipboard"        "$("$CJ" show "$W/clip.json" 'Clip.get')" 'Clipboard'
want   "clipboard write is Clipboard"       "$("$CJ" show "$W/clip.json" 'Clip.set')" 'Clipboard'
absent "DataFlavor data type stays pure"    "$clip"                                   '"Clip.flavor"'
want   "Clipboard is an ambient authority (AS-EFF-004 flags a direct reach)" \
       "$(CANDOR_NO_AMBIENT=1 "$CJ" "$W/clcls" 2>&1)" '[AS-EFF-004] `Clip.get`'

echo "== whole-owner fabrication guard: pure handle accessors + inert ctors stay PURE =="
# The cardinal sin of an effect-checker is fabricating an effect on a PURE method. Several handle types
# carry their effect at WHOLE-OWNER level (File→Fs, Socket→Net, Clock, Random→Rand, ZipFile/JarFile→Fs,
# Clipboard) — but their path/field accessors and inert ctors do NO I/O / read NO entropy / read NO
# clock. isPureHandleAccessor SUBTRACTS exactly those; everything else on the type keeps its effect.
# Each case is proven BOTH directions: (a) the pure accessor/inert-ctor is pure, (b) a genuinely
# effectful method on the SAME type still fires. (Found: every accessor below was fabricating.)
cat > "$W/src/Fab.java" <<'J'
import java.io.File;
import java.net.Socket;
import java.time.*;
import java.util.Random;
import java.security.SecureRandom;
import java.util.zip.ZipFile;
import java.util.concurrent.ThreadLocalRandom;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.DatagramChannel;
public class Fab {
  // java.io.File — a File is an immutable pathname; these touch no filesystem (the ctor does ZERO I/O).
  static String  fName()   { return new File("/tmp/x").getName(); }          // PURE (inert ctor + accessor)
  static String  fParent() { return new File("/tmp/x").getParent(); }        // PURE
  static boolean fAbs()    { return new File("/tmp/x").isAbsolute(); }       // PURE
  static java.net.URI fUri(){ return new File("/tmp/x").toURI(); }           // PURE
  static boolean fDelete() { return new File("/tmp/x").delete(); }           // Fs (real I/O)
  static boolean fExists() { return new File("/tmp/x").exists(); }           // Fs (stat)
  static String  fCanon()  { try { return new File("/tmp/x").getCanonicalPath(); } catch (Exception e) { return null; } } // Fs (resolves symlinks)
  // java.net.Socket — these read fields cached on the handle; the streams are the wire boundary.
  static int     sPort(Socket s)   { return s.getPort(); }                   // PURE
  static boolean sClosed(Socket s) { return s.isClosed(); }                  // PURE
  static java.net.SocketAddress sRemote(Socket s) { return s.getRemoteSocketAddress(); } // PURE
  static java.io.OutputStream sOut(Socket s) { try { return s.getOutputStream(); } catch (Exception e) { return null; } } // Net (I/O boundary)
  // java.time.Clock — factories/accessors read NO wall clock; instant()/millis() do.
  static Clock   cUtc()            { return Clock.systemUTC(); }             // PURE
  static Clock   cFixed()          { return Clock.fixed(Instant.EPOCH, ZoneOffset.UTC); } // PURE
  static ZoneId  cZone(Clock c)    { return c.getZone(); }                   // PURE
  static Instant cInstant(Clock c) { return c.instant(); }                   // Clock (reads time)
  static long    cMillis(Clock c)  { return c.millis(); }                    // Clock (reads time)
  // java.util.Random / SecureRandom — metadata is pure; the draws read entropy.
  static String  rAlgo(SecureRandom r) { return r.getAlgorithm(); }          // PURE
  static int     rNext(Random r)       { return r.nextInt(); }               // Rand (draws)
  static byte[]  rSeed(SecureRandom r) { return r.generateSeed(8); }         // Rand (entropy)
  // java.util.zip.ZipFile — getName/size are cached; entries() re-reads the archive.
  static String  zName(ZipFile z)    { return z.getName(); }                 // PURE (no ctor in this fn)
  static int     zSize(ZipFile z)    { return z.size(); }                    // PURE
  static Object  zEntries(ZipFile z) { return z.entries(); }                 // Fs (reads archive)
  // java.util.concurrent.ThreadLocalRandom — current() is a pure thread-local factory (seeds from an
  // atomic counter, not OS entropy); the draws read entropy.
  static ThreadLocalRandom tlrCur()  { return ThreadLocalRandom.current(); } // PURE (factory, no entropy)
  static int     tlrNext()           { return ThreadLocalRandom.current().nextInt(); } // Rand (draws)
  // java.nio.channels.FileChannel — isOpen() is a field read; position()/size() lseek/stat the fd.
  static boolean fcOpen(FileChannel fc) { return fc.isOpen(); }              // PURE (!closed field read)
  static long    fcPos(FileChannel fc)  throws Exception { return fc.position(); } // Fs (lseek syscall)
  static long    fcSize(FileChannel fc) throws Exception { return fc.size(); }     // Fs (stat the file)
  static int     fcRead(FileChannel fc) throws Exception { return fc.read(ByteBuffer.allocate(1)); } // Fs
  // NIO socket channels — open/state/blocking flags + cached addresses + socket() adaptor are pure;
  // read/write/accept/receive touch the wire.
  static boolean scOpen(SocketChannel sc)        { return sc.isOpen(); }            // PURE
  static boolean scConn(SocketChannel sc)        { return sc.isConnected(); }       // PURE
  static java.net.SocketAddress scLoc(SocketChannel sc) throws Exception { return sc.getLocalAddress(); } // PURE
  static java.net.Socket scSock(SocketChannel sc) { return sc.socket(); }           // PURE (adaptor)
  static int     scRead(SocketChannel sc) throws Exception { return sc.read(ByteBuffer.allocate(1)); } // Net
  static boolean sscOpen(ServerSocketChannel ssc) { return ssc.isOpen(); }          // PURE
  static java.nio.channels.SocketChannel sscAccept(ServerSocketChannel ssc) throws Exception { return ssc.accept(); } // Net
  static boolean dcOpen(DatagramChannel dc)      { return dc.isOpen(); }            // PURE
  static java.net.SocketAddress dcRemote(DatagramChannel dc) throws Exception { return dc.getRemoteAddress(); } // PURE
  static java.net.SocketAddress dcRecv(DatagramChannel dc) throws Exception { return dc.receive(ByteBuffer.allocate(1)); } // Net
  // java.util.logging — the whole-PACKAGE logging gate would fabricate Log on a Logger's pure name
  // accessor (getName is getfield;areturn). The genuine emit (info/log) stays Log. (Real-world slf4j
  // sweep found pure Marker/formatter/factory accessors over-claiming Log; the jul Logger.getName
  // accessor is the same class of bug, reachable with only JDK types.)
  static String lgName(java.util.logging.Logger l) { return l.getName(); }   // PURE (cached field read)
  static void   lgInfo(java.util.logging.Logger l) { l.info("hi"); }         // Log (real emit)
}
J
javac -d "$W/fabcls" "$W/src/Fab.java" 2>/dev/null
"$CJ" "$W/fabcls" --json "$W/fab.json" >/dev/null 2>&1
fab="$(cat "$W/fab.json")"
# (a) pure accessors / inert ctors — effect ABSENT
absent "File.getName + inert new File() is pure (no Fs)"   "$fab" '"Fab.fName"'
absent "File.getParent is pure"                            "$fab" '"Fab.fParent"'
absent "File.isAbsolute is pure"                           "$fab" '"Fab.fAbs"'
absent "File.toURI is pure"                                "$fab" '"Fab.fUri"'
absent "Socket.getPort is pure (cached field)"             "$fab" '"Fab.sPort"'
absent "Socket.isClosed is pure"                           "$fab" '"Fab.sClosed"'
absent "Socket.getRemoteSocketAddress is pure"             "$fab" '"Fab.sRemote"'
absent "Clock.systemUTC factory is pure (reads no time)"   "$fab" '"Fab.cUtc"'
absent "Clock.fixed factory is pure"                       "$fab" '"Fab.cFixed"'
absent "Clock.getZone accessor is pure"                    "$fab" '"Fab.cZone"'
absent "SecureRandom.getAlgorithm is pure (no entropy)"    "$fab" '"Fab.rAlgo"'
absent "ZipFile.getName accessor is pure"                  "$fab" '"Fab.zName"'
absent "ZipFile.size accessor is pure (cached count)"      "$fab" '"Fab.zSize"'
absent "ThreadLocalRandom.current is pure (factory)"       "$fab" '"Fab.tlrCur"'
absent "FileChannel.isOpen is pure (field read)"           "$fab" '"Fab.fcOpen"'
absent "SocketChannel.isOpen is pure"                      "$fab" '"Fab.scOpen"'
absent "SocketChannel.isConnected is pure"                 "$fab" '"Fab.scConn"'
absent "SocketChannel.getLocalAddress is pure (cached)"    "$fab" '"Fab.scLoc"'
absent "SocketChannel.socket adaptor is pure"              "$fab" '"Fab.scSock"'
absent "ServerSocketChannel.isOpen is pure"                "$fab" '"Fab.sscOpen"'
absent "DatagramChannel.isOpen is pure"                    "$fab" '"Fab.dcOpen"'
absent "DatagramChannel.getRemoteAddress is pure (cached)" "$fab" '"Fab.dcRemote"'
absent "Logger.getName is pure (cached field, not a Log emit)" "$fab" '"Fab.lgName"'
# (b) genuinely-effectful members on the SAME types STILL fire (no under-report introduced)
want   "File.delete still Fs"                "$("$CJ" show "$W/fab.json" 'Fab.fDelete')"   'Fs'
want   "File.exists still Fs"                "$("$CJ" show "$W/fab.json" 'Fab.fExists')"   'Fs'
want   "File.getCanonicalPath still Fs"      "$("$CJ" show "$W/fab.json" 'Fab.fCanon')"    'Fs'
want   "Socket.getOutputStream still Net"    "$("$CJ" show "$W/fab.json" 'Fab.sOut')"      'Net'
want   "Clock.instant still Clock"           "$("$CJ" show "$W/fab.json" 'Fab.cInstant')"  'Clock'
want   "Clock.millis still Clock"            "$("$CJ" show "$W/fab.json" 'Fab.cMillis')"   'Clock'
want   "Random.nextInt still Rand"           "$("$CJ" show "$W/fab.json" 'Fab.rNext')"     'Rand'
want   "SecureRandom.generateSeed still Rand" "$("$CJ" show "$W/fab.json" 'Fab.rSeed')"    'Rand'
want   "ZipFile.entries still Fs"            "$("$CJ" show "$W/fab.json" 'Fab.zEntries')"  'Fs'
want   "ThreadLocalRandom.nextInt still Rand" "$("$CJ" show "$W/fab.json" 'Fab.tlrNext')" 'Rand'
want   "FileChannel.position still Fs (lseek)" "$("$CJ" show "$W/fab.json" 'Fab.fcPos')"  'Fs'
want   "FileChannel.size still Fs (stat)"    "$("$CJ" show "$W/fab.json" 'Fab.fcSize')"   'Fs'
want   "FileChannel.read still Fs"           "$("$CJ" show "$W/fab.json" 'Fab.fcRead')"   'Fs'
want   "SocketChannel.read still Net"        "$("$CJ" show "$W/fab.json" 'Fab.scRead')"   'Net'
want   "ServerSocketChannel.accept still Net" "$("$CJ" show "$W/fab.json" 'Fab.sscAccept')" 'Net'
want   "DatagramChannel.receive still Net"   "$("$CJ" show "$W/fab.json" 'Fab.dcRecv')"   'Net'
want   "Logger.info still Log (real emit)"   "$("$CJ" show "$W/fab.json" 'Fab.lgInfo')"   'Log'

echo "== anon-class instantiation edges to the INVOKABLE surface, not dead private helpers =="
# A runtime-executor anon class (Runnable) has its run() invoked outside project code, so the
# instantiation edges to the anon class's methods. A PRIVATE helper can't be a framework-invoked
# override (reached only via an in-class call), so a DEAD private effectful helper must NOT leak.
mkdir -p "$W/an"
cat > "$W/an/A.java" <<'J'
public class A {
  Runnable launch() {
    return new Runnable() {
      public void run() { helperLive(); }
      void helperLive() { try { new java.io.FileInputStream("/x").read(); } catch (Exception e) {} }
      private void helperDead() { try { Runtime.getRuntime().exec("rm -rf /"); } catch (Exception e) {} }
    };
  }
}
J
javac -d "$W/anout" "$W/an/A.java" 2>/dev/null
"$CJ" "$W/anout" --json "$W/an.json" >/dev/null 2>&1
anLaunch="$("$CJ" show "$W/an.json" 'A.launch')"
absent "anon-class: a DEAD private exec() does not leak Exec onto the spawner" "$anLaunch" 'Exec'
want   "anon-class: a LIVE helper reached via the run() override still propagates (Fs)" "$anLaunch" 'Fs'

echo "== ktor CLIENT: HttpStatement.execute is the Net dispatch (stub-compiled) =="
# The ktor request verbs (get/post/request) are INLINE suspend extensions — the compiler emits one
# funnel, HttpStatement.execute (+ the response-body readers). Stub the owner so the consumer's call
# site carries the real owner string; analyze only the consumer (classification is owner-keyed).
mkdir -p "$W/ktsrc/io/ktor/client/statement" "$W/ktsrc/app"
printf 'package io.ktor.client.statement; public class HttpStatement { public Object execute(Object c){ return null; } }\n' > "$W/ktsrc/io/ktor/client/statement/HttpStatement.java"
printf 'package io.ktor.client.statement; public class HttpResponseKt { public static String bodyAsText(Object r){ return ""; } }\n' > "$W/ktsrc/io/ktor/client/statement/HttpResponseKt.java"
cat > "$W/ktsrc/app/KtorUse.java" <<'J'
package app; import io.ktor.client.statement.*;
public class KtorUse {
  public static Object hit(HttpStatement s) { return s.execute(null); }           // the dispatch -> Net
  public static String readBody(Object r) { return HttpResponseKt.bodyAsText(r); } // response read -> Net
  public static HttpStatement build() { return new HttpStatement(); }              // construction stays pure
}
J
javac -d "$W/ktcls" $(find "$W/ktsrc" -name '*.java') 2>/dev/null
"$CJ" "$W/ktcls/app" --json "$W/kt.json" >/dev/null 2>&1
kshow() { python3 -c "import json;print(sorted(next((e['inferred'] for e in json.load(open('$W/kt.json'))['functions'] if e['fn']=='$1'), [])))"; }
want   "ktor HttpStatement.execute consumer is Net"  "$(kshow 'app.KtorUse.hit')" "Net"
want   "ktor bodyAsText consumer is Net"             "$(kshow 'app.KtorUse.readBody')" "Net"
want   "ktor statement construction stays pure"      "$(kshow 'app.KtorUse.build')" "[]"

echo "== groovy consumers: metaclass dynamic dispatch is reflection-class Unknown (stub-compiled) =="
mkdir -p "$W/gvsrc/groovy/lang" "$W/gvsrc/app"
printf 'package groovy.lang; public class GroovyShell { public Object evaluate(String s){ return null; } }\n' > "$W/gvsrc/groovy/lang/GroovyShell.java"
printf 'package groovy.lang; public interface GroovyObject { Object invokeMethod(String n, Object a); }\n' > "$W/gvsrc/groovy/lang/GroovyObject.java"
cat > "$W/gvsrc/app/GroovyUse.java" <<'J'
package app; import groovy.lang.*;
public class GroovyUse {
  public static Object scripted(GroovyShell sh) { return sh.evaluate("anything()"); } // dynamic eval -> Unknown
  public static Object dyn(GroovyObject o) { return o.invokeMethod("x", null); }      // metaclass dispatch -> Unknown
}
J
javac -d "$W/gvcls" $(find "$W/gvsrc" -name '*.java') 2>/dev/null
"$CJ" "$W/gvcls/app" --json "$W/gv.json" >/dev/null 2>&1
gshow() { python3 -c "import json;print(sorted(next((e['inferred'] for e in json.load(open('$W/gv.json'))['functions'] if e['fn']=='$1'), [])))"; }
want   "GroovyShell.evaluate consumer is Unknown"   "$(gshow 'app.GroovyUse.scripted')" "Unknown"
want   "GroovyObject.invokeMethod consumer is Unknown" "$(gshow 'app.GroovyUse.dyn')" "Unknown"

echo "== AS-EFF-007 taint (CANDOR_TAINT): injection-class effect on a caller-derived argument =="
# Intraprocedural taint dataflow: a parameter flowing (directly or through string concat) into an
# injection-class effect (Exec/Fs/Db/Net/Env/Ipc) is flagged. A literal arg, a fresh local, and a pure
# method must NOT flag (precision). Advisory: never fails CI. Gated by CANDOR_TAINT.
cat > "$W/src/Taint.java" <<'J'
import java.nio.file.*;
public class Taint {
  public void execParam(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); }       // param -> Exec
  public void readConcat(String key) throws Exception { Files.readAllBytes(Path.of("/c/" + key)); } // concat -> Fs
  public static void staticExec(String c) throws Exception { Runtime.getRuntime().exec(c); }    // static slot 0
  public void execLiteral() throws Exception { Runtime.getRuntime().exec("/bin/ls"); }          // literal -> pure
  public void readLocal() throws Exception { String p = "/etc/hosts"; Files.readAllBytes(Path.of(p)); } // local
  public String pure(String s) { return s.trim(); }                                            // no effect
}
J
javac -d "$W/tcls2" "$W/src/Taint.java" 2>/dev/null
taint="$(CANDOR_TAINT=1 "$CJ" "$W/tcls2" 2>&1)"
want   "param flowing to exec is AS-EFF-007 (Exec)"        "$taint" '[AS-EFF-007] `Taint.execParam` performs { Exec }'
want   "param through string concat to a read is flagged (Fs)" "$taint" '[AS-EFF-007] `Taint.readConcat` performs { Fs }'
want   "static method param (slot 0) is flagged"          "$taint" '[AS-EFF-007] `Taint.staticExec`'
absent "a literal exec arg is NOT tainted"               "$taint" '`Taint.execLiteral`'
absent "a fresh-local path is NOT tainted"               "$taint" '`Taint.readLocal`'
absent "a pure method is NOT tainted"                    "$taint" '`Taint.pure`'
absent "taint is silent without CANDOR_TAINT"            "$("$CJ" "$W/tcls2" 2>&1)" 'AS-EFF-007'

echo "== callers: the PRE-EDIT blast radius of a PURE function (the agent-use gap) =="
# An agent about to add an effect to a pure fn asks "who depends on me?". `callers` must answer that for a
# PURE function (not just already-effectful ones) — via the full call-graph SIDECAR written beside the
# report (the report omits pure fns). Closes the parity gap an agent-use eval found (candor-scan had it).
cat > "$W/src/Blast.java" <<'J'
public class Blast {
  static int leaf(int x) { return x * 2; }   // PURE — the fn about to gain an effect
  static int mid(int x)  { return leaf(x); }
  static int top(int x)  { return mid(x); }
}
J
javac -d "$W/bcls" "$W/src/Blast.java" 2>/dev/null
"$CJ" "$W/bcls" --json "$W/b.json" >/dev/null 2>&1
bc="$("$CJ" callers "$W/b.json" leaf)"
want   "callgraph sidecar is written beside the report"   "$(ls "$W"/b.callgraph.json 2>/dev/null)" 'b.callgraph.json'
want   "callers of a PURE fn returns the blast radius"     "$bc" 'blast radius if it gained an effect'
want   "  …names the direct caller"                       "$bc" 'Blast.mid (direct)'
want   "  …names the transitive caller"                   "$bc" 'Blast.top'
want   "callers --json: structured blast radius"          "$("$CJ" callers "$W/b.json" leaf --json)" '"transitive"'

echo "== whatif: the PRE-EDIT policy verdict (blast radius x the gate, before the edit) =="
# "if I add Net to pricing.quote, what propagates and does it break policy?" — answered BEFORE writing
# code. Layers are PACKAGES (scopeMatches is segment-aware on '.'); reuses Candor.parsePolicy/scopeMatches
# so the verdict equals what the real gate would do.
mkdir -p "$W/wi/com/ex/pricing" "$W/wi/com/ex/api"
printf 'package com.ex.pricing; public class P { public static int quote(int c){ return c; } }\n' > "$W/wi/com/ex/pricing/P.java"
printf 'package com.ex.api; import com.ex.pricing.P; public class A { public static int handle(int c){ return P.quote(c); } }\n' > "$W/wi/com/ex/api/A.java"
javac -d "$W/wicls" $(find "$W/wi" -name '*.java') 2>/dev/null
"$CJ" "$W/wicls" --json "$W/wi.json" >/dev/null 2>&1
printf 'deny Net api\n' > "$W/wipol"
wi="$("$CJ" whatif "$W/wi.json" quote Net "$W/wipol")"
want   "whatif: adding Net propagates to the transitive caller" "$wi" 'com.ex.api.A.handle'
want   "whatif: returns the WOULD-VIOLATE verdict"              "$wi" 'WOULD VIOLATE policy'
want   "whatif: names the violating fn + the rule"             "$wi" '`com.ex.api.A.handle`  (rule: `deny Net api`)'
want   "whatif --json: ok=false on a violation"                "$("$CJ" whatif "$W/wi.json" quote Net "$W/wipol" --json)" '"ok": false'
want   "whatif: a non-denied effect is within policy"          "$("$CJ" whatif "$W/wi.json" quote Db "$W/wipol")" 'within policy'

echo "== rewire: the de-wiring detector (catch a 'fix' that games the gate by disconnecting a call) =="
# A method that DROPS a call it made in the baseline — how an agent satisfies an effect gate by
# disconnecting functionality (the gate passes, the feature breaks). The effect diff can't see it; the
# call graph can. baseline: A.handle calls B.work; gamed: A.handle no longer calls it.
mkdir -p "$W/rw/base/p/a" "$W/rw/base/p/b" "$W/rw/gamed/p/a" "$W/rw/gamed/p/b"
printf 'package p.b; public class B { public static int work(int c){ return c*2; } }\n' | tee "$W/rw/base/p/b/B.java" > "$W/rw/gamed/p/b/B.java"
printf 'package p.a; import p.b.B; public class A { public static int handle(int c){ return B.work(c); } }\n' > "$W/rw/base/p/a/A.java"
printf 'package p.a; public class A { public static int handle(int c){ return c; } }\n' > "$W/rw/gamed/p/a/A.java"   # de-wired
javac -d "$W/rw/bcls" $(find "$W/rw/base"  -name '*.java') 2>/dev/null
javac -d "$W/rw/gcls" $(find "$W/rw/gamed" -name '*.java') 2>/dev/null
"$CJ" "$W/rw/bcls" --json "$W/rw/base.json"  >/dev/null 2>&1
"$CJ" "$W/rw/gcls" --json "$W/rw/gamed.json" >/dev/null 2>&1
rw="$("$CJ" rewire "$W/rw/gamed.json" "$W/rw/base.json")"
want   "rewire: flags the dropped call (de-wiring)"      "$rw" 'p.a.A.handle  ⊘  no longer calls: p.b.B.work'
want   "rewire --json: ok=false when an edge is dropped" "$("$CJ" rewire "$W/rw/gamed.json" "$W/rw/base.json" --json)" '"ok": false'
want   "rewire: clean when nothing is de-wired"          "$("$CJ" rewire "$W/rw/base.json" "$W/rw/base.json")" 'nothing de-wired'

# ── JPA declarative tables: @Table(name) + the repository's generic signature → `tables` ─────────
echo "== JPA declarative tables =="
javac -d "$W/jpa" $(find spring-sample -name '*.java') 2>/dev/null
"$CJ" "$W/jpa/com/example" --json "$W/jpa.json" >/dev/null 2>&1
JPA_SVC=$(python3 -c "import json; r=json.load(open('$W/jpa.json')); print(next((f.get('tables') for f in r['functions'] if f['fn']=='com.example.UserService.register'), []))")
want "register carries the declared table"            "$JPA_SVC" "users"
JPA_CTL=$(python3 -c "import json; r=json.load(open('$W/jpa.json')); print(next((f.get('tables') for f in r['functions'] if f['fn']=='com.example.UserController.get'), []))")
want "the controller inherits it transitively"        "$JPA_CTL" "users"
printf 'allow Db in example accounts\n' > "$W/jpa.pol"
JPA_GATE=$(CANDOR_POLICY="$W/jpa.pol" "$CJ" "$W/jpa/com/example" 2>&1 | grep "AS-EFF-008" | head -1)
want "the table allowlist gates the declared surface" "$JPA_GATE" "reaches { users }"

# ── SQL tables: multi-line literals + the opaque (no-literal) gate case ──────────────────────────
echo "== SQL tables: multi-line literals + the opaque gate case =="
# The \n-without-indent form is the regression: split("\s+") written with a single backslash is the
# Java space ESCAPE, so "orders\njoin" stayed one token and both tables vanished from the surface.
mkdir -p "$W/sql/q"
cat > "$W/sql/q/Dao.java" <<'J'
package q;
import java.sql.*;
public class Dao {
    public static void multi(Connection c) throws SQLException {
        String q = "SELECT o.id\nFROM orders\nJOIN ledger.entries le ON le.oid = o.id";
        c.prepareStatement(q).executeQuery();
    }
    public static void opaque(Connection c, String sql) throws SQLException {
        c.prepareStatement(sql).executeQuery();
    }
}
J
javac -d "$W/sqlcls" "$W/sql/q/Dao.java" 2>/dev/null
"$CJ" "$W/sqlcls" --json "$W/sql.json" >/dev/null 2>&1
SQL_TBL=$(python3 -c "import json; r=json.load(open('$W/sql.json')); print(next((f.get('tables') for f in r['functions'] if f['fn']=='q.Dao.multi'), []))")
want "multi-line SQL: FROM table extracted across \\n"  "$SQL_TBL" "orders"
want "multi-line SQL: qualified JOIN table too"          "$SQL_TBL" "ledger.entries"
printf 'allow Db in q customers\n' > "$W/sql.pol"
SQL_GATE=$(CANDOR_POLICY="$W/sql.pol" "$CJ" "$W/sqlcls" 2>&1)
want "the allowlist flags the reached tables"            "$SQL_GATE" "reaches { ledger.entries, orders }"
want "Db with NO visible literal cannot be certified"    "$SQL_GATE" '`q.Dao.opaque` performs Db with no visible literal'
# Per-rule semantics (SEMANTICS AS-EFF-008 quantifies over each rule; values are NOT unioned across
# rules): two half-covering rules must each still flag, exactly like the Rust gate.
printf 'allow Db in q orders\nallow Db in q ledger.*\n' > "$W/sql2.pol"
SQL_PERRULE=$(CANDOR_POLICY="$W/sql2.pol" "$CJ" "$W/sqlcls" 2>&1 | grep -c "AS-EFF-008.*q\.Dao\.multi")
want "two half-covering allow rules don't pass by union" "$SQL_PERRULE" "2"

# ── κ-coverage ledger: an unlisted external package the code calls is NAMED in the receipt ───────
echo "== κ-coverage ledger =="
mkdir -p "$W/kap/src/com/thirdparty/json" "$W/kap/src/org/acme"
cat > "$W/kap/src/com/thirdparty/json/Mapper.java" <<'J'
package com.thirdparty.json;
public class Mapper { public String render(Object o) { return o.toString(); } }
J
cat > "$W/kap/src/org/acme/App.java" <<'J'
package org.acme;
import com.thirdparty.json.Mapper;
public class App {
    public static String run() throws Exception {
        java.nio.file.Files.readString(java.nio.file.Path.of("/tmp/x"));
        return new Mapper().render("x");
    }
}
J
javac -d "$W/kap/dep" "$W/kap/src/com/thirdparty/json/Mapper.java" 2>/dev/null
javac -cp "$W/kap/dep" -d "$W/kap/app" "$W/kap/src/org/acme/App.java" 2>/dev/null
KAP=$("$CJ" "$W/kap/app" 2>&1)
want   "unlisted external package named in the receipt" "$KAP" "classifier doesn't cover 1 package"
want   "with its grouped name and call count"           "$KAP" "com.thirdparty.json (2 calls)"
absent "the JDK frontier stays out of the ledger"       "$KAP" "java.nio"

# ── dep-JAR chaining: scan a dependency jar once, CANDOR_DEPS carries it into the app scan ───────
echo "== dep-jar chaining =="
mkdir -p "$W/djc/src/com/thirdparty/io" "$W/djc/src/org/acme2"
cat > "$W/djc/src/com/thirdparty/io/Loader.java" <<'J'
package com.thirdparty.io;
public class Loader {
    public String load(String p) throws Exception {
        return java.nio.file.Files.readString(java.nio.file.Path.of(p));
    }
}
J
cat > "$W/djc/src/org/acme2/App2.java" <<'J'
package org.acme2;
import com.thirdparty.io.Loader;
public class App2 {
    public static String run() throws Exception { return new Loader().load("/tmp/x"); }
}
J
javac -d "$W/djc/depcls" "$W/djc/src/com/thirdparty/io/Loader.java" 2>/dev/null
jar cf "$W/djc/dep.jar" -C "$W/djc/depcls" . 2>/dev/null
javac -cp "$W/djc/dep.jar" -d "$W/djc/app" "$W/djc/src/org/acme2/App2.java" 2>/dev/null
"$CJ" "$W/djc/dep.jar" --json "$W/djc/dep.json" >/dev/null 2>&1
DJC_HASH=$(python3 -c "import json; r=json.load(open('$W/djc/dep.json')); print(next((f.get('hash','') for f in r['functions'] if f['fn']=='com.thirdparty.io.Loader.load'), ''))")
want "the dep JAR scan emits the method-ref hash"  "$DJC_HASH" "com/thirdparty/io/Loader.load"
DJC_PLAIN=$("$CJ" "$W/djc/app" 2>&1)
absent "without CANDOR_DEPS the dep call is invisible"      "$DJC_PLAIN" "App2.run"
want   "…and the κ ledger names the blind spot"             "$DJC_PLAIN" "com.thirdparty.io"
DJC_CHAIN=$(CANDOR_DEPS="$W/djc/dep.json" "$CJ" "$W/djc/app" 2>&1)
want   "with CANDOR_DEPS the app inherits the jar's effect" "$(echo "$DJC_CHAIN" | grep App2.run)" '{ Fs* }'
absent "…and the chained package leaves the coverage ledger" "$DJC_CHAIN" "classifier doesn't cover"
# An ALL-PURE dep's EMPTY report in SPEC singular-`package` form must register coverage (SPEC §2
# rule 3) — reading only `packages[]` (the JVM's own plural) ignored it and falsely named the
# package a blind spot. (/code-review max: the spec + the Rust/TS producers emit singular `package`.)
#
# The version must be THIS BUILD's. It was hardcoded `"x"` — i.e. permanently STALE — so this row was
# really asserting that an UNTRUSTED report grants coverage, the §2.1 defect pinned as a requirement.
# Coverage is what silences the κ ledger for every key a report OMITS, and a report whose producing
# build cannot be verified has no standing to silence anything. Both directions are rows now; the
# singular-vs-plural `package` reading this row exists for is untouched.
#
# ⟨0.24⟩ THE FIXTURE NOW CARRIES `analyzed`, AND THAT IS THE RUNG, NOT AN ADJUSTMENT MADE TO SUIT IT. This
# row is about READING the singular `package` key, so it needs a report whose silence is a real claim —
# and ⟨0.24⟩ is what makes `functions: []` say which of the two things it means. `count: 3` = "I judged
# three units and none of them has an effect", which SPEC §2 chaining rule 3 says to believe, so this row
# asserts exactly what it always did. Left without the field it would have become the row two below: a
# producer that cannot say whether it judged anything, which falls back to the unchained reading.
# (The label's backticks are escaped now: unescaped in a double-quoted string they were COMMAND
# SUBSTITUTION, so this row has been printing "a singular- empty report" and running `package`.)
DJC_OWNVER=$(python3 -c "import json; print(json.load(open('$W/djc/dep.json'))['candor']['version'])")
printf '{"candor":{"version":"%s","spec":"0.4"},"package":"com.thirdparty.io","analyzed":{"count":3},"functions":[]}' \
    "$DJC_OWNVER" > "$W/djc/empty-pkg.json"
DJC_EMPTY=$(CANDOR_DEPS="$W/djc/empty-pkg.json" "$CJ" "$W/djc/app" 2>&1)
absent "a singular-\`package\` all-pure report covers its package (no false blind spot)" "$DJC_EMPTY" "classifier doesn't cover"
# ⟨0.24⟩ THE SAME FILE WITH ONE INTEGER CHANGED — the whole rung, on the stderr channel. `count: 0` says
# the producer judged NOTHING, so it has no silence to offer and its package goes back to being a named
# blind spot: chaining a report must never buy more confidence than not chaining it at all. Before the fix
# both spellings were answered identically and this arm was silent and exit 0.
printf '{"candor":{"version":"%s","spec":"0.4"},"package":"com.thirdparty.io","analyzed":{"count":0},"functions":[]}' \
    "$DJC_OWNVER" > "$W/djc/empty-pkg-zero.json"
DJC_EMPTY_ZERO=$(CANDOR_DEPS="$W/djc/empty-pkg-zero.json" "$CJ" "$W/djc/app" 2>&1)
want   "…but \`analyzed.count: 0\` judged NOTHING, so its package stays a blind spot" "$DJC_EMPTY_ZERO" "classifier doesn't cover"
want   "…and the run says so on stderr, naming the report"                           "$DJC_EMPTY_ZERO" "judged NOTHING"
# ⟨0.24⟩ row 3: a pre-⟨0.21⟩ producer has no manifest, so nothing on the wire says whether it judged
# anything — it falls back to the unchained reading. This is a CHANGE to what this engine did before the
# rung (a manifest-less empty report used to buy full coverage), and it is the spec's third row, not an
# extrapolation from the first.
printf '{"candor":{"version":"%s","spec":"0.4"},"package":"com.thirdparty.io","functions":[]}' \
    "$DJC_OWNVER" > "$W/djc/empty-pkg-nomanifest.json"
DJC_EMPTY_NOMAN=$(CANDOR_DEPS="$W/djc/empty-pkg-nomanifest.json" "$CJ" "$W/djc/app" 2>&1)
want   "…and a manifest-LESS empty report makes no claim either (⟨0.24⟩ row 3)" "$DJC_EMPTY_NOMAN" "classifier doesn't cover"
printf '{"candor":{"version":"%s-NOT-THIS-BUILD","spec":"0.4"},"package":"com.thirdparty.io","functions":[]}' \
    "$DJC_OWNVER" > "$W/djc/empty-pkg-stale.json"
DJC_EMPTY_STALE=$(CANDOR_DEPS="$W/djc/empty-pkg-stale.json" "$CJ" "$W/djc/app" 2>&1)
want   "…but a STALE empty report grants NO coverage (§2.1: no trust, no silence)" "$DJC_EMPTY_STALE" "classifier doesn't cover"
want   "…and the run says so, naming the other build"                              "$DJC_EMPTY_STALE" "not this one"

# ── chained LITERAL SURFACES + empty-report coverage + array owners (/code-review fixes) ─────────
echo "== chained surfaces, empty-report coverage, array owners =="
# (a) a dep doing Db on a named table; the app's `allow Db` must see the INHERITED tables surface
mkdir -p "$W/sj/dep/com/dbl" "$W/sj/app/org/uses"
cat > "$W/sj/dep/com/dbl/Repo.java" <<'J'
package com.dbl;
public class Repo {
    public void post() throws Exception {
        java.sql.DriverManager.getConnection("jdbc:x").prepareStatement("INSERT INTO ledger.entries VALUES (1)").executeQuery();
    }
}
J
cat > "$W/sj/app/org/uses/Svc.java" <<'J'
package org.uses;
public class Svc {
    public static void settle() throws Exception { new com.dbl.Repo().post(); }
}
J
javac -d "$W/sj/depcls" "$W/sj/dep/com/dbl/Repo.java" 2>/dev/null
javac -cp "$W/sj/depcls" -d "$W/sj/appcls" "$W/sj/app/org/uses/Svc.java" 2>/dev/null
"$CJ" "$W/sj/depcls" --json "$W/sj/dep.json" >/dev/null 2>&1
SJ_TBL=$(CANDOR_DEPS="$W/sj/dep.json" "$CJ" "$W/sj/appcls" --json "$W/sj/app.json" >/dev/null 2>&1; python3 -c "import json; r=json.load(open('$W/sj/app.json')); print(next((f.get('tables') for f in r['functions'] if f['fn']=='org.uses.Svc.settle'), []))")
want "the chain inherits the dep's tables surface"       "$SJ_TBL" "ledger.entries"
printf 'allow Db in uses ledger.*\n' > "$W/sj/pol"
SJ_GATE=$(CANDOR_DEPS="$W/sj/dep.json" CANDOR_POLICY="$W/sj/pol" "$CJ" "$W/sj/appcls" 2>&1)
absent "an inherited surface satisfies the allowlist (no cannot-be-certified)" "$SJ_GATE" "cannot be certified"
# (b) an all-pure dep's EMPTY report still covers its package (the serde_json rule, ported)
mkdir -p "$W/sj/pure/com/pure"
printf 'package com.pure;\npublic class Calc { public static int add(int a, int b) { return a + b; } }\n' > "$W/sj/pure/com/pure/Calc.java"
javac -d "$W/sj/purecls" "$W/sj/pure/com/pure/Calc.java" 2>/dev/null
"$CJ" "$W/sj/purecls" --json "$W/sj/pure.json" >/dev/null 2>&1
mkdir -p "$W/sj/app2/org/uses2"
cat > "$W/sj/app2/org/uses2/U.java" <<'J'
package org.uses2;
public class U { public static int go() { java.nio.file.Path.of("/x"); return com.pure.Calc.add(1, 2); } }
J
javac -cp "$W/sj/purecls" -d "$W/sj/app2cls" "$W/sj/app2/org/uses2/U.java" 2>/dev/null
SJ_PURE=$(CANDOR_DEPS="$W/sj/pure.json" "$CJ" "$W/sj/app2cls" 2>&1)
absent "an all-pure dep's EMPTY report covers its package"  "$SJ_PURE" "com.pure"
# (c) array-type owners (enum values()' clone) never reach the ledger
mkdir -p "$W/sj/arr/org/arr"
printf 'package org.arr;\npublic class A { public static String[] dup(String[] xs) { return xs.clone(); } }\n' > "$W/sj/arr/org/arr/A.java"
javac -d "$W/sj/arrcls" "$W/sj/arr/org/arr/A.java" 2>/dev/null
SJ_ARR=$("$CJ" "$W/sj/arrcls" 2>&1)
absent "array owners stay out of the ledger"                "$SJ_ARR" "classifier doesn't cover"

# ── literal-getMethod reflection: the named target's effects flow; Unknown stays ─────────────────
echo "== literal-getMethod reflection =="
mkdir -p "$W/refl"
cat > "$W/refl/R.java" <<'J'
public class R {
    static void target() throws Exception { java.nio.file.Files.readString(java.nio.file.Path.of("/x")); }
    static void caller() throws Exception { R.class.getMethod("target").invoke(null); }
}
J
javac -d "$W/reflcls" "$W/refl/R.java" 2>/dev/null
REFL=$("$CJ" "$W/reflcls" 2>&1 | grep "R.caller")
want "a literal getMethod target's effects flow to the reflector" "$REFL" "Fs*"
want "…and reflection keeps its honest Unknown"                   "$REFL" "Unknown"

# ── reflection MUST NOT fabricate across an unrelated receiver (the /code-review max find) ────────
echo "== reflection fabrication guard =="
mkdir -p "$W/refl2"
cat > "$W/refl2/F.java" <<'J'
public class F {
    static void strip() throws Exception { java.nio.file.Files.readString(java.nio.file.Path.of("/x")); }   // project method named strip, does Fs
    static void runIt() throws Exception { Runtime.getRuntime().exec("x"); }                                  // project method named runIt, does Exec
    static void extRecv() throws Exception { String.class.getMethod("strip").invoke("y"); }                   // EXTERNAL receiver, name collides with F.strip
    static void dynRecv(Object o) throws Exception { o.getClass().getMethod("strip").invoke(o); }             // runtime receiver
    static void wrongLit() throws Exception { String tag = "runIt"; String.class.getMethod("strip").invoke("z"); } // nearest literal is "strip", not "runIt"
}
J
javac -d "$W/refl2cls" "$W/refl2/F.java" 2>/dev/null
absent "external-receiver reflection does NOT fabricate Fs onto the caller" "$("$CJ" "$W/refl2cls" 2>/dev/null | grep 'F.extRecv')" "Fs\*"
absent "runtime-receiver reflection does NOT fabricate an edge"             "$("$CJ" "$W/refl2cls" 2>/dev/null | grep 'F.dynRecv')"  "Fs\*"
absent "nearest-literal: an unrelated prior constant never fabricates Exec" "$("$CJ" "$W/refl2cls" 2>/dev/null | grep 'F.wrongLit')" "Exec\*"

echo "== --parallel: one JVM, N targets — collision refusal + per-target failure honesty =="
# happy path: two targets, one report each (byte-identical to standalone runs is gated by the LB-1b
# reentrancy suite; here we pin the CLI contract: files land, exit 0)
mkdir -p "$W/par"
jar cf "$W/par/fx.jar" -C "$W/cls" . 2>/dev/null
jar cf "$W/par/app.jar" -C "$W/acls" . 2>/dev/null
pout="$("$CJ" --parallel "$W/par/out" "$W/par/fx.jar" "$W/par/app.jar" 2>&1)"; prc=$?
want "parallel: scans both targets"                    "$pout" 'scanned 2 target(s)'
if [ "$prc" -eq 0 ]; then echo "  ok   parallel happy path exits 0"; pass=$((pass+1));
else echo "  FAIL parallel happy path — exit $prc"; fail=$((fail+1)); fi
[ -s "$W/par/out/fx.json" ] && [ -s "$W/par/out/app.json" ] \
  && { echo "  ok   parallel: one report per target"; pass=$((pass+1)); } \
  || { echo "  FAIL parallel: missing fx.json/app.json"; fail=$((fail+1)); }
want "parallel report is a real report"                "$(cat "$W/par/out/fx.json")" '"Fx.reads"'
# basename COLLISION: moduleA/app.jar + moduleB/app.jar would both write app.json — silently clobbering
# one report reads as a false PASS downstream. Refuse up front (exit 2), name both paths.
mkdir -p "$W/par/modA" "$W/par/modB"
cp "$W/par/app.jar" "$W/par/modA/app.jar"; cp "$W/par/fx.jar" "$W/par/modB/app.jar"
pcol="$("$CJ" --parallel "$W/par/out2" "$W/par/modA/app.jar" "$W/par/modB/app.jar" 2>&1)"; pcolrc=$?
want "parallel: collision refusal names the clash"     "$pcol" 'output collision'
if [ "$pcolrc" -eq 2 ]; then echo "  ok   parallel collision exits 2 (refused up front)"; pass=$((pass+1));
else echo "  FAIL parallel collision — exit $pcolrc (want 2)"; fail=$((fail+1)); fi
# a jar.zip pair collides too (the extension is stripped from the output basename)
cp "$W/par/fx.jar" "$W/par/fx.zip"
pzip="$("$CJ" --parallel "$W/par/out3" "$W/par/fx.jar" "$W/par/fx.zip" 2>&1)"; pziprc=$?
if [ "$pziprc" -eq 2 ]; then echo "  ok   parallel: fx.jar + fx.zip collide on fx.json (exit 2)"; pass=$((pass+1));
else echo "  FAIL parallel jar/zip collision — exit $pziprc (want 2)"; fail=$((fail+1)); fi
# one missing target of three: the run FAILS (exit 1) and names it, but the good reports still land —
# a crashing target must never vanish under a green exit, and the healthy work isn't thrown away.
pmiss="$("$CJ" --parallel "$W/par/out4" "$W/par/fx.jar" "$W/no-such.jar" "$W/par/app.jar" 2>&1)"; pmissrc=$?
want "parallel: the missing target is named"           "$pmiss" 'no-such.jar (no such path)'
want "parallel: failure count over total"              "$pmiss" '1 of 3 target(s) failed'
if [ "$pmissrc" -eq 1 ]; then echo "  ok   parallel partial failure exits 1"; pass=$((pass+1));
else echo "  FAIL parallel partial failure — exit $pmissrc (want 1)"; fail=$((fail+1)); fi
[ -s "$W/par/out4/fx.json" ] && [ -s "$W/par/out4/app.json" ] \
  && { echo "  ok   parallel: the good reports still written"; pass=$((pass+1)); } \
  || { echo "  FAIL parallel: good reports missing after partial failure"; fail=$((fail+1)); }
# usage guard: fewer than 2 args after the flag is a misuse, not a silent no-op
"$CJ" --parallel "$W/par/only-outdir" >/dev/null 2>&1; purc=$?
if [ "$purc" -eq 2 ]; then echo "  ok   parallel usage error exits 2"; pass=$((pass+1));
else echo "  FAIL parallel usage — exit $purc (want 2)"; fail=$((fail+1)); fi

# ── CANDOR_STRICT conformance gate (AS-EFF-001/002/003, SEMANTICS §6 through the DI reading) ─────
# The gate that shipped for months with zero coverage in ANY harness (TESTING.md §2 pin 1): a class's
# injected-collaborator fields are its declared capabilities; performing beyond them fires 001, an
# unused capability fires 002, an unresolvable call fires 003. Exit codes exact: violation 1, clean 0.
echo "== CANDOR_STRICT conformance gate =="
mkdir -p "$W/strict/app"
cat > "$W/strict/app/FsWorker.java" <<'J'
package app;
import java.nio.file.*;
public class FsWorker { public void doIt() { try { Files.readAllBytes(Path.of("/tmp/x")); } catch (Exception e) {} } }
J
cat > "$W/strict/app/Svc.java" <<'J'
package app;
public class Svc {
  private final FsWorker w = new FsWorker();
  public void run() { w.doIt(); }
}
J
cat > "$W/strict/app/Holder.java" <<'J'
package app;
public class Holder {
  private FsWorker w;   // injected, never used
  public int idle() { return 1; }
}
J
cat > "$W/strict/app/Refl.java" <<'J'
package app;
public class Refl {
  public Object go(String n) throws Exception { return Class.forName(n).getDeclaredConstructor().newInstance(); }
}
J
javac -d "$W/strictcls" "$W/strict/app"/*.java
# whole-unit: the leaf FsWorker reaches for ambient Fs with no injected capability → AS-EFF-001, exit 1
sv="$(CANDOR_STRICT=1 "$CJ" "$W/strictcls" 2>&1)"; svrc=$?
want "whole-unit CANDOR_STRICT fires AS-EFF-001 on the capability-less leaf" "$sv" '[AS-EFF-001]'
want "the AS-EFF-001 diagnostic names the class"                             "$sv" 'app.FsWorker'
if [ "$svrc" -eq 1 ]; then echo "  ok   a conformance violation exits 1"; pass=$((pass+1));
else echo "  FAIL strict violation exit $svrc (want 1)"; fail=$((fail+1)); fi
# scoped to the conformant consumer: its collaborator covers the Fs it performs → clean, exit 0
sc="$(CANDOR_STRICT=app.Svc "$CJ" "$W/strictcls" 2>&1)"; scrc=$?
want    "scoped CANDOR_STRICT passes the conformant class" "$sc" 'no violations'
wantnot "the out-of-scope violation is not evaluated"      "$sc" 'AS-EFF-001'
if [ "$scrc" -eq 0 ]; then echo "  ok   a clean scoped gate exits 0"; pass=$((pass+1));
else echo "  FAIL clean strict exit $scrc (want 0)"; fail=$((fail+1)); fi
# an injected-but-unused capability → AS-EFF-002, exit 1
h="$(CANDOR_STRICT=app.Holder "$CJ" "$W/strictcls" 2>&1)"; hrc=$?
want "an unused injected capability fires AS-EFF-002" "$h" '[AS-EFF-002]'
if [ "$hrc" -eq 1 ]; then echo "  ok   AS-EFF-002 exits 1"; pass=$((pass+1));
else echo "  FAIL AS-EFF-002 exit $hrc (want 1)"; fail=$((fail+1)); fi
# an unresolvable (reflective) call → AS-EFF-003 (not provably complete), exit 1; never a 001
rl="$(CANDOR_STRICT=app.Refl "$CJ" "$W/strictcls" 2>&1)"; rlrc=$?
want    "an unresolved call fires AS-EFF-003"                       "$rl" '[AS-EFF-003]'
wantnot "Unknown never reads as an AS-EFF-001 undeclared effect"    "$rl" 'AS-EFF-001'
if [ "$rlrc" -eq 1 ]; then echo "  ok   AS-EFF-003 exits 1"; pass=$((pass+1));
else echo "  FAIL AS-EFF-003 exit $rlrc (want 1)"; fail=$((fail+1)); fi
# SPEC §6: the program entry point (psvm main) is exempt from AS-EFF-001 — it mints the bundle
mkdir -p "$W/strictmain/app"
cat > "$W/strictmain/app/Main.java" <<'J'
package app;
import java.nio.file.*;
public class Main { public static void main(String[] a) throws Exception { Files.writeString(Path.of("/tmp/x"), "y"); } }
J
javac -d "$W/strictmaincls" "$W/strictmain/app/Main.java"
em="$(CANDOR_STRICT=1 "$CJ" "$W/strictmaincls" 2>&1)"; emrc=$?
want "the psvm entry class is exempt from AS-EFF-001 (SPEC §6)" "$em" 'no violations'
if [ "$emrc" -eq 0 ]; then echo "  ok   entry-point exemption exits 0"; pass=$((pass+1));
else echo "  FAIL entry-exemption exit $emrc (want 0)"; fail=$((fail+1)); fi

# ── CANDOR_TAINT (AS-EFF-007): heuristic ADVISORY — findings print, CI never fails on them ───────
echo "== CANDOR_TAINT advisory =="
mkdir -p "$W/taint/app"
cat > "$W/taint/app/Tnt.java" <<'J'
package app;
public class Tnt {
  public void go(String p, boolean c) {
    String x = "safe";
    if (c) x = p;   // tainted on one branch only — the control-flow-join rule
    try { Runtime.getRuntime().exec(x); } catch (Exception e) {}
  }
}
J
javac -d "$W/taintcls" "$W/taint/app/Tnt.java"
tn="$(CANDOR_TAINT=1 "$CJ" "$W/taintcls" 2>&1)"; tnrc=$?
want "a branch-join tainted arg at an Exec sink prints AS-EFF-007" "$tn" '[AS-EFF-007]'
want "the advisory names the injection surface"                    "$tn" 'caller-derived input'
if [ "$tnrc" -eq 0 ]; then echo "  ok   AS-EFF-007 is advisory — findings never fail CI (exit 0)"; pass=$((pass+1));
else echo "  FAIL CANDOR_TAINT advisory exit $tnrc (want 0)"; fail=$((fail+1)); fi

# ── CLI surface: --help / --version / bare --json stdout purity / the empty-scan advice ──────────
echo "== CLI surface: --help, --version, bare --json, empty scan =="
hp="$("$CJ" --help 2>&1)"; hprc=$?
want "--help shows usage"                          "$hp" 'USAGE'
want "--help shows the scan form"                  "$hp" 'candor <classes-or-jar>'
want "--help names the gate flag"                  "$hp" '--gate-json'
wantnot "--help leaves the spec disclosure to --version" "$hp" 'candor-spec'
if [ "$hprc" -eq 0 ]; then echo "  ok   --help exits 0"; pass=$((pass+1));
else echo "  FAIL --help exit $hprc (want 0)"; fail=$((fail+1)); fi
hs="$("$CJ" -h 2>&1)"
want "-h is the same surface"                      "$hs" 'USAGE'
vv="$("$CJ" --version 2>&1)"; vvrc=$?
want    "--version prints the release + spec"      "$vv" "(spec $SPEC_DECLARED)"
want    "--version prints the upgrade line"        "$vv" 'jbang --fresh'
wantnot "--version release is baked (not the 'unknown' fallback)" "$vv" 'candor-java unknown'
if [ "$vvrc" -eq 0 ]; then echo "  ok   --version exits 0"; pass=$((pass+1));
else echo "  FAIL --version exit $vvrc (want 0)"; fail=$((fail+1)); fi
vshort="$("$CJ" -V 2>&1)"
if [ "$vshort" = "$vv" ]; then echo "  ok   -V and --version agree byte-for-byte"; pass=$((pass+1));
else echo "  FAIL -V and --version disagree"; fail=$((fail+1)); fi
# bare --json (no file value): the report ENVELOPE streams to stdout as PURE JSON; every human line
# (the progress line, the effect summary) goes to stderr; no sidecar files are written.
mkdir -p "$W/jsonstdout" && cd "$W/jsonstdout"
"$CJ" "$W/cls" --json > "$W/js.out" 2> "$W/js.err"; jsrc=$?
cd "$ROOT"
want "bare --json stdout is a whole JSON report envelope" \
     "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("ENVELOPE" if "candor" in d and "functions" in d else "BAD")' "$W/js.out" 2>/dev/null)" 'ENVELOPE'
want    "the progress line goes to stderr"          "$(cat "$W/js.err")" 'to stdout'
want    "the human effect summary goes to stderr"   "$(cat "$W/js.err")" 'reach effects'
wantnot "no human text pollutes stdout"             "$(cat "$W/js.out")" 'reach effects'
sidecars="$(ls "$W/jsonstdout" 2>/dev/null)"
if [ -z "$sidecars" ]; then echo "  ok   bare --json writes no sidecar files"; pass=$((pass+1));
else echo "  FAIL bare --json left files behind: $sidecars"; fail=$((fail+1)); fi
if [ "$jsrc" -eq 0 ]; then echo "  ok   bare --json exits 0"; pass=$((pass+1));
else echo "  FAIL bare --json exit $jsrc (want 0)"; fail=$((fail+1)); fi
# an existing path with NO .class files: fail loud with the build advice (a source dir must never
# read as "clean, pure project"), exit 2
mkdir -p "$W/emptydir"
es="$("$CJ" "$W/emptydir" 2>&1)"; esrc=$?
want "an empty scan says no .class files were found" "$es" 'no .class files found'
want "…and points at compiled output"                "$es" 'reads BYTECODE'
if [ "$esrc" -eq 2 ]; then echo "  ok   an empty scan exits 2 (never a trivially-green gate)"; pass=$((pass+1));
else echo "  FAIL empty scan exit $esrc (want 2)"; fail=$((fail+1)); fi

# ── fail-closed residuals: unreadable deps DIRECTORY walk + exists-but-unreadable config ─────────
echo "== fail-closed residuals: unreadable deps dir, unreadable config =="
if [ "$(id -u)" -eq 0 ]; then
  echo "  SKIP (loud): running as root — chmod-000 stays readable, the two unreadable-path pins cannot run"
else
  # CANDOR_DEPS names a directory that exists but cannot be WALKED (the Files.walk IOException arm —
  # distinct from the not-a-file token arm already pinned above): exit 2, never silently-pure deps.
  mkdir -p "$W/depsdir-noread"; : > "$W/depsdir-noread/lib.json"; chmod 000 "$W/depsdir-noread"
  dw="$(CANDOR_DEPS="$W/depsdir-noread" "$CJ" "$W/cls" 2>&1)"; dwrc=$?
  chmod 755 "$W/depsdir-noread"
  want "an unwalkable CANDOR_DEPS dir is named" "$dw" 'CANDOR_DEPS cannot read'
  if [ "$dwrc" -eq 2 ]; then echo "  ok   unwalkable deps dir exits 2"; pass=$((pass+1));
  else echo "  FAIL unwalkable deps dir exit $dwrc (want 2)"; fail=$((fail+1)); fi
  # a DISCOVERED .candor/config that exists but cannot be read: the file may carry the policy —
  # a silently-dropped config is a silently-dropped gate. Exit 2 (spec §3.4 fail-closed).
  mkdir -p "$W/cfgnoread/.candor"
  printf 'policy .candor/arch.policy\n' > "$W/cfgnoread/.candor/config"
  cp -r "$W/cls" "$W/cfgnoread/build-cls"
  chmod 000 "$W/cfgnoread/.candor/config"
  cn="$("$CJ" "$W/cfgnoread/build-cls" 2>&1)"; cnrc=$?
  chmod 644 "$W/cfgnoread/.candor/config"
  want "an unreadable discovered config is named" "$cn" 'exists but could not be read'
  if [ "$cnrc" -eq 2 ]; then echo "  ok   exists-but-unreadable config exits 2"; pass=$((pass+1));
  else echo "  FAIL unreadable config exit $cnrc (want 2)"; fail=$((fail+1)); fi
fi

# ── ⟨0.24⟩ SPEC §6.2 `--class`: the reason-class filter, over the SHIPPED launcher ────────────────
# Driven end-to-end and PARSED, not unit-tested: the two things under test are an exit CODE and a JSON
# document, and a unit test that calls the function can agree with a binary that prints something else.
# The fixture is hand-written (no scan, no compiler) because every §6.2 consumer surface is a pure
# function of a REPORT + a policy — which is also what lets the four-engine conformance differential
# (PART 27) hand every engine the same bytes.
echo "== --class reason-class filter (§6.2) =="
mkdir -p "$W/cls6"
cat > "$W/cls6/r.json" <<'J'
{ "candor": {"version":"handwritten","spec":"0.23"}, "package": "app",
  "analyzed": {"count":7,"digest":"0"},
  "functions": [
    {"fn":"app.a_reasonless_only","inferred":["Unknown"],"calls":["app.src_reasonless"]},
    {"fn":"app.b_reasoned_only","inferred":["Unknown"],"calls":["app.src_reasoned"]},
    {"fn":"app.c_both","inferred":["Unknown"],"calls":["app.src_reasonless","app.src_reasoned"]},
    {"fn":"app.d_named_direct","inferred":["Unknown"],"direct":["Unknown"],
     "unknownWhy":["reflect:Method.invoke","native:strlen"]},
    {"fn":"app.e_named_inherited","inferred":["Unknown"],"calls":["app.d_named_direct"]},
    {"fn":"app.src_reasonless","inferred":["Unknown"],"direct":["Unknown"],"unknownWhy":[]},
    {"fn":"app.src_reasoned","inferred":["Unknown"],"direct":["Unknown"],
     "unknownWhy":["dispatch:app.Base.run"]} ] }
J
cat > "$W/cls6/r.callgraph.json" <<'J'
{ "app.a_reasonless_only":["app.src_reasonless"], "app.b_reasoned_only":["app.src_reasoned"],
  "app.c_both":["app.src_reasonless","app.src_reasoned"], "app.d_named_direct":[],
  "app.e_named_inherited":["app.d_named_direct"], "app.src_reasonless":[], "app.src_reasoned":[] }
J
# the same report plus ONE entry whose only class is `setup` — `dynamic` aliases every GENUINE class,
# which by its own definition EXCLUDES setup, so the invariant is "unfiltered MINUS setup-only". Stated
# flatly ("dynamic excludes nothing") it would fail on any corpus carrying a setup reason.
python3 - "$W/cls6/r.json" "$W/cls6/s.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
r["functions"].append({"fn": "app.f_setup_only", "inferred": ["Unknown"], "direct": ["Unknown"],
                       "unknownWhy": ["missing-config"]})
r["analyzed"]["count"] = len(r["functions"])
json.dump(r, open(sys.argv[2], "w"))
json.dump({e["fn"]: e.get("calls", []) for e in r["functions"]},
          open(sys.argv[2].replace(".json", ".callgraph.json"), "w"))
PY
printf 'pure app\n' > "$W/cls6/pol"
# the SORTED fn list a `--json` selection names, or the literal BADJSON — an empty answer and a CLI that
# never ran must not print the same thing.
csel() { # csel <verb> <report> [--class …]
  local verb="$1" rep="$2"; shift 2
  local args=("$verb" --report "$rep" --json)
  [ "$verb" = unverified ] && args+=(--policy "$W/cls6/pol")
  "$CJ" "${args[@]}" "$@" 2>/dev/null | python3 -c '
import json, sys
raw = sys.stdin.read()
try: d = json.loads(raw)
except Exception: print("BADJSON"); sys.exit()
print(",".join(sorted(x["fn"] for x in d.get("unverified", d.get("sources", [])))))'
}
ALL7='app.a_reasonless_only,app.b_reasoned_only,app.c_both,app.d_named_direct,app.e_named_inherited,app.src_reasoned,app.src_reasonless'
want "unverified: the unfiltered denominator is all 7 Unknown-bearing entries" "$(csel unverified "$W/cls6/r.json")" "$ALL7"
# THE DIAGNOSTIC. `dynamic` names every genuine class, so on a setup-free report it must exclude
# NOTHING. Measured before this landed: 2 of 7 (−71%) — the filter under-reported the holes the verb
# exists to surface, and under-reported MORE the more the user narrowed.
want "unverified --class dynamic excludes nothing on a setup-free report" \
     "$(csel unverified "$W/cls6/r.json" --class dynamic)" "$ALL7"
want "unverified --class dynamic drops ONLY the setup-only entry" \
     "$(csel unverified "$W/cls6/s.json" --class dynamic)" "$ALL7"
absent "…and dynamic really does exclude it" \
     "$(csel unverified "$W/cls6/s.json" --class dynamic)" 'app.f_setup_only'
want "…while the setup fixture's UNFILTERED set carries it (not a vacuous subtraction)" \
     "$(csel unverified "$W/cls6/s.json")" 'app.f_setup_only'
want "unverified --class setup names it" "$(csel unverified "$W/cls6/s.json" --class setup)" 'app.f_setup_only'
# §6.2 (2) FAIL CLOSED + (1) TRANSITIVE: a hole nobody named is `unresolved` — at the source that raised
# it, at the caller that inherits it, AND at the caller that reaches BOTH it and a `dispatch:` hole
# (the counterexample: c_both is strictly worse-known than a_reasonless_only and used to select nothing).
want "unverified --class unresolved selects the reasonless source + both its reachers" \
     "$(csel unverified "$W/cls6/r.json" --class unresolved)" 'app.a_reasonless_only,app.c_both,app.src_reasonless'
want "unverified --class dispatch travels transitively to the two inheriting callers" \
     "$(csel unverified "$W/cls6/r.json" --class dispatch)" 'app.b_reasoned_only,app.c_both,app.src_reasoned'
# §6.2 (3) THE MIRROR FABRICATION, both controls: an entry whose reasons are ALL classifiable and none
# `unresolved` must NOT match `--class unresolved` — including when its Unknown is INHERITED (absence is
# also what an inherited Unknown looks like, so a rule keyed on absence over-fires on exactly these).
absent "…and an inherited-but-CLASSIFIED caller is not swept in as unresolved" \
     "$(csel unverified "$W/cls6/r.json" --class unresolved)" 'app.e_named_inherited'
absent "…nor is the caller of the reasoned source" \
     "$(csel unverified "$W/cls6/r.json" --class unresolved)" 'app.b_reasoned_only'
want "unverified --class reflect selects the named source AND its inheriting caller" \
     "$(csel unverified "$W/cls6/r.json" --class reflect)" 'app.d_named_direct,app.e_named_inherited'
# the DISCRIMINATION control's zero row, asserted with an explicit emptiness test (`want` greps, and
# grep for the empty string over empty input matches nothing — a false FAIL, or a false pass elsewhere).
ind=$(csel unverified "$W/cls6/r.json" --class indirect)
if [ -z "$ind" ]; then echo "  ok   unverified --class indirect selects nothing (no entry carries a callback:)"; pass=$((pass+1));
else echo "  FAIL unverified --class indirect selected: $ind"; fail=$((fail+1)); fi
# `blindspots` SHARES THE FLAG AND MUST NOT SHARE THE FIX. §3.1 makes it the SOURCE view: a unit whose
# Unknown is purely inherited is DEFINED out of it, so the direct-only read is correct there and
# resolving transitively would turn a ranked worklist of root causes into everything downstream of them.
want "blindspots is the SOURCE view — only entries with a direct, named reason" \
     "$(csel blindspots "$W/cls6/r.json")" 'app.d_named_direct,app.src_reasoned'
want "blindspots --class dispatch stays direct-only (the source, not its callers)" \
     "$(csel blindspots "$W/cls6/r.json" --class dispatch)" 'app.src_reasoned'
want "blindspots --class reflect stays direct-only" \
     "$(csel blindspots "$W/cls6/r.json" --class reflect)" 'app.d_named_direct'
# ⟨0.24⟩ THE FLAG'S VALUE GRAMMAR. A dropped token here leaves a NARROWER filter (unlike the policy
# side, where it leaves a wider rule), so `--class dyanmic` would silently answer a question nobody
# asked, with a smaller number. A query flag that cannot be honoured is refused.
for v in unverified blindspots; do
  vargs=(--report "$W/cls6/r.json" --json); [ "$v" = unverified ] && vargs+=(--policy "$W/cls6/pol")
  typo=$("$CJ" "$v" "${vargs[@]}" --class dyanmic 2>&1); trc=$?
  if [ "$trc" -eq 2 ]; then echo "  ok   $v --class <typo> is a usage error (exit 2)"; pass=$((pass+1));
  else echo "  FAIL $v --class dyanmic exit $trc (want 2)"; fail=$((fail+1)); fi
  want "$v --class <typo> NAMES the offending token"   "$typo" 'dyanmic'
  want "$v --class <typo> lists the accepted set"      "$typo" 'reflect, dispatch, indirect, native, unresolved, setup'
  rep2=$("$CJ" "$v" "${vargs[@]}" --class unresolved --class native 2>&1); rrc=$?
  if [ "$rrc" -eq 2 ]; then echo "  ok   $v repeated --class is a usage error (exit 2)"; pass=$((pass+1));
  else echo "  FAIL $v repeated --class exit $rrc (want 2)"; fail=$((fail+1)); fi
  want "$v repeated --class points at the one comma list" "$rep2" '--class unresolved,native'
  empty=$("$CJ" "$v" "${vargs[@]}" --class '' 2>&1); erc=$?
  if [ "$erc" -eq 2 ]; then echo "  ok   $v --class '' is a usage error (exit 2)"; pass=$((pass+1));
  else echo "  FAIL $v --class '' exit $erc (want 2)"; fail=$((fail+1)); fi
  # CONTROL: the refusal must not have swallowed the values it exists to protect.
  "$CJ" "$v" "${vargs[@]}" --class dynamic >/dev/null 2>&1; grc=$?
  "$CJ" "$v" "${vargs[@]}" --class '*' >/dev/null 2>&1; src=$?
  "$CJ" "$v" "${vargs[@]}" --class reflect,native >/dev/null 2>&1; crc=$?
  if [ "$grc" -eq 0 ] && [ "$src" -eq 0 ] && [ "$crc" -eq 0 ]; then
    echo "  ok   $v still accepts dynamic, * and a comma list"; pass=$((pass+1));
  else echo "  FAIL $v rejected a valid --class (dynamic=$grc *=$src list=$crc)"; fail=$((fail+1)); fi
done

echo "== candor wrapper =="
want "./candor analyzes via the wrapper"   "$("$ROOT/candor" "$W/cls" 2>/dev/null)"               'Fx.reads'
want "./candor queries via the wrapper"    "$("$ROOT/candor" show "$W/r.json" reads 2>/dev/null)" 'Fs'

# an unknown --flag in QUERY position must FAIL (exit 2), not be swallowed as a query positional
"$CJ" show "$W/r.json" --jsno >/dev/null 2>&1; qrc=$?
[ "$qrc" -eq 2 ] && echo "  ok   query rejects an unknown flag (exit 2)" && pass=$((pass+1)) \
                 || { echo "  FAIL query unknown-flag exit $qrc"; fail=$((fail+1)); }

# ── ./candor --deps <classpath>: scan the dep jars + chain (the JVM dep-scan convenience) ─────────
mkdir -p "$W/dep/com/lib" "$W/dapp/com/app"
cat > "$W/dep/com/lib/L.java" <<'J'
package com.lib;
public class L { public String load(String p) throws Exception { return java.nio.file.Files.readString(java.nio.file.Path.of(p)); } }
J
cat > "$W/dapp/com/app/A.java" <<'J'
package com.app;
import com.lib.L;
public class A { public static String run() throws Exception { return new L().load("/tmp/x"); } }
J
javac -d "$W/depcls" "$W/dep/com/lib/L.java" 2>/dev/null
jar cf "$W/d.jar" -C "$W/depcls" . 2>/dev/null
javac -cp "$W/d.jar" -d "$W/dappcls" "$W/dapp/com/app/A.java" 2>/dev/null
( cd "$W" && CANDOR_DEPS_DIR="$W/.deps" "$ROOT/candor" --deps "$W/d.jar" "$W/dappcls" 2>/dev/null ) > "$W/deps.out"
want "./candor --deps scans the classpath jar and chains it (A.run inherits Fs)" "$(grep 'A.run' "$W/deps.out")" 'Fs*'

# ── the MCP surface: ⟨0.24⟩ THE STALE-DOCUMENT RULE BINDS IT TOO (SPEC §3.1) ─────────────────────
# The server used to discard the scan's result and serve `os.path.exists(REPORT)`, so a scan that FAILED
# left the PREVIOUS run's report on disk and every query was answered from it, as current, silently.
# MEASURED: a good jar, then the same path replaced by a corrupt one — `candor_effects` kept returning the
# old jar's Net/hosts/netClass for bytecode that was no longer there. An agent has no other way to know.
echo "== MCP surface (stale report + isError) =="
MCPW="$W/mcp"; mkdir -p "$MCPW/.candor"
( cd "$W/cls" && jar cf "$MCPW/good.jar" . ) 2>/dev/null
cat > "$W/mcp-drive.py" <<'PY'
import json, os, subprocess, sys
cwd, jar, rep = sys.argv[1], sys.argv[2], sys.argv[3]
env = dict(os.environ); env["CANDOR_CLASSES"] = jar; env["CANDOR_REPORT"] = rep
env.pop("CANDOR_POLICY", None)
srv = subprocess.Popen([sys.executable, sys.argv[4]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, text=True, cwd=cwd, env=env)
def call(i, m, p=None):
    srv.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": m, **({"params": p} if p else {})}) + "\n")
    srv.stdin.flush()
    return json.loads(srv.stdout.readline())
call(1, "initialize", {})
tools = [t["name"] for t in call(2, "tools/list")["result"]["tools"]]
# argv[5] (optional): the tool + its argument, so one driver covers `candor_effects` and `candor_where`.
tool = sys.argv[5] if len(sys.argv) > 5 else "candor_effects"
args = ({"function": sys.argv[6]} if tool != "candor_where" else {"effect": sys.argv[6]}) \
    if len(sys.argv) > 6 else {"function": "Fx.reads"}
r = call(3, "tools/call", {"name": tool, "arguments": args})["result"]
srv.stdin.close(); srv.wait()
print("TOOLS=%s" % ",".join(tools))
print("ISERROR=%s" % bool(r.get("isError")))
print("BLOCKS=%d" % len(r["content"]))
for b in r["content"]:
    print(b["text"])
PY
MCPSRV="$ROOT/integrations/mcp/candor-mcp.py"
mcp1="$(python3 "$W/mcp-drive.py" "$MCPW" "$MCPW/good.jar" "$MCPW/.candor/report.json" "$MCPSRV" 2>&1)"
want "MCP answers from a fresh scan"                 "$mcp1" 'ISERROR=False'
want "…with the real effect set"                     "$mcp1" '"Fs"'
sleep 1
printf 'not a zip at all' > "$MCPW/good.jar"          # same path, newer mtime, unscannable
mcp2="$(python3 "$W/mcp-drive.py" "$MCPW" "$MCPW/good.jar" "$MCPW/.candor/report.json" "$MCPSRV" 2>&1)"
want    "MCP REFUSES rather than serving the previous run's report" "$mcp2" 'ISERROR=True'
want    "…and says the stale report is NOT being served"            "$mcp2" 'NOT being served'
wantnot "…so the old jar's effect set does not leak through"        "$mcp2" '"Fs"'
# THE MIRROR: exit 1 is a gate VIOLATION, not a failure — the report it wrote is valid and must be served.
rm -f "$MCPW/good.jar" "$MCPW/.candor/report.json"
( cd "$W/cls" && jar cf "$MCPW/good.jar" . ) 2>/dev/null
echo 'deny Fs Fx' > "$MCPW/p.policy"
mcp3="$(CANDOR_POLICY="$MCPW/p.policy" python3 "$W/mcp-drive.py" "$MCPW" "$MCPW/good.jar" "$MCPW/.candor/report.json" "$MCPSRV" 2>&1)"
want "MIRROR: a GATING scan (exit 1) still serves its valid report" "$mcp3" 'ISERROR=False'
want "…with the real effect set"                                    "$mcp3" '"Fs"'

# ── ⟨0.21⟩ THE COMPLETENESS MANIFEST HAS TO REACH THE AGENT ──────────────────────────────────────
# candor-ts found its MCP `candor_gate` implementing NO ⟨0.21⟩ incompleteness rule — `{"ok":true}` over a
# report declaring `unanalyzed` where the CLI exits 2. This server exposes NO gate tool (the TOOLS= line
# below is that check, asserted rather than assumed), so there is no `ok` to be wrong. The sibling defect
# it DOES have is a silently short ANSWER: MEASURED, two classes — one performing Fs, one performing Net
# with its bytecode major version bumped past what ASM reads — and `candor_where(Net)` replied
# `{"directly": [], "inherited": []}`, isError unset. *Nobody performs Net*, over a report that names the
# Net-performing class as unread. The report held the answer; the verb dropped it.
echo "== MCP surface (⟨0.21⟩ incompleteness reaches the agent) =="
IW="$W/mcpinc"; mkdir -p "$IW/.candor" "$IW/src/app"
cat > "$IW/src/app/A.java" <<'J'
package app;
public class A { public void reads(){ try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/tmp/x")); } catch (Exception e) {} } }
J
cat > "$IW/src/app/B.java" <<'J'
package app;
public class B { public void fetch() throws Exception { new java.net.URL("http://example.com").openStream().close(); } }
J
javac -d "$IW/classes" "$IW/src/app/A.java" "$IW/src/app/B.java" 2>/dev/null
# CONTROL FIRST, while every class is readable: the answer is complete and the response is ONE block —
# byte-identical to a pre-⟨0.21⟩ one, so the extra block means something when it appears.
mcpc="$(python3 "$W/mcp-drive.py" "$IW" "$IW/classes" "$IW/.candor/report.json" "$MCPSRV" candor_where Net 2>&1)"
want    "CONTROL: a complete report finds the Net performer"        "$mcpc" 'app.B.fetch'
want    "…and answers in ONE content block"                         "$mcpc" 'BLOCKS=1'
wantnot "…with no incompleteness claim it does not have"            "$mcpc" 'INCOMPLETE ANALYSIS'
want    "…and this server exposes NO gate tool, so there is no ok field to be wrong" \
        "$mcpc" 'TOOLS=candor_effects,candor_where,candor_callers,candor_whatif'
# Now bump B.class past the major version ASM reads. Same source, same tool, one unreadable class.
python3 - "$IW/classes/app/B.class" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read()); b[6] = 0; b[7] = 99
open(p, "wb").write(b)
PY
sleep 1; touch "$IW/classes/app/B.class"
mcpi="$(python3 "$W/mcp-drive.py" "$IW" "$IW/classes" "$IW/.candor/report.json" "$MCPSRV" candor_where Net 2>&1)"
wantnot "the Net performer is now INVISIBLE (the premise — an empty answer)" "$mcpi" 'app.B.fetch'
want    "…so the answer carries the completeness manifest"                   "$mcpi" 'INCOMPLETE ANALYSIS'
want    "…naming the unit that was never read"                               "$mcpi" 'B.class'
want    "…and WHY, so it is actionable"                                      "$mcpi" 'major version 99'
want    "…as a SECOND block, leaving content[0] the parseable payload"       "$mcpi" 'BLOCKS=2'
# NOT isError: a partial answer that says it is partial beats a refusal (SPEC §3.2) — these verbs are
# consulted BEFORE an edit, where the alternative is the agent guessing.
want    "…and NOT as an error: the answer is partial, not absent"            "$mcpi" 'ISERROR=False'

# ── --agents: the self-describing engine (the contract is a jar resource) ────────────────────────
echo "== --agents =="
AG=$("$CJ" --agents 2>&1)
want "--agents prints the version header"      "$AG" '<!-- candor-java'
want "--agents prints the installed contract"  "$AG" 'ships inside the jar'
if cmp -s "$ROOT/AGENTS.md" "$ROOT/src/main/resources/AGENTS.md"; then
  echo "  ok   the jar resource matches the repo AGENTS.md (drift gate)"; pass=$((pass+1))
else
  echo "  FAIL the jar resource drifted from AGENTS.md — re-copy: cp AGENTS.md src/main/resources/AGENTS.md"; fail=$((fail+1))
fi

# ── family identity phrases (drift gate): the claims that have actually drifted before ───────────
echo "== family identity phrases =="
README_TXT="$(cat "$ROOT/README.md")"; AGENTS_TXT="$(cat "$ROOT/AGENTS.md")"
# The spec the docs must pin is read from the BINARY, not written here as a literal. A literal makes
# this gate ENFORCE the drift it exists to catch: at the 0.23→0.24 floor bump the constant moved and
# these two assertions kept both docs pinned to 0.23, green. Derive it and the gate cannot go stale.
BSPEC="$("$CJ" --version 2>/dev/null | sed -nE 's/.*\(spec ([0-9.]+)\).*/\1/p' | head -1)"
if [ -n "$BSPEC" ]; then echo "  ok   docs gate reads the spec floor off the binary ($BSPEC)"; pass=$((pass+1));
else echo "  FAIL could not read the binary's declared spec for the docs drift gate"; fail=$((fail+1)); fi
want    "README names candor-java the family's reference engine" "$README_TXT" "the family's reference engine"
want    "README pins the spec floor (spec $BSPEC)"               "$README_TXT" "spec $BSPEC"
wantnot "README does not call Rust the reference"                "$README_TXT" "Rust reference"
want    "AGENTS names candor-java the reference engine"          "$AGENTS_TXT" "reference engine"
want    "AGENTS pins the spec floor (spec $BSPEC)"               "$AGENTS_TXT" "spec $BSPEC"

echo
echo "smoke: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
