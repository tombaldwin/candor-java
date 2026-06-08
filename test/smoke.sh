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
want "envelope declares the spec contract 0.3" "$rep" '"spec": "0.3"'
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
want "queries emit --json (agent/MCP form)"    "$("$CJ" show "$W/r.json" both --json)" '"inferred"'
want "where --json: structured result"         "$("$CJ" where "$W/r.json" Fs --json)"  '"directly"'

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
}
J
javac -d "$W/cics" "$W/src/Ci.java"
"$CJ" "$W/cics" --json "$W/ci.json" >/dev/null 2>&1
ci="$(cat "$W/ci.json")"
# the audit output prints the fn name unescaped (the JSON escapes `<clinit>` as <…)
want   "static initializer's Fs is captured"               "$("$CJ" "$W/cics" 2>/dev/null)" 'Ci$Cfg.<clinit> '
want   "static CALL triggers <clinit> (Fs propagates)"     "$("$CJ" show "$W/ci.json" Ci.viaStaticCall)"  'Fs'
want   "static FIELD access triggers <clinit>"             "$("$CJ" show "$W/ci.json" Ci.viaStaticField)" 'Fs'
absent "a pure static initializer doesn't flood callers"   "$ci" '"Ci.pure"'

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
u="$(CANDOR_POLICY="$W/no-such.policy" "$CJ" "$W/cls" 2>&1)"
want   "an unreadable policy fails LOUD, not silent"             "$u" 'could not be read'

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
cont="$("$CJ" containment "$W/c.json" 2>&1)"
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

echo "== candor wrapper =="
want "./candor analyzes via the wrapper"   "$("$ROOT/candor" "$W/cls" 2>/dev/null)"               'Fx.reads'
want "./candor queries via the wrapper"    "$("$ROOT/candor" show "$W/r.json" reads 2>/dev/null)" 'Fs'

echo
echo "smoke: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
