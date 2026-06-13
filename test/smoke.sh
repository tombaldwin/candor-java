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
want "envelope declares the spec contract 0.4" "$rep" '"spec": "0.4"'
want "functions array present"               "$rep" '"functions"'
want "reads performs Fs"                      "$rep" '"Fx.reads"'
want "dyn is Unknown (reflection, trust §4)"  "$rep" '"Unknown"'

echo "== Exec-cliff refinement by known sub-command head (spec §4 ⟨0.5⟩) =="
want    "curl head refines the cliff: + Net"        "$("$CJ" show "$W/r.json" netcmd)"   'Net'
want    "curl head keeps Exec (never dropped)"      "$("$CJ" show "$W/r.json" netcmd)"   'Exec'
want    "psql head (Runtime.exec line) refines: + Db" "$("$CJ" show "$W/r.json" dbcmd)"  'Db'
want    "candor head is Fs/Env (spec §7.12 supplied)" "$("$CJ" show "$W/r.json" auditcmd)" 'Env'
wantnot "an unknown head 'x' stays the bare Exec cliff (no fabricated Net)" "$("$CJ" show "$W/r.json" spawn)" 'Net'

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
want   "a <clinit> unit carries unitKind initializer (spec 0.5 draft)" \
       "$(python3 -c "import json;print([e.get('unitKind','') for e in json.load(open('$W/ci.json'))['functions'] if e['fn'].endswith('.<clinit>')][0])")" 'initializer'

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
want   "unlisted external package named in the receipt" "$KAP" "κ doesn't know 1 package"
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
absent "…and the chained package leaves the κ ledger"       "$DJC_CHAIN" "κ doesn't know"
# An ALL-PURE dep's EMPTY report in SPEC singular-`package` form must register coverage (SPEC §2
# rule 3) — reading only `packages[]` (the JVM's own plural) ignored it and falsely named the
# package a blind spot. (/code-review max: the spec + the Rust/TS producers emit singular `package`.)
printf '{"candor":{"version":"x","spec":"0.4"},"package":"com.thirdparty.io","functions":[]}' > "$W/djc/empty-pkg.json"
DJC_EMPTY=$(CANDOR_DEPS="$W/djc/empty-pkg.json" "$CJ" "$W/djc/app" 2>&1)
absent "a singular-`package` empty report covers its package (no false blind spot)" "$DJC_EMPTY" "κ doesn't know"

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
absent "array owners stay out of the ledger"                "$SJ_ARR" "κ doesn't know"

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

echo
echo "smoke: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
