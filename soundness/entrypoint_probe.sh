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
# Framework stubs (real package paths so the supertype/annotation gate matches the FQN, not a nested name).
# candor roots on the supertype-name substring / annotation desc, so a faithful stub is enough — no jars.
mkdir -p "$TMP/jakarta/persistence" "$TMP/com/netflix/hystrix" \
         "$TMP/org/springframework/boot/actuate/health" "$TMP/jakarta/enterprise/event" \
         "$TMP/com/google/common/eventbus"
cat > "$TMP/jakarta/persistence/AttributeConverter.java" <<'EOF'
package jakarta.persistence;
public interface AttributeConverter<X,Y> { Y convertToDatabaseColumn(X x); X convertToEntityAttribute(Y y); }
EOF
cat > "$TMP/com/netflix/hystrix/HystrixCommand.java" <<'EOF'
package com.netflix.hystrix;
public abstract class HystrixCommand<T> { protected abstract T run() throws Exception; }
EOF
cat > "$TMP/org/springframework/boot/actuate/health/HealthIndicator.java" <<'EOF'
package org.springframework.boot.actuate.health;
public interface HealthIndicator { Object health(); }
EOF
cat > "$TMP/jakarta/enterprise/event/Observes.java" <<'EOF'
package jakarta.enterprise.event;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.PARAMETER) public @interface Observes {}
EOF
cat > "$TMP/com/google/common/eventbus/Subscribe.java" <<'EOF'
package com.google.common.eventbus;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Subscribe {}
EOF
cat > "$TMP/EP.java" <<'EOF'
import java.io.*;
import java.util.*;
import java.lang.reflect.*;
public class EP {
  @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME) @interface JsonCreator {}
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
  // JDK reflective/runtime invocation: sort machinery calls compare/compareTo; the proxy runtime calls
  // invoke; Jackson calls a @JsonCreator factory. Each does I/O with NO in-project call site → must root.
  static class Cmp implements Comparator<String> {
    public int compare(String a, String b) { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception e) {} return 0; }
  }
  static class Ord implements Comparable<Ord> {
    public int compareTo(Ord o) { try { new FileOutputStream("/tmp/candor_ep_o").close(); } catch (Exception e) {} return 0; }
  }
  static class Handler implements InvocationHandler {
    public Object invoke(Object p, Method m, Object[] a) { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception e) {} return null; }
  }
  static class Maker {
    @JsonCreator static Maker of(String s) { System.getenv("MK"); return new Maker(); }
  }
  // Round-10 runtime-invoked roots: JPA AttributeConverter, Hystrix command body, Spring Boot
  // HealthIndicator, CDI @Observes (PARAM annotation), Guava EventBus @Subscribe, Swing ActionListener.
  static class Conv implements jakarta.persistence.AttributeConverter<String,String> {
    public String convertToDatabaseColumn(String x) { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception e) {} return x; }
    public String convertToEntityAttribute(String y) { return y; }
  }
  static class Cmd extends com.netflix.hystrix.HystrixCommand<String> {
    protected String run() { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception e) {} return null; }
  }
  static class Health implements org.springframework.boot.actuate.health.HealthIndicator {
    public Object health() { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception e) {} return null; }
  }
  static class Obs {
    public void onEvent(@jakarta.enterprise.event.Observes Object e) { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception ex) {} }
  }
  static class Sub {
    @com.google.common.eventbus.Subscribe public void handle(Object e) { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception ex) {} }
  }
  static class Act implements java.awt.event.ActionListener {
    public void actionPerformed(java.awt.event.ActionEvent e) { try { new java.net.Socket("127.0.0.1",9).close(); } catch (Exception ex) {} }
  }
  // NON-implementor decoy: same method NAMES + signatures, but the class implements NONE of the runtime
  // interfaces — must NOT be rooted (the supertype/annotation gate guards against fabrication). Effectful
  // so the methods appear in the report (candor omits pure fns) and the entryPoint flag can be asserted.
  static class D {
    private void readObject(ObjectInputStream in) { try { new FileOutputStream("/tmp/candor_ep_d").close(); } catch (Exception e) {} }
    Object readResolve() { System.getenv("Z"); return null; }
    public int compare(Object a, Object b) { try { new FileOutputStream("/tmp/candor_ep_dc").close(); } catch (Exception e) {} return 0; }
    public int compareTo(Object o) { System.getenv("DCT"); return 0; }
  }
  public static void main(String[] a) { new S(); new X(); new Cmp(); new Ord(); new Handler(); Maker.of("");
    new Conv(); new Cmd(); new Health(); new Obs(); new Sub(); new Act(); new D(); }
}
EOF
javac -d "$TMP/out" $(find "$TMP" -name '*.java') 2>/dev/null || { echo "entrypoint-probe: GENERATOR BUG — fixture does not compile"; exit 1; }
java -jar "$JAR" "$TMP/out" --json "$TMP/r.json" >/dev/null 2>&1 || { echo "entrypoint-probe: scan FAILED on the fixture"; exit 1; }
python3 - "$TMP/r.json" <<'PY'
import json, sys
fns = {f["fn"]: f for f in json.load(open(sys.argv[1]))["functions"]}
ep  = lambda n: fns.get(n, {}).get("entryPoint", False)
must_root = ["EP$S.readObject", "EP$S.writeObject", "EP$S.readResolve", "EP$S.finalize",
             "EP$X.readExternal", "EP$X.writeExternal",
             "EP$Cmp.compare", "EP$Ord.compareTo", "EP$Handler.invoke", "EP$Maker.of",
             "EP$Conv.convertToDatabaseColumn", "EP$Cmd.run", "EP$Health.health",
             "EP$Obs.onEvent", "EP$Sub.handle", "EP$Act.actionPerformed"]
must_not  = ["EP$D.readObject", "EP$D.readResolve", "EP$D.compare", "EP$D.compareTo"]
bad = []
for n in must_root:
    if n not in fns:   bad.append(f"{n} MISSING from report (its effect went silent)")
    elif not ep(n):    bad.append(f"{n} entryPoint=false — orphaned from roots (should be a runtime root)")
for n in must_not:
    if ep(n):          bad.append(f"{n} entryPoint=true — FABRICATED root on a non-implementor class")
if bad:
    print("entrypoint-probe: FAIL")
    for b in bad: print("  " + b)
    sys.exit(1)
print("entrypoint-probe: OK — serialization/finalize/Comparator/Comparable/InvocationHandler/@JsonCreator/"
      "AttributeConverter/Hystrix/HealthIndicator/@Observes/@Subscribe/ActionListener callbacks rooted; "
      "non-implementor decoy not fabricated")
PY
