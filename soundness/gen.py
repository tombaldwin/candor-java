#!/usr/bin/env python3
"""Construction-based soundness fuzzer for candor-java (sibling of the Rust impl's soundness/gen.py).

Generates a compilable Java class that threads a KNOWN effect (Fs/Net/Exec/Env/Clock/Rand) from a `sink` method up
through a random chain of methods, where each call edge uses a randomly-chosen JVM CALL FORM — the ways
an effect can reach a method on the JVM: a direct static call, a lambda, a method reference, a
constructor (`<init>`), a static initializer (`<clinit>`), interface/virtual dispatch (CHA), and an
anonymous class.

Every emitted method transitively reaches the effect, so candor-java must report each `Gen.fNN` / `sink`
/ `main` with the effect in its `inferred` set OR with `Unknown` (a sound over-approximation). A method
reported pure — or omitted from the report (candor omits pure methods) — is a SILENT UNDER-REPORT: the
bug class this harness exists to catch. truth.json lists the methods that must be effect-or-Unknown;
run.sh checks the report against it.

Usage:  gen.py <seed> <out-dir>     # writes <out-dir>/Gen.java + truth.json
"""
import json
import os
import random
import sys

# effect -> the Java statement that performs it (caught so the generated code compiles & is well-formed).
EFFECTS = {
    "Fs":   'try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/tmp/candor_fuzz")); } catch (Exception e) {}',
    "Net":  'try { java.net.Socket s = new java.net.Socket("127.0.0.1", 9); s.close(); } catch (Exception e) {}',
    "Exec": 'try { new ProcessBuilder("echo", "x").start(); } catch (Exception e) {}',
    "Env":  'System.getenv("CANDOR_FUZZ");',
    "Clock": 'System.currentTimeMillis();',
    "Rand":  'new java.util.Random().nextInt();',
    # Db was fuzzer-blind (no leaf) — so the whole JDBC/JPA Db classification surface was unexercised by the
    # soundness fuzzer. DriverManager.getConnection is a self-contained Db sink (no param needed).
    "Db":   'try { java.sql.DriverManager.getConnection("jdbc:candor:fuzz"); } catch (Exception e) {}',
    # Log + Clipboard were also fuzzer-blind (classify-only, never propagation-tested). jul Logger.info is a
    # Log emit verb; Toolkit.getSystemClipboard is the Clipboard read/write handle. Both self-contained (the
    # fuzzer only scans bytecode — getSystemClipboard's headless throw is irrelevant + try-guarded anyway).
    "Log":  'java.util.logging.Logger.getGlobal().info("candor_fuzz");',
    "Clipboard": 'try { java.awt.Toolkit.getDefaultToolkit().getSystemClipboard(); } catch (Throwable e) {}',
}


# Each edge form returns (body_calling_callee, extra_nested_items). The body is the statement(s) that
# reach `callee`; the items are nested types emitted inside `Gen` (a per-edge ctor/clinit/iface).
def edge_forms(callee, i):
    return {
        # direct static call (invokestatic).
        "direct":    (f"{callee}();", []),
        # lambda: the body's effect is in a `lambda$` synthetic, edged via the invokedynamic Handle.
        "lambda":    (f"Runnable r{i} = () -> {callee}(); r{i}.run();", []),
        # method reference to a static method (invokedynamic Handle straight to `callee`).
        "methodref": (f"Runnable r{i} = Gen::{callee}; r{i}.run();", []),
        # constructor: the effect lives in `<init>`, reached by `new Ctor{i}()`.
        "ctor":      (f"new Ctor{i}();",
                      [f"static class Ctor{i} {{ Ctor{i}() {{ {callee}(); }} }}"]),
        # static initializer: the effect lives in `<clinit>`, reached by a static call that loads the class.
        "clinit":    (f"Clinit{i}.touch();",
                      [f"static class Clinit{i} {{ static {{ {callee}(); }} static void touch() {{}} }}"]),
        # interface dispatch: resolved by CHA to the concrete impl whose method calls `callee`.
        "iface":     (f"I{i} x{i} = new Impl{i}(); x{i}.run();",
                      [f"interface I{i} {{ void run(); }}",
                       f"static class Impl{i} implements I{i} {{ public void run() {{ {callee}(); }} }}"]),
        # anonymous class implementing Runnable (a distinct synthesized class, resolved by CHA).
        "anon":      (f"Runnable r{i} = new Runnable() {{ public void run() {{ {callee}(); }} }}; r{i}.run();", []),
        # interface DEFAULT method: the effect lives in a default body the impl does NOT override —
        # resolved by walking the supertype chain to the concrete default (chaTargets supertype walk).
        "default":   (f"D{i} d{i} = new DImpl{i}(); d{i}.act();",
                      [f"interface D{i} {{ default void act() {{ {callee}(); }} }}",
                       f"static class DImpl{i} implements D{i} {{}}"]),
        # INHERITED concrete method: the effect lives in a superclass method the subclass does NOT
        # override; a call on the subtype must resolve UP to the inherited body (chaTargets supertype walk).
        "inherited": (f"Sub{i} s{i} = new Sub{i}(); s{i}.act();",
                      [f"static class Base{i} {{ void act() {{ {callee}(); }} }}",
                       f"static class Sub{i} extends Base{i} {{}}"]),
        # SUPER call (invokespecial): an override delegates to the superclass body via `super.act()`.
        "super":     (f"new SubS{i}().act();",
                      [f"static class BaseS{i} {{ void act() {{ {callee}(); }} }}",
                       f"static class SubS{i} extends BaseS{i} {{ void act() {{ super.act(); }} }}"]),
        # SUPERCLASS <clinit> chain: the effect lives in a BASE class's <clinit>; touching the SUBCLASS (a
        # static call) triggers the base's class-load too (JVMS §5.5), so clinitEdge must walk the supertype
        # chain. Was a silent-pure hole (candor-java 0.5.26).
        "clinit_super": (f"SubCl{i}.touch();",
                      [f"static class BaseCl{i} {{ static {{ {callee}(); }} }}",
                       f"static class SubCl{i} extends BaseCl{i} {{ static void touch() {{}} }}"]),
        # METHOD-REF <clinit>: a static method-ref to a PURE body on a class with an effectful <clinit> — the
        # ref resolution triggers the class load (the indy site must clinitEdge the owner), even though the
        # referenced body does nothing. Was a silent-pure hole (candor-java 0.5.28).
        "methodref_clinit": (f"Runnable rmc{i} = HRef{i}::pure; rmc{i}.run();",
                      [f"static class HRef{i} {{ static {{ {callee}(); }} static void pure() {{}} }}"]),
        # CTOR-REF <clinit>: same trigger via `H::new`.
        "ctorref_clinit": (f"java.util.function.Supplier<Object> sct{i} = HCtor{i}::new; sct{i}.get();",
                      [f"static class HCtor{i} {{ static {{ {callee}(); }} HCtor{i}() {{}} }}"]),
        # ---- concurrency / resource forms: the runtime invokes the body, no in-project call to run() ----
        # Thread with a lambda: the effect is in a `lambda$` synthetic; the SCHEDULING method must
        # inherit it (SEMANTICS §2: closure effects attribute to the nearest enclosing function — the
        # Rust engines attribute `thread::spawn(closure)` to the spawner).
        "thread":    (f"new Thread(() -> {callee}()).start();", []),
        # Thread with an ANONYMOUS Runnable: no in-project `.run()` call — if run() is only covered as
        # an entry point, the scheduler under-reports vs the closure-attribution rule.
        "thread_anon": (f"new Thread(new Runnable() {{ public void run() {{ {callee}(); }} }}).start();", []),
        # ExecutorService.submit(lambda).
        "executor":  (f"java.util.concurrent.Executors.newSingleThreadExecutor().submit(() -> {callee}());", []),
        # CompletableFuture.runAsync(lambda).
        "future":    (f"java.util.concurrent.CompletableFuture.runAsync(() -> {callee}());", []),
        # Stream terminal op with a lambda consumer.
        "stream":    (f"java.util.stream.Stream.of(1).forEach(x{i} -> {callee}());", []),
        # try-with-resources: the effect lives in close(), invoked by compiler-generated bytecode.
        "trywith":   (f"try (R{i} r{i} = new R{i}()) {{ }} catch (Exception e) {{}}",
                      [f"static class R{i} implements AutoCloseable {{ public void close() {{ {callee}(); }} }}"]),
        # NAMED Runnable invoked SYNCHRONOUSLY (not via an executor): the dispatch is on the external
        # java.lang.Runnable interface, but the caller genuinely runs it in-line, so the effect must
        # attribute to the CALLER (bounded CHA), not just to run()'s entry-point row. An unconditional
        # Runnable.run skip blinded this — /code-review found it.
        "named_run": (f"new NR{i}().run();",
                      [f"static class NR{i} implements Runnable {{ public void run() {{ {callee}(); }} }}"]),
        # NAMED Callable invoked synchronously via call().
        "named_call":(f"try {{ new NC{i}().call(); }} catch (Exception e) {{}}",
                      [f"static class NC{i} implements java.util.concurrent.Callable<Object> {{ public Object call() {{ {callee}(); return null; }} }}"]),
        # for-each over a CUSTOM Iterable: desugars to `iterator().next()` where the `.next()` receiver is
        # the java.util.Iterator INTERFACE type (not a pinned impl), so the effect resolves only by CHA
        # fan-out to the project's Iterator impls. Skipping java.util-container dispatch silently drops the
        # iterator's effect at the loop site — the §4 silent-pure violation 3c25656 introduced (fuzzer-blind
        # until this form: `for (x : customBag)` came back pure though next() performs I/O).
        "foreach":   (f"for (Object o{i} : new Bag{i}()) {{}}",
                      [f"static class Bag{i} implements Iterable<Object> {{ public java.util.Iterator<Object> iterator() {{ return new It{i}(); }} }}",
                       f"static class It{i} implements java.util.Iterator<Object> {{ public boolean hasNext() {{ return false; }} public Object next() {{ {callee}(); return null; }} }}"]),
        # BROAD fan-out over an EXTERNAL interface: 13 (> CHA_FANOUT_LIMIT=12) project impls of
        # java.util.function.Supplier dispatched at a SINGLE site (`s.get()` looped over all of them),
        # ONE of which reaches `callee`. Bounded CHA DROPS the whole fan-out (broad), and because the
        # owner (Supplier) is EXTERNAL the old `isProjectIfaceOrAbstract(owner)` Unknown-gate was false —
        # so the caller went SILENTLY PURE though a dropped project body carries the effect (the cardinal
        # §4 violation). The fix raises Unknown whenever a broad drop discards PROJECT impls (cha non-
        # empty). Asserts the caller is effect-or-Unknown, never pure. The other forms use a SINGLE impl,
        # so this broad-drop path was fuzzer-blind. (/code-review max found the hole.)
        "fanout": (
            "java.util.List<java.util.function.Supplier<Object>> sup{0} = new java.util.ArrayList<>();".format(i)
            + "".join(f"sup{i}.add(new Sup{i}_{k}());" for k in range(13))
            + f"for (java.util.function.Supplier<Object> z{i} : sup{i}) {{ z{i}.get(); }}",
            [f"static class Sup{i}_0 implements java.util.function.Supplier<Object> {{ public Object get() {{ {callee}(); return null; }} }}"]
            + [f"static class Sup{i}_{k} implements java.util.function.Supplier<Object> {{ public Object get() {{ return null; }} }}"
               for k in range(1, 13)]),
        # UNPINNED java.lang.Runnable.run(): the receiver `r` comes from iterating a List<Runnable> (the
        # element type is the Runnable INTERFACE, not a pinned `new`), so run() resolves only by CHA
        # fan-out to the project's Runnable impls. Runnable.run / Callable.call USED to be CHA-exempt → an
        # unpinned task dispatch came back silently pure; now they go through normal bounded CHA (narrow →
        # fan out to the actual impls, broad → Unknown). A pinned `new TR().run()` would resolve
        # monomorphically and never exercise the exempt path — the list element is the point.
        "task_unpinned": (
            f"Runnable rr{i} = C{i} ? new TR{i}() : new TU{i}(); rr{i}.run();",
            [f"static boolean C{i};",
             f"static class TR{i} implements Runnable {{ public void run() {{ {callee}(); }} }}",
             f"static class TU{i} implements Runnable {{ public void run() {{}} }}"]),
        # ---- DEFENSE-IN-DEPTH forms: verified SOUND in the cross-engine hunt; these lock the behavior. ----
        # OVERLOAD: two same-name `ov{i}` overloads — the SUPERTYPE/interface-param one is effectful and
        # reaches `callee`; the unrelated-ref one is a pure decoy. Called with a SUBTYPE argument (the
        # static type is the interface base, sourced from a branch-MERGE so it stays unpinned), so
        # overload resolution must select the supertype overload to thread the effect. A boxed-vs-
        # primitive sibling pair (`box{i}(Integer)` effectful vs `box{i}(int)` pure) is exercised with a
        # boxed `Integer` receiver so the reference overload — not int — is selected and reaches `callee`.
        "overload": (
            f"OvBase{i} ob{i} = OC{i} ? new OvSub{i}() : new OvSubB{i}(); ov{i}(ob{i}); Integer bx{i} = OC{i} ? 1 : 2; box{i}(bx{i});",
            [f"static boolean OC{i};",
             f"interface OvBase{i} {{}}",
             f"static class OvSub{i} implements OvBase{i} {{}}",
             f"static class OvSubB{i} implements OvBase{i} {{}}",
             f"static void ov{i}(OvBase{i} x) {{ {callee}(); }}",   # effectful (supertype/iface param)
             f"static void ov{i}(String s) {{}}",                    # pure decoy (unrelated ref overload)
             f"static void box{i}(Integer n) {{ {callee}(); }}",     # effectful (boxed ref overload)
             f"static void box{i}(int n) {{}}"]),                     # pure decoy (primitive overload)
        # GEN_BRIDGE: a named generic-interface impl reached through a synthetic BRIDGE method. A
        # `Function<String,String>` impl's `apply(String)` does the chain effect; the JVM emits a
        # `apply(Object)` bridge that forwards. Invoked via an UNPINNED receiver (branch-merge of two
        # impls, typed as the erased Function interface) so resolution goes through the bridge, not a
        # pinned concrete call.
        "gen_bridge": (
            f"java.util.function.Function<String,String> gf{i} = GC{i} ? new GFn{i}() : new GFnB{i}(); gf{i}.apply(\"x\");",
            [f"static boolean GC{i};",
             f"static class GFn{i} implements java.util.function.Function<String,String> {{ public String apply(String s) {{ {callee}(); return s; }} }}",
             f"static class GFnB{i} implements java.util.function.Function<String,String> {{ public String apply(String s) {{ {callee}(); return s; }} }}"]),
        # ENUM_CONST: the effect lives in an enum CONSTANT's method-override body (anonymous-class-per-
        # constant — each constant compiles to a synthetic subclass of the enum). Reached via the enum's
        # ABSTRACT method on an UNPINNED enum-typed receiver (branch-merge of two constants), so dispatch
        # must resolve to the per-constant override.
        "enum_const": (
            f"En{i} e{i} = EC{i} ? En{i}.A : En{i}.B; e{i}.act();",
            [f"static boolean EC{i};",
             f"enum En{i} {{ A {{ void act() {{ {callee}(); }} }}, B {{ void act() {{ {callee}(); }} }}; abstract void act(); }}"]),
        # ARRAY_IFACE: `Handler[] hs; for (Handler h : hs) h.handle();` where a handler impl does the
        # effect. The loop receiver `h` is an ARRAY ELEMENT typed as the Handler interface — unpinned —
        # so handle() resolves only by CHA fan-out to the project's Handler impls.
        "array_iface": (
            f"Handler{i}[] hs{i} = new Handler{i}[] {{ new HImpl{i}(), new HImplB{i}() }}; for (Handler{i} h{i} : hs{i}) {{ h{i}.handle(); }}",
            [f"interface Handler{i} {{ void handle(); }}",
             f"static class HImpl{i} implements Handler{i} {{ public void handle() {{ {callee}(); }} }}",
             f"static class HImplB{i} implements Handler{i} {{ public void handle() {{ {callee}(); }} }}"]),
        # INSTANCE_METHODREF: a BOUND instance method reference `obj::method` (method does the effect)
        # stored as a Runnable and invoked. The bound receiver `obj` comes from a branch-MERGE so it is
        # not a pinned single `new`; the invokedynamic Handle targets the instance method, which must
        # resolve to the effectful body.
        "instance_methodref": (
            f"MR{i} m{i} = MC{i} ? new MR{i}() : new MR{i}(); Runnable rmr{i} = m{i}::go; rmr{i}.run();",
            [f"static boolean MC{i};",
             f"static class MR{i} {{ void go() {{ {callee}(); }} }}"]),
        # RECORD: a record's compiler-synthesized equals/hashCode/toString carry an `invokedynamic` to
        # java.lang.runtime.ObjectMethods whose bootstrap args include an H_GETFIELD Handle per component
        # (owner = the record class, a PROJECT class). That handle is a FIELD-kind handle: its `desc` is a
        # FIELD descriptor ("I"), not a method descriptor. The component `v{i}` also has an OVERLOADED
        # method name here (accessor `v{i}()` + `v{i}(int)`), so the handle routes into methodId →
        # paramTypeList → Type.getArgumentTypes on a parenthesis-less descriptor, which overran and CRASHED
        # the whole scan (found on a real app: uFlexi). The fix skips non-method-kind handles. The effect is
        # threaded through `rtouch{i}` so the chain stays sound; the teeth are that the scan must COMPLETE.
        # DO NOT remove `int v{i}(int n)`: that decoy OVERLOADS the component accessor so overloadDescs has
        # >1 desc, which is what routes the H_GETFIELD handle into methodId→paramTypeList (the crash path).
        # Without it methodId short-circuits to the bare name and the form silently stops reproducing the bug.
        "record": (
            f"new Rec{i}(1).rtouch{i}();",
            [f"record Rec{i}(int v{i}) {{ int v{i}(int n) {{ return n; }} void rtouch{i}() {{ {callee}(); }} }}"]),
    }


def main():
    seed = int(sys.argv[1])
    out = sys.argv[2]
    rng = random.Random(seed)

    allowed = os.environ.get("CANDOR_FUZZ_EFFECTS", "").split() or list(EFFECTS)
    effect = rng.choice([e for e in EFFECTS if e in allowed])
    only_forms = os.environ.get("CANDOR_FUZZ_FORMS", "").split()
    n = rng.randint(3, 8)  # chain length

    fns = [f"f{i:02d}" for i in range(n)]
    bodies = {}
    items = []
    forms_log = {}
    for i in range(n):
        callee = fns[i + 1] if i + 1 < n else "sink"
        forms = edge_forms(callee, i)
        choices = [f for f in forms if f in only_forms] if only_forms else list(forms)
        form = rng.choice(choices)
        body, extra = forms[form]
        bodies[fns[i]] = body
        items.extend(extra)
        forms_log[fns[i]] = form

    lines = [f"// GENERATED by soundness/gen.py — do not edit. seed={seed} effect={effect}",
             "public class Gen {",
             f"    static void sink() {{ {EFFECTS[effect]} }}"]
    for f in fns:
        lines.append(f"    static void {f}() {{ {bodies[f]} }}")
    lines.append(f"    public static void main(String[] a) {{ {fns[0]}(); }}")
    for it in items:
        lines.append(f"    {it}")
    lines.append("}")
    src = "\n".join(lines) + "\n"

    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "Gen.java"), "w") as f:
        f.write(src)
    # Methods that MUST be effect-or-Unknown (candor-java names them `Gen.<method>`).
    expect = sorted([f"Gen.{x}" for x in fns] + ["Gen.sink", "Gen.main"])
    with open(os.path.join(out, "truth.json"), "w") as f:
        json.dump({"seed": seed, "effect": effect, "expect": expect, "forms": forms_log}, f, indent=2)


if __name__ == "__main__":
    main()
