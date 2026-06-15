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
