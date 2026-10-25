#!/usr/bin/env python3
"""Call-target matrix generator for candor-java (2026-10-24).

Generates one directory per cell under <out>/cells/<id>/ with
  src/<group>/<pkg>/<Class>.java   sources, by compile group
  cell.json                        layout, runs, arms, expectation

Groups: dep (chained producer A), dep2 (chained producer B, compiled/scanned against dep),
        app (the consumer / the in-scan target; always holds app.Main), hid (compiled, on the
        runtime classpath, NEVER scanned).

Axes: kind (call kind / implicit hook / deferred / unit identity / control) x placement (where the
owner T, the effectful implementor W, the pure implementors S_i, and the call site live) x count
(implementors: W alone, W + 2 pure, W + 11 pure (=12, at the bound), W + 12 pure (=13, past it))
x effect (Fs everywhere; Net and Exec on a cross-section). The gated caller is always app.Main.go.
"""
import json, os, sys, itertools, shutil

OUT = sys.argv[1]
CELLS = os.path.join(OUT, 'cells')

# ---------------------------------------------------------------- effects
def eff(e):
    if e == 'Fs':
        return ('try { java.nio.file.Files.writeString(java.nio.file.Path.of(System.getProperty("cell.out")), "x"); }'
                ' catch (Exception e) { }')
    if e == 'Exec':
        return ('try { new ProcessBuilder("/usr/bin/touch", System.getProperty("cell.out")).start().waitFor(); }'
                ' catch (Exception e) { }')
    if e == 'FsHid':
        return 'hid.Leaf.write();'
    if e == 'Net':
        return ('try (java.net.Socket s = new java.net.Socket("127.0.0.1", Integer.getInteger("cell.port"))) { }'
                ' catch (Exception e) { }')
    raise ValueError(e)

# ---------------------------------------------------------------- placements
# Each placement: where T (owner), W (effectful impl), S (pure impls), and RUN (a dep-side call site,
# 'callback' shapes) live, as (group, pkg). 'nested' puts T/W/S inside app.Box.
PLACES = {
    # in-scan
    'nested':   dict(T=('app', 'app', 'Box'), W=('app', 'app', 'Box'), S=('app', 'app', 'Box'), chained=False),
    'pkg':      dict(T=('app', 'app'), W=('app', 'app'), S=('app', 'app'), chained=False),
    'mod':      dict(T=('app', 'lib'), W=('app', 'lib'), S=('app', 'lib'), chained=False),
    'split':    dict(T=('app', 'lib'), W=('app', 'app'), S=('app', 'app'), chained=False),
    'unseen':   dict(T=('app', 'lib'), W=('hid', 'hid'), S=('app', 'lib'), chained=False),
    # chained
    'dep':      dict(T=('dep', 'dep'), W=('dep', 'dep'), S=('dep', 'dep'), chained=True),
    'appimpl':  dict(T=('dep', 'dep'), W=('app', 'app'), S=('app', 'app'), chained=True),
    'split2':   dict(T=('dep', 'dep'), W=('app', 'app'), S=('dep', 'dep'), chained=True),
    'third':    dict(T=('dep', 'dep'), W=('dep2', 'dep2'), S=('dep2', 'dep2'), chained=True),
    'callback': dict(T=('dep', 'dep'), W=('app', 'app'), S=('app', 'app'), RUN=('dep', 'dep'), chained=True),
    'cbdep':    dict(T=('dep', 'dep'), W=('dep', 'dep'), S=('dep', 'dep'), RUN=('dep', 'dep'), chained=True),
    'depunseen': dict(T=('dep', 'dep'), W=('hid', 'hid'), S=('dep', 'dep'), chained=True),
    # added after the first run (axis gap for R1316): the DEPENDENCY's own call site, implementors in a THIRD package
    'cbthird':  dict(T=('dep', 'dep'), W=('dep2', 'dep2'), S=('dep2', 'dep2'), RUN=('dep', 'dep'), chained=True),
}
MODE = sys.argv[2] if len(sys.argv) > 2 else 'base'

class Src:
    """Accumulates declarations per (group, pkg, outer|None)."""
    def __init__(self):
        self.top = {}      # (group,pkg,simple) -> text
        self.nested = {}   # (group,pkg,outer) -> [text]
        self.imports = {}
    def add(self, loc, simple, text):
        g, p = loc[0], loc[1]
        if len(loc) == 3:
            self.nested.setdefault((g, p, loc[2]), []).append(text)
        else:
            assert (g, p, simple) not in self.top, (g, p, simple)
            self.top[(g, p, simple)] = text
    def files(self):
        fs = {}
        for (g, p, s), t in self.top.items():
            fs[f'src/{g}/{p}/{s}.java'] = f'package {p};\n{t}\n'
        for (g, p, o), ts in self.nested.items():
            fs[f'src/{g}/{p}/{o}.java'] = f'package {p};\npublic class {o} {{\n' + '\n'.join(ts) + '\n}\n'
        return fs

def ref(loc, simple):
    return f'{loc[1]}.{loc[2]}.{simple}' if len(loc) == 3 else f'{loc[1]}.{simple}'

def binn(loc, simple):
    return f'{loc[1]}.{loc[2]}${simple}' if len(loc) == 3 else f'{loc[1]}.{simple}'

def mods(loc, kw='class'):
    # top-level 'public class', nested 'public static class'
    return f'public static {kw}' if len(loc) == 3 else f'public {kw}'

# ---------------------------------------------------------------- kinds
# A dispatch kind: owner declaration, implementor declaration, call statement in go(PT t).
# 'how' = how main obtains an instance: 'new' (reflective ctor), 'factory' (static method returning a value).
# member(body, effectful) -> member declaration text in the implementor.
K = {}
def kind(name, **kw):
    kw.setdefault('how', 'new')
    kw.setdefault('family', 'explicit')
    kw.setdefault('counts', [1, 3, 13])
    K[name] = kw

PURE_RET = {'void': '', 'String': 'return "s";', 'int': 'return 0;', 'Object': 'return "s";', 'boolean': 'return false;'}

def M(sig, ret):
    """member(body) for an implementor: 'public <sig> { body; return }'"""
    def f(body, effectful):
        r = PURE_RET[ret] if ret != 'Object' else 'return "s";'
        return f'@Override public {sig} {{ {body} {r} }}'
    return f

# ---- explicit dispatch
kind('virt',  owner=lambda T, l: f'{mods(l)} {T} {{ public void m() {{ }} }}', ext='extends', member=M('void m()', 'void'), call='t.m();')
kind('abs',   owner=lambda T, l: f'{mods(l, "abstract class")} {T} {{ public abstract void m(); }}', ext='extends', member=M('void m()', 'void'), call='t.m();')
kind('iface', owner=lambda T, l: f'{mods(l, "interface")} {T} {{ void m(); }}', ext='implements', member=M('void m()', 'void'), call='t.m();')
kind('dflt',  owner=lambda T, l: f'{mods(l, "interface")} {T} {{ default void m() {{ }} }}', ext='implements', member=M('void m()', 'void'), call='t.m();')
kind('generic', owner=lambda T, l: f'{mods(l, "interface")} {T} {{ void m(); }}', ext='implements', member=M('void m()', 'void'), call='t.m();', generic=True)
# a functional value: implementors are LAMBDAS in factory classes
kind('fn_jdk', owner=None, jdk='Runnable', how='factory', lam=lambda body: f'() -> {{ {body} }}', call='t.run();', family='fnvalue')
kind('fn_own', owner=lambda T, l: f'@FunctionalInterface {mods(l, "interface")} {T} {{ void m(); }}', how='factory', lam=lambda body: f'() -> {{ {body} }}', call='t.m();', family='fnvalue')
kind('mref',  owner=None, jdk='Runnable', how='factory', mref=True, call='t.run();', family='fnvalue')
kind('anon',  owner=lambda T, l: f'{mods(l, "interface")} {T} {{ void m(); }}', how='factory', anon=('m', 'void m()', 'void'), call='t.m();', family='fnvalue')
# explicit Object-protocol calls on a declared T
kind('op_tostr_decl', owner=lambda T, l: f'{mods(l)} {T} {{ public String toString() {{ return "t"; }} }}', ext='extends', member=M('String toString()', 'String'), call='String r = t.toString();', family='objproto')
kind('op_tostr_inh',  owner=lambda T, l: f'{mods(l)} {T} {{ }}', ext='extends', member=M('String toString()', 'String'), call='String r = t.toString();', family='objproto')
kind('op_tostr_iface', owner=lambda T, l: f'{mods(l, "interface")} {T} {{ int k(); }}', ext='implements', member=M('String toString()', 'String'), extra='public int k() { return 1; }', call='String r = t.toString();', family='objproto')
kind('op_hash_inh',   owner=lambda T, l: f'{mods(l)} {T} {{ }}', ext='extends', member=M('int hashCode()', 'int'), call='int r = t.hashCode();', family='objproto')
# implicit runtime -> user hooks
ABS = lambda body='': (lambda T, l: f'{mods(l, "abstract class")} {T} {{ {body} }}')
kind('h_concat',  owner=ABS(), ext='extends', member=M('String toString()', 'String'), call='String r = "v=" + t;', family='hook')
kind('h_valueof', owner=ABS(), ext='extends', member=M('String toString()', 'String'), call='String r = String.valueOf(t);', family='hook')
kind('h_sb',      owner=ABS(), ext='extends', member=M('String toString()', 'String'), call='String r = new StringBuilder().append(t).toString();', family='hook')
kind('h_format',  owner=ABS(), ext='extends', member=M('String toString()', 'String'), call='String r = String.format("%s", t);', family='hook')
kind('h_println', owner=ABS(), ext='extends', member=M('String toString()', 'String'), call='System.out.println(t);', family='hook')
kind('h_exccause', owner=lambda T, l: f'{mods(l, "abstract class")} {T} extends Exception {{ }}', ext='extends', member=M('String toString()', 'String'), call='RuntimeException r = new RuntimeException(t);', family='hook')
kind('h_hashmap', owner=ABS(), ext='extends', member=M('int hashCode()', 'int'), call='new java.util.HashMap<Object, Object>().put(t, 1);', family='hook')
kind('h_equals',  owner=ABS(), ext='extends', member=M('boolean equals(Object o)', 'boolean'), call='boolean r = java.util.Arrays.asList((Object) "a").contains(t);', family='hook')
kind('h_treeset', owner=lambda T, l: f'{mods(l, "abstract class")} {T} implements Comparable<{T.split()[0]}> {{ public int compareTo({T.split()[0]} o) {{ return 0; }} }}',
     ext='extends', member_t=lambda Tref: M(f'int compareTo({Tref} o)', 'int'), call='new java.util.TreeSet<Object>().add(t);', family='hook')
kind('h_sort', owner=lambda T, l: f'{mods(l, "abstract class")} {T} implements Comparable<{T.split()[0]}> {{ public int compareTo({T.split()[0]} o) {{ return 0; }} }}',
     ext='extends', member_t=lambda Tref: M(f'int compareTo({Tref} o)', 'int'),
     call_t=lambda Tref: f'java.util.List<{Tref}> l = new java.util.ArrayList<>(); l.add(t); l.add(t); java.util.Collections.sort(l);', family='hook')
kind('h_foreach', owner=ABS(), owner_impl='implements Iterable<Object>', ext='extends', member=M('java.util.Iterator<Object> iterator()', 'Object'), iter_ret=True, call='for (Object o : t) { }', family='hook')
kind('h_twr', owner=lambda T, l: f'{mods(l, "abstract class")} {T} implements AutoCloseable {{ public void close() {{ }} }}', ext='extends', member=M('void close()', 'void'), call_t=lambda Tref: f'try ({Tref} x = t) {{ }}', family='hook')
kind('h_skel_contains', owner=lambda T, l: f'{mods(l, "abstract class")} {T} extends java.util.AbstractList<Object> {{ public int size() {{ return 1; }} }}', ext='extends', member=M('Object get(int i)', 'Object'), call='boolean r = t.contains("z");', family='hook')
kind('h_skel_tostr', owner=lambda T, l: f'{mods(l, "abstract class")} {T} extends java.util.AbstractCollection<Object> {{ public int size() {{ return 0; }} }}', ext='extends', member=M('java.util.Iterator<Object> iterator()', 'Object'), iter_ret=True, call='String r = t.toString();', family='hook')
kind('h_skel_mapget', owner=lambda T, l: f'{mods(l, "abstract class")} {T} extends java.util.AbstractMap<Object, Object> {{ }}', ext='extends', member=M('java.util.Set<java.util.Map.Entry<Object, Object>> entrySet()', 'Object'), set_ret=True, call='Object r = t.get("k");', family='hook')
kind('h_thread', owner=lambda T, l: f'{mods(l, "abstract class")} {T} extends Thread {{ }}', ext='extends', member=M('void run()', 'void'), call='t.start(); try { t.join(); } catch (InterruptedException e) { }', family='hook')
kind('h_newthread', owner=lambda T, l: f'{mods(l, "interface")} {T} extends Runnable {{ }}', ext='implements', member=M('void run()', 'void'), call='Thread th = new Thread(t); th.start(); try { th.join(); } catch (InterruptedException e) { }', family='hook')
kind('h_cfrun', owner=lambda T, l: f'{mods(l, "interface")} {T} extends Runnable {{ }}', ext='implements', member=M('void run()', 'void'), call='java.util.concurrent.CompletableFuture.runAsync(t).join();', family='hook')
kind('h_listforeach', owner=lambda T, l: f'{mods(l, "interface")} {T} extends java.util.function.Consumer<Object> {{ }}', ext='implements', member=M('void accept(Object o)', 'void'), call='java.util.List.of((Object) 1).forEach(t);', family='hook')
kind('h_sortcmp', owner=lambda T, l: f'{mods(l, "interface")} {T} extends java.util.Comparator<Object> {{ }}', ext='implements', member=M('int compare(Object a, Object b)', 'int'), call='java.util.List<Object> l = new java.util.ArrayList<>(java.util.List.of(1, 2)); l.sort(t);', family='hook')
kind('h_orelseget', owner=lambda T, l: f'{mods(l, "interface")} {T} extends java.util.function.Supplier<Object> {{ }}', ext='implements', member=M('Object get()', 'Object'), call='Object r = java.util.Optional.empty().orElseGet(t);', family='hook')
kind('h_cia', owner=lambda T, l: f'{mods(l, "interface")} {T} extends java.util.function.Function<Object, Object> {{ }}', ext='implements', member=M('Object apply(Object k)', 'Object'), call='new java.util.HashMap<Object, Object>().computeIfAbsent("k", t);', family='hook')
kind('h_serial', owner=lambda T, l: f'{mods(l, "abstract class")} {T} implements java.io.Serializable {{ }}', ext='extends', serial=True,
     call='try { new java.io.ObjectOutputStream(java.io.OutputStream.nullOutputStream()).writeObject(t); } catch (java.io.IOException e) { }', family='hook')
# proven-closed shapes (positive)
kind('sealed', owner=None, sealed=True, ext='implements', member=M('void m()', 'void'), call='t.m();', family='closed')
kind('enum', owner=None, enum=True, call='t.m();', how='enum', family='closed')
# unit identity (positive)
kind('u_overload', owner=lambda T, l: f'{mods(l)} {T} {{ public void m(Object o) {{ }} public void m(String s) {{ }} }}', ext='extends',
     member=M('void m(Object o)', 'void'), extra='public void m(String s) { }', call='t.m((Object) "x");', family='identity')
kind('u_bridge', owner=lambda T, l: f'{mods(l, "interface")} {T}<X> {{ void m(X x); }}', ext='implements', tparam='<String>',
     member=M('void m(String s)', 'void'), call='t.m("x");', ptype_suffix='<String>', family='identity')
kind('u_covariant', owner=lambda T, l: f'{mods(l)} {T} {{ public Object get() {{ return null; }} }}', ext='extends',
     member=M('String get()', 'Object'), call='Object r = t.get();', family='identity')

# ---- deferred (no dispatch through a parameter; the deferred body is WF.loud)
DEFER = {
    'd_tl_local':  dict(call='ThreadLocal<Object> tl = ThreadLocal.withInitial({WF}::loud); tl.get();'),
    'd_tl_param':  dict(holder='public class H {{ ThreadLocal<Object> t; public H(ThreadLocal<Object> t) {{ this.t = t; }} public Object use() {{ return t.get(); }} }}',
                        call='new {H}(ThreadLocal.withInitial({WF}::loud)).use();'),
    'd_tl_own':    dict(holder='public class H {{ ThreadLocal<Object> t = ThreadLocal.withInitial({WF}::loud); public Object use() {{ return t.get(); }} }}',
                        call='new {H}().use();'),
    'd_sup_param': dict(holder='public class H {{ java.util.function.Supplier<Object> s; public H(java.util.function.Supplier<Object> s) {{ this.s = s; }} public Object use() {{ return s.get(); }} }}',
                        call='new {H}({WF}::loud).use();'),
    'd_cf_supply': dict(call='java.util.concurrent.CompletableFuture.supplyAsync({WF}::loud).join();'),
    'd_clinit':    dict(call='int r = {WF}.V;'),
}
# deferred placements: where WF (the deferred body) and H (the container) live
DPLACES = {
    'pkg': dict(WF=('app', 'app'), H=('app', 'app'), chained=False),
    'mod': dict(WF=('app', 'lib'), H=('app', 'lib'), chained=False),
    'unseen': dict(WF=('hid', 'hid'), H=('app', 'lib'), chained=False),
    'dep': dict(WF=('dep', 'dep'), H=('dep', 'dep'), chained=True),
    'deph_appwf': dict(WF=('app', 'app'), H=('dep', 'dep'), chained=True),
    'depunseen': dict(WF=('hid', 'hid'), H=('dep', 'dep'), chained=True),
}

# ---- fabrication controls (ground truth: the effect can NEVER run from go)
# Each is a small explicit program; placements: 'mod' (in-scan) and 'dep' (chained) where meaningful.
def controls():
    E = eff('Fs')
    out = {}
    # unrelated hierarchy with the same member name
    out['c_unrelated'] = dict(
        files={'lib/T.java': 'package lib; public interface T { void m(); }',
               'lib/S0.java': 'package lib; public class S0 implements T { public void m() { } }',
               'lib/S1.java': 'package lib; public class S1 implements T { public void m() { } }',
               'lib/U.java': 'package lib; public interface U { void m(); }',
               'lib/W.java': f'package lib; public class W implements U {{ public void m() {{ {E} }} }}'},
        go='public static void go(lib.T t) { t.m(); }', runs=['new:lib.S0', 'new:lib.S1'],
        extra_run='lib.W', ptype='lib.T')
    # overload: W's effectful member has a different descriptor
    out['c_overload'] = dict(
        files={'lib/T.java': 'package lib; public class T { public void m() { } public void m(int i) { } }',
               'lib/W.java': f'package lib; public class W extends T {{ public void m(int i) {{ {E} }} public void m() {{ }} }}'},
        go='public static void go(lib.T t) { t.m(); }', runs=['new:lib.W', 'new:lib.T'], ptype='lib.T')
    # package-private, NOT overridden across packages (JVMS 5.4.5)
    out['c_pkgpriv'] = dict(
        files={'lib/T.java': 'package lib; public class T { void m() { } public static void call(T t) { t.m(); } }',
               'lib2/W.java': f'package lib2; public class W extends lib.T {{ public void m() {{ {E} }} }}'},
        go='public static void go(lib.T t) { lib.T.call(t); }', runs=['new:lib2.W', 'new:lib.T'], ptype='lib.T')
    # private member shadowed by a subclass's same-named member
    out['c_private'] = dict(
        files={'lib/T.java': 'package lib; public class T { private void m() { } public void call() { m(); } }',
               'lib/W.java': f'package lib; public class W extends T {{ public void m() {{ {E} }} }}'},
        go='public static void go(lib.T t) { t.call(); }', runs=['new:lib.W', 'new:lib.T'], ptype='lib.T')
    # static hiding
    out['c_static'] = dict(
        files={'lib/T.java': 'package lib; public class T { public static void s() { } }',
               'lib/W.java': f'package lib; public class W extends T {{ public static void s() {{ {E} }} }}'},
        go='public static void go(lib.T t) { lib.T.s(); }', runs=['new:lib.W'], ptype='lib.T')
    # sibling: receiver declared as a pure subtype S0; the effectful W is S0's sibling
    out['c_sibling'] = dict(
        files={'lib/T.java': 'package lib; public abstract class T { public abstract void m(); }',
               'lib/S0.java': 'package lib; public class S0 extends T { public void m() { } }',
               'lib/W.java': f'package lib; public class W extends T {{ public void m() {{ {E} }} }}'},
        go='public static void go(lib.S0 t) { t.m(); }', runs=['new:lib.S0'], ptype='lib.S0')
    # exact final receiver
    out['c_final'] = dict(
        files={'lib/T.java': 'package lib; public abstract class T { public abstract void m(); }',
               'lib/S0.java': 'package lib; public final class S0 extends T { public void m() { } }',
               'lib/W.java': f'package lib; public class W extends T {{ public void m() {{ {E} }} }}'},
        go='public static void go(lib.S0 t) { t.m(); }', runs=['new:lib.S0'], ptype='lib.S0')
    # hook on a type whose subtypes are all pure, while an UNRELATED class's toString writes
    out['c_hook_unrelated'] = dict(
        files={'lib/T.java': 'package lib; public abstract class T { }',
               'lib/S0.java': 'package lib; public class S0 extends T { public String toString() { return "s"; } }',
               'lib/W.java': f'package lib; public class W {{ public String toString() {{ {E} return "w"; }} }}'},
        go='public static void go(lib.T t) { String r = "v=" + t; }', runs=['new:lib.S0'], ptype='lib.T')
    # overload of the hooked member: W declares toString(int) (not the protocol member)
    out['c_hook_overload'] = dict(
        files={'lib/T.java': 'package lib; public abstract class T { }',
               'lib/W.java': f'package lib; public class W extends T {{ public String toString(int i) {{ {E} return "w"; }} }}'},
        go='public static void go(lib.T t) { String r = String.valueOf(t); }', runs=['new:lib.W'], ptype='lib.T')
    # skeleton: AbstractList.isEmpty calls only size(), W's effectful get() never runs (R1242's own caution)
    out['c_skel_isempty'] = dict(
        files={'lib/T.java': 'package lib; public abstract class T extends java.util.AbstractList<Object> { public int size() { return 1; } }',
               'lib/W.java': f'package lib; public class W extends T {{ public Object get(int i) {{ {E} return "w"; }} }}'},
        go='public static void go(lib.T t) { boolean r = t.isEmpty(); }', runs=['new:lib.W'], ptype='lib.T')
    # deferred never forced
    out['c_tl_unforced'] = dict(
        files={'lib/WF.java': f'package lib; public class WF {{ public static Object loud() {{ {E} return "w"; }} }}'},
        go='public static void go(Object t) { ThreadLocal<Object> tl = ThreadLocal.withInitial(lib.WF::loud); }', runs=['none'], ptype='Object')
    return out

# ---- SECOND controls (round 1, 2026-10-25): each is the one-variable twin of a control above, or a control for the
# consumer-side resolver CallTargets introduces. Files carry an explicit compile GROUP ('app', 'dep', 'dep2', 'hid')
# so a split package (one runtime package in two groups) can be laid out. negative=False cells are POSITIVE twins:
# the effect DOES run, so a fix to the paired control's fabrication must not delete them.
def controls2():
    E = eff('Fs')
    S = lambda i: f'S{i}'
    out = {}
    # c_pkgpriv's twin: the SAME runtime package split across the chain -> it IS an override (JVMS 5.4.5).
    out['x_pkgpriv_same'] = dict(place='dep', negative=False, files={
        'dep:dep/T.java': 'package dep; public class T { void m() { } public static void call(T t) { t.m(); } }',
        'app:dep/W.java': f'package dep; public class W extends T {{ void m() {{ {E} }} }}'},
        go='public static void go(dep.T t) { dep.T.call(t); }', runs=['new:dep.W'])
    out['x_pkgpriv_same_mod'] = dict(place='mod', negative=False, files={
        'app:lib/T.java': 'package lib; public class T { void m() { } public static void call(T t) { t.m(); } }',
        'app:lib/W.java': f'package lib; public class W extends T {{ void m() {{ {E} }} }}'},
        go='public static void go(lib.T t) { lib.T.call(t); }', runs=['new:lib.W'])
    # c_sibling's twin (R868 with the member DECLARED by the ancestor only): the receiver's type inherits the
    # effectful body, so the UP walk's charge is TRUE here.
    for pl, g, pk in (('dep', 'dep', 'dep'), ('mod', 'app', 'lib')):
        out[f'x_inh_up_{pl}'] = dict(place=pl, negative=False, files={
            f'{g}:{pk}/T.java': f'package {pk}; public abstract class T {{ public void m() {{ {E} }} }}',
            f'{g}:{pk}/S0.java': f'package {pk}; public class S0 extends T {{ }}',
            f'{g}:{pk}/W.java': f'package {pk}; public class W extends T {{ public void m() {{ }} }}'},
            go=f'public static void go({pk}.S0 t) {{ t.m(); }}', runs=[f'new:{pk}.S0'])
    # c_skel_isempty's twin: a skeleton member that calls back, but into a PURE override; the effectful member
    # (toString) is never called by AbstractList.contains.
    for pl, g, pk in (('dep', 'dep', 'dep'), ('mod', 'app', 'lib'), ('appimpl', 'app', 'app')):
        tg, tp = ('dep', 'dep') if pl == 'appimpl' else (g, pk)
        out[f'c_skel_contains_tostr_{pl}'] = dict(place=pl, negative=True, files={
            f'{tg}:{tp}/T.java': f'package {tp}; public abstract class T extends java.util.AbstractList<Object> {{ public int size() {{ return 1; }} }}',
            f'{g}:{pk}/W.java': f'package {pk}; public class W extends {tp}.T {{ public Object get(int i) {{ return "w"; }} public String toString() {{ {E} return "w"; }} }}'},
            go=f'public static void go({tp}.T t) {{ boolean r = t.contains("z"); }}', runs=[f'new:{pk}.W'])
    # c_tl_unforced's twin: a lambda STORED in a field and never run.
    for pl, g, pk in (('dep', 'dep', 'dep'), ('mod', 'app', 'lib')):
        out[f'c_lambda_stored_{pl}'] = dict(place=pl, negative=True, files={
            f'{g}:{pk}/H.java': f'package {pk}; public class H {{ Runnable r; public H(Runnable r) {{ this.r = r; }} public void use() {{ }} }}',
            f'app:app/L.java': f'package app; public class L {{ public static void loud() {{ {E} }} }}'},
            go=f'public static void go(Object o) {{ new {pk}.H(app.L::loud).use(); }}', runs=['none'])
    # CONSUMER-SIDE RESOLVER controls (CallTargets.resolve): the declared type is a DEPENDENCY type, the
    # consumer holds subtypes. (a) an UNRELATED consumer class's effectful member must not be joined;
    # (b) thirteen PURE consumer overrides past the bound must read pure (S4: hedged only where one is charged).
    for hook, call in (('tostr', 'String r = "v=" + t;'), ('decl', 'String r = t.toString();'),
                       ('hash', 'new java.util.HashMap<Object, Object>().put(t, 1);')):
        mem = ('public int hashCode() { %s return 1; }' if hook == 'hash' else 'public String toString() { %s return "w"; }')
        tdecl = ' public String toString() { return "t"; }' if hook == 'decl' else ''
        out[f'c_ct_unrelated_{hook}'] = dict(place='appimpl', negative=True, files={
            'dep:dep/T.java': f'package dep; public abstract class T {{{tdecl} }}',
            'app:app/S0.java': 'package app; public class S0 extends dep.T { ' + (mem % '') + ' }',
            'app:app/U.java': 'package app; public class U { ' + (mem % E) + ' }'},
            go=f'public static void go(dep.T t) {{ {call} }}', runs=['new:app.S0'])
        files = {'dep:dep/T.java': f'package dep; public abstract class T {{{tdecl} }}'}
        for i in range(13):
            files[f'app:app/S{i}.java'] = f'package app; public class S{i} extends dep.T {{ ' + (mem % '') + ' }'
        out[f'c_ct_widepure_{hook}'] = dict(place='appimpl', negative=True, files=files,
            go=f'public static void go(dep.T t) {{ {call} }}', runs=['new:app.S0'])
    # the Object.toString / interface spellings of the same two controls (R1378 / R1379 shapes)
    for spel, tsrc, sext, call in (
            ('inh', 'package dep; public abstract class T { }', 'extends', 'String r = t.toString();'),
            ('iface', 'package dep; public interface T { int k(); }', 'implements', 'String r = t.toString();')):
        extra = ' public int k() { return 1; }' if spel == 'iface' else ''
        out[f'c_ct_unrelated_{spel}'] = dict(place='appimpl', negative=True, files={
            'dep:dep/T.java': tsrc,
            'app:app/S0.java': f'package app; public class S0 {sext} dep.T {{ public String toString() {{ return "s"; }}{extra} }}',
            'app:app/U.java': f'package app; public class U {{ public String toString() {{ {E} return "w"; }} }}'},
            go=f'public static void go(dep.T t) {{ {call} }}', runs=['new:app.S0'])
        files = {'dep:dep/T.java': tsrc}
        for i in range(13):
            files[f'app:app/S{i}.java'] = f'package app; public class S{i} {sext} dep.T {{ public String toString() {{ return "s"; }}{extra} }}'
        out[f'c_ct_widepure_{spel}'] = dict(place='appimpl', negative=True, files=files,
            go=f'public static void go(dep.T t) {{ {call} }}', runs=['new:app.S0'])
    # EXACT producers: the receiver is provably a pure consumer subtype (a factory's return), an effectful SIBLING
    # exists. The consumer half must follow the producer (ExactTypes), not union the overriders.
    for spel, tsrc, sext in (('inh', 'package dep; public abstract class T { }', 'extends'),
                             ('decl', 'package dep; public abstract class T { public String toString() { return "t"; } }', 'extends'),
                             ('iface', 'package dep; public interface T { int k(); }', 'implements')):
        extra = ' public int k() { return 1; }' if spel == 'iface' else ''
        out[f'c_ct_exact_{spel}'] = dict(place='appimpl', negative=True, files={
            'dep:dep/T.java': tsrc,
            'app:app/S0.java': f'package app; public class S0 {sext} dep.T {{ public String toString() {{ return "s"; }}{extra} }}',
            'app:app/W.java': f'package app; public class W {sext} dep.T {{ public String toString() {{ {E} return "w"; }}{extra} }}',
            'app:app/Mk.java': 'package app; public class Mk { public static dep.T s0() { return new S0(); } }'},
            go='public static void go(Object o) { dep.T t = app.Mk.s0(); String r = t.toString(); }',
            runs=['none'])
    # compareTo by name (h_sort's spelling): consumer subtype pure, an unrelated Comparable effectful
    out['c_ct_unrelated_sort'] = dict(place='appimpl', negative=True, files={
        'dep:dep/T.java': 'package dep; public abstract class T implements Comparable<T> { public int compareTo(T o) { return 0; } }',
        'app:app/S0.java': 'package app; public class S0 extends dep.T { public int compareTo(dep.T o) { return 0; } }',
        'app:app/U.java': f'package app; public class U implements Comparable<U> {{ public int compareTo(U o) {{ {E} return 0; }} }}'},
        go='public static void go(dep.T t) { java.util.List<dep.T> l = new java.util.ArrayList<>(); l.add(t); l.add(t); java.util.Collections.sort(l); }',
        runs=['new:app.S0'])
    return out

# ---- ROUND-2 controls (call-target round 2, 2026-10-25; FABLE-REVIEW §3.1/§3.2/§3.4), written and run on published
# 0.40.17 BEFORE the site generator. Same layout as controls2 (files carry their compile group). Three axes:
#   wx_unrelated_*  the consumer overrides the member on a class UNRELATED to, or in a SIBLING subtree of, the
#                   dispatched receiver's static type -> CLEAN;
#   wx_exact_*      dispatch on a value of FINAL type (or a held value typed by an OPEN subclass the consumer does not
#                   subclass: the re-key leg) with a consumer subclass of the base -> CLEAN;
#   nl_*            NON-INVOKING look-alikes, executed: syntax that resembles a hook but runs none -> CLEAN, beside the
#                   positive twins x_* whose effect DOES run (R1441's provided-overload premise among them).
def controls3():
    E = eff('Fs')
    out = {}
    def both(name, negative, files_of, go_of, runs_of, places=('mod', 'appimpl')):
        for pl in places:
            # mod: everything in-scan under lib; appimpl: owner hierarchy in dep, consumer classes in app
            o, c = ('lib', 'lib') if pl == 'mod' else ('dep', 'app')
            og, cg = ('app', 'app') if pl == 'mod' else ('dep', 'app')
            fs = {}
            for k, t in files_of(o, c).items():
                side, path = k.split(':', 1)
                fs[f'{og if side == "o" else cg}:{path}'] = t
            out[f'{name}_{pl}'] = dict(place=pl, negative=negative, files=fs, go=go_of(o, c), runs=runs_of(o, c))
    # -- wx_unrelated: sibling subtree (B, not A) and an unrelated hierarchy, four spellings
    def sib(decl, mem_pure, mem_eff, call, base_extra='', b_mem=''):
        def files(o, c):
            return {f'o:{o}/T.java': f'package {o}; public abstract class T {base_extra} {{ {decl} }}',
                    f'o:{o}/A.java': f'package {o}; public class A extends T {{ {mem_pure} }}',
                    f'o:{o}/B.java': f'package {o}; public class B extends T {{ {b_mem} }}',
                    f'c:{c}/W.java': f'package {c}; public class W extends {o}.B {{ {mem_eff} }}'}
        return files
    both('wx_unrelated_sib_virt', True, sib('public void m() { }', '', f'public void m() {{ {E} }}', ''),
         lambda o, c: f'public static void go({o}.A a) {{ a.m(); }}', lambda o, c: [f'new:{o}.A'])
    both('wx_unrelated_sib_tostr', True, sib('', 'public String toString() { return "a"; }', f'public String toString() {{ {E} return "w"; }}', ''),
         lambda o, c: f'public static void go({o}.A a) {{ String r = "v=" + a; }}', lambda o, c: [f'new:{o}.A'])
    both('wx_unrelated_sib_skel', True, sib('public int size() { return 1; }', 'public Object get(int i) { return "a"; }',
                                            f'public Object get(int i) {{ {E} return "w"; }}', '', base_extra='extends java.util.AbstractList<Object>',
                                            b_mem='public Object get(int i) { return "b"; }'),
         lambda o, c: f'public static void go({o}.A a) {{ boolean r = a.contains("z"); }}', lambda o, c: [f'new:{o}.A'])
    both('wx_unrelated_sib_read', True, sib('', 'public int read() { return -1; }', f'public int read() {{ {E} return -1; }}', '',
                                            base_extra='extends java.io.InputStream', b_mem='public int read() { return -1; }'),
         lambda o, c: f'public static void go({o}.A a) {{ try {{ a.skip(3); }} catch (java.io.IOException e) {{ }} }}', lambda o, c: [f'new:{o}.A'])
    both('wx_unrelated_sib_thread', True, sib('', 'public void run() { }', f'public void run() {{ {E} }}', '', base_extra='extends Thread'),
         lambda o, c: f'public static void go({o}.A a) {{ a.start(); try {{ a.join(); }} catch (InterruptedException e) {{ }} }}', lambda o, c: [f'new:{o}.A'])
    def unrel_skel(o, c):
        return {f'o:{o}/T.java': f'package {o}; public abstract class T extends java.util.AbstractList<Object> {{ public int size() {{ return 1; }} }}',
                f'o:{o}/A.java': f'package {o}; public class A extends T {{ public Object get(int i) {{ return "a"; }} }}',
                f'c:{c}/U.java': f'package {c}; public class U extends java.util.AbstractList<Object> {{ public int size() {{ return 1; }} public Object get(int i) {{ {E} return "u"; }} }}'}
    both('wx_unrelated_skel', True, unrel_skel, lambda o, c: f'public static void go({o}.A a) {{ boolean r = a.contains("z"); }}', lambda o, c: [f'new:{o}.A'])
    # -- wx_exact: a FINAL receiver type, and the re-key leg (held value typed by an open subclass O)
    def fin(decl, mem_eff, base_extra=''):
        def files(o, c):
            return {f'o:{o}/T.java': f'package {o}; public abstract class T {base_extra} {{ {decl} }}',
                    f'o:{o}/F.java': f'package {o}; public final class F extends T {{ }}',
                    f'o:{o}/O.java': f'package {o}; public class O extends T {{ }}',
                    f'o:{o}/Mk.java': f'package {o}; public class Mk {{ public static F f() {{ return new F(); }} public static O o() {{ return new O(); }} '
                                      f'public static T t() {{ return new F(); }} }}',
                    f'o:{o}/Run.java': f'package {o}; public class Run {{ public static void virt(O x) {{ x.m(); }} }}'
                                      if 'm()' in decl else
                                      (f'package {o}; public class Run {{ public static boolean skel(O x) {{ return x.contains("z"); }} }}' if 'size' in decl else
                                       f'package {o}; public class Run {{ }}'),
                    f'c:{c}/W.java': f'package {c}; public class W extends {o}.T {{ {mem_eff} }}'}
        return files
    vf = fin('public void m() { }', f'public void m() {{ {E} }}')
    sf = fin('public int size() { return 1; } public Object get(int i) { return "t"; }', f'public Object get(int i) {{ {E} return "w"; }}',
             base_extra='extends java.util.AbstractList<Object>')
    both('wx_exact_final_virt', True, vf, lambda o, c: f'public static void go(Object x) {{ {o}.F f = {o}.Mk.f(); f.m(); }}', lambda o, c: ['none'])
    both('wx_exact_final_skel', True, sf, lambda o, c: f'public static void go(Object x) {{ {o}.F f = {o}.Mk.f(); boolean r = f.contains("z"); }}', lambda o, c: ['none'])
    both('wx_exact_prod_skel', True, sf, lambda o, c: f'public static void go(Object x) {{ {o}.T t = {o}.Mk.t(); boolean r = t.contains("z"); }}', lambda o, c: ['none'])
    # the EXPLICIT twin of wx_exact_prod_skel: the same exact producer, the member called by name. Bounded CHA over the
    # declared type charges a consumer subclass it cannot be (the licensed over-approximation, R868's family): this
    # cell says whether the skeleton spelling is held to the explicit one's answer, not to a stricter one
    both('wx_exact_prod_virt', True, vf, lambda o, c: f'public static void go(Object x) {{ {o}.T t = {o}.Mk.t(); t.m(); }}', lambda o, c: ['none'])
    both('wx_rekey_virt', True, vf, lambda o, c: f'public static void go(Object x) {{ {o}.Run.virt({o}.Mk.o()); }}', lambda o, c: ['none'])
    both('wx_rekey_skel', True, sf, lambda o, c: f'public static void go(Object x) {{ boolean r = {o}.Run.skel({o}.Mk.o()); }}', lambda o, c: ['none'])
    # -- nl: non-invoking look-alikes (negative) and their positive twins (x_)
    def single(cls_src):
        return lambda o, c: {f'c:{c}/W.java': cls_src(o, c)}
    both('nl_mref_stored_local', True, lambda o, c: {f'c:{c}/L.java': f'package {c}; public class L {{ public static void loud() {{ {E} }} }}'},
         lambda o, c: f'public static void go(Object x) {{ Runnable r = {c}.L::loud; Object k = r; }}', lambda o, c: ['none'])
    both('nl_instanceof', True, single(lambda o, c: f'package {c}; public class W {{ public boolean equals(Object x) {{ {E} return false; }} public int hashCode() {{ return 1; }} }}'),
         lambda o, c: f'public static void go(Object t) {{ boolean b = t instanceof {c}.W; }}', lambda o, c: [f'new:{c}.W'])
    both('nl_requirenonnull', True, single(lambda o, c: f'package {c}; public class W {{ public String toString() {{ {E} return "w"; }} }}'),
         lambda o, c: f'public static void go({c}.W t) {{ java.util.Objects.requireNonNull(t, "msg"); }}', lambda o, c: [f'new:{c}.W'])
    both('nl_thread_unstarted', True, single(lambda o, c: f'package {c}; public class W extends Thread {{ public void run() {{ {E} }} }}'),
         lambda o, c: f'public static void go({c}.W t) {{ t.setName("x"); }}', lambda o, c: [f'new:{c}.W'])
    both('nl_oos_other', True, single(lambda o, c: f'package {c}; public class W implements java.io.Serializable {{ private void writeObject(java.io.ObjectOutputStream s) throws java.io.IOException {{ {E} s.defaultWriteObject(); }} }}'),
         lambda o, c: f'public static void go({c}.W t) {{ try {{ new java.io.ObjectOutputStream(java.io.OutputStream.nullOutputStream()).writeObject(t.getClass().getName()); }} catch (java.io.IOException e) {{ }} }}',
         lambda o, c: [f'new:{c}.W'])
    # R1441: the PROVIDED overload is overridden, so the JDK body that would re-enter read never runs
    def skipov(o, c):
        return {f'o:{o}/T.java': f'package {o}; public abstract class T extends java.io.InputStream {{ public long skip(long n) {{ return n; }} }}',
                f'c:{c}/W.java': f'package {c}; public class W extends {o}.T {{ public int read() {{ {E} return -1; }} }}'}
    both('nl_skip_overridden', True, skipov, lambda o, c: f'public static void go({o}.T t) {{ try {{ t.skip(3); }} catch (Exception e) {{ }} }}',
         lambda o, c: [f'new:{c}.W'])
    def skipown(o, c):
        return {f'c:{c}/W.java': f'package {c}; public class W extends java.io.InputStream {{ public int read() {{ {E} return -1; }} public long skip(long n) {{ return n; }} }}'}
    both('nl_skip_own', True, skipown, lambda o, c: f'public static void go({c}.W t) {{ try {{ t.skip(3); }} catch (Exception e) {{ }} }}', lambda o, c: [f'new:{c}.W'])
    def skipinh(o, c):
        return {f'o:{o}/T.java': f'package {o}; public abstract class T extends java.io.InputStream {{ }}',
                f'c:{c}/W.java': f'package {c}; public class W extends {o}.T {{ public int read() {{ {E} return -1; }} }}'}
    both('x_skip_inherited', False, skipinh, lambda o, c: f'public static void go({o}.T t) {{ try {{ t.skip(3); }} catch (java.io.IOException e) {{ }} }}',
         lambda o, c: [f'new:{c}.W'])
    def wrinh(o, c):
        return {f'o:{o}/T.java': f'package {o}; public abstract class T extends java.io.Writer {{ public void flush() {{ }} public void close() {{ }} }}',
                f'c:{c}/W.java': f'package {c}; public class W extends {o}.T {{ public void write(char[] b, int off, int len) {{ {E} }} }}'}
    both('x_write_inherited', False, wrinh, lambda o, c: f'public static void go({o}.T t) {{ try {{ t.write("s"); }} catch (java.io.IOException e) {{ }} }}',
         lambda o, c: [f'new:{c}.W'])
    # an AbstractCollection skeleton reached through a JDK STATIC: new ArrayList<>(c) runs c.toArray() -> iterator()
    def coll(o, c):
        return {f'o:{o}/T.java': f'package {o}; public abstract class T extends java.util.AbstractCollection<Object> {{ public int size() {{ return 0; }} }}',
                f'c:{c}/W.java': f'package {c}; public class W extends {o}.T {{ public java.util.Iterator<Object> iterator() {{ {E} return java.util.Collections.emptyIterator(); }} }}'}
    both('x_skel_copyctor', False, coll, lambda o, c: f'public static void go({o}.T t) {{ java.util.List<Object> l = new java.util.ArrayList<>(t); }}', lambda o, c: [f'new:{c}.W'])
    both('x_skel_addall', False, coll, lambda o, c: f'public static void go({o}.T t) {{ java.util.List<Object> l = new java.util.ArrayList<>(); l.addAll(t); }}', lambda o, c: [f'new:{c}.W'])
    return out

# ---------------------------------------------------------------- Main
def main_src(go_src, effect, how_needed=True):
    net_setup = net_check = ''
    if effect == 'Net':
        net_setup = ('java.net.ServerSocket ss = new java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress()); '
                     'System.setProperty("cell.port", String.valueOf(ss.getLocalPort()));')
        net_check = ('ss.setSoTimeout(3000); try { ss.accept().close(); java.nio.file.Files.writeString(java.nio.file.Path.of(a[1]), "net"); } '
                     'catch (java.net.SocketTimeoutException e) { } ss.close();')
    return f'''package app;
public class Main {{
  {go_src}
  static Object make(String spec) throws Exception {{
    String[] p = spec.split(":", 2);
    switch (p[0]) {{
      case "new": {{ java.lang.reflect.Constructor<?> c = Class.forName(p[1]).getDeclaredConstructor(); c.setAccessible(true); return c.newInstance(); }}
      case "factory": {{ String[] q = p[1].split("#"); return Class.forName(q[0]).getMethod(q[1]).invoke(null); }}
      case "enum": {{ String[] q = p[1].split("#"); return Class.forName(q[0]).getField(q[1]).get(null); }}
      default: return null;
    }}
  }}
  public static void main(String[] a) throws Exception {{
    System.setProperty("cell.out", a[1]);
    {net_setup}
    Object o = make(a[0]);
    invoke(o);
    {net_check}
    System.exit(0);
  }}
  static void invoke(Object o) throws Exception {{ java.lang.reflect.Method g = null; for (java.lang.reflect.Method x : Main.class.getDeclaredMethods()) if (x.getName().equals("go")) g = x; g.invoke(null, g.getParameterCount() == 0 ? new Object[0] : new Object[] {{ o }}); }}
}}
'''

# ---------------------------------------------------------------- dispatch cell builder
def build_dispatch(kname, kd, pname, pl, n, effect):
    src = Src()
    E = eff(effect)
    T = 'T'
    TL = pl['T']
    jdk = kd.get('jdk')
    Tref = jdk if jdk else ref(TL, T)
    gen_suffix = kd.get('tparam', '')
    # owner
    if kd.get('sealed'):
        if pl['T'][:2] != pl['W'][:2] or pl['T'][:2] != pl['S'][:2] or len(TL) == 3 and pname != 'nested':
            return None
        names = ['W'] + [f'S{i}' for i in range(n - 1)]
        permits = ', '.join(ref(pl['W'], x) for x in names)
        src.add(TL, T, f'{mods(TL, "sealed interface")} {T} permits {permits} {{ void m(); }}')
    elif kd.get('enum'):
        if pl['T'] != pl['W'] or pl['T'] != pl['S']:
            return None
        consts = [f'W {{ public void m() {{ {E} }} }}'] + [f'S{i} {{ public void m() {{ }} }}' for i in range(n - 1)]
        src.add(TL, T, f'{mods(TL, "enum")} {T} {{ ' + ', '.join(consts) + '; public abstract void m(); }')
    elif kd.get('owner'):
        o = kd['owner'](T, TL)
        if kd.get('owner_impl'):
            o = o.replace(f' {T} {{', f' {T} {kd["owner_impl"]} {{', 1)
        src.add(TL, T, o)
    # implementors
    runs_pos = []
    fam = kd['family']
    if kd.get('enum'):
        runs_pos = [f'enum:{binn(TL, T)}#W']
    elif kd['how'] == 'factory':
        # lambdas / method refs / anonymous classes in a factory class F per (group,pkg)
        facs = {}
        def fac_add(loc, meth, body_expr, extra=''):
            facs.setdefault(tuple(loc), []).append((meth, body_expr, extra))
        items = [('w', True)] + [(f's{i}', False) for i in range(n - 1)]
        for meth, effectful in items:
            loc = pl['W'] if effectful else pl['S']
            body = E if effectful else ''
            if kd.get('mref'):
                fac_add(loc, meth, f'F::{meth}Body', f'static void {meth}Body() {{ {body} }}')
            elif kd.get('anon'):
                mname, sig, ret = kd['anon']
                fac_add(loc, meth, f'new {Tref}() {{ public {sig} {{ {body} }} }}')
            else:
                fac_add(loc, meth, kd['lam'](body))
        for loc, ms in facs.items():
            body = '\n'.join(f'  public static {Tref} {m}() {{ return {e}; }}\n  {x}' for m, e, x in ms)
            src.add(loc, 'F', f'{mods(loc)} F {{\n{body}\n}}')
        runs_pos = [f'factory:{binn(pl["W"], "F")}#w']
    else:
        names = [('W', True)] + [(f'S{i}', False) for i in range(n - 1)]
        for nm, effectful in names:
            loc = pl['W'] if effectful else pl['S']
            body = E if effectful else ''
            if kd.get('serial'):
                mem = (f'private void writeObject(java.io.ObjectOutputStream o) throws java.io.IOException {{ {body} o.defaultWriteObject(); }}'
                       if effectful else '')
            else:
                memf = kd['member_t'](Tref) if 'member_t' in kd else kd['member']
                mem = memf(body, effectful)
                if kd.get('iter_ret'):
                    mem = mem.replace('return "s";', 'return java.util.Collections.emptyIterator();')
                if kd.get('set_ret'):
                    mem = mem.replace('return "s";', 'return java.util.Collections.emptySet();')
            extra = kd.get('extra', '')
            sealed_final = 'final ' if kd.get('sealed') else ''
            kw = f'{sealed_final}class'
            src.add(loc, nm, f'{mods(loc, kw)} {nm} {kd["ext"]} {Tref}{gen_suffix} {{ {mem} {extra} }}')
        runs_pos = [f'new:{binn(pl["W"], "W")}']
    # call site
    ptype = Tref + kd.get('ptype_suffix', '')
    call = kd['call_t'](Tref) if 'call_t' in kd else kd['call']
    if 'RUN' in pl:
        rl = pl['RUN']
        src.add(rl, 'Run', f'{mods(rl)} Run {{ public static void go({ptype} t) {{ {call} }} }}')
        go = f'public static void go({ptype} t) {{ {ref(rl, "Run")}.go(t); }}'
    elif kd.get('generic'):
        go = f'public static <X extends {ptype}> void go(X t) {{ {call} }}'
    else:
        go = f'public static void go({ptype} t) {{ {call} }}'
    return src, go, runs_pos

def build_defer(kname, dk, pname, pl, effect):
    src = Src()
    E = eff(effect)
    WFl, Hl = pl['WF'], pl['H']
    if kname == 'd_clinit':
        src.add(WFl, 'WF', f'{mods(WFl)} WF {{ public static int V; static {{ {E} V = 1; }} }}')
    else:
        src.add(WFl, 'WF', f'{mods(WFl)} WF {{ public static Object loud() {{ {E} return "w"; }} }}')
    fmt = dict(WF=ref(WFl, 'WF'), H=ref(Hl, 'H'))
    if 'holder' in dk:
        src.add(Hl, 'H', dk['holder'].format(**fmt).replace('public class H', mods(Hl) + ' H', 1).replace('{{', '{').replace('}}', '}'))
    call = dk['call'].format(**fmt)
    go = f'public static void go() {{ {call} }}'
    return src, go, ['none']

# ---------------------------------------------------------------- emit
def emit(cid, meta, src_files, go, runs, effect, chained, negative=False):
    d = os.path.join(CELLS, cid)
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(d)
    files = dict(src_files)
    files['src/app/app/Main.java'] = main_src(go, 'Fs' if effect == 'FsHid' else effect)
    if effect == 'FsHid':
        files['src/hid/hid/Leaf.java'] = ('package hid; public class Leaf { public static void write() { '
            'try { java.nio.file.Files.writeString(java.nio.file.Path.of(System.getProperty("cell.out")), "x"); } catch (Exception e) { } } }')
    groups = sorted({p.split('/')[1] for p in files})
    for p, t in files.items():
        fp = os.path.join(d, p)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        open(fp, 'w').write(t)
    meta.update(id=cid, effect=effect, chained=chained, groups=groups, runs=runs, negative=negative,
                gated='app.Main.go')
    json.dump(meta, open(os.path.join(d, 'cell.json'), 'w'), indent=1)
    return cid

def sig_of(kd, pl):
    # canonical placement signature, used to drop duplicate placements for JDK-owner kinds
    t = None if kd.get('jdk') else pl['T']
    return (t, pl['W'], pl['S'], pl.get('RUN'))

def main():
    os.makedirs(CELLS, exist_ok=True)
    ids = []
    pruned = []
    for kname, kd in K.items():
        seen = {}
        for pname, pl in PLACES.items():
            if kd.get('generic') and pname not in ('mod', 'dep', 'appimpl'):
                pruned.append((kname, pname, 'erasure: bytecode identical to iface; sampled at mod/dep/appimpl only'))
                continue
            s = sig_of(kd, pl)
            if s in seen:
                pruned.append((kname, pname, f'JDK owner: identical program to placement {seen[s]}'))
                continue
            seen[s] = pname
            counts = list(kd['counts'])
            if kd['family'] in ('explicit', 'objproto', 'fnvalue', 'closed'):
                counts = sorted(set(counts + [12]))
            for n in counts:
                for effect in ['Fs', 'Net', 'Exec', 'FsHid']:
                    if MODE == 'extra':
                        if not ((pname == 'cbthird' and effect == 'Fs') or (effect == 'FsHid' and n in (3, 13) and pname in ('mod', 'dep', 'appimpl', 'callback')
                                and kd['family'] in ('explicit', 'objproto', 'hook', 'identity'))):
                            continue
                    elif pname == 'cbthird' or effect == 'FsHid':
                        continue
                    elif effect != 'Fs' and not (kname in ('virt', 'iface', 'fn_jdk', 'op_tostr_decl', 'h_concat', 'h_hashmap')
                                               and pname in ('mod', 'dep', 'appimpl', 'callback') and n in (3, 13)):
                        continue
                    r = build_dispatch(kname, kd, pname, pl, n, effect)
                    if r is None:
                        if effect == 'Fs':
                            pruned.append((kname, f'{pname}/n{n}', 'sealed/enum: permitted subclasses / constants must share the owner package'))
                        continue
                    src, go, runs = r
                    cid = f'{kname}.{pname}.n{n}.{effect}'
                    ids.append(emit(cid, dict(kind=kname, family=kd['family'], place=pname, n=n), src.files(), go, runs, effect, pl['chained']))
    for kname, dk in (DEFER.items() if MODE == 'base' else []):
        for pname, pl in DPLACES.items():
            for effect in ['Fs']:
                src, go, runs = build_defer(kname, dk, pname, pl, effect)
                cid = f'{kname}.{pname}.n1.{effect}'
                ids.append(emit(cid, dict(kind=kname, family='deferred', place=pname, n=1), src.files(), go, runs, effect, pl['chained']))
    # controls: in-scan (group app) and chained (lib -> dep group, call in app)
    for cname, c in (controls().items() if MODE == 'base' else {}.items()):
        for pname in ('mod', 'dep'):
            files = {}
            for p, t in c['files'].items():
                g = 'app' if pname == 'mod' else 'dep'
                if pname == 'dep':
                    t = t.replace('package lib;', 'package dep;').replace('package lib2;', 'package dep2x;').replace('lib.', 'dep.').replace('lib2.', 'dep2x.')
                    p = p.replace('lib2/', 'dep2x/').replace('lib/', 'dep/')
                files[f'src/{g}/{p}'] = t
            go = c['go'] if pname == 'mod' else c['go'].replace('lib.', 'dep.')
            runs = c['runs'] if pname == 'mod' else [r.replace('lib2.', 'dep2x.').replace('lib.', 'dep.') for r in c['runs']]
            cid = f'{cname}.{pname}.n0.Fs'
            ids.append(emit(cid, dict(kind=cname, family='control', place=pname, n=0), files, go, runs, 'Fs', pname == 'dep', negative=True))
    for cname, c in (list(controls2().items()) + list(controls3().items()) if MODE == 'base' else []):
        files = {}
        for k, t in c['files'].items():
            g, p = k.split(':', 1)
            files[f'src/{g}/{p}'] = t
        cid = f'{cname}.{c["place"]}.n0.Fs'
        chained = c['place'] != 'mod'
        ids.append(emit(cid, dict(kind=cname, family='control2', place=c['place'], n=0), files, c['go'], c['runs'], 'Fs',
                        chained, negative=c['negative']))
    json.dump(dict(ids=ids, pruned=pruned), open(os.path.join(OUT, 'manifest.json'), 'w'), indent=1)
    print(len(ids), 'cells;', len(pruned), 'pruned')

main()
