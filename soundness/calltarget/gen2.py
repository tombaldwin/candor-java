#!/usr/bin/env python3
"""Extra cells: Kotlin (kotlinc 2.4, default indy lambdas) and Java shapes named by the code inventory as
code-read candidates. Compiles here (one kotlinc call for all Kotlin cells) and marks build/.ok so run.py skips
compilation. Every cell gates app.Main.go, which calls into the cell's own package."""
import json, os, sys, subprocess, shutil, glob
OUT = sys.argv[1]
CELLS = os.path.join(OUT, 'cells')
KHOME = os.environ.get('CT_KOTLIN_HOME', os.path.expanduser('~/.sdkman/candidates/kotlin/current'))
STDLIB = f'{KHOME}/lib/kotlin-stdlib.jar'
JH = os.environ.get('CT_JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home')
ENV = dict(os.environ, JAVA_HOME=JH, PATH=f'{JH}/bin:' + os.environ['PATH'])
FS = 'java.nio.file.Files.writeString(java.nio.file.Path.of(System.getProperty("cell.out")), "x")'
FSJ = f'try {{ {FS}; }} catch (Exception e) {{ }}'

def loud_kt(p):
    return f'fun loud(): String {{ {FS}; return "w" }}\n'

# kotlin cells: name -> (kotlin source in package P, java go body calling it, run spec, negative?)
KT = {
 'k_lazy_local': ('fun go() { val v by lazy { loud() }; v.length }', 'P.KKt.go();', 'none'),
 'k_lazy_member': ('class H { val v by lazy { loud() } }\nfun go() { H().v.length }', 'P.KKt.go();', 'none'),
 'k_template': ('abstract class T\nclass W : T() { override fun toString(): String = loud() }\nclass S0 : T() { override fun toString() = "s" }\nclass S1 : T() { override fun toString() = "s" }\nfun go(t: T) { "v=$t".length }', 'P.KKt.go((P.T) t);', 'new:P.W'),
 'k_dataclass': ('abstract class T\nclass W : T() { override fun toString(): String = loud() }\nclass S0 : T() { override fun toString() = "s" }\ndata class D(val t: T)\nfun go(t: T) { D(t).toString().length }', 'P.KKt.go((P.T) t);', 'new:P.W'),
 'k_delegation': ('interface T { fun m() }\nclass W : T { override fun m() { loud() } }\nclass S0 : T { override fun m() { } }\nclass D(i: T) : T by i\nfun go(t: T) { D(t).m() }', 'P.KKt.go((P.T) t);', 'new:P.W'),
 'k_funiface': ('fun interface T { fun m() }\nobject F { @JvmStatic fun w(): T = T { loud() }\n @JvmStatic fun s0(): T = T { } }\nfun go(t: T) { t.m() }', 'P.KKt.go((P.T) t);', 'factory:P.F#w'),
 'k_fnvalue': ('object F { @JvmStatic fun w(): () -> Unit = { loud() }\n @JvmStatic fun s0(): () -> Unit = { } }\nfun go(t: () -> Unit) { t() }', 'P.KKt.go((kotlin.jvm.functions.Function0<kotlin.Unit>) t);', 'factory:P.F#w'),
 'k_fnfield': ('class H(val f: () -> Unit) { fun use() = f() }\nfun go() { H { loud() }.use() }', 'P.KKt.go();', 'none'),
 'k_fnfield_mut': ('class H { var f: () -> Unit = { }\n fun use() = f() }\nfun go(o: Any?) { val h = H(); if (o != null) h.f = o as () -> Unit; h.f = { loud() }; h.use() }', 'P.KKt.go(null);', 'none'),
 'k_operator': ('interface T { operator fun plus(o: T): T }\nclass W : T { override fun plus(o: T): T { loud(); return this } }\nclass S0 : T { override fun plus(o: T): T = this }\nfun go(t: T) { t + t }', 'P.KKt.go((P.T) t);', 'new:P.W'),
 'k_default': ('fun f(x: String = loud()) = x.length\nfun go() { f() }', 'P.KKt.go();', 'none'),
 'k_inline': ('inline fun run2(b: () -> Unit) = b()\nfun go() { run2 { loud() } }', 'P.KKt.go();', 'none'),
 'k_seq': ('fun go() { sequenceOf(1).map { loud() }.toList() }', 'P.KKt.go();', 'none'),
 'k_listmap_noninline': ('fun go() { listOf(1).forEach { loud() } }', 'P.KKt.go();', 'none'),
 'k_sealed': ('sealed interface T { fun m() }\nclass W : T { override fun m() { loud() } }\nclass S0 : T { override fun m() { } }\nfun go(t: T) { t.m() }', 'P.KKt.go((P.T) t);', 'new:P.W'),
}

# java extras: name -> (files {relpath: src}, go src, run spec)
JX = {
 'x_anon_fieldinit': ({'lib/H.java': f'package lib; public class H {{ Runnable r = new Runnable() {{ public void run() {{ {FSJ} }} }}; public void use() {{ r.run(); }} }}'},
                      'public static void go(Object o) { new lib.H().use(); }', 'none'),
 'x_anon_static': ({'lib/H.java': f'package lib; public class H {{ static final Runnable R = new Runnable() {{ public void run() {{ {FSJ} }} }}; public static void use() {{ R.run(); }} }}'},
                   'public static void go(Object o) { lib.H.use(); }', 'none'),
 'x_thread_opaque': ({'lib/W.java': f'package lib; public class W implements Runnable {{ public void run() {{ {FSJ} }} public static Thread make() {{ return new Thread(new W()); }} }}'},
                     'public static void go(Thread t) { t.start(); try { t.join(); } catch (InterruptedException e) { } }', 'factory:lib.W#make'),
 'x_hof_indirect': ({'lib/B.java': 'package lib; public abstract class B implements java.util.function.Consumer<Object> { }',
                     'lib/W.java': f'package lib; public class W extends B {{ public void accept(Object o) {{ {FSJ} }} }}'},
                    'public static void go(Object o) { java.util.List.of((Object) 1).forEach(new lib.W()); }', 'none'),
 'x_hof_direct': ({'lib/W.java': f'package lib; public class W implements java.util.function.Consumer<Object> {{ public void accept(Object o) {{ {FSJ} }} }}'},
                  'public static void go(Object o) { java.util.List.of((Object) 1).forEach(new lib.W()); }', 'none'),
 'x_lambda_field_late': ({'lib/H.java': f'package lib; public class H {{ Runnable r; public void set() {{ r = () -> {{ {FSJ} }}; }} public void use() {{ r.run(); }} }}'},
                         'public static void go(Object o) { lib.H h = new lib.H(); h.set(); h.use(); }', 'none'),
 'x_lambda_list': ({'lib/H.java': f'package lib; public class H {{ public static java.util.List<Runnable> make() {{ java.util.List<Runnable> l = new java.util.ArrayList<>(); l.add(() -> {{ {FSJ} }}); return l; }} }}'},
                   'public static void go(Object o) { for (Runnable r : lib.H.make()) r.run(); }', 'none'),
 'x_supplier_return': ({'lib/H.java': f'package lib; public class H {{ public static java.util.function.Supplier<String> make() {{ return () -> {{ {FSJ} return "w"; }}; }} }}'},
                       'public static void go(Object o) { lib.H.make().get(); }', 'none'),
 'x_iface_static_private': ({'lib/T.java': f'package lib; public interface T {{ static void s() {{ p(); }} private static void p() {{ {FSJ} }} }}'},
                            'public static void go(Object o) { lib.T.s(); }', 'none'),
 'x_super_default': ({'lib/T.java': f'package lib; public interface T {{ default void m() {{ {FSJ} }} }}',
                      'lib/W.java': 'package lib; public class W implements T { public void m() { T.super.m(); } }'},
                     'public static void go(lib.T t) { t.m(); }', 'new:lib.W'),
 'x_reflect_invoke': ({'lib/W.java': f'package lib; public class W {{ public static void m() {{ {FSJ} }} }}'},
                      'public static void go(Object o) { try { Class.forName("lib.W").getMethod("m").invoke(null); } catch (Exception e) { } }', 'none'),
 'x_serviceloader': ({'lib/T.java': 'package lib; public interface T { void m(); }',
                      'lib/W.java': f'package lib; public class W implements T {{ public void m() {{ {FSJ} }} }}',
                      'META-INF/services/lib.T': 'lib.W\n'},
                     'public static void go(Object o) { for (lib.T t : java.util.ServiceLoader.load(lib.T.class)) t.m(); }', 'none'),
}

MAIN = open(os.path.join(os.path.dirname(__file__), 'gen.py')).read()

def main_src(go):
    ns = {}
    # reuse gen.py's Main template without running gen.main()
    src = MAIN.split('# ---------------------------------------------------------------- Main')[1].split('# ---------------------------------------------------------------- dispatch')[0]
    exec('import json\n' + src, ns)
    return ns['main_src'](go, 'Fs')

def sh(cmd, **kw):
    p = subprocess.run(cmd, env=ENV, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        print(' '.join(cmd[:4]), p.stdout[-2000:], p.stderr[-3000:])
        raise SystemExit(1)

def meta(cid, kind, run, extra_cp, fam):
    return dict(id=cid, kind=kind, family=fam, place='pkg', n=1, effect='Fs', chained=False, groups=['app'],
                runs=[run], negative=False, gated='app.Main.go', extra_cp=extra_cp)

def emit_built(cid, m, classes_dir, main_go, extra_cp_compile, resources=None):
    d = os.path.join(CELLS, cid)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, 'src/app/app'))
    open(os.path.join(d, 'src/app/app/Main.java'), 'w').write(main_src(main_go))
    b = os.path.join(d, 'build', 'app')
    shutil.copytree(classes_dir, b)
    sh([f'{JH}/bin/javac', '-nowarn', '-cp', ':'.join([b] + extra_cp_compile), '-d', b, os.path.join(d, 'src/app/app/Main.java')])
    for rel, txt in (resources or {}).items():
        fp = os.path.join(b, rel); os.makedirs(os.path.dirname(fp), exist_ok=True); open(fp, 'w').write(txt)
    open(os.path.join(d, 'build', '.ok'), 'w').write('ok')
    json.dump(m, open(os.path.join(d, 'cell.json'), 'w'), indent=1)

def main():
    os.makedirs(CELLS, exist_ok=True)
    ids = []
    # Kotlin: one compile
    ks = os.path.join(OUT, 'ksrc'); kb = os.path.join(OUT, 'kbuild')
    shutil.rmtree(ks, ignore_errors=True); shutil.rmtree(kb, ignore_errors=True); os.makedirs(ks)
    for name, (src, go, run) in KT.items():
        P = name
        open(os.path.join(ks, f'{name}.kt'), 'w').write(f'@file:JvmName("KKt")\npackage {P}\n{loud_kt(P)}{src}\n')
    sh([f'{KHOME}/bin/kotlinc', '-jvm-target', '17', '-d', kb] + sorted(glob.glob(os.path.join(ks, '*.kt'))), timeout=900)
    for name, (src, go, run) in KT.items():
        tmp = os.path.join(OUT, 'ktmp', name)
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.copytree(os.path.join(kb, name), os.path.join(tmp, name))
        jgo = f'public static void go(Object t) {{ {go.replace("P.", name + ".")} }}'
        cid = f'{name}.pkg.n1.Fs'
        emit_built(cid, meta(cid, name, run.replace('P.', name + '.'), [STDLIB], 'kotlin'), tmp, jgo, [STDLIB])
        ids.append(cid)
    # Java extras
    for name, (files, go, run) in JX.items():
        src = os.path.join(OUT, 'jxsrc', name); out = os.path.join(OUT, 'jxbuild', name)
        shutil.rmtree(src, ignore_errors=True); shutil.rmtree(out, ignore_errors=True); os.makedirs(out)
        res = {}
        jfiles = []
        for rel, txt in files.items():
            if not rel.endswith('.java'):
                res[rel] = txt; continue
            fp = os.path.join(src, rel); os.makedirs(os.path.dirname(fp), exist_ok=True); open(fp, 'w').write(txt); jfiles.append(fp)
        sh([f'{JH}/bin/javac', '-nowarn', '-d', out] + jfiles)
        cid = f'{name}.mod.n1.Fs'
        m = meta(cid, name, run, [], 'extra'); m['place'] = 'mod'
        emit_built(cid, m, out, go, [], res)
        ids.append(cid)
    json.dump(dict(ids=ids, pruned=[]), open(os.path.join(OUT, 'manifest.json'), 'w'), indent=1)
    print(len(ids), 'cells')

main()
