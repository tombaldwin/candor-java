package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * IMPLICIT-CONTRACT-REENTRY: a JDK sink candor models as a pure leaf actually re-enters user code via the
 * JVM's implicit contract — {@code String.valueOf}/concat/{@code StringBuilder.append}/{@code String.format}
 * call {@code toString}; {@code Set.contains}/{@code Map.get}/{@code HashSet.add} call {@code equals}+{@code
 * hashCode}; {@code TreeSet.add} calls {@code compareTo}. An EFFECTFUL override reached only through such a
 * sink previously read silent-pure (the cardinal sin). The fix CHA-dispatches the contract method over the
 * ARGUMENT's declared type and edges to its LOCAL override(s) — and only those, so a String/Integer/external
 * argument or a pure override contributes nothing (no flood, no fabrication). Same shape as the
 * executor-handoff fix: an opaque callee re-entering user code.
 */
class ImplicitReentryTest {

    private static boolean fs(Map<String, EffectSet> r, String m) {
        return r.getOrDefault(m, EffectSet.empty()).toNames().contains("Fs");
    }

    // ---- toString reentry: each sink carries the effectful override's Fs --------------------------------
    @Test void toStringViaConcat() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Loud x){ String s = \"ctx=\"+x; }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "concat toString reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void toStringViaValueOf() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Loud x){ String s = String.valueOf(x); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "String.valueOf reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void toStringViaAppend() throws Exception {
        Path cls = compile(Map.of("app/D.java",
            wrap("void m(Loud x){ StringBuilder b=new StringBuilder(); b.append(x); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "StringBuilder.append(Object) reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void toStringViaFormat() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Loud x){ String s = String.format(\"v=%s\", x); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "String.format reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void toStringViaPrintln() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Loud x){ System.out.println(x); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "PrintStream.println(Object) reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void realisticLogConcat() throws Exception {
        // log(obj) { logger.info("ctx="+obj) } where obj.toString does FileOutputStream → log carries Fs.
        Path cls = compile(Map.of("app/D.java",
            wrap("void log(Loud x){ java.util.logging.Logger.getLogger(\"a\").info(\"ctx=\"+x); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.log"), "realistic log(concat) must carry the toString Fs"); }
        finally { rm(cls.getParent()); }
    }

    // ---- toString NO-FABRICATION controls --------------------------------------------------------------
    @Test void pureToStringStaysPure() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Quiet q){ String s = \"ctx=\"+q; }")));
        try { assertFalse(fs(Candor.runScan(cls), "app.D.m"), "pure toString via concat must stay pure"); }
        finally { rm(cls.getParent()); }
    }
    @Test void stringOperandStaysPure() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(String v){ String s = \"ctx=\"+v; }")));
        try { assertFalse(fs(Candor.runScan(cls), "app.D.m"), "String operand (non-local) must stay pure"); }
        finally { rm(cls.getParent()); }
    }
    @Test void primitiveOperandStaysPure() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(int i){ String s = \"ctx=\"+i; }")));
        try { assertFalse(fs(Candor.runScan(cls), "app.D.m"), "primitive operand must stay pure"); }
        finally { rm(cls.getParent()); }
    }

    // ---- equals/hashCode reentry -----------------------------------------------------------------------
    @Test void equalsViaSetContains() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Set<Keyed> s, Keyed k){ boolean b=s.contains(k); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "Set.contains equals/hashCode reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void equalsViaMapGet() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Map<Keyed,String> mp, Keyed k){ String s=mp.get(k); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "Map.get key equals/hashCode reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void hashViaHashSetAdd() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(HashSet<Keyed> s, Keyed k){ s.add(k); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "HashSet.add equals/hashCode reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void pureKeyContainsStaysPure() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Set<PureKey> s, PureKey k){ boolean b=s.contains(k); }")));
        try { assertFalse(fs(Candor.runScan(cls), "app.D.m"), "pure key contains must stay pure"); }
        finally { rm(cls.getParent()); }
    }
    @Test void stringKeyContainsStaysPure() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Set<String> s, String k){ boolean b=s.contains(k); }")));
        try { assertFalse(fs(Candor.runScan(cls), "app.D.m"), "String key contains (non-local) must stay pure"); }
        finally { rm(cls.getParent()); }
    }

    // ---- compareTo reentry (direct-arg form) -----------------------------------------------------------
    @Test void compareToViaTreeSetAdd() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(TreeSet<Ord> ts, Ord o){ ts.add(o); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "TreeSet.add compareTo reentry must carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void integerSortStaysPure() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(List<Integer> xs){ Collections.sort(xs); }")));
        try { assertFalse(fs(Candor.runScan(cls), "app.D.m"), "sort(List<Integer>) (non-local) must stay pure"); }
        finally { rm(cls.getParent()); }
    }

    // ---- explicit forms must STILL carry (no regression) -----------------------------------------------
    @Test void explicitToStringStillCarries() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Loud x){ String s = x.toString(); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "explicit o.toString() must still carry Fs"); }
        finally { rm(cls.getParent()); }
    }
    @Test void explicitEqualsStillCarries() throws Exception {
        Path cls = compile(Map.of("app/D.java", wrap("void m(Keyed a, Keyed b){ boolean r = a.equals(b); }")));
        try { assertTrue(fs(Candor.runScan(cls), "app.D.m"), "explicit a.equals(b) must still carry Fs"); }
        finally { rm(cls.getParent()); }
    }

    // ---- WRITER side (R16): a JDK formatting facade over a CUSTOM sink drives the sink's append/write.
    // `new Formatter(Appendable).format` / `new PrintWriter(Writer).printf` reach the sink's method only
    // through the non-local facade, so an effectful custom sink was silent-pure (the write-fmt writer-side
    // blind spot, closed in the rust/scan/swift engines too). A std StringBuilder sink stays pure. ------
    private static Path compileWriter() throws Exception {
        return compile(Map.of("app/W.java", String.join("\n",
            "package app;",
            "import java.io.*; import java.util.*;",
            "class LoudSink implements Appendable {",
            "  public Appendable append(CharSequence c){ try{ new FileOutputStream(\"/tmp/ls\").write(1);}catch(Exception e){} return this; }",
            "  public Appendable append(CharSequence c,int s,int e){ return this; }",
            "  public Appendable append(char c){ return this; } }",
            "class LoudWriter extends Writer {",
            "  public void write(char[] b,int o,int l){ try{ new FileOutputStream(\"/tmp/lw\").write(1);}catch(Exception e){} }",
            "  public void flush(){} public void close(){} }",
            "public class W {",
            "  void viaFormatter(){ LoudSink s = new LoudSink(); new Formatter(s).format(\"hi %s\", 1); }",
            "  void viaPrintWriter(){ LoudWriter w = new LoudWriter(); new PrintWriter(w).printf(\"hi %s\", 1); }",
            "  void viaStringBuilder(){ StringBuilder sb = new StringBuilder(); new Formatter(sb).format(\"hi %s\", 1); } }")));
    }

    @Test void writerSideCustomSinkCarriesEffect() throws Exception {
        Path cls = compileWriter();
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(fs(r, "app.W.viaFormatter"), "new Formatter(customAppendable).format must carry the sink's append Fs");
            assertTrue(fs(r, "app.W.viaPrintWriter"), "new PrintWriter(customWriter).printf must carry the sink's write Fs");
            assertFalse(fs(r, "app.W.viaStringBuilder"), "a std StringBuilder sink must stay pure (no fabrication)");
        } finally { rm(cls.getParent()); }
    }

    // ---- R32: a DIRECT call to a concrete PROVIDED java.io method (`w.write(String)` / `r.read(char[])`)
    // whose JDK body drives the abstract required method on the RECEIVER. A custom effectful Writer/Reader
    // subclass reached only via a provided overload was silent-pure (the direct sibling of the R16 facade
    // case). Every receiver form must carry; a pure impl / coincidental non-io `write` / std sink stays pure.
    private static Path compileDirectProvided() throws Exception {
        return compile(Map.of("app/W.java", String.join("\n",
            "package app;",
            "import java.io.*; import java.nio.file.*;",
            "class LoudWriter extends Writer {",
            "  public void write(char[] c,int o,int l) throws IOException { Files.write(Paths.get(\"/tmp/x\"), new String(c,o,l).getBytes()); }",
            "  public void flush(){} public void close(){} }",
            "class QuietWriter extends Writer {",
            "  public void write(char[] c,int o,int l){}",   // pure
            "  public void flush(){} public void close(){} }",
            "class LoudReader extends Reader {",
            "  public int read(char[] c,int o,int l) throws IOException { return (int) Files.size(Paths.get(\"/tmp/x\")); }",
            "  public void close(){} }",
            "class Logger { void write(String s){} }",       // coincidental non-io write
            "public class W {",
            "  void viaParam(LoudWriter w) throws IOException { w.write(\"hi\"); }",
            "  void viaLocalNew() throws IOException { LoudWriter w = new LoudWriter(); w.write(\"hi\"); }",
            "  void viaBaseLocal() throws IOException { Writer w = new LoudWriter(); w.write(\"hi\"); }",
            "  void viaAppend(LoudWriter w) throws IOException { w.append(\"hi\"); }",
            "  void viaReader(LoudReader r) throws IOException { char[] b=new char[4]; r.read(b); }",
            "  void viaQuiet(QuietWriter w) throws IOException { w.write(\"hi\"); }",
            "  void viaLogger(Logger g){ g.write(\"x\"); }",
            "  void viaStdSink() throws IOException { StringWriter sw=new StringWriter(); sw.write(\"x\"); } }")));
    }

    @Test void directProvidedIoMethodReachesReceiverOverride() throws Exception {
        Path cls = compileDirectProvided();
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(fs(r, "app.W.viaParam"),     "w.write(String) on a param LoudWriter must carry Fs");
            assertTrue(fs(r, "app.W.viaLocalNew"),  "w.write(String) on a local-new LoudWriter must carry Fs");
            assertTrue(fs(r, "app.W.viaBaseLocal"), "w.write(String) on a base-typed LoudWriter must carry Fs");
            assertTrue(fs(r, "app.W.viaAppend"),    "w.append(..) drives the Writer's write override → Fs");
            assertTrue(fs(r, "app.W.viaReader"),    "r.read(char[]) on a custom Reader must carry the read override's Fs");
            assertFalse(fs(r, "app.W.viaQuiet"),    "a pure Writer override must stay pure (no over-fire)");
            assertFalse(fs(r, "app.W.viaLogger"),   "a coincidental non-io write() must not get an io reentry");
            assertFalse(fs(r, "app.W.viaStdSink"),  "a std StringWriter sink must stay pure (no fabrication)");
        } finally { rm(cls.getParent()); }
    }

    /** Wrap a single method body in the shared D class + contract-override fixtures. */
    private static String wrap(String method) {
        return String.join("\n",
            "package app;",
            "import java.io.*;",
            "import java.util.*;",
            "class Loud { public String toString() {",
            "  try { new FileOutputStream(\"/tmp/loud\").write(1); } catch (Exception e) {} return \"x\"; } }",
            "class Quiet { public String toString() { return \"q\"; } }",
            "class Keyed {",
            "  public boolean equals(Object o) {",
            "    try { new FileOutputStream(\"/tmp/keq\").write(1); } catch (Exception e) {} return o==this; }",
            "  public int hashCode() {",
            "    try { new FileOutputStream(\"/tmp/khc\").write(1); } catch (Exception e) {} return 7; } }",
            "class PureKey { public boolean equals(Object o){return o==this;} public int hashCode(){return 3;} }",
            "class Ord implements Comparable<Ord> {",
            "  public int compareTo(Ord o) {",
            "    try { new FileOutputStream(\"/tmp/cmp\").write(1); } catch (Exception e) {} return 0; } }",
            "public class D { " + method + " }");
    }
}
