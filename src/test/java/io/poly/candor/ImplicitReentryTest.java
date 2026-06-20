package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
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

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-reentry");
        List<String> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path p = dir.resolve(e.getKey());
            Files.createDirectories(p.getParent());
            Files.writeString(p, e.getValue());
            files.add(p.toString());
        }
        Path out = dir.resolve("cls");
        Files.createDirectories(out);
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        args.addAll(files);
        org.junit.jupiter.api.Assertions.assertEquals(
                0, jc.run(null, null, null, args.toArray(new String[0])), "fixture must compile");
        return out;
    }

    private static void rm(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

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
