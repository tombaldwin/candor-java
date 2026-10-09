package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R492/R727 — the GENERATED framework table ({@link FrameworkReach}).
 *
 * <p>Two halves. The table's own INTEGRITY: it is machine output, so a hand edit (content checksum) or a generator
 * change it was not regenerated for (generator checksum over {@code FrameworkReachGen.java}, {@code derive.sh} and
 * {@code sources.tsv}) fails here, on every push. Whether it is still what its inputs produce against THIS engine is
 * {@code derive.sh --check}, which needs the jars and runs weekly. And the engine's USE of it: each spelling of a
 * call that resolves to a charged member — direct, inherited through a project subclass, method reference — is
 * charged, the charge is a side charge (an unnamed locator leaves the surface incomplete), and a member the table
 * does not list stays exactly as it was.
 */
class KappaFrameworkReachTest {

    private static List<String> tableLines() throws Exception {
        try (InputStream in = FrameworkReach.class.getResourceAsStream(FrameworkReach.RESOURCE)) {
            assertTrue(in != null, "the table must be bundled");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
        }
    }

    private static String header(List<String> lines, String key) {
        for (String l : lines) if (l.startsWith("# " + key + " ")) return l.substring(key.length() + 3);
        return null;
    }

    @Test
    void theTableIsExactlyWhatItsHeaderSaysAndWasNotEditedByHand() throws Exception {
        List<String> lines = tableLines();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        int rows = 0;
        String prev = null;
        for (String l : lines) {
            if (l.startsWith("#")) continue;
            assertTrue(prev == null || prev.compareTo(l) < 0, "rows are sorted and unique (generator output): " + l);
            prev = l;
            md.update((l + "\n").getBytes(StandardCharsets.UTF_8));
            rows++;
        }
        assertTrue(rows > 1000, "the table is populated (a stripped resource reads as an empty table)");
        assertEquals(String.valueOf(rows), header(lines, "entries"), "entry count in the header");
        assertEquals(HexFormat.of().formatHex(md.digest()), header(lines, "content-sha256"),
                "the rows do not hash to the header's content-sha256 — the table was edited by hand. Regenerate it with "
                        + "soundness/kappa_table/derive.sh; never edit it");
        assertEquals(rows, FrameworkReach.size(), "every row loads");
    }

    @Test
    void theTableWasGeneratedByTheCheckedInGeneratorFromTheCheckedInSources() throws Exception {
        Path dir = Path.of("soundness/kappa_table");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (String f : new String[] { "FrameworkReachGen.java", "derive.sh", "sources.tsv" })
            md.update(Files.readAllBytes(dir.resolve(f)));
        List<String> lines = tableLines();
        assertEquals(HexFormat.of().formatHex(md.digest()), header(lines, "generator-sha256"),
                "the generator or its source list changed since the table was generated — rerun "
                        + "soundness/kappa_table/derive.sh");
        List<String> want = new ArrayList<>();
        for (String l : Files.readAllLines(dir.resolve("sources.tsv"))) {
            if (l.isBlank()) continue;
            String[] p = l.split("\t");
            want.add(p[1] + " " + p[3]);
        }
        List<String> got = new ArrayList<>();
        for (String l : lines) if (l.startsWith("# source ")) got.add(l.substring("# source ".length()));
        assertEquals(want, got, "the header names every pinned source artefact, coordinate and SHA-256");
    }

    /** The members R492/R727 measured silent on a compiled consumer (each EXECUTED in the lane's fixtures), and a
     *  pure member of each library that must stay absent. */
    @Test
    void theMeasuredSilentMembersAreChargedAndTheirPureNeighboursAreNot() {
        assertTrue(FrameworkReach.charges("org/codehaus/groovy/runtime/ResourceGroovyMethods", "deleteDir",
                "(Ljava/io/File;)Z").contains(Effect.FS));
        assertTrue(FrameworkReach.charges("org/apache/commons/csv/CSVParser", "parse",
                "(Ljava/io/File;Ljava/nio/charset/Charset;Lorg/apache/commons/csv/CSVFormat;)Lorg/apache/commons/csv/CSVParser;")
                .contains(Effect.FS));
        assertTrue(FrameworkReach.charges("org/springframework/core/io/FileSystemResource", "contentLength", "()J")
                .contains(Effect.FS));
        assertTrue(FrameworkReach.charges("com/sun/jna/Native", "loadLibrary",
                "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;").contains(Effect.EXEC));
        assertTrue(FrameworkReach.charges("org/apache/struts/actions/DownloadAction$FileStreamInfo", "getInputStream",
                "()Ljava/io/InputStream;").contains(Effect.FS));
        // pure neighbours
        assertTrue(FrameworkReach.charges("org/codehaus/groovy/runtime/StringGroovyMethods", "capitalize",
                "(Ljava/lang/CharSequence;)Ljava/lang/String;").isEmpty());
        assertTrue(FrameworkReach.charges("org/apache/commons/csv/CSVParser", "parse",
                "(Ljava/lang/String;Lorg/apache/commons/csv/CSVFormat;)Lorg/apache/commons/csv/CSVParser;").isEmpty());
        assertTrue(FrameworkReach.charges("org/springframework/util/StringUtils", "cleanPath",
                "(Ljava/lang/String;)Ljava/lang/String;").isEmpty());
        assertTrue(FrameworkReach.charges("com/sun/jna/WString", "length", "()I").isEmpty());
        // VERSION POLICY: `processActionPerform` reaches Net in struts 1.3.10 and not in 1.2.9 (R727) — the
        // intersection is charged, the divergent Net is not.
        List<Effect> pap = FrameworkReach.charges("org/apache/struts/action/RequestProcessor", "processActionPerform",
                "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;"
                        + "Lorg/apache/struts/action/Action;Lorg/apache/struts/action/ActionForm;"
                        + "Lorg/apache/struts/action/ActionMapping;)Lorg/apache/struts/action/ActionForward;");
        assertFalse(pap.contains(Effect.NET), "a charge present in only one surveyed version is not made");
        // THE LOGGING FRONTIER: obtaining a logger is not charged its classpath configuration discovery.
        assertTrue(FrameworkReach.charges("org/slf4j/LoggerFactory", "getLogger",
                "(Ljava/lang/Class;)Lorg/slf4j/Logger;").isEmpty());
        assertTrue(FrameworkReach.charges("org/apache/commons/logging/LogFactory", "getLog",
                "(Ljava/lang/Class;)Lorg/apache/commons/logging/Log;").isEmpty());
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    private static TreeSet<String> incomplete(String fn) {
        return AnalysisState.ctx().surfaceIncomplete.getOrDefault(fn, new TreeSet<>());
    }

    /** Every spelling of a call that resolves to a charged member is charged; stub bodies stand in for the real jar
     *  (the engine reads the table by NAME and DESCRIPTOR — the bodies are never consulted). */
    @Test
    void everySpellingOfAChargedMemberIsChargedAsAnIncompleteSideCharge() throws Exception {
        Path app = compileApp(Map.of(
                "org/codehaus/groovy/runtime/ResourceGroovyMethods.java",
                "package org.codehaus.groovy.runtime; public class ResourceGroovyMethods {"
                    + " public static boolean deleteDir(java.io.File f) { return true; } }",
                "org/codehaus/groovy/runtime/StringGroovyMethods.java",
                "package org.codehaus.groovy.runtime; public class StringGroovyMethods {"
                    + " public static String capitalize(CharSequence s) { return null; } }",
                "org/springframework/core/io/FileSystemResource.java",
                "package org.springframework.core.io; public class FileSystemResource {"
                    + " public FileSystemResource(String p) {} public long contentLength() { return 0; } }"),
            Map.of("app/G.java", String.join("\n",
                "package app;",
                "import java.io.File; import org.codehaus.groovy.runtime.*;",
                "public class G {",
                "  boolean direct(File d) { return ResourceGroovyMethods.deleteDir(d); }",
                "  void viaRef(java.util.List<File> ds) { ds.forEach(ResourceGroovyMethods::deleteDir); }",
                "  boolean masked(File d) { boolean b = new File(\"/tmp/benign\").exists(); ResourceGroovyMethods.deleteDir(d); return b; }",
                "  String pure(String s) { return StringGroovyMethods.capitalize(s); }",
                "}"),
                "app/MyRes.java", String.join("\n",
                "package app;",
                "public class MyRes extends org.springframework.core.io.FileSystemResource {",
                "  MyRes(String p) { super(p); }",
                "  long inherited() { return contentLength(); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.G.direct").contains(Effect.FS), "the direct call spelling");
            assertTrue(eff(r, "app.G.viaRef").contains(Effect.FS), "the method-reference spelling");
            assertTrue(eff(r, "app.MyRes.inherited").contains(Effect.FS),
                    "an inherited member called through a project subclass compiles with the PROJECT owner");
            assertTrue(eff(r, "app.G.pure").isEmpty(), "a member the table does not list is untouched");
            assertTrue(incomplete("app.G.masked").contains("Fs"),
                    "the table names no locator, so a sibling literal must not certify the deletion");
            assertTrue(incomplete("app.G.viaRef").contains("Fs"), "a reference has no operand to judge");
        } finally { rm(app.getParent()); }
    }

    /** Groovy's emitted cast: the CLASS argument decides the ladder arm, and groovyc passes it as an ldc constant.
     *  To String the arm is FormatHelper.toString (no row); to List the Collection arm (asCollection ->
     *  ResourceGroovyMethods.readLines(File)) keeps the member's whole row. */
    @Test
    void aGroovyCastToAConstantFinalJdkClassTakesOnlyItsArm() throws Exception {
        Path app = compileApp(Map.of(
                "org/codehaus/groovy/runtime/ScriptBytecodeAdapter.java",
                "package org.codehaus.groovy.runtime; public class ScriptBytecodeAdapter {"
                    + " public static Object castToType(Object o, Class<?> c) { return o; } }"),
            Map.of("app/C.java", String.join("\n",
                "package app;",
                "import org.codehaus.groovy.runtime.ScriptBytecodeAdapter;",
                "public class C {",
                "  Object toStr(Object o) { return ScriptBytecodeAdapter.castToType(o, String.class); }",
                "  Object toObj(Object o) { return ScriptBytecodeAdapter.castToType(o, Object.class); }",
                "  Object toList(Object o) { return ScriptBytecodeAdapter.castToType(o, java.util.List.class); }",
                "  Object toDyn(Object o, Class<?> k) { return ScriptBytecodeAdapter.castToType(o, k); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(FrameworkReach.charges("org/codehaus/groovy/runtime/ScriptBytecodeAdapter", "castToType",
                    "(Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;").contains(Effect.FS), "control: the row");
            assertTrue(eff(r, "app.C.toStr").isEmpty(), "a String cast runs FormatHelper.toString only");
            assertTrue(eff(r, "app.C.toObj").isEmpty(), "an Object cast returns its argument");
            assertTrue(eff(r, "app.C.toList").contains(Effect.FS), "a Collection cast keeps the ladder's charge");
            assertTrue(eff(r, "app.C.toDyn").contains(Effect.FS), "a non-constant class keeps the whole row");
        } finally { rm(app.getParent()); }
    }

    @Test
    void theHedgeListIsGeneratorOutputToo() throws Exception {
        List<String> lines;
        try (InputStream in = FrameworkReach.class.getResourceAsStream(FrameworkReach.HEDGE_RESOURCE)) {
            assertTrue(in != null, "the hedge list must be bundled");
            lines = new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        int rows = 0;
        for (String l : lines) { if (l.startsWith("#")) continue; md.update((l + "\n").getBytes(StandardCharsets.UTF_8)); rows++; }
        assertTrue(rows > 1000, "populated");
        assertEquals(HexFormat.of().formatHex(md.digest()), header(lines, "content-sha256"),
                "framework-hedge.tsv was edited by hand — regenerate with soundness/kappa_table/derive.sh");
        assertEquals(header(tableLines(), "generator-sha256"), header(lines, "generator-sha256"),
                "the table and the hedge list come from the same generator run");
    }

    /** The residue the table cannot vouch for discloses Unknown; what it examined stays silent; the JDK and the
     *  language runtimes keep the grant. */
    @Test
    void theResidueDisclosesAndTheExaminedPureDoesNot() throws Exception {
        assertEquals("A", FrameworkReach.hedgeKind("com/fasterxml/jackson/core/JsonParser", "nextToken",
                "()Lcom/fasterxml/jackson/core/JsonToken;"), "an abstract member: the body is chosen at run time");
        assertEquals("X", FrameworkReach.hedgeKind("org/hibernate/criterion/Restrictions", "eq",
                "(Ljava/lang/String;Ljava/lang/Object;)Lorg/hibernate/criterion/SimpleExpression;"), "an unsurveyed framework class");
        assertEquals(null, FrameworkReach.hedgeKind("org/apache/commons/csv/CSVRecord", "get", "(I)Ljava/lang/String;"),
                "examined, pure");
        assertEquals("U", FrameworkReach.hedgeKind("org/apache/commons/csv/CSVParser", "parse",
                "(Ljava/lang/String;Lorg/apache/commons/csv/CSVFormat;)Lorg/apache/commons/csv/CSVParser;"),
                "examined, and the scan could read it only as Unknown (the Reader it wraps)");
        assertEquals(null, FrameworkReach.hedgeKind("org/apache/commons/csv/CSVParser", "parse",
                "(Ljava/io/File;Ljava/nio/charset/Charset;Lorg/apache/commons/csv/CSVFormat;)Lorg/apache/commons/csv/CSVParser;"), "charged, not hedged");
        assertEquals(null, FrameworkReach.hedgeKind("java/util/List", "size", "()I"), "the JDK keeps the grant");
        assertEquals(null, FrameworkReach.hedgeKind("javax/crypto/Cipher", "doFinal", "([B)[B"), "a JDK javax package too");
        assertEquals(null, FrameworkReach.hedgeKind("kotlin/collections/CollectionsKt", "listOf",
                "([Ljava/lang/Object;)Ljava/util/List;"), "a language runtime keeps the grant");
        assertEquals(null, FrameworkReach.hedgeKind("org/slf4j/Logger", "info", "(Ljava/lang/String;)V"), "logging frontier");
        Path app = compileApp(Map.of(
                "com/fasterxml/jackson/core/JsonParser.java",
                "package com.fasterxml.jackson.core; public abstract class JsonParser { public abstract JsonToken nextToken(); }",
                "com/fasterxml/jackson/core/JsonToken.java", "package com.fasterxml.jackson.core; public enum JsonToken { A }"),
            Map.of("app/J.java", String.join("\n",
                "package app;",
                "public class J {",
                "  Object next(com.fasterxml.jackson.core.JsonParser p) { return p.nextToken(); }",
                "  int pure(String s) { return s.length(); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.J.next").contains(Effect.UNKNOWN), "the abstract call discloses");
            assertTrue(AnalysisState.ctx().unknownWhy.get("app.J.next").toString().contains("dispatch:com.fasterxml.jackson.core.JsonParser.nextToken"),
                    "with its reason: " + AnalysisState.ctx().unknownWhy.get("app.J.next"));
            assertTrue(eff(r, "app.J.pure").isEmpty(), "control");
        } finally { rm(app.getParent()); }
    }
}
