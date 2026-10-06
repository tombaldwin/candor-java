package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R814 (+R812) — JDK members that really perform an effect and that the κ covered-prefix grant had
 * certified PURE. Every charge here was EXECUTED against a SecurityManager oracle before it was written (see
 * {@link KappaJdkSinks}); these tests pin the ENGINE's answer end to end, the masking each new locator gets,
 * and the controls that must not move.
 */
class KappaJdkSinksTest {

    private static final String SIB = "java.nio.file.Files.write(java.nio.file.Paths.get(\"/tmp/benign/x\"), new byte[0]); ";

    private static boolean inc(String fn, String eff) {
        return AnalysisState.ctx().surfaceIncomplete.getOrDefault(fn, new TreeSet<>()).contains(eff);
    }
    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        EffectSet e = r.get(fn);
        return e == null ? EffectSet.empty() : e;
    }

    /** One call per family, each in its own method, each asserted to carry the effect it really performs. */
    @Test
    void everyFamilyIsChargedEndToEnd() throws Exception {
        Path cls = compile(Map.of("app/S.java", String.join("\n",
            "package app;",
            "import java.io.*; import java.net.*; import java.nio.file.*; import java.util.*;",
            "public class S {",
            "  void font(File f) throws Exception { java.awt.Font.createFont(java.awt.Font.TRUETYPE_FONT, f); }",
            "  void fontStream(InputStream in) throws Exception { java.awt.Font.createFont(java.awt.Font.TRUETYPE_FONT, in); }",
            "  void keystore(File f) throws Exception { java.security.KeyStore.getInstance(f, new char[0]); }",
            "  void imageRead(InputStream in) throws Exception { javax.imageio.ImageIO.read(in); }",
            "  void imageStream(File f) throws Exception { new javax.imageio.stream.FileImageInputStream(f).read(); }",
            "  void midi(File f) throws Exception { javax.sound.midi.MidiSystem.getSequence(f); }",
            "  void midiUrl(URL u) throws Exception { javax.sound.midi.MidiSystem.getSequence(u); }",
            "  void schema(File f) throws Exception { javax.xml.validation.SchemaFactory.newDefaultInstance().newSchema(f); }",
            "  Object streamResult(File f) { return new javax.xml.transform.stream.StreamResult(f); }",
            "  void jfr(jdk.jfr.Recording r, Path p) throws Exception { r.dump(p); }",
            "  Object bodyToFile(Path p) { return java.net.http.HttpResponse.BodyHandlers.ofFile(p); }",
            "  Object redirectTo(File f) { return ProcessBuilder.Redirect.to(f); }",
            "  ProcessBuilder redirectOut(ProcessBuilder pb, File f) { return pb.redirectOutput(f); }",
            "  void keytab(File f) { javax.security.auth.kerberos.KeyTab.getInstance(f); }",
            "  void chooser(File f) { new javax.swing.JFileChooser(f); }",
            "  int urlHash(URL u) { return u.hashCode(); }",
            "  boolean urlEq(URL a, URL b) { return a.equals(b); }",
            "  boolean reach(InetAddress a) throws Exception { return a.isReachable(100); }",
            "  void export(java.rmi.Remote r) throws Exception { java.rmi.server.UnicastRemoteObject.exportObject(r, 0); }",
            "  void jmx(javax.management.remote.JMXConnectorServer cs) throws Exception { cs.start(); }",
            "  void shuffle(List<Integer> l) { Collections.shuffle(l); }",
            "  Object bigRandom(Random r) { return new java.math.BigInteger(64, r); }",
            "  void rmiLoad(URL u) throws Exception { java.rmi.server.RMIClassLoader.loadClass(u, \"X\"); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            Map<String, Effect> want = new java.util.LinkedHashMap<>();
            for (String m : new String[] {"font", "fontStream", "keystore", "imageRead", "imageStream", "midi", "schema",
                    "streamResult", "jfr", "bodyToFile", "redirectTo", "redirectOut", "keytab", "chooser"})
                want.put(m, Effect.FS);
            for (String m : new String[] {"midiUrl", "urlHash", "urlEq", "reach", "export", "jmx"}) want.put(m, Effect.NET);
            want.put("shuffle", Effect.RAND);
            want.put("bigRandom", Effect.RAND);
            want.put("rmiLoad", Effect.UNKNOWN);
            List<String> bad = new ArrayList<>();
            for (var w : want.entrySet())
                if (!eff(r, "app.S." + w.getKey()).contains(w.getValue()))
                    bad.add(w.getKey() + ": expected " + w.getValue() + ", got " + r.get("app.S." + w.getKey()));
            assertTrue(bad.isEmpty(), String.join("\n", bad));
            assertTrue(eff(r, "app.S.redirectOut").contains(Effect.EXEC), "the redirect setter stays Exec as well");
        } finally { rm(cls.getParent()); }
    }

    /**
     * R812, the exact shape and its siblings: a benign sibling literal must not certify a caller-chosen file
     * that a newly charged sink reaches. And the CONTROLS — a determined literal locator in the same sinks — stay
     * certifiable, so the mark is the locator's, not the sink's.
     */
    @Test
    void aNewlyChargedSinksLocatorIsJudgedLikeAnyFsCall() throws Exception {
        Path cls = compile(Map.of("app/M.java", String.join("\n",
            "package app;",
            "import java.io.*; import java.nio.file.*;",
            "public class M {",
            "  void r812(String child) throws Exception { " + SIB + "new ProcessBuilder(\"/bin/echo\").redirectOutput(new File(\"/tmp/benign\", child)).start(); }",
            "  void r812param(File f) throws Exception { " + SIB + "new ProcessBuilder(\"/bin/echo\").redirectOutput(f).start(); }",
            "  void redirectTo(File f) throws Exception { " + SIB + "new ProcessBuilder(\"/bin/echo\").redirectOutput(ProcessBuilder.Redirect.to(f)).start(); }",
            "  void font(File f) throws Exception { " + SIB + "java.awt.Font.createFont(0, f); }",
            "  void parse(File f) throws Exception { " + SIB + "javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(f); }",
            "  void imageRead(InputStream in) throws Exception { " + SIB + "javax.imageio.ImageIO.read(in); }",
            "  void fileObject(Object o) throws Exception { " + SIB + "javax.imageio.ImageIO.createImageInputStream(o); }",
            "  void chooserFiles(javax.swing.JFileChooser c, File[] fs) { c.setSelectedFiles(fs); }",
            // controls
            "  void ctlRedirect() throws Exception { " + SIB + "new ProcessBuilder(\"/bin/echo\").redirectOutput(new File(\"/tmp/benign/out\")).start(); }",
            "  void ctlFont() throws Exception { " + SIB + "java.awt.Font.createFont(0, new File(\"/tmp/benign/f.ttf\")); }",
            "  void ctlImageWriteFile(java.awt.image.RenderedImage i) throws Exception { " + SIB + "javax.imageio.ImageIO.write(i, \"png\", new File(\"/tmp/benign/i.png\")); }",
            "  void ctlDirectory(File d) throws Exception { " + SIB + "new ProcessBuilder(\"/bin/echo\").directory(d); }",
            "}")));
        try {
            Candor.runScan(cls);
            for (String m : new String[] {"r812", "r812param", "redirectTo", "font", "parse", "imageRead", "fileObject", "chooserFiles"})
                assertTrue(inc("app.M." + m, "Fs"), m + ": the file this sink touches is invisible to the gate — must mark");
            for (String m : new String[] {"ctlRedirect", "ctlFont", "ctlImageWriteFile", "ctlDirectory"})
                assertFalse(inc("app.M." + m, "Fs"), m + ": a determined literal (or no file at all) must stay certifiable");
        } finally { rm(cls.getParent()); }
    }

    /** `URL.hashCode()` resolves its receiver's host. An inline literal URL must surface that host, not be
     *  credited as "allocated here" with nothing captured. */
    @Test
    void urlHashCodeAttributesTheHostItResolves() throws Exception {
        Path cls = compile(Map.of("app/U.java", String.join("\n",
            "package app;",
            "public class U {",
            "  int inline() throws Exception { new java.net.URL(\"https://good.example/\").openStream(); return new java.net.URL(\"https://evil.example/\").hashCode(); }",
            "  int param(java.net.URL u) throws Exception { new java.net.URL(\"https://good.example/\").openStream(); return u.hashCode(); }",
            "}")));
        try {
            Candor.runScan(cls);
            Set<String> hosts = AnalysisState.ctx().hostsDirect.getOrDefault("app.U.inline", new TreeSet<>());
            assertTrue(hosts.contains("evil.example") || inc("app.U.inline", "Net"),
                    "the resolved host must be named or the surface marked, got hosts " + hosts);
            assertTrue(inc("app.U.param", "Net"), "a caller's URL resolved by hashCode() must mark the surface");
        } finally { rm(cls.getParent()); }
    }

    /** CONTROLS that must not move: path/URI algebra, a working directory, the stream forms that only read a
     *  caller's stream, a factory that draws nothing, a file: URL compared by string. */
    @Test
    void theNeighboursStayPure() {
        assertNull(Classifier.classify("java.nio.file.Path", "toFile", "()Ljava/io/File;"));
        assertNull(Classifier.classify("java.net.URI", "getHost", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("java.net.URL", "getHost", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("java.net.UnixDomainSocketAddress", "of", "(Ljava/nio/file/Path;)Ljava/net/UnixDomainSocketAddress;"));
        assertNull(Classifier.classify("javax.imageio.ImageIO", "read", "(Ljavax/imageio/stream/ImageInputStream;)Ljava/awt/image/BufferedImage;"));
        assertNull(Classifier.classify("javax.imageio.ImageIO", "write",
                "(Ljava/awt/image/RenderedImage;Ljava/lang/String;Ljavax/imageio/stream/ImageOutputStream;)Z"));
        assertNull(Classifier.classify("javax.imageio.stream.FileImageInputStream", "getStreamPosition", "()J"));
        assertNull(Classifier.classify("javax.swing.filechooser.FileSystemView", "createFileObject", "(Ljava/lang/String;)Ljava/io/File;"));
        assertNull(Classifier.classify("javax.swing.JFileChooser", "setDialogTitle", "(Ljava/lang/String;)V"));
        assertNull(Classifier.classify("javax.swing.JEditorPane", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V"),
                "JEditorPane(type, text) is pure; only the one-String ctor is setPage(url)");
        assertNull(Classifier.classify("java.math.BigInteger", "isProbablePrime", "(I)Z"),
                "incidental Monte-Carlo witnesses are not charged (stated in KappaJdkSinks)");
        assertNull(Classifier.classify("java.security.KeyStore", "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;"));
        assertEquals(List.of(), KappaJdkSinks.alsoCharges("java.lang.ProcessBuilder", "directory", "(Ljava/io/File;)Ljava/lang/ProcessBuilder;"),
                "a working directory is not a file the JVM opens (EXECUTED: no syscall)");
        assertEquals(List.of(), KappaJdkSinks.alsoCharges("java.lang.ProcessBuilder", "redirectOutput",
                "(Ljava/lang/ProcessBuilder$Redirect;)Ljava/lang/ProcessBuilder;"),
                "the Redirect overload carries no File here — Redirect.to(File) is charged where the File is");
    }

    /** No answer the κ table ALREADY gave may change: the helper runs last in each bucket. Asked of the rules
     *  whose owners it shares. */
    @Test
    void existingAnswersOnSharedOwnersAreUnchanged() {
        assertEquals(Effect.FS, Classifier.classify("javax.imageio.ImageIO", "read", "(Ljava/io/File;)Ljava/awt/image/BufferedImage;"));
        assertEquals(Effect.NET, Classifier.classify("javax.imageio.ImageIO", "read", "(Ljava/net/URL;)Ljava/awt/image/BufferedImage;"));
        assertEquals(Effect.NET, Classifier.classify("java.net.URL", "openStream", "()Ljava/io/InputStream;"));
        assertEquals(Effect.NET, Classifier.classify("java.net.InetAddress", "getByName", "(Ljava/lang/String;)Ljava/net/InetAddress;"));
        assertEquals(Effect.EXEC, Classifier.classify("java.lang.ProcessBuilder", "redirectOutput", "(Ljava/io/File;)Ljava/lang/ProcessBuilder;"));
        assertEquals(Effect.EXEC, Classifier.classify("java.awt.Desktop", "open", "(Ljava/io/File;)V"));
        assertEquals(Effect.FS, Classifier.classify("javax.sound.sampled.AudioSystem", "getAudioInputStream", "(Ljava/io/File;)Ljavax/sound/sampled/AudioInputStream;"));
    }

    /** The FileSystemView DENYLIST is pinned to the JDK's declared members: every name in it must exist (a dead
     *  entry would hide a renamed member), and the members it charges are the complement. */
    @Test
    void theFileSystemViewDenylistNamesRealMembers() {
        Set<String> declared = new TreeSet<>();
        for (Method m : javax.swing.filechooser.FileSystemView.class.getDeclaredMethods())
            if (Modifier.isPublic(m.getModifiers()) || Modifier.isProtected(m.getModifiers())) declared.add(m.getName());
        declared.add("<init>");
        for (String pure : new String[] {"getFileSystemView", "createFileObject", "createFileSystemRoot", "isComputerNode",
                "isDrive", "isFloppyDrive", "isFileSystemRoot", "getHomeDirectory", "getSystemTypeDescription", "<init>"}) {
            assertTrue(declared.contains(pure), "denylist names a member FileSystemView does not declare: " + pure);
            assertTrue(KappaJdkSinks.isPureFileSystemViewMember(pure), pure);
        }
        for (String io : new String[] {"getFiles", "createNewFolder", "isTraversable", "getRoots", "isHiddenFile", "isLink"})
            assertEquals(Effect.FS, Classifier.classify("javax.swing.filechooser.FileSystemView", io, "(Ljava/io/File;)V"), io);
    }
}
