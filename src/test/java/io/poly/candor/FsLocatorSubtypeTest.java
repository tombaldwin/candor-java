package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R813 — R409's receiver-locator test read only the exact owners {@code File}/{@code Path}, so
 * {@code f.delete()} on a {@code class DirFile extends File} (bytecode owner {@code DirFile}) named no file,
 * and a benign sibling literal certified it under {@code allow Fs in … /tmp/benign}: exit 0 over an executed
 * delete of a caller-chosen file. "Is a locator" is a hierarchy question. One variable per pair: the static
 * type of the receiver.
 */
class FsLocatorSubtypeTest {

    private static boolean inc(String fn) {
        return AnalysisState.ctx().surfaceIncomplete.getOrDefault(fn, new TreeSet<>()).contains("Fs");
    }

    @Test
    void aFileSubclassReceiverNamesItsFile() throws Exception {
        Path cls = compile(Map.of(
            "app/DirFile.java", "package app; public class DirFile extends java.io.File {"
                + " public DirFile(String p) { super(p); } public DirFile(java.io.File d, String c) { super(d, c); } }",
            "app/DeepFile.java", "package app; public class DeepFile extends DirFile { public DeepFile(String p) { super(p); } }",
            "app/M.java", String.join("\n",
                "package app;",
                "import java.io.*; import java.nio.file.*;",
                "public class M {",
                "  void viaFile(File f) throws Exception { Files.write(Paths.get(\"/tmp/benign\"), new byte[0]); f.delete(); }",
                "  void viaSub(DirFile f) throws Exception { Files.write(Paths.get(\"/tmp/benign\"), new byte[0]); f.delete(); }",
                "  void viaDeep(DeepFile f) throws Exception { Files.write(Paths.get(\"/tmp/benign\"), new byte[0]); f.exists(); }",
                "  void composed(String c) throws Exception { Files.write(Paths.get(\"/tmp/benign\"), new byte[0]);"
                    + " new DirFile(new File(\"/tmp/benign\"), c).delete(); }",
                // controls: path algebra on the subclass is pure (classified null), and a determined File stays determined
                "  String algebra(DirFile f) throws Exception { Files.write(Paths.get(\"/tmp/benign\"), new byte[0]); return f.getName() + f.getPath(); }",
                "  void detFile() throws Exception { Files.write(Paths.get(\"/tmp/benign\"), new byte[0]); new File(\"/tmp/benign\").delete(); }",
                "}")));
        try {
            Candor.runScan(cls);
            for (String fn : new String[] {"viaFile", "viaSub", "viaDeep", "composed"})
                assertTrue(inc("app.M." + fn), fn + ": a File-subtype receiver names a file the gate cannot see");
            assertFalse(inc("app.M.algebra"), "path algebra on a File subtype names nothing — no mark");
            assertFalse(inc("app.M.detFile"), "a literal File stays determined — no mark");
        } finally { rm(cls.getParent()); }
    }
}
