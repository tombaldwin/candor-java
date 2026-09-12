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
 * SOUNDNESS R409 — an Fs call NAMES ITS OWN FILE, and a file nobody captured leaves the `paths` surface
 * incomplete. Before this rule the only Fs masking guard fired at the path-ESTABLISHING call
 * ({@code Path.of}/{@code Paths.get}/a path ctor), so a locator that arrived ALREADY BUILT — as an argument
 * (`Files.exists(pathParam)`) or as the RECEIVER (`fileParam.exists()`) — was never examined, and both
 * spellings certified under `allow Fs /tmp/benign` beside one benign sibling literal: exit 0, nothing
 * disclosed. Mirrors conformance {@code gen_stat_locator.py}'s four arms.
 *
 * <p>THE CONTROLS ARE HALF THE TEST, and breaking one is worse than the bug. A handle use-verb
 * (`out.write(b)`, `in.read()`) names no file and must make no claim; a locator whose value is statically
 * DETERMINED must still certify however it reaches the call — through a local, inline, through a
 * `toPath()`, or through a const String. Marking those would be the over-mask two other engines were
 * measured making (R416).
 */
class FsLocatorSurfaceTest {

    private static boolean inc(String fn) {
        return AnalysisState.ctx().surfaceIncomplete.getOrDefault(fn, new TreeSet<>()).contains("Fs");
    }

    /** The two DEFECT arms and the two CONTROL arms of the stat-locator differential, verbatim. */
    @Test
    void locatorIsReadFromArgumentAndFromReceiver() throws Exception {
        Path cls = compile(Map.of("app/M.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "import java.nio.file.*;",
            "public class M {",
            // a1arg — the locator arrives as an ARGUMENT, already built
            "  void argStat(Path p) throws Exception {",
            "    Files.write(Paths.get(\"/tmp/benign\"), new byte[0]);",
            "    Files.exists(p); }",
            // a2recv — the locator arrives as the RECEIVER
            "  void recvStat(File h) throws Exception {",
            "    Files.write(Paths.get(\"/tmp/benign\"), new byte[0]);",
            "    h.exists(); }",
            // a3handle — a handle use-verb names no file of its own
            "  void handle(InputStream in) throws Exception {",
            "    Files.write(Paths.get(\"/tmp/benign\"), new byte[0]);",
            "    in.read(); }",
            // a4local — a determined locator stays determined through a local
            "  void localBound() throws Exception {",
            "    Path p = Paths.get(\"/tmp/benign\");",
            "    Files.write(p, new byte[0]); }",
            "}")));
        try {
            Candor.runScan(cls);
            assertTrue(inc("app.M.argStat"),
                    "a stat on a Path PARAMETER names a file the gate cannot see — the surface is incomplete");
            assertTrue(inc("app.M.recvStat"),
                    "a stat on a File RECEIVER names a file the gate cannot see — the surface is incomplete");
            assertFalse(inc("app.M.handle"),
                    "a handle use-verb carries no locator, so it is evidence in NEITHER direction");
            assertFalse(inc("app.M.localBound"),
                    "a locator bound to a literal is DETERMINED however it reaches the call — not incomplete");
        } finally { rm(cls.getParent()); }
    }

    /** Every OTHER way a determined locator reaches an Fs call — the over-mask controls. Each of these was
     *  invisible to the per-call literal WINDOW the Net/Db surfaces use, which is why this rule reads the
     *  value's provenance instead. */
    @Test
    void aDeterminedLocatorStillCertifiesHoweverItArrives() throws Exception {
        Path cls = compile(Map.of("app/D.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "import java.nio.file.*;",
            "public class D {",
            "  void inlineBuilt() throws Exception { Files.readAllBytes(Paths.get(\"/tmp/ok\")); }",
            "  void ctorBuilt() { new File(\"/tmp/ok\").exists(); }",
            "  void ctorLocal() { File f = new File(\"/tmp/ok\"); f.length(); }",
            "  void viaToPath() throws Exception { Files.readAllBytes(new File(\"/tmp/ok\").toPath()); }",
            "  void openStream() throws Exception { new FileInputStream(new File(\"/tmp/ok\")).close(); }",
            "}")));
        try {
            Candor.runScan(cls);
            for (String fn : new String[]{"inlineBuilt", "ctorBuilt", "ctorLocal", "viaToPath", "openStream"})
                assertFalse(inc("app.D." + fn), "`" + fn + "` names a statically-determined file — "
                        + "marking it incomplete is the over-mask this rule must not introduce");
        } finally { rm(cls.getParent()); }
    }

    /** The cases the rule must still catch once the determined ones are credited — including the two the
     *  provenance merge decides, which no syntactic window could. */
    @Test
    void anUndeterminedLocatorIsCaughtWhereverItComesFrom() throws Exception {
        Path cls = compile(Map.of("app/U.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "import java.nio.file.*;",
            "public class U {",
            // a field-held locator: no allocation guarantee, so it must not be claimed determined
            "  static File held;",
            "  void fromField() { held.delete(); }",
            // a BRANCH-MERGED locator: both arms literal, but the merge cannot say which ran — and the
            // consumer would otherwise certify against whichever arm won
            "  void merged(boolean c) throws Exception { Files.delete(c ? Paths.get(\"/tmp/a\") : Paths.get(\"/tmp/b\")); }",
            // a runtime File flowing into a stream ctor — the ctor guard only ever gated the String form
            "  void streamCtor(File f) throws Exception { new FileOutputStream(f).close(); }",
            // Path.of's VARARGS: the base is literal and the child is not
            "  void varargs(String child) throws Exception { Files.readAllBytes(Path.of(\"/tmp\", child)); }",
            // a locator derived by path ALGEBRA this pass does not model
            "  void resolved(Path base) throws Exception { Files.readAllBytes(base.resolve(\"x\")); }",
            "}")));
        try {
            Candor.runScan(cls);
            for (String fn : new String[]{"fromField", "merged", "streamCtor", "varargs", "resolved"})
                assertTrue(inc("app.U." + fn), "`" + fn + "` names a file the gate cannot see — "
                        + "a benign sibling literal must not be able to certify it");
        } finally { rm(cls.getParent()); }
    }

    /** WHERE THE TWO Fs GUARDS DISAGREE, and the union is fail-closed. `String s = "/lit"; Paths.get(s)`
     *  is a DETERMINED locator by this rule's provenance, and an UNCAPTURED one by the older
     *  path-establishing guard, whose {@link Literals#firstLiteralArg} walk stops at the ASTORE and never
     *  consults {@code constLocals} the way {@link Literals#literalArgsInWindow} does for hosts and tables.
     *  So the function is marked incomplete — by the OTHER guard, exactly as it was before R409.
     *
     *  <p>Pinned rather than described, because it is a real (small) over-mask on a fully visible path and
     *  the next reader should have to change an assertion to close it, not just a comment. Closing it means
     *  teaching the establishing guard the same const-local resolution the Net/Db surfaces already have —
     *  a change to what `paths` REPORTS, which is why it is not folded into this one. */
    @Test
    void aConstStringLocalIsStillMarkedByTheOlderEstablishingGuard() throws Exception {
        Path cls = compile(Map.of("app/C.java", String.join("\n",
            "package app;",
            "import java.nio.file.*;",
            "public class C {",
            "  void viaConstString() throws Exception { String s = \"/tmp/ok\"; Files.readAllBytes(Paths.get(s)); }",
            "}")));
        try {
            Candor.runScan(cls);
            assertTrue(inc("app.C.viaConstString"),
                    "the path-establishing guard does not resolve a const-local path — over-mask, pre-R409");
        } finally { rm(cls.getParent()); }
    }

    /** `java.io.File` is classified Fs WHOLE-OWNER and is the one path-VALUE type that appears as a
     *  RECEIVER, so the path ALGEBRA on it — `getName`, `getPath`, `toPath`, `getParentFile` — would reach
     *  the locator rule with a File receiver and no syscall behind it, and marking those would flood every
     *  method that takes a File. It does not, because {@link Candor#isPureHandleAccessor} already answers
     *  that question and `classify` consults it first. This is the control that keeps the rule from
     *  growing a SECOND list of the same verbs — if this ever goes red, fix the authority, not here. */
    @Test
    void filePathAlgebraMakesNoClaim() throws Exception {
        Path cls = compile(Map.of("app/A.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "public class A {",
            "  String name(File f) { return f.getName(); }",
            "  String abs(File f) { return f.getAbsolutePath(); }",
            "  File parent(File f) { return f.getParentFile(); }",
            "  java.nio.file.Path asPath(File f) { return f.toPath(); }",
            "}")));
        try {
            Candor.runScan(cls);
            for (String fn : new String[]{"name", "abs", "parent", "asPath"})
                assertFalse(inc("app.A." + fn), "`File." + fn + "` is path algebra — no syscall, no locator claim");
        } finally { rm(cls.getParent()); }
    }
}
