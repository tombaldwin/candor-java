package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R486 / R487 — the {@link ThirdPartySubprocessBuilderTest} class (R480) one owner further,
 * into the packages where the under-report is SILENT rather than disclosed.
 *
 * <p><b>Why these outrank R480 even though the defect is identical.</b> R480's four packages are not in
 * {@code Rules.KAPPA_COVERED_PREFIXES}, so a floored call carried {@code invisible: [<package>]} plus the
 * coverage advisory — the honest floor working. {@code scala} and {@code org.codehaus.groovy} ARE covered,
 * so the identical floored call is not ledgered at all: no {@code invisible}, no advisory,
 * {@code coverage: null}, and under ⟨0.21⟩ the arm-only method is ABSENT from {@code functions} entirely,
 * which is a certified purity claim. <b>The covered-prefix list is a second, independent way to lose a
 * call, and it converts a disclosed under-report into a silent one.</b>
 *
 * <p>MEASURED PRE-FIX at 1e98b2d, and for R486 against REAL scalac 3.8.4 output rather than a stub —
 * {@code def armString(cmd: String): ProcessBuilder = Process(cmd)} and five siblings reported no
 * effects, no {@code invisible}, and {@code deny Exec} / {@code deny Unknown} / {@code allow Exec git}
 * all exited 0. Calibrated on the same tree: adding {@code Process("id").!} turned {@code deny Exec} red,
 * so the exit 0 was an under-report and not a broken scan. The groovy half was measured the same way on a
 * consumer compiled against groovy-4.0.22 (six of seven methods absent from the report pre-fix, all seven
 * {@code Exec} after), and R487 on a consumer compiled against the real ffmpeg-0.8.0.jar.
 *
 * <p>The stub owners below exist because there is no scalac or groovyc in this build. What is held
 * constant is the CALL INSTRUCTION — owner, name and descriptor are read off the real jars with
 * {@code javap} — which is the whole of what the classifier sees.
 */
class CoveredPrefixSubprocessTest {

    // ── stub owners, signatures taken from javap over scala-library 2.13.14 / 3.8.4, groovy-4.0.22 and
    //    ffmpeg-0.8.0 (compiled to a separate -classpath dir, never scanned) ─────────────────────────

    private static final Map<String, String> LIB = Map.of(
        "scala/sys/process/ProcessBuilder.java", String.join("\n",
            "package scala.sys.process;",
            "public interface ProcessBuilder {",
            "  int $bang();",
            "  Process run();",
            "  ProcessBuilder $hash$bar(ProcessBuilder b);",   // #|  — the pipe the allowlist never named
            "  ProcessBuilder $hash$amp$amp(ProcessBuilder b);", // #&&
            "  ProcessBuilder $hash$greater(java.io.File f);", // #>
            "  boolean canPipeTo();",
            "}"),
        "scala/sys/process/Process.java",
            "package scala.sys.process;\npublic interface Process {"
                + " int exitValue(); void destroy(); boolean isAlive(); }",
        "scala/sys/process/Process$.java", String.join("\n",
            "package scala.sys.process;",
            "public final class Process$ {",
            "  public static final Process$ MODULE$ = new Process$();",
            "  public ProcessBuilder apply(String cmd) { return null; }",          // THE payload carrier
            "  public ProcessBuilder apply(String cmd, java.io.File cwd) { return null; }",
            "  public ProcessBuilder cat(Object sources) { return null; }",
            "}"),
        "scala/sys/process/package$.java", String.join("\n",
            "package scala.sys.process;",
            "public final class package$ {",
            "  public static final package$ MODULE$ = new package$();",
            "  public ProcessBuilder stringToProcess(String s) { return null; }",  // what `\"ls\".!` goes through
            "  public java.io.InputStream stdin() { return null; }",               // System.in — carved out
            "  public java.io.PrintStream stdout() { return null; }",
            "}"),
        "scala/sys/process/ProcessLogger.java",
            "package scala.sys.process;\npublic interface ProcessLogger { void out(String s); }",
        "org/codehaus/groovy/runtime/ProcessGroovyMethods.java", String.join("\n",
            "package org.codehaus.groovy.runtime;",
            "public class ProcessGroovyMethods {",
            "  public static Process execute(String cmd) { return null; }",
            "  public static String getText(Process p) { return null; }",
            "  public static java.io.InputStream getIn(Process p) { return null; }",
            "  public static java.io.Writer leftShift(Process p, Object in) { return null; }",
            "  public static void waitForOrKill(Process p, long ms) {}",
            "  public static void consumeProcessOutput(Process p) {}",
            "  public static Process pipeTo(Process a, Process b) { return null; }",
            "}"),
        "net/bramp/ffmpeg/builder/FFmpegBuilder.java", String.join("\n",
            "package net.bramp.ffmpeg.builder;",
            "public class FFmpegBuilder {",
            "  public FFmpegBuilder setInput(String in) { return this; }",
            "  public FFmpegBuilder addExtraArgs(String... a) { return this; }",
            "  public FFmpegBuilder addOutput(String out) { return this; }",
            "  public boolean getOverrideOutputFiles() { return false; }",
            "  public java.util.List<String> build() { return null; }",
            "}"),
        "net/bramp/ffmpeg/FFmpeg.java", String.join("\n",
            "package net.bramp.ffmpeg;",
            "public class FFmpeg {",
            "  public FFmpeg(String path) {}",                       // javap: the ctor calls version()
            "  public String version() { return null; }",
            "  public String getPath() { return null; }",
            "  public void run(java.util.List<String> a) {}",
            "}"),
        "net/bramp/ffmpeg/FFmpegExecutor.java",
            "package net.bramp.ffmpeg;\npublic class FFmpegExecutor {"
                + " public FFmpegExecutor(FFmpeg f) {}"
                + " public Object createJob(net.bramp.ffmpeg.builder.FFmpegBuilder b) { return null; } }");

    // ── R486: the end-to-end arm-only fixture ───────────────────────────────────────────────────────

    /** Every one of these assembles or composes an invocation and hands it back; none launches anything.
     *  Pre-fix all five reported no effects — and, because {@code scala} and {@code org.codehaus.groovy}
     *  are κ-covered, with no {@code invisible} and no advisory either. */
    @Test
    void armingUnderACoveredPrefixIsExec() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Arm.java", String.join("\n",
            "package com.x;",
            "import scala.sys.process.Process$;",
            "import scala.sys.process.ProcessBuilder;",
            "import org.codehaus.groovy.runtime.ProcessGroovyMethods;",
            "public class Arm {",
            // scala — Process$.apply is the constructor that CARRIES THE PROGRAM. The old rule charged
            // `run`/`$bang`/`lazyLines`/`lineStream` and not this.
            "  public ProcessBuilder scalaApply(String cmd) { return Process$.MODULE$.apply(cmd); }",
            "  public ProcessBuilder scalaApplyCwd(String c, java.io.File d) { return Process$.MODULE$.apply(c, d); }",
            "  public ProcessBuilder scalaPipe(ProcessBuilder a, ProcessBuilder b) { return a.$hash$bar(b); }",
            "  public ProcessBuilder scalaRedirect(ProcessBuilder a, java.io.File f) { return a.$hash$greater(f); }",
            "  public ProcessBuilder scalaImplicit(String s) { return scala.sys.process.package$.MODULE$.stringToProcess(s); }",
            // groovy — every member but `execute*` was uncharged, including the one that FEEDS the child.
            "  public String groovyText(java.lang.Process p) { return ProcessGroovyMethods.getText(p); }",
            "  public java.io.Writer groovyFeed(java.lang.Process p, Object in) { return ProcessGroovyMethods.leftShift(p, in); }",
            "  public void groovyKill(java.lang.Process p) { ProcessGroovyMethods.waitForOrKill(p, 5L); }",
            "  public java.lang.Process groovyChain(java.lang.Process a, java.lang.Process b) { return ProcessGroovyMethods.pipeTo(a, b); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"scalaApply", "scalaApplyCwd", "scalaPipe", "scalaRedirect",
                    "scalaImplicit", "groovyText", "groovyFeed", "groovyKill", "groovyChain"}) {
                assertTrue(eff(r, "com.x.Arm." + m).contains(Effect.EXEC),
                    m + " arms, composes or drives a subprocess — must be Exec, got " + r.get("com.x.Arm." + m));
            }
        } finally { rm(app.getParent()); }
    }

    // ── R487: the end-to-end ffmpeg fixture ─────────────────────────────────────────────────────────

    /** The payload-carrying builder and the executor, plus the two members that FORK the binary while
     *  reading like accessors: {@code new FFmpeg(path)} ends in {@code invokevirtual version()} (javap over
     *  ffmpeg-0.8.0), and {@code version()} runs it. Neither is named {@code run}, which is all the old
     *  rule charged. */
    @Test
    void ffmpegBuilderAndExecutorAreExec() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Ff.java", String.join("\n",
            "package com.x;",
            "import net.bramp.ffmpeg.FFmpeg;",
            "import net.bramp.ffmpeg.FFmpegExecutor;",
            "import net.bramp.ffmpeg.builder.FFmpegBuilder;",
            "public class Ff {",
            "  public FFmpegBuilder arm(String in, String out) { return new FFmpegBuilder().setInput(in).addOutput(out); }",
            "  public java.util.List<String> argv(String in, String[] extra) { return new FFmpegBuilder().setInput(in).addExtraArgs(extra).build(); }",
            "  public Object job(FFmpeg f, FFmpegBuilder b) { return new FFmpegExecutor(f).createJob(b); }",
            "  public FFmpeg construct(String path) { return new FFmpeg(path); }",
            "  public String ver(FFmpeg f) { return f.version(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"arm", "argv", "job", "construct", "ver"})
                assertTrue(eff(r, "com.x.Ff." + m).contains(Effect.EXEC),
                    m + " arms or forks ffmpeg — must be Exec, got " + r.get("com.x.Ff." + m));
        } finally { rm(app.getParent()); }
    }

    // ── OVER-CHARGE CONTROLS ────────────────────────────────────────────────────────────────────────

    /** The carve-outs, executed end-to-end rather than asserted at the table, because an absence-shaped
     *  control is evidence only if the program reaches the branch. {@code package$.stdin/stdout} hand back
     *  THIS JVM's streams (javap: {@code getstatic java/lang/System.in; areturn}), so charging them Exec
     *  would be the wrong effect; {@code FFmpegBuilder.getOverrideOutputFiles()} and {@code FFmpeg.getPath()}
     *  return fields; a project type that merely shares a name is a different owner. */
    @Test
    void control_carveOutsStayPure() throws Exception {
        Path app = compileApp(LIB, Map.of(
            "com/x/R.java", String.join("\n",
                "package com.x;",
                "public class R {",
                "  public Object jvmStdin() { return scala.sys.process.package$.MODULE$.stdin(); }",
                "  public Object jvmStdout() { return scala.sys.process.package$.MODULE$.stdout(); }",
                "  public boolean ffFlag(net.bramp.ffmpeg.builder.FFmpegBuilder b) { return b.getOverrideOutputFiles(); }",
                "  public String ffPath(net.bramp.ffmpeg.FFmpeg f) { return f.getPath(); }",
                "}"),
            "com/mine/Process$.java",
                "package com.mine;\npublic class Process$ { public Object apply(String c) { return null; } }",
            "com/mine/Use.java",
                "package com.mine;\npublic class Use { public Object arm(Process$ p) { return p.apply(\"x\"); } }"));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"jvmStdin", "jvmStdout", "ffFlag", "ffPath"})
                assertFalse(eff(r, "com.x.R." + m).contains(Effect.EXEC),
                    m + " reads back stored state or this JVM's own streams — must NOT be Exec, got "
                        + r.get("com.x.R." + m));
            assertTrue(eff(r, "com.mine.Use.arm").isEmpty(),
                "a project Process$ is not scala's — must stay pure, got " + r.get("com.mine.Use.arm"));
        } finally { rm(app.getParent()); }
    }

    /** The HALF OF ffmpeg THAT IS NOT A PROCESS WRAPPER. {@code net.bramp.ffmpeg} is mixed — a media
     *  metadata model bolted onto a CLI wrapper — so unlike commons-exec it is deliberately NOT charged
     *  whole-package. These four were the over-charges a whole-package rule would have introduced; every
     *  one was checked against the real jar with {@code javap}, and two of them
     *  ({@code MetadataSpecifier.spec}, {@code FFmpegJob$State}) live INSIDE the two packages that ARE
     *  charged, which is why they are carved out by type. */
    @Test
    void control_ffmpegModelSurfaceStaysPure() {
        assertNull(Classifier.classify("net.bramp.ffmpeg.probe.FFmpegFormat", "getDuration", "()D"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.FFmpegUtils", "toTimecode",
            "(JLjava/util/concurrent/TimeUnit;)Ljava/lang/String;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.Preconditions", "checkNotEmpty",
            "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.nut.NutReader", "read", "()V"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.builder.MetadataSpecifier", "spec", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.builder.StreamSpecifier", "stream",
            "(I)Lnet/bramp/ffmpeg/builder/StreamSpecifier;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.builder.FFmpegBuilder$Verbosity", "values",
            "()[Lnet/bramp/ffmpeg/builder/FFmpegBuilder$Verbosity;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.job.FFmpegJob$State", "valueOf",
            "(Ljava/lang/String;)Lnet/bramp/ffmpeg/job/FFmpegJob$State;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.job.FFmpegJob", "getState",
            "()Lnet/bramp/ffmpeg/job/FFmpegJob$State;"));
    }

    // ── the whole class at the classifier table ─────────────────────────────────────────────────────

    /** The members the three verb allowlists omitted. Every owner/name/descriptor here was read off the
     *  real jar with {@code javap}. */
    @Test
    void everyOmittedMemberIsExec() {
        String[][] rows = {
            // scala — the payload carrier, its overloads, the implicit conversions, and the composers.
            {"scala.sys.process.Process$", "apply", "(Ljava/lang/String;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.Process$", "apply", "(Lscala/collection/Seq;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.Process$", "cat", "(Lscala/collection/Seq;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.Process", "apply", "(Ljava/lang/String;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.ProcessCreation", "apply", "(Ljava/lang/String;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.package$", "stringToProcess", "(Ljava/lang/String;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.package$", "stringSeqToProcess", "(Lscala/collection/Seq;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.ProcessImplicits", "fileToProcess", "(Ljava/io/File;)Lscala/sys/process/ProcessBuilder$FileBuilder;"},
            {"scala.sys.process.ProcessBuilder", "$hash$bar", "(Lscala/sys/process/ProcessBuilder;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.ProcessBuilder", "$hash$amp$amp", "(Lscala/sys/process/ProcessBuilder;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.ProcessBuilder$Source", "$hash$greater", "(Ljava/io/File;)Lscala/sys/process/ProcessBuilder;"},
            {"scala.sys.process.ProcessBuilder$Sink", "$hash$less", "(Ljava/io/File;)Lscala/sys/process/ProcessBuilder;"},
            // …a spelling an owner-EQUALS rule could never see: the impl class the bytecode names.
            {"scala.sys.process.ProcessBuilderImpl$AbstractBuilder", "run", "()Lscala/sys/process/Process;"},
            {"scala.sys.process.ProcessImpl$SimpleProcess", "destroy", "()V"},
            {"scala.sys.process.Process", "exitValue", "()I"},
            // the child's streams / logger, one layer up from Process.getInputStream.
            {"scala.sys.process.ProcessLogger", "out", "(Lscala/Function0;)V"},
            {"scala.sys.process.ProcessIO", "processOutput", "()Lscala/Function1;"},
            {"scala.sys.process.BasicIO$", "transferFully", "(Ljava/io/InputStream;Ljava/io/OutputStream;)V"},
            {"scala.sys.process.Parser", "tokenize", "(Ljava/lang/String;)Lscala/collection/immutable/List;"},
            // groovy — everything but `execute*`, which was the whole of the old rule.
            {"org.codehaus.groovy.runtime.ProcessGroovyMethods", "getText", "(Ljava/lang/Process;)Ljava/lang/String;"},
            {"org.codehaus.groovy.runtime.ProcessGroovyMethods", "getIn", "(Ljava/lang/Process;)Ljava/io/InputStream;"},
            {"org.codehaus.groovy.runtime.ProcessGroovyMethods", "leftShift", "(Ljava/lang/Process;Ljava/lang/Object;)Ljava/io/Writer;"},
            {"org.codehaus.groovy.runtime.ProcessGroovyMethods", "waitForOrKill", "(Ljava/lang/Process;J)V"},
            {"org.codehaus.groovy.runtime.ProcessGroovyMethods", "consumeProcessOutput", "(Ljava/lang/Process;)V"},
            {"org.codehaus.groovy.runtime.ProcessGroovyMethods", "pipeTo", "(Ljava/lang/Process;Ljava/lang/Process;)Ljava/lang/Process;"},
            {"org.codehaus.groovy.runtime.ProcessGroovyMethods$ProcessRunner", "waitForOrKill", "(J)V"},
            // ffmpeg — the builder, the executor, the job, and the forks that are not called `run`.
            {"net.bramp.ffmpeg.builder.FFmpegBuilder", "setInput", "(Ljava/lang/String;)Lnet/bramp/ffmpeg/builder/FFmpegBuilder;"},
            {"net.bramp.ffmpeg.builder.FFmpegBuilder", "addExtraArgs", "([Ljava/lang/String;)Lnet/bramp/ffmpeg/builder/FFmpegBuilder;"},
            {"net.bramp.ffmpeg.builder.FFmpegBuilder", "build", "()Ljava/util/List;"},
            {"net.bramp.ffmpeg.builder.FFmpegOutputBuilder", "setVideoCodec", "(Ljava/lang/String;)Lnet/bramp/ffmpeg/builder/AbstractFFmpegStreamBuilder;"},
            {"net.bramp.ffmpeg.FFmpegExecutor", "createJob", "(Lnet/bramp/ffmpeg/builder/FFmpegBuilder;)Lnet/bramp/ffmpeg/job/FFmpegJob;"},
            {"net.bramp.ffmpeg.FFmpegExecutor", "createTwoPassJob", "(Lnet/bramp/ffmpeg/builder/FFmpegBuilder;)Lnet/bramp/ffmpeg/job/FFmpegJob;"},
            {"net.bramp.ffmpeg.FFmpeg", "<init>", "(Ljava/lang/String;)V"},
            {"net.bramp.ffmpeg.FFcommon", "version", "()Ljava/lang/String;"},
            {"net.bramp.ffmpeg.FFmpeg", "codecs", "()Ljava/util/List;"},
            {"net.bramp.ffmpeg.FFprobe", "probe", "(Ljava/lang/String;)Lnet/bramp/ffmpeg/probe/FFmpegProbeResult;"},
            {"net.bramp.ffmpeg.RunProcessFunction", "setWorkingDirectory", "(Ljava/io/File;)Lnet/bramp/ffmpeg/RunProcessFunction;"},
            {"net.bramp.ffmpeg.io.ProcessUtils", "waitForWithTimeout", "(Ljava/lang/Process;JLjava/util/concurrent/TimeUnit;)I"},
            {"net.bramp.ffmpeg.job.SinglePassFFmpegJob", "run", "()V"},
        };
        for (String[] row : rows)
            assertEquals(Effect.EXEC, Classifier.classify(row[0], row[1], row[2]),
                row[0] + "." + row[1] + row[2] + " arms or drives a subprocess — must be Exec");
    }

    /** The denylists at the table. A name in the set with a {@code ()} descriptor is pure; the carve-out is
     *  NOT "no argument ⇒ pure" — {@code FFcommon.version()} and {@code FFmpeg.codecs()} take none and fork
     *  the binary, and they are the discriminator rather than decoration. */
    @Test
    void carveOutsAreDescriptorGated() {
        assertNull(Classifier.classify("scala.sys.process.package$", "stdin", "()Ljava/io/InputStream;"));
        assertNull(Classifier.classify("scala.sys.process.package$", "stdout", "()Ljava/io/PrintStream;"));
        assertNull(Classifier.classify("scala.sys.process.package$", "stderr", "()Ljava/io/PrintStream;"));
        assertNull(Classifier.classify("scala.sys.process.BasicIO$", "BufferSize", "()I"));
        assertNull(Classifier.classify("scala.sys.process.Parser$ParseException", "getMessage", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("scala.sys.process.ProcessBuilder", "toString", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.FFcommon", "getPath", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("net.bramp.ffmpeg.builder.FFmpegBuilder", "getOverrideOutputFiles", "()Z"));
        // ProcessGroovyMethods is a static-extension holder: its no-arg ctor builds nothing.
        assertNull(Classifier.classify("org.codehaus.groovy.runtime.ProcessGroovyMethods", "<init>", "()V"));
        // …and the members the same shape must NOT reach.
        assertEquals(Effect.EXEC, Classifier.classify("net.bramp.ffmpeg.FFcommon", "version", "()Ljava/lang/String;"));
        assertEquals(Effect.EXEC, Classifier.classify("net.bramp.ffmpeg.FFmpeg", "pixelFormats", "()Ljava/util/List;"));
        assertEquals(Effect.EXEC, Classifier.classify("net.bramp.ffmpeg.FFprobe", "isFFprobe", "()Z"));
        assertEquals(Effect.EXEC, Classifier.classify("net.bramp.ffmpeg.FFcommon", "path", "(Ljava/util/List;)Ljava/util/List;"));
        assertEquals(Effect.EXEC, Classifier.classify("scala.sys.process.ProcessBuilder", "$bang", "()I"));
        assertEquals(Effect.EXEC, Classifier.classify("scala.sys.process.ProcessBuilder", "run", "()Lscala/sys/process/Process;"));
    }

    /** SCALA'S ENVIRONMENT READS, found by the same κ-covered-prefix sweep. {@code sys.env} and
     *  {@code scala.util.Properties.envOr*} are Scala's spelling of {@code System.getenv} — VERIFIED with
     *  {@code javap -c}: {@code scala.sys.package$.env()} is {@code invokestatic java/lang/System.getenv}
     *  and so are {@code envOrElse}/{@code envOrNone}. Silent for the same reason R486 was. MEASURED
     *  against real scalac output: {@code sys.env.get(k)} reported no effects, beside a
     *  {@code System.getenv(k)} control in the same file that reported {@code Env}.
     *
     *  <p>The JVM PROPERTY namespace is deliberately NOT {@code Env} in this classifier, so the two
     *  {@code assertNull} rows are the boundary, not decoration. */
    @Test
    void scalaEnvironmentReadsAreEnv() {
        assertEquals(Effect.ENV, Classifier.classify("scala.sys.package$", "env", "()Lscala/collection/immutable/Map;"));
        assertEquals(Effect.ENV, Classifier.classify("scala.util.Properties$", "envOrElse",
            "(Ljava/lang/String;Lscala/Function0;)Ljava/lang/String;"));
        assertEquals(Effect.ENV, Classifier.classify("scala.util.Properties$", "envOrNone",
            "(Ljava/lang/String;)Lscala/Option;"));
        assertEquals(Effect.ENV, Classifier.classify("scala.util.PropertiesTrait", "envOrSome",
            "(Ljava/lang/String;Lscala/Function0;)Lscala/Option;"));
        assertEquals(Effect.ENV, Classifier.classify("scala.util.PropertiesTrait", "envOrElse$",
            "(Lscala/util/PropertiesTrait;Ljava/lang/String;Lscala/Function0;)Ljava/lang/String;"));
        assertEquals(Effect.ENV, Classifier.classify("scala.util.Properties$", "jdkHome", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("scala.util.Properties$", "propOrElse",
            "(Ljava/lang/String;Lscala/Function0;)Ljava/lang/String;"));
        assertNull(Classifier.classify("scala.util.Properties$", "scalaPropOrEmpty", "(Ljava/lang/String;)Ljava/lang/String;"));
        assertNull(Classifier.classify("scala.util.Properties$", "isWin", "()Z"));
    }

    // ── harness ─────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
