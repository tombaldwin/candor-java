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
 * SOUNDNESS R480 — the {@code java.lang.ProcessBuilder} whole-type-plus-denylist fix generalised to the
 * THIRD-PARTY subprocess builders, which were left on the verb allowlist that rule's own comment records
 * as MEASURED to under-report.
 *
 * <p>MEASURED PRE-FIX at 5440749, against library stubs whose signatures were read off the real jars with
 * {@code javap} (zt-exec 1.12, commons-exec 1.4.0, testcontainers 1.19.8, im4java 1.4.0): thirteen
 * arm-only methods, every one {@code inferred: []}, and {@code deny Exec}, {@code deny Unknown},
 * {@code deny Exec Unknown} and {@code allow Exec git} all exiting 0 — including
 * {@code new ProcessExecutor().command(argv)}, which assembles a fully-armed invocation out of
 * caller-supplied argv and hands it back. Post-fix all thirteen are {@code Exec} and the three Exec-reading
 * policy forms exit 1.
 *
 * <p>The under-report was DISCLOSED, not silent — none of the four packages is in
 * {@code Rules.KAPPA_COVERED_PREFIXES}, so each floored call carried {@code invisible: [<package>]}. It was
 * still a gate PASS over an armed subprocess, which is what this pins.
 *
 * <p><b>This test is written for the CLASS, not for the instance the row was filed from.</b> The
 * program-setting verbs {@code commandSplit}, {@code withCommand}, {@code addArgument} and
 * {@code addImage} were named NOWHERE in {@code Classifier.java}; two whole payload-carrier types
 * ({@code CommandLine}, {@code IMOperation}/{@code ImageCommand}) were absent from it entirely. Every one
 * of them is pinned below, alongside the OVER-CHARGE CONTROLS that keep the widening honest: the no-arg
 * read-backs stay pure, the pure value helpers in the same packages stay pure, and a project type that
 * merely shares a name gains nothing.
 */
class ThirdPartySubprocessBuilderTest {

    // ── the stub libraries (compiled to a separate -classpath dir, never scanned) ───────────────────

    private static final Map<String, String> LIB = Map.of(
        "org/zeroturnaround/exec/ProcessExecutor.java", String.join("\n",
            "package org.zeroturnaround.exec;",
            "import java.io.File; import java.util.List;",
            "public class ProcessExecutor {",
            "  public ProcessExecutor() {}",
            "  public ProcessExecutor(String... c) {}",
            "  public List<String> getCommand() { return null; }",
            "  public File getDirectory() { return null; }",
            "  public java.util.Map<String,String> getEnvironment() { return null; }",
            "  public ProcessExecutor command(String... c) { return this; }",
            "  public ProcessExecutor commandSplit(String c) { return this; }",
            "  public ProcessExecutor directory(File d) { return this; }",
            "  public ProcessExecutor readOutput(boolean b) { return this; }",
            "  public Object execute() { return null; }",
            "  public Object start() { return null; }",
            "}"),
        "org/testcontainers/containers/GenericContainer.java", String.join("\n",
            "package org.testcontainers.containers;",
            "import java.util.List;",
            "public class GenericContainer {",
            "  public GenericContainer(String image) {}",
            "  public GenericContainer withCommand(String... parts) { return this; }",
            "  public GenericContainer withExposedPorts(Integer... p) { return this; }",
            "  public void setCommand(String cmd) {}",
            "  public String[] getCommandParts() { return null; }",
            "  public List<Integer> getExposedPorts() { return null; }",
            "  public String getLogs() { return null; }",
            "  public void start() {}",
            "  public Object execInContainer(String... cmd) { return null; }",
            "}"),
        "org/testcontainers/containers/PostgreSQLContainer.java",
            "package org.testcontainers.containers;\npublic class PostgreSQLContainer extends GenericContainer {"
                + " public PostgreSQLContainer(String image) { super(image); } }",
        "org/apache/commons/exec/CommandLine.java", String.join("\n",
            "package org.apache.commons.exec;",
            "public class CommandLine {",
            "  public CommandLine(String executable) {}",
            "  public static CommandLine parse(String line) { return null; }",
            "  public CommandLine addArgument(String a) { return this; }",
            "  public CommandLine addArguments(String[] a) { return this; }",
            "  public String[] getArguments() { return null; }",
            "  public String getExecutable() { return null; }",
            "}"),
        "org/apache/commons/exec/DefaultExecutor.java", String.join("\n",
            "package org.apache.commons.exec;",
            "import java.io.File;",
            "public class DefaultExecutor {",
            "  public DefaultExecutor() {}",
            "  public void setWorkingDirectory(File d) {}",
            "  public File getWorkingDirectory() { return null; }",
            "  public int execute(CommandLine cl) { return 0; }",
            "}"),
        "org/apache/commons/exec/util/StringUtils.java",
            "package org.apache.commons.exec.util;\npublic class StringUtils {"
                + " public static String toString(String[] a, String sep) { return null; } }",
        "org/apache/commons/exec/environment/EnvironmentUtils.java",
            "package org.apache.commons.exec.environment;\npublic class EnvironmentUtils {"
                + " public static java.util.Map<String,String> getProcEnvironment() { return null; } }",
        "org/im4java/core/Operation.java", String.join("\n",
            "package org.im4java.core;",
            "import java.util.LinkedList;",
            "public class Operation {",
            "  public Operation() {}",
            "  public Operation addImage(String... image) { return this; }",
            "  public Operation addRawArgs(String... args) { return this; }",
            "  public LinkedList<String> getCmdArgs() { return null; }",
            "}"),
        "org/im4java/core/IMOperation.java",
            "package org.im4java.core;\npublic class IMOperation extends Operation { public IMOperation() {} }",
        "org/im4java/core/ConvertCmd.java", String.join("\n",
            "package org.im4java.core;",
            "public class ConvertCmd {",
            "  public ConvertCmd() {}",
            "  public void setCommand(String... c) {}",
            "  public java.util.LinkedList<String> getCommand() { return null; }",
            "  public void run(Operation op, Object... images) {}",
            "}"));

    /** The gap fixture, one method per library, none of which launches anything: the program/argv is set
     *  HERE and the launch happens elsewhere. All thirteen reported `inferred: []` pre-fix. */
    @Test
    void armingAThirdPartyInvocationIsExec() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Arm.java", String.join("\n",
            "package com.x;",
            "import org.zeroturnaround.exec.ProcessExecutor;",
            "import org.testcontainers.containers.GenericContainer;",
            "import org.testcontainers.containers.PostgreSQLContainer;",
            "import org.apache.commons.exec.CommandLine;",
            "import org.apache.commons.exec.DefaultExecutor;",
            "import org.im4java.core.IMOperation;",
            "import org.im4java.core.ConvertCmd;",
            "public class Arm {",
            // zt-exec — the java-specific shape: the EMPTY constructor names no program, so only the
            // config verb can catch it (candor-rust charges `Command::new`; that route does not exist here).
            "  public ProcessExecutor ztCommand(String[] argv) { return new ProcessExecutor().command(argv); }",
            "  public ProcessExecutor ztCommandSplit(String line) { return new ProcessExecutor().commandSplit(line); }",
            "  public void ztDirectory(ProcessExecutor pe, java.io.File d) { pe.directory(d); }",
            // testcontainers — the image is the program, withCommand the argv.
            "  public GenericContainer tcWithCommand(String img, String[] c) { return new GenericContainer(img).withCommand(c); }",
            "  public void tcSetCommand(GenericContainer c, String cmd) { c.setCommand(cmd); }",
            // …and on a LIBRARY subclass, whose owner is what the bytecode carries. The supertype walk that
            // rescues a PROJECT subclass cannot see this one — testcontainers' own jar is never scanned.
            "  public void tcSubclass(PostgreSQLContainer c, String[] cmd) { c.withCommand(cmd); }",
            // commons-exec — CommandLine carries executable+argv; the executor only runs what it is handed.
            "  public CommandLine ceParse(String line) { return CommandLine.parse(line); }",
            "  public CommandLine ceNew(String exe) { return new CommandLine(exe); }",
            "  public void ceAddArgument(CommandLine cl, String a) { cl.addArgument(a); }",
            "  public void ceWorkingDir(DefaultExecutor ex, java.io.File d) { ex.setWorkingDirectory(d); }",
            // im4java — IMOperation carries the argv, *Cmd the program.
            "  public IMOperation imAddImage(String p) { IMOperation o = new IMOperation(); o.addImage(p); return o; }",
            "  public void imRawArgs(IMOperation o, String[] a) { o.addRawArgs(a); }",
            "  public void imSetCommand(ConvertCmd c, String[] argv) { c.setCommand(argv); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"ztCommand", "ztCommandSplit", "ztDirectory", "tcWithCommand",
                    "tcSetCommand", "tcSubclass", "ceParse", "ceNew", "ceAddArgument", "ceWorkingDir",
                    "imAddImage", "imRawArgs", "imSetCommand"}) {
                assertTrue(eff(r, "com.x.Arm." + m).contains(Effect.EXEC),
                    m + " arms a subprocess invocation — must be Exec, got " + r.get("com.x.Arm." + m));
            }
        } finally { rm(app.getParent()); }
    }

    // ── OVER-CHARGE CONTROLS ───────────────────────────────────────────────────────────────────────

    /** (a) The no-arg READ-BACKS return state already stored and add no capability. These are the named
     *  denylist carved out of each whole-type rule; if they ever gain Exec, every logger or debug printer
     *  that dumps an invocation becomes a subprocess violation. Executed end-to-end, not asserted at the
     *  table, because an absence-shaped control is only evidence if the program reaches the branch. */
    @Test
    void control_readBacksStayPure() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/R.java", String.join("\n",
            "package com.x;",
            "public class R {",
            "  public Object ztArgv(org.zeroturnaround.exec.ProcessExecutor pe) { return pe.getCommand(); }",
            "  public Object ztDir(org.zeroturnaround.exec.ProcessExecutor pe) { return pe.getDirectory(); }",
            "  public Object ztEnv(org.zeroturnaround.exec.ProcessExecutor pe) { return pe.getEnvironment(); }",
            "  public Object tcPorts(org.testcontainers.containers.GenericContainer c) { return c.getExposedPorts(); }",
            "  public Object tcParts(org.testcontainers.containers.GenericContainer c) { return c.getCommandParts(); }",
            "  public Object ceArgs(org.apache.commons.exec.CommandLine cl) { return cl.getArguments(); }",
            "  public Object ceExe(org.apache.commons.exec.CommandLine cl) { return cl.getExecutable(); }",
            "  public Object ceCwd(org.apache.commons.exec.DefaultExecutor e) { return e.getWorkingDirectory(); }",
            "  public Object imArgs(org.im4java.core.IMOperation o) { return o.getCmdArgs(); }",
            "  public Object imCmd(org.im4java.core.ConvertCmd c) { return c.getCommand(); }",
            "  public Object ceJoin(String[] a) { return org.apache.commons.exec.util.StringUtils.toString(a, \",\"); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"ztArgv", "ztDir", "ztEnv", "tcPorts", "tcParts", "ceArgs",
                    "ceExe", "ceCwd", "imArgs", "imCmd", "ceJoin"}) {
                assertFalse(eff(r, "com.x.R." + m).contains(Effect.EXEC),
                    m + " reads back stored state (or joins strings) — must NOT be Exec, got " + r.get("com.x.R." + m));
            }
        } finally { rm(app.getParent()); }
    }

    /** (b) A PROJECT type that merely shares a name with a modelled one gains nothing — the rules are
     *  owner-scoped on the real package, and a same-named local class is a different owner. */
    @Test
    void control_sameNamedProjectTypeGainsNothing() throws Exception {
        Path app = compileApp(Map.of("unused/Nothing.java", "package unused; public class Nothing {}"),
            Map.of("com/mine/CommandLine.java",
                "package com.mine;\npublic class CommandLine { public CommandLine addArgument(String a) { return this; } }",
                "com/mine/Use.java",
                "package com.mine;\npublic class Use { public void arm(CommandLine c) { c.addArgument(\"x\"); } }"));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "com.mine.Use.arm").isEmpty(),
                "a project CommandLine is not commons-exec's — must stay pure, got " + r.get("com.mine.Use.arm"));
        } finally { rm(app.getParent()); }
    }

    // ── the whole class at the classifier table, including the verbs that were named NOWHERE ───────

    /** Every program-setting verb of every payload carrier. `commandSplit`, `withCommand`, `addArgument`
     *  and `addImage` appeared nowhere in Classifier.java before R480; `command` and `parse` appeared, but
     *  only under unrelated owners ({@code ProcessHandle$Info.command} is an Env rule), so an owner-blind
     *  grep reported them covered. */
    @Test
    void everyPayloadCarrierVerbIsExec() {
        String[][] rows = {
            {"org.zeroturnaround.exec.ProcessExecutor", "<init>", "()V"},
            {"org.zeroturnaround.exec.ProcessExecutor", "command", "([Ljava/lang/String;)Lorg/zeroturnaround/exec/ProcessExecutor;"},
            {"org.zeroturnaround.exec.ProcessExecutor", "commandSplit", "(Ljava/lang/String;)Lorg/zeroturnaround/exec/ProcessExecutor;"},
            {"org.zeroturnaround.exec.ProcessExecutor", "environment", "(Ljava/lang/String;Ljava/lang/String;)Lorg/zeroturnaround/exec/ProcessExecutor;"},
            {"org.zeroturnaround.exec.ProcessExecutor", "timeout", "(JLjava/util/concurrent/TimeUnit;)Lorg/zeroturnaround/exec/ProcessExecutor;"},
            {"org.zeroturnaround.exec.ProcessExecutor", "destroyOnExit", "()Lorg/zeroturnaround/exec/ProcessExecutor;"},
            {"org.zeroturnaround.exec.ProcessExecutor", "executeNoTimeout", "()Lorg/zeroturnaround/exec/ProcessResult;"},
            {"org.apache.commons.exec.CommandLine", "<init>", "(Ljava/lang/String;)V"},
            {"org.apache.commons.exec.CommandLine", "parse", "(Ljava/lang/String;)Lorg/apache/commons/exec/CommandLine;"},
            {"org.apache.commons.exec.CommandLine", "addArgument", "(Ljava/lang/String;)Lorg/apache/commons/exec/CommandLine;"},
            {"org.apache.commons.exec.CommandLine", "addArguments", "([Ljava/lang/String;)Lorg/apache/commons/exec/CommandLine;"},
            {"org.apache.commons.exec.CommandLine", "setSubstitutionMap", "(Ljava/util/Map;)V"},
            {"org.apache.commons.exec.DefaultExecutor", "execute", "(Lorg/apache/commons/exec/CommandLine;)I"},
            {"org.apache.commons.exec.DefaultExecutor", "setWorkingDirectory", "(Ljava/io/File;)V"},
            // the spellings an owner-EQUALS rule could never see: the interface, and a library subclass.
            {"org.apache.commons.exec.Executor", "execute", "(Lorg/apache/commons/exec/CommandLine;)I"},
            {"org.apache.commons.exec.DaemonExecutor", "execute", "(Lorg/apache/commons/exec/CommandLine;)I"},
            {"org.apache.commons.exec.ExecuteWatchdog", "destroyProcess", "()V"},
            {"org.apache.commons.exec.launcher.CommandLauncherImpl", "exec", "(Lorg/apache/commons/exec/CommandLine;Ljava/util/Map;)Ljava/lang/Process;"},
            {"org.im4java.core.IMOperation", "addImage", "([Ljava/lang/String;)Lorg/im4java/core/Operation;"},
            {"org.im4java.core.Operation", "addImage", "([Ljava/lang/String;)Lorg/im4java/core/Operation;"},
            {"org.im4java.core.Operation", "addRawArgs", "([Ljava/lang/String;)Lorg/im4java/core/Operation;"},
            {"org.im4java.core.IMOps", "resize", "(Ljava/lang/Integer;Ljava/lang/Integer;)Lorg/im4java/core/IMOps;"},
            {"org.im4java.core.ImageCommand", "setCommand", "([Ljava/lang/String;)V"},
            {"org.im4java.core.ImageCommand", "run", "(Lorg/im4java/core/Operation;[Ljava/lang/Object;)V"},
            {"org.im4java.core.ConvertCmd", "run", "(Lorg/im4java/core/Operation;[Ljava/lang/Object;)V"},
            {"org.im4java.core.Info", "<init>", "(Ljava/lang/String;)V"},
            {"org.im4java.process.ProcessStarter", "run", "(Ljava/util/LinkedList;)I"},
            {"org.im4java.process.ProcessStarter", "setSearchPath", "(Ljava/lang/String;)V"},
            {"org.testcontainers.containers.GenericContainer", "withCommand", "([Ljava/lang/String;)Lorg/testcontainers/containers/GenericContainer;"},
            {"org.testcontainers.containers.GenericContainer", "setCommand", "(Ljava/lang/String;)V"},
            {"org.testcontainers.containers.GenericContainer", "start", "()V"},
            {"org.testcontainers.containers.GenericContainer", "execInContainer", "([Ljava/lang/String;)Lorg/testcontainers/containers/Container$ExecResult;"},
            {"org.testcontainers.containers.GenericContainer", "getLogs", "()Ljava/lang/String;"},
            {"org.testcontainers.containers.PostgreSQLContainer", "withCommand", "([Ljava/lang/String;)Lorg/testcontainers/containers/GenericContainer;"},
            {"org.testcontainers.containers.ContainerState", "copyFileFromContainer", "(Ljava/lang/String;Ljava/lang/String;)V"},
        };
        for (String[] row : rows)
            assertEquals(Effect.EXEC, Classifier.classify(row[0], row[1], row[2]),
                row[0] + "." + row[1] + row[2] + " arms or drives a subprocess — must be Exec");
    }

    /** The denylist, at the table. A no-arg name in the set is pure; the SAME name with arguments is the
     *  configuring setter and stays Exec — membership is only half the test, exactly as for
     *  {@code ProcessBuilder.command()} vs {@code command(List)}. */
    @Test
    void readBackDenylistIsDescriptorGated() {
        assertNull(Classifier.classify("org.zeroturnaround.exec.ProcessExecutor", "getCommand", "()Ljava/util/List;"));
        assertNull(Classifier.classify("org.zeroturnaround.exec.ProcessExecutor", "getEnvironment", "()Ljava/util/Map;"));
        assertNull(Classifier.classify("org.zeroturnaround.exec.ProcessExecutor", "streams", "()Lorg/zeroturnaround/exec/stream/ExecuteStreamHandler;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.zeroturnaround.exec.ProcessExecutor", "streams",
            "(Lorg/zeroturnaround/exec/stream/ExecuteStreamHandler;)Lorg/zeroturnaround/exec/ProcessExecutor;"));
        assertNull(Classifier.classify("org.apache.commons.exec.CommandLine", "getExecutable", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("org.apache.commons.exec.CommandLine", "toStrings", "()[Ljava/lang/String;"));
        assertNull(Classifier.classify("org.im4java.core.Operation", "getCmdArgs", "()Ljava/util/LinkedList;"));
        assertNull(Classifier.classify("org.im4java.process.ProcessStarter", "isAsyncMode", "()Z"));
        assertNull(Classifier.classify("org.testcontainers.containers.GenericContainer", "getExposedPorts", "()Ljava/util/List;"));
        assertNull(Classifier.classify("org.testcontainers.containers.GenericContainer", "isPrivilegedMode", "()Z"));
        // the §4 Object protocol on an invocation carrier stays pure in every one of these types.
        assertNull(Classifier.classify("org.apache.commons.exec.CommandLine", "toString", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("org.testcontainers.containers.GenericContainer", "hashCode", "()I"));
        // …and the carve-out is NOT "takes no argument ⇒ pure": these no-arg members launch or configure.
        assertEquals(Effect.EXEC, Classifier.classify("org.zeroturnaround.exec.ProcessExecutor", "execute", "()Lorg/zeroturnaround/exec/ProcessResult;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.zeroturnaround.exec.ProcessExecutor", "start", "()Lorg/zeroturnaround/exec/StartedProcess;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.zeroturnaround.exec.ProcessExecutor", "exitValueAny", "()Lorg/zeroturnaround/exec/ProcessExecutor;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.testcontainers.containers.GenericContainer", "stop", "()V"));
    }

    /** The non-subprocess members of the same packages: pure value helpers stay pure and the Throwables
     *  stay pure. commons-exec's OS-environment probe is NOT among them — see the rows below, which
     *  reverse this sweep's original "it is the library's own `System.getenv`" precision claim on
     *  `javap` evidence from five published versions. */
    @Test
    void neighboursInThosePackagesAreNotAllExec() {
        assertNull(Classifier.classify("org.apache.commons.exec.util.StringUtils", "toString",
            "([Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        assertNull(Classifier.classify("org.apache.commons.exec.util.MapUtils", "merge",
            "(Ljava/util/Map;Ljava/util/Map;)Ljava/util/Map;"));
        assertNull(Classifier.classify("org.apache.commons.exec.OS", "isFamilyWindows", "()Z"));
        // DebugUtils is the one `util.*` member that is not a value helper — it writes to System.err.
        // Carving it out is a no-op, not a purity claim: a stderr println is not a modelled effect here,
        // and the two rows below are the proof, so if that ever changes this test says so.
        assertNull(Classifier.classify("org.apache.commons.exec.util.DebugUtils", "handleException",
            "(Ljava/lang/String;Ljava/lang/Exception;)V"));
        assertNull(Classifier.classify("java.io.PrintStream", "println", "(Ljava/lang/String;)V"));
        assertNull(Classifier.classify("org.apache.commons.exec.ExecuteException", "getExitValue", "()I"));
        // WAS `assertEquals(Effect.ENV, …)`, AND THAT ASSERTION PINNED A SILENT UNDER-REPORT.
        // `EnvironmentUtils.getProcEnvironment()` reads the environment WITHOUT a child process in
        // commons-exec 1.3/1.4 only. `javap -c` over the published 1.0/1.1/1.2 jars shows it delegating
        // to `DefaultProcessingEnvironment.getProcEnvironment` -> `createProcEnvironment` ->
        // `runProcEnvCommand` -> `Executor.execute(…)` on the literal argv `cmd /c set` / `/usr/bin/env`.
        // This classifier cannot see a version, so the Env answer was a positive claim that is FALSE for
        // three published releases, and it silenced the package rule that had it right.
        // Proven on a consumer compiled against the real commons-exec 1.2 jar with the library out of
        // scope: `inferred: ["Env"]`, no Unknown, and `deny Exec` / `deny Unknown` / `deny Exec Unknown`
        // / `deny Exec <scope>` ALL exited 0 over a call that forks a child. See the classifier comment.
        assertEquals(Effect.EXEC, Classifier.classify("org.apache.commons.exec.environment.EnvironmentUtils",
            "getProcEnvironment", "()Ljava/util/Map;"));
        // The class the carve-out would have been EXTENDED to under SOUNDNESS R499 — refuted by the same
        // version evidence, and pinned here so the refutation cannot be silently undone. In 1.0-1.2 this
        // IS the method that forks; in 1.4.0 it is `System.getenv()`. Exec is the only version-blind
        // answer that is not a false negative for a published release.
        assertEquals(Effect.EXEC,
            Classifier.classify("org.apache.commons.exec.environment.DefaultProcessingEnvironment",
                "getProcEnvironment", "()Ljava/util/Map;"));
        // im4java's script generator and geometry helpers are deliberately outside the rule.
        assertNull(Classifier.classify("org.im4java.utils.Colors", "toColor", "(Ljava/lang/String;)Ljava/awt/Color;"));
        assertNull(Classifier.classify("org.im4java.core.IM4JavaException", "getMessage", "()Ljava/lang/String;"));
        // a neighbouring org.testcontainers package that is NOT the containers one is untouched.
        assertNull(Classifier.classify("org.testcontainers.utility.DockerImageName", "asCanonicalNameString",
            "()Ljava/lang/String;"));
    }

    /** THE MEASURED NEAR-MISS. The first version of this fix copied the ProcessBuilder shape exactly and
     *  gated every carve-out on a `()` descriptor. Measured against a real consumer compiled against
     *  testcontainers 1.19.8, that charged `container.getMappedPort(6379)` — the pure read of already
     *  stored port state that is in essentially every testcontainers test — `Exec`, and
     *  `InternetProtocol.TCP.toDockerNotation()` with it. Both are pinned here because both were
     *  over-charges a green suite would not have shown; only the consumer A/B did.
     *
     *  <p>The gate is dropped for testcontainers ONLY, and on a checked property: `javap` over
     *  `GenericContainer`/`ContainerState`/`Container` finds exactly two argument-taking `get*` members,
     *  `getMappedPort(int)` (pure, carved out) and `getLogs(OutputType...)` (a `docker logs` round trip,
     *  NOT carved out) — so the last two rows here are the discriminator, not decoration. */
    @Test
    void control_testcontainersPureAccessorsAndEnums() {
        assertNull(Classifier.classify("org.testcontainers.containers.GenericContainer", "getMappedPort", "(I)Ljava/lang/Integer;"));
        assertNull(Classifier.classify("org.testcontainers.containers.ContainerState", "getFirstMappedPort", "()Ljava/lang/Integer;"));
        assertNull(Classifier.classify("org.testcontainers.containers.ContainerState", "getHost", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("org.testcontainers.containers.InternetProtocol", "toDockerNotation", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("org.testcontainers.containers.InternetProtocol", "values", "()[Lorg/testcontainers/containers/InternetProtocol;"));
        assertNull(Classifier.classify("org.testcontainers.containers.BindMode", "valueOf", "(Ljava/lang/String;)Lorg/testcontainers/containers/BindMode;"));
        assertNull(Classifier.classify("org.testcontainers.containers.SelinuxContext", "values", "()[Lorg/testcontainers/containers/SelinuxContext;"));
        // …and the two members the same shape must NOT reach: a daemon round trip, and the payload carrier.
        assertEquals(Effect.EXEC, Classifier.classify("org.testcontainers.containers.GenericContainer", "getLogs",
            "([Lorg/testcontainers/containers/output/OutputFrame$OutputType;)Ljava/lang/String;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.testcontainers.containers.ExecConfig$ExecConfigBuilder", "command",
            "([Ljava/lang/String;)Lorg/testcontainers/containers/ExecConfig$ExecConfigBuilder;"));
    }

    /** The CHILD-OUTPUT surface: reading a subprocess's stdout is the capability `Process.getInputStream()`
     *  is charged for, and these are the same read one library layer up. Charged, not carved out. */
    @Test
    void readingTheChildsOutputIsExec() {
        assertEquals(Effect.EXEC, Classifier.classify("org.testcontainers.containers.Container$ExecResult", "getStdout", "()Ljava/lang/String;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.testcontainers.containers.output.OutputFrame", "getUtf8String", "()Ljava/lang/String;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.im4java.process.ArrayListOutputConsumer", "getOutput", "()Ljava/util/ArrayList;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.im4java.core.ImageCommand", "getErrorText", "()Ljava/util/ArrayList;"));
        // commons-exec's watchdog holds the kill handle — the `ProcessHandle.of(pid)` argument.
        assertEquals(Effect.EXEC, Classifier.classify("org.apache.commons.exec.ExecuteWatchdog", "<init>", "(J)V"));
    }

    // ── harness ────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
