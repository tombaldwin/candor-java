package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * `Exec` charges reach to the subprocess CAPABILITY, not only the launch (SPEC §1). CONSTRUCTING or
 * CONFIGURING an invocation is `Exec`, exactly as launching it is: an invocation object carries its own
 * payload — program, argv, environment — and travels fully armed, so splitting build from launch across
 * two functions MUST NOT make the builder invisible.
 *
 * <p>MEASURED GAP this closes: {@code ProcessBuilder arm(String[] argv) { return new ProcessBuilder(argv); }}
 * — a method assembling a fully-armed invocation from caller-supplied argv and handing it back — reported
 * {@code inferred: []} and passed `deny Exec` with exit 0. candor-rust (whole-type {@code process::Command}
 * rule), candor-swift ({@code Process()}) and candor-ts (whole {@code child_process} module) all already
 * charged capability; candor-java enumerated LAUNCH VERBS, and an allowlist under-reports what it omits.
 *
 * <p>The OVER-CHARGE CONTROLS are the deliverable half of this test and are written to fail if the rule
 * is widened past invocation objects: pure read-backs of stored state stay pure, a project-local type
 * that merely SHARES THE NAME gains nothing, and option-builders for OTHER effects
 * ({@code HttpRequest.Builder}, {@code StandardOpenOption}) stay pure because their resource arrives at
 * the terminal verb, which is charged at its own call site.
 */
class ExecInvocationCapabilityTest {

    // ── the rule: construct + configure are Exec ────────────────────────────────────────────────────

    /** The gap fixture verbatim: build-and-return an armed invocation, and configure a RECEIVED one.
     *  Both are Exec — neither spawns anything. */
    @Test
    void constructingAndConfiguringAnInvocationIsExec() throws Exception {
        Path cls = compile(Map.of("com/x/B.java", String.join("\n",
            "package com.x;",
            "public class B {",
            "  public ProcessBuilder arm(String[] argv) { return new ProcessBuilder(argv); }",
            "  public void configure(ProcessBuilder pb) { pb.directory(new java.io.File(\"/\")); }",
            "  public void argv(ProcessBuilder pb) { pb.command(\"sh\", \"-c\", \"id\"); }",
            "  public void wire(ProcessBuilder pb) { pb.inheritIO(); }",
            "  public void merge(ProcessBuilder pb) { pb.redirectErrorStream(true); }",
            "  public void sink(ProcessBuilder pb) { pb.redirectOutput(new java.io.File(\"/tmp/o\")); }",
            "  public void src(ProcessBuilder pb) { pb.redirectInput(new java.io.File(\"/tmp/i\")); }",
            "  public void err(ProcessBuilder pb) { pb.redirectError(new java.io.File(\"/tmp/e\")); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"arm", "configure", "argv", "wire", "merge", "sink", "src", "err"}) {
                assertTrue(eff(r, "com.x.B." + m).contains(Effect.EXEC),
                    m + " assembles/configures a subprocess invocation — must be Exec, got " + r.get("com.x.B." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** `environment()` hands back the child's environment MAP — that is `Env` (the process environment,
     *  SPEC §1), and it stays `Env`. Charging it `Exec` as well would make every env read through a
     *  builder look like a subprocess capability it does not add. */
    @Test
    void environmentStaysEnvNotExec() throws Exception {
        Path cls = compile(Map.of("com/x/E.java", String.join("\n",
            "package com.x;",
            "public class E {",
            "  public String envOnly(ProcessBuilder pb) { return pb.environment().get(\"PATH\"); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            EffectSet e = eff(r, "com.x.E.envOnly");
            assertTrue(e.contains(Effect.ENV), "environment() is Env, got " + e);
            assertFalse(e.contains(Effect.EXEC), "environment() must not be charged Exec, got " + e);
        } finally { rm(cls.getParent()); }
    }

    // ── OVER-CHARGE CONTROLS ────────────────────────────────────────────────────────────────────────

    /** (a) Pure READ-BACKS of stored state — the no-arg `command()` / `directory()` overloads — return what
     *  was already set and add no capability. A denylist carve-out, not an omission: if these ever gain
     *  `Exec`, every logger/debug-printer that dumps a builder becomes a subprocess violation. */
    @Test
    void control_readBackGettersAreNotExec() throws Exception {
        Path cls = compile(Map.of("com/x/R.java", String.join("\n",
            "package com.x;",
            "public class R {",
            "  public java.util.List<String> argvOf(ProcessBuilder pb) { return pb.command(); }",
            "  public java.io.File dirOf(ProcessBuilder pb) { return pb.directory(); }",
            "  public boolean mergedQ(ProcessBuilder pb) { return pb.redirectErrorStream(); }",
            "  public Object outQ(ProcessBuilder pb) { return pb.redirectOutput(); }",
            "  public Object inQ(ProcessBuilder pb) { return pb.redirectInput(); }",
            "  public Object errQ(ProcessBuilder pb) { return pb.redirectError(); }",
            "  public String dump(ProcessBuilder pb) { return pb.command() + \"@\" + pb.directory(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"argvOf", "dirOf", "mergedQ", "outQ", "inQ", "errQ", "dump"}) {
                assertFalse(eff(r, "com.x.R." + m).contains(Effect.EXEC),
                    m + " only READS BACK stored builder state — must not be Exec, got " + r.get("com.x.R." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** (b) A project-local type that merely SHARES THE NAME `ProcessBuilder` gains nothing. The rule is
     *  anchored at the fully-qualified `java.lang.ProcessBuilder`, never a simple-name suffix. */
    @Test
    void control_userDefinedProcessBuilderIsNotExec() throws Exception {
        Path cls = compile(Map.of(
            "app/ProcessBuilder.java", String.join("\n",
                "package app;",
                "public class ProcessBuilder {",
                "  private String[] argv;",
                "  public ProcessBuilder(String[] argv) { this.argv = argv; }",
                "  public ProcessBuilder command(String... a) { this.argv = a; return this; }",
                "  public ProcessBuilder directory(java.io.File d) { return this; }",
                "  public ProcessBuilder inheritIO() { return this; }",
                "  public java.util.Map<String,String> environment() { return java.util.Map.of(); }",
                "}"),
            "app/UseLocal.java", String.join("\n",
                "package app;",
                "public class UseLocal {",
                "  public ProcessBuilder make(String[] a) { return new ProcessBuilder(a); }",
                "  public void set(ProcessBuilder pb) { pb.command(\"x\").directory(new java.io.File(\"/\")).inheritIO(); }",
                "  public java.util.Map<String,String> env(ProcessBuilder pb) { return pb.environment(); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"make", "set", "env"}) {
                assertFalse(eff(r, "app.UseLocal." + m).contains(Effect.EXEC),
                    m + " uses a PROJECT-LOCAL type that only shares the name ProcessBuilder — must not be"
                        + " Exec, got " + r.get("app.UseLocal." + m));
            }
            assertFalse(eff(r, "app.ProcessBuilder.<init>").contains(Effect.EXEC),
                "the project-local ProcessBuilder ctor must not be Exec, got " + r.get("app.ProcessBuilder.<init>"));
        } finally { rm(cls.getParent()); }
    }

    /** (c) Option-builders for OTHER effects stay PURE — an `OpenOptions`-shaped `StandardOpenOption` set
     *  and an `HttpRequest.Builder` chain carry no resource of their own: the file and the socket arrive at
     *  the terminal verb (`Files.newOutputStream`, `HttpClient.send`), which is charged at its own call
     *  site. This is the boundary that keeps the ruling from widening into "every builder is its effect". */
    @Test
    void control_optionBuildersForOtherEffectsStayPure() throws Exception {
        Path cls = compile(Map.of("app/Opt.java", String.join("\n",
            "package app;",
            "import java.net.http.HttpRequest;",
            "import java.nio.file.OpenOption;",
            "import java.nio.file.StandardOpenOption;",
            "public class Opt {",
            "  public java.util.Set<OpenOption> fsOptions() {",
            "    return java.util.Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE,"
                + " StandardOpenOption.APPEND);",
            "  }",
            "  public HttpRequest netRequest(String u) {",
            "    return HttpRequest.newBuilder().uri(java.net.URI.create(u)).header(\"a\", \"b\")"
                + ".timeout(java.time.Duration.ofSeconds(1)).GET().build();",
            "  }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Opt.fsOptions").isEmpty(),
                "an OpenOptions-shaped option set is pure — the FILE arrives at the terminal verb, got "
                    + r.get("app.Opt.fsOptions"));
            assertTrue(eff(r, "app.Opt.netRequest").isEmpty(),
                "an HttpRequest builder chain is pure — the SOCKET arrives at HttpClient.send, got "
                    + r.get("app.Opt.netRequest"));
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
