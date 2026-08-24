package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.32⟩ THE UNREAD-CODE RULE, ON BOTH ROUTES — and the CONDITION IT IS DECIDED BY.
 *
 * <p><b>The verified fail-open this file was written for.</b> {@code gate --report} certified code nobody
 * had read, where {@code scan --policy} over the same tree refused:
 *
 * <pre>
 * &lt;tree: compiled com/x/Ok.class + an UNCOMPILED com/x/Deploy.java calling Runtime.exec("id")&gt;
 * candor &lt;tree&gt; --policy 'deny Exec'                 -&gt; exit 2  (correct)
 * candor &lt;tree&gt; --json nop.json                        (NO policy)
 * candor gate --report nop.json --policy 'deny Exec'  -&gt; exit 0  FAIL-OPEN
 * </pre>
 *
 * <p><b>The mechanism was a condition on the PRODUCER'S HISTORY.</b> The whole rule was gated on
 * {@code envObj.has("outOfScope")} — "was that scan asked a policy question?" — so a report written by a
 * bare {@code candor &lt;tree&gt; --json out.json}, which carries {@code excluded[].peeked: false} on every
 * class precisely because nothing was asked, skipped the rule in exactly the case it exists for.
 *
 * <p><b>The rule, stated once.</b> A class the producing scan did not READ licenses nothing, and whether
 * that matters is decided by the policy in force NOW. {@code peeked: false} genuinely has two causes —
 * "opened it and failed" and "never asked" — but from a REPORT they are indistinguishable and they leave
 * the identical hole: that code's effects are absent from {@code functions} because nothing looked, and
 * ⟨0.21⟩ licenses a purity claim only over units the scan actually judged. {@code excluded} is MANDATORY
 * from ⟨0.29⟩ (SPEC §2.2), so a ⟨0.29⟩-era no-policy report over a tree with exclusions carries the flag
 * and must fail closed. The carve-out is about the QUESTION: only a {@code deny}/{@code pure} rule's
 * answer depends on code outside the scan's scope, so the condition is "this policy holds a deny rule",
 * applied ONCE TO THE VALUE on both routes.
 *
 * <p><b>Why to the value and not at the exit arm.</b> The same list feeds {@code incomplete}/{@code ok} in
 * the verdict DOCUMENT and the exit code. A condition stated at only one of them lets the two disagree —
 * and this engine HAD that drift: its exit arm asked {@code !denyRules.isEmpty()} while
 * {@link Candor#scanGateFacts} recorded the unread classes unconditionally, so a {@code forbid}-only
 * policy over a tree with an uncompiled source wrote {@code "ok": false, "incomplete": true} AT EXIT 0.
 * The exit was right, the document was the over-charge, and only a machine reading the JSON could see it.
 * ({@code aNoDenyRulePolicyIsNotRefusedForWantOfAPeek} is that row; candor-rust measured the same split in
 * the same direction and fixed it in {@code ab505c0}.)
 */
class UnreadCodeRouteTest {

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

    private Path policy(String name, String text) throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, text);
        return p;
    }

    /**
     * A hand-built §2 report, in a directory of its OWN so the locator's prefix expansion cannot pull in a
     * sibling row's report and answer a question this row did not ask.
     *
     * @param excludedJson the raw text of the `excluded` key's value, or null to OMIT the key entirely
     *                     (the pre-⟨0.29⟩ producer, which is a different claim — ⟨0.26⟩)
     */
    private Path report(String name, String excludedJson) throws Exception {
        Path dir = Files.createDirectories(tmp.resolve("r-" + name));
        Path f = dir.resolve(name + ".jvm.json");
        Files.writeString(f, "{\n"
                + "  \"candor\": { \"version\": \"t\", \"toolchain\": \"jdk-21\", \"spec\": \"0.31\" },\n"
                + "  \"packages\": [ \"com.x\" ],\n"
                + "  \"analyzed\": { \"count\": 2, \"digest\": \"0000000000000000\" },\n"
                + (excludedJson == null ? "" : "  \"excluded\": " + excludedJson + ",\n")
                + "  \"functions\": []\n"
                + "}\n");
        return f;
    }

    /**
     * The REPRO's tree: one COMPILED class, and one `.java` that was never compiled — the
     * {@code source-without-class} exclusion, which candor-java declares {@code peeked: false} when no
     * peek ran (no policy ⇒ no question ⇒ nothing opened).
     */
    private Path unreadTree() throws Exception {
        return tree("tree", "  public void go() throws Exception { Runtime.getRuntime().exec(\"id\"); }");
    }

    /**
     * The same shape, with a source the peek CANNOT drive: it does not compile, so the compile-peek fails
     * and the class stays {@code peeked: false} even under a policy that denies. That isolates the
     * unread-code arm — the ⟨0.30⟩ {@code outOfScope} arm cannot fire over a file nothing could read — so
     * a row using this tree is answering about THIS rule and not about its neighbour.
     */
    private Path unpeekableTree() throws Exception {
        return tree("broken", "  public void go() { Runtime.getRuntime().exec(\"id\")   // no semicolon,");
    }

    private Path tree(String name, String body) throws Exception {
        Path classes = compile(Map.of("Ok.java", String.join("\n",
            "package com.x;",
            "public class Ok { public int add(int a, int b){ return a + b; } }")));
        Path root = tmp.resolve(name);
        Files.createDirectories(root.resolve("com/x"));
        Files.copy(classes.resolve("com/x/Ok.class"), root.resolve("com/x/Ok.class"));
        Files.writeString(root.resolve("com/x/Deploy.java"), String.join("\n",
            "package com.x;",
            "public class Deploy {",
            body,
            "}"));
        rm(classes.getParent());
        return root;
    }

    private JsonObject json(Path f) throws Exception {
        return JsonParser.parseString(Files.readString(f)).getAsJsonObject();
    }

    // ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────

    /**
     * THE ROUTE SPLIT ITSELF. Both routes, one tree, one policy — and the report route must not certify
     * what the scan route refused. The scan arm is not decoration: without it a green row here could mean
     * the fixture simply has nothing unread in it.
     */
    @Test void aReportProducedWithoutAPolicyStillFailsClosedOnCodeNobodyRead() throws Exception {
        Path root = unreadTree();
        Path pol = policy("exec.policy", "deny Exec\n");

        Run scan = runCli(root.toString(), "--policy", pol.toString());
        assertEquals(2, scan.exit(), "the SCAN route refuses — the uncompiled source went unread: "
                + scan.stderr());

        Path rep = tmp.resolve("nop").resolve("nop.jvm.json");
        Files.createDirectories(rep.getParent());
        Run write = runCli(root.toString(), "--json", rep.toString());
        assertEquals(0, write.exit(), "a bare scan does not refuse — it discloses: " + write.stderr());
        JsonObject rpt = json(rep);
        assertFalse(rpt.getAsJsonArray("excluded").get(0).getAsJsonObject().get("peeked").getAsBoolean(),
            "the fixture must actually carry the flag this rule reads, or the row below is vacuous: "
                + rpt.get("excluded"));
        assertFalse(rpt.has("outOfScope"),
            "…and NO `outOfScope`, which is the producer history the rule used to be gated on: " + rpt);

        Run gate = runCli("gate", "--report", rep.toString(), "--policy", pol.toString());
        assertEquals(2, gate.exit(), "VERIFIED FAIL-OPEN: `gate --report` certified code the producing "
                + "scan says it never read, where `scan --policy` over the same tree refuses. `peeked: "
                + "false` is the producer stating it did not open those files; from a report its two "
                + "causes are indistinguishable and leave the identical hole. Got: " + gate.stdout()
                + gate.stderr());
        assertTrue(gate.stderr().contains("did not READ"),
            "…and it must NAME the class, not just exit 2: " + gate.stderr());
        assertTrue(gate.stderr().contains("source-without-class"), gate.stderr());
    }

    /**
     * THE DOCUMENT AND THE EXIT CODE AGREE, ON BOTH ROUTES (SPEC §3.1). The condition is applied to the
     * VALUE precisely so this cannot drift: a verdict reading {@code ok: true} beside exit 2 is the
     * gateless green one level down, and {@code ok: false} beside exit 0 is the over-charge.
     */
    @Test void theVerdictDocumentAgreesWithTheExitOnBothRoutes() throws Exception {
        Path root = unreadTree();
        Path pol = policy("exec2.policy", "deny Exec\n");

        Path scanV = tmp.resolve("scan.verdict.json");
        Run scan = runCli(root.toString(), "--policy", pol.toString(), "--gate-json", scanV.toString());
        assertEquals(2, scan.exit(), scan.stderr());
        JsonObject sv = json(scanV);
        assertFalse(sv.get("ok").getAsBoolean(), "exit 2 and `ok: true` is the gateless green: " + sv);
        assertTrue(sv.has("incomplete") && sv.get("incomplete").getAsBoolean(),
            "…and the machine channel must say WHY it is not a pass: " + sv);

        Path rep = tmp.resolve("nop2").resolve("nop.jvm.json");
        Files.createDirectories(rep.getParent());
        runCli(root.toString(), "--json", rep.toString());
        Path gateV = tmp.resolve("gate.verdict.json");
        Run gate = runCli("gate", "--report", rep.toString(), "--policy", pol.toString(),
                          "--gate-json", gateV.toString());
        assertEquals(2, gate.exit(), gate.stderr());
        JsonObject gv = json(gateV);
        assertFalse(gv.get("ok").getAsBoolean(), "the report route's document must agree with its exit: " + gv);
        assertTrue(gv.has("incomplete") && gv.get("incomplete").getAsBoolean(), gv.toString());
    }

    // ── THE OVER-CHARGE CONTROLS ──────────────────────────────────────────────────────────────────────
    // Written BEFORE the fix and green on the pre-fix build, except where noted. The safe-LOOKING value
    // (refuse everything) passes the defect row above while deleting the verb, so these are the half that
    // decides whether the repair is a repair.

    /** A report whose every excluded class was PEEKED — asked and answered — certifies. */
    @Test void aFullyPeekedReportStillCertifies() throws Exception {
        Path rep = report("peeked",
                "[ { \"class\": \"archive-under-the-scan-root\", \"count\": 3, \"peeked\": true, "
                + "\"reason\": \"read\" } ]");
        Run r = runCli("gate", "--report", rep.toString(),
                       "--policy", policy("p1.policy", "deny Exec\n").toString());
        assertEquals(0, r.exit(), "a class the producer READ hides nothing: " + r.stdout() + r.stderr());
    }

    /** A report that excluded NOTHING certifies — ⟨0.27⟩'s zero-match is a positive statement. */
    @Test void aReportWithNoExclusionsStillCertifies() throws Exception {
        Path rep = report("none", "[]");
        Run r = runCli("gate", "--report", rep.toString(),
                       "--policy", policy("p2.policy", "deny Exec\n").toString());
        assertEquals(0, r.exit(), "nothing was excluded, so nothing went unread: " + r.stdout() + r.stderr());
    }

    /**
     * An ABSENT {@code excluded} key still certifies. ⟨0.26⟩: absent means "this producer cannot answer",
     * and refusing over one would refuse every report a pre-⟨0.29⟩ engine ever wrote. STRICTNESS BELONGS
     * ON THE UNREADABLE SHAPE, not on the older producer.
     */
    @Test void aPreFileSetReportStillCertifies() throws Exception {
        Path rep = report("legacy", null);
        Run r = runCli("gate", "--report", rep.toString(),
                       "--policy", policy("p3.policy", "deny Exec\n").toString());
        assertEquals(0, r.exit(), "a pre-⟨0.29⟩ report carries no `excluded` at all: "
                + r.stdout() + r.stderr());
    }

    /** {@code judgedElsewhere: true} — the producer saying those files are COPIES of code it already
     *  judged — carves the class out, unpeeked or not. Only the PRODUCER may say it. */
    @Test void judgedElsewhereCarvesTheClassOut() throws Exception {
        Path rep = report("je",
                "[ { \"class\": \"build-output-archive\", \"count\": 1, \"peeked\": false, "
                + "\"judgedElsewhere\": true, \"reason\": \"derived\" } ]");
        Run r = runCli("gate", "--report", rep.toString(),
                       "--policy", policy("p4.policy", "deny Exec\n").toString());
        assertEquals(0, r.exit(), "a derived copy of judged code hides nothing: " + r.stdout() + r.stderr());
    }

    /**
     * A POLICY WITH NO DENY RULE IS NOT REFUSED FOR WANT OF A PEEK — the over-charge that decides whether
     * the condition is about the QUESTION or about the code. The peek short-circuits when nothing is
     * denied ({@code peekRules.isEmpty()}), so every class comes back {@code peeked: false} without a
     * question ever having been put; reading that as unread code refuses a tree nobody asked about.
     *
     * <p>ON THE SCAN ROUTE, because that is where a no-deny policy reaches a verdict at all: the report
     * route refuses {@code forbid}/{@code allow} UNIFORMLY and earlier, for answerability.
     *
     * <p><b>The document half of this row was RED before the fix</b>, and it is the drift the value-side
     * condition exists to close: the exit arm asked for a deny rule, {@link Candor#scanGateFacts} did not,
     * so this wrote {@code "ok": false, "incomplete": true} at exit 0.
     */
    @Test void aNoDenyRulePolicyIsNotRefusedForWantOfAPeek() throws Exception {
        Path root = unpeekableTree();
        // §6.2 spellings, both checked with `parsepolicy` — a rule this engine DROPS would make the row
        // pass for the wrong reason (a zero-rule policy refuses, and the refusal is not the property
        // under test).
        for (String body : List.of("forbid com.x -> com.y\n", "allow Exec in com.x id\n")) {
            String tag = body.startsWith("forbid") ? "forbid" : "allow";
            Path v = tmp.resolve(tag + ".verdict.json");
            Run r = runCli(root.toString(), "--policy", policy(tag + ".policy", body).toString(),
                           "--gate-json", v.toString());
            assertEquals(0, r.exit(), "`" + body.trim() + "` denies nothing, so no peek was ever asked "
                    + "for and there is no unread-code question to answer: " + r.stderr());
            JsonObject d = json(v);
            assertTrue(d.get("ok").getAsBoolean(),
                "…and the DOCUMENT must say the same thing the exit does — `ok: false` beside exit 0 is "
                + "the over-charge only a machine reading the JSON can see: " + d);
            assertFalse(d.has("incomplete"), "…nor may it claim incompleteness: " + d);
        }

        // THE DENY-RULE CONTROL, in the same row: without it, deleting the recorder outright passes every
        // assertion above. The IDENTICAL tree under a policy that DOES deny must refuse — and over this
        // tree it can only be the unread arm doing it, because the peek cannot compile the source and so
        // finds nothing to put in `outOfScope`.
        Path v = tmp.resolve("deny.verdict.json");
        Run r = runCli(root.toString(), "--policy", policy("deny.policy", "deny Exec\n").toString(),
                       "--gate-json", v.toString());
        assertEquals(2, r.exit(), "the same tree under a deny rule refuses: " + r.stderr());
        assertTrue(r.stderr().contains("did not READ"), "…and by the UNREAD arm: " + r.stderr());
        assertFalse(json(v).get("ok").getAsBoolean(), json(v).toString());
    }

    /**
     * {@code pure} IS A DENY RULE AND MUST ARM THE RULE. A recorded trap in this project: flattening rules
     * into effect NAMES made {@code pure} name nothing, so the STRICTEST policy silently disarmed the peek
     * — exit 0 where the weaker {@code deny Exec} exits 2 on the same tree. The condition here is the
     * RULE LIST, never a name set, and this row is what holds it there.
     */
    @Test void aPureRuleArmsTheUnreadCodeRule() throws Exception {
        Path root = unpeekableTree();
        Run scan = runCli(root.toString(), "--policy", policy("pure.policy", "pure com.x\n").toString());
        assertEquals(2, scan.exit(), "`pure` is a deny rule with an EMPTY effect list, not a policy that "
                + "denies nothing: " + scan.stderr());
        assertTrue(scan.stderr().contains("did not READ"), "…by the UNREAD arm: " + scan.stderr());

        Path rep = tmp.resolve("nop3").resolve("nop.jvm.json");
        Files.createDirectories(rep.getParent());
        runCli(root.toString(), "--json", rep.toString());
        Run gate = runCli("gate", "--report", rep.toString(),
                          "--policy", policy("pure2.policy", "pure com.x\n").toString());
        assertEquals(2, gate.exit(), "…on the report route too: " + gate.stdout() + gate.stderr());
    }

    // ── CORRUPT INPUT FAILS CLOSED ────────────────────────────────────────────────────────────────────

    /**
     * A NON-BOOLEAN {@code peeked} IS CORRUPT INPUT — <b>the SAME defect as the row below, in the key one
     * field UP, shipped in the same commit that hardened its neighbour.</b> That commit's own comment
     * called {@code judgedElsewhere} "the ONE key here that can DELETE a refusal"; it is not, and writing
     * that down is part of why nothing looked at {@code peeked}.
     *
     * <p>MEASURED on the build this repairs — same report, same policy, only the value's TYPE changed:
     * <pre>
     * "peeked": false   -> gate --report exits 2   {"ok":false,…,"incomplete":true}
     * "peeked": "true"  -> gate --report exits 0   {"ok":true,"violations":[]}      no hedge, no disclosure
     * </pre>
     * Four-way on those bytes: <b>java 0, rust 2, ts 2, swift 2</b>.
     *
     * <p><b>EVERY SHAPE, because only ONE of them was fail-open.</b> {@code getAsBoolean} on a string is
     * {@code Boolean.parseBoolean}, so {@code "true"} carved the class out while {@code 1}, {@code 0} and
     * {@code null} coerced to {@code false} and refused ANYWAY — for the wrong reason, and reasoning about
     * the class instead of enumerating it would have stopped at "this coerces safely". After the fix all
     * seven refuse and all seven NAME the key, which is the difference between a refusal an operator can
     * act on and one that reads as unread code they do not have.
     */
    @Test void aNonBooleanPeekedIsCorruptInput() throws Exception {
        // `"false"` is in here deliberately: it exits 2 either way, so only the MESSAGE distinguishes a
        // document this engine impeached from one it read as an honest unread class.
        List<String> shapes = List.of("\"true\"", "\"false\"", "1", "0", "null", "{ }", "[ ]");
        for (String shape : shapes) {
            String tag = "pk" + Math.abs(shape.hashCode());
            Path rep = report(tag,
                    "[ { \"class\": \"build-output-archive\", \"count\": 1, \"peeked\": " + shape
                    + ", \"reason\": \"r\" } ]");
            Run r = runCli("gate", "--report", rep.toString(),
                           "--policy", policy(tag + ".policy", "deny Exec\n").toString());
            assertEquals(2, r.exit(), "`peeked`: " + shape + " is not a boolean, and coercing it deletes "
                    + "the unread-code refusal: " + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("peeked"),
                "…and the refusal must NAME the key, or a corrupt document is indistinguishable from an "
                + "honestly unread class (`peeked`: " + shape + "): " + r.stderr());
        }
    }

    /**
     * THE CONTROLS FOR THE ROW ABOVE, in one place: the SAFE-LOOKING repair (refuse every {@code peeked})
     * passes every assertion up there while deleting the carve-out the key exists for. A genuine boolean
     * {@code true} must still suppress, a genuine {@code false} must still refuse, and an ABSENT key must
     * still read as NOT peeked (never as "the producer opened them").
     */
    @Test void aGenuineBooleanPeekedIsUntouched() throws Exception {
        Path yes = report("pkTrue",
                "[ { \"class\": \"archive-under-the-scan-root\", \"count\": 3, \"peeked\": true, "
                + "\"reason\": \"read\" } ]");
        Run r1 = runCli("gate", "--report", yes.toString(),
                        "--policy", policy("pk1.policy", "deny Exec\n").toString());
        assertEquals(0, r1.exit(), "a real `true` still certifies — this is the carve-out, not the defect: "
                + r1.stdout() + r1.stderr());

        Path no = report("pkFalse",
                "[ { \"class\": \"build-output-archive\", \"count\": 1, \"peeked\": false, "
                + "\"reason\": \"r\" } ]");
        Run r2 = runCli("gate", "--report", no.toString(),
                        "--policy", policy("pk2.policy", "deny Exec\n").toString());
        assertEquals(2, r2.exit(), "a real `false` still refuses: " + r2.stdout() + r2.stderr());
        assertTrue(r2.stderr().contains("did not READ"), "…by the UNREAD arm, not as corrupt input: "
                + r2.stderr());

        Path absent = report("pkAbsent",
                "[ { \"class\": \"build-output-archive\", \"count\": 1, \"reason\": \"r\" } ]");
        Run r3 = runCli("gate", "--report", absent.toString(),
                        "--policy", policy("pk3.policy", "deny Exec\n").toString());
        assertEquals(2, r3.exit(), "an ABSENT `peeked` is NOT peeked — a producer that does not carry the "
                + "key cannot be read as having opened the files: " + r3.stdout() + r3.stderr());
        assertTrue(r3.stderr().contains("did not READ"),
            "…and absence is not corruption: it must refuse by the UNREAD arm: " + r3.stderr());
    }

    /**
     * A NON-BOOLEAN {@code judgedElsewhere} IS CORRUPT INPUT. Gson's {@code getAsBoolean} coerces — the
     * STRING {@code "true"} came back {@code true} — so a report could carve a class out with a value the
     * §2.2 shape does not allow, which is the fail-open reading of a key whose whole job is to be a
     * producer's narrow, explicit exemption.
     */
    @Test void aNonBooleanJudgedElsewhereIsCorruptInput() throws Exception {
        Path rep = report("jebad",
                "[ { \"class\": \"build-output-archive\", \"count\": 1, \"peeked\": false, "
                + "\"judgedElsewhere\": \"true\", \"reason\": \"derived\" } ]");
        Run r = runCli("gate", "--report", rep.toString(),
                       "--policy", policy("p5.policy", "deny Exec\n").toString());
        assertEquals(2, r.exit(), "a string is not a boolean, and coercing it carves out a class the "
                + "producer never exempted: " + r.stdout() + r.stderr());
        assertTrue(r.stderr().contains("judgedElsewhere"), "…and the refusal names the key: " + r.stderr());
    }

    /**
     * {@code excluded} PRESENT BUT UNREADABLE IMPEACHES THE DOCUMENT — it joins the strictly-read §2
     * signature keys beside {@code outOfScope} and {@code netPartners}. Read as the empty list it makes
     * the claim "this scan excluded nothing", which is the safe-LOOKING value and deletes this rule.
     */
    @Test void anUnreadableExcludedKeyImpeachesTheDocument() throws Exception {
        for (String shape : List.of("\"lots\"", "[ 123 ]")) {
            Path rep = report("bad" + Math.abs(shape.hashCode()), shape);
            Run r = runCli("gate", "--report", rep.toString(),
                           "--policy", policy("p6-" + Math.abs(shape.hashCode()) + ".policy",
                                              "deny Exec\n").toString());
            assertEquals(2, r.exit(), "`excluded`: " + shape + " must not be coerced to []: "
                    + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("excluded"), "…and the refusal names the key: " + r.stderr());
        }
    }

    /**
     * THE ADVISORY HEDGE NAMES ITS CAUSE. ⟨0.24⟩ binds a descriptive verb never to be LESS sensitive to
     * incompleteness than the gate over the same bytes, and {@code ReportCompleteness.incomplete()} has
     * counted the two SCOPE causes since ⟨0.30⟩ — but the SENTENCE was built from the three manifest rows
     * alone, so over a report whose only cause is one of them the line came out as
     * {@code ⚠ INCOMPLETE — the report(s) under this locator ,} — an empty clause. A hedge whose sentence
     * says nothing is the deleted-disclosure defect inside the disclosure itself.
     *
     * <p>Latent for the unread cause while the rule was gated on the producer's history (that state could
     * not be reached here); MEASURED for the {@code outOfScope} cause on the pre-fix build, so it was
     * already live. Both arms, because a repair to one is not a repair to the other.
     */
    @Test void theAdvisoryHedgeNamesTheScopeCauseItFiredOn() throws Exception {
        Path root = unreadTree();

        Path nop = tmp.resolve("adv1").resolve("r.jvm.json");
        Files.createDirectories(nop.getParent());
        runCli(root.toString(), "--json", nop.toString());
        Run unread = runCli("blindspots", "--report", nop.toString(), "--strict");
        assertTrue(unread.stdout().contains("⚠ INCOMPLETE"), "the hedge must fire: " + unread.stdout());
        assertFalse(unread.stdout().contains("under this locator ,"),
            "…and it must NAME its cause, not trail off into an empty clause: " + unread.stdout());
        assertTrue(unread.stdout().contains("did NOT READ"), unread.stdout());

        Path pol = tmp.resolve("adv2").resolve("r.jvm.json");
        Files.createDirectories(pol.getParent());
        runCli(root.toString(), "--json", pol.toString(),
               "--policy", policy("adv.policy", "deny Exec\n").toString());
        Run oos = runCli("blindspots", "--report", pol.toString(), "--strict");
        assertTrue(oos.stdout().contains("⚠ INCOMPLETE"), oos.stdout());
        assertFalse(oos.stdout().contains("under this locator ,"),
            "the ⟨0.30⟩ scope cause was ALREADY silent here before this rung: " + oos.stdout());
        assertTrue(oos.stdout().contains("OUTSIDE the scan's scope"), oos.stdout());
    }

    /**
     * AN EXCLUSION WITH NO {@code class} IS STILL A CLASS THE SCAN DID NOT READ. Dropping the entry for
     * want of a label would let a malformed report delete its own disclosure — the same fail-open
     * coercion as reading the key's absence as "nothing was excluded", one field down.
     */
    @Test void anExclusionWithNoClassNameStillCountsAsUnread() throws Exception {
        Path rep = report("noclass", "[ { \"count\": 1, \"peeked\": false, \"reason\": \"r\" } ]");
        Run r = runCli("gate", "--report", rep.toString(),
                       "--policy", policy("p7.policy", "deny Exec\n").toString());
        assertEquals(2, r.exit(), "an unnamed exclusion is not an absent one: " + r.stdout() + r.stderr());
    }

    /**
     * …AND AN UNREADABLE CLASS NAME IS WITHHELD, NOT REFUSED — the DECORATION side of §2's role test,
     * held deliberately against the sweep that hardened {@code peeked} beside it.
     *
     * <p>Nothing DECIDES on this token: the rule reads the producer's {@code peeked} flag and never the
     * name (keying on the name would gate another engine's report differently from the engine that wrote
     * it — the same concept is {@code build-output-archive} here and {@code build-output} in rust and
     * swift), and the name reaches stderr and the hedge sentence, never the verdict DOCUMENT. So §2's
     * instruction applies as written: <i>"withhold the decoration, disclose it, and answer. Refusing
     * there drops a hedge to be strict about ornament."</i> There is no fail-open behind it either — an
     * unreadable name already left the entry counted as unread.
     *
     * <p>The row exists because the FIRST draft of that sweep DID harden this one, and only asking which
     * side of §2's line it sits on caught it. Without a row, the next sweep makes the same over-reach.
     */
    @Test void anUnreadableExclusionClassNameIsWithheldRatherThanRefused() throws Exception {
        for (String shape : List.of("123", "true", "{ }", "[ ]", "null")) {
            String tag = "cls" + Math.abs(shape.hashCode());
            Path rep = report(tag, "[ { \"class\": " + shape + ", \"count\": 1, \"peeked\": false, "
                    + "\"reason\": \"r\" } ]");
            Run r = runCli("gate", "--report", rep.toString(),
                           "--policy", policy(tag + ".policy", "deny Exec\n").toString());
            // Still exit 2 — but by the UNREAD arm, and that distinction is the whole row: the class is
            // counted, the document is NOT impeached, and the name is withheld rather than rendered.
            assertEquals(2, r.exit(), "the class is still unread (`class`: " + shape + "): "
                    + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("did not READ"),
                "…and it must refuse by the UNREAD arm, not impeach the document over a LABEL (`class`: "
                + shape + "): " + r.stderr());
            assertTrue(r.stderr().contains("(unnamed exclusion class)"),
                "…withholding the unreadable name rather than rendering one no producer wrote — "
                + "`\"class\": 123` used to print a class called `123` (`class`: " + shape + "): "
                + r.stderr());
        }
    }
}
