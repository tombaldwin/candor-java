package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.24⟩ <b>AN ADVISORY VERB MAY BE LESS CERTAIN THAN THE GATE, NEVER MORE</b> — SPEC §3.2, ruled in
 * candor-spec {@code 4fd140c}. The invariant is a COMPARISON, not a behaviour: for any report and policy,
 * {@code U_clear ⊆ G_clear}. Conformance PART 27 row R11 pins it four-way; this class pins the same law
 * inside the engine, with the two mechanisms that produced it.
 *
 * <p><b>The law was written over three instances that share only the DIRECTION of the error</b> — a lenient
 * manifest reader, a hole predicate ignoring the class filter, and (this one) an advisory verb answering
 * where the gate refused. Two of the three were patched before it was stated, which is why it is a law: a
 * rule stated over any one of them would not have caught the next two, and did not.
 *
 * <p><b>MEASURED, two mechanisms, on a jar built from the commit before this one.</b>
 *
 * <pre>
 *   (1) the R11 report — `hosts` present, `netClass` ABSENT — under `deny Net[unknown-host] app`:
 *       gate --report   exit 2   §3.1 answerability refusal — it CANNOT judge `app.noClass`
 *       unverified      exit 0   names `app.nativeHole` (a DIFFERENT hole), CLEARS `app.noClass`
 *
 *   (2) an entry whose `Unknown` is INHERITED with no reason reachable, under `deny Unknown[unresolved] app`:
 *       gate --report        exit 2   it CANNOT judge `app.inherits`
 *       unverified           exit 0   ok:true, `unverified: []`  — NOTHING NAMED AT ALL
 *       fix-gate --strict    exit 1   a full hoist plan for `app.inherits`, and a RED CI check
 * </pre>
 *
 * <p>(2) is the stronger row and the one that names the mechanism. There is no single bug here: there was
 * no QUESTION. {@code unverified}'s hole predicate asks "does the gate PASS this function while it is
 * Unknown?", and both halves of that quietly assume the gate reached a verdict at all — {@code app.noClass}
 * carries no {@code Unknown} so it was never a candidate, and {@code app.inherits} had its narrowing FIRE on
 * {@link Policy#reasonClassesOf}'s fail-closed {@code unresolved} floor, i.e. on a class DERIVED from the
 * very field the gate refused to read. A hedge does beat a hole, but a derivation is not a hedge.
 *
 * <p><b>AT SCALE, on an external corpus</b> — {@code aws-java-sdk-s3-1.12.395} (2157 entries, 696
 * {@code Net}-bearing of which 689 carry {@code hosts}, 821 {@code Unknown}-bearing), scanned by this
 * engine and then re-served with one channel dropped, as a producer below the rung would write it. The
 * partition below is the property; the numbers are in {@link #thePartitionAccountsForEveryFunctionTheRuleReaches}.
 */
class AdvisoryBoundTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void fresh() {
        Candor.resetState();
        Candor.gateViolations.clear();
        Candor.gateCapture = false;
    }

    @AfterEach
    void clear() {
        Candor.gateCapture = false;
        Candor.gateViolations.clear();
        Candor.resetState();
    }

    // ── fixtures ───────────────────────────────────────────────────────────────────────────────────────

    private static Map<String, Object> entry(String fn, List<String> inferred, List<String> direct,
                                             Map<String, Object> extra) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", fn);
        m.put("loc", "Svc.java:1");
        m.put("inferred", inferred);
        m.put("direct", direct);
        m.put("declared", List.of());
        m.put("undeclared", List.of());
        m.put("overdeclared", List.of());
        m.put("entryPoint", false);
        m.put("unresolved", inferred.contains("Unknown"));
        m.put("hash", "");
        if (extra != null) m.putAll(extra);
        return m;
    }

    private Path report(String name, List<Map<String, Object>> entries) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", entries.size(), "digest", "0"));
        env.put("functions", entries);
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    /** Conformance R11's report, entry for entry: an {@code Unknown} the class filter EXCLUDES, a
     *  {@code Net} entry carrying {@code hosts} but NO {@code netClass}, and a plain violator so the gate
     *  has something to charge and the fixture is not vacuous. */
    private Path r11Report() throws Exception {
        return report("r11.jvm.json", List.of(
                entry("app.nativeHole", List.of("Unknown"), List.of("Unknown"),
                        Map.of("unknownWhy", List.of("native:dlopen"))),
                entry("app.noClass", List.of("Net"), List.of("Net"),
                        Map.of("hosts", List.of("api.example.com"))),
                entry("app.writes", List.of("Fs"), List.of("Fs"),
                        Map.of("paths", List.of("/etc/hosts")))));
    }

    /** THE HARDER HALF: an {@code Unknown} that is purely INHERITED, with no reason reachable — so §6.2's
     *  class set resolves EMPTY and the gate refuses. Note the empty {@code calls}: the ⟨0.24⟩ producer-side
     *  repair makes this state unreachable in a report THIS engine writes, which is exactly why the verb
     *  has to handle it — a report is DATA, and this is what a foreign or pre-rung producer emits. */
    private Path inheritedReasonlessReport() throws Exception {
        return report("inherited.jvm.json", List.of(
                entry("app.inherits", List.of("Unknown"), List.of(), null),
                entry("app.clean", List.of(), List.of(), null)));
    }

    /** The MIRROR fixture: the same shape with the channel PRESENT, so the gate CAN judge it. */
    private Path netClassPresentReport() throws Exception {
        return report("present.jvm.json", List.of(
                entry("app.nativeHole", List.of("Unknown"), List.of("Unknown"),
                        Map.of("unknownWhy", List.of("native:dlopen"))),
                entry("app.noClass", List.of("Net"), List.of("Net"),
                        Map.of("hosts", List.of("api.example.com"),
                               "netClass", List.of("unknown-host"))),
                entry("app.writes", List.of("Fs"), List.of("Fs"),
                        Map.of("paths", List.of("/etc/hosts")))));
    }

    private Path policy(String body) throws Exception {
        Path p = tmp.resolve("p" + Math.abs(body.hashCode()) + ".policy");
        Files.writeString(p, body);
        return p;
    }

    // ── drivers (through the CLI dispatcher, so the flag grammar is under test too) ─────────────────────

    private static int cli(String... argv) {
        Candor.resetState();
        return Query.run(argv);
    }

    private static int exitOf(Path report, Path pol, String verb, String... more) {
        List<String> a = new ArrayList<>(List.of(verb, "--report", report.toString(),
                "--policy", pol.toString()));
        a.addAll(List.of(more));
        PrintStream o = System.out, e = System.err;
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        System.setOut(new PrintStream(sink));
        System.setErr(new PrintStream(sink));
        try {
            return cli(a.toArray(new String[0]));
        } finally {
            System.setOut(o);
            System.setErr(e);
        }
    }

    private static JsonObject json(Path report, Path pol, String verb, String... more) {
        List<String> a = new ArrayList<>(List.of(verb, "--report", report.toString(),
                "--policy", pol.toString(), "--json"));
        a.addAll(List.of(more));
        PrintStream o = System.out, e = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buf));
        System.setErr(new PrintStream(new ByteArrayOutputStream()));
        try {
            cli(a.toArray(new String[0]));
        } finally {
            System.setOut(o);
            System.setErr(e);
        }
        return JsonParser.parseString(buf.toString()).getAsJsonObject();
    }

    private static String stderrOf(Path report, Path pol, String verb, String... more) {
        List<String> a = new ArrayList<>(List.of(verb, "--report", report.toString(),
                "--policy", pol.toString()));
        a.addAll(List.of(more));
        PrintStream o = System.out, e = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(new ByteArrayOutputStream()));
        System.setErr(new PrintStream(buf));
        try {
            cli(a.toArray(new String[0]));
        } finally {
            System.setOut(o);
            System.setErr(e);
        }
        return buf.toString();
    }

    private static List<String> unverifiedFns(JsonObject o) {
        List<String> out = new ArrayList<>();
        for (var el : o.getAsJsonArray("unverified")) out.add(el.getAsJsonObject().get("fn").getAsString());
        return out;
    }

    /** The entries this verb named as UNJUDGED — told apart by `why`, the missing-evidence reason. */
    private static List<String> unjudgedFns(JsonObject o) {
        List<String> out = new ArrayList<>();
        for (var el : o.getAsJsonArray("unverified"))
            if (el.getAsJsonObject().has("why")) out.add(el.getAsJsonObject().get("fn").getAsString());
        return out;
    }

    private static List<String> remedyFns(JsonObject o) {
        List<String> out = new ArrayList<>();
        for (var el : o.getAsJsonArray("remedies")) out.add(el.getAsJsonObject().get("fn").getAsString());
        return out;
    }

    // ── 1. THE ROW CONFORMANCE R11 MEASURES ────────────────────────────────────────────────────────────

    /**
     * The gate REFUSES over {@code app.noClass} (§3.1 answerability), so {@code unverified} must NAME it.
     * <b>The assertion is PER FUNCTION and that is load-bearing:</b> a weaker form — "the gate is not clean
     * ⇒ the verb names SOMETHING" — passed on all four engines while this defect stood, because the verb
     * named {@code app.nativeHole} instead. R11's header says so explicitly; it is the one thing about this
     * row that is easy to get wrong and impossible to notice.
     */
    @Test
    void unverifiedNamesTheFunctionTheGateCouldNotJudge() throws Exception {
        Path rep = r11Report();
        Path pol = policy("deny Net[unknown-host] app\n");

        assertEquals(2, exitOf(rep, pol, "gate"), "§3.1 answerability: the gate cannot judge `app.noClass`");

        JsonObject uv = json(rep, pol, "unverified");
        assertTrue(unverifiedFns(uv).contains("app.noClass"),
                "the gate could NOT clear `app.noClass`, so the verb must name it — naming a DIFFERENT hole "
                + "satisfies a bare non-empty check while leaving the defect intact: " + unverifiedFns(uv));
        assertEquals(List.of("app.noClass"), unjudgedFns(uv),
                "…as UNJUDGED, not as a pass: `app.nativeHole` beside it is a genuine PASS-but-Unknown hole "
                + "and must not be relabelled");
        assertFalse(uv.get("ok").getAsBoolean(),
                "`ok` is the claim, and it is bounded above by the gate's — which exited 2");
    }

    /** The reason recorded is the MISSING EVIDENCE, never the derived class. {@code app.noClass} would
     *  derive {@code unknown-host} (no recognised host ⇒ the fail-closed floor) — and {@code unknown-host}
     *  is precisely the class the policy names, so a verb that recorded the derivation would print a
     *  confident, correct-looking, and wholly invented match for a rule the gate declined to evaluate. */
    @Test
    void theReasonIsTheAbsentFieldAndNotTheClassItWouldHaveHeld() throws Exception {
        Path rep = r11Report();
        Path pol = policy("deny Net[unknown-host] app\n");
        JsonObject uv = json(rep, pol, "unverified");
        JsonObject row = null;
        for (var el : uv.getAsJsonArray("unverified"))
            if ("app.noClass".equals(el.getAsJsonObject().get("fn").getAsString())) row = el.getAsJsonObject();
        assertTrue(row != null && row.has("why"), "the withheld entry carries a reason");
        String why = row.get("why").getAsString();
        assertTrue(why.contains("`netClass`"), "…and it NAMES THE ABSENT FIELD: " + why);
        assertTrue(why.contains("WITHHELD"), "…and says the rule was withheld, not passed: " + why);
        assertEquals("deny Net[unknown-host] app", row.get("rule").getAsString(),
                "the rule is quoted VERBATIM, filter and all — a reconstruction here would attribute the "
                + "refusal to a rule nobody wrote");
        assertEquals("deny Net app", row.get("upgrade").getAsString(),
                "the only edit that turns a refusal into a verdict without inventing the missing datum — "
                + "the gate's own refusal already recommends it");
    }

    /** SPEC §3.2: both verbs carry {@code unevaluated: [{rule, why}]}, the GATE'S OWN SHAPE. Inventing a
     *  second spelling is the mistake that document has made four times, so this asserts the shape rather
     *  than merely the presence — the same two keys {@link Candor#unevaluatedJson} writes for the gate. */
    @Test
    void bothVerbsCarryTheGatesUnevaluatedShape() throws Exception {
        Path rep = r11Report();
        Path pol = policy("deny Net[unknown-host] app\n");
        for (String verb : List.of("unverified", "fix-gate")) {
            JsonObject o = json(rep, pol, verb);
            assertTrue(o.has("unevaluated"), verb + " carries the disclosure");
            JsonObject row = o.getAsJsonArray("unevaluated").get(0).getAsJsonObject();
            assertEquals(List.of("rule", "why"), new ArrayList<>(row.keySet()),
                    verb + ": the gate's shape, not a second spelling of it");
            assertEquals("deny Net[unknown-host] app", row.get("rule").getAsString(),
                    verb + ": one row per RULE, the raw policy line verbatim");
        }
    }

    /** {@code --strict} exits 2, matching the gate — 1 is "there are crossings you can go and fix", and a
     *  refusal is not one of those. The non-strict contract is untouched: these verbs are advisory. */
    @Test
    void strictExitsTwoWhereTheGateRefuses() throws Exception {
        Path rep = r11Report();
        Path pol = policy("deny Net[unknown-host] app\n");
        assertEquals(2, exitOf(rep, pol, "gate"));
        for (String verb : List.of("unverified", "fix-gate")) {
            assertEquals(2, exitOf(rep, pol, verb, "--strict"), verb + " --strict follows the gate");
            assertEquals(0, exitOf(rep, pol, verb), verb + " without --strict stays advisory");
        }
    }

    // ── 2. THE HARDER HALF: fix-gate's remedy, and the verb that said nothing at all ────────────────────

    /**
     * The mechanism, stated so it cannot be re-introduced: {@link Policy#reasonClassesOf} floors an absent
     * class set to {@code unresolved}. That floor is RIGHT for the gate — it is fail-closed, and the gate
     * then refuses — and it is a fabricated premise for a REMEDY, because
     * {@link Policy#classNarrowingFires} returns the same {@code true} whether the class was read or
     * defaulted. So {@code deny Unknown[unresolved]} produced a hoist plan for a boundary the gate exits 2
     * over, and {@code --strict} turned it into a red CI check.
     */
    @Test
    void fixGateOffersNoRemedyPremisedOnEvidenceTheGateRefusedToRead() throws Exception {
        Path rep = inheritedReasonlessReport();
        Path pol = policy("deny Unknown[unresolved] app\n");

        assertEquals(2, exitOf(rep, pol, "gate"), "the gate cannot judge `app.inherits`");
        assertEquals(List.of(), remedyFns(json(rep, pol, "fix-gate")),
                "no hoist plan for a boundary the gate REFUSED to adjudicate");
        assertEquals(2, exitOf(rep, pol, "fix-gate", "--strict"),
                "…and --strict follows the gate's 2, not the 1 it used to invent");

        // …and the single-function verb takes the same predicate. "nothing to fix" and "the gate could not
        // tell" are different sentences; only one of them was ever true here.
        String out = stderrOf(rep, pol, "fix", "app.inherits", "Unknown");
        assertTrue(out.contains("could NOT evaluate"), "`fix` discloses rather than clearing: " + out);
        assertEquals(2, exitOf(rep, pol, "fix", "app.inherits", "Unknown"));
    }

    /** The starkest form: {@code unverified} returned {@code ok:true} with an EMPTY list while the gate
     *  refused. Not a misattribution — a total silence, from the verb whose entire job is to say
     *  "your green gate is not provably green". */
    @Test
    void unverifiedIsNotSilentWhereTheGateRefuses() throws Exception {
        Path rep = inheritedReasonlessReport();
        Path pol = policy("deny Unknown[unresolved] app\n");

        assertEquals(2, exitOf(rep, pol, "gate"));
        JsonObject uv = json(rep, pol, "unverified");
        assertEquals(List.of("app.inherits"), unjudgedFns(uv), "the one function the gate could not judge");
        assertFalse(uv.get("ok").getAsBoolean());
        assertEquals(2, exitOf(rep, pol, "unverified", "--strict"));

        // THE PROSE CHANNEL CARRIES THE SAME DISCLOSURE. A qualifier that exists only under `--json` leaves
        // the human reading the identical all-clear, which is the channel consulted more.
        String text = stderrOf(rep, pol, "unverified");
        assertTrue(text.contains("could NOT evaluate") && text.contains("app.inherits"),
                "the human channel says it too: " + text);
    }

    // ── 3. THE MIRROR — a function the gate CAN clear must not start being named ───────────────────────

    /**
     * <b>The over-report is the failure mode this repair could plausibly introduce</b>, so it is asserted
     * before the repair is believed: with {@code netClass} PRESENT the rule is answerable, the gate reaches
     * a verdict, and nothing here is UNJUDGED. Every existing channel keeps its exact contents — the hole
     * stays a hole, the remedy stays a remedy, the exits stay 0/1.
     */
    @Test
    void nothingNewIsNamedWhereTheGateCanJudge() throws Exception {
        Path rep = netClassPresentReport();

        // (a) the rule FIRES: `unknown-host` is squarely inside the filter.
        Path bites = policy("deny Net[unknown-host] app\n");
        assertEquals(1, exitOf(rep, bites, "gate"), "answerable, and it bites");
        JsonObject uv = json(rep, bites, "unverified");
        assertEquals(List.of(), unjudgedFns(uv), "nothing is UNJUDGED when the gate reached a verdict");
        assertFalse(uv.has("unevaluated"), "and no rule went unevaluated");
        assertEquals(List.of("app.noClass"), remedyFns(json(rep, bites, "fix-gate")),
                "the remedy is still computed — this moves what is DISCLOSED, never what is decided");
        assertEquals(1, exitOf(rep, bites, "fix-gate", "--strict"), "…and --strict is still the crossing's 1");

        // (b) the rule DOES NOT fire: a class the report answers and the filter excludes. `app.noClass` is
        //     tolerated and must NOT be named — "the filter says a different class" is a verdict, and a
        //     verdict is exactly what this change must not touch.
        Path misses = policy("deny Net[known-telemetry] app\n");
        assertEquals(0, exitOf(rep, misses, "gate"), "answerable, and it does not fire");
        JsonObject uv2 = json(rep, misses, "unverified");
        assertEquals(List.of(), unjudgedFns(uv2), "a tolerated function is judged, not withheld");
        assertEquals(List.of("app.nativeHole"), unverifiedFns(uv2),
                "only the genuine PASS-but-Unknown hole, exactly as before");
    }

    // ── 4. THE PARTITION — the property both mechanisms are instances of ───────────────────────────────

    /**
     * <b>EVERY IN-SCOPE FUNCTION CARRYING AN EFFECT THE RULE NAMES IS A GATE VIOLATION, AN UNVERIFIED PASS,
     * OR UNJUDGED. Never none.</b> This is {@code NarrowedRuleAdvisoryVerbTest}'s two-channel partition with
     * the third channel the law requires: a function the gate could not judge belongs to no other channel
     * by construction, so before this change it belonged to none at all.
     *
     * <p>MEASURED at scale on an EXTERNAL corpus, {@code aws-java-sdk-s3-1.12.395} scanned by this engine
     * (2157 entries; 696 {@code Net}-bearing of which 689 carry {@code hosts}; 821 {@code Unknown}-bearing),
     * then re-served with one channel dropped — the state §3.1 says a scan cannot reach and a foreign or
     * pre-rung producer writes routinely. A/B against a jar built from the previous commit:
     *
     * <pre>
     *   population = in-scope functions carrying an effect the rule names
     *
     *   netClass PRESENT   deny Net[unknown-host]     VIOL  PASS  UNJUDGED   SUM/696   IN NO CHANNEL
     *     PRE                                          696     0         0       696               0
     *     POST                                         696     0         0       696               0   ← the mirror
     *   netClass STRIPPED  deny Net[unknown-host]
     *     PRE                                            0   686         0       686              10
     *     POST                                           0     0       696       696               0
     *   netClass STRIPPED  deny Net  (answerable control)
     *     PRE / POST                                   696     0         0       696               0   ← unmoved
     *
     *   reason PRESENT     deny Unknown[dispatch,unresolved]                   SUM/821
     *     PRE / POST                                   693   128         0       821               0   ← the mirror
     *   reason STRIPPED    deny Unknown[dispatch,unresolved]
     *     PRE                                            0     0         0         0             821
     *     POST                                           0     0       821       821               0
     *   reason STRIPPED    deny Unknown  (answerable control)
     *     PRE / POST                                   821     0         0       821               0   ← unmoved
     * </pre>
     *
     * <p>Three things the table says that the fixtures cannot. <b>The 686 PRE "unverified passes" were not
     * a silence but a MISATTRIBUTION</b> — filed as passing a rule that was never evaluated. <b>The 821-row
     * is the defect with nothing left to hide behind</b>: a whole corpus in no channel at all. And the
     * unnarrowed CONTROLS do not move on either axis, over the same stripped bytes — so what moved is the
     * NARROWING, not the stripping, and the gate verdict is byte-identical in every row of both halves.
     *
     * <p>The in-repo form below is the same property over the two fixtures, which is what a test can carry.
     */
    @Test
    void thePartitionAccountsForEveryFunctionTheRuleReaches() throws Exception {
        record Case(String label, Path rep, String rule, List<String> population) {}
        List<Case> cases = List.of(
                new Case("Net, channel absent", r11Report(), "deny Net[unknown-host] app",
                        List.of("app.noClass")),
                new Case("Net, channel present", netClassPresentReport(), "deny Net[unknown-host] app",
                        List.of("app.noClass")),
                new Case("Net, answerable control", r11Report(), "deny Net app",
                        List.of("app.noClass")),
                new Case("Unknown, channel absent", inheritedReasonlessReport(),
                        "deny Unknown[unresolved] app", List.of("app.inherits")),
                new Case("Unknown, answerable control", inheritedReasonlessReport(),
                        "deny Unknown app", List.of("app.inherits")));
        for (Case c : cases) {
            Path pol = policy(c.rule() + "\n");
            Candor.gateViolations.clear();
            Candor.gateCapture = true;
            List<String> caught = new ArrayList<>();
            try {
                exitOf(c.rep(), pol, "gate");
                for (var v : Candor.gateViolations) caught.add(String.valueOf(v.get("fn")));
            } finally {
                Candor.gateCapture = false;
                Candor.gateViolations.clear();
            }
            List<String> named = unverifiedFns(json(c.rep(), pol, "unverified"));
            for (String fn : c.population())
                assertTrue(caught.contains(fn) || named.contains(fn),
                        c.label() + " / `" + c.rule() + "`: `" + fn + "` is in NO channel — a gate that "
                        + "did not charge it and a verb that did not name it is the set nothing said "
                        + "anything about (violations=" + caught + ", named=" + named + ")");
        }
    }

    // ── 5. THE RULE KIND the gate refuses WHOLESALE — the same law one granularity up ──────────────────

    /** {@code gate --report} refuses every {@code allow} rule (the AS-EFF-008 completeness marker does not
     *  ride the wire) and every {@code forbid} rule (a report's {@code calls} is effect-relevant). An
     *  advisory verb that answered over such a policy with a clean bill would be more confident than the
     *  gate over identical bytes — the identical comparison, with no function to name. It carries the rows
     *  and declines the claim; the rows are the GATE'S, from one producer. */
    @Test
    void aRuleKindTheGateRefusesWholesaleAlsoBoundsTheVerbs() throws Exception {
        Path rep = netClassPresentReport();            // answerable; the refusal is the rule KIND, not the report
        Path pol = policy("allow Net app api.example.com\n");
        assertEquals(2, exitOf(rep, pol, "gate"), "`allow` is refused by `gate --report`");
        for (String verb : List.of("unverified", "fix-gate")) {
            JsonObject o = json(rep, pol, verb);
            assertFalse(o.get("ok").getAsBoolean(), verb + " cannot report a clean bill over a refused rule");
            assertTrue(o.has("unevaluated"), verb + " names the rule the gate could not evaluate");
            assertEquals("allow Net app api.example.com",
                    o.getAsJsonArray("unevaluated").get(0).getAsJsonObject().get("rule").getAsString());
            assertEquals(2, exitOf(rep, pol, verb, "--strict"), verb + " --strict follows the gate");
        }
    }

    /** THE MIXED RUN, which is where the two output channels can disagree with each other rather than with
     *  the gate: a policy carrying BOTH a rule that yields an ordinary hole (exit 1's cause) and a rule the
     *  gate refuses (exit 2's cause). The refusal wins in both — a rule that was never evaluated is not a
     *  crossing anyone can go and fix — and, just as load-bearing, {@code --json} and the prose path must
     *  return the SAME code over identical input. */
    @Test
    void aHoleBesideARefusedRuleExitsTwoInBothChannels() throws Exception {
        Path rep = netClassPresentReport();
        Path pol = policy("deny Unknown[reflect] app\nallow Net app api.example.com\n");
        assertEquals(2, exitOf(rep, pol, "gate"));
        for (String verb : List.of("unverified", "fix-gate")) {
            JsonObject o = json(rep, pol, verb);
            assertTrue(o.has("unevaluated"), verb + ": the `allow` rule is named");
            assertEquals(2, exitOf(rep, pol, verb, "--strict", "--json"), verb + " --strict --json");
            assertEquals(2, exitOf(rep, pol, verb, "--strict"), verb + " --strict, prose channel");
        }
        // the hole is still there and still named — the refusal did not delete the finding beside it,
        // which is the precedence harm one level down (see Policy#gate).
        assertEquals(List.of("app.nativeHole"),
                unverifiedFns(json(rep, pol, "unverified")), "the native-class hole survives the refusal");
    }
}
