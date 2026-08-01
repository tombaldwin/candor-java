package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
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
import java.util.TreeSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.24⟩ <b>A NARROWED RULE IS A NARROWER RULE FOR EVERY VERB THAT READS IT</b> — SPEC §6.2, "THE GATE AND
 * THE DISCLOSURE MUST APPLY THE SAME RULE, AND SHOULD SHARE THE SAME CODE".
 *
 * <p>{@code deny E Unknown[c…]} and {@code deny Net[dest…]} carry a CLASS FILTER. {@link Policy#gate} has
 * always honoured it. The two advisory verbs beside the gate computed from the EFFECT SET ALONE, so over a
 * report whose only hole is {@code native:} under {@code deny Unknown[reflect,unresolved] app} — a layer the
 * gate PASSES — this engine measured, before the fix:
 *
 * <pre>
 *   gate --report        exit 0                        correct — the class is excluded
 *   fix-gate --strict    exit 1 + a remedy naming it   OVER-CHARGE: a red CI check and a hoist
 *                                                      instruction for a boundary nothing denies
 *   unverified --strict  exit 0, ok:true               UNDER-REPORT, and the worse half
 * </pre>
 *
 * <p><b>The under-report is the half that matters.</b> The layer PASSES while carrying an {@code Unknown},
 * so it is exactly a PASS-but-Unknown hole — and {@code unverified}, the verb whose entire job is "your
 * green gate is not provably green", certified it clean. It did so because its hole predicate asked
 * {@code inferred ∩ rule.effects() ≠ ∅} and stopped: the rule NAMES {@code Unknown}, the function HAS
 * {@code Unknown}, so it read as a violation the gate would catch — and the gate, applying the filter, did
 * not catch it. Nobody reported it.
 *
 * <p><b>Both halves are one defect and are fixed in one change</b> (see
 * {@code feedback-fabrication-fixes-cause-misses}: killing an over-charge is exactly where a silent
 * under-report gets introduced). The MIRRORS ride here beside the defect rows — a filter can only ever
 * NARROW what a verb reports, so what has to be guarded is LOST DISCLOSURE: every row below whose policy
 * classes DO match the hole asserts the finding is still named, with the same words.
 */
class NarrowedRuleAdvisoryVerbTest {

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

    // ── the fixture: ONE hole, and its reason class is `native` ────────────────────────────────────────

    /** One report entry. {@code why} is the raw {@code unknownWhy} channel — the reason class travels over
     *  {@code calls}, so {@code app.Svc.load} inherits `native` from the leaf without naming one itself. */
    private static Map<String, Object> entry(String fn, List<String> inferred, List<String> direct,
                                             List<String> why, List<String> calls,
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
        if (!why.isEmpty()) m.put("unknownWhy", why);
        m.put("hash", "");
        if (!calls.isEmpty()) m.put("calls", calls);
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

    /** The measured shape: a JNI leaf whose ONLY {@code unknownWhy} is `native:dlopen`, and one caller that
     *  inherits the {@code Unknown} without naming a reason of its own. */
    private Path nativeHoleReport() throws Exception {
        return report("native.jvm.json", List.of(
                entry("app.Svc.dlopen", List.of("Unknown"), List.of("Unknown"),
                        List.of("native:dlopen"), List.of(), null),
                entry("app.Svc.load", List.of("Unknown"), List.of(),
                        List.of(), List.of("app.Svc.dlopen"), null)));
    }

    private Path policy(String body) throws Exception {
        Path p = tmp.resolve("p" + Math.abs(body.hashCode()) + ".policy");
        Files.writeString(p, body);
        return p;
    }

    // ── the three verbs, driven through the CLI dispatcher so the flag grammar is under test too ───────

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

    /** The `fn` names an `unverified` run disclosed. */
    private static List<String> unverifiedFns(JsonObject o) {
        List<String> out = new ArrayList<>();
        for (var el : o.getAsJsonArray("unverified")) out.add(el.getAsJsonObject().get("fn").getAsString());
        return out;
    }

    /** The functions a `fix-gate` run computed a remedy for. */
    private static List<String> remedyFns(JsonObject o) {
        List<String> out = new ArrayList<>();
        for (var el : o.getAsJsonArray("remedies")) out.add(el.getAsJsonObject().get("fn").getAsString());
        return out;
    }

    // ── 1. THE UNDER-REPORT — the half that matters ────────────────────────────────────────────────────

    /**
     * The layer PASSES the gate while carrying an {@code Unknown} the rule's filter excluded. That IS a
     * provable-purity hole — the `native` {@code Unknown} could hide the very effect a wider rule would
     * forbid, and no rule in this policy proved otherwise — so {@code unverified} must NAME it.
     *
     * <p>Both entries are named: §6.2 resolves the class set TRANSITIVELY, so {@code app.Svc.load}'s
     * inherited hole is `native` too, and an inherited hole is still a hole the gate did not prove.
     */
    @Test
    void unverifiedNamesTheHoleANarrowedRuleLetPass() throws Exception {
        Path rep = nativeHoleReport();
        Path pol = policy("deny Unknown[reflect,unresolved] app\n");

        // CONTROL — the gate is right, and the disclosure exists to explain THIS pass.
        assertEquals(0, exitOf(rep, pol, "gate"),
                "the gate is correct: `native` is outside [reflect,unresolved], so nothing is denied");

        JsonObject o = json(rep, pol, "unverified");
        assertFalse(o.get("ok").getAsBoolean(),
                "a layer that PASSES while carrying an Unknown is not provably clean — `ok: true` here is "
                + "the verb that exists to say 'your green gate is not provably green' certifying it");
        assertEquals(List.of("app.Svc.dlopen", "app.Svc.load"), unverifiedFns(o),
                "the direct hole AND the caller that inherits it — §6.2 resolves the class set transitively");
        assertEquals(1, exitOf(rep, pol, "unverified", "--strict"),
                "--strict is how CI consumes it, so the exit has to move too");
    }

    /**
     * THE DISCLOSURE MUST QUOTE THE RULE THE OPERATOR WROTE, filter included, and name an upgrade that
     * would actually close THIS hole. Reconstructing the rule from its effect set alone printed
     * {@code deny Unknown app} for {@code deny Unknown[reflect,unresolved] app} — misattributing the pass to
     * a rule nobody wrote, and one that would not have passed — and appending {@code Unknown} to a rule that
     * already names it produced {@code deny Unknown[reflect,unresolved] Unknown app}, which is not a policy.
     * The upgrade for an already-narrowed rule is to WIDEN THE FILTER to the class that got through.
     */
    @Test
    void theQuotedRuleKeepsItsFilterAndTheUpgradeWidensIt() throws Exception {
        Path rep = nativeHoleReport();
        Path pol = policy("deny Unknown[reflect,unresolved] app\n");
        JsonObject h = json(rep, pol, "unverified").getAsJsonArray("unverified")
                .get(0).getAsJsonObject();

        assertEquals("deny Unknown[reflect,unresolved] app", h.get("rule").getAsString(),
                "the rule is quoted as written — stripping the filter attributes the pass to a rule the "
                + "operator did not write, and to one that would not have passed");
        assertEquals("deny Unknown[native,reflect,unresolved] app", h.get("upgrade").getAsString(),
                "the upgrade WIDENS the existing filter by the hole's own class; appending a second bare "
                + "`Unknown` to a rule that already names it is not a policy");
    }

    // ── 2. THE OVER-CHARGE ─────────────────────────────────────────────────────────────────────────────

    /**
     * {@code fix-gate} computes the hoist refactor for a boundary crossing. There is no crossing here — the
     * gate says so — so a remedy is an instruction to restructure code around a boundary the policy does not
     * draw, and {@code --strict} turns it into a red CI check beside a green gate.
     */
    @Test
    void fixGateComputesNoRemedyForAClassTheRuleDoesNotDeny() throws Exception {
        Path rep = nativeHoleReport();
        Path pol = policy("deny Unknown[reflect,unresolved] app\n");

        JsonObject o = json(rep, pol, "fix-gate");
        assertTrue(o.get("ok").getAsBoolean(), "no crossing -> ok");
        assertEquals(List.of(), remedyFns(o),
                "a hoist instruction for a boundary the policy does not deny is a fabricated refactor");
        assertEquals(0, exitOf(rep, pol, "fix-gate", "--strict"),
                "…and --strict must not fail CI red beside a gate that is green");
    }

    /** {@code fix <fn> <Effect>} shares the same denied-layer predicate, so it moves with it. */
    @Test
    void fixSaysTheBoundaryIsNotCrossed() throws Exception {
        Path rep = nativeHoleReport();
        Path pol = policy("deny Unknown[reflect,unresolved] app\n");
        PrintStream o = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buf));
        int rc;
        try {
            rc = cli("fix", "app.Svc.dlopen", "Unknown", "--report", rep.toString(),
                    "--policy", pol.toString());
        } finally {
            System.setOut(o);
        }
        assertEquals(0, rc);
        assertTrue(buf.toString().contains("no policy forbids it there"),
                "the narrowed rule does not forbid a `native` Unknown here: " + buf);
    }

    // ── 3. THE MIRROR — a filter can only NARROW, so guard the LOST DISCLOSURE ─────────────────────────

    /**
     * THE MIRROR, and the row this whole change is written to not break. Same report, same verbs; the ONLY
     * difference is that the policy's classes DO cover the hole. Every finding must still be named, in both
     * verbs, with the gate red beneath them — otherwise the fix for the over-charge has bought its silence
     * with a real disclosure.
     */
    @Test
    void aRuleWhoseClassesCoverTheHoleStillFiresEverywhere() throws Exception {
        Path rep = nativeHoleReport();
        for (String body : List.of("deny Unknown[native,unresolved] app\n",   // names the class
                                   "deny Unknown[dynamic] app\n",             // the alias that includes it
                                   "deny Unknown[*] app\n",                   // explicit all-classes
                                   "deny Unknown app\n")) {                   // the bare, unfiltered form
            Path pol = policy(body);
            assertEquals(1, exitOf(rep, pol, "gate"), "the gate FIRES under: " + body.trim());

            JsonObject fg = json(rep, pol, "fix-gate");
            assertFalse(fg.get("ok").getAsBoolean(), "fix-gate still has a crossing under: " + body.trim());
            assertEquals(List.of("app.Svc.dlopen"), remedyFns(fg),
                    "…and still names the hoist for it under: " + body.trim());
            assertEquals(1, exitOf(rep, pol, "fix-gate", "--strict"),
                    "…and --strict still exits 1 under: " + body.trim());

            // `unverified` is the complement, not the same list: a function the gate CATCHES is a real
            // violation, not an unverified PASS. Its silence here is the definition of the verb, and the
            // row above is what proves the silence is not the bug this test class exists about.
            JsonObject uv = json(rep, pol, "unverified");
            assertTrue(uv.get("ok").getAsBoolean(),
                    "a caught violation is not an unverified pass under: " + body.trim());
        }
    }

    /**
     * The mirror for the rules that never had a filter: an unfiltered rule the fn does not violate must go
     * on producing exactly the disclosure it produced before, byte-for-byte.
     *
     * <p>The third row pins the ONE thing this change deliberately does NOT touch. {@code deny Net Db app}
     * is quoted back as {@code deny Db Net app} — the effect list is reconstructed in the canonical
     * {@code Effect} order, not in the order it was typed. That normalisation is pre-existing, it names the
     * same rule, and conformance PART 12c compares the {@code upgrade} across all four engines; a filter is
     * a different matter, because dropping one names a DIFFERENT rule. Fixing the misquote that changes
     * meaning and leaving the one that does not is the smaller change, and the smaller change is the one
     * whose blast radius is known.
     */
    @Test
    void anUnfilteredRuleDisclosesExactlyWhatItAlwaysDid() throws Exception {
        Path rep = nativeHoleReport();
        for (String[] row : List.of(new String[]{"pure app\n", "pure app", "deny Unknown app"},
                                    new String[]{"deny Net app\n", "deny Net app", "deny Net Unknown app"},
                                    new String[]{"deny Net Db app\n", "deny Db Net app", "deny Db Net Unknown app"})) {
            Path pol = policy(row[0]);
            assertEquals(0, exitOf(rep, pol, "gate"), "no real effect to deny under: " + row[1]);
            JsonObject uv = json(rep, pol, "unverified");
            assertEquals(List.of("app.Svc.dlopen", "app.Svc.load"), unverifiedFns(uv),
                    "both holes still disclosed under: " + row[1]);
            JsonObject h = uv.getAsJsonArray("unverified").get(0).getAsJsonObject();
            assertEquals(row[1], h.get("rule").getAsString());
            assertEquals(row[2], h.get("upgrade").getAsString());
        }
    }

    // ── 4. THE SIBLING FILTER — `Net[dest…]` is the same defect under a different key ───────────────────

    /** {@code app.Wire.post} reaches ONLY a known-telemetry destination, and is Unknown besides. */
    private Path telemetryReport(String netClass) throws Exception {
        return report("net" + netClass + ".jvm.json", List.of(
                entry("app.Wire.post", List.of("Net", "Unknown"), List.of("Net", "Unknown"),
                        List.of("native:post"), List.of(),
                        Map.of("netClass", List.of(netClass)))));
    }

    /**
     * {@code deny Net[unknown-host] app} over a function whose {@code Net} reaches a known-telemetry host:
     * the gate tolerates it, so {@code fix-gate} must compute nothing — and {@code unverified} must name it,
     * because the function passes that rule WHILE carrying an {@code Unknown} that could hide a Net to
     * somewhere else entirely. Same defect, different key; fixing one key and not the other leaves the
     * identical hole under {@code Net[…]}.
     *
     * <p><b>⟨0.24⟩ RE-MEASURED INDEPENDENTLY AT SCALE, AND THE RESULT IS NULL — this axis is closed.</b>
     * candor-swift reported the {@code Net} half as a live defect in its own engine and asked whether java
     * carried it, on the argument that a destination class cannot be derived from the fields the hole and
     * remedy records carry (it needs the host surface plus the partner set) and is therefore a data-threading
     * job rather than a conjunct. That argument is correct in general and was already discharged here: the
     * hoist took {@link Policy.GateInput} — which carries {@code netClasses()} — rather than an effect set,
     * so threading it into {@link Policy#unverifiedHoleRule} and {@code Query#deniedLayer} covered BOTH axes
     * at once, and all three call sites loop over {@code {UNKNOWN, NET}}.
     *
     * <p>Measured rather than read, on a 2395-function scan of {@code httpclient5-5.6.1} (393 {@code Net}-
     * bearing functions, 389 {@code Unknown}-bearing in scope), A/B against a jar built from the commit
     * BEFORE the hoist — so the instrument is shown able to fail before its null result is believed:
     *
     * <pre>
     *   rule                       PRE-HOIST                     HEAD
     *   deny Net[known-telemetry]  gate   0 + unverified 114 ✗   gate   0 + unverified 389 ✓
     *   deny Net[known-partner]    gate   0 + unverified 114 ✗   gate   0 + unverified 389 ✓
     *   deny Net[unknown-host]     gate 393 + unverified 114 ✓   gate 393 + unverified 114 ✓
     *   deny Net                   gate 393 + unverified 114 ✓   gate 393 + unverified 114 ✓
     * </pre>
     *
     * The two narrowed rows are the defect at scale and the shape swift described: a wholly green gate over
     * 275 unproven {@code Net}-carrying {@code Unknown}s that nothing named. They partition on HEAD and did
     * not before. <b>The gate verdict is byte-identical in every row</b> (0/0, 0/0, 393/393, 393/393), and
     * the two unfiltered/covering rows do not move at all — the mirror, at scale.
     */
    @Test
    void theNetDestinationFilterMovesWithTheReasonFilter() throws Exception {
        Path pol = policy("deny Net[unknown-host] app\n");

        Path ok = telemetryReport("known-telemetry");
        assertEquals(0, exitOf(ok, pol, "gate"), "known-telemetry is outside [unknown-host]");
        assertEquals(List.of(), remedyFns(json(ok, pol, "fix-gate")),
                "no crossing -> no hoist instruction");
        assertEquals(0, exitOf(ok, pol, "fix-gate", "--strict"));
        JsonObject uv = json(ok, pol, "unverified");
        assertEquals(List.of("app.Wire.post"), unverifiedFns(uv),
                "it PASSES `deny Net[unknown-host]` while Unknown — an unverified pass, which is the hole");
        assertEquals("deny Net[unknown-host] app", uv.getAsJsonArray("unverified").get(0)
                .getAsJsonObject().get("rule").getAsString(),
                "the destination filter is quoted too — `deny Net app` is a rule nobody wrote");

        // THE MIRROR — the same rule over a function that DOES reach the denied destination class.
        Path bad = telemetryReport("unknown-host");
        assertEquals(1, exitOf(bad, pol, "gate"), "unknown-host is squarely inside [unknown-host]");
        assertEquals(List.of("app.Wire.post"), remedyFns(json(bad, pol, "fix-gate")),
                "…and the remedy is still computed for it");
        assertEquals(1, exitOf(bad, pol, "fix-gate", "--strict"));
    }

    // ── 5. THE PARTITION — the property both halves are instances of ───────────────────────────────────

    /**
     * <b>EVERY {@code Unknown}-BEARING FUNCTION IN A RULE'S SCOPE IS EITHER A GATE VIOLATION OR AN
     * UNVERIFIED PASS. Never neither.</b> With one rule in scope those two channels partition the set by
     * construction — the function violates the rule or it does not, and if it does not it is an
     * {@code Unknown} the rule passed — so a row where they sum to LESS than the whole is exactly a set of
     * functions nothing said anything about.
     *
     * <p>This is the property the individual rows above are instances of, and it is what the defect looked
     * like at scale. MEASURED on candor-java's own 407-function report (72 {@code Unknown}-bearing
     * functions), before → after:
     *
     * <pre>
     *   deny Unknown[reflect,unresolved]    gate 44 + unverified  0 = 44   →  44 + 28 = 72
     *   deny Unknown[indirect,unresolved]   gate 34 + unverified  0 = 34   →  34 + 38 = 72
     *   deny Unknown[dispatch,unresolved]   gate  0 + unverified  0 =  0   →   0 + 72 = 72
     * </pre>
     *
     * The last row is the whole defect in one line: a completely green gate over 72 unproven
     * {@code Unknown}s, and not one word about any of them from the verb that exists to say so. The gate
     * counts are BYTE-IDENTICAL across the change — this fix moves what is DISCLOSED, never a verdict.
     */
    @Test
    void theTwoChannelsPartitionTheUnknownBearingFunctions() throws Exception {
        Path rep = nativeHoleReport();
        for (String body : List.of("deny Unknown app\n", "deny Unknown[dynamic] app\n",
                                   "deny Unknown[native,unresolved] app\n",
                                   "deny Unknown[reflect,unresolved] app\n",
                                   "deny Unknown[dispatch] app\n",
                                   "deny Unknown[setup] app\n")) {
            Path pol = policy(body);
            Candor.gateViolations.clear();
            Candor.gateCapture = true;
            int caught;
            try {
                exitOf(rep, pol, "gate");
                caught = Candor.gateViolations.size();
            } finally {
                Candor.gateCapture = false;
                Candor.gateViolations.clear();
            }
            int disclosed = unverifiedFns(json(rep, pol, "unverified")).size();
            assertEquals(2, caught + disclosed,
                    "both Unknown-bearing functions must be accounted for by exactly one channel under `"
                    + body.trim() + "` — a sum below the whole is the set nothing said anything about "
                    + "(caught=" + caught + ", disclosed=" + disclosed + ")");
        }
    }

    // ── 6. THE GATE'S OWN AUTO-DISCLOSURE takes the same rule ──────────────────────────────────────────

    /**
     * A {@code --policy} run prints the provable-purity holes on stderr from the SAME predicate
     * ({@link Policy#unverifiedHoleRule}) — conformance PART 12d pins the two to agree. So the scan-side
     * note has to move with the query, or the engine would say one thing in the gate's own output and the
     * opposite in the verb the gate's output tells you to run.
     */
    @Test
    void theGateNoteAgreesWithTheVerbBesideIt() throws Exception {
        Path rep = nativeHoleReport();
        Path pol = policy("deny Unknown[reflect,unresolved] app\n");
        PrintStream e = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setErr(new PrintStream(buf));
        try {
            cli("gate", "--report", rep.toString(), "--policy", pol.toString());
        } finally {
            System.setErr(e);
        }
        String note = buf.toString();
        assertTrue(note.contains("PASS the policy but are Unknown"),
                "the gate's own auto-disclosure names the same holes the verb does: " + note);
        assertTrue(note.contains("deny Unknown[native,reflect,unresolved] app"),
                "…and the same upgrade, so the two channels cannot contradict each other: " + note);
        for (String fn : new TreeSet<>(List.of("app.Svc.dlopen", "app.Svc.load")))
            assertTrue(note.contains(fn), "…for " + fn + ": " + note);
    }
}
