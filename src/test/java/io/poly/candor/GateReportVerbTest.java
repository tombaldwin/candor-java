package io.poly.candor;

import static io.poly.candor.TestCompiler.compile;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.poly.candor.model.EffectSet;
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
 * ⟨0.24⟩ {@code gate --report <locator> --policy <file>} (SPEC §3.1) — apply a policy to an EXISTING
 * report, with no scan.
 *
 * <p>Three properties, in the order that matters:
 *
 * <p><b>1. THE MUST NOT.</b> "An engine MUST NOT re-derive, widen, or re-classify anything while serving
 * this verb … a report entry that is ABSENT is absent — the ⟨0.21⟩ purity claim — and MUST NOT be
 * back-filled from a callgraph sidecar or a chained dep." {@link #absentEntryIsPureEvenBesideASidecarAndAChainedDep}
 * builds exactly that trap — an absent entry, a {@code .callgraph.json} that names it, a chained dep
 * report that would give it {@code Net}, and a {@code .candor/config} pointing at that dep — and asserts
 * the verdict reads it as pure. The POSITIVE CONTROL beside it is what makes that mean anything: the same
 * policy over a report that DOES carry the effect must fail. Without both, the test only shows the verb
 * runs.
 *
 * <p><b>2. EQUIVALENCE with the scanning path.</b> For a program scanned normally, {@code scan --policy P}
 * and {@code gate --report <that report> --policy P} must produce the same verdict and the same exit code,
 * over passing AND failing policies. That is the property the ANSWERABILITY refusals (see
 * {@link Query#gate}) exist to keep true rather than approximately true.
 *
 * <p><b>3. AGREEMENT WITH THE REFERENCE MODEL.</b> {@code candor-spec/reference/policy_model.py} is the
 * executable transcription of PAPER3's Definitions 4/30/31/32. This verb is what finally lets an ENGINE be
 * checked against it: a report carrying an exact {@code (S, D)} in, a verdict out. The rows in
 * {@link #agreesWithTheReferenceModelOnDenyAndDenyUnknown} are the model's own worked examples plus the
 * ⟨0.24⟩ repair rows.
 */
class GateReportVerbTest {

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

    // ── report construction (hand-built, so a test states an EXACT (S, D)) ──────────────────────────────

    /** One report entry. {@code inferred} is candor's `S` (with `Unknown` carried as a member — the engine
     *  encoding of the model's `D ≠ ∅`); {@code why} is the raw `unknownWhy` tags, i.e. `D`. */
    private static Map<String, Object> entry(String fn, List<String> inferred, List<String> why,
                                             Map<String, Object> extra) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", fn);
        m.put("loc", "X.java:1");
        m.put("inferred", inferred);
        m.put("direct", inferred);
        m.put("declared", List.of());
        m.put("undeclared", List.of());
        m.put("overdeclared", List.of());
        m.put("entryPoint", false);
        m.put("unresolved", inferred.contains("Unknown"));
        if (!why.isEmpty()) m.put("unknownWhy", why);
        m.put("hash", "");
        if (extra != null) m.putAll(extra);
        return m;
    }

    private static Map<String, Object> entry(String fn, List<String> inferred) {
        return entry(fn, inferred, List.of(), null);
    }

    /** Write a §2 envelope report holding the given entries. */
    private Path report(String name, List<Map<String, Object>> entries) throws Exception {
        return report(name, entries, entries.size());
    }

    /** As above with an EXPLICIT ⟨0.21⟩ {@code analyzed.count}: a report omits its pure units (§2 rule 3),
     *  so the count is normally LARGER than the entry list, and a test about the count must be able to
     *  say so — the count is what reveals a report the verb never opened. */
    private Path report(String name, List<Map<String, Object>> entries, int analyzedCount) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", analyzedCount, "digest", "0"));
        env.put("functions", entries);
        Path p = tmp.resolve(name);
        Files.createDirectories(p.getParent() == null ? tmp : p.getParent());
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    private Path policy(String body) throws Exception {
        Path p = tmp.resolve("p" + Math.abs(body.hashCode()) + ".policy");
        Files.writeString(p, body);
        return p;
    }

    /** Run the verb the way a user does — through the CLI dispatcher, so the flag grammar is under test
     *  too. Returns the exit code. */
    private static int gate(Path report, Path policy, String... more) {
        List<String> a = new ArrayList<>(List.of("gate", "--report", report.toString(),
                "--policy", policy.toString()));
        a.addAll(List.of(more));
        return Query.run(a.toArray(new String[0]));
    }

    // ── 1. THE MUST NOT ────────────────────────────────────────────────────────────────────────────────

    /**
     * THE LOAD-BEARING TEST. {@code app.Facade.load} is ABSENT from the report. Beside the report sit two
     * things that WOULD give it {@code Net} if the verb consulted them:
     * <ul>
     *   <li>a {@code .callgraph.json} sidecar with the edge {@code app.Facade.load → app.Wire.post}, and
     *       {@code app.Wire.post} is in the report WITH {@code Net} — so propagating over the sidecar
     *       hands {@code load} a {@code Net} the report does not claim;</li>
     *   <li>a chained dep report giving {@code app.Facade.load} {@code Net} outright, wired up through a
     *       {@code .candor/config} {@code deps} key in the directory the verb DOES open a config from
     *       (it reads that directory for {@code unknown-alias}) — so the bait is on the one path the code
     *       actually walks, not on a path it was never going to look at.</li>
     * </ul>
     * Under {@code deny Net app.Facade} the answer must be: no violation. An absent entry is the ⟨0.21⟩
     * purity claim, and this verb takes it as given.
     */
    @Test
    void absentEntryIsPureEvenBesideASidecarAndAChainedDep() throws Exception {
        Path rep = report("app.jvm.json", List.of(
                entry("app.Wire.post", List.of("Net"))));          // app.Facade.load is ABSENT

        // BAIT 1 — the §2.2 callgraph sidecar, naming the absent fn and edging it to the effectful one.
        Files.writeString(tmp.resolve("app.jvm.callgraph.json"), io.poly.candor.model.ReportJson.pretty(
                Map.of("app.Facade.load", List.of("app.Wire.post"), "app.Wire.post", List.of())));

        // BAIT 2 — a chained dep report that gives the absent fn Net outright, wired via .candor/config.
        Path dep = report("dep.jvm.json", List.of(entry("app.Facade.load", List.of("Net"))));
        Files.createDirectories(tmp.resolve(".candor"));
        Files.writeString(tmp.resolve(".candor/config"), "deps " + dep.getFileName() + "\n");

        Path pol = policy("deny Net app.Facade\n");
        assertEquals(0, gate(rep, pol),
                "an ABSENT report entry is PURE (⟨0.21⟩) — neither the callgraph sidecar nor the chained "
                + "dep may back-fill an effect for it (SPEC §3.1 ⟨0.24⟩ MUST NOT)");
        assertEquals(0, Candor.gateViolations.size(), "and no violation was recorded");

        // POSITIVE CONTROL. Same policy, same directory, same baits — the ONLY change is that the report
        // now CARRIES the effect. Without this the test above would pass on a verb that gates nothing.
        Path rep2 = report("carrying.jvm.json", List.of(
                entry("app.Wire.post", List.of("Net")),
                entry("app.Facade.load", List.of("Net"))));
        assertEquals(1, gate(rep2, pol),
                "the same policy over a report that DOES carry Net for that fn must FAIL — so the pass "
                + "above is a property of the input, not of a gate that never fires");
    }

    /** The sidecar is not consulted for TOPOLOGY either. Here {@code app.Facade.load} IS in the report but
     *  carries no effect; the sidecar edges it to the {@code Net} unit. A verb that walked the sidecar and
     *  propagated would flag it. (Effects on the wire are already transitive — §2 — so propagating at gate
     *  time is not a refinement, it is fabrication.) */
    @Test
    void anEffectlessEntryIsNotWidenedOverTheSidecarGraph() throws Exception {
        Path rep = report("t.jvm.json", List.of(
                entry("app.Facade.load", List.of()),
                entry("app.Wire.post", List.of("Net"))));
        Files.writeString(tmp.resolve("t.jvm.callgraph.json"), io.poly.candor.model.ReportJson.pretty(
                Map.of("app.Facade.load", List.of("app.Wire.post"))));
        assertEquals(0, gate(rep, policy("deny Net app.Facade\n")),
                "an entry whose `inferred` is empty stays empty — the wire's effect sets are already "
                + "transitive, so re-propagating them at gate time invents reach");
    }

    // ── 2. EQUIVALENCE with the scanning path ──────────────────────────────────────────────────────────

    /**
     * <b>EQUIVALENCE IS THE ACCEPTANCE TEST, AND IT IS BYTE-LEVEL.</b> SPEC §3.1: for any report a scan
     * produced, {@code gate --report <it> --policy P} MUST produce a {@code --gate-json} document
     * <b>byte-equal</b> to {@code scan --policy P}'s — "{@code analyzed.count}, {@code reasonClass},
     * {@code netClass} and the coverage advisory included". Anything less lets the two routes drift into
     * two gates.
     *
     * <p>⟨0.24⟩ <b>This test used to compare only the violation COUNT and the exit code</b>, which is the
     * weakest reading of a MUST that names specific fields — and this engine is the reference one, so
     * those fields were in fact pinned by the newer engines' suites rather than by java's. Every field of
     * both documents is now compared as bytes.
     *
     * <p>The comparison carries a <b>MUTATION CONTROL</b>: a byte comparison that can never fail proves
     * nothing, so one row is deliberately perturbed (a single field of the scan-side document rewritten)
     * and the comparator must report it. Without that, a bug in the comparator reads exactly like 12 green
     * rows.
     *
     * <p>The corpus is non-vacuous by assertion, not by hope: at least one policy must FAIL, and the
     * ⟨0.19⟩ {@code reasonClass} and ⟨0.20⟩ {@code netClass} fields — two of the four §3.1 names — must
     * actually appear in the compared bytes.
     */
    @Test
    void scanAndGateProduceByteEqualVerdictDocuments() throws Exception {
        Path cls = compile(Map.of("app/Svc.java", String.join("\n",
                "package app;",
                "import java.net.*;",
                "public class Svc {",
                "  public void fetch() throws Exception { new URL(\"https://api.stripe.com/v1\").openStream().close(); }",
                "  public void relay() throws Exception { fetch(); }",
                "  public void telem() throws Exception { new URL(\"https://sentry.io/e\").openStream().close(); }",
                "  public void log() { System.out.println(\"x\"); }",
                "  public void dyn(Object o) throws Exception { o.getClass().getMethod(\"run\").invoke(o); }",
                "}")));
        List<String> policies = List.of(
                "deny Net app\n",                    // fails
                "deny Exec app\n",                   // passes (nothing execs)
                "pure app.Svc\n",                    // fails
                "pure app.Nothing\n",                // passes (scope matches nothing)
                "deny Net Unknown app\n",            // fails on both arms
                "deny Unknown[reflect,unresolved] app\n",   // reason-scoped — carries reasonClass
                "deny Unknown[native,unresolved] app\n",    // reason-scoped, other class
                "deny Net[known-telemetry] app\n",   // ⟨0.20⟩ destination class — carries netClass
                "deny Net[known-partner] app\n",
                "deny Net[unknown-host] app\n",
                "deny Fs app\ndeny Db app\n",
                "deny Log app\npure app.Svc.dyn\n");
        List<String> diffs = new ArrayList<>();
        int fired = 0;
        boolean sawReasonClass = false, sawNetClass = false;
        try {
            for (String body : policies) {
                String tag = "eq" + Math.abs(body.hashCode());
                Path rep = tmp.resolve(tag + ".jvm.json");
                Path pol = policy(body);
                Path a = tmp.resolve(tag + ".scan.verdict.json");     // scan --policy's document
                Path b = tmp.resolve(tag + ".gate.verdict.json");     // gate --report's document
                // DELETE the outputs before measuring — a stale artefact is a flattering datapoint.
                Files.deleteIfExists(a);
                Files.deleteIfExists(b);

                // ── the SCAN route, writing its verdict exactly as Candor.main does ──
                Candor.resetState();
                Map<String, EffectSet> inferred = Candor.runScan(cls);
                ReportWriter.writeReport(inferred, rep.toString(), null);
                Candor.gateCapture = true;
                Candor.gateViolations.clear();
                int scanViolations = Policy.checkPolicy(inferred, pol.toString());
                Candor.writeGateJson(a.toString(), scanViolations);
                int scanExit = scanViolations > 0 ? 1 : 0;

                // ── the GATE route, over the report that scan just wrote ──
                Candor.resetState();                 // no scan state may survive into the report route
                Candor.gateViolations.clear();
                int gateExit = gate(rep, pol, "--gate-json", b.toString());

                if (!Files.exists(a) || !Files.exists(b)) {
                    diffs.add(tag + " (" + body.trim() + "): a verdict document was not written");
                    continue;
                }
                byte[] av = Files.readAllBytes(a), bv = Files.readAllBytes(b);
                if (!java.util.Arrays.equals(av, bv))
                    diffs.add("NOT BYTE-EQUAL for `" + body.replace("\n", " ; ").trim() + "`\n  scan: "
                            + new String(av) + "\n  gate: " + new String(bv));
                if (scanExit != gateExit)
                    diffs.add("EXIT " + scanExit + " (scan) vs " + gateExit + " (gate) for `"
                            + body.replace("\n", " ; ").trim() + "`");
                if (scanExit == 1) fired++;
                String s = new String(av);
                if (s.contains("reasonClass")) sawReasonClass = true;
                if (s.contains("netClass")) sawNetClass = true;
            }
            assertTrue(diffs.isEmpty(), "§3.1's byte-equality MUST, over " + policies.size()
                    + " policies:\n" + String.join("\n", diffs));

            // NON-VACUITY. Byte-equal EMPTY verdicts prove nothing, and §3.1 names `reasonClass` and
            // `netClass` specifically — so the corpus has to put them in the compared bytes.
            assertTrue(fired >= 4, "the corpus must contain policies that actually FAIL — fired=" + fired);
            assertTrue(sawReasonClass, "⟨0.19⟩ `reasonClass` must ride the compared verdict — it is one of "
                    + "the four fields §3.1 names, and a comparison that never sees it does not pin it");
            assertTrue(sawNetClass, "⟨0.20⟩ `netClass` likewise");

            // ── THE MUTATION CONTROL ──────────────────────────────────────────────────────────────────
            // A byte comparison that cannot fail is 12 green rows and no information. Perturb ONE field of
            // one scan-side document and require the comparator to see it. `analyzed.count` is chosen
            // because it is a §3.1-named field that the old count-and-exit-code test could not have seen:
            // both routes can agree on every violation and still disagree about how much was analysed,
            // which is precisely the shape of the report-set defect this suite already carries a row for.
            Path a = tmp.resolve("mut.scan.json"), b = tmp.resolve("mut.gate.json");
            Path pol = policy("deny Net app\n");
            Path rep = tmp.resolve("mut.jvm.json");
            Candor.resetState();
            Map<String, EffectSet> inferred = Candor.runScan(cls);
            ReportWriter.writeReport(inferred, rep.toString(), null);
            Candor.gateCapture = true;
            Candor.gateViolations.clear();
            Candor.writeGateJson(a.toString(), Policy.checkPolicy(inferred, pol.toString()));
            Candor.resetState();
            Candor.gateViolations.clear();
            gate(rep, pol, "--gate-json", b.toString());
            assertArrayEquals(Files.readAllBytes(a), Files.readAllBytes(b),
                    "the control row is byte-equal BEFORE the mutation");
            String mutated = Files.readString(a).replaceFirst("\"count\": \\d+", "\"count\": 99999");
            assertNotEquals(Files.readString(a), mutated, "the mutation must actually change the bytes");
            Files.writeString(a, mutated);
            assertFalse(java.util.Arrays.equals(Files.readAllBytes(a), Files.readAllBytes(b)),
                    "MUTATION CONTROL: a one-field difference in `analyzed.count` MUST be visible to this "
                    + "comparison. If it is not, every green row above is meaningless — and the old test, "
                    + "which compared only the violation count and the exit code, would have passed here");
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    /** …and the equivalence is not vacuous: at least one of those policies actually FAILED and at least
     *  one PASSED. A suite where every row is green on both sides proves nothing about the gate. */
    @Test
    void theEquivalenceCorpusContainsBothVerdicts() throws Exception {
        Path cls = compile(Map.of("app/Svc.java", String.join("\n",
                "package app;",
                "import java.net.*;",
                "public class Svc {",
                "  public void fetch() throws Exception { new URL(\"https://api.stripe.com/v1\").openStream().close(); }",
                "}")));
        try {
            Candor.resetState();
            Map<String, EffectSet> inferred = Candor.runScan(cls);
            Path rep = tmp.resolve("both.jvm.json");
            ReportWriter.writeReport(inferred, rep.toString(), null);
            Candor.resetState();
            assertEquals(1, gate(rep, policy("deny Net app\n")), "a failing policy must exit 1");
            Candor.resetState();
            assertEquals(0, gate(rep, policy("deny Exec app\n")), "a passing policy must exit 0");
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    /**
     * ⟨0.23⟩ EQUIVALENCE SURVIVES THE {@code interfaceUnion} RUNG. With {@code CANDOR_WORKSPACE_CHAIN} set,
     * {@link ReportWriter#appendInterfaceUnions} appends a SYNTHETIC entry per bodiless interface member
     * carrying the CHA union over the package's implementers — a publication device so a CHAINED CONSUMER's
     * dispatch resolves across the scan boundary, not an assertion that a declaration performs anything.
     *
     * <p>MEASURED before the repair, on the engine's OWN output: {@code scan --policy deny Net} flagged 2
     * ({@code app.impl.HttpClient.get}, {@code app.main.Runner.run}) while {@code gate --report} over the
     * report that same scan wrote flagged 3 — the extra row being the synthetic {@code app.api.Client.get}.
     * §3.1's byte-equality MUST refuted, in the FABRICATION direction, by turning on an opt-in PRODUCER
     * rung: a producer's own gate verdict must not move because it published more for its consumers.
     *
     * <p>Skipped, never dropped. Every effect under a union entry is already carried by the implementer's
     * own entry in the SAME report, so no reach is lost — and the entry stays in the gate's {@code inferred}
     * map, so a {@code calls} edge naming it still propagates. The advisory {@link Policy#gate} prints names
     * each skipped entry and the rule it matched, so nothing the gate saw goes unsaid.
     */
    @Test
    void aSyntheticInterfaceUnionEntryIsNotGatedAsAFunction() throws Exception {
        Path cls = compile(Map.of(
                "app/api/Client.java", String.join("\n",
                        "package app.api;",
                        "public interface Client { String get(String u) throws Exception; }"),
                "app/impl/HttpClient.java", String.join("\n",
                        "package app.impl;",
                        "public class HttpClient implements app.api.Client {",
                        "  public String get(String u) throws Exception {",
                        "    return String.valueOf(new java.net.URL(u).openStream().read()); }",
                        "}"),
                "app/main/Runner.java", String.join("\n",
                        "package app.main;",
                        "public class Runner {",
                        "  public String run(app.api.Client c) throws Exception { return c.get(\"http://x\"); }",
                        "}")));
        try {
            ReportWriter.workspaceChainOverride = true;      // the PRODUCER rung, opt-in
            Candor.resetState();
            Map<String, EffectSet> inferred = Candor.runScan(cls);
            Path rep = tmp.resolve("iu.jvm.json");
            ReportWriter.writeReport(inferred, rep.toString(), null);

            // the fixture is non-vacuous only if the rung actually emitted the synthetic entry
            assertTrue(Files.readString(rep).contains("\"interfaceUnion\": true"),
                    "precondition: the workspace-chain rung must have published a union entry, otherwise "
                    + "this test asserts nothing about it");

            Path pol = policy("deny Net\n");
            Candor.gateCapture = true;
            Candor.gateViolations.clear();
            int scanViolations = Policy.checkPolicy(inferred, pol.toString());

            Candor.resetState();
            Candor.gateViolations.clear();
            int gateExit = gate(rep, pol);
            List<String> gated = new ArrayList<>();
            for (var v : Candor.gateViolations) gated.add(String.valueOf(v.get("fn")));

            assertEquals(1, gateExit, "the real violators still fail the gate");
            assertEquals(scanViolations, gated.size(),
                    "scan --policy and gate --report must flag the SAME number of functions over the "
                    + "engine's own report — measured 2 vs 3 before, the extra row being the synthetic "
                    + "entry; got " + gated);
            assertFalse(gated.contains("app.api.Client.get"),
                    "a bodiless interface declaration cannot `perform` an effect — the union under its "
                    + "hash exists for a chained consumer's dispatch, and every effect in it is already "
                    + "gated under the implementer's own entry; got " + gated);
            assertTrue(gated.contains("app.impl.HttpClient.get") && gated.contains("app.main.Runner.run"),
                    "and the skip must not have taken the REAL violators with it — the fabrication fix "
                    + "must not become an under-report; got " + gated);
        } finally {
            ReportWriter.workspaceChainOverride = null;
            TestCompiler.rm(cls.getParent());
        }
    }

    // ── 3. AGREEMENT WITH THE REFERENCE MODEL ──────────────────────────────────────────────────────────

    /**
     * Rows taken from {@code reference/policy_model.py}: Definition 4's refinement example, Definition 30's
     * second sentence ("a non-empty `D` must NOT fire a bare `deny e`"), Definition 31, and the three
     * ⟨0.24⟩ repair rows from {@code repair_reproduces_the_counterexample_correctly}.
     *
     * <p>The mapping from a model {@code Sig(S, D)} to a candor report entry: {@code inferred} = S, plus
     * the {@code Unknown} marker iff D ≠ ∅ (candor carries the marker in the effect set; the model carries
     * it in D); {@code unknownWhy} = one raw tag per class in D.
     */
    @Test
    void agreesWithTheReferenceModelOnDenyAndDenyUnknown() throws Exception {
        // {policy, S, D, expected reject}
        Object[][] rows = {
            // Refinement is directional: `deny Db` must NOT fire on {Net}. Model and engine agree.
            {"deny Db app\n", List.of("Net"), List.<String>of(), false},
            // Definition 30, the sentence implementations get wrong: a non-empty D does NOT fire a bare deny.
            {"deny Net app\n", List.<String>of(), List.of("dispatch:app.X.m"), false},
            // Definition 31: bare `deny e Unknown` is C = R, so ANY reason fires it.
            {"deny Net Unknown app\n", List.<String>of(), List.of("dispatch:app.X.m"), true},
            {"deny Net Unknown app\n", List.<String>of(), List.of("native:x"), true},
            // Definition 31 with a class filter: ψ_C is D ∩ C ≠ ∅, no more.
            {"deny Net Unknown[dispatch] app\n", List.<String>of(), List.of("dispatch:app.X.m"), true},
            {"deny Net Unknown[dispatch] app\n", List.<String>of(), List.of("reflect:x"), false},
            {"deny Net Unknown[reflect,unresolved] app\n", List.<String>of(), List.of("reflect:x"), true},
            {"deny Net Unknown[reflect,unresolved] app\n", List.<String>of(), List.of("native:x"), false},
            // φ is independent of ψ: a determined Net fires `deny Net Unknown[native]` through φ alone.
            {"deny Net Unknown[native] app\n", List.of("Net"), List.of("reflect:x"), true},
            // ⟨0.24⟩ repair rows. Row 2 (reasoned only) passes; row 3 (worse-known, same filter) rejects.
            {"deny Net Unknown[unresolved] app\n", List.<String>of(), List.of("dispatch:x"), false},
            {"deny Net Unknown[unresolved] app\n", List.<String>of(), List.of("dispatch:x", "someUnrecognised:x"), true},
        };
        for (Object[] r : rows) {
            @SuppressWarnings("unchecked") List<String> s = (List<String>) r[1];
            @SuppressWarnings("unchecked") List<String> d = (List<String>) r[2];
            List<String> inferred = new ArrayList<>(s);
            if (!d.isEmpty()) inferred.add("Unknown");   // candor's encoding of the model's `D ≠ ∅`
            Path rep = report("m" + Math.abs((r[0] + s.toString() + d).hashCode()) + ".jvm.json",
                    List.of(entry("app.U.f", inferred, d, null)));
            Candor.resetState();
            int exit = gate(rep, policy((String) r[0]));
            assertEquals(((Boolean) r[3]) ? 1 : 0, exit,
                    "model row: " + r[0].toString().trim() + "  over S=" + s + " D=" + d);
        }
    }

    /**
     * A MEASURED DISAGREEMENT between the engine and the reference model, pinned here rather than fixed —
     * the first thing {@code gate --report} was able to find, and the reason the verb is a MUST.
     *
     * <p>PAPER3 Definition 4, transcribed in {@code policy_model.py}, makes {@code ⊑ₑ} a preorder with
     * {@code Db ⊑ₑ Net} and {@code Llm ⊑ₑ Net}, and Definition 30's firing condition is
     * {@code φₑ(S,D) := ∃ e' ∈ S. e' ⊑ₑ e}. So the model REJECTS {@code deny Net} over {@code S = {Db}},
     * and its {@code selftest} asserts that as a worked example. Every candor engine instead intersects the
     * denied set with {@code inferred} — plain membership, no preorder — so it PASSES. Confirmed by running
     * the model: {@code deny('Net')(Sig({'Db'})) -> True}.
     *
     * <p>Which side is wrong is NOT this test's call, and the disagreement is not obviously the engine's:
     * SPEC §6.2's normative {@code deny} grammar says only "each token that names an effect … joins the
     * forbidden set", and AS-EFF-006 is stated as an intersection. So the CONTRACT the four engines
     * implement has no refinement clause, and the model has one — the same species of model-versus-contract
     * divergence as the ⟨0.24⟩ §6.2 defect, which is what this file's existence is meant to surface. It is
     * reported upstream, not patched here: making {@code deny Net} fire on {@code Db} is a four-way
     * semantic change to a security gate, and it would tighten every existing policy silently.
     *
     * <p>The row is pinned in BOTH directions so a future change in either is loud rather than silent.
     */
    @Test
    void engineDoesNotImplementTheModelsRefinementPreorderInDeny() throws Exception {
        Path db = report("ref1.jvm.json", List.of(entry("app.U.f", List.of("Db"))));
        assertEquals(0, gate(db, policy("deny Net app\n")),
                "MEASURED: candor-java passes `deny Net` over a determined {Db}; policy_model's Definition 4 "
                + "REJECTS it (Db ⊑ₑ Net). Reported as a model-vs-contract divergence, not fixed here.");
        Candor.resetState();
        Path llm = report("ref2.jvm.json", List.of(entry("app.U.f", List.of("Llm"))));
        assertEquals(0, gate(llm, policy("deny Net app\n")),
                "…and the same for Llm ⊑ₑ Net, so the divergence is the preorder itself, not one pair");
        Candor.resetState();
        Path net = report("ref3.jvm.json", List.of(entry("app.U.f", List.of("Net"))));
        assertEquals(1, gate(net, policy("deny Net app\n")),
                "the plain membership case still fires — the gate is not simply inert on Net");
    }

    /**
     * A report entry that raises {@code Unknown} DIRECTLY and records NO reason for it. Only a hand-authored
     * or foreign report can reach this state — the ⟨0.24⟩ producer-side repair makes it unreachable from a
     * scan (every in-scan site records an {@code unknownWhy} beside the {@code Unknown} it raises, and
     * {@code Loader#synthesizeReasonlessDepReasons} covers the dependency boundary).
     *
     * <p>⟨0.24⟩ SPEC §6.2 requirement (3): the entry CONTRIBUTES {@code unresolved}, and this is not
     * inventing a datum — the report positively asserts a direct {@code Unknown} and positively asserts no
     * reason for it, and "a direct {@code Unknown} you did not name" IS the {@code unresolved} class. So
     * {@code Unknown[unresolved]} FIRES and {@code Unknown[native]} tolerates, which is exactly what
     * {@code scan --policy} does over the same signature (there, the reason is synthesised at the source
     * and classifies to {@code unresolved} the same way). This row previously asserted exit 2 for BOTH,
     * from the pre-⟨0.24⟩ reading in which the rule was keyed on the class set being EMPTY: under that
     * reading the contribution really would have been an invention, because the same empty set also
     * describes an INHERITED {@code Unknown} whose reason the report simply did not link to. Requirement
     * (3) is the distinction — gate on a DIRECT {@code Unknown} it did not name, never on absence — and
     * with it drawn, refusing here would COST the scan-vs-report equivalence this verb exists to provide.
     *
     * <p>The refusal has not gone anywhere: the last rows are the case the class set genuinely cannot be
     * derived for — an INHERITED {@code Unknown} with no {@code calls} edge to the reason — and it is still
     * exit 2. The BARE forms gate throughout; the effect set alone answers them.
     */
    @Test
    void aReasonlessDirectUnknownContributesUnresolvedRatherThanBeingRefused() throws Exception {
        Path rep = report("rl.jvm.json", List.of(entry("app.U.f", List.of("Unknown"), List.of(), null)));
        assertEquals(1, gate(rep, policy("deny Net Unknown[unresolved] app\n")),
                "§6.2 (3): a DIRECT Unknown the entry did not name IS of class `unresolved` — the filter "
                + "naming that class must select it, not refuse the policy");
        Candor.resetState();
        assertEquals(0, gate(rep, policy("deny Net Unknown[native] app\n")),
                "…and a filter naming a class it is NOT tolerates it, the same narrowing `scan --policy` "
                + "performs over the same signature — the contribution discriminates, it does not flood");
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Net Unknown app\n")),
                "the BARE form still fires — the effect set alone answers it, so the refusal costs no reach");
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Net Unknown[*] app\n")),
                "`[*]` is the bare form spelled out (an empty filter), so it fires too");

        // THE REFUSAL IS STILL ALIVE — the control that separates "contributes" from "answers everything".
        // Same `inferred`, but the Unknown is INHERITED (no direct Unknown) and no `calls` edge reaches a
        // reason, so nothing in the report bears on the class. §6.2 requirement (3) does not apply and the
        // narrowing is refused in BOTH directions.
        Candor.resetState();
        Path inherited = report("rl2.jvm.json", List.of(
                entry("app.U.g", List.of("Unknown"), List.of(), Map.of("direct", List.of()))));
        assertEquals(2, gate(inherited, policy("deny Net Unknown[unresolved] app\n")),
                "an INHERITED Unknown with no reason reachable is the case the class set WOULD have to be "
                + "invented for — still refused, so the contribution above is gated, not blanket");
        Candor.resetState();
        assertEquals(2, gate(inherited, policy("deny Net Unknown[native] app\n")),
                "…including the tolerating direction, which is the dangerous one");
        Candor.resetState();
        assertEquals(1, gate(inherited, policy("deny Net Unknown app\n")),
                "…and the BARE form still fires on it, so the refusal costs no reach");
    }

    /**
     * FINDING 3 — AN ABSENT OPTIONAL FIELD MUST NOT RELAX A FAIL-CLOSED GATE.
     *
     * <p>A class-scoped {@code deny} narrows on a second question ("…and is the destination / the reason
     * class one of THESE?"). When the report does not carry the field that question is read from, the
     * matcher sees an empty set, nothing matches, and the effect is DROPPED from the violation — the
     * narrowing succeeds precisely BECAUSE the evidence is missing. Measured before the refusal, one
     * function per row:
     * <pre>
     *   Net-bearing entry, netClass ABSENT   →  deny Net[unknown-host]  exit 0   |  deny Net      exit 1
     *   inherited Unknown, `calls` ABSENT    →  deny Unknown[dispatch]  exit 0   |  deny Unknown  exit 1
     * </pre>
     * Both are now exit 2. Each row is asserted with its EVIDENCE-PRESENT control, because a refusal that
     * fires on everything would pass the fail-open half while destroying the verb.
     */
    @Test
    void aScopedDenyIsRefusedWhenTheReportCannotAnswerTheNarrowing() throws Exception {
        // ── the Net destination-class half ──
        Path noNetClass = report("nc0.jvm.json", List.of(entry("app.A.f", List.of("Net"))));
        assertEquals(2, gate(noNetClass, policy("deny Net[unknown-host] app\n")),
                "no `netClass` on a Net-bearing entry ⇒ the filter cannot be answered — refuse, never pass");
        Candor.resetState();
        assertEquals(1, gate(noNetClass, policy("deny Net app\n")),
                "…and the BARE rule still fires on the very same report, which is what made the green above "
                + "a relaxation rather than a true negative");
        Candor.resetState();
        Path withNetClass = report("nc1.jvm.json", List.of(entry("app.A.f", List.of("Net"), List.of(),
                Map.of("netClass", List.of("unknown-host")))));
        assertEquals(1, gate(withNetClass, policy("deny Net[unknown-host] app\n")),
                "CONTROL: with the evidence present the scoped rule evaluates normally");
        Candor.resetState();
        assertEquals(0, gate(withNetClass, policy("deny Net[known-telemetry] app\n")),
                "CONTROL: …and still DISCRIMINATES — a non-matching class passes, so the refusal has not "
                + "collapsed into always-fail");

        // ── the Unknown reason-class half ──
        // `direct: []` is LOAD-BEARING here, not decoration: it is what makes `app.C.go`'s Unknown
        // INHERITED, which is the case this refusal is for. The row said INHERITED in a comment while the
        // report it built said `direct: ["Unknown"]` (the `entry` helper's default), so it was in fact
        // asserting the ⟨0.24⟩ §6.2 CONTRIBUTES case — which is answerable, and is asserted as such by
        // #aReasonlessDirectUnknownContributesUnresolvedRatherThanBeingRefused.
        Candor.resetState();
        Path noCalls = report("nk0.jvm.json", List.of(
                entry("app.C.go", List.of("Unknown"), List.of(), Map.of("direct", List.of())),
                entry("app.L.m", List.of("Unknown"), List.of("dispatch:app.L.m"), null)));
        assertEquals(2, gate(noCalls, policy("deny Unknown[dispatch] app.C\n")),
                "the reason lives on a callee the report does not link to — the class set is unreachable, "
                + "so the narrowing must not succeed by default");
        Candor.resetState();
        assertEquals(1, gate(noCalls, policy("deny Unknown app.C\n")), "…the BARE rule still fires");
        Candor.resetState();
        Path withCalls = report("nk1.jvm.json", List.of(
                entry("app.C.go", List.of("Unknown"), List.of(),
                        Map.of("direct", List.of(), "calls", List.of("app.L.m"))),
                entry("app.L.m", List.of("Unknown"), List.of("dispatch:app.L.m"), null)));
        assertEquals(1, gate(withCalls, policy("deny Unknown[dispatch] app.C\n")),
                "CONTROL: with the `calls` edge present the class resolves transitively and the rule fires");
        Candor.resetState();
        assertEquals(0, gate(withCalls, policy("deny Unknown[native] app.C\n")),
                "CONTROL: …and a non-matching class still passes");
    }

    /** The refusal is per (rule, function): a scoped rule whose MATCHED functions all carry their evidence
     *  evaluates normally even when some other, out-of-scope entry does not. Otherwise one legacy entry
     *  anywhere in a big report would disable every scoped rule in the policy. */
    @Test
    void theScopedRefusalIsScopedToTheRulesOwnMatches() throws Exception {
        Path rep = report("sc.jvm.json", List.of(
                entry("app.ok.A.f", List.of("Net"), List.of(), Map.of("netClass", List.of("unknown-host"))),
                entry("app.legacy.B.g", List.of("Net"))));            // no netClass — but out of scope
        assertEquals(1, gate(rep, policy("deny Net[unknown-host] app.ok\n")),
                "the rule's own matches all carry `netClass`, so it is answerable and evaluates");
        Candor.resetState();
        // ⟨0.24⟩ Widening the scope pulls the evidence-less entry in. `app.legacy.B.g` is withheld — but
        // `app.ok.A.f` still FIRES on evidence the report carries, so the policy is rejected with
        // certainty and exit 1 dominates the refusal (§3.1). This row asserted exit 2 before that
        // correction: the whole verdict was withheld because ONE of two entries lacked a field.
        assertEquals(1, gate(rep, policy("deny Net[unknown-host] app\n")),
                "the same rule fires on the entry that CARRIES its evidence — the withheld sibling cannot "
                + "un-reject a rejected policy");
        // …and the entry that could not be judged is not silently folded into the pass. The CONTROL that
        // makes exit 2 reachable: drop the firing entry and the same widened rule refuses.
        Candor.resetState();
        Path onlyLegacy = report("sc2.jvm.json", List.of(entry("app.legacy.B.g", List.of("Net"))));
        assertEquals(2, gate(onlyLegacy, policy("deny Net[unknown-host] app\n")),
                "CONTROL: with nothing left to fire on, the unanswerable entry IS the answer — exit 2");
    }

    /** The reason class must travel TRANSITIVELY over the report's own `calls` (§6.2: `unknownWhy` is
     *  direct-only by contract, so a filter matching the direct field reads a field that answers a
     *  different question). The caller here has `Unknown` with NO reason of its own; the reason lives on
     *  the callee it names in `calls`. */
    @Test
    void reasonClassesResolveTransitivelyOverTheReportsOwnCalls() throws Exception {
        Path rep = report("tr.jvm.json", List.of(
                entry("app.Caller.go", List.of("Unknown"), List.of(), Map.of("calls", List.of("app.Leaf.m"))),
                entry("app.Leaf.m", List.of("Unknown"), List.of("reflect:app.Leaf.m"), null)));
        assertEquals(1, gate(rep, policy("deny Unknown[reflect] app.Caller\n")),
                "the CALLER inherits the callee's `reflect` class — resolving it only from the caller's own "
                + "(empty) unknownWhy would default to `unresolved` and let a reflection-caused hole pass");
    }

    // ── the ANSWERABILITY refusals ─────────────────────────────────────────────────────────────────────

    /** `forbid A -> B` is refused, loudly, rather than evaluated over the report's EFFECT-RELEVANT `calls`
     *  graph — where a crossing into a wholly PURE unit is invisible and the rule would read green. */
    @Test
    void forbidRulesAreRefusedNotApproximated() throws Exception {
        Path rep = report("f.jvm.json", List.of(entry("app.web.H.go", List.of("Net"))));
        assertEquals(2, gate(rep, policy("forbid app.web -> app.db\n")),
                "a rule this verb cannot faithfully evaluate must FAIL (exit 2), never pass silently");
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Net app.web\nforbid app.web -> app.db\n")),
                "⟨0.24⟩ …but a rule that FIRES beside it wins. `deny Net app.web` is answered from the "
                + "report, so the policy is REJECTED, and `Reject` being upward-closed (Lemma 2) no "
                + "resolution of the `forbid` could un-reject it. This row asserted exit 2 on the reading "
                + "that enforcing only the answerable half means exiting 0 — it does not: it means exiting "
                + "1 and disclosing the rule that went unevaluated");
    }

    /**
     * EVERY {@code allow} rule is refused — the AS-EFF-008 surface-completeness marker rides the wire for
     * no effect at all.
     *
     * <p>This test exists in this shape because the first implementation got it wrong in the fail-OPEN
     * direction and {@link #scanAndGateAgreeOnTheSameProgram} caught it. That version reconstructed the
     * marker for {@code Net} from {@code netClass ∋ unknown-host}, which reads plausible and is a different
     * predicate: {@code unknown-host} is ALSO what {@code netDestClass} returns for a merely UNRECOGNISED
     * host, so {@code api.stripe.com} — fully visible, nothing masked — carried it. The reconstruction
     * flagged 2 functions the scan passes. Refusing is the only posture that neither fails open nor
     * invents violations.
     */
    @Test
    void everyAllowRuleIsRefused() throws Exception {
        Path rep = report("a.jvm.json", List.of(
                entry("app.R.run", List.of("Exec"), List.of(), Map.of("cmds", List.of("git"))),
                entry("app.R.get", List.of("Net"), List.of(),
                        Map.of("hosts", List.of("api.stripe.com"), "netClass", List.of("unknown-host")))));
        for (String body : List.of("allow Exec in app git\n", "allow Fs in app /tmp\n",
                "allow Db in app users\n", "allow Net in app api.stripe.com\n",
                "allow Llm in app api.openai.com\n")) {
            Candor.resetState();
            assertEquals(2, gate(rep, policy(body)),
                    "not answerable from a report — must fail loudly, never certify: " + body.trim());
        }
        // ⟨0.24⟩ The refusal is the answer only while nothing else fires. Mixed with a rule the report DOES
        // answer, the certain violation dominates (§3.1) — exit 1, never 0, and never the exit 2 that would
        // delete the violation from the verdict document.
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Net app\nallow Exec in app git\n")),
                "a policy mixing a FIRING rule with an unanswerable one exits 1 on the violation it is "
                + "certain of, disclosing the `allow` it could not evaluate");
    }

    /**
     * ⟨0.24⟩ <b>A CERTAIN VIOLATION DOMINATES A REFUSAL — SPEC §3.1.</b> Three outcomes can be live at
     * once and the order is <b>violation (1) &gt; refusal (2) &gt; incomplete (2)</b>, forced by Lemma 2
     * rather than chosen: a rule that FIRES on evidence the report carries REJECTS the policy, and
     * {@code Reject} is upward-closed, so however the unanswerable rule would have resolved cannot
     * un-reject it.
     *
     * <p><b>MEASURED before this repair</b>, on the fixture below (a hand-built report carrying one
     * {@code Fs} unit and one INHERITED {@code Unknown} with no reason and no {@code calls}):
     * <pre>
     *   deny Fs app                                   →  exit 1, document naming app.W.write
     *   deny Unknown[dispatch] app                    →  exit 2, NO document
     *   deny Fs app  +  deny Unknown[dispatch] app    →  exit 2, NO document   ← the defect
     * </pre>
     * The third row is the harm, and it is not taxonomic: the refusal standing beside the firing rule
     * DELETED a certain violation from the machine-consumer channel. Four-way agreement, and four-way
     * wrong (rust/java/ts/swift all measured at exit 2 with no document).
     *
     * <p><b>The assertion is on the DOCUMENT, not the exit code.</b> A test that only checked the exit
     * cannot see this defect — it is precisely the case where the exit code is repaired while the
     * violation stays absent from what CI reads.
     */
    @Test
    void aFiringRuleDominatesAnUnanswerableOneAndTheViolationReachesTheDocument() throws Exception {
        // `direct: []` makes the Unknown INHERITED, and there is no `calls` edge to a reason — the state
        // no scan can produce and the one `deny Unknown[dispatch]` genuinely cannot be answered over.
        Path rep = report("prec.jvm.json", List.of(
                entry("app.W.write", List.of("Fs")),
                entry("app.U.g", List.of("Unknown"), List.of(), Map.of("direct", List.of()))));
        Path both = policy("deny Fs app\ndeny Unknown[dispatch] app\n");
        Path out = tmp.resolve("prec.verdict.json");
        Files.deleteIfExists(out);                       // never measure against a stale artifact

        Candor.gateCapture = true;
        Candor.gateViolations.clear();
        int rc = Query.run(new String[]{"gate", "--report", rep.toString(), "--policy", both.toString(),
                "--gate-json", out.toString()});
        assertEquals(1, rc, "a rule that fires on evidence the report carries makes exit 1 CERTAIN — the "
                + "unanswerable rule beside it cannot un-reject the policy (§3.1, PAPER3 Lemma 2)");

        assertTrue(Files.exists(out), "…and the verdict DOCUMENT must exist: the whole harm of refusing "
                + "here was that the refusal wrote nothing, so CI re-read the previous run's file");
        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertFalse(v.get("ok").getAsBoolean(), "ok must be false");
        assertEquals(1, v.getAsJsonArray("violations").size(),
                "THE POINT: the violation is IN THE DOCUMENT, not merely implied by the exit code");
        assertEquals("app.W.write",
                v.getAsJsonArray("violations").get(0).getAsJsonObject().get("fn").getAsString(),
                "and it names the function — the datum the refusal used to delete");

        // …and the part it could not read is NOT concealed. §3.1: "exit 1 reports the violation it is sure
        // of, it does not conceal the part it could not read."
        assertTrue(v.has("unevaluated"), "the rule that could not be evaluated must be disclosed IN the "
                + "document too — a stderr line a CI wrapper discards is not a disclosure to the consumer");
        assertTrue(v.getAsJsonArray("unevaluated").get(0).getAsJsonObject().get("rule").getAsString()
                        .contains("Unknown[dispatch]"),
                "…naming the rule: " + v.getAsJsonArray("unevaluated"));

        // CONTROL 1 — the refusal has NOT been dissolved. Alone, the same rule over the same report is
        // still exit 2; without this the test above would pass on an engine that stopped refusing at all.
        Candor.resetState();
        assertEquals(2, gate(rep, policy("deny Unknown[dispatch] app\n")),
                "CONTROL: the unanswerable rule ALONE still refuses — the precedence rule reorders the "
                + "outcomes, it does not delete the middle one");

        // CONTROL 2 — the firing rule alone gives the same verdict, so the exit 1 above comes from the
        // violation and not from the mere presence of a second rule.
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Fs app\n")),
                "CONTROL: the firing rule alone is exit 1 over the same report");

        // CONTROL 3 — and a policy whose firing rule does NOT fire falls back to the refusal. This is what
        // separates "violation dominates" from "never refuse when two rules are present".
        Candor.resetState();
        assertEquals(2, gate(rep, policy("deny Exec app\ndeny Unknown[dispatch] app\n")),
                "CONTROL: with the answerable rule passing, the refusal is the answer again");
    }

    /**
     * ⟨0.24⟩ WITHHOLDING IS PER (rule, function, EFFECT) — candor-spec {@code b3748ed}, which corrects the
     * per-{@code (rule, function)} form §3.1 first specced (and this engine first implemented).
     *
     * <p>A single rule may name SEVERAL effects and the evidence for them is INDEPENDENT.
     * {@code deny Fs Net[unknown-host] app} over ONE function carrying a certain {@code Fs} beside a
     * {@code netClass}-less {@code Net} has a certain match and an unanswerable one on the SAME function.
     * MEASURED on this engine at {@code 868dbc9}, that one function alone in the report:
     * <pre>
     *   per (rule, function)          exit 2, refused, `violations` key ABSENT   ← the certain Fs DELETED
     *   per (rule, function, effect)  exit 1, violations: [{app.mixed, [Fs]}] + `unevaluated` for the Net
     * </pre>
     * The pair form reintroduces exactly the harm the precedence ruling above exists to remove, arrived at
     * through the fix for it. The document must now carry BOTH keys — the violation it is sure of and the
     * part it could not read.
     *
     * <p>The precedence test above cannot see this: its fixture puts the certain effect and the
     * unanswerable one on DIFFERENT functions, where pair-granularity and effect-granularity agree.
     */
    @Test
    void anUnevidencedEffectMustNotSuppressACertainOneInTheSameRule() throws Exception {
        // ONE function: certain Fs, and a Net whose `netClass` the report does not carry.
        Path rep = report("gran.jvm.json", List.of(entry("app.mixed", List.of("Fs", "Net"))));
        Path pol = policy("deny Fs Net[unknown-host] app\n");
        Path out = tmp.resolve("gran.verdict.json");
        Files.deleteIfExists(out);                       // never measure against a stale artifact

        Candor.gateCapture = true;
        Candor.gateViolations.clear();
        int rc = Query.run(new String[]{"gate", "--report", rep.toString(), "--policy", pol.toString(),
                "--gate-json", out.toString()});
        assertEquals(1, rc, "the rule FIRES for Fs on evidence the entry carries; the Net it cannot decide "
                + "sits in the same rule on the same function and must not un-reject the policy");

        assertTrue(Files.exists(out), "a verdict document, not a refusal that writes nothing");
        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertTrue(v.has("violations"), "THE DEFECT: the pair form deleted the `violations` key entirely, "
                + "so the certain Fs never reached a machine consumer — an exit-code-only assertion "
                + "cannot see that: " + v);
        assertEquals(1, v.getAsJsonArray("violations").size(), "one violation: " + v);
        JsonObject viol = v.getAsJsonArray("violations").get(0).getAsJsonObject();
        assertEquals("app.mixed", viol.get("fn").getAsString());
        assertEquals(List.of("Fs"),
                viol.getAsJsonArray("effects").asList().stream().map(x -> x.getAsString()).toList(),
                "…charging ONLY the effect the entry evidences. Charging the Net too would be the "
                + "fabrication mirror: the report never asserted its destination class");
        assertTrue(v.has("unevaluated"), "…and the withheld EFFECT is still disclosed. The repair is that a "
                + "withheld effect must not suppress a fired one, NOT that the disclosure goes away — a "
                + "document carrying the violation while silently dropping the Net would be this same "
                + "defect one level down: " + v);
        assertTrue(v.getAsJsonArray("unevaluated").get(0).getAsJsonObject().get("why").getAsString()
                        .contains("Net DESTINATION CLASS"),
                "…naming which part of the rule went unread: " + v.getAsJsonArray("unevaluated"));

        // CONTROL 1 — the refusal is not dissolved. Strip the certain effect from the entry and the SAME
        // rule over the SAME shape is exit 2 again. Without this the assertion above would pass on an
        // engine that had simply stopped withholding.
        Candor.resetState();
        Path netOnly = report("gran2.jvm.json", List.of(entry("app.mixed", List.of("Net"))));
        assertEquals(2, gate(netOnly, pol),
                "CONTROL: with nothing certain beside it, the unanswerable Net still refuses");

        // CONTROL 2 — the Fs really is certain over this report, so the exit 1 above is the violation and
        // not the mere presence of a second effect token in the rule.
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Fs app\n")),
                "CONTROL: the bare `deny Fs` over the same report is exit 1");
    }

    /**
     * THE MIRROR OF THE ROW ABOVE, AND IT IS NOT HYPOTHETICAL — this rung has produced its own inverse
     * three times. Making a rule fire per EFFECT must not resurrect the fabrication {@code 9f24cc5} closed:
     * {@code reasonClassesOf} floors an empty class set at {@code unresolved}, which is the right
     * fail-closed default for a MATCHER and the wrong basis for a FIRING, so a scoped
     * {@code deny Unknown[unresolved]} over an entry whose class set is genuinely EMPTY (INHERITED
     * {@code Unknown}, no {@code unknownWhy}, no {@code calls}) would charge a class the report never
     * asserted.
     *
     * <p>Row 3 is the one the granularity change actually endangers, and it was MEASURED failing during
     * this change rather than assumed safe. The two causes — netless {@code Net} and reasonless
     * {@code Unknown} — used to be tested with an {@code else if}, which was harmless while either one
     * withheld the whole pair. Per EFFECT it is not: with the {@code else} in place, one function carrying
     * BOTH causes under ONE rule emitted {@code violations: [{app.both, [Unknown]}]} at exit 1 — the
     * fabrication, reintroduced by the fix for its mirror.
     */
    @Test
    void aWithheldEffectIsStillWithheldWhenNothingCertainStandsBesideIt() throws Exception {
        // 1. The reasonless INHERITED Unknown alone — refused, and no `violations` key to fabricate into.
        Path inh = report("mir1.jvm.json", List.of(
                entry("app.inh", List.of("Unknown"), List.of(), Map.of("direct", List.of()))));
        Path out = tmp.resolve("mir1.verdict.json");
        Files.deleteIfExists(out);
        assertEquals(2, gate(inh, policy("deny Unknown[unresolved] app\n"),
                        "--gate-json", out.toString()),
                "the class set is EMPTY here, not `unresolved` — an effect that fires only on the default "
                + "for the ABSENT datum has not fired");
        JsonObject v1 = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertFalse(v1.has("violations"), "…and a refusal makes no claim about violations, not even []: " + v1);

        // 2. The certain Fs beside it — the Fs fires, the Unknown stays withheld. Both halves in one run.
        Candor.resetState();
        Path mixed = report("mir2.jvm.json", List.of(
                entry("app.inh", List.of("Fs", "Unknown"), List.of(), Map.of("direct", List.of("Fs")))));
        Path out2 = tmp.resolve("mir2.verdict.json");
        Files.deleteIfExists(out2);
        Candor.gateCapture = true;
        Candor.gateViolations.clear();
        assertEquals(1, gate(mixed, policy("deny Fs Unknown[unresolved] app\n"),
                "--gate-json", out2.toString()));
        JsonObject v2 = JsonParser.parseString(Files.readString(out2)).getAsJsonObject();
        assertEquals(List.of("Fs"), v2.getAsJsonArray("violations").get(0).getAsJsonObject()
                        .getAsJsonArray("effects").asList().stream().map(x -> x.getAsString()).toList(),
                "the fired effect and ONLY the fired effect — the withheld Unknown must not ride along on "
                + "the violation the Fs earned: " + v2);
        assertTrue(v2.has("unevaluated"), "…with the withheld half disclosed: " + v2);

        // 3. BOTH causes on ONE function under ONE rule — the `else if` hazard the granularity change
        //    creates. Nothing in this entry is decidable, so nothing may fire.
        Candor.resetState();
        Path both = report("mir3.jvm.json", List.of(
                entry("app.both", List.of("Net", "Unknown"), List.of(), Map.of("direct", List.of()))));
        Path out3 = tmp.resolve("mir3.verdict.json");
        Files.deleteIfExists(out3);
        assertEquals(2, gate(both, policy("deny Net[unknown-host] Unknown[unresolved] app\n"),
                        "--gate-json", out3.toString()),
                "MEASURED with an `else if` between the two causes: exit 1 charging `Unknown` — the "
                + "fabrication resurrected by the granularity fix. The causes are independent and must "
                + "each be tested");
        JsonObject v3 = JsonParser.parseString(Files.readString(out3)).getAsJsonObject();
        assertFalse(v3.has("violations"), "…and no violation record naming a class the report never "
                + "asserted: " + v3);
        assertEquals(2, v3.getAsJsonArray("unevaluated").size(),
                "BOTH withheld effects are disclosed — an `else` would have named only the Net while "
                + "silently deciding the Unknown: " + v3);

        // CONTROL — the bare forms still fire on every one of these entries, so the withholding costs no
        // reach: it is the NARROWED filter that cannot be answered, never the effect's membership.
        Candor.resetState();
        assertEquals(1, gate(inh, policy("deny Unknown app\n")),
                "CONTROL: the bare `deny Unknown` fires on the same entry — the effect set alone answers it");
        Candor.resetState();
        assertEquals(1, gate(both, policy("deny Net Unknown app\n")),
                "CONTROL: …and the bare forms fire on the both-causes entry too");
    }

    /**
     * ⟨0.24⟩ <b>A REFUSAL MUST STILL WRITE A DOCUMENT — SPEC §3.1.</b>
     *
     * <p>MEASURED at 2cdc443: every refusal path exited 2 having written NOTHING to the {@code --gate-json}
     * path. A CI wrapper that reads that path unconditionally therefore re-reads <b>the PREVIOUS run's
     * document as current</b> — a green file from yesterday's clean run becomes today's all-clear. Deleting
     * the path is not the fix: a consumer that reads a missing file as "nothing to report" fails open by a
     * different route.
     *
     * <p>The document is fail-closed to a NAIVE reader: {@code ok: false} (a consumer keying only on
     * {@code ok} lands on FAIL) plus {@code refused: true} and the reason (a consumer keying on
     * {@code refused} learns why). And it carries <b>no {@code violations} key at all</b> — not an empty
     * array. The gate is making no claim about violations, and {@code []} is exactly the claim it cannot
     * make. That distinction is the test's whole point, so it is asserted as ABSENCE, not emptiness.
     */
    @Test
    void everyRefusalWritesAFailClosedDocumentWithNoViolationsKey() throws Exception {
        Path rep = report("ref.jvm.json", List.of(
                entry("app.U.g", List.of("Unknown"), List.of(), Map.of("direct", List.of()))));

        // The STALE-DOCUMENT bait, made literal: a green verdict from "yesterday" already sits at the path.
        Path out = tmp.resolve("verdict.json");
        String yesterday = "{\n \"spec\": \"0.24\",\n \"ok\": true,\n \"violations\": []\n}\n";

        record Row(String name, String[] argv) {}
        Path good = policy("deny Unknown[dispatch] app\n");
        List<Row> rows = List.of(
                new Row("an unanswerable scoped deny",
                        new String[]{"gate", "--report", rep.toString(), "--policy", good.toString()}),
                new Row("a whole-policy `forbid` refusal",
                        new String[]{"gate", "--report", rep.toString(),
                                "--policy", policy("forbid app -> lib\n").toString()}),
                new Row("a whole-policy `allow` refusal",
                        new String[]{"gate", "--report", rep.toString(),
                                "--policy", policy("allow Exec in app git\n").toString()}),
                new Row("an UNREADABLE policy",
                        new String[]{"gate", "--report", rep.toString(),
                                "--policy", tmp.resolve("no-such.policy").toString()}),
                new Row("an UNREADABLE report",
                        new String[]{"gate", "--report", tmp.resolve("corrupt.jvm.json").toString(),
                                "--policy", good.toString()}));
        Files.writeString(tmp.resolve("corrupt.jvm.json"), "{ not json");

        for (Row row : rows) {
            Candor.resetState();
            Files.writeString(out, yesterday);            // the stale green, back on disk for every row
            List<String> argv = new ArrayList<>(List.of(row.argv()));
            argv.addAll(List.of("--gate-json", out.toString()));
            assertEquals(2, Query.run(argv.toArray(new String[0])), row.name() + ": refuses");

            String written = Files.readString(out);
            assertNotEquals(yesterday, written, row.name()
                    + ": the document at the --gate-json path must have been REPLACED. Leaving it is how "
                    + "yesterday's clean run becomes today's all-clear");
            JsonObject v = JsonParser.parseString(written).getAsJsonObject();
            assertFalse(v.get("ok").getAsBoolean(), row.name()
                    + ": `ok` must be false — a consumer keying only on `ok` has to land on FAIL");
            assertTrue(v.get("refused").getAsBoolean(), row.name() + ": `refused: true` says WHY it is false");
            assertTrue(v.has("reason"), row.name() + ": …and the reason travels with it");
            assertFalse(v.has("violations"), row.name()
                    + ": the `violations` key must be ABSENT, not empty — the gate is making no claim "
                    + "about violations, and `[]` is precisely the claim it cannot make. Got: " + written);
        }

        // CONTROL — a run that DOES give a verdict still carries `violations`, so the absence above is a
        // property of refusing and not of the writer having lost the key.
        Candor.resetState();
        Files.deleteIfExists(out);
        assertEquals(1, Query.run(new String[]{"gate", "--report",
                report("ok.jvm.json", List.of(entry("app.W.w", List.of("Fs")))).toString(),
                "--policy", policy("deny Fs app\n").toString(), "--gate-json", out.toString()}));
        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertTrue(v.has("violations"), "CONTROL: a real verdict carries the key");
        assertFalse(v.has("refused"), "CONTROL: …and is not marked refused");
    }

    /**
     * ⟨0.24⟩ The SCAN route reaches a gate too, and it had the same hole: {@code candor <classes> --policy
     * <typo> --gate-json <path>} exited 2 having written nothing, so the CI wrapper read the previous run's
     * document. Closing it only on {@code gate --report} would be closing half of it.
     */
    @Test
    void theScanRoutesUnreadablePolicyAlsoWritesTheRefusalDocument() throws Exception {
        Path cls = compile(Map.of("app/S.java", String.join("\n",
                "package app;",
                "public class S { public void go() {} }")));
        try {
            Path out = tmp.resolve("scanverdict.json");
            String yesterday = "{\n \"spec\": \"0.24\",\n \"ok\": true,\n \"violations\": []\n}\n";
            Files.writeString(out, yesterday);

            // The real CLI in a child JVM — this path ends in System.exit(2), so it cannot be driven
            // in-process, and the wiring (not just the writer) is what needs to be under test.
            String javaBin = System.getProperty("java.home") + "/bin/java";
            Process p = new ProcessBuilder(javaBin, "-cp", System.getProperty("java.class.path"),
                    "io.poly.candor.Candor", cls.toString(),
                    "--policy", tmp.resolve("no-such.policy").toString(),
                    "--gate-json", out.toString())
                    .redirectErrorStream(true).start();
            String log = new String(p.getInputStream().readAllBytes());
            assertEquals(2, p.waitFor(), "an unreadable --policy fails the scan closed: " + log);

            String written = Files.readString(out);
            assertNotEquals(yesterday, written, "MEASURED at 2cdc443: the scan route exited 2 having "
                    + "written NOTHING here, so a CI wrapper re-read yesterday's green verdict as today's");
            JsonObject v = JsonParser.parseString(written).getAsJsonObject();
            assertFalse(v.get("ok").getAsBoolean(), "the scan route's refusal document is the SAME document");
            assertTrue(v.get("refused").getAsBoolean());
            assertFalse(v.has("violations"), "and it makes no violations claim either");
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    /**
     * ⟨0.24⟩ <b>AN UNRECOGNISED CLASS TOKEN REFUSES THE WHOLE GATE — SPEC §6.2</b> (candor-spec 382a7e0),
     * end to end and on BOTH routes, because the parser-level assertion in {@link PolicyParserTest} cannot
     * see whether the caller acts on it.
     *
     * <p>MEASURED at 2cdc443 over a report carrying one {@code Unknown} unit whose reason is
     * {@code reflect}:
     * <pre>
     *   deny Unknown[dispatch,nativ] app  ->  exit 0   ← the rule NARROWED to [dispatch] and passed
     *   deny Unknown[corp] app            ->  exit 1   ← the rule WIDENED to bare `deny Unknown`
     * </pre>
     * Two different wrong answers from two different silent rewrites of the same one-line policy. The
     * first is the fail-open one and it is the common case.
     */
    @Test
    void anUnrecognisedClassTokenRefusesTheWholeGate() throws Exception {
        Path rep = report("tok.jvm.json", List.of(
                entry("app.U.f", List.of("Unknown"), List.of("reflect:app.U.f"), null),
                entry("app.N.g", List.of("Net"), List.of(),
                        Map.of("netClass", List.of("known-partner")))));

        for (String body : List.of(
                "deny Unknown[dispatch,nativ] app\n",              // NARROWS — was exit 0
                "deny Unknown[corp] app\n",                        // WIDENS  — was exit 1
                "deny Net[known-partner,unkown-host] app\n",       // NARROWS
                "deny Net[unkown-host] app\n")) {                  // WIDENS
            Candor.resetState();
            Path out = tmp.resolve("tok" + Math.abs(body.hashCode()) + ".json");
            assertEquals(2, Query.run(new String[]{"gate", "--report", rep.toString(),
                            "--policy", policy(body).toString(), "--gate-json", out.toString()}),
                    "a policy that cannot be honoured as written takes the unreadable-policy posture, "
                    + "never a silently rewritten rule: " + body.trim());
            assertEquals(0, Candor.gateViolations.size(),
                    "…and NOTHING was evaluated — a rewritten rule must not produce a verdict either way");
            JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
            assertFalse(v.get("ok").getAsBoolean());
            assertTrue(v.get("refused").getAsBoolean(),
                    "…and the refusal reaches the machine consumer, per the ⟨0.24⟩ document rung");
        }

        // CONTROLS — the same rules, spelled correctly, still discriminate in BOTH directions. Without
        // these the block above passes on a gate that refuses every scoped rule.
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Unknown[reflect,unresolved] app\n")),
                "CONTROL: the correctly-spelled filter FIRES on the reflect-caused hole");
        Candor.resetState();
        assertEquals(0, gate(rep, policy("deny Unknown[native,unresolved] app.N\n")),
                "CONTROL: …and a correctly-spelled non-matching filter still passes");
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Net[known-partner] app\n")),
                "CONTROL: the Net destination-class vocabulary works when spelled right");
    }

    /**
     * ⟨0.24⟩ <b>THE FOURTH CHANNEL: POLICY VOCABULARY ANCHORS AT THE POLICY FILE, ON BOTH ROUTES</b> —
     * SPEC §3.1 (candor-spec 99eb4e9).
     *
     * <p>§3.1's MUST NOT names three channels through which an effect must never enter a gate that its
     * report does not carry. The fourth is {@code .candor/config}'s {@code unknown-alias}, and no engine
     * tested it: all four GATE verbs anchored discovery at the POLICY file's directory while all four SCAN
     * routes anchored at the TARGET. With the policy filed outside the scan target, the two routes expand
     * the same rule differently — <b>so the byte-equality MUST is breakable by a file that is neither the
     * report nor the policy.</b>
     *
     * <p>MEASURED at 2cdc443. {@code unknown-alias corp = native} sits beside the policy, the scan target
     * carries no config, and the target's one {@code Unknown} is {@code reflect}-caused:
     * <pre>
     *   scan --policy polhome/my.policy               →  exit 1   alias UNRESOLVED, rule WIDENED to bare Unknown
     *   gate --report r --policy polhome/my.policy    →  exit 0   alias resolved, deny Unknown[native], no match
     * </pre>
     * Same report, same policy, two verdicts — and the fail-open one is the gate.
     *
     * <p>The second half is the DISCLOSURE: a verdict changed by a file the operator cannot see named in
     * the output is the ambient-input failure this format exists to refuse, so the document names it. It
     * fires on an alias a rule REFERENCED, not only on one that fired — the measured harm above was a
     * GREEN verdict a vocabulary file made green.
     */
    @Test
    void policyVocabularyAnchorsAtThePolicyFileOnBothRoutesAndIsNamedInTheVerdict() throws Exception {
        // The target tree, with NO config of its own.
        Path cls = compile(Map.of("app/Svc.java", String.join("\n",
                "package app;",
                "public class Svc {",
                "  public void dyn(Object o) throws Exception { o.getClass().getMethod(\"run\").invoke(o); }",
                "}")));
        try {
            // The policy tree, elsewhere, carrying the vocabulary. `native` is chosen so the alias
            // DISCRIMINATES: the fn's Unknown is `reflect`, so the resolved rule must NOT fire — which is
            // what makes the two routes' answers differ rather than agree by luck.
            Path polHome = tmp.resolve("polhome");
            Files.createDirectories(polHome.resolve(".candor"));
            Files.writeString(polHome.resolve(".candor/config"), "unknown-alias corp = native\n");
            Path pol = polHome.resolve("my.policy");
            Files.writeString(pol, "deny Unknown[corp,unresolved] app\n");

            // ── the SCAN route, through the REAL CLI in a child JVM. Calling the anchor helper from the
            // test would leave Candor.main's own wiring untested, which is exactly where the defect was.
            Path rep = tmp.resolve("anchor.jvm.json");
            String javaBin = System.getProperty("java.home") + "/bin/java";
            Process p = new ProcessBuilder(javaBin, "-cp", System.getProperty("java.class.path"),
                    "io.poly.candor.Candor", cls.toString(), "--json", rep.toString(),
                    "--policy", pol.toString())
                    .redirectErrorStream(true).start();
            String scanLog = new String(p.getInputStream().readAllBytes());
            int scanExit = p.waitFor();
            assertTrue(scanExit == 0 || scanExit == 1, "the scan gives a verdict, not an error: " + scanLog);

            // ── the GATE route, over the report that scan wrote ──
            Candor.resetState();
            Candor.gateViolations.clear();
            Path out = tmp.resolve("anchor.verdict.json");
            int gateExit = Query.run(new String[]{"gate", "--report", rep.toString(),
                    "--policy", pol.toString(), "--gate-json", out.toString()});

            assertEquals(scanExit, gateExit,
                    "the two routes must expand `Unknown[corp]` the SAME way. Before the anchor fix the "
                    + "scan resolved it against the TARGET (no config → token dropped → rule widened to "
                    + "bare `deny Unknown` → exit 1) while the gate resolved it against the POLICY (→ "
                    + "`deny Unknown[native]` → exit 0), which is §3.1's byte-equality MUST broken by a "
                    + "file that is neither the report nor the policy");
            assertEquals(0, gateExit, "and the AGREED answer is the policy-anchored one: `corp` = native, "
                    + "the fn's Unknown is reflect, so the rule does not fire");

            // THE DISCLOSURE. The verdict is GREEN and a file the operator never named is why.
            JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
            assertTrue(v.has("policyVocabulary"), "a config file that supplied vocabulary participating in "
                    + "the verdict MUST be named in the document — this verdict is green BECAUSE of it");
            JsonObject pv = v.getAsJsonObject("policyVocabulary");
            assertTrue(pv.get("config").getAsString().endsWith(".candor/config"),
                    "…by path: " + pv.get("config").getAsString());
            assertTrue(pv.get("config").getAsString().contains("polhome"),
                    "…and it is the POLICY's config, not the target's: " + pv.get("config").getAsString());
            assertEquals("corp", pv.getAsJsonArray("aliases").get(0).getAsString(),
                    "…and names which alias was used");

            // NEGATIVE CONTROL — a policy using no alias gets no such key, so the field means something.
            Candor.resetState();
            Path plain = polHome.resolve("plain.policy");
            Files.writeString(plain, "deny Unknown[native,unresolved] app\n");
            Path out2 = tmp.resolve("plain.verdict.json");
            assertEquals(0, Query.run(new String[]{"gate", "--report", rep.toString(),
                    "--policy", plain.toString(), "--gate-json", out2.toString()}));
            assertFalse(JsonParser.parseString(Files.readString(out2)).getAsJsonObject()
                            .has("policyVocabulary"),
                    "CONTROL: no alias used ⇒ no key, so a pre-⟨0.24⟩ verdict is byte-identical");

            // POSITIVE CONTROL on the alias itself — spell it to a class the fn DOES have and the same
            // rule fires. Without this the green above could be a rule that never gates.
            Candor.resetState();
            Files.writeString(polHome.resolve(".candor/config"), "unknown-alias corp = reflect\n");
            assertEquals(1, gate(rep, pol),
                    "CONTROL: `corp` = reflect makes the same rule FIRE — the alias is load-bearing");

            // …and the SAME vocabulary reaches the pre-edit verbs. `whatif` and `fix-gate` never loaded
            // `unknown-alias` at all, so before this they silently rewrote an aliased rule (widening or
            // narrowing it) while the gate honoured it — the same rule meaning two things in the verb an
            // agent consults BEFORE editing and in the gate that judges the edit.
            Candor.resetState();
            assertNotEquals(2, Query.run(new String[]{"fix-gate", "--report", rep.toString(),
                            "--policy", pol.toString()}),
                    "`fix-gate` must honour the policy's own vocabulary, not refuse it as unspellable");

        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    // ── CLI shape + the loud-failure postures ──────────────────────────────────────────────────────────

    /** A CONFIGURED-but-unreadable policy fails loudly (exit 2), never gateless-green (§6.2). */
    @Test
    void anUnreadablePolicyFailsClosed() throws Exception {
        Path rep = report("u.jvm.json", List.of(entry("app.A.f", List.of("Net"))));
        assertEquals(2, Query.run(new String[]{"gate", "--report", rep.toString(),
                "--policy", tmp.resolve("nope.policy").toString()}));
    }

    /** No policy at all is a usage error, not an empty pass. */
    @Test
    void aMissingPolicyIsAUsageErrorNotAPass() throws Exception {
        Path rep = report("np.jvm.json", List.of(entry("app.A.f", List.of("Net"))));
        assertEquals(2, Query.run(new String[]{"gate", "--report", rep.toString()}),
                "with no policy there is no verdict to give — never exit 0");
    }

    // ── the REPORT SET a prefix locator names (§2 "a single analysis world") ───────────────────────────

    /**
     * A PREFIX locator matching SEVERAL reports must gate over EVERY one of them. The engine-wide resolver
     * ({@link Query#expandPrefix}) picks the lexicographically-first match and discloses the choice on
     * stderr; on this verb that narrowing is invisible to the consumer, because the output is an exit code
     * and a verdict document.
     *
     * <p>The fixture puts the violation in the SECOND file, which is exactly the one a first-match pick
     * never opens. MEASURED before the repair: exit 0, {@code analyzed.count: 3}, zero violations — where
     * candor-rust and candor-ts both gave exit 1, {@code analyzed.count: 4}, one violation.
     *
     * <p><b>The count is asserted, not just the exit code.</b> 3-vs-4 is the only part of the verdict that
     * names the failure mode: an exit code can be repaired by a gate that happens to fire, but a count of 3
     * over a 3+1 report set says in the document itself that a located report was never read — and the
     * ⟨0.21⟩ reading of that document is that those units were analysed and found pure.
     */
    @Test
    void aPrefixNamingSeveralReportsGatesOverEveryOneOfThem() throws Exception {
        report("set/rep.Aclean.jvm.json", List.of(entry("a.ok", List.of())), 3);
        report("set/rep.Bdirty.jvm.json", List.of(entry("b.leak", List.of("Net"))), 1);
        Path pol = policy("deny Net\n");
        Path out = tmp.resolve("setverdict.json");

        Candor.gateCapture = true;
        Candor.gateViolations.clear();
        int rc = Query.run(new String[]{"gate", "--report", tmp.resolve("set/rep").toString(),
                "--policy", pol.toString(), "--gate-json", out.toString()});
        assertEquals(1, rc, "the violation lives in the SECOND report of the set — a locator that names "
                + "both must not exit 0 over the one that happens to sort first");

        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertEquals(4, v.getAsJsonObject("analyzed").get("count").getAsInt(),
                "analyzed.count must SUM the set (3 + 1). A count of 3 is the tell: it claims ⟨0.21⟩ "
                + "coverage of one report while a located sibling was never opened");
        assertFalse(v.get("ok").getAsBoolean(), "the verdict document must be red, not just the exit code");
        assertEquals(1, v.getAsJsonArray("violations").size());
        assertEquals("b.leak",
                v.getAsJsonArray("violations").get(0).getAsJsonObject().get("fn").getAsString(),
                "and it must name the sibling's function");

        // NEGATIVE CONTROL — the same policy over the clean report ALONE is green. Without this the test
        // above would also pass on a gate that flags everything.
        Candor.resetState();
        Path out2 = tmp.resolve("cleanonly.json");
        assertEquals(0, Query.run(new String[]{"gate", "--report",
                tmp.resolve("set/rep.Aclean.jvm.json").toString(), "--policy", pol.toString(),
                "--gate-json", out2.toString()}), "the clean report alone passes — so the failure above "
                + "comes from the sibling, not from the policy");
        assertEquals(3, JsonParser.parseString(Files.readString(out2)).getAsJsonObject()
                .getAsJsonObject("analyzed").get("count").getAsInt(),
                "and a locator naming ONE report is byte-identical to before the set reading");
    }

    /**
     * A PARTIALLY-CORRUPT report set gates RED-LOUD, never green. §3.1: "a report that cannot be parsed is
     * corrupt input, not an effect-free package … A located report that yields no trustworthy functions
     * MUST fail loudly." Over a SET that has to mean the set — the half-written sibling here is exactly the
     * file that would have carried the violation, so gating over its readable neighbour publishes a green
     * verdict whose only evidence is which file the writer happened to finish.
     *
     * <p>MEASURED before the repair: exit 0 with a clean verdict document, because the verb read one
     * report and the one it read was the clean one. candor-rust and candor-swift both exit 2 here.
     */
    @Test
    void aPartiallyCorruptReportSetRefusesRatherThanGatingTheReadableHalf() throws Exception {
        report("torn/rep.Aclean.jvm.json", List.of(entry("a.ok", List.of())), 3);
        Path b = tmp.resolve("torn/rep.Bdirty.jvm.json");
        // truncated mid-write — the shape a report has while a producer is still writing it
        Files.writeString(b, "{\"candor\":{\"spec\":\"" + Candor.SPEC_VERSION + "\"},\"package\":\"dirty\","
                + "\"functions\":[{\"fn\":\"b.leak\",\"inferred\":[\"Ne");
        Path out = tmp.resolve("tornverdict.json");
        assertEquals(2, Query.run(new String[]{"gate", "--report", tmp.resolve("torn/rep").toString(),
                "--policy", policy("deny Net\n").toString(), "--gate-json", out.toString()}),
                "a torn sibling under the same prefix must refuse the whole run — a green verdict over "
                + "the readable half asserts purity for functions nothing parsed");
        // ⟨0.24⟩ This assertion used to read `assertFalse(Files.exists(out))`, on the argument that writing
        // no verdict keeps a wrapper from mistaking one for a judgement. SPEC §3.1 overturns it, and the
        // counter is decisive: writing nothing does not leave the wrapper with no document, it leaves the
        // wrapper with the PREVIOUS run's — a green file from yesterday's clean run, read as today's. The
        // document below cannot be mistaken for a judgement by anyone who reads it (`refused: true`, no
        // `violations` key at all) and is FAIL to anyone who reads only `ok`.
        assertTrue(Files.exists(out), "a refusal must still write a document — see §3.1's stale-verdict "
                + "hazard: a missing file is not 'no verdict', it is LAST RUN's verdict");
        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertFalse(v.get("ok").getAsBoolean(), "…and it is fail-closed to a reader that keys only on `ok`");
        assertTrue(v.get("refused").getAsBoolean(), "…and says it is a refusal, not a judgement");
        assertFalse(v.has("violations"), "…and makes NO claim about violations — that is what stops it "
                + "being mistaken for a judgement, not its absence from the disk");
    }

    // ── a report that JUDGED NOTHING (⟨0.24⟩ SPEC §2/§3.1) ────────────────────────────────────────────

    /**
     * A report with {@code analyzed.count: 0} has judged nothing, so it licenses NO purity claim — and the
     * verb MUST SAY SO. As a DISCLOSURE, and only that.
     *
     * <p>The three assertions are the three halves of the corrected clause, and the last two are the ones
     * that keep the repair from becoming a different defect:
     * <ul>
     *   <li>stderr is NON-EMPTY and names the package. MEASURED before: {@code candor-java: no violations}
     *       on stdout and <b>zero bytes</b> on stderr — the forbidden literal with nothing beside it.</li>
     *   <li>the EXIT CODE is unmoved (0). §3.3 enumerates exactly two exit-2 causes — a broken gate CONFIG
     *       and an INCOMPLETE analysis of the target's OWN code — and a judged-nothing DEPENDENCY is
     *       neither, so refusing here mints a third and splits the verb.</li>
     *   <li>the VERDICT DOCUMENT is unmoved. §3.1's byte-equality MUST binds this route to
     *       {@code scan --policy}, and a scan of an empty facade package exits 0 with a clean verdict; and
     *       manufacturing a violation would assert an effect the consumer has no evidence for.</li>
     * </ul>
     */
    @Test
    void aReportThatJudgedNothingIsDisclosedWithoutMovingTheVerdict() throws Exception {
        Path rep = report("facade.jvm.json", List.of(), 0);       // analyzed.count: 0, functions: []
        Path out = tmp.resolve("nothingverdict.json");
        java.io.PrintStream priorErr = System.err;
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        int rc;
        try {
            System.setErr(new java.io.PrintStream(err, true));
            rc = Query.run(new String[]{"gate", "--report", rep.toString(),
                    "--policy", policy("deny Net\n").toString(), "--gate-json", out.toString()});
        } finally {
            System.setErr(priorErr);
        }
        String e = err.toString();
        assertFalse(e.isBlank(), "a count-0 report must be DISCLOSED — the measured defect was `candor-java: "
                + "no violations` with ZERO bytes on stderr, which is the deleted disclosure §2 names as "
                + "the harm");
        assertTrue(e.contains("app"), "the advisory must NAME the package it judged nothing about, "
                + "otherwise a multi-package CI log cannot act on it — got: " + e);

        assertEquals(0, rc, "the exit code is UNMOVED: §3.3 has exactly two exit-2 causes and a "
                + "judged-nothing dependency is neither — refusing here mints a third and splits the verb");
        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertTrue(v.get("ok").getAsBoolean(), "and the verdict document is UNMOVED — §3.1's byte-equality "
                + "MUST binds this route to `scan --policy`, which exits 0 with a clean verdict over an "
                + "empty facade package");
        assertEquals(0, v.getAsJsonObject("analyzed").get("count").getAsInt());
        assertEquals(0, v.getAsJsonArray("violations").size(),
                "manufacturing a violation would assert an effect the consumer has no evidence for");

        // NEGATIVE CONTROL — the same policy over a report that DID judge something must NOT carry the
        // advisory. Without this the assertion above passes on a verb that prints the note unconditionally.
        Candor.resetState();
        Path rep2 = report("judged.jvm.json", List.of(entry("app.A.f", List.of("Fs"))), 5);
        java.io.ByteArrayOutputStream err2 = new java.io.ByteArrayOutputStream();
        try {
            System.setErr(new java.io.PrintStream(err2, true));
            Query.run(new String[]{"gate", "--report", rep2.toString(),
                    "--policy", policy("deny Net\n").toString(), "--gate-json",
                    tmp.resolve("judgedverdict.json").toString()});
        } finally {
            System.setErr(priorErr);
        }
        assertFalse(err2.toString().contains("JUDGED NOTHING"),
                "a report with analyzed.count > 0 judged something — the advisory must not fire on it");
    }

    /** A corrupt report fails loudly rather than reading as an effect-free package (§3.1). */
    @Test
    void aCorruptReportFailsClosed() throws Exception {
        Path bad = tmp.resolve("bad.jvm.json");
        Files.writeString(bad, "{\"nope\": 1}");
        assertEquals(2, Query.run(new String[]{"gate", "--report", bad.toString(),
                "--policy", policy("deny Net app\n").toString()}));
    }

    /** `gate` takes no positionals, and a valueless `--gate-json` must not swallow the next flag (the
     *  `--gate-json --policy p` shape that ran a scan GATELESS and green). A genuinely unknown flag is
     *  {@link Candor#rejectUnknownFlag}'s shared exit-2 posture, which halts the JVM and so is pinned by
     *  the out-of-process CLI suite rather than here. */
    @Test
    void strayPositionalsAndAValuelessGateJsonAreRejected() throws Exception {
        Path rep = report("uf.jvm.json", List.of(entry("app.A.f", List.of("Net"))));
        Path pol = policy("deny Exec app\n");
        assertEquals(2, Query.run(new String[]{"gate", "--report", rep.toString(),
                "--policy", pol.toString(), "somestray"}), "gate takes no positional args");
        assertEquals(2, Query.run(new String[]{"gate", "--report", rep.toString(), "--gate-json"}),
                "a valueless --gate-json must fail, never swallow the next flag");
        assertEquals(2, Query.run(new String[]{"gate", "--report", rep.toString(),
                "--gate-json", "--policy", pol.toString()}),
                "a flag-shaped --gate-json value must fail — swallowing --policy here is exactly how a "
                + "gate runs green with no policy at all");
    }

    /** `--gate-json` is a GATE flag: on a read-only query it would be silently inert, which reads as a
     *  clean verdict to a wrapper that only checks the file exists. */
    @Test
    void gateJsonIsRejectedOnNonGateVerbs() throws Exception {
        Path rep = report("gj.jvm.json", List.of(entry("app.A.f", List.of("Net"))));
        assertEquals(2, Query.run(new String[]{"map", "--report", rep.toString(),
                "--gate-json", tmp.resolve("v.json").toString()}));
    }

    /**
     * The VERDICT DOCUMENT is the scanning path's, from the same writer — a consumer must not be able to
     * tell the two routes apart from the output. Asserts the ⟨0.21⟩ {@code analyzed.count} rides from the
     * report ENVELOPE rather than being invented, and that {@code --json} ≡ {@code --gate-json -}.
     */
    @Test
    void theVerdictDocumentMatchesTheScanningPathsShape() throws Exception {
        Path rep = report("v.jvm.json", List.of(
                entry("app.A.f", List.of("Net")), entry("app.A.g", List.of("Fs"))));
        Path out = tmp.resolve("verdict.json");
        assertEquals(1, gate(rep, policy("deny Net app\n"), "--gate-json", out.toString()));
        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertEquals(Candor.SPEC_VERSION, v.get("spec").getAsString());
        assertFalse(v.get("ok").getAsBoolean());
        assertEquals(2, v.getAsJsonObject("analyzed").get("count").getAsInt(),
                "analyzed.count comes from the report envelope — the scan's own count is unavailable here "
                + "and must not be faked from the entry list");
        assertEquals(1, v.getAsJsonArray("violations").size());
        JsonObject viol = v.getAsJsonArray("violations").get(0).getAsJsonObject();
        assertEquals("AS-EFF-006", viol.get("rule").getAsString());
        assertEquals("app.A.f", viol.get("fn").getAsString());
        assertEquals("Net", viol.getAsJsonArray("effects").get(0).getAsString());
    }

    /**
     * In {@code --json} mode STDOUT MUST BE PURE JSON. Found by piping the real CLI into a parser: the
     * trailer line ("→ candor fix-gate names the remedy…") was written to {@code Candor.diagOut} AFTER the
     * finally-block restored it to stdout, so it prefixed the verdict document and
     * {@code candor gate … --json | jq} failed to parse. Both verdicts are asserted — the clean run prints
     * "no violations" on the same stream and would corrupt stdout identically.
     */
    @Test
    void inJsonModeStdoutIsPureJson() throws Exception {
        Path rep = report("pj.jvm.json", List.of(entry("app.A.f", List.of("Net"))));
        for (String pol : List.of("deny Net app\n", "deny Exec app\n")) {   // one failing, one clean
            Candor.resetState();
            java.io.PrintStream realOut = System.out;
            java.io.PrintStream realDiag = Candor.diagOut;
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            try {
                java.io.PrintStream cap =
                        new java.io.PrintStream(buf, true, java.nio.charset.StandardCharsets.UTF_8);
                System.setOut(cap);
                // `Candor.diagOut` is a static initialised to System.out AT CLASS LOAD, so swapping
                // System.out alone leaves it pointing at the REAL stdout — and the first version of this
                // test passed against the bug for exactly that reason, because the stray trailer went to
                // the console instead of the buffer. Point it at the capture too, which is the state a
                // fresh process is actually in.
                Candor.diagOut = cap;
                gate(rep, policy(pol), "--json");
            } finally {
                System.setOut(realOut);
                Candor.diagOut = realDiag;
            }
            String out = buf.toString(java.nio.charset.StandardCharsets.UTF_8);
            JsonObject v = JsonParser.parseString(out).getAsJsonObject();   // throws if anything else rode along
            assertTrue(v.has("ok") && v.has("violations"),
                    "stdout must be the verdict document and nothing else, for policy: " + pol.trim());
        }
    }

    /** ⟨0.21⟩ COMPLETENESS MANIFEST: a report declaring unanalyzed units cannot yield a green gate. The
     *  scan path exits 2 on its own manifest; here the manifest travels ON the report and the same verdict
     *  follows from it. */
    @Test
    void anIncompleteReportCannotProduceAGreenGate() throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", 1, "digest", "0"));
        env.put("unanalyzed", List.of(Map.of("path", "app/Broken.class", "reason", "unsupported class version")));
        env.put("functions", List.of(entry("app.A.f", List.of("Fs"))));
        Path rep = tmp.resolve("inc.jvm.json");
        Files.writeString(rep, io.poly.candor.model.ReportJson.pretty(env));

        Path out = tmp.resolve("incverdict.json");
        assertEquals(2, gate(rep, policy("deny Net app\n"), "--gate-json", out.toString()),
                "no violation, but the analysis was incomplete — exit 2 (could-not-evaluate), never 0");
        JsonObject v = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
        assertFalse(v.get("ok").getAsBoolean(), "ok requires BOTH no violation AND a complete analysis");
        assertTrue(v.get("incomplete").getAsBoolean());
        assertEquals("app/Broken.class",
                v.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().get("path").getAsString());
    }

    /** The one difference between {@code scan --policy} and this verb is where the signature comes from —
     *  so a report produced by a DIFFERENT engine (no `hash`, `::`-separated names, a foreign `unknownWhy`
     *  prefix) must gate just as well. This is the supply-chain case. */
    @Test
    void gatesAForeignEnginesReport() throws Exception {
        Path rep = report("rust.crate.json", List.of(
                entry("app::client::post", List.of("Net"), List.of(), null),
                entry("app::util::spawn", List.of("Unknown"), List.of("ambiguous:same-name"), null)));
        assertEquals(1, gate(rep, policy("deny Net app::client\n")),
                "a `::`-written name and scope must match (the §6.2 segment rule)");
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Unknown[dispatch] app::util\n")),
                "⟨0.24⟩ `ambiguous:` — the FIFTH canonical §4 kind, which candor-java consumes but never "
                        + "produces — projects to `dispatch` (§6.2's normative table)");
        Candor.resetState();
        assertNotEquals(1, gate(rep, policy("deny Exec app\n")), "…and it is not just always-failing");
    }

    /**
     * ⟨0.24⟩ THE CONTROL for the fifth §4 kind, end to end through the verb a supply-chain consumer
     * actually runs. {@code ambiguous:} is now canonical and projects to class {@code dispatch} (row above);
     * a genuinely off-vocabulary kind must behave EXACTLY as it did before — the conservative
     * {@code unresolved} catch-all under §2 forward compatibility. The two tests together are what separate
     * "candor-java learned a fifth kind" from "candor-java stopped classifying kinds": had the check become
     * a blanket, {@code banana:} would fire {@code Unknown[dispatch]} here too.
     */
    @Test
    void anOffVocabularyKindStillClassifiesUnresolvedNotAsTheNewCanonicalOne() throws Exception {
        Path rep = report("mystery.crate.json", List.of(
                entry("app::util::spawn", List.of("Unknown"), List.of("banana:whatever"), null)));
        assertNotEquals(1, gate(rep, policy("deny Unknown[dispatch] app::util\n")),
                "an off-vocabulary kind must NOT be swept into `dispatch` — that is a blanket, not a kind");
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Unknown[unresolved] app::util\n")),
                "it lands in the conservative catch-all, so it is never silently tolerated (§2)");
        Candor.resetState();
        assertEquals(1, gate(rep, policy("deny Unknown[dynamic] app::util\n")),
                "…and the `dynamic` alias still covers it");
    }
}
