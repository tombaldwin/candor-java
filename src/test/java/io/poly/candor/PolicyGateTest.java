package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The policy GATE checkers — each returns its violation count, the contract the CI exit code rides on. Only
 * the deny-verdict was exercised (via the policy/ conformance fixture); this covers the AS-EFF-008 fail-closed
 * allowlist, the AS-EFF-005 baseline-drift guard (+ its dual-format loader), and the advisory AS-EFF-004/007.
 */
class PolicyGateTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void fresh() {
        Candor.resetState();
    }

    private Path file(String name, String body) throws Exception {
        Path p = Files.createTempFile(tmp, name, ".json");
        Files.writeString(p, body);
        return p;
    }

    private Path policy(String body) throws Exception {
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, body);
        return p;
    }

    // ── AS-EFF-008 allowlist: empty/incomplete surface is FAIL-CLOSED (gate-evasion defense) ──────────

    @Test
    void allowlistFailsClosedOnAnInvisibleSurface() throws Exception {
        Path pol = policy("allow Net in api host.ok");
        Map<String, EffectSet> inferred = Map.of("api.Svc.call", EffectSet.of(Effect.NET));
        // NO visible host literal for the Net-performing method → cannot be certified → violation.
        assertTrue(Policy.checkPolicy(inferred, pol.toString()) >= 1,
            "a Net call with no visible host must fail-closed (a benign literal must not mask an invisible endpoint)");
    }

    @Test
    void allowlistPassesAReachedAllowedHost() throws Exception {
        Path pol = policy("allow Net in api host.ok");
        ctx().hostsDirect.put("api.Svc.call", new TreeSet<>(java.util.List.of("host.ok")));
        Map<String, EffectSet> inferred = Map.of("api.Svc.call", EffectSet.of(Effect.NET));
        assertEquals(0, Policy.checkPolicy(inferred, pol.toString()),
            "reaching only the allow-listed host must pass");
    }

    @Test
    void allowlistFlagsAHostOutsideTheList() throws Exception {
        Path pol = policy("allow Net in api host.ok");
        ctx().hostsDirect.put("api.Svc.call", new TreeSet<>(java.util.List.of("evil.example")));
        Map<String, EffectSet> inferred = Map.of("api.Svc.call", EffectSet.of(Effect.NET));
        assertTrue(Policy.checkPolicy(inferred, pol.toString()) >= 1,
            "reaching a host outside the allowlist must be a violation");
    }

    // ── AS-EFF-005 baseline drift + the dual-format loader ───────────────────────────────────────────

    @Test
    void baselineLoaderAcceptsBothEnvelopeAndBareArray() throws Exception {
        Path env = file("benv", "{\"functions\":[{\"fn\":\"a.B.c\",\"inferred\":[\"Net\"]}]}");
        Path bare = file("bbare", "[{\"fn\":\"a.B.c\",\"inferred\":[\"Net\"]}]");
        assertTrue(Policy.loadBaseline(env.toString()).containsKey("a.B.c"), "v0.2 envelope must load");
        assertTrue(Policy.loadBaseline(bare.toString()).containsKey("a.B.c"), "v0.1 bare array must load");
        assertNull(Policy.loadBaseline("/no/such/baseline.json"), "an unreadable baseline must be null (loud, not silent)");
        Path scalar = file("bscalar", "5");
        assertNull(Policy.loadBaseline(scalar.toString()), "a non-report scalar must be null");
    }

    @Test
    void baselineVersionIsReadFromTheEnvelope() throws Exception {
        // The stale-baseline POSTURE (mismatch/no-provenance → exit 2, no evaluation) exits the JVM, so
        // it is pinned at the CLI level (CliBehaviourTest.staleBaselineFailsClosedWithoutEvaluating);
        // here: the version parse both ways.
        Path env = file("bver", "{\"candor\":{\"version\":\"aaaaaaa\"},\"functions\":[]}");
        assertEquals("aaaaaaa", Policy.baselineVersion(env.toString()));
        Path bare = file("bvbare", "[{\"fn\":\"a.B.c\",\"inferred\":[\"Fs\"]}]");
        assertNull(Policy.baselineVersion(bare.toString()), "a bare array has no provenance");
    }

    @Test
    void baselineFlagsAGainedEffectButNotNewCode() throws Exception {
        // the fixture must carry THIS build's provenance — a stale/absent version now fails closed (exit 2)
        String v = ReportWriter.provenance()[0];
        Path base = file("base", "{\"candor\":{\"version\":\"" + v + "\"},\"functions\":[{\"fn\":\"a.B.c\",\"inferred\":[\"Fs\"]}]}");
        // No sidecar here (report-only): a.B.c gained Net vs the baseline → AS-EFF-005; a.B.New is
        // absent from the report AND there is no callgraph to prove it existed → reviewed as new code.
        Map<String, EffectSet> inferred = new HashMap<>();
        inferred.put("a.B.c", EffectSet.of(Effect.FS, Effect.NET));
        inferred.put("a.B.New", EffectSet.of(Effect.NET));
        assertEquals(1, Policy.checkBaseline(inferred, base.toString()),
            "only the function that gained an effect vs the baseline is a regression");
    }

    /** ⟨0.16⟩ Write a callgraph sidecar next to a baseline report path (strip a trailing `.json`,
     *  append `.callgraph.json` — the {@link Query#loadCallgraphSignalled} pairing). `body` is the raw
     *  sidecar JSON, so a test can also write a CORRUPT one. */
    private void writeSidecar(Path reportPath, String body) throws Exception {
        String p = reportPath.toString();
        String cg = (p.endsWith(".json") ? p.substring(0, p.length() - 5) : p) + ".callgraph.json";
        Files.writeString(Path.of(cg), body);
    }

    @Test
    void baselineSidecarCatchesPureToEffectful() throws Exception {
        // ⟨0.16⟩ The sharpest supply-chain shape: a fn that was PURE at the baseline (absent from
        // the report, which omits pure fns — but present as a callgraph NODE) now performs an effect.
        // With the sidecar present it is keyed as existing (baseline ∅) → any effect is a GAIN.
        String v = ReportWriter.provenance()[0];
        Path base = file("base", "{\"candor\":{\"version\":\"" + v + "\"},\"functions\":[]}");
        writeSidecar(base, "{\"util.Fmt.fmt\":[],\"api.Api.fetch\":[\"util.Fmt.fmt\"]}");
        Map<String, EffectSet> inferred = new HashMap<>();
        inferred.put("util.Fmt.fmt", EffectSet.of(Effect.FS)); // formerly pure, now does I/O
        assertEquals(1, Policy.checkBaseline(inferred, base.toString()),
            "a formerly-pure callgraph node that turns effectful is a GAIN, not exempt new code");
    }

    @Test
    void baselineUnknownOnlyGainIsAdvisoryNotAViolation() throws Exception {
        // ⟨0.16⟩ A fn that was PURE at the baseline (a callgraph node, absent from the report) now
        // reaches only an UNRESOLVED call (reflection/dynamic → Unknown). Unknown is the §4 trust marker,
        // not an effect (`pure` policies exclude it); on version bumps it is resolution noise. So this is
        // ADVISORY — disclosed on stderr, NOT an AS-EFF-005 regression (returns 0).
        String v = ReportWriter.provenance()[0];
        Path base = file("base", "{\"candor\":{\"version\":\"" + v + "\"},\"functions\":[]}");
        writeSidecar(base, "{\"util.Fmt.fmt\":[],\"api.Api.fetch\":[\"util.Fmt.fmt\"]}");
        Map<String, EffectSet> inferred = new HashMap<>();
        inferred.put("util.Fmt.fmt", EffectSet.of(Effect.UNKNOWN)); // formerly pure, now only an unresolved call
        assertEquals(0, Policy.checkBaseline(inferred, base.toString()),
            "an Unknown-only gain is advisory (Unknown is not an effect), not an AS-EFF-005 regression");
    }

    @Test
    void baselineMixedRealPlusUnknownGainReportsOnlyTheRealEffect() throws Exception {
        // ⟨0.16⟩ A gain of a REAL effect (Fs) alongside Unknown is STILL a violation (exit 1), but
        // the reported effect set is the REAL gained set — Unknown is filtered out of what the finding shows.
        String v = ReportWriter.provenance()[0];
        Path base = file("base", "{\"candor\":{\"version\":\"" + v + "\"},\"functions\":[{\"fn\":\"a.B.c\",\"inferred\":[\"Net\"]}]}");
        Map<String, EffectSet> inferred = new HashMap<>();
        inferred.put("a.B.c", EffectSet.of(Effect.NET, Effect.FS, Effect.UNKNOWN)); // gained Fs (real) + Unknown
        assertEquals(1, Policy.checkBaseline(inferred, base.toString()),
            "gaining a real effect (even mixed with Unknown) is still an AS-EFF-005 regression");
    }

    @Test
    void baselineWithoutSidecarDegradesToReportOnly() throws Exception {
        // ⟨0.16⟩ No sidecar → existence is report-only (pre-⟨0.16⟩): a fn absent from the report is
        // indistinguishable from new code, so the pure→effectful transition slips through — NOT a failure,
        // the weaker guard, disclosed once on stderr. (Sidecar-present is baselineSidecarCatchesPureToEffectful.)
        String v = ReportWriter.provenance()[0];
        Path base = file("base", "{\"candor\":{\"version\":\"" + v + "\"},\"functions\":[]}");
        // deliberately NO writeSidecar — the .callgraph.json is absent
        Map<String, EffectSet> inferred = new HashMap<>();
        inferred.put("util.Fmt.fmt", EffectSet.of(Effect.FS));
        assertEquals(0, Policy.checkBaseline(inferred, base.toString()),
            "without a sidecar a pure→effectful fn reads as new code — the degraded guard does not fail");
    }

    @Test
    void baselineUnreadableDoesNotFail() throws Exception {
        Map<String, EffectSet> inferred = Map.of("a.B.c", EffectSet.of(Effect.NET));
        assertEquals(0, Policy.checkBaseline(inferred, "/no/such/baseline.json"),
            "an unreadable baseline disables the guard (returns 0), it does not fail the run");
    }

    // ── AS-EFF-007 taint + AS-EFF-004 ambient (advisory) ─────────────────────────────────────────────

    @Test
    void taintFlagsAnInjectionSurface() {
        ctx().tainted.put("x.Y.handle", EffectSet.of(Effect.FS));
        assertEquals(1, Policy.checkTaint(Map.of()), "a caller-derived Fs is an injection surface");
        Candor.resetState();
        assertEquals(0, Policy.checkTaint(Map.of()), "no tainted surface → no finding");
    }

    @Test
    void noAmbientFlagsDirectAmbientAuthorityInScope() {
        // AS-EFF-004's "ambient authority" set is 𝔼 \ {Log} (Candor.java:101) — every effect a class should
        // RECEIVE (via injection) rather than reach for directly. Note: this is NOT the §6.1 containment
        // ambient set (Log/Clock/Rand/Env) — so Clock/Net here are flagged, only Log is the carve-out.
        ctx().direct.put("svc.Svc.go", EffectSet.of(Effect.CLOCK));
        assertEquals(1, Policy.checkNoAmbient(Map.of("svc.Svc.go", EffectSet.of(Effect.CLOCK)), "svc"),
            "direct use of ambient authority (Clock) in scope is flagged");
        Candor.resetState();
        // Log is the sole carve-out (𝔼 \ {Log}) — emitting a log line is not reaching for ambient authority.
        ctx().direct.put("svc.Svc.log", EffectSet.of(Effect.LOG));
        assertEquals(0, Policy.checkNoAmbient(Map.of("svc.Svc.log", EffectSet.of(Effect.LOG)), "svc"),
            "Log is exempt from AS-EFF-004 (it is not ambient authority to inject)");
        Candor.resetState();
        // out of scope → not checked
        ctx().direct.put("other.X.go", EffectSet.of(Effect.CLOCK));
        assertEquals(0, Policy.checkNoAmbient(Map.of("other.X.go", EffectSet.of(Effect.CLOCK)), "svc"),
            "a method outside the scope is not flagged");
    }
}
