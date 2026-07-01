package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The `--gate-json` structured capture (Candor.gateViolations): every AS-EFF diagnostic is recorded at the
 * one {@link Candor#diag} sink as {rule, fn, detail} — the machine analog of the console lines, the SAME
 * source the exit code rides on, powering the PR-native SARIF reporter (integrations/github). Contract:
 * captures ONLY when gateCapture is on (byte-identical output otherwise), one entry per emitted violation,
 * fn = the diagnostic's subject, rule = the spec code.
 */
class GateJsonTest {

    @BeforeEach
    void fresh() {
        Candor.resetState();
        Candor.gateViolations.clear();
        Candor.gateCapture = false;
    }

    @AfterEach
    void clearCapture() {
        Candor.gateCapture = false;   // never leak the flag into a sibling test
        Candor.gateViolations.clear();
    }

    private static Path policy(String body) throws Exception {
        Path p = Files.createTempFile("pol", ".policy");
        Files.writeString(p, body);
        p.toFile().deleteOnExit();
        return p;
    }

    @Test
    void capturesADenyViolationStructurally() throws Exception {
        Candor.gateCapture = true;
        Path pol = policy("deny Fs app.domain");
        Map<String, EffectSet> inferred = Map.of("app.domain.Order.audit", EffectSet.of(Effect.FS));
        int v = Policy.checkPolicy(inferred, pol.toString());

        assertEquals(1, v, "one deny violation");
        assertEquals(1, Candor.gateViolations.size(), "one structured entry, matching the count");
        var e = Candor.gateViolations.get(0);
        assertEquals("AS-EFF-006", e.get("rule"));
        assertEquals("app.domain.Order.audit", e.get("fn"), "fn is the diagnostic subject (args[0])");
        assertEquals(java.util.List.of("Fs"), e.get("effects"),
            "effects is the DENIED set (what the fn does ∩ what the rule forbids), not the fn's full direct set");
        assertTrue(((String) e.get("detail")).contains("forbidden by policy"),
            "detail carries the engine's own message (the SARIF message body)");
        // the detail is the message BODY, without the bracketed code prefix (the ruleId carries the code).
        assertFalse(((String) e.get("detail")).startsWith("[AS-EFF"), "no code prefix in detail");
    }

    @Test
    void effectsIsTheDeniedSubsetNotTheFullEffectSet() throws Exception {
        // The reason `effects` can't be reconstructed from the report: a fn that does { Clock, Fs } under
        // `deny Fs` violates on Fs ONLY. The report's direct set is { Clock, Fs }; the verdict's effects is
        // { Fs } — the intersection a consumer needs for a precise message / codeFlow.
        Candor.gateCapture = true;
        Path pol = policy("deny Fs app.domain");
        var inferred = Map.of("app.domain.Order.audit", EffectSet.of(Effect.CLOCK, Effect.FS));
        Policy.checkPolicy(inferred, pol.toString());
        assertEquals(1, Candor.gateViolations.size());
        assertEquals(java.util.List.of("Fs"), Candor.gateViolations.get(0).get("effects"),
            "effects is the DENIED intersection { Fs }, not the fn's full { Clock, Fs }");
    }

    @Test
    void capturesEveryViolationOncePerFn() throws Exception {
        Candor.gateCapture = true;
        Path pol = policy("deny Fs app.domain");
        Map<String, EffectSet> inferred = new java.util.TreeMap<>(Map.of(
            "app.domain.A.read", EffectSet.of(Effect.FS),
            "app.domain.B.read", EffectSet.of(Effect.FS),
            "app.domain.C.pure", EffectSet.empty()));   // pure — no violation
        int v = Policy.checkPolicy(inferred, pol.toString());

        assertEquals(2, v);
        assertEquals(2, Candor.gateViolations.size(), "one entry per violating fn, the pure fn excluded");
        assertTrue(Candor.gateViolations.stream().allMatch(m -> m.get("rule").equals("AS-EFF-006")));
    }

    @Test
    void capturesNothingWhenGateCaptureIsOff() throws Exception {
        // The default (no --gate-json): the checker still runs + prints, but records NOTHING — this is what
        // keeps the report/console byte-identical when the flag is absent.
        assertFalse(Candor.gateCapture);
        Path pol = policy("deny Fs app.domain");
        int v = Policy.checkPolicy(Map.of("app.domain.Order.audit", EffectSet.of(Effect.FS)), pol.toString());
        assertEquals(1, v, "the violation still counts (exit code unaffected)");
        assertTrue(Candor.gateViolations.isEmpty(), "but nothing is captured when the flag is off");
    }

    @Test
    void aCleanPolicyCapturesNoViolations() throws Exception {
        Candor.gateCapture = true;
        Path pol = policy("deny Net app.domain");   // no Net present
        int v = Policy.checkPolicy(Map.of("app.domain.Order.audit", EffectSet.of(Effect.FS)), pol.toString());
        assertEquals(0, v);
        assertTrue(Candor.gateViolations.isEmpty(), "ok run → empty violations list");
    }
}
