package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * FAMILY RULING (§6.2 ↔ §3.1): policy-scope segments split on the same boundaries as the query name
 * ladder — for the JVM that includes the {@code $} nested-type boundary. A verified cross-engine
 * divergence: {@code deny Net client} / {@code forbid app -> repo} matched a rust module member and a
 * swift enum-namespace member but NOT a function in a Java NESTED class ({@code q.L$app.entry}) — the
 * rule was silently inert on the engine whose flagship pitch is the architecture gate. These pin the
 * ruling at both altitudes: {@link Policy#scopeMatches} directly, and the AS-EFF-006/009 gate verdicts.
 */
class PolicyScopeNestedTypeTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void fresh() {
        Candor.resetState();
    }

    private Path policy(String body) throws Exception {
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, body);
        return p;
    }

    // ── the matcher: `$` is a segment boundary, same ladder as §3.1 name queries ─────────────────────

    @Test
    void nestedTypeBoundaryIsASegmentBoundary() {
        assertTrue(Policy.scopeMatches("q.L$app.entry", "app"),
            "a scope naming the nested class must match through the $ boundary");
        assertTrue(Policy.scopeMatches("Outer$client.entry", "client.entry"),
            "a multi-segment scope must match across the $ boundary");
        assertTrue(Policy.scopeMatches("com.acme.Outer$Repo.save", "Outer.Repo"),
            "the $ boundary and the dot boundary are the same ladder");
    }

    @Test
    void nestedCousinDoesNotMatch() {
        // intermediate segments are EXACT (only the LAST is a prefix — the rust scope_matches contract),
        // so a scope anchored past the nested segment must not hit the `clientx` cousin.
        assertFalse(Policy.scopeMatches("Outer$clientx.entry", "client.entry"),
            "the nested cousin `clientx` must not match an exact intermediate `client`");
        assertFalse(Policy.scopeMatches("Outer$client.entry", "clientx"),
            "an unrelated scope still misses");
    }

    // ── AS-EFF-006: the deny verdict bites on a nested-class function ────────────────────────────────

    @Test
    void denyScopeHitsANestedClassFunction() throws Exception {
        Path pol = policy("deny Net client");
        Map<String, EffectSet> inferred = Map.of("Outer$client.entry", EffectSet.of(Effect.NET));
        assertEquals(1, Policy.checkPolicy(inferred, pol.toString()),
            "deny Net client must bite on Outer$client.entry (the nested-type ruling)");
    }

    @Test
    void denyScopeStillMissesAnUnrelatedNestedClass() throws Exception {
        // `client` as the LAST scope segment start-matches `clientx` (the documented domain/domain_logic
        // prefix rule, unchanged) — so pin the miss with the exact-intermediate form instead.
        Path pol = policy("deny Net client.entry");
        Map<String, EffectSet> inferred = Map.of("Outer$clientx.entry", EffectSet.of(Effect.NET));
        assertEquals(0, Policy.checkPolicy(inferred, pol.toString()),
            "an exact-intermediate scope must not hit the `clientx` cousin");
    }

    // ── AS-EFF-009: forbid app -> repo bites across nested classes ───────────────────────────────────

    @Test
    void forbidBitesAcrossNestedClasses() throws Exception {
        Path pol = policy("forbid app -> repo");
        // q.L$app.entry -> q.L$repo.save, both nested classes of q.L (the conformance-battery shape).
        ctx().edges.put("q.L$app.entry", new HashSet<>(Set.of("q.L$repo.save")));
        ctx().edges.put("q.L$repo.save", new HashSet<>());
        assertEquals(1, Policy.checkPolicy(Map.of(), pol.toString()),
            "forbid app -> repo must bite when both layers are nested classes");
    }

    @Test
    void forbidStaysQuietWithoutTheForbiddenReach() throws Exception {
        Path pol = policy("forbid app -> repo");
        ctx().edges.put("q.L$app.entry", new HashSet<>(Set.of("q.L$svc.helper")));
        ctx().edges.put("q.L$svc.helper", new HashSet<>());
        assertEquals(0, Policy.checkPolicy(Map.of(), pol.toString()),
            "no reach into the forbidden layer, no violation");
    }
}
