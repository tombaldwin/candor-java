package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.PolicyRule;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The CANDOR_POLICY grammar parser (SPEC §6.2) — each case below pins a real anti-regression the parser
 * carries (a security gate that silently mis-parses a rule lets a real violation through). Only `scopeMatches`
 * was unit-tested before; this covers `parsePolicy` itself.
 */
class PolicyParserTest {

    @BeforeEach
    void fresh() {
        Candor.resetState(); // a clean ctx() so denyRules/allowRules/forbidRules start empty
    }

    private static String parse(String body) throws Exception {
        Path p = Files.createTempFile("pol", ".policy");
        Files.writeString(p, body);
        p.toFile().deleteOnExit();
        assertTrue(Policy.parsePolicy(p.toString()), "a readable policy file must parse");
        return p.toString();
    }

    /** An inline `#` comment is stripped to end-of-line — its tokens must NOT survive as the scope (a bare
     *  startsWith("#") check once left `deny Exec # x` with scope="#", neutering the deny). */
    @Test
    void inlineCommentStrippedNotTakenAsScope() throws Exception {
        parse("deny Exec   # this is a comment, not a scope");
        assertEquals(1, ctx().denyRules.size());
        PolicyRule.Deny d = ctx().denyRules.get(0);
        assertTrue(d.effects().contains(Effect.EXEC));
        assertEquals("", d.scope(), "the comment must not become the scope");
    }

    /** Multiple effects then the first non-effect token is the scope (and ends the rule). */
    @Test
    void multiEffectThenScope() throws Exception {
        parse("deny Db Net   com.acme.domain");
        PolicyRule.Deny d = ctx().denyRules.get(0);
        assertTrue(d.effects().contains(Effect.DB) && d.effects().contains(Effect.NET));
        assertEquals("com.acme.domain", d.scope());
    }

    /** A `deny` naming NO known effect is DROPPED — it must NOT be reinterpreted as a `pure` (empty-effect)
     *  rule, which would forbid EVERYTHING. */
    @Test
    void denyWithNoKnownEffectIsDroppedNotPure() throws Exception {
        parse("deny notaneffect");
        assertTrue(ctx().denyRules.isEmpty(), "a deny with no known effect must be dropped, not become pure");
    }

    /** `pure <scope>` IS the empty-effect Deny (forbid any effect in scope). */
    @Test
    void pureIsEmptyEffectDeny() throws Exception {
        parse("pure com.acme.domain");
        assertEquals(1, ctx().denyRules.size());
        PolicyRule.Deny d = ctx().denyRules.get(0);
        assertTrue(d.effects().isEmpty());
        assertEquals("com.acme.domain", d.scope());
    }

    /** `forbid <A> -> <B>` needs the `->` as a spaced token; `a->b` without spaces is malformed → dropped. */
    @Test
    void forbidRequiresSpacedArrow() throws Exception {
        parse("forbid com.acme.web -> com.acme.db");
        assertEquals(1, ctx().forbidRules.size());
        assertEquals("com.acme.web", ctx().forbidRules.get(0).from());
        assertEquals("com.acme.db", ctx().forbidRules.get(0).to());
        fresh();
        parse("forbid com.acme.web->com.acme.db");
        assertTrue(ctx().forbidRules.isEmpty(), "an unspaced arrow is malformed and must be dropped");
    }

    /** `allow <Effect> in <scope> <values…>` parses the scope + values; a value-less allow is dropped (not
     *  left with "in" kept as a value), and only Net/Exec/Fs/Db carry an allow surface. */
    @Test
    void allowInScopeWithValues() throws Exception {
        parse("allow Net in com.acme.integration api.stripe.com api.internal");
        assertEquals(1, ctx().allowRules.size());
        PolicyRule.Allow a = ctx().allowRules.get(0);
        assertEquals(Effect.NET, a.effect());
        assertEquals("com.acme.integration", a.scope());
        assertTrue(a.values().contains("api.stripe.com") && a.values().contains("api.internal"));
        assertFalse(a.values().contains("in"), "the `in` keyword must not be kept as an allowed value");
    }

    @Test
    void valuelessAllowAndUnsupportedEffectAreDropped() throws Exception {
        parse("allow Net in");          // no values → dropped
        assertTrue(ctx().allowRules.isEmpty(), "a value-less allow must be dropped");
        fresh();
        parse("allow Log com.acme.x");  // Log has no literal surface → dropped
        assertTrue(ctx().allowRules.isEmpty(), "allow supports only Net/Exec/Fs/Db");
    }
}
