package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.PolicyRule;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The CANDOR_POLICY grammar parser (SPEC §6.2) — each case below pins a real anti-regression the parser
 * carries (a security gate that silently mis-parses a rule lets a real violation through). Only `scopeMatches`
 * was unit-tested before; this covers `parsePolicy` itself.
 */
class PolicyParserTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void fresh() {
        Candor.resetState(); // a clean ctx() so denyRules/allowRules/forbidRules start empty
    }

    private String parse(String body) throws Exception {
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, body);
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

    /**
     * ⟨0.24⟩ <b>AN UNRECOGNISED CLASS TOKEN IS A POLICY ERROR — SPEC §6.2</b> (candor-spec 382a7e0). The
     * clause used to justify leaving the policy side at drop-with-warning by asserting that a dropped
     * token "leaves a WIDER rule standing, so the failure is loud". Measured, it does BOTH, and one of the
     * two directions was a hole the whole time the clause claimed there was none.
     *
     * <p>MEASURED on this engine at 2cdc443, via {@code candor parsepolicy} (which dumps the rules the
     * gate would actually run):
     * <pre>
     *   deny Unknown[corp] app            -> exit 0, rule KEPT as bare `deny Unknown`   (WIDENS)
     *   deny Unknown[dispatch,nativ] app  -> exit 0, rule KEPT as `Unknown[dispatch]`   (NARROWS)
     *   deny Net[known-partner,unkown-host] app
     *                                     -> exit 0, rule KEPT as `Net[known-partner]`  (NARROWS)
     * </pre>
     * The first printed <i>"ignoring policy rule (unknown reason-class/alias `corp`)"</i> and then kept
     * and re-scoped the rule — a FALSE DISCLOSURE. The second and third are worse, and are the COMMON
     * case: a typo lands beside correct tokens far more often than alone, and there the rule silently
     * NARROWS, so it stops gating native-caused holes (resp. unknown hosts) while the operator reads a
     * gate that looks armed. That is fail-open.
     *
     * <p>The typo-beside-valid-tokens rows are the ones that will regress, so they are asserted first and
     * for BOTH class vocabularies.
     */
    @Test
    void anUnrecognisedClassTokenIsAPolicyErrorNotASilentRewrite() throws Exception {
        // ── THE FAIL-OPEN HALF: a typo BESIDE valid tokens, which NARROWS ──
        assertPolicyError("deny Unknown[dispatch,nativ] app\n", "nativ",
                "a typo beside valid reason-class tokens silently NARROWED the rule to `[dispatch]`, so it "
                + "stopped gating native-caused holes while the gate still looked armed");
        assertPolicyError("deny Net[known-partner,unkown-host] app\n", "unkown-host",
                "same shape on the Net destination-class vocabulary: the rule NARROWED to "
                + "`[known-partner]` and stopped gating unknown hosts");

        // ── THE FALSE-DISCLOSURE HALF: the sole token, which WIDENS while claiming to be ignored ──
        assertPolicyError("deny Unknown[corp] app\n", "corp",
                "the sole unrecognised token emptied the filter, so the rule WIDENED to a bare "
                + "`deny Unknown` — while the engine printed `ignoring policy rule`, which it did not do");
        assertPolicyError("deny Net[unkown-host] app\n", "unkown-host",
                "…and the same on the Net side");

        // ── CONTROLS. Without these the test passes on a parser that rejects every scoped rule. ──
        fresh();
        parse("deny Unknown[dispatch,native,unresolved] app\n");
        assertEquals(1, ctx().denyRules.size(), "CONTROL: all-valid reason-class tokens still parse");
        fresh();
        parse("deny Net[known-partner,unknown-host] app\n");
        assertEquals(1, ctx().denyRules.size(), "CONTROL: all-valid destination-class tokens still parse");
        fresh();
        parse("deny Unknown[dynamic] app\n");
        assertEquals(1, ctx().denyRules.size(), "CONTROL: the `dynamic` alias is not a typo");
        fresh();
        parse("deny Unknown[*] app\n");
        assertEquals(1, ctx().denyRules.size(), "CONTROL: `*` is not a typo either");

        // A config-declared `unknown-alias` is the REMEDY the diagnostic names, so it must actually work —
        // otherwise the error is a dead end and the operator has nowhere to go.
        fresh();
        ctx().unknownAliases.put("corp", java.util.Set.of(io.poly.candor.model.ReasonClass.NATIVE));
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, "deny Unknown[corp,unresolved] app\n");
        assertTrue(Policy.parsePolicy(p.toString()),
                "CONTROL: a config `unknown-alias` resolves — the remedy the diagnostic names is real");
        assertEquals(1, ctx().denyRules.size());
    }

    /**
     * ⟨0.24⟩ SPEC §3.1 — EVERY offending token is recorded, not just the first, and the FILE-unreadable case
     * stays distinguishable from the token case. Both exist for the `parsepolicy` witness (candor-spec
     * 6929dce): it must name them ALL (stopping at the first sends the operator round the loop once per
     * typo) and it must still REFUSE when there is no parse to show. The gate takes the first — it does not
     * matter which token defeated it.
     */
    @Test
    void everyUnhonourableTokenIsRecordedAndAnUnreadableFileStaysDistinct() throws Exception {
        fresh();
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, "deny Unknown[dispatch,nativ] app\ndeny Net[unkown-host] app\n");
        assertFalse(Policy.parsePolicy(p.toString()));
        assertEquals(List.of("nativ", "unkown-host"),
                Policy.policyErrors.stream().map(Policy.PolicyTokenError::token).toList(),
                "both tokens, in file order — a witness that stops at the first hides the second typo");
        assertFalse(Policy.policyUnreadable, "the file READ fine; it is the tokens that cannot be honoured");
        assertTrue(Policy.policyErrors.get(0).accepted().contains("dispatch"),
                "the accepted set travels as DATA, not only inside the prose message");

        fresh();
        assertFalse(Policy.parsePolicy(tmp.resolve("nope.policy").toString()));
        assertTrue(Policy.policyUnreadable,
                "an unreadable FILE is the other failure — `parsepolicy` refuses THAT one, since there is "
                + "no parse to report");
        assertTrue(Policy.policyErrors.isEmpty());
        assertTrue(Policy.policyFailure(tmp.resolve("nope.policy").toString()).contains("could not be read"),
                "…and it keeps its own wording");
    }

    /**
     * ⟨0.24⟩ SPEC §3.1 (candor-spec {@code 195d45a}) — <b>{@code errors} CARRIES EVERY LINE THE ENGINE DID
     * NOT HONOUR AS WRITTEN, not only unrecognised tokens.</b>
     *
     * <p>MEASURED on the conformance battery the moment the list existed: {@code parsepolicy} reported 2
     * token errors while its stderr reported 8 further lines DROPPED entirely — an unknown effect name, an
     * {@code allow} on an effect with no literal surface, two malformed {@code forbid}s, an unknown rule
     * kind. None reached the machine output. A dropped rule is the LIMIT CASE of "silently rewritten into a
     * different policy": the rewritten policy is the one WITHOUT that line, which is a bigger rewrite than
     * a narrowed filter, not a smaller one. The witness was disclosing the two cases that prompted the
     * clause and staying silent on the rest.
     *
     * <p>The gate's behaviour over a dropped rule is DELIBERATELY UNCHANGED, and the second block pins
     * that: the parser cannot tell {@code deny Net Exex app} from a legitimate scope, so making unknown
     * effect names refuse is a GRAMMAR change rather than a token change, and that question stays open.
     * Reporting needs no such decision — and until it is reported nobody can measure how often it happens.
     */
    @Test
    void errorsCarriesEveryLineTheEngineDidNotHonour() throws Exception {
        fresh();
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, String.join("\n",
                "deny Net domain",                       // honoured — the control that the parse still works
                "deny notaneffect",                      // dropped: unknown effect name
                "allow Clock whatever",                  // dropped: no literal surface for Clock
                "forbid bad",                            // dropped: malformed
                "forbid glued->arrow",                   // dropped: the arrow must be its own token
                "allow Net in",                          // dropped: names no values
                "nonsense line",                         // dropped: unknown rule kind
                "deny Unknown[bogus] api") + "\n");      // FATAL: an unrecognised class token
        assertFalse(Policy.parsePolicy(p.toString()),
                "the FATAL token still refuses — dropped lines must not dilute that");

        String json = Query.policyJson();
        com.google.gson.JsonArray errs =
                com.google.gson.JsonParser.parseString(json).getAsJsonObject().getAsJsonArray("errors");
        assertEquals(7, errs.size(), "6 dropped lines + 1 unhonourable token — a witness that reports the "
                + "token and stays silent on the six DROPPED rules is silent about the bigger rewrite: " + json);

        List<String> rules = errs.asList().stream()
                .map(e -> e.getAsJsonObject().get("rule").getAsString()).toList();
        assertEquals(List.of("deny notaneffect", "allow Clock whatever", "forbid bad", "forbid glued->arrow",
                        "allow Net in", "nonsense line", "deny Unknown[bogus] api"), rules,
                "every unhonoured line, verbatim, in FILE ORDER — the operator reads these against their "
                + "policy top-to-bottom: " + rules);

        // The SHAPE is pinned (§3.1): exactly {kind, token, accepted, rule, message}, no more. A sixth key
        // here would be this engine inventing a field the other three would each have to guess at.
        for (var e : errs)
            assertEquals(List.of("kind", "token", "accepted", "rule", "message"),
                    List.copyOf(e.getAsJsonObject().keySet()), "the pinned entry shape: " + e);

        // …and each entry says WHICH vocabulary failed and WHICH token, as data rather than only in prose.
        assertEquals("effect name", errs.get(0).getAsJsonObject().get("kind").getAsString());
        assertEquals("notaneffect", errs.get(0).getAsJsonObject().get("token").getAsString());
        assertTrue(errs.get(0).getAsJsonObject().getAsJsonArray("accepted").toString().contains("Net"),
                "the accepted set travels with it, as data: " + errs.get(0));
        assertTrue(errs.get(0).getAsJsonObject().get("message").getAsString().contains("DROPPED"),
                "…and a dropped line says it was DROPPED, not that a token was unknown: " + errs.get(0));
        assertEquals("rule kind", errs.get(5).getAsJsonObject().get("kind").getAsString());
        assertEquals("nonsense", errs.get(5).getAsJsonObject().get("token").getAsString());

        // ADDITIVE TO THE WITNESS, SILENT ABOUT THE GATE. With the fatal token removed, a policy full of
        // dropped lines still PARSES — they are reported and the gate runs the rules that survived, exactly
        // as before. Turning them into refusals is a grammar change and stays open.
        fresh();
        Path q = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(q, "deny Net domain\ndeny notaneffect\nnonsense line\n");
        assertTrue(Policy.parsePolicy(q.toString()),
                "a DROPPED line must not make the gate refuse — that question is deliberately still open, "
                + "because the parser cannot tell `deny Net Exex app` from a legitimate scope");
        assertEquals(1, ctx().denyRules.size(), "…and exactly the honoured rule survives");
        assertEquals(2, com.google.gson.JsonParser.parseString(Query.policyJson()).getAsJsonObject()
                        .getAsJsonArray("errors").size(),
                "…while both dropped lines are still REPORTED");

        // CONTROL — a clean policy emits NO `errors` key at all, so a clean battery's dump stays
        // byte-identical to the pre-feature one and the four-way deny/allow/forbid diff is untouched.
        fresh();
        parse("deny Net domain\nallow Net in domain example.com\nforbid domain -> infra\n");
        assertFalse(com.google.gson.JsonParser.parseString(Query.policyJson()).getAsJsonObject().has("errors"),
                "CONTROL: `errors` is OMITTED when empty: " + Query.policyJson());
    }

    /** Parse the body and require the ⟨0.24⟩ policy-error posture: {@code parsePolicy} returns FALSE, the
     *  diagnostic NAMES the offending token and the accepted set, and NO rule survives — the policy is not
     *  rewritten into a different one. */
    private void assertPolicyError(String body, String token, String why) throws Exception {
        fresh();
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, body);
        assertFalse(Policy.parsePolicy(p.toString()), why + " — parsePolicy must REJECT: " + body.trim());
        String msg = Policy.policyFailure(p.toString());
        assertTrue(msg.contains("`" + token + "`"), "the diagnostic must NAME the token `" + token
                + "`, so the operator does not have to guess which one: " + msg);
        assertTrue(msg.contains("known:"), "…and list the accepted set: " + msg);
        // The rule may sit in ctx() as a parse artefact, but the CALLER exits 2 before evaluating it —
        // asserted end-to-end by GateReportVerbTest#anUnrecognisedClassTokenRefusesTheWholeGate.
    }
}
