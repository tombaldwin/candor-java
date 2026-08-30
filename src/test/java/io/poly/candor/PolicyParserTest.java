package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.PolicyRule;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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

    /** ⟨0.24⟩ The CLOSED `errors[].kind` set SPEC §3.1 pins (candor-spec {@code f735b16}). Written out here
     *  rather than read from the engine on purpose: a test that derives the admissible set from the code it
     *  is checking cannot catch the code widening it. */
    static final List<String> CLOSED_KINDS = List.of(
            "reason-class/alias", "Net destination-class", "effect-name", "rule-kind", "rule-form");

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

    /**
     * A `deny` naming NO known effect must NOT be reinterpreted as a `pure` (empty-effect) rule, which
     * would forbid EVERYTHING.
     *
     * <p>⟨0.24⟩ …and it is no longer merely DROPPED either (candor-spec {@code 1e1748a}): a `deny` whose
     * effect list is empty after scope-splitting is a POLICY ERROR. Measured before, `deny Nett app` exited
     * 0 four-way — the rule silently deleted, the operator reading an armed `deny Net` where no gate
     * existed. This document already calls a dropped rule "the limit case of silently rewritten into a
     * different policy… a bigger rewrite than a narrowed filter", and the narrowed filter was already
     * exit 2. The misreading-as-`pure` invariant is unchanged and asserted alongside.
     */
    @Test
    void denyWithNoKnownEffectIsAPolicyErrorNotPure() throws Exception {
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, "deny notaneffect\n");
        assertFalse(Policy.parsePolicy(p.toString()),
                "a `deny` left with no effect is malformed under EITHER reading — there is no legitimate "
                + "policy it could be, so refusing it loses nothing");
        assertTrue(ctx().denyRules.isEmpty(),
                "…and it certainly must not become a `pure` rule, which would forbid EVERYTHING");
        assertTrue(Policy.policyUnhonourable(), "the GATE refuses over it (exit 2), it is not a warning");
    }

    /**
     * THE AMBIGUOUS MIDDLE STAYS PERMISSIVE — deliberately, and this is the control that keeps the ruling
     * above from over-reaching. `deny Net Exex app` cannot be told from a legitimate scope by the parser:
     * an effect survived, so `Exex` reads as the scope. Only the two unambiguous cases are errors.
     */
    @Test
    void aTrailingUnknownTokenBesideAValidEffectIsStillAScope() throws Exception {
        parse("deny Net Exex app");
        assertEquals(1, ctx().denyRules.size(), "the rule is KEPT — the parser has no way to know `Exex` is "
                + "not the scope the operator meant");
        assertEquals("Exex", ctx().denyRules.get(0).scope());
        assertFalse(Policy.policyUnhonourable(), "…and the gate is not refused over it");
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

    /**
     * ⟨0.29⟩ `only <A> -> <B> [<C> …]`'s OWN malformed-form drop — the sibling of {@link
     * #forbidRequiresSpacedArrow} for a rule kind `forbid`'s test does not exercise. {@code only} reuses
     * the identical {@code t.length >= 4 && t[2].equals("->")} shape and the identical {@link
     * Policy#warnPolicy} call, but is a SEPARATE {@code case} in the parser's switch (added a whole rung
     * later, ⟨0.29⟩) — a distinct call site nothing before this test drove. Before this test, deleting the
     * {@code warnPolicy} call from the {@code only} arm entirely (turning the drop silent — no stderr
     * warning, no {@link Policy#policyErrors} entry, no {@code ignored} row in the verdict document) left
     * the FULL suite green: {@code onlyRules} was already empty either way, because the {@code if} that
     * adds the rule never fired — only the DISCLOSURE was unprotected, and nothing exercised it. This is
     * the A.2 shape named in the corpus brief: one grammar rule's malformed-form drop tested, its sibling
     * rule kind's identical-shaped drop not. */
    @Test
    void onlyRequiresSpacedArrowAndDropsWithDisclosure() throws Exception {
        parse("only app.M -> app.util app.infra");
        assertEquals(1, ctx().onlyRules.size());
        assertEquals("app.M", ctx().onlyRules.get(0).from());
        assertEquals(List.of("app.util", "app.infra"), ctx().onlyRules.get(0).to());
        fresh();
        parse("only app.M->app.util");
        assertTrue(ctx().onlyRules.isEmpty(), "an unspaced arrow is malformed and must be dropped, exactly "
                + "as `forbid`'s");
        assertEquals(1, Policy.policyErrors.size(),
                "the drop must be RECORDED — a silent drop here is indistinguishable from the operator's "
                + "permission list actually having no rule at all, which is fail-OPEN for a form whose "
                + "entire point is to fail safe");
        assertEquals("rule-form", Policy.policyErrors.get(0).kind());
        assertTrue(Policy.policyErrors.get(0).message().contains("DROPPED"),
                "…and the message says DROPPED, not merely that a token failed: "
                + Policy.policyErrors.get(0).message());
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

    /** A value-less `allow` is a FORM failure, not a vocabulary one — it stays a DROP (the ⟨0.24⟩ ruling
     *  closes the effect POSITION, and this token is not in it). */
    @Test
    void valuelessAllowIsDropped() throws Exception {
        parse("allow Net in");          // no values → dropped
        assertTrue(ctx().allowRules.isEmpty(), "a value-less allow must be dropped");
    }

    /**
     * ⟨0.24⟩ <b>`allow`'s EFFECT POSITION IS A FIXED, CLOSED SET, so an unrecognised token there is a
     * POLICY ERROR</b> (candor-spec {@code 1e1748a}). Unlike `deny`, there is no scope reading available in
     * that position at all — `allow Nett host.example` is unambiguously a typo — and dropping it made the
     * certification silently vanish while the operator read one that was armed. Measured before:
     * {@code allow Nett host.example} exited 0 on all four engines.
     *
     * <p>`Log` is the same error for a different reason: a real effect name, but not one carrying a
     * literal surface, so `allow Log …` names no allowlist this engine can enforce either.
     */
    @Test
    void anAllowOnAnEffectOutsideTheClosedSetIsAPolicyError() throws Exception {
        for (String body : List.of("allow Nett host.example\n", "allow Log com.acme.x\n")) {
            fresh();
            Path p = Files.createTempFile(tmp, "pol", ".policy");
            Files.writeString(p, body);
            assertFalse(Policy.parsePolicy(p.toString()),
                    "the effect position is closed — a token outside it is a typo, never a scope: " + body.trim());
            assertTrue(ctx().allowRules.isEmpty(), "…and no rule is manufactured from it");
        }
        // CONTROL: every member of the closed set still parses, so the test cannot pass on a parser that
        // rejects `allow` outright.
        for (String eff : List.of("Net", "Llm", "Exec", "Fs", "Db")) {
            fresh();
            parse("allow " + eff + " in com.acme.x somevalue\n");
            assertEquals(1, ctx().allowRules.size(), "CONTROL: `allow " + eff + "` still parses");
        }
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
     * <p>⟨0.24⟩ The population shifted under {@code 1e1748a}: a typo'd EFFECT NAME is now FATAL on both
     * `deny` and `allow`, so those two lines moved from the dropped half to the refusing half. What stays
     * DROPPED is exactly what the ruling left open — the FORM failures (a malformed `forbid`, a value-less
     * `allow`) and an unknown rule kind — and the second block still pins that the gate does not refuse
     * over them.
     */
    @Test
    void errorsCarriesEveryLineTheEngineDidNotHonour() throws Exception {
        fresh();
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, String.join("\n",
                "deny Net domain",                       // honoured — the control that the parse still works
                "deny notaneffect",                      // ⟨0.24⟩ FATAL: the effect list ends up EMPTY
                "allow Clock whatever",                  // ⟨0.24⟩ FATAL: outside `allow`'s closed effect set
                "forbid bad",                            // dropped: malformed FORM
                "forbid glued->arrow",                   // dropped: the arrow must be its own token
                "allow Net in",                          // dropped: names no values
                "nonsense line",                         // dropped: unknown rule kind
                "deny Unknown[bogus] api") + "\n");      // FATAL: an unrecognised class token
        assertFalse(Policy.parsePolicy(p.toString()),
                "the FATAL tokens still refuse — dropped lines must not dilute that");

        String json = Query.policyJson();
        com.google.gson.JsonArray errs =
                com.google.gson.JsonParser.parseString(json).getAsJsonObject().getAsJsonArray("errors");
        assertEquals(7, errs.size(), "4 dropped lines + 3 unhonourable ones — a witness that reports the "
                + "tokens and stays silent on the DROPPED rules is silent about the bigger rewrite: " + json);

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
        assertEquals("effect-name", errs.get(0).getAsJsonObject().get("kind").getAsString());
        assertEquals("notaneffect", errs.get(0).getAsJsonObject().get("token").getAsString());
        assertTrue(errs.get(0).getAsJsonObject().getAsJsonArray("accepted").toString().contains("Net"),
                "the accepted set travels with it, as data: " + errs.get(0));
        assertTrue(errs.get(0).getAsJsonObject().get("message").getAsString().contains("unknown effect-name"),
                "⟨0.24⟩ a FATAL effect name says the token was unknown, not that the line was dropped — the "
                + "line was refused over, not silently removed: " + errs.get(0));
        assertEquals("effect-name", errs.get(1).getAsJsonObject().get("kind").getAsString(),
                "…and `allow`'s effect position reports the SAME vocabulary, differing only in `accepted`");
        assertTrue(errs.get(2).getAsJsonObject().get("message").getAsString().contains("DROPPED"),
                "…while a FORM failure is still a DROP and still says so: " + errs.get(2));
        assertEquals("rule-kind", errs.get(5).getAsJsonObject().get("kind").getAsString());
        assertEquals("nonsense", errs.get(5).getAsJsonObject().get("token").getAsString());

        // ADDITIVE TO THE WITNESS, SILENT ABOUT THE GATE. With the fatal lines removed, a policy full of
        // dropped lines still PARSES — they are reported and the gate runs the rules that survived, exactly
        // as before. ⟨0.24⟩ closed only the two unambiguous positions; the FORM failures stay open.
        fresh();
        Path q = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(q, "deny Net domain\nforbid glued->arrow\nnonsense line\n");
        assertTrue(Policy.parsePolicy(q.toString()),
                "a DROPPED line must not make the gate refuse — that question is deliberately still open "
                + "for the FORM failures, which have no closed vocabulary to be measured against");
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

    /**
     * ⟨0.24⟩ SPEC §3.1 (candor-spec {@code f735b16}) — <b>{@code errors[].accepted} IS AN ARRAY OF TOKENS
     * and {@code kind} is drawn from a CLOSED set of FIVE</b>: {@code reason-class/alias}, {@code Net
     * destination-class}, {@code effect-name}, {@code rule-kind}, {@code rule-form}. The measured
     * divergence was candor-ts emitting {@code accepted} as a PROSE STRING (unparseable by the consumer the
     * field exists for) and renaming {@code kind}/{@code rule} to {@code vocabulary}/{@code where}.
     *
     * <p><b>THE DIVERGENCE THIS ENGINE CARRIED, now closed at the SPEC end.</b> Two of this engine's rows
     * report a FORM failure rather than a vocabulary one — a malformed {@code forbid} and a value-less
     * {@code allow} — and the four-member set had no member for them, so they shipped as {@code forbid
     * form} / {@code allow values}: outside the set, and unhyphenated, so not machine-comparable with any
     * other engine's answer. Reporting rather than folding them into {@code rule-kind} was right — {@code
     * rule-kind} would have told a consumer that {@code forbid} is not a known rule kind, which is false —
     * and the ruling was to widen the DOMAIN, not the reading: {@code rule-form} is the fifth member.
     *
     * <p><b>The mirror this test guards is that the widening did not COLLAPSE the two.</b> {@code frobid a
     * -&gt; b} names no rule kind at all and stays {@code rule-kind}; {@code forbid glued-&gt;arrow} names
     * one and is {@code rule-form}. Those are different failures with different remedies (respell the head
     * token vs. fix the line's shape), and a consumer that cannot tell them apart is back where the prose
     * spellings left it.
     */
    @Test
    void everyErrorRowCarriesAnAcceptedArrayAndAPinnedKind() throws Exception {
        fresh();
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, String.join("\n",
                "deny Unknown[corp] app",                // reason-class/alias
                "deny Net[unkown-host] app",             // Net destination-class
                "deny Nett app",                         // effect-name (deny position)
                "allow Nett host.example",               // effect-name (allow position)
                "frobid a -> b",                         // rule-kind  — the head token names NO rule
                "forbid glued->arrow",                   // rule-form  — `forbid` IS a rule; the FORM failed
                "allow Net in") + "\n");                 // rule-form  — likewise
        assertFalse(Policy.parsePolicy(p.toString()));

        com.google.gson.JsonArray errs = com.google.gson.JsonParser.parseString(Query.policyJson())
                .getAsJsonObject().getAsJsonArray("errors");
        List<String> kinds = errs.asList().stream()
                .map(e -> e.getAsJsonObject().get("kind").getAsString()).toList();
        assertEquals(List.of("reason-class/alias", "Net destination-class", "effect-name", "effect-name",
                        "rule-kind", "rule-form", "rule-form"), kinds,
                "every `kind` is one of the pinned CLOSED FIVE, hyphenated: " + kinds);
        // THE CLOSED SET, asserted as a set membership rather than as this row order — so a NEW error site
        // added later cannot introduce a sixth spelling without this failing.
        assertEquals(List.of(), kinds.stream().distinct()
                        .filter(k -> !CLOSED_KINDS.contains(k)).toList(),
                "nothing outside the closed five is invented; the set is " + CLOSED_KINDS);
        // THE MIRROR: `rule-form` must not have SWALLOWED `rule-kind`. A head token that names no rule at
        // all is a KIND failure and must still say so — collapsing the two would trade one false
        // disclosure ("`forbid` is not a rule kind") for its opposite ("`frobid` is one, badly spelled").
        assertEquals("rule-kind", errs.get(4).getAsJsonObject().get("kind").getAsString(),
                "`frobid a -> b` names no rule kind — that is a KIND failure, not a FORM one");
        assertEquals("rule-form", errs.get(5).getAsJsonObject().get("kind").getAsString(),
                "`forbid glued->arrow` names a REAL rule kind whose line is malformed");
        // …and the two are distinguishable BY VALUE, not only by the prose in `message`.
        assertNotEquals(errs.get(4).getAsJsonObject().get("kind").getAsString(),
                errs.get(5).getAsJsonObject().get("kind").getAsString(),
                "FORM and KIND are different failures and must not share one value");

        for (var e : errs) {
            var row = e.getAsJsonObject();
            assertTrue(row.get("accepted").isJsonArray(),
                    "`accepted` is an ARRAY OF TOKENS — a prose string is unparseable by the consumer the "
                    + "field exists for: " + row);
            for (var tok : row.getAsJsonArray("accepted"))
                assertTrue(tok.isJsonPrimitive() && tok.getAsJsonPrimitive().isString(),
                        "…of strings: " + row);
            assertTrue(row.get("token").isJsonPrimitive(), "`token` is the thing not recognised: " + row);
            assertTrue(row.get("rule").isJsonPrimitive(), "`rule` is the raw line, NOT renamed `where`: " + row);
        }
        // `accepted` may be EMPTY (a form failure has no fixed admissible set) but it is still an array —
        // the shape does not change with the population.
        assertEquals(0, errs.get(6).getAsJsonObject().getAsJsonArray("accepted").size(),
                "a value-less `allow` has no fixed accepted set; the key stays an (empty) array");
    }

    /**
     * ⟨0.24⟩ THE END-TO-END HALF OF {@code 1e1748a}: the harm measured was an EXIT CODE, not a parse
     * artefact. {@code deny Nett app} and {@code allow Nett host.example} both exited <b>0</b> on all four
     * engines — the operator reads an armed gate that does not exist. Asserted through the real CLI
     * dispatcher over a report that would make a correctly-spelled rule fire, so a green here would be a
     * green on genuinely violating code.
     */
    @Test
    void aTypodEffectNameRefusesTheGateRatherThanExitingZero() throws Exception {
        Path rep = tmp.resolve("t.jvm.json");
        Files.writeString(rep, io.poly.candor.model.ReportJson.pretty(java.util.Map.of(
                "candor", java.util.Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION),
                "packages", List.of("app"),
                "analyzed", java.util.Map.of("count", 1, "digest", "0"),
                "functions", List.of(java.util.Map.of("fn", "app.S.get", "inferred", List.of("Net"),
                        "direct", List.of("Net"), "hosts", List.of("evil.example"),
                        "netClass", List.of("unknown-host"))))));

        for (String body : List.of("deny Nett app\n", "allow Nett evil.example\n")) {
            fresh();
            Path pol = Files.createTempFile(tmp, "pol", ".policy");
            Files.writeString(pol, body);
            assertEquals(2, Query.run(new String[]{"gate", "--report", rep.toString(),
                            "--policy", pol.toString()}),
                    "a typo'd effect name must REFUSE (exit 2), never exit 0 over a rule it deleted: "
                    + body.trim());
        }
        // CONTROL — correctly spelled, the same report, the same verb: the rules are real and one FIRES.
        fresh();
        Path good = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(good, "deny Net app\n");
        Candor.gateCapture = true;
        Candor.gateViolations.clear();
        assertEquals(1, Query.run(new String[]{"gate", "--report", rep.toString(), "--policy", good.toString()}),
                "CONTROL: the rule the operator MEANT fires — so the exit 0 above was a deleted gate, not "
                + "a policy that legitimately had nothing to say");
        Candor.gateCapture = false;
    }
}
