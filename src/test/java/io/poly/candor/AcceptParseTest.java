package io.poly.candor;

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
 * SPEC §6.2 ⟨0.41⟩ `accept` lines — the PARSE half. The cardinal direction is accepting a violation that is
 * NEW, so every malformed shape below must leave NO entry (and be listed in `ignored`), and a positional key must
 * be refused. The verdict half is pinned cross-engine by conformance PART 105.
 */
class AcceptParseTest {
    @TempDir Path tmp;

    @BeforeEach
    void fresh() { Candor.resetState(); }

    private boolean parse(String body) throws Exception {
        Path p = Files.createTempFile(tmp, "pol", ".policy");
        Files.writeString(p, body);
        return Policy.parsePolicy(p.toString());
    }

    private static final String RULE = "deny Fs dao\n";

    @Test
    void aWellFormedLineBecomesOneEntryEvenWhenItsRuleComesLater() throws Exception {
        assertTrue(parse("accept dao.D.a Fs for deny Fs dao because known since 2026\n" + RULE));
        assertEquals(1, Accept.entries.size());
        var e = Accept.entries.get(0);
        assertEquals("dao.D.a", e.fn());
        assertEquals("deny Fs dao", e.ruleKey());
        assertEquals("known since 2026", e.because());
    }

    @Test
    void anAcceptLineIsNotARuleSoAnAcceptOnlyPolicyStillYieldsNoRules() throws Exception {
        assertTrue(parse("accept dao.D.a Fs for deny Fs dao because x\n"));
        assertTrue(Policy.policyYieldedNoRules(), "§6.2: an accept-only policy still refuses (zero rules)");
    }

    @Test
    void everyMalformedShapeLeavesNoEntry() throws Exception {
        String[] bad = {
            "accept dao.D.a Fs for deny Fs dao",                       // no reason
            "accept dao.D.a Fs for deny Fs dao because #123",          // `#` begins a comment: no reason
            "accept dao.D.a Fs deny Fs dao because x",                 // no `for`
            "accept dao.D.a for deny Fs dao because x",                // deny needs an effect
            "accept dao.D.a Fs for deny Fs app because x",             // names no parsed rule
            "accept dao.D.a Unknown for deny Fs dao because x",        // bare Unknown
            "accept dao.D.a Unknown[*] for deny Fs dao because x",
            "accept dao.D.a Unknown[dynamic] for deny Fs dao because x",
            "accept dao.D.a Net[unknown-host] for deny Fs dao because x",
            "accept dao.D.lambda$a$0 Fs for deny Fs dao because x",    // positional key
            "accept dao.D$1.run Fs for deny Fs dao because x",         // anonymous class: positional
        };
        for (String b : bad) {
            Candor.resetState();
            assertTrue(parse(RULE + b + "\n"), b);
            assertTrue(Accept.entries.isEmpty(), "must leave no entry: " + b);
            assertTrue(Policy.ignoredLinesJson().stream().anyMatch(m -> ((Integer) m.get("line")) == 2),
                    "must be listed in `ignored`: " + b);
        }
    }

    @Test
    void allowAndOnlyRulesCannotBeAccepted() throws Exception {
        assertTrue(parse("allow Net in dao ok.example\naccept dao.D.n Net for allow Net in dao ok.example because x\n"));
        assertTrue(Accept.entries.isEmpty());
        Candor.resetState();
        assertTrue(parse("only dao -> util\naccept dao.D.n for only dao -> util because x\n"));
        assertTrue(Accept.entries.isEmpty());
    }

    @Test
    void anUnrecognisedEffectOrClassTokenRefusesThePolicy() throws Exception {
        assertFalse(parse(RULE + "accept dao.D.a Fss for deny Fs dao because x\n"));
        Candor.resetState();
        assertFalse(parse("deny Unknown dao\naccept dao.D.a Unknown[dispatchh] for deny Unknown dao because x\n"));
    }

    @Test
    void ruleTokensAreTheRawLexedTokensNotTheConsumedOnes() throws Exception {
        assertTrue(parse("deny Fs dao extra\naccept dao.D.a Fs for deny Fs dao because x\n"));
        assertTrue(Accept.entries.isEmpty(), "`deny Fs dao` is not the line `deny Fs dao extra`");
        Candor.resetState();
        assertTrue(parse("deny   Fs\tdao extra # c\naccept dao.D.a Fs for deny Fs dao extra because x\n"));
        assertEquals(1, Accept.entries.size(), "whitespace and comments do not change the tokens");
    }

    @Test
    void aForbidEntryTakesNoEffects() throws Exception {
        assertTrue(parse("forbid dao -> infra\naccept dao.D.a Fs for forbid dao -> infra because x\n"));
        assertTrue(Accept.entries.isEmpty());
        Candor.resetState();
        assertTrue(parse("forbid dao -> infra\naccept dao.D.a for forbid dao -> infra because x\n"));
        assertEquals(1, Accept.entries.size());
    }

    @Test
    void positionalSpellingsAreRefusedAndOrdinaryNamesAreNot() {
        for (String p : List.of("a.B.lambda$m$0", "a.B$1.run", "a.B$1Local.m", "a.B.access$000", "a.B.$deserializeLambda$"))
            assertTrue(Accept.positional(p), p);
        for (String p : List.of("dao.D.a", "dao.D$Inner.a", "dao.Repo.load", "a.b.C.lambdaFactory"))
            assertFalse(Accept.positional(p), p);
    }
}
