package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1548 / R1549. candor-java spells an overloaded method with its parameter types, and when two
 * overloads' simple names collide the types go fully qualified: {@code bank.Bank.pay(ua.user.User)}. The
 * parameter list is a DISAMBIGUATOR, not a path, so a scope must not match inside it.
 *
 * <p>EXECUTED (field fixture, candor-java 0.40.13): {@code only app -> user} exited 0 "no violations" on a
 * program whose only call was {@code bank.Bank.pay(ua.user.User)} (a file write, {@code bank} not
 * permitted) — a false green on a permission list — and {@code deny Fs User} exited 1 naming a function
 * that merely takes a User.
 */
class ScopeOverloadSuffixTest {
    private static final String PAY = "bank.Bank.pay(ua.user.User)";

    @Test
    void aParameterTypeIsNotAPermittedPathSegment() {
        assertFalse(Policy.scopeMatchesPermitted(PAY, "user"), "R1548: `user` is in the parameter type only");
        assertFalse(Policy.scopeMatchesPermitted(PAY, "ua"));
        assertFalse(Policy.scopeMatchesPermitted(PAY, "User"));
    }

    @Test
    void aParameterTypeIsNotAScopeSegmentEither() {
        assertFalse(Policy.scopeMatches(PAY, "User"), "R1549: a function that merely takes a User");
        assertFalse(Policy.scopeMatches(PAY, "user"));
        assertFalse(Policy.scopeMatches(PAY, "ua.user"));
        assertFalse(Policy.scopeMatches(PAY, "ua.user.User"));
    }

    @Test
    void theRealPathStillMatches() {
        assertTrue(Policy.scopeMatchesPermitted(PAY, "bank"), "`only app -> bank` must still permit it");
        assertTrue(Policy.scopeMatchesPermitted(PAY, "Bank"));
        assertTrue(Policy.scopeMatches(PAY, "bank"));
        assertTrue(Policy.scopeMatches(PAY, "bank.Bank"));
        assertTrue(Policy.scopeMatches(PAY, "bank.Bank.pay"), "the method name prefix-matches its own overload");
        assertTrue(Policy.scopeMatches("bank.Bank.pay(User)", "bank.Bank.pay"));
    }

    @Test
    void aScopeSpelledWithTheDisambiguatorSelectsExactlyThatOverload() {
        assertTrue(Policy.scopeMatches(PAY, "bank.Bank.pay(ua.user.User)"));
        assertFalse(Policy.scopeMatches("bank.Bank.pay(ub.user.User)", "bank.Bank.pay(ua.user.User)"));
        assertTrue(Policy.scopeMatchesPermitted(PAY, "bank.Bank.pay(ua.user.User)"));
        assertFalse(Policy.scopeMatchesPermitted("bank.Bank.pay(ub.user.User)", "bank.Bank.pay(ua.user.User)"));
    }

    @Test
    void segmentsKeepTheParameterListAsOneSegment_andNestedTypesStillSplitOutsideIt() {
        assertArrayEquals(new String[] {"bank", "Bank", "pay(ua.user.User)"}, Policy.nameSegments(PAY));
        assertArrayEquals(new String[] {"bank", "Bank", "Inner", "pay(a.B$C,int)"},
                Policy.nameSegments("bank.Bank$Inner.pay(a.B$C,int)"));
        // an unbalanced paren must not swallow the tail of the name
        assertArrayEquals(new String[] {"a", "b(c.d"}, Policy.nameSegments("a.b(c.d"));
    }
}
