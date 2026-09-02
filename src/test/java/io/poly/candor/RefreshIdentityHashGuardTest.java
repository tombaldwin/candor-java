package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * THE REFRESH DIGEST'S IDENTITY-HASH GUARD, WHICH HAD NO COVERAGE AT ALL.
 *
 * <p>{@link Refresh}'s digest refuses any chunk containing {@code some.Class@1b6d3586} — what
 * {@code Object.toString()} emits and nothing else in that rendering does. It exists because ASM
 * encodes an enum constant as a {@code String[]}, so {@code String.valueOf(values)} produced an
 * identity hash, the digest differed on every JVM run, and the cache never hit once. The guard is the
 * reason a non-value-based rendering cannot silently return.
 *
 * <p>It had never been exercised by a test. Found while sizing SOUNDNESS R151: the guard turned out to
 * be the digest's dominant cost (1.19s of 1.46s once 23,624 chained dep entries took the input to
 * 15.4 MB), because a bare {@code [\w.$\[;]+@} retries the run from every position inside it. Anchoring
 * it to the start of a run and making the quantifier possessive is linear and finds the same thing —
 * but "finds the same thing" is a claim about a guard nobody had ever made fail, so it is measured here
 * rather than asserted in a comment.
 *
 * <p>The negative cases are NEAR MISSES, not absences: a short hex tail, a non-hex tail, and the
 * annotation renderings that legitimately carry {@code @} all over the digest's input. An absence
 * control would only prove the pattern looks at something.
 */
class RefreshIdentityHashGuardTest {

    /** The pattern as {@link Refresh} compiles it. Read reflectively rather than copied, because a copy
     *  is a second implementation of the thing under test and would pass after the original drifted. */
    private static Pattern pattern() throws Exception {
        java.lang.reflect.Field f = Refresh.class.getDeclaredField("IDENTITY_HASH");
        f.setAccessible(true);
        return (Pattern) f.get(null);
    }

    @Test
    void itFiresOnEveryShapeObjectToStringProduces() throws Exception {
        Pattern p = pattern();
        for (String s : new String[] {
                "some.Class@1b6d3586",
                "[Ljava.lang.String;@2ef5e5e3",                      // the exact ASM enum encoding
                "org.objectweb.asm.tree.AnnotationNode@7a81197d",
                "Foo@abcdef",                                        // 6 hex, the low bound
                "Foo@abcdef12",                                      // 8 hex, the high bound
                "prefix io.poly.Bar@0f1e2d3c suffix",                // embedded in a chunk
                "x@deadbe",                                          // a one-character run
                "effects=[Fs]x@deadbe",                              // a run that starts mid-chunk
        }) {
            assertTrue(p.matcher(s).find(), "the identity-hash guard did NOT fire on " + s
                    + " — a non-value-based rendering would reach the digest and the cache would never hit");
        }
    }

    @Test
    void itDoesNotFireOnTheNearMissesTheDigestActuallyContains() throws Exception {
        Pattern p = pattern();
        for (String s : new String[] {
                "Foo@abcde",                                         // five hex: one short
                "Foo@abcdef123",                                     // nine hex: \b fails
                "Foo@zzzzzzzz",                                      // not hex at all
                "@Ljakarta/persistence/Entity;=null",                // an annotation rendering
                "@Lorg/springframework/stereotype/Service;=E[VALUE]",
                "user@example.com",                                  // a host in a dep's `hosts`
                "io/poly/candor/Refresh=41444b2bbaec4e69d2a65d51dce28c5f",   // a content hash
        }) {
            assertFalse(p.matcher(s).find(), "the identity-hash guard FIRED on " + s
                    + " — a false positive abandons the cache for a full scan on ordinary content");
        }
    }

    /** The reason the pattern is anchored and possessive. A bare {@code [\w.$\[;]+@} is quadratic in run
     *  length, and the digest's input is now megabytes of exactly that shape. The bound is deliberately
     *  loose (the old pattern took ~1.2s over this input on the machine it was measured on, this one
     *  ~50ms) so that it fails on a reintroduced blowup and not on a slow runner. */
    @Test
    void itScansMegabytesOfRunHeavyTextLinearly() throws Exception {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < 4_000_000)
            sb.append("org.hibernate.boot.registry.classloading.internal.AggregatedServiceLoader")
              .append("$ClassPathAndModulePathAggregatedServiceLoader.hasNextIgnoringServiceConfiguration=")
              .append("effects[Db]incomplete[]\n");
        String haystack = sb.toString();
        Pattern p = pattern();
        p.matcher(haystack).find();                     // warm the JIT
        long t0 = System.nanoTime();
        boolean hit = p.matcher(haystack).find();
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertFalse(hit, "this fixture contains no identity hash");
        assertTrue(ms < 600, "the identity-hash guard took " + ms + " ms over " + haystack.length()
                + " characters of run-heavy text. That is the quadratic shape the anchor and the "
                + "possessive quantifier removed; it made the guard cost more than everything it guards.");
    }
}
