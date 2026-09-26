package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R626 — <b>the owner-blanket denylist probe is a SILENT instrument: nothing goes red when
 * {@link Candor#isPureHandleAccessor} starts swallowing it.</b>
 *
 * <p>{@link Candor#isOwnerBlanketRule} asks the classifier <em>"would your rule for this owner fire for a
 * method name that cannot exist?"</em>, and a TRUE answer denylists the owner from R131's supertype walk —
 * because a whole-owner rule applied through a supertype fabricates the type's effect on every inherited
 * member. The probe is a NUL-bracketed non-identifier, so no {@code equals} / {@code startsWith} /
 * {@code endsWith} in the classifier can match it.
 *
 * <p><b>The hazard this gate exists for, and its direction.</b> {@code Classifier.classify} consults
 * {@code isPureHandleAccessor} FIRST. That method is a per-owner carve-out list, and it is written in
 * exact {@code equals} / {@code switch} form TODAY. The first carve-out written in a NEGATED or
 * predicate shape — {@code !method.startsWith("read")}, {@code !isEffectfulVerb(method)},
 * {@code method.charAt(0) != 'g'} — answers TRUE for the probe, {@code classify} then returns
 * {@code null}, {@code isOwnerBlanketRule} reads FALSE, and the denylist switches <b>OFF for exactly the
 * owners that have carve-outs</b> — which are exactly the blanket-with-exemption owners it targets. The
 * failure is a FABRICATION (a supertype's whole-owner effect charged onto inherited members) and nothing
 * in the suite could see it, because the probe never throws and never logs: it just answers the other way.
 *
 * <p><b>Every owner asserted below has BOTH a blanket rule and a carve-out</b>, which is the intersection
 * the hazard lives in. An owner with a blanket rule and no carve-out cannot be swallowed; an owner with a
 * carve-out and no blanket rule has nothing to switch off.
 *
 * <p>Calibrated by injection, not by reasoning — TWICE, in two unrelated arms, because a gate that fires
 * only for the arm its author was looking at is the audit-boundary failure (§9). Adding
 * {@code || !method.startsWith("accept")} to the socket arm, and separately
 * {@code !method.startsWith("delete") ||} to the {@code java.io.File} arm, each turns TWO of these four
 * tests RED and leaves the other two green:
 * <pre>
 *   java.net.Socket: isPureHandleAccessor answered TRUE for a NUL-bracketed non-identifier … ==&gt; expected: &lt;false&gt; but was: &lt;true&gt;
 *   java.net.Socket has a blanket rule AND an isPureHandleAccessor carve-out …              ==&gt; expected: &lt;true&gt;  but was: &lt;false&gt;
 *   java.io.File:    isPureHandleAccessor answered TRUE for a NUL-bracketed non-identifier … ==&gt; expected: &lt;false&gt; but was: &lt;true&gt;
 * </pre>
 * Both RED runs are in the commit message beside the green.
 */
class OwnerBlanketProbeGateTest {

    /** Owners carrying BOTH a whole-owner (blanket) classifier rule and an {@code isPureHandleAccessor}
     *  carve-out — read off that method's own {@code switch} labels. This is the set the probe must keep
     *  seeing THROUGH the carve-out. */
    private static final String[] BLANKET_WITH_CARVE_OUT = {
            "java.io.File",
            "java.net.Socket", "java.net.ServerSocket", "java.net.DatagramSocket",
            "java.net.MulticastSocket",
            "javax.net.ssl.SSLSocket", "javax.net.ssl.SSLServerSocket",
            "java.time.Clock",
            "java.util.Random", "java.security.SecureRandom",
            "java.util.concurrent.ThreadLocalRandom", "java.util.SplittableRandom",
            "java.util.zip.ZipFile", "java.util.jar.JarFile",
            "java.awt.datatransfer.Clipboard",
    };

    /**
     * R626's FIRST direction. A blanket-ruled owner must still be DETECTED as blanket-ruled when the
     * question is routed through {@code isPureHandleAccessor}, for every owner that has a carve-out.
     * {@code "()I"} is a zero-argument descriptor deliberately: it names no locator, so nothing here can
     * pass because a descriptor-gated rule happened to fire instead (see
     * {@link #aDescriptorOnlyRuleReadsAsBlanketAndThatResidualIsPINNED}).
     */
    @Test
    void blanketOwnersWithCarveOutsStayDenylisted() {
        for (String owner : BLANKET_WITH_CARVE_OUT) {
            assertTrue(Candor.isOwnerBlanketRule(owner, "()I"),
                    owner + " has a blanket rule AND an isPureHandleAccessor carve-out; if the probe stops"
                            + " reaching the rule, R131's walk starts fabricating on it");
        }
    }

    /**
     * The mechanism under the assertion above, pinned separately so a failure says WHICH half broke.
     * The probe is not a legal identifier; no carve-out may ever call it pure.
     */
    @Test
    void theProbeSurvivesEveryPureAccessorCarveOut() {
        for (String owner : BLANKET_WITH_CARVE_OUT) {
            assertFalse(Candor.isPureHandleAccessor(owner, Candor.BLANKET_PROBE),
                    owner + ": isPureHandleAccessor answered TRUE for a NUL-bracketed non-identifier, so"
                            + " the carve-out is matching on a SHAPE rather than on names");
        }
    }

    /**
     * R626's SECOND direction, and the reason it is not symmetrical: a VERB-GATED owner must read as NOT
     * blanket, so R131's walk still applies to it. {@code java.io.FilterInputStream} is the row's own
     * example and the R622/R712 delegation family's owner — its rule names members, so the probe matches
     * nothing and the walk is free to charge inherited spellings like {@code DataInputStream.read}.
     */
    @Test
    void verbGatedOwnersAreNotDenylisted() {
        assertFalse(Candor.isOwnerBlanketRule("java.io.FilterInputStream", "()I"),
                "FilterInputStream's rule is verb-gated; reading it as blanket would denylist the whole"
                        + " java.io delegation family from R131's walk");
        assertFalse(Candor.isOwnerBlanketRule("java.io.BufferedInputStream", "()I"),
                "the sibling spelling of the same delegation rule");
        assertFalse(Candor.isOwnerBlanketRule("org.apache.commons.io.FileUtils", "()I"),
                "a method.startsWith-gated owner: broad, but not blanket");
    }

    /**
     * THE RESIDUAL R626 NAMES AND THE COMMIT THAT BUILT THE PROBE DID NOT: a DESCRIPTOR-ONLY rule — one
     * with no name test at all — reads as BLANKET to the probe, so the walk declines it. The direction is
     * conservative (no fabrication), but it means <b>R131 is inert over that whole rule family</b>, and
     * the residual as stated in the commit was the prefix/suffix one, which errs the OTHER way.
     *
     * <p>Pinned as a FACT rather than as a wish: it is asserted in BOTH directions on one owner, so the
     * day someone name-gates these rules this test says so instead of going quietly green.
     */
    @Test
    void aDescriptorOnlyRuleReadsAsBlanketAndThatResidualIsPINNED() {
        // org.redisson.config.Config — `if (params contains Ljava/io/File;) return FS;`, no name test.
        assertTrue(Candor.isOwnerBlanketRule("org.redisson.config.Config", "(Ljava/io/File;)V"),
                "a descriptor-only rule fires for the probe, so the probe calls the owner blanket and"
                        + " R131's walk declines it — R626's second direction");
        assertFalse(Candor.isOwnerBlanketRule("org.redisson.config.Config", "()V"),
                "and it is the DESCRIPTOR doing it, not the owner: the same owner at a descriptor the rule"
                        + " cannot fire for reads as non-blanket");
    }
}
