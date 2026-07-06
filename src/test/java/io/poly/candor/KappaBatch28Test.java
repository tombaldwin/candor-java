package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import org.junit.jupiter.api.Test;

/**
 * κ batch 28 — the legacy-enterprise frontier (commons-logging / Joda-Time / commons-lang3 /
 * hibernate.criterion / Struts 1.x), inventory-driven from a real 2,257-class Struts app's complete
 * 169-member call surface (the uflexi dogfood: 81 ledgered packages, struts alone 5,502 calls).
 * Every classification is verb-precise; the anti-fabrication twins pin the pure siblings.
 */
class KappaBatch28Test {

    // ── commons-logging (JCL): the 5th log facade ────────────────────────────────────────────────────
    @Test
    void jclEmitVerbsAreLogAndFactoryIsPure() {
        assertEquals(Effect.LOG, Classifier.classify("org.apache.commons.logging.Log", "info", "(Ljava/lang/Object;)V"));
        assertEquals(Effect.LOG, Classifier.classify("org.apache.commons.logging.Log", "fatal", "(Ljava/lang/Object;Ljava/lang/Throwable;)V"));
        assertNull(Classifier.classify("org.apache.commons.logging.LogFactory", "getLog", "(Ljava/lang/Class;)Lorg/apache/commons/logging/Log;"),
                "the factory is pure — no fabricated Log");
        assertNull(Classifier.classify("org.apache.commons.logging.Log", "isDebugEnabled", "()Z"),
                "level checks are pure");
    }

    // ── Joda-Time: reading the current instant is Clock; value work is pure ─────────────────────────
    @Test
    void jodaNowFamilyIsClockAndValueWorkIsPure() {
        assertEquals(Effect.CLOCK, Classifier.classify("org.joda.time.DateTime", "now", "()Lorg/joda/time/DateTime;"));
        assertEquals(Effect.CLOCK, Classifier.classify("org.joda.time.DateTime", "<init>", "()V"),
                "the no-arg ctor reads the clock (== now())");
        assertEquals(Effect.CLOCK, Classifier.classify("org.joda.time.DateTimeUtils", "currentTimeMillis", "()J"));
        assertNull(Classifier.classify("org.joda.time.DateTime", "<init>", "(J)V"),
                "the millis ctor is a pure value ctor — descriptor-gated");
        assertNull(Classifier.classify("org.joda.time.DateTime", "plusDays", "(I)Lorg/joda/time/DateTime;"));
        assertNull(Classifier.classify("org.joda.time.format.PeriodFormatter", "print", "(Lorg/joda/time/ReadablePeriod;)Ljava/lang/String;"),
                "formatter print returns a String — pure, never Net/Fs");
    }

    // ── commons-lang3: the entropy pair + the env readers; the utility surface is pure ──────────────
    @Test
    void lang3EntropyAndEnvAreClassifiedUtilitiesArePure() {
        assertEquals(Effect.RAND, Classifier.classify("org.apache.commons.lang3.RandomStringUtils", "randomAlphanumeric", "(I)Ljava/lang/String;"));
        assertEquals(Effect.RAND, Classifier.classify("org.apache.commons.lang3.RandomUtils", "nextInt", "(II)I"));
        assertEquals(Effect.ENV, Classifier.classify("org.apache.commons.lang3.SystemProperties", "getJavaHome", "()Ljava/lang/String;"));
        assertEquals(Effect.ENV, Classifier.classify("org.apache.commons.lang3.SystemUtils", "getUserDir", "()Ljava/io/File;"));
        assertNull(Classifier.classify("org.apache.commons.lang3.StringUtils", "trimToNull", "(Ljava/lang/String;)Ljava/lang/String;"));
        assertNull(Classifier.classify("org.apache.commons.lang3.builder.HashCodeBuilder", "append", "(I)Lorg/apache/commons/lang3/builder/HashCodeBuilder;"));
    }

    // ── Struts 1.x: the two effectful surfaces; the bean plumbing is pure ───────────────────────────
    @Test
    void strutsTagWriteIsNetUploadReadIsFsPlumbingIsPure() {
        assertEquals(Effect.NET, Classifier.classify("org.apache.struts.taglib.TagUtils", "write", "(Ljavax/servlet/jsp/PageContext;Ljava/lang/String;)V"),
                "tag output goes to the JSP response — the client socket (the ServletResponse stance)");
        assertEquals(Effect.FS, Classifier.classify("org.apache.struts.upload.FormFile", "getInputStream", "()Ljava/io/InputStream;"),
                "reading a multipart upload reads the spooled temp file");
        assertNull(Classifier.classify("org.apache.struts.upload.FormFile", "getFileSize", "()I"), "size accessor is pure");
        assertNull(Classifier.classify("org.apache.struts.action.ActionMapping", "findForward", "(Ljava/lang/String;)Lorg/apache/struts/action/ActionForward;"));
        assertNull(Classifier.classify("org.apache.struts.action.ActionMessages", "add", "(Ljava/lang/String;Lorg/apache/struts/action/ActionMessage;)V"));
        assertNull(Classifier.classify("org.apache.struts.taglib.TagUtils", "getInstance", "()Lorg/apache/struts/taglib/TagUtils;"));
    }

    // ── the coverage boundary: batch-28 namespaces are ledger-exempt; org.hibernate broadly is NOT ──
    @Test
    void coverageBoundaryIsExact() {
        assertTrue(Candor.kappaCovers("org.apache.commons.logging"));
        assertTrue(Candor.kappaCovers("org.apache.commons.lang3.builder"));
        assertTrue(Candor.kappaCovers("org.joda.time.format"));
        assertTrue(Candor.kappaCovers("org.hibernate.criterion"));
        assertTrue(Candor.kappaCovers("org.apache.struts.action"));
        assertFalse(Candor.kappaCovers("org.hibernate"),
                "org.hibernate broadly stays LEDGERED — its unclassified surface is not vouched for");
        assertFalse(Candor.kappaCovers("org.apache.strutsx"), "segment-exact prefixes, never substring");
    }
}
