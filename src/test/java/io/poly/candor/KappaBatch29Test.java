package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import org.junit.jupiter.api.Test;

/**
 * κ batch 29 — the next ledger tier after batch 28, same inventory discipline (a real app's complete
 * 68-member frontier into these packages, triaged member-by-member): commons-validator / beanutils /
 * displaytag / w3c.dom are pure-surface coverage; threeten-extra / jjwt / jdom2 / ehcache carry precise
 * effectful members. Anti-fabrication twins pin the pure siblings throughout.
 */
class KappaBatch29Test {

    @Test
    void threetenNowIsClockValueOpsArePure() {
        assertEquals(Effect.CLOCK, Classifier.classify("org.threeten.extra.YearWeek", "now", "()Lorg/threeten/extra/YearWeek;"));
        assertNull(Classifier.classify("org.threeten.extra.Interval", "of", "(Ljava/time/Instant;Ljava/time/Instant;)Lorg/threeten/extra/Interval;"));
        assertNull(Classifier.classify("org.threeten.extra.Interval", "getStart", "()Ljava/time/Instant;"));
    }

    @Test
    void jjwtParseIsClockKeysAreRandBuildingIsPure() {
        assertEquals(Effect.CLOCK, Classifier.classify("io.jsonwebtoken.JwtParser", "parseClaimsJws", "(Ljava/lang/String;)Lio/jsonwebtoken/Jws;"),
                "parsing VALIDATES exp/nbf against the system clock");
        assertEquals(Effect.RAND, Classifier.classify("io.jsonwebtoken.security.Keys", "secretKeyFor", "(Lio/jsonwebtoken/SignatureAlgorithm;)Ljavax/crypto/SecretKey;"));
        assertNull(Classifier.classify("io.jsonwebtoken.Jwts", "parser", "()Lio/jsonwebtoken/JwtParser;"),
                "review 0.8.3: the no-arg parser() factory reads no clock — only parsing a token (a parse* method that TAKES the token) does");
        assertNull(Classifier.classify("io.jsonwebtoken.Jwts", "parserBuilder", "()Lio/jsonwebtoken/JwtParserBuilder;"));
        assertNull(Classifier.classify("io.jsonwebtoken.JwtBuilder", "compact", "()Ljava/lang/String;"),
                "signing is pure CPU — no fabricated effect");
        assertNull(Classifier.classify("io.jsonwebtoken.Jwts", "builder", "()Lio/jsonwebtoken/JwtBuilder;"));
        assertNull(Classifier.classify("io.jsonwebtoken.Claims", "getSubject", "()Ljava/lang/String;"));
    }

    @Test
    void jdom2InputIsEffectfulBySourceModelIsPure() {
        assertEquals(Effect.FS, Classifier.classify("org.jdom2.input.SAXBuilder", "build", "(Ljava/io/File;)Lorg/jdom2/Document;"));
        assertEquals(Effect.NET, Classifier.classify("org.jdom2.input.SAXBuilder", "build", "(Ljava/net/URL;)Lorg/jdom2/Document;"));
        assertNull(Classifier.classify("org.jdom2.input.SAXBuilder", "build", "(Ljava/io/InputStream;)Lorg/jdom2/Document;"),
                "a caller-opened stream's effect was carried by the open — relative purity");
        assertNull(Classifier.classify("org.jdom2.Element", "setAttribute", "(Ljava/lang/String;Ljava/lang/String;)Lorg/jdom2/Element;"));
        assertNull(Classifier.classify("org.jdom2.output.XMLOutputter", "outputString", "(Lorg/jdom2/Document;)Ljava/lang/String;"));
    }

    @Test
    void ehcacheAcquisitionPointsAreClassifiedHeapIsPure() {
        assertEquals(Effect.FS, Classifier.classify("org.ehcache.config.builders.CacheManagerBuilder", "persistence", "(Ljava/lang/String;)Lorg/ehcache/config/builders/CacheManagerBuilder;"),
                "the persistence config names the disk directory — the Fs acquisition point");
        assertNull(Classifier.classify("org.ehcache.config.builders.CacheManagerBuilder", "build", "(Z)Lorg/ehcache/CacheManager;"),
                "build is vouched — a disk tier's Fs was carried by persistence(); heap-only apps never fabricate");
        assertNull(Classifier.classify("org.ehcache.config.builders.ResourcePoolsBuilder", "heap", "(J)Lorg/ehcache/config/builders/ResourcePoolsBuilder;"));
        assertNull(Classifier.classify("org.ehcache.Cache", "get", "(Ljava/lang/Object;)Ljava/lang/Object;"));
    }

    @Test
    void pureSurfacePackagesHaveNoClassificationsAndAreCovered() {
        assertNull(Classifier.classify("org.apache.commons.validator.GenericValidator", "isBlankOrNull", "(Ljava/lang/String;)Z"));
        assertNull(Classifier.classify("org.apache.commons.beanutils.BeanUtils", "copyProperties", "(Ljava/lang/Object;Ljava/lang/Object;)V"));
        assertNull(Classifier.classify("org.displaytag.decorator.TableDecorator", "getDecoratedObject", "()Ljava/lang/Object;"));
        assertNull(Classifier.classify("org.w3c.dom.Document", "createElement", "(Ljava/lang/String;)Lorg/w3c/dom/Element;"));
        assertTrue(Candor.kappaCovers("org.apache.commons.validator.routines"));
        assertTrue(Candor.kappaCovers("org.apache.commons.beanutils"));
        assertTrue(Candor.kappaCovers("org.threeten.extra"));
        assertTrue(Candor.kappaCovers("io.jsonwebtoken"));
        assertTrue(Candor.kappaCovers("org.jdom2.output"));
        assertTrue(Candor.kappaCovers("org.displaytag.util"));
        assertTrue(Candor.kappaCovers("org.ehcache.config.builders"));
        assertTrue(Candor.kappaCovers("org.w3c.dom"));
        assertFalse(Candor.kappaCovers("org.w3c"), "org.w3c broadly is NOT vouched — only the DOM package");
        assertFalse(Candor.kappaCovers("org.jdom2x"), "segment-exact, never substring");
    }
}
