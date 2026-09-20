package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import org.junit.jupiter.api.Test;

/**
 * The utility-library ledger tier, same inventory discipline as {@link LegacyEnterpriseKappaTest}
 * (a real app's complete 68-member frontier into these packages, triaged member-by-member):
 * commons-validator / beanutils / displaytag / w3c.dom are pure-surface coverage; threeten-extra /
 * jjwt / jdom2 / ehcache carry precise effectful members. Anti-fabrication twins pin the pure
 * siblings throughout.
 *
 * <p>Provenance: κ batch 29, 2026-07-06.
 */
class UtilityLibrariesKappaTest {

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

    /**
     * SOUNDNESS R508's ehcache carve-out — the one the version-blindness sweep checked at a SINGLE
     * version (3.10.8) and said so. Closed with {@code javap -c}, method-scoped, over all 56 published
     * 3.x releases: the XML source entry point on {@code ConfigurationParser} took a STRING systemId in
     * 3.0.0–3.5.3 (the constructor) and 3.6.0–3.6.3 ({@code parseXml}), reaching
     * {@code DocumentBuilder.parse(Ljava/lang/String;)} — and only from 3.7.0 does it take a
     * {@code URI}, which is the shape the descriptor gate was written against. {@code org.ehcache} is
     * κ-COVERED, so on those 25 releases the fall-through {@code null} was a certified purity claim.
     *
     * <p>Both directions are pinned, because the whole risk of a fix like this is the over-charge it
     * introduces one member over.
     */
    @Test
    void ehcacheXmlStringSystemIdIsFsAndTheSiblingsStayPure() {
        assertEquals(Effect.FS, Classifier.classify("org.ehcache.xml.ConfigurationParser", "<init>",
                        "(Ljava/lang/String;)V"),
                "ehcache 3.0.0–3.5.3: the public ConfigurationParser(String) READS the document at that systemId");
        assertEquals(Effect.FS, Classifier.classify("org.ehcache.xml.ConfigurationParser", "parseXml",
                        "(Ljava/lang/String;)Lorg/ehcache/xml/model/ConfigType;"),
                "ehcache 3.6.0–3.6.3: parseXml(String) is DocumentBuilder.parse(systemId)");
        // The ANTI-FABRICATION twins. Each is a member javap shows taking no source.
        assertNull(Classifier.classify("org.ehcache.xml.ConfigurationParser", "<init>", "()V"),
                "3.7.0+ the no-arg ctor only compiles the classpath schema — charging it would fabricate Fs "
                        + "on every consumer that merely constructs a parser");
        assertNull(Classifier.classify("org.ehcache.xml.XmlConfiguration", "getClassForName",
                        "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;"),
                "a String parameter is NOT the trigger — the two named members are");
        assertNull(Classifier.classify("org.ehcache.xml.ConfigurationParser", "documentToText",
                        "(Lorg/w3c/dom/Document;)Ljava/lang/String;"));
        // And the gate the rule sits in front of still answers as it did.
        assertEquals(Effect.NET, Classifier.classify("org.ehcache.xml.ConfigurationParser", "uriToDocument",
                        "(Ljava/net/URI;)Lorg/w3c/dom/Document;"),
                "3.7.0+ the URI entry point stays Net — the new rule must not shadow the descriptor gate");
        assertEquals(Effect.NET, Classifier.classify("org.ehcache.xml.XmlConfiguration", "<init>",
                        "(Ljava/net/URL;)V"));
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
