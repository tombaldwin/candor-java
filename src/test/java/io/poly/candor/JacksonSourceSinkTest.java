package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import org.junit.jupiter.api.Test;

/**
 * Jackson, classified by source/sink. The stack's API shape allows one descriptor-driven rule: an
 * entry point that names its own source/sink does so via File/Path (→ Fs) or URL (→ Net); the
 * String/bytes/stream overloads are pure-RELATIVE (the caller-opened source carried the effect —
 * the JDOM2 stance).
 *
 * <p>Provenance: κ batch 30, 2026-07-06.
 */
class JacksonSourceSinkTest {

    @Test
    void fileAndUrlEntryPointsAreClassifiedBySource() {
        assertEquals(Effect.FS, Classifier.classify("com.fasterxml.jackson.databind.ObjectMapper", "readValue", "(Ljava/io/File;Ljava/lang/Class;)Ljava/lang/Object;"));
        assertEquals(Effect.FS, Classifier.classify("com.fasterxml.jackson.databind.ObjectMapper", "writeValue", "(Ljava/io/File;Ljava/lang/Object;)V"));
        assertEquals(Effect.NET, Classifier.classify("com.fasterxml.jackson.databind.ObjectMapper", "readTree", "(Ljava/net/URL;)Lcom/fasterxml/jackson/databind/JsonNode;"));
        assertEquals(Effect.FS, Classifier.classify("com.fasterxml.jackson.core.JsonFactory", "createParser", "(Ljava/io/File;)Lcom/fasterxml/jackson/core/JsonParser;"));
        assertEquals(Effect.NET, Classifier.classify("com.fasterxml.jackson.core.JsonFactory", "createParser", "(Ljava/net/URL;)Lcom/fasterxml/jackson/core/JsonParser;"));
    }

    @Test
    void pureAndPureRelativeSurfacesFabricateNothing() {
        assertNull(Classifier.classify("com.fasterxml.jackson.databind.ObjectMapper", "readValue", "(Ljava/lang/String;Lcom/fasterxml/jackson/core/type/TypeReference;)Ljava/lang/Object;"),
                "a String source is pure value work");
        assertNull(Classifier.classify("com.fasterxml.jackson.databind.ObjectMapper", "readValue", "(Ljava/io/InputStream;Ljava/lang/Class;)Ljava/lang/Object;"),
                "a caller-opened stream's effect was carried by the open");
        assertNull(Classifier.classify("com.fasterxml.jackson.databind.ObjectMapper", "writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;"));
        assertNull(Classifier.classify("com.fasterxml.jackson.core.JsonGenerator", "writeStringField", "(Ljava/lang/String;Ljava/lang/String;)V"),
                "generators write to a caller-provided sink");
        assertNull(Classifier.classify("com.fasterxml.jackson.databind.ObjectMapper", "convertValue", "(Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;"));
        assertTrue(Candor.kappaCovers("com.fasterxml.jackson.databind.node"), "the whole stack is covered");
    }

    // ── 30b REVERTED (review 0.8.3): the Amazon*/AWS* interface-owner widening fabricated Net on pure
    //    value types (AmazonS3URI) and, paired with a com.amazonaws coverage grant, silenced unmodeled
    //    facades (DynamoDBMapper). The *Client rule stands; interface-typed requests disclose invisible. ──
    @Test
    void awsClientClassesAreNetInterfacesDiscloseInvisibleNotFabricatedNotSilent() {
        // the concrete *Client classes are still Net (the sound pre-30b rule + the copy* verb kept)
        assertEquals(Effect.NET, Classifier.classify("com.amazonaws.services.s3.AmazonS3Client", "copyObject", "(Lcom/amazonaws/services/s3/model/CopyObjectRequest;)Lcom/amazonaws/services/s3/model/CopyObjectResult;"));
        // an interface-typed request is NOT classified here → discloses `invisible` (com.amazonaws is NOT
        // κ-covered), the honest floor — never fabrication, never silent-pure.
        assertNull(Classifier.classify("com.amazonaws.services.s3.AmazonS3", "copyObject", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/amazonaws/services/s3/model/CopyObjectResult;"));
        assertFalse(Candor.kappaCovers("com.amazonaws.services.dynamodbv2.datamodeling"),
                "com.amazonaws is NOT ledger-covered — an unmodeled facade (DynamoDBMapper.save) discloses invisible, never silent-pure");
    }

    @Test
    void awsNamedValueTypesAreNotFabricated() {
        // AmazonS3URI is a pure s3:// URI parser whose simple name starts with "Amazon" — the reverted
        // interface heuristic fabricated Net on its accessors.
        assertNull(Classifier.classify("com.amazonaws.services.s3.AmazonS3URI", "getBucket", "()Ljava/lang/String;"),
                "a URI parser makes no request — the Amazon*-name heuristic used to fabricate Net here");
        assertNull(Classifier.classify("com.amazonaws.services.s3.AmazonS3URI", "getKey", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("com.amazonaws.services.s3.transfer.TransferManager", "getConfiguration", "()Lcom/amazonaws/services/s3/transfer/TransferManagerConfiguration;"),
                "a config accessor on TransferManager is pure");
    }
}
