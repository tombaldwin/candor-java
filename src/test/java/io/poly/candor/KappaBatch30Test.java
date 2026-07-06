package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import org.junit.jupiter.api.Test;

/**
 * κ batch 30 — Jackson. The stack's API shape allows one descriptor-driven rule: an entry point that
 * names its own source/sink does so via File/Path (→ Fs) or URL (→ Net); the String/bytes/stream
 * overloads are pure-RELATIVE (the caller-opened source carried the effect — the JDOM2 stance).
 */
class KappaBatch30Test {

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

    // ── 30b: the AWS v1 INTERFACE gap (found live — AmazonS3.copyObject read silent-invisible) ──────
    @Test
    void awsV1InterfaceCallsAreNetLikeTheClientClasses() {
        assertEquals(Effect.NET, Classifier.classify("com.amazonaws.services.s3.AmazonS3", "copyObject", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/amazonaws/services/s3/model/CopyObjectResult;"),
                "a call through the v1 service INTERFACE is a request — the Client-suffix gate missed it");
        assertEquals(Effect.NET, Classifier.classify("com.amazonaws.services.s3.AmazonS3", "getObject", "(Ljava/lang/String;Ljava/lang/String;)Lcom/amazonaws/services/s3/model/S3Object;"));
        assertEquals(Effect.NET, Classifier.classify("com.amazonaws.services.simpleemail.AmazonSimpleEmailService", "sendEmail", "(Lcom/amazonaws/services/simpleemail/model/SendEmailRequest;)Lcom/amazonaws/services/simpleemail/model/SendEmailResult;"));
        assertEquals(Effect.NET, Classifier.classify("com.amazonaws.services.s3.transfer.TransferManager", "upload", "(Ljava/lang/String;Ljava/lang/String;Ljava/io/File;)Lcom/amazonaws/services/s3/transfer/Upload;"));
    }

    @Test
    void awsV1PurePlumbingFabricatesNothing() {
        assertNull(Classifier.classify("com.amazonaws.services.s3.AmazonS3ClientBuilder", "withRegion", "(Ljava/lang/String;)Lcom/amazonaws/client/builder/AwsClientBuilder;"),
                "builders are pure config");
        assertNull(Classifier.classify("com.amazonaws.services.s3.model.S3Object", "getObjectContent", "()Lcom/amazonaws/services/s3/model/S3ObjectInputStream;"),
                "model accessors are pure — the GET request carried the Net");
        assertNull(Classifier.classify("com.amazonaws.util.StringUtils", "isNullOrEmpty", "(Ljava/lang/String;)Z"));
        assertTrue(Candor.kappaCovers("com.amazonaws.services.s3.model"));
    }
}
