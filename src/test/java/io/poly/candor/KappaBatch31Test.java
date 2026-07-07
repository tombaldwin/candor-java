package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import org.junit.jupiter.api.Test;

/** κ batch 31 — the long-tail sweep (111 members triaged), plus the StopWatch gap batch 28 missed. */
class KappaBatch31Test {

    @Test
    void stopWatchReadsTheClockBothGenerations() {
        assertEquals(Effect.CLOCK, Classifier.classify("org.apache.commons.lang3.time.StopWatch", "start", "()V"),
                "the batch-28 gap: StopWatch went silent-pure under lang3 coverage");
        assertEquals(Effect.CLOCK, Classifier.classify("org.apache.commons.lang.time.StopWatch", "getTime", "()J"));
        assertEquals(Effect.RAND, Classifier.classify("org.apache.commons.lang.RandomStringUtils", "randomNumeric", "(I)Ljava/lang/String;"));
    }

    @Test
    void twilioTerminalsAndLazyPagingAreNet() {
        assertEquals(Effect.NET, Classifier.classify("com.twilio.rest.api.v2010.account.MessageCreator", "create", "()Lcom/twilio/rest/api/v2010/account/Message;"),
                "create() is the REST POST that sends the SMS");
        assertEquals(Effect.NET, Classifier.classify("com.twilio.base.ResourceSet", "iterator", "()Ljava/util/Iterator;"),
                "iterating a ResourceSet lazily fetches further pages — a wire call in a for-loop");
        assertNull(Classifier.classify("com.twilio.rest.api.v2010.account.Message", "getSid", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("com.twilio.type.PhoneNumber", "toString", "()Ljava/lang/String;"));
        assertNull(Classifier.classify("com.twilio.Twilio", "init", "(Ljava/lang/String;Ljava/lang/String;)V"), "config is pure");
    }

    @Test
    void redissonHandlesAreRemoteByDesign() {
        assertEquals(Effect.DB, Classifier.classify("org.redisson.api.RMap", "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals(Effect.DB, Classifier.classify("org.redisson.api.RedissonClient", "shutdown", "()V"));
        assertEquals(Effect.DB, Classifier.classify("org.redisson.Redisson", "create", "(Lorg/redisson/config/Config;)Lorg/redisson/api/RedissonClient;"));
        assertNull(Classifier.classify("org.redisson.config.Config", "useSingleServer", "()Lorg/redisson/config/SingleServerConfig;"), "config is pure");
    }

    @Test
    void commonsIoFollowsTheSourceSinkStance() {
        assertEquals(Effect.FS, Classifier.classify("org.apache.commons.io.FileUtils", "readFileToString", "(Ljava/io/File;Ljava/nio/charset/Charset;)Ljava/lang/String;"));
        assertEquals(Effect.NET, Classifier.classify("org.apache.commons.io.IOUtils", "toString", "(Ljava/net/URL;Ljava/nio/charset/Charset;)Ljava/lang/String;"));
        assertNull(Classifier.classify("org.apache.commons.io.IOUtils", "toByteArray", "(Ljava/io/InputStream;)[B"),
                "a caller-opened stream is pure-relative");
        assertNull(Classifier.classify("org.apache.commons.io.FilenameUtils", "concat", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
                "filename STRING work is pure — the String-path rule deliberately does not exist here");
        assertNull(Classifier.classify("org.apache.commons.io.FileUtils", "getTempDirectory", "()Ljava/io/File;"),
                "a File RETURN type is not a File parameter — the source/sink rules match params only");
    }

    @Test
    void proceedIsDisclosedUnknownNeverSilent() {
        assertEquals(Effect.UNKNOWN, Classifier.classify("org.aopalliance.intercept.MethodInvocation", "proceed", "()Ljava/lang/Object;"),
                "proceed() executes the intercepted target — the reflection stance");
        assertNull(Classifier.classify("org.aopalliance.intercept.MethodInvocation", "getMethod", "()Ljava/lang/reflect/Method;"));
    }

    @Test
    void theRestOfTheTail() {
        assertEquals(Effect.DB, Classifier.classify("org.dbunit.operation.TransactionOperation", "execute", "(Lorg/dbunit/database/IDatabaseConnection;Lorg/dbunit/dataset/IDataSet;)V"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.engine.jdbc.internal.ResultSetReturnImpl", "extract", "(Ljava/sql/PreparedStatement;)Ljava/sql/ResultSet;"));
        assertNull(Classifier.classify("org.hibernate.engine.jdbc.internal.BasicFormatterImpl", "format", "(Ljava/lang/String;)Ljava/lang/String;"),
                "the SQL pretty-printer is pure — the 685-fn invisible-noise source");
        assertEquals(Effect.NET, Classifier.classify("io.awspring.cloud.ses.SimpleEmailServiceMailSender", "send", "(Lorg/springframework/mail/SimpleMailMessage;)V"));
        assertEquals(Effect.ENV, Classifier.classify("software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider", "resolveCredentials", "()Lsoftware/amazon/awssdk/auth/credentials/AwsCredentials;"));
        assertEquals(Effect.FS, Classifier.classify("com.csvreader.CsvReader", "<init>", "(Ljava/lang/String;CLjava/nio/charset/Charset;)V"),
                "a path-taking ctor opens the file");
        assertNull(Classifier.classify("com.csvreader.CsvReader", "get", "(Ljava/lang/String;)Ljava/lang/String;"), "column access is pure");
        assertEquals(Effect.UNKNOWN, Classifier.classify("org.xml.sax.XMLReader", "parse", "(Ljava/lang/String;)V"),
                "the PRE-EXISTING stance is richer than Fs: parse drives user handler callbacks + XXE-class source resolution — disclosed Unknown");
        assertNull(Classifier.classify("org.apache.commons.codec.digest.DigestUtils", "sha256Hex", "(Ljava/lang/String;)Ljava/lang/String;"), "digests are pure CPU");
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.jpa.HibernatePersistenceProvider", "createEntityManagerFactory", "(Ljava/lang/String;Ljava/util/Map;)Ljakarta/persistence/EntityManagerFactory;"),
                "the provider bootstrap opens the persistence unit");
        assertNull(Classifier.classify("org.hibernate.jpa.TypedParameterValue", "<init>", "(Lorg/hibernate/type/Type;Ljava/lang/Object;)V"),
                "a pure query-parameter value wrapper");
        assertTrue(Candor.kappaCovers("com.opensymphony.oscache.general"));
        assertTrue(Candor.kappaCovers("org.postgresql.util"));
        assertTrue(!Candor.kappaCovers("org.postgresql"), "the DRIVER is not vouched — only its value-type util package");
        assertTrue(!Candor.kappaCovers("com.google.common.io"), "guava is covered ONLY at base/math — its io/cache stay honest");
    }
}
