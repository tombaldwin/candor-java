package io.poly.candor;

import io.poly.candor.model.Effect;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Table-driven pins for the κ classifier buckets ({@link Classifier#classify}) — the TESTING.md §2.3 rule
 * ("where the rule is a member/verb table, add a table-driven positive test so a typo un-classifies
 * loudly") applied to the largest never-anchored regions the coverage measurement named: classifyJava,
 * classifyOrg, classifyCom, classifyComTail, classifyIo, classifyOther. Each row asserts one
 * (owner, method, desc) → effect mapping through the real classify() entry point; each namespace family
 * carries anti-fabrication TWINS — the pure neighbour / lookalike verb / wrong-descriptor overload that
 * must stay null (a widened rule fabricates loudly here).
 *
 * <p>Deliberately REPRESENTATIVE, not exhaustive (TESTING.md §6: a missing rule has no lines to cover —
 * the κ probes and corpus rounds own completeness; this table makes the existing rows' regressions
 * un-shippable). Rows were taken from the rule text, never invented: every positive row is a documented
 * modeling decision, every twin is a documented non-effect (lazy factory, config setter, pure accessor,
 * in-memory overload).
 */
class ClassifierTableTest {

    private static final String ANY = "()V";   // rules that don't read the descriptor

    private record Row(String owner, String method, String desc, Effect want) {}

    private static Row fx(String owner, String method, Effect want) { return new Row(owner, method, ANY, want); }

    private static Row fx(String owner, String method, String desc, Effect want) { return new Row(owner, method, desc, want); }

    // ── classifyJava ──────────────────────────────────────────────────────────────────────────────────
    private static final List<Row> JAVA = List.of(
            // reflection / dynamic invocation / deserialization — the trust-contract Unknowns
            fx("java.lang.reflect.Method", "invoke", Effect.UNKNOWN),
            fx("java.lang.Class", "forName", Effect.UNKNOWN),
            fx("java.io.ObjectInputStream", "readObject", Effect.UNKNOWN),
            fx("java.lang.ClassLoader", "loadClass", Effect.UNKNOWN),
            fx("java.lang.invoke.MethodHandles$Lookup", "defineClass", Effect.UNKNOWN),
            // filesystem
            fx("java.nio.file.Files", "readAllBytes", Effect.FS),
            fx("java.util.jar.JarFile", "<init>", Effect.FS),
            fx("java.nio.MappedByteBuffer", "force", Effect.FS),
            fx("java.nio.MappedByteBuffer", "capacity", null),           // pure Buffer query (cardinal-sin twin)
            fx("java.nio.file.FileStore", "getTotalSpace", Effect.FS),
            fx("java.io.FileDescriptor", "sync", Effect.FS),
            fx("java.lang.Class", "getResourceAsStream", Effect.FS),
            fx("java.util.ResourceBundle", "getBundle", Effect.FS),
            fx("java.util.ServiceLoader", "load", Effect.FS),
            fx("java.nio.file.FileSystems", "newFileSystem", Effect.FS),
            fx("java.util.prefs.Preferences", "exportSubtree", Effect.FS),
            fx("java.util.logging.LogManager", "readConfiguration", Effect.FS),
            fx("java.util.Scanner", "<init>", "(Ljava/io/File;)V", Effect.FS),
            fx("java.util.Scanner", "<init>", "(Ljava/lang/String;)V", null),   // string source — pure twin
            fx("java.io.PrintWriter", "<init>", "(Ljava/lang/String;)V", Effect.FS),
            fx("java.io.PrintWriter", "<init>", "(Ljava/io/OutputStream;)V", null), // wrapped sink — pure twin
            fx("java.nio.file.WatchService", "take", Effect.FS),
            fx("java.nio.file.Path", "toRealPath", Effect.FS),
            fx("java.nio.file.Path", "normalize", null),                 // pure path algebra twin
            fx("java.io.File", "delete", Effect.FS),
            fx("java.io.File", "getName", null),                         // pure pathname accessor twin
            // network
            fx("java.net.Socket", "connect", Effect.NET),
            fx("java.net.Socket", "getPort", null),                      // cached-handle accessor twin
            fx("java.nio.channels.SocketChannel", "connect", Effect.NET),
            fx("java.nio.channels.Selector", "select", Effect.NET),
            fx("java.nio.channels.Selector", "wakeup", null),            // readiness bookkeeping twin
            fx("java.net.http.HttpClient", "send", Effect.NET),
            fx("java.net.InetAddress", "getByName", Effect.NET),
            fx("java.security.cert.CertPathValidator", "validate", Effect.NET),
            // db
            fx("java.sql.Driver", "connect", Effect.DB),
            fx("java.sql.Statement", "executeQuery", Effect.DB),
            fx("java.sql.Connection", "prepareStatement", Effect.DB),
            // exec
            fx("java.lang.ProcessBuilder", "start", Effect.EXEC),
            fx("java.lang.Runtime", "exec", Effect.EXEC),
            fx("java.lang.Process", "destroyForcibly", Effect.EXEC),
            // env / clock / rand / clipboard-adjacent
            fx("java.lang.System", "getenv", Effect.ENV),
            fx("java.lang.ProcessBuilder", "environment", Effect.ENV),
            fx("java.lang.System", "currentTimeMillis", Effect.CLOCK),
            fx("java.time.Clock", "instant", Effect.CLOCK),
            fx("java.util.Calendar", "getInstance", Effect.CLOCK),
            fx("java.util.UUID", "randomUUID", Effect.RAND),
            fx("java.security.KeyPairGenerator", "generateKeyPair", Effect.RAND));

    // ── classifyOrg ───────────────────────────────────────────────────────────────────────────────────
    private static final List<Row> ORG = List.of(
            fx("org.springframework.expression.Expression", "getValue", Effect.UNKNOWN),
            fx("org.yaml.snakeyaml.Yaml", "load", Effect.UNKNOWN),
            fx("org.apache.commons.lang3.SerializationUtils", "deserialize", Effect.UNKNOWN),
            fx("org.mvel2.MVEL", "eval", Effect.UNKNOWN),
            fx("org.python.util.PythonInterpreter", "exec", Effect.UNKNOWN),
            fx("org.apache.commons.io.FileUtils", "readFileToString", Effect.FS),
            fx("org.apache.commons.io.FileUtils", "getTempDirectory", null),   // pure factory twin (round-12 pin)
            fx("org.springframework.util.FileSystemUtils", "deleteRecursively", Effect.FS),
            fx("org.springframework.util.FileCopyUtils", "copy", "(Ljava/io/File;Ljava/io/File;)I", Effect.FS),
            fx("org.springframework.util.FileCopyUtils", "copy",
                    "(Ljava/io/InputStream;Ljava/io/OutputStream;)I", null),   // in-memory pump twin
            fx("org.jsoup.Connection", "execute", Effect.NET),
            fx("org.jsoup.Connection", "userAgent", null),                     // fluent builder twin
            fx("org.jsoup.Jsoup", "parse", "(Ljava/io/File;Ljava/lang/String;)Lorg/jsoup/nodes/Document;", Effect.FS),
            fx("org.jsoup.Jsoup", "parse", "(Ljava/lang/String;)Lorg/jsoup/nodes/Document;", null), // in-memory twin
            fx("org.apache.poi.ss.usermodel.WorkbookFactory", "create", "(Ljava/io/File;)LW;", Effect.FS),
            fx("org.apache.poi.ss.usermodel.WorkbookFactory", "create", "(Ljava/io/InputStream;)LW;", null),
            fx("org.apache.commons.net.ftp.FTPClient", "retrieveFile", Effect.NET),
            fx("org.apache.commons.net.ftp.FTPClient", "setBufferSize", null), // config setter twin
            fx("org.flywaydb.core.Flyway", "migrate", Effect.DB),
            fx("org.flywaydb.core.Flyway", "configure", null),                 // fluent builder twin
            fx("org.eclipse.jgit.api.Git", "open", "(Ljava/io/File;)Lorg/eclipse/jgit/api/Git;", Effect.FS),
            fx("org.apache.commons.compress.archivers.zip.ZipFile", "<init>", "(Ljava/io/File;)V", Effect.FS),
            fx("org.apache.tika.Tika", "parseToString", "(Ljava/io/File;)Ljava/lang/String;", Effect.FS),
            fx("org.apache.tika.Tika", "parseToString", "(Ljava/net/URL;)Ljava/lang/String;", Effect.NET),
            fx("org.apache.pdfbox.Loader", "loadPDF", "(Ljava/io/File;)LD;", Effect.FS),
            fx("org.springframework.data.jpa.repository.JpaRepository", "save", Effect.DB),
            fx("org.springframework.data.repository.CrudRepository", "toString", null), // Object protocol twin
            fx("org.springframework.data.redis.core.ValueOperations", "set", Effect.DB),
            fx("org.elasticsearch.client.RestClient", "performRequest", Effect.NET),
            fx("org.springframework.mail.javamail.JavaMailSender", "send", Effect.NET),
            fx("org.springframework.mail.javamail.JavaMailSenderImpl", "setHost", null), // config setter twin
            fx("org.springframework.web.client.RestTemplate", "getForObject", Effect.NET),
            fx("org.jruby.embed.ScriptingContainer", "runScriptlet", Effect.UNKNOWN),
            fx("org.apache.zookeeper.ZooKeeper", "create", Effect.NET));

    // ── classifyCom ───────────────────────────────────────────────────────────────────────────────────
    private static final List<Row> COM = List.of(
            fx("com.sun.tools.javac.Main", "compile", Effect.FS),
            fx("com.sun.jna.Function", "invoke", Effect.UNKNOWN),
            fx("com.sun.jna.Native", "load", Effect.EXEC),
            fx("com.sun.tools.attach.VirtualMachine", "attach", Effect.EXEC),
            fx("com.thoughtworks.xstream.XStream", "fromXML", Effect.UNKNOWN),
            fx("com.esotericsoftware.kryo.Kryo", "readObject", Effect.UNKNOWN),
            fx("com.google.common.io.Files", "toByteArray", Effect.FS),
            fx("com.google.common.io.Files", "asByteSource", null),           // lazy-factory twin (round-13 pin)
            fx("com.fasterxml.jackson.databind.ObjectMapper", "readValue",
                    "(Ljava/io/File;Ljava/lang/Class;)Ljava/lang/Object;", Effect.FS),
            fx("com.fasterxml.jackson.databind.ObjectMapper", "readValue",
                    "(Ljava/net/URL;Ljava/lang/Class;)Ljava/lang/Object;", Effect.NET),
            fx("com.fasterxml.jackson.databind.ObjectMapper", "readValue",
                    "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;", null), // in-memory twin
            fx("com.fasterxml.jackson.dataformat.yaml.YAMLMapper", "readValue",
                    "(Ljava/io/File;Ljava/lang/Class;)Ljava/lang/Object;", Effect.FS), // format-module subclass
            fx("com.typesafe.config.ConfigFactory", "parseFile", Effect.FS),
            fx("com.typesafe.config.ConfigFactory", "parseString", null),     // in-memory twin
            fx("com.itextpdf.kernel.pdf.PdfWriter", "<init>", "(Ljava/lang/String;)V", Effect.FS),
            fx("com.jcraft.jsch.Session", "connect", Effect.NET),
            fx("com.jcraft.jsch.Session", "setConfig", null),                 // config setter twin
            fx("com.jcraft.jsch.ChannelSftp", "get", Effect.NET),
            fx("com.influxdb.client.WriteApi", "writeRecord", Effect.NET),
            fx("com.couchbase.client.java.Collection", "upsert", Effect.NET),
            fx("com.univocity.parsers.csv.CsvParser", "parse", "(Ljava/io/File;)V", Effect.FS),
            fx("com.univocity.parsers.csv.CsvParser", "parse", "(Ljava/io/Reader;)V", null), // caller stream twin
            fx("com.stripe.model.Charge", "create", Effect.NET),
            fx("com.stripe.model.Charge", "getAmount", null),                 // model getter twin
            fx("com.sendgrid.SendGrid", "api", Effect.NET),
            fx("com.google.crypto.tink.KeysetHandle", "generateNew", Effect.RAND),
            fx("com.zaxxer.hikari.HikariDataSource", "getConnection", Effect.DB));

    // ── classifyComTail ───────────────────────────────────────────────────────────────────────────────
    private static final List<Row> COM_TAIL = List.of(
            fx("com.cloudinary.Uploader", "upload", Effect.NET),
            fx("com.backblaze.b2.client.B2StorageClient", "uploadSmallFile", Effect.NET),
            fx("com.meilisearch.sdk.Index", "search", Effect.NET),
            fx("com.meilisearch.sdk.Client", "index", null),                  // navigator twin
            fx("com.algolia.api.SearchClient", "saveObjects", Effect.NET),
            fx("com.google.firebase.messaging.FirebaseMessaging", "send", Effect.NET),
            fx("com.google.firebase.auth.FirebaseAuth", "createUser", Effect.NET),
            fx("com.google.firebase.auth.FirebaseAuth", "verifyIdToken", null), // local JWT verify twin (documented)
            fx("com.postmarkapp.postmark.client.ApiClient", "deliverMessage", Effect.NET),
            fx("com.mailjet.client.MailjetClient", "post", Effect.NET),
            fx("com.messagebird.MessageBirdClient", "sendMessage", Effect.NET),
            fx("com.plivo.api.models.message.Message", "create", Effect.NET),
            fx("com.pusher.rest.Pusher", "trigger", Effect.NET),
            fx("com.google.api.client.http.HttpRequest", "execute", Effect.NET),
            fx("com.mongodb.client.MongoCollection", "insertOne", Effect.DB),
            fx("com.mongodb.client.MongoCollection", "withDocumentClass", null), // pure view twin
            fx("com.datastax.oss.driver.api.core.CqlSession", "execute", Effect.DB),
            fx("com.fasterxml.jackson.core.JsonFactory", "createParser",
                    "(Ljava/io/File;)Lcom/fasterxml/jackson/core/JsonParser;", Effect.FS), // descriptor-driven batch 30
            fx("com.fasterxml.jackson.core.JsonFactory", "createParser",
                    "(Ljava/lang/String;)Lcom/fasterxml/jackson/core/JsonParser;", null),
            fx("com.twilio.rest.api.v2010.account.MessageCreator", "create", Effect.NET),
            fx("com.twilio.rest.api.v2010.account.MessageCreator", "toString", null), // Object protocol twin
            fx("com.twilio.base.ResourceSet", "iterator", Effect.NET),        // wire call hiding in a for-loop
            fx("com.csvreader.CsvReader", "<init>", "(Ljava/lang/String;)V", Effect.FS),
            fx("com.csvreader.CsvReader", "<init>", "(Ljava/io/Reader;)V", null));

    // ── classifyIo ────────────────────────────────────────────────────────────────────────────────────
    private static final List<Row> IO = List.of(
            fx("io.netty.bootstrap.Bootstrap", "connect", Effect.NET),
            fx("io.netty.bootstrap.Bootstrap", "group", null),                // config twin
            fx("io.netty.channel.ChannelHandlerContext", "writeAndFlush", Effect.NET),
            fx("io.grpc.ClientCall", "sendMessage", Effect.NET),
            fx("io.grpc.stub.ClientCalls", "blockingUnaryCall", Effect.NET),
            fx("io.lettuce.core.api.sync.RedisCommands", "set", Effect.DB),
            fx("io.lettuce.core.api.sync.RedisCommands", "toString", null),   // Object protocol twin
            fx("io.github.cdimascio.dotenv.Dotenv", "load", Effect.FS),
            fx("io.sentry.Sentry", "captureException", Effect.NET),
            fx("io.fabric8.kubernetes.client.dsl.MixedOperation", "list", Effect.NET),
            fx("io.fabric8.kubernetes.client.dsl.MixedOperation", "inNamespace", null), // DSL view twin
            fx("io.etcd.jetcd.KV", "put", Effect.NET),
            fx("io.rsocket.RSocket", "requestResponse", Effect.NET),
            fx("io.pinecone.clients.Index", "upsert", Effect.NET),
            fx("io.qdrant.client.QdrantClient", "upsertAsync", Effect.NET),
            fx("io.milvus.client.MilvusServiceClient", "search", Effect.NET),
            fx("io.restassured.RestAssured", "get", Effect.NET),
            fx("io.restassured.RestAssured", "given", null),                  // builder twin
            fx("io.micronaut.http.client.HttpClient", "retrieve", Effect.NET),
            fx("io.micronaut.http.client.HttpClient", "toBlocking", null),    // adapter twin
            fx("io.vertx.ext.web.client.HttpRequest", "sendJson", Effect.NET),
            fx("io.vertx.core.http.HttpClientRequest", "end", Effect.NET),
            fx("io.r2dbc.spi.Statement", "execute", Effect.DB),
            fx("io.r2dbc.spi.ConnectionFactory", "create", Effect.DB),
            fx("io.jsonwebtoken.JwtParser", "parseClaimsJws", "(Ljava/lang/String;)LJ;", Effect.CLOCK),
            fx("io.jsonwebtoken.Jwts", "parserBuilder", "()LB;", null),       // no-arg factory twin (review fix pin)
            fx("io.jsonwebtoken.security.Keys", "secretKeyFor", Effect.RAND),
            fx("io.pebbletemplates.pebble.PebbleEngine", "getTemplate", Effect.FS),
            fx("io.minio.MinioClient", "putObject", Effect.NET));

    // ── classifyOther (misc first-segments: groovy/kotlin/scala/net/okhttp3/…) ────────────────────────
    private static final List<Row> OTHER = List.of(
            fx("groovy.lang.GroovyShell", "evaluate", Effect.UNKNOWN),
            fx("bsh.Interpreter", "eval", Effect.UNKNOWN),
            fx("clojure.lang.Compiler", "eval", Effect.UNKNOWN),
            fx("sun.misc.Unsafe", "allocateInstance", Effect.UNKNOWN),
            fx("ognl.Ognl", "getValue", Effect.UNKNOWN),
            fx("ai.onnxruntime.OrtSession", "run", Effect.UNKNOWN),
            fx("ai.onnxruntime.OrtEnvironment", "createSession", "(Ljava/lang/String;)LS;", Effect.FS),
            fx("liquibase.Liquibase", "update", Effect.DB),
            fx("liquibase.Liquibase", "getDatabase", null),                   // accessor twin
            fx("feign.Client", "execute", Effect.NET),
            fx("net.schmizz.sshj.SSHClient", "connect", Effect.NET),
            fx("freemarker.template.Configuration", "getTemplate", Effect.FS),
            fx("reactor.netty.http.client.HttpClient$ResponseReceiver", "response", Effect.NET),
            fx("kong.unirest.HttpRequest", "asString", Effect.NET),
            fx("net.coobird.thumbnailator.Thumbnails", "of", "([Ljava/io/File;)LB;", Effect.FS),
            fx("net.coobird.thumbnailator.Thumbnails", "of", "([Ljava/io/InputStream;)LB;", null), // stream twin
            fx("dev.langchain4j.model.chat.ChatLanguageModel", "generate", Effect.NET),
            fx("dev.langchain4j.model.embedding.EmbeddingModel", "embed", null), // may be in-process — no fabrication
            fx("net.dv8tion.jda.api.requests.RestAction", "queue", Effect.NET),
            fx("spark.Spark", "init", Effect.NET),
            fx("net.bramp.ffmpeg.FFmpeg", "run", Effect.EXEC),
            fx("edu.stanford.nlp.pipeline.StanfordCoreNLP", "<init>", Effect.FS),
            fx("groovy.sql.Sql", "eachRow", Effect.DB),
            fx("groovy.sql.Sql", "close", null),                              // lifecycle twin
            fx("kotlin.io.FilesKt", "readText", "(Ljava/io/File;Ljava/nio/charset/Charset;)Ljava/lang/String;", Effect.FS),
            fx("kotlin.io.FilesKt", "relativeTo", "(Ljava/io/File;Ljava/io/File;)Ljava/io/File;", null), // path algebra twin
            fx("kotlin.io.TextStreamsKt", "readText", "(Ljava/net/URL;)Ljava/lang/String;", Effect.NET), // URL receiver
            fx("kotlin.random.Random", "nextInt", Effect.RAND),
            fx("kotlin.collections.CollectionsKt", "shuffled", Effect.RAND),
            fx("kotlin.collections.CollectionsKt", "first", null),            // pure collection verb twin
            fx("scala.io.Source$", "fromFile", Effect.FS),
            fx("scala.io.Source$", "fromURL", Effect.NET),
            fx("scala.io.Source$", "fromString", null),                       // in-memory twin
            fx("scala.sys.process.ProcessBuilderImpl", "run", Effect.EXEC),
            fx("okhttp3.Call", "execute", Effect.NET),
            fx("retrofit2.Call", "execute", Effect.NET),
            fx("redis.clients.jedis.Jedis", "set", Effect.DB),                // the Redis→Db reconciliation
            fx("redis.clients.jedis.Jedis", "isConnected", null),             // cached-handle accessor twin
            fx("net.spy.memcached.MemcachedClient", "get", Effect.NET));      // Memcached stays Net (deliberate)

    private static void check(String bucket, List<Row> rows, List<String> mismatches) {
        for (Row r : rows) {
            Effect got = Classifier.classify(r.owner(), r.method(), r.desc());
            if (got != r.want()) {
                mismatches.add(bucket + ": " + r.owner() + "." + r.method() + " " + r.desc()
                        + " → " + got + " (want " + r.want() + ")");
            }
        }
    }

    @Test
    void classifierTableRowsMapAsDocumented() {
        List<String> mismatches = new ArrayList<>();
        check("classifyJava", JAVA, mismatches);
        check("classifyOrg", ORG, mismatches);
        check("classifyCom", COM, mismatches);
        check("classifyComTail", COM_TAIL, mismatches);
        check("classifyIo", IO, mismatches);
        check("classifyOther", OTHER, mismatches);
        assertEquals(List.of(), mismatches, "every table row (positive + anti-fabrication twin) must hold");
    }
}
