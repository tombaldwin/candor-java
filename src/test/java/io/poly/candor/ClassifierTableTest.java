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

    // ── wave 2: the rule clusters a coverage re-measure showed still unexecuted ──────────────────────

    private static final List<Row> JAVA_2 = List.of(
            fx("java.sql.DriverManager", "getConnection", Effect.DB),
            fx("java.sql.ResultSet", "next", Effect.DB),
            fx("java.util.logging.Logger", "info", Effect.LOG),
            fx("java.util.logging.Logger", "isLoggable", null),          // level query twin
            fx("java.lang.System$Logger", "log", Effect.LOG),
            fx("java.awt.Desktop", "browseFileDirectory", Effect.EXEC),
            fx("java.lang.ProcessHandle", "destroy", Effect.EXEC),
            fx("java.lang.System", "loadLibrary", Effect.EXEC),
            fx("java.util.Random", "nextInt", Effect.RAND),
            fx("java.net.URL", "openStream", Effect.NET),
            fx("java.net.InetAddress", "getLoopbackAddress", null),      // no-lookup accessor twin
            fx("java.time.LocalDate", "now", Effect.CLOCK),
            fx("java.io.RandomAccessFile", "read", Effect.FS),
            fx("java.io.File", "exists", Effect.FS));

    private static final List<Row> ORG_2 = List.of(
            fx("org.asynchttpclient.AsyncHttpClient", "executeRequest", Effect.NET),
            fx("org.apache.velocity.app.VelocityEngine", "getTemplate", Effect.FS),
            fx("org.apache.commons.vfs2.FileContent", "getInputStream", Effect.FS),
            fx("org.rocksdb.RocksDB", "put", Effect.FS),                 // embedded store = local files
            fx("org.mapdb.DBMaker", "fileDB", Effect.FS),
            fx("org.mapdb.DBMaker", "memoryDB", null),                   // in-memory twin
            fx("org.apache.lucene.store.FSDirectory", "open", Effect.FS),
            fx("org.testcontainers.containers.GenericContainer", "start", Effect.EXEC),
            fx("org.testcontainers.containers.GenericContainer", "withExposedPorts", null), // builder twin
            fx("org.openqa.selenium.WebDriver", "get", Effect.NET),
            fx("org.apache.camel.ProducerTemplate", "sendBody", Effect.NET),
            fx("org.zeromq.ZMQ$Socket", "send", Effect.NET),
            fx("org.apache.thrift.transport.TSocket", "open", Effect.NET),
            fx("org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator", "generateKeyPair", Effect.RAND),
            fx("org.jdbi.v3.core.Handle", "createQuery", Effect.DB),
            fx("org.springframework.data.couchbase.core.CouchbaseTemplate", "save", Effect.DB),
            fx("org.apache.commons.mail.Email", "send", Effect.NET),
            fx("org.im4java.core.ConvertCmd", "run", Effect.EXEC),
            fx("org.eclipse.jetty.client.HttpClient", "GET", Effect.NET),
            fx("org.eclipse.jetty.client.Request", "send", Effect.NET),
            fx("org.apache.activemq.artemis.api.core.client.ClientProducer", "send", Effect.NET),
            fx("org.jasypt.encryption.pbe.StandardPBEStringEncryptor", "encrypt", Effect.RAND),
            fx("org.redisson.api.RMap", "put", Effect.DB),               // Redis → Db reconciliation
            fx("org.apache.curator.framework.api.GetDataBuilder", "forPath", Effect.NET),
            fx("org.apache.solr.client.solrj.SolrClient", "getById", Effect.NET),
            fx("org.apache.tinkerpop.gremlin.driver.Client", "submit", Effect.NET),
            fx("org.web3j.protocol.core.Request", "send", Effect.NET),
            fx("org.springframework.ai.chat.model.ChatModel", "call", Effect.NET),
            fx("org.telegram.telegrambots.bots.AbsSender", "execute", Effect.NET),
            fx("org.springframework.batch.core.launch.JobLauncher", "run", Effect.DB),
            fx("org.springframework.data.elasticsearch.core.ElasticsearchOperations", "search", Effect.NET),
            fx("org.springframework.data.neo4j.core.Neo4jTemplate", "save", Effect.DB),
            fx("org.springframework.ldap.core.LdapTemplate", "search", Effect.NET),
            fx("org.apache.geode.cache.Region", "put", Effect.NET),
            fx("org.simplejavamail.api.mailer.Mailer", "sendMail", Effect.NET),
            fx("org.hibernate.StatelessSession", "insert", Effect.DB),
            fx("org.hibernate.query.MutationQuery", "executeUpdate", Effect.DB),
            fx("org.jooq.Query", "execute", Effect.DB),
            fx("org.jooq.ResultQuery", "fetchOne", Effect.DB),
            fx("org.apache.ibatis.session.SqlSession", "flushStatements", Effect.DB),
            fx("org.neo4j.driver.Session", "writeTransaction", Effect.DB),
            fx("org.apache.commons.exec.DefaultExecutor", "execute", Effect.EXEC),
            fx("org.springframework.core.env.Environment", "getProperty", Effect.ENV),
            fx("org.apache.commons.lang3.SystemUtils", "getEnvironmentVariable", Effect.ENV),
            fx("org.joda.time.DateTime", "now", Effect.CLOCK),
            fx("org.joda.time.DateTimeUtils", "currentTimeMillis", Effect.CLOCK),
            fx("org.apache.commons.lang3.RandomStringUtils", "randomAlphanumeric", Effect.RAND),
            fx("org.apache.commons.lang3.SystemProperties", "getJavaVersion", Effect.ENV),
            fx("org.slf4j.Logger", "info", Effect.LOG),                  // shared logging facade
            fx("org.slf4j.Logger", "isDebugEnabled", null));             // level-query twin

    private static final List<Row> COM_2 = List.of(
            fx("com.google.cloud.bigquery.BigQuery", "query", Effect.NET),
            fx("com.google.cloud.firestore.DocumentReference", "set", Effect.NET),
            fx("com.google.cloud.firestore.DocumentSnapshot", "get", null), // already-fetched snapshot twin (documented)
            fx("com.google.cloud.pubsub.v1.Publisher", "publish", Effect.NET),
            fx("com.github.dockerjava.api.command.CreateContainerCmd", "exec", Effect.NET),
            fx("com.github.dockerjava.api.command.CreateContainerCmd", "withName", null), // builder twin
            fx("com.orbitz.consul.KeyValueClient", "getValue", Effect.NET),
            fx("com.unboundid.ldap.sdk.LDAPConnection", "search", Effect.NET),
            fx("com.github.sardine.Sardine", "put", Effect.NET),
            fx("com.google.cloud.spanner.ReadContext", "executeQuery", Effect.DB),
            fx("com.azure.cosmos.CosmosContainer", "createItem", Effect.NET),
            fx("com.azure.messaging.servicebus.ServiceBusSenderClient", "sendMessage", Effect.NET),
            fx("com.azure.security.keyvault.secrets.SecretClient", "getSecret", Effect.NET),
            fx("com.google.cloud.secretmanager.v1.SecretManagerServiceClient", "accessSecretVersion", Effect.NET),
            fx("com.theokanning.openai.service.OpenAiService", "createCompletion", Effect.NET),
            fx("com.anthropic.services.MessageService", "create", Effect.NET),
            fx("com.aerospike.client.AerospikeClient", "put", Effect.NET),
            fx("com.azure.messaging.eventhubs.EventHubProducerClient", "send", Effect.NET),
            fx("com.azure.data.tables.TableClient", "createEntity", Effect.NET),
            fx("com.slack.api.methods.MethodsClient", "chatPostMessage", Effect.NET),
            fx("com.slack.api.methods.MethodsClient", "toString", null), // Object protocol twin
            fx("com.okta.sdk.resource.client.ApiClient", "invokeAPI", Effect.NET),
            fx("com.braintreegateway.TransactionGateway", "sale", Effect.NET),
            fx("com.braintreegateway.BraintreeGateway", "sale", null),   // pure navigator owner (documented)
            fx("com.google.maps.GeocodingApiRequest", "await", Effect.NET),
            fx("com.clickhouse.client.ClickHouseClient", "execute", Effect.DB),
            fx("com.orientechnologies.orient.core.db.ODatabaseSession", "query", Effect.DB),
            fx("com.arangodb.ArangoDatabase", "query", Effect.NET),
            fx("com.rethinkdb.gen.ast.ReqlExpr", "run", Effect.NET),
            fx("com.rethinkdb.net.Connection$Builder", "connect", Effect.NET),
            fx("com.github.jknack.handlebars.Handlebars", "compile", Effect.FS),
            fx("com.github.mustachejava.DefaultMustacheFactory", "compile", "(Ljava/lang/String;)LM;", Effect.FS),
            fx("com.aliyun.oss.OSSClient", "putObject", Effect.NET),
            fx("com.drew.imaging.ImageMetadataReader", "readMetadata", "(Ljava/io/File;)LM;", Effect.FS),
            fx("com.drew.imaging.ImageMetadataReader", "readMetadata", "(Ljava/io/InputStream;)LM;", null),
            fx("com.razorpay.PaymentClient", "create", Effect.NET),
            fx("com.adyen.service.checkout.PaymentsApi", "payments", Effect.NET),
            fx("com.google.firebase.auth.FirebaseAuth", "createCustomToken", null)); // local JWT sign twin (documented)

    private static final List<Row> IO_2 = List.of(
            fx("io.minio.MinioAsyncClient", "getObject", Effect.NET),
            fx("io.opentelemetry.sdk.trace.export.SpanExporter", "export", Effect.NET),
            fx("io.awspring.cloud.ses.SimpleEmailServiceMailSender", "send", Effect.NET),
            fx("io.lettuce.core.api.async.RedisAsyncCommands", "get", Effect.DB),
            fx("io.qdrant.client.QdrantClient", "close", null));         // non-Async lifecycle twin

    private static final List<Row> OTHER_2 = List.of(
            fx("okio.Okio", "source", "(Ljava/io/File;)Lokio/Source;", Effect.FS),
            fx("okio.Okio", "source", "(Ljava/net/Socket;)Lokio/Source;", Effect.NET), // socket stream, not a file
            fx("reactor.netty.http.client.HttpClient", "responseConnection", Effect.NET),
            fx("android.database.sqlite.SQLiteOpenHelper", "getWritableDatabase", Effect.DB),
            fx("android.webkit.WebView", "loadUrl", Effect.NET),
            fx("android.provider.Settings$Secure", "getFloat", Effect.ENV),
            fx("android.content.SharedPreferences$Editor", "commit", Effect.FS),
            fx("software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider", "resolveCredentials", Effect.ENV),
            fx("net.spy.memcached.MemcachedClient", "isConnected", null)); // cached-handle twin

    // ── wave 3: full VERB sweeps for the member/verb tables (TESTING.md §2.3 — every verb of a table
    // is a κ rule of its own; a typo'd verb un-classifies ONLY that verb, which nothing else catches) ──

    /** One row per verb, same owner/effect — the compact verb-table sweep. */
    private static List<Row> verbs(String owner, Effect want, String... methods) {
        List<Row> rows = new ArrayList<>();
        for (String m : methods) rows.add(fx(owner, m, want));
        return rows;
    }

    private static List<Row> verbSweeps() {
        List<Row> r = new ArrayList<>();
        // classifyJava / shared
        r.addAll(verbs("java.util.prefs.Preferences", Effect.FS,
                "get", "put", "remove", "flush", "sync", "removeNode", "clear",
                "exportNode", "exportSubtree", "importPreferences"));
        r.addAll(verbs("java.lang.Process", Effect.EXEC, "destroy", "destroyForcibly"));
        // classifyOrg (+ tails)
        r.addAll(verbs("org.apache.commons.net.ftp.FTPClient", Effect.NET,
                "connect", "disconnect", "login", "logout", "retrieveFile", "retrieveFileStream",
                "storeFile", "storeFileStream", "appendFile", "appendFileStream", "listFiles",
                "listDirectories", "listNames", "deleteFile", "makeDirectory", "removeDirectory",
                "changeWorkingDirectory", "rename", "sendCommand", "getReply", "completePendingCommand", "abort"));
        r.addAll(verbs("org.apache.commons.io.FileUtils", Effect.FS,
                "readLines", "writeStringToFile", "copyFile", "moveFile", "deleteQuietly", "forceDelete",
                "touch", "cleanDirectory", "listFiles", "openInputStream", "openOutputStream", "iterateFiles"));
        // IOUtils: File/URL overloads are Fs/Net; a caller-opened STREAM overload is pure-relative (the
        // source/sink stance charges at creation, not at each read — see ClassifierLongTailTest).
        r.add(fx("org.apache.commons.io.IOUtils", "toByteArray", "(Ljava/net/URL;)[B", Effect.NET));
        r.add(fx("org.apache.commons.io.IOUtils", "toByteArray", "(Ljava/io/InputStream;)[B", null));
        r.add(fx("org.apache.commons.io.IOUtils", "copy", "(Ljava/io/InputStream;Ljava/io/OutputStream;)I", null));
        r.addAll(verbs("org.flywaydb.core.Flyway", Effect.DB,
                "migrate", "clean", "validate", "baseline", "repair", "info"));
        r.addAll(verbs("org.rocksdb.RocksDB", Effect.FS,
                "open", "openReadOnly", "get", "write", "merge", "delete", "deleteRange",
                "newIterator", "multiGetAsList", "flush"));
        r.addAll(verbs("org.redisson.api.RMap", Effect.DB,
                "get", "set", "getAndSet", "putIfAbsent", "remove", "add", "contains", "containsKey",
                "isExists", "delete", "trySet", "compareAndSet", "fastPut", "fastRemove", "expire"));
        r.addAll(verbs("org.springframework.ldap.core.LdapTemplate", Effect.NET,
                "lookup", "bind", "unbind", "rebind", "modifyAttributes", "lookupContext",
                "searchForObject", "searchForContext", "authenticate", "list", "listBindings", "rename"));
        r.addAll(verbs("org.apache.geode.cache.Region", Effect.NET,
                "get", "putAll", "getAll", "remove", "removeAll", "create", "invalidate", "destroy",
                "putIfAbsent", "replace", "query", "containsKey", "containsValueForKey", "keySetOnServer"));
        r.addAll(verbs("org.springframework.data.elasticsearch.core.ElasticsearchOperations", Effect.NET,
                "save", "saveAll", "searchForStream", "get", "multiGet", "delete", "deleteAll",
                "index", "bulkIndex", "bulkUpdate", "count", "searchSimilar", "update"));
        r.addAll(verbs("org.hibernate.StatelessSession", Effect.DB,
                "insertMultiple", "update", "updateMultiple", "upsert", "upsertMultiple",
                "delete", "deleteMultiple", "get", "getMultiple", "getIdentifier", "refresh", "fetch"));
        r.addAll(verbs("org.jsoup.Connection", Effect.NET, "get", "post"));
        r.addAll(verbs("org.apache.camel.ProducerTemplate", Effect.NET,
                "sendBodyAndHeader", "requestBody", "asyncSendBody", "asyncRequestBody"));
        // classifyCom
        r.addAll(verbs("com.couchbase.client.java.Collection", Effect.NET,
                "get", "insert", "replace", "remove", "exists", "getAndLock", "getAndTouch",
                "touch", "unlock", "mutateIn", "lookupIn", "scan"));
        r.addAll(verbs("com.aerospike.client.AerospikeClient", Effect.NET,
                "get", "delete", "exists", "operate", "query", "scanAll", "add", "append",
                "prepend", "execute", "truncate"));
        r.addAll(verbs("com.google.cloud.bigquery.BigQuery", Effect.NET,
                "insertAll", "listTableData", "getQueryResults"));
        r.addAll(verbs("com.google.cloud.firestore.DocumentReference", Effect.NET,
                "get", "getAll", "update", "delete", "create", "add", "commit"));
        r.addAll(verbs("com.orbitz.consul.KeyValueClient", Effect.NET,
                "getValues", "getKeys", "putValue", "deleteKey"));
        r.addAll(verbs("com.unboundid.ldap.sdk.LDAPConnection", Effect.NET,
                "bind", "connect", "modify", "add", "delete", "compare", "modifyDN"));
        r.addAll(verbs("com.github.sardine.Sardine", Effect.NET,
                "get", "delete", "list", "exists", "move", "copy"));
        r.addAll(verbs("com.google.cloud.spanner.ReadContext", Effect.DB,
                "read", "readRow", "executeQueryAsync", "readUsingIndex"));
        r.addAll(verbs("com.azure.cosmos.CosmosContainer", Effect.NET,
                "readItem", "upsertItem", "deleteItem", "replaceItem", "queryItems", "patchItem"));
        r.addAll(verbs("com.azure.messaging.servicebus.ServiceBusSenderClient", Effect.NET,
                "sendMessages", "scheduleMessage", "scheduleMessages"));
        r.addAll(verbs("com.azure.security.keyvault.secrets.SecretClient", Effect.NET,
                "setSecret", "getDeletedSecret", "beginDeleteSecret", "listPropertiesOfSecrets"));
        r.addAll(verbs("com.google.cloud.secretmanager.v1.SecretManagerServiceClient", Effect.NET,
                "getSecret", "createSecret", "addSecretVersion", "listSecrets"));
        r.addAll(verbs("com.azure.data.tables.TableClient", Effect.NET,
                "getEntity", "updateEntity", "deleteEntity", "upsertEntity", "listEntities"));
        r.addAll(verbs("com.braintreegateway.TransactionGateway", Effect.NET,
                "create", "find", "submitForSettlement", "refund", "void", "delete", "update",
                "search", "cancel"));
        r.addAll(verbs("com.orientechnologies.orient.core.db.ODatabaseSession", Effect.DB,
                "command", "execute", "save", "load", "commit", "begin", "delete"));
        r.addAll(verbs("com.clickhouse.client.ClickHouseClient", Effect.DB, "send", "executeAndWait"));
        r.addAll(verbs("com.aliyun.oss.OSSClient", Effect.NET,
                "getObject", "deleteObject", "deleteObjects", "listObjects", "copyObject",
                "doesObjectExist", "getObjectMetadata", "appendObject", "uploadPart",
                "initiateMultipartUpload", "completeMultipartUpload"));
        r.addAll(verbs("com.mongodb.client.MongoCollection", Effect.DB,
                "find", "updateOne", "replaceOne", "deleteMany", "aggregate", "countDocuments",
                "estimatedDocumentCount", "distinct", "bulkWrite", "watch", "createIndex", "drop"));
        r.addAll(verbs("com.google.firebase.auth.FirebaseAuth", Effect.NET,
                "getUser", "updateUser", "deleteUser", "getUserByEmail", "listUsers",
                "setCustomUserClaims", "revokeRefreshTokens", "generatePasswordResetLink", "importUsers"));
        r.addAll(verbs("com.stripe.model.Charge", Effect.NET,
                "retrieve", "update", "list", "delete", "cancel", "capture", "confirm", "search"));
        r.addAll(verbs("com.google.common.io.Files", Effect.FS,
                "write", "copy", "move", "readLines", "createParentDirs", "touch",
                "deleteRecursively", "deleteDirectoryContents"));
        // classifyComTail
        r.addAll(verbs("com.vonage.client.SmsClient", Effect.NET, "submitMessage", "sendMessage", "send"));
        r.addAll(verbs("com.backblaze.b2.client.B2StorageClient", Effect.NET,
                "downloadById", "getFileInfo", "deleteFileVersion", "listFileNames", "copyFile"));
        r.addAll(verbs("com.cloudinary.Uploader", Effect.NET, "destroy", "rename", "explicit"));
        r.addAll(verbs("com.meilisearch.sdk.Index", Effect.NET,
                "addDocuments", "updateDocuments", "deleteDocument", "getDocument"));
        r.addAll(verbs("com.meilisearch.sdk.Client", Effect.NET, "createIndex", "deleteIndex", "getIndexes"));
        r.addAll(verbs("com.algolia.api.SearchClient", Effect.NET,
                "searchSingleIndex", "deleteObjects", "getObject", "partialUpdateObject", "batch"));
        r.addAll(verbs("com.plivo.api.models.message.Message", Effect.NET, "update", "fetch", "delete"));
        r.addAll(verbs("com.mailjet.client.MailjetClient", Effect.NET, "get", "put", "delete"));
        r.addAll(verbs("com.google.firebase.messaging.FirebaseMessaging", Effect.NET,
                "sendMulticast", "subscribeToTopic", "unsubscribeFromTopic"));
        // the Twilio terminal pattern: each resource-suffix owner + its sync/async verb pair
        r.addAll(verbs("com.twilio.rest.api.v2010.account.MessageCreator", Effect.NET, "createAsync"));
        r.addAll(verbs("com.twilio.rest.api.v2010.account.MessageReader", Effect.NET, "read", "readAsync"));
        r.addAll(verbs("com.twilio.rest.api.v2010.account.MessageFetcher", Effect.NET, "fetch", "fetchAsync"));
        r.addAll(verbs("com.twilio.rest.api.v2010.account.MessageUpdater", Effect.NET, "update", "updateAsync"));
        r.addAll(verbs("com.twilio.rest.api.v2010.account.MessageDeleter", Effect.NET, "delete", "deleteAsync"));
        // classifyIo
        r.addAll(verbs("io.fabric8.kubernetes.client.dsl.MixedOperation", Effect.NET,
                "create", "get", "delete", "replace", "update", "patch", "edit", "watch",
                "createOrReplace", "serverSideApply", "getLog", "exec", "getList"));
        r.addAll(verbs("io.milvus.client.MilvusServiceClient", Effect.NET,
                "insert", "query", "delete", "upsert", "get", "createCollection",
                "dropCollection", "loadCollection", "flush"));
        r.addAll(verbs("io.pinecone.clients.Index", Effect.NET,
                "query", "fetch", "update", "deleteByIds", "deleteAll", "describeIndexStats", "list"));
        r.addAll(verbs("io.etcd.jetcd.KV", Effect.NET, "get", "delete", "txn"));
        r.addAll(verbs("io.rsocket.RSocket", Effect.NET,
                "fireAndForget", "requestStream", "requestChannel", "metadataPush"));
        r.addAll(verbs("io.restassured.RestAssured", Effect.NET,
                "post", "put", "delete", "patch", "head", "options"));
        r.addAll(verbs("io.netty.channel.Channel", Effect.NET,
                "write", "writeAndFlush", "connect", "flush", "bind"));
        r.addAll(verbs("io.grpc.ClientCall", Effect.NET, "halfClose", "start", "request"));
        // classifyOther (+ tail)
        r.addAll(verbs("kong.unirest.HttpRequest", Effect.NET,
                "asJson", "asObject", "asBytes", "asEmpty", "asFile", "asPaged"));
        r.addAll(verbs("groovy.sql.Sql", Effect.DB,
                "execute", "executeInsert", "executeUpdate", "rows", "firstRow", "query",
                "call", "callWithRows", "withBatch"));
        r.addAll(verbs("kotlinx.io.files.FileSystem", Effect.FS,
                "source", "sink", "delete", "createDirectories", "atomicMove", "list", "metadataOrNull"));
        r.addAll(verbs("kotlin.io.FilesKt", Effect.FS,
                "writeText", "appendText", "copyTo", "deleteRecursively", "walkTopDown",
                "forEachLine", "useLines", "inputStream", "outputStream", "bufferedReader",
                "bufferedWriter", "printWriter", "reader", "writer"));
        r.addAll(verbs("kotlin.collections.CollectionsKt", Effect.RAND, "random", "randomOrNull", "shuffle"));
        r.addAll(verbs("net.rubyeye.xmemcached.XMemcachedClient", Effect.NET,
                "get", "set", "delete", "add", "replace", "incr", "decr", "append", "prepend"));
        r.addAll(verbs("net.dv8tion.jda.api.requests.RestAction", Effect.NET,
                "complete", "submit", "queueAfter", "submitAfter"));
        r.addAll(verbs("redis.clients.jedis.Jedis", Effect.DB, "get", "hset", "expire", "publish"));

        // classifyJava — the remaining Unknown-sink / Fs / socket-family / clock / rand rows
        r.addAll(verbs("java.lang.Class", Effect.UNKNOWN, "newInstance"));
        r.addAll(verbs("java.lang.reflect.Constructor", Effect.UNKNOWN, "newInstance"));
        r.addAll(verbs("java.lang.reflect.Proxy", Effect.UNKNOWN, "newProxyInstance"));
        r.addAll(verbs("java.lang.invoke.MethodHandle", Effect.UNKNOWN, "invokeExact"));
        r.addAll(verbs("java.io.ObjectInputStream", Effect.UNKNOWN, "readUnshared"));
        r.addAll(verbs("java.beans.XMLDecoder", Effect.UNKNOWN, "readObject"));
        r.addAll(verbs("java.net.URLClassLoader", Effect.UNKNOWN, "<init>", "loadClass"));
        r.addAll(verbs("java.lang.ClassLoader", Effect.UNKNOWN, "defineClass"));
        r.addAll(verbs("java.lang.foreign.SymbolLookup", Effect.UNKNOWN, "find"));
        r.addAll(verbs("java.lang.foreign.Linker", Effect.UNKNOWN, "upcallStub"));
        r.addAll(verbs("java.lang.instrument.Instrumentation", Effect.UNKNOWN, "redefineClasses", "retransformClasses"));
        r.addAll(verbs("java.io.FileInputStream", Effect.FS, "<init>", "read"));
        r.addAll(verbs("java.io.FileOutputStream", Effect.FS, "write"));
        r.addAll(verbs("java.io.FileReader", Effect.FS, "<init>"));
        r.addAll(verbs("java.io.FileWriter", Effect.FS, "<init>"));
        r.addAll(verbs("java.io.RandomAccessFile", Effect.FS, "write", "seek"));
        r.addAll(verbs("java.nio.channels.FileChannel", Effect.FS, "open", "map"));
        r.addAll(verbs("java.nio.channels.AsynchronousFileChannel", Effect.FS, "open"));
        r.addAll(verbs("java.util.zip.ZipFile", Effect.FS, "entries", "getInputStream"));
        r.addAll(verbs("java.nio.MappedByteBuffer", Effect.FS, "get", "put", "load", "isLoaded"));
        r.addAll(verbs("java.nio.file.FileStore", Effect.FS, "getUsableSpace", "type", "isReadOnly",
                "supportsFileAttributeView"));
        r.addAll(verbs("java.lang.ClassLoader", Effect.FS, "getResource", "getResources",
                "getSystemResourceAsStream", "getSystemResource", "getSystemResources"));
        r.addAll(verbs("java.lang.Module", Effect.FS, "getResourceAsStream"));
        r.addAll(verbs("java.nio.file.WatchService", Effect.FS, "poll"));
        r.addAll(verbs("java.nio.file.Path", Effect.FS, "register"));
        r.addAll(verbs("java.security.KeyPairGenerator", Effect.RAND, "genKeyPair"));
        r.addAll(verbs("java.nio.channels.Selector", Effect.NET, "selectNow"));
        r.addAll(verbs("java.nio.channels.MulticastChannel", Effect.NET, "join"));
        r.addAll(verbs("java.net.ServerSocket", Effect.NET, "accept", "bind"));
        r.addAll(verbs("java.net.DatagramSocket", Effect.NET, "send", "receive"));
        r.addAll(verbs("java.net.MulticastSocket", Effect.NET, "joinGroup"));
        r.addAll(verbs("java.nio.channels.ServerSocketChannel", Effect.NET, "accept"));
        r.addAll(verbs("java.nio.channels.DatagramChannel", Effect.NET, "send"));
        r.addAll(verbs("java.nio.channels.AsynchronousSocketChannel", Effect.NET, "connect"));
        r.addAll(verbs("java.rmi.Naming", Effect.NET, "lookup"));
        r.addAll(verbs("java.rmi.registry.LocateRegistry", Effect.NET, "getRegistry"));
        r.addAll(verbs("java.security.cert.CertStore", Effect.NET, "getCertificates", "getCRLs"));
        r.addAll(verbs("java.sql.CallableStatement", Effect.DB, "execute"));
        r.addAll(verbs("java.awt.Toolkit", Effect.CLIPBOARD, "getSystemClipboard", "getSystemSelection"));
        r.addAll(verbs("java.awt.datatransfer.Clipboard", Effect.CLIPBOARD, "getContents", "setContents"));
        r.addAll(verbs("java.time.Instant", Effect.CLOCK, "now"));
        r.addAll(verbs("java.time.LocalDateTime", Effect.CLOCK, "now"));
        r.addAll(verbs("java.time.ZonedDateTime", Effect.CLOCK, "now"));
        r.addAll(verbs("java.time.OffsetDateTime", Effect.CLOCK, "now"));
        r.add(fx("java.util.Date", "<init>", "()V", Effect.CLOCK));
        r.add(fx("java.util.Date", "<init>", "(J)V", null));              // valued ctor — no clock read (twin)
        r.addAll(verbs("java.security.SecureRandom", Effect.RAND, "nextBytes"));
        r.addAll(verbs("java.util.concurrent.ThreadLocalRandom", Effect.RAND, "nextLong"));
        r.addAll(verbs("java.util.SplittableRandom", Effect.RAND, "nextInt"));
        r.addAll(verbs("java.util.random.RandomGenerator", Effect.RAND, "nextDouble"));
        r.add(fx("java.util.random.RandomGenerator", "isDeprecated", null)); // pure metadata twin (sweep 22)
        r.add(fx("java.lang.Math", "random", Effect.RAND));
        r.add(fx("java.util.UUID", "fromString", null));                  // pure value-op twin

        // classifyOrg — remaining descriptor variants + verb rows
        r.add(fx("org.apache.commons.compress.archivers.sevenz.SevenZFile", "<init>", "(Ljava/io/File;)V", Effect.FS));
        r.add(fx("org.apache.commons.compress.archivers.tar.TarFile", "<init>", "(Ljava/nio/file/Path;)V", Effect.FS));
        r.add(fx("org.opensearch.client.RestClient", "performRequest", Effect.NET));
        r.add(fx("org.elasticsearch.client.RestClient", "performRequestAsync", Effect.NET));
        r.add(fx("org.apache.avro.file.DataFileReader", "<init>", "(Ljava/io/File;LD;)V", Effect.FS));
        r.add(fx("org.apache.avro.file.DataFileWriter", "create", "(LS;Ljava/io/File;)LW;", Effect.FS));
        r.add(fx("org.apache.commons.configuration2.builder.fluent.Configurations", "properties",
                "(Ljava/io/File;)LC;", Effect.FS));
        r.add(fx("org.apache.commons.configuration2.builder.fluent.Configurations", "xml",
                "(Ljava/net/URL;)LC;", Effect.NET));
        r.add(fx("org.springframework.mail.MailSender", "send", Effect.NET));
        r.add(fx("org.springframework.mail.javamail.JavaMailSenderImpl", "doSend", Effect.NET));
        r.add(fx("org.springframework.data.repository.CrudRepository", "save", Effect.DB));
        r.add(fx("org.springframework.data.redis.core.SetOperations", "add", Effect.DB));
        r.add(fx("org.apache.poi.xssf.usermodel.XSSFWorkbookFactory", "create", "(Ljava/io/File;)LW;", Effect.FS));
        r.add(fx("org.eclipse.jgit.api.Git", "open", "(Ljava/nio/file/Path;)LG;", Effect.FS));
        r.add(fx("org.apache.tika.Tika", "parseToString", "(Ljava/nio/file/Path;)Ljava/lang/String;", Effect.FS));
        r.add(fx("org.apache.pdfbox.Loader", "loadPDF", "(Ljava/nio/file/Path;)LD;", Effect.FS));
        r.add(fx("org.apache.velocity.app.VelocityEngine", "mergeTemplate", Effect.FS));
        r.add(fx("org.apache.commons.vfs2.FileContent", "getOutputStream", Effect.FS));
        r.add(fx("org.im4java.process.ProcessStarter", "run", Effect.EXEC));
        r.add(fx("org.apache.thrift.transport.TNonblockingSocket", "read", Effect.NET));
        r.add(fx("org.apache.thrift.transport.TSocket", "write", Effect.NET));
        r.add(fx("org.zeromq.ZMQ$Socket", "recv", Effect.NET));
        r.add(fx("org.web3j.protocol.core.Request", "sendAsync", Effect.NET));
        r.add(fx("org.apache.tinkerpop.gremlin.driver.Client", "submitAsync", Effect.NET));
        r.add(fx("org.joda.time.LocalDate", "now", Effect.CLOCK));
        r.add(fx("org.joda.time.DateTimeUtils", "currentTimeMillis", Effect.CLOCK));
        r.add(fx("org.apache.commons.lang3.RandomUtils", "nextInt", Effect.RAND));
        r.add(fx("org.docx4j.openpackaging.packages.WordprocessingMLPackage", "load", "(Ljava/io/File;)LP;", Effect.FS));

        // classifyOther — remaining dynamic-dispatch / stdlib rows
        r.add(fx("groovy.lang.MetaClassImpl", "invokeMethod", Effect.UNKNOWN));
        r.add(fx("groovy.lang.GroovyObject", "invokeMethod", Effect.UNKNOWN));
        r.add(fx("groovy.lang.MetaObjectProtocol", "invokeMethod", Effect.UNKNOWN));
        r.add(fx("groovy.lang.GroovyShell", "run", Effect.UNKNOWN));
        r.add(fx("groovy.lang.Script", "evaluate", Effect.UNKNOWN));
        r.add(fx("groovy.util.Eval", "me", Effect.UNKNOWN));               // whole-owner eval
        r.add(fx("groovy.lang.GroovyClassLoader", "parseClass", Effect.UNKNOWN));
        r.addAll(verbs("sun.misc.Unsafe", Effect.UNKNOWN, "putLong", "getInt", "allocateMemory", "defineClass"));
        r.add(fx("jdk.internal.misc.Unsafe", "freeMemory", Effect.UNKNOWN));
        r.addAll(verbs("liquibase.Liquibase", Effect.DB, "rollback", "dropAll", "changeLogSync", "forceReleaseLocks"));
        r.add(fx("net.sourceforge.tess4j.Tesseract", "doOCR", "(Ljava/io/File;)Ljava/lang/String;", Effect.FS));
        r.add(fx("net.sourceforge.tess4j.Tesseract", "doOCR", "(Ljava/awt/image/BufferedImage;)Ljava/lang/String;", null));
        r.add(fx("net.openhft.chronicle.queue.impl.single.SingleChronicleQueueBuilder", "build", Effect.FS));
        r.add(fx("dev.langchain4j.model.chat.ChatLanguageModel", "chat", Effect.NET));
        r.add(fx("net.bramp.ffmpeg.FFprobe", "run", Effect.EXEC));
        r.addAll(verbs("scala.sys.process.ProcessImpl", Effect.EXEC, "$bang", "$bang$bang", "lazyLines", "lineStream"));
        r.add(fx("groovy.xml.XmlSlurper", "parse", "(Ljava/io/File;)LN;", Effect.FS));
        r.add(fx("groovy.xml.XmlSlurper", "parse", "(Ljava/net/URL;)LN;", Effect.NET));
        r.add(fx("groovy.json.JsonSlurper", "parse", "(Ljava/io/File;)Ljava/lang/Object;", Effect.FS));
        r.add(fx("groovy.json.JsonSlurper", "parseText", "(Ljava/lang/String;)Ljava/lang/Object;", null)); // in-memory twin
        r.add(fx("kotlin.io.path.PathsKt", "readText", "(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/lang/String;", Effect.FS));
        r.add(fx("kotlin.ranges.RangesKt", "random", Effect.RAND));
        r.add(fx("kotlin.collections.ArraysKt", "random", Effect.RAND));
        r.add(fx("kotlin.random.RandomKt", "Random", Effect.RAND));
        r.add(fx("kotlin.random.Random$Default", "nextBytes", Effect.RAND));
        r.add(fx("okhttp3.RealCall", "execute", Effect.NET));
        r.add(fx("okhttp3.Call", "enqueue", Effect.NET));
        r.add(fx("retrofit2.Call", "enqueue", Effect.NET));
        r.add(fx("scala.io.Source", "fromPath", Effect.FS));
        r.add(fx("scala.io.Source$", "fromResource", Effect.FS));
        r.add(fx("scala.io.Source$", "fromURI", Effect.NET));
        r.add(fx("android.provider.Settings$System", "getFloat", Effect.ENV));
        r.add(fx("android.provider.Settings$Global", "putFloat", Effect.ENV));
        r.add(fx("redis.clients.jedis.JedisCluster", "set", Effect.DB));
        r.add(fx("net.spy.memcached.MemcachedClient", "set", Effect.NET));
        r.addAll(verbs("org.apache.solr.client.solrj.SolrClient", Effect.NET,
                "query", "add", "commit", "deleteById", "deleteByQuery", "request", "optimize"));
        r.addAll(verbs("org.keycloak.admin.client.resource.UsersResource", Effect.NET,
                "create", "search", "update", "remove", "count", "list", "add", "findAll",
                "sendVerifyEmail", "resetPassword", "logout"));
        r.addAll(verbs("org.springframework.ai.chat.client.ChatClient$CallResponseSpec", Effect.NET,
                "content", "chatResponse", "entity", "responseEntity"));
        r.add(fx("org.springframework.ai.openai.OpenAiChatModel", "call", Effect.NET));
        r.add(fx("org.apache.commons.mail.Email", "sendMimeMessage", Effect.NET));
        r.add(fx("org.im4java.core.IMOperation$Cmd", "run", Effect.EXEC)); // *Cmd prefix+suffix owner shape
        r.add(fx("org.springframework.cloud.openfeign.FeignBlockingLoadBalancerClient", "execute", Effect.NET));
        return r;
    }

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
        check("classifyJava/2", JAVA_2, mismatches);
        check("classifyOrg/2", ORG_2, mismatches);
        check("classifyCom/2", COM_2, mismatches);
        check("classifyIo/2", IO_2, mismatches);
        check("classifyOther/2", OTHER_2, mismatches);
        check("verb-sweeps", verbSweeps(), mismatches);
        assertEquals(List.of(), mismatches, "every table row (positive + anti-fabrication twin) must hold");
    }
}
