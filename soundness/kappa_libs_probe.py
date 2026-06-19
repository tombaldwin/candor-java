#!/usr/bin/env python3
"""kappa_libs_probe.py — the DIRECT effect-leaf κ-coverage gate for THIRD-PARTY LIBRARIES.

Sibling of kappa_probe.py, which pins the JDK effect leaves. The JVM dogfood showed candor handles
APPLICATION code well (effects land in the right layer, low Unknown) but LIBRARIES are the risk surface:
candor's κ table is NAME-BASED (it matches the call-site owner type, e.g. `okhttp3.Call` or
`org.slf4j.Logger`), so a library leaf whose owner/verb candor doesn't enumerate makes EVERY caller of
it read silent-pure — the cardinal sin, and it hides inside the library, where reviewers rarely look.

This probe calls a curated set of REAL library effect leaves DIRECTLY (the methods an app actually calls:
slf4j Logger.info, ObjectMapper.readValue(File), FileUtils.readFileToString, OkHttpClient.newCall().execute(),
JdbcTemplate.query, DataSource.getConnection, …), compiles the fixture AGAINST the library jars, scans, and
asserts each surfaces its expected effect (or a disclosed `Unknown` — a PASS). A silent-pure is a GAP =
a real soundness finding (a library leaf worth modelling in κ).

κ is name-based, so the library BODIES are NOT needed for classification — candor matches the owner name
emitted in the call instruction; the jars are needed only to COMPILE the fixture (and to give javac the
right declared types so the call instruction carries the owner candor expects). CANDOR_DEPS is for chaining
sibling *reports* (cross-module), NOT for resolving library bytecode, so it is NOT set here. (Empirically
confirmed: the run with no CANDOR_DEPS classifies every modeled leaf — see the report.)

    CJ=build/libs/candor-java-0.7.7-all.jar python3 soundness/kappa_libs_probe.py
    # CJ may be a launcher script OR an -all.jar (auto-detected). LIBDIR defaults to soundness/lib.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LIBDIR = os.environ.get("LIBDIR", os.path.join(HERE, "lib"))

IMPORTS = (
    "import java.io.*; import java.nio.charset.*; import java.util.*; import javax.sql.*;"
    "import java.sql.*;"
    "import org.slf4j.*;"
    "import com.fasterxml.jackson.databind.*;"
    "import com.google.common.io.*;"
    "import org.apache.commons.io.*;"
    "import okhttp3.*;"
    "import org.springframework.jdbc.core.*;"
    "import org.springframework.web.client.*;"
    # --- added libraries ---
    "import org.yaml.snakeyaml.*;"
    "import org.apache.hc.client5.http.impl.classic.*;"
    "import org.apache.hc.core5.http.*;"
    "import org.apache.commons.exec.*;"
    "import org.apache.poi.ss.usermodel.*;"
    "import jakarta.persistence.*;"
    "import com.mongodb.client.*;"
    "import org.bson.*;"
    # NB: redis.clients.jedis.Jedis referenced by FQN below — no wildcard import
    # to avoid clashing with okhttp3.Response (both define a Response type).
    "import org.apache.kafka.clients.producer.*;"
    "import org.apache.kafka.clients.consumer.*;"
    "import org.jsoup.*;"
    # NB: log4j Logger referenced by FQN below — no `import org.apache.logging.log4j.*`
    # to avoid clashing with slf4j's Logger (both *-imported).
    # ====================== ADDED LIBRARIES (2026-06-19 batch 2) ======================
    # Everything below is referenced by FULLY-QUALIFIED name in the bodies (no wildcard
    # imports) to avoid clashes among the many libraries that define same-simple-name types
    # (Response, Channel, Document, Loader, Configuration, …). FQNs keep the call-site owner
    # unambiguous, which is exactly what κ matches on.
)

# (method, expected effect, params, body) — PASS iff candor reports the effect OR a disclosed Unknown.
# Each body's TERMINAL call is the leaf under test; params supply a correctly-typed receiver so the call
# instruction carries the owner candor's κ keys on. Signatures verified against the downloaded versions.
EFFECT_CASES = [
    # ---- Log (slf4j) ----
    ("slf4jInfo",  "Log", "Logger l", 'l.info("x")'),
    ("slf4jWarn",  "Log", "Logger l", 'l.warn("x")'),
    ("slf4jError", "Log", "Logger l", 'l.error("x")'),
    ("slf4jGetLogger", "Log", "", 'Logger l = LoggerFactory.getLogger("x"); l.info("y")'),

    # ---- Fs/Net (jackson file/url (de)serialization — descriptor-gated κ, modeled 0.7.7) ----
    ("jacksonReadFile",  "Fs",  "ObjectMapper m, File f", 'Object o = m.readValue(f, String.class)'),
    ("jacksonWriteFile", "Fs",  "ObjectMapper m, File f", 'm.writeValue(f, "x")'),
    ("jacksonReadUrl",   "Net", "ObjectMapper m, java.net.URL u", 'Object o = m.readValue(u, String.class)'),

    # ---- Fs (commons-io FileUtils) ----
    ("commonsReadFile",  "Fs", "File f", 'String s = FileUtils.readFileToString(f, "UTF-8")'),
    ("commonsWriteFile", "Fs", "File f", 'FileUtils.writeStringToFile(f, "x", "UTF-8")'),
    ("commonsCopyFile",  "Fs", "File a, File b", 'FileUtils.copyFile(a, b)'),

    # ---- Fs (guava com.google.common.io.Files — eager verbs are modeled) ----
    ("guavaToByteArray", "Fs", "File f", 'byte[] b = Files.toByteArray(f)'),
    ("guavaWrite",       "Fs", "File f", 'Files.write(new byte[1], f)'),
    ("guavaReadLines",   "Fs", "File f", 'List<String> ls = Files.readLines(f, Charset.defaultCharset())'),
    # NOTE: guava's lazy source terminal `Files.asCharSource(f,..).read()` (owner CharSource.read) is an
    # ACCEPTED gap, NOT tested here: the receiver CharSource may be file-backed OR `CharSource.wrap("str")`
    # (in-memory), so candor cannot tell without the receiver's concrete type — the same ambiguous-receiver
    # class as the documented abstract-java.io.Reader boundary (dynamic/README "First real finding").
    # Modeling CharSource.read as Fs would FABRICATE on wrap()-backed sources; left disclosed-by-omission.

    # ---- Net (okhttp) ----
    ("okhttpExecute", "Net", "OkHttpClient c, Request r", 'Response resp = c.newCall(r).execute()'),
    ("okhttpCallExecute", "Net", "Call call", 'Response resp = call.execute()'),

    # ---- Net (spring RestTemplate) ----
    ("restGetForObject", "Net", "RestTemplate rt", 'Object o = rt.getForObject("http://h/", String.class)'),

    # ---- Db (spring JdbcTemplate) ----
    ("jdbcQuery",   "Db", "JdbcTemplate t",
        'List<?> r = t.queryForList("select 1")'),
    ("jdbcUpdate",  "Db", "JdbcTemplate t", 'int n = t.update("update t set x=1")'),
    ("jdbcExecute", "Db", "JdbcTemplate t", 't.execute("create table t(x int)")'),

    # ---- Db (javax.sql.DataSource — JDK type, modeled) ----
    ("dataSourceGetConn", "Db", "DataSource ds", 'java.sql.Connection c = ds.getConnection()'),

    # ====================== ADDED LIBRARIES (2026-06-19 sweep) ======================
    # ---- Net (Apache HttpClient 5 — CloseableHttpClient.execute) ----
    ("hc5Execute", "Net", "CloseableHttpClient c, ClassicHttpRequest req",
        'org.apache.hc.core5.http.ClassicHttpResponse r = c.execute(req)'),

    # ---- Exec (Apache Commons Exec — Executor.execute(CommandLine)) ----
    ("commonsExecRun", "Exec", "DefaultExecutor e, CommandLine cl", 'int rc = e.execute(cl)'),

    # ---- Fs (Apache POI — WorkbookFactory.create(File)) ----
    ("poiCreateFile", "Fs", "File f", 'Workbook wb = WorkbookFactory.create(f)'),

    # ---- Db (Jakarta Persistence / JPA — EntityManager + Query terminals) ----
    ("jpaPersist",    "Db", "EntityManager em, Object o", 'em.persist(o)'),
    ("jpaFind",       "Db", "EntityManager em", 'Object o = em.find(String.class, 1)'),
    ("jpaMerge",      "Db", "EntityManager em, Object o", 'Object r = em.merge(o)'),
    ("jpaResultList", "Db", "EntityManager em",
        'java.util.List<?> r = em.createQuery("from X").getResultList()'),
    ("jpaExecUpdate", "Db", "EntityManager em",
        'int n = em.createQuery("delete from X").executeUpdate()'),

    # ---- Db/Net (MongoDB driver — eager insertOne; lazy find() iterable) ----
    ("mongoInsertOne", "Db", "MongoCollection<Document> c, Document d", 'c.insertOne(d)'),
    ("mongoFind",      "Db", "MongoCollection<Document> c", 'FindIterable<Document> it = c.find()'),

    # ---- Net (Jedis — get/set; candor models the Jedis socket as Net, a datastore over TCP) ----
    ("jedisGet", "Net", "redis.clients.jedis.Jedis j", 'String v = j.get("k")'),
    ("jedisSet", "Net", "redis.clients.jedis.Jedis j", 'String v = j.set("k", "v")'),

    # ---- Net (Kafka — producer.send / consumer.poll) ----
    ("kafkaSend", "Net", "KafkaProducer<String,String> p, ProducerRecord<String,String> rec",
        'java.util.concurrent.Future<RecordMetadata> f = p.send(rec)'),
    ("kafkaPoll", "Net", "KafkaConsumer<String,String> c",
        'ConsumerRecords<String,String> r = c.poll(java.time.Duration.ofMillis(1))'),

    # ---- Net/Fs (jsoup public API — connect().get() is Net; parse(File) is Fs) ----
    ("jsoupConnectGet", "Net", "", 'org.jsoup.nodes.Document d = Jsoup.connect("http://h/").get()'),
    ("jsoupParseFile",  "Fs",  "File f", 'org.jsoup.nodes.Document d = Jsoup.parse(f, "UTF-8")'),

    # ---- Log (Log4j 2 — Logger.info; FQN to avoid clash with slf4j Logger) ----
    ("log4jInfo", "Log", "org.apache.logging.log4j.Logger l", 'l.info("x")'),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 2) ======================
    # ---- Net (Netty — Bootstrap.connect / Channel.writeAndFlush; both open/use a socket) ----
    ("nettyConnect", "Net", "io.netty.bootstrap.Bootstrap b",
        'io.netty.channel.ChannelFuture f = b.connect("h", 80)'),
    ("nettyWriteAndFlush", "Net", "io.netty.channel.Channel ch",
        'io.netty.channel.ChannelFuture f = ch.writeAndFlush(new Object())'),

    # ---- Net (AWS SDK v2 S3 — getObject/putObject; S3 is HTTP under the hood) ----
    ("awsS3GetObject", "Net",
        "software.amazon.awssdk.services.s3.S3Client s3, "
        "software.amazon.awssdk.services.s3.model.GetObjectRequest req",
        'software.amazon.awssdk.core.ResponseInputStream<software.amazon.awssdk.services.s3.model.GetObjectResponse> r = s3.getObject(req)'),
    ("awsS3PutObject", "Net",
        "software.amazon.awssdk.services.s3.S3Client s3, "
        "software.amazon.awssdk.services.s3.model.PutObjectRequest req, "
        "software.amazon.awssdk.core.sync.RequestBody body",
        'software.amazon.awssdk.services.s3.model.PutObjectResponse r = s3.putObject(req, body)'),

    # ---- Net (gRPC — the real wire send is ClientCalls.blockingUnaryCall / ClientCall.sendMessage;
    #      ManagedChannelBuilder.build/newCall are setup, the send is the leaf) ----
    ("grpcBlockingUnaryCall", "Net",
        "io.grpc.ClientCall<String,String> call",
        'String r = io.grpc.stub.ClientCalls.blockingUnaryCall(call, "x")'),
    ("grpcSendMessage", "Net", "io.grpc.ClientCall<String,String> call", 'call.sendMessage("x")'),

    # ---- Fs (JGit — Git.open(File) reads the on-disk repo) ----
    ("jgitOpen", "Fs", "File f", 'org.eclipse.jgit.api.Git g = org.eclipse.jgit.api.Git.open(f)'),

    # ---- Net (Apache Commons Net — FTPClient.connect / retrieveFile over a socket) ----
    ("ftpConnect", "Net", "org.apache.commons.net.ftp.FTPClient c", 'c.connect("h")'),
    ("ftpRetrieveFile", "Net", "org.apache.commons.net.ftp.FTPClient c, OutputStream os",
        'boolean ok = c.retrieveFile("p", os)'),

    # ---- Fs (Apache Commons Compress — new ZipFile(File) opens the archive on disk) ----
    ("compressZipFile", "Fs", "File f",
        'org.apache.commons.compress.archivers.zip.ZipFile z = new org.apache.commons.compress.archivers.zip.ZipFile(f)'),

    # ---- Db (Flyway — migrate() applies SQL to the configured DB) ----
    ("flywayMigrate", "Db", "org.flywaydb.core.Flyway fw",
        'org.flywaydb.core.api.output.MigrateResult r = fw.migrate()'),

    # ---- Db (Liquibase — update() applies changesets to the DB) ----
    ("liquibaseUpdate", "Db", "liquibase.Liquibase lb", 'lb.update()'),

    # ---- Fs (Apache Tika — parseToString(File) reads the file) ----
    ("tikaParseFile", "Fs", "org.apache.tika.Tika t, File f", 'String s = t.parseToString(f)'),

    # ---- Fs (Apache PDFBox — Loader.loadPDF(File) reads the PDF off disk) ----
    ("pdfboxLoadFile", "Fs", "File f",
        'org.apache.pdfbox.pdmodel.PDDocument d = org.apache.pdfbox.Loader.loadPDF(f)'),

    # ---- Net (Spring WebClient — get()...retrieve().bodyToMono(); the HTTP call) ----
    ("webClientRetrieve", "Net", "org.springframework.web.reactive.function.client.WebClient wc",
        'reactor.core.publisher.Mono<String> m = wc.get().uri("http://h/").retrieve().bodyToMono(String.class)'),

    # ---- Net (Spring RestClient — get()...retrieve().body(); body() blocks on the HTTP exchange) ----
    ("restClientBody", "Net", "org.springframework.web.client.RestClient rc",
        'String s = rc.get().uri("http://h/").retrieve().body(String.class)'),

    # ---- Db (Hibernate — Session.get / persist / createQuery(...).list(); the ORM DB leaves) ----
    ("hibernateGet", "Db", "org.hibernate.Session s", 'Object o = s.get(String.class, 1)'),
    ("hibernatePersist", "Db", "org.hibernate.Session s, Object o", 's.persist(o)'),
    ("hibernateQueryList", "Db", "org.hibernate.Session s",
        'java.util.List<?> r = s.createQuery("from X", Object.class).list()'),
]

# Deliberately-PURE neighbours — anti-over-classification anchors (a future κ widening must keep these pure).
PURE_CASES = [
    # slf4j level CHECK reads no record (pure), unlike the emit verbs.
    ("slf4jIsEnabledPure", "boolean b = l.isInfoEnabled()", "Logger l"),
    # guava lazy FACTORY — returns a CharSource view, touches no file until a terminal read (documented in κ).
    ("guavaAsCharSourcePure", "CharSource cs = Files.asCharSource(f, Charset.defaultCharset())", "File f"),
    # ObjectMapper in-memory string (de)serialization touches no file/socket — must stay pure.
    ("jacksonReadStringPure", "Object o = m.readValue(\"{}\", Object.class)", "ObjectMapper m"),
    ("jacksonWriteStringPure", "String s = m.writeValueAsString(new Object())", "ObjectMapper m"),

    # ---- SnakeYAML: every load/dump overload takes a CALLER-SUPPLIED stream/string (no File overload
    #      exists in 2.x). The file open is the caller's `new FileInputStream` — the Yaml leaf is pure.
    #      These pin that: candor must NOT fabricate Fs on the parse itself (ambiguous-receiver class).
    ("yamlLoadStreamPure", "Object o = new Yaml().load(in)", "InputStream in"),
    ("yamlLoadReaderPure", "Object o = new Yaml().load(rd)", "Reader rd"),
    ("yamlLoadStringPure", "Object o = new Yaml().load(\"a: 1\")", ""),
    ("yamlDumpWriterPure", "new Yaml().dump(new Object(), w)", "Writer w"),

    # ---- POI: the InputStream overload is caller-supplied — pure (the File overload is the Fs leaf above).
    ("poiCreateStreamPure", "Workbook wb = WorkbookFactory.create(in)", "InputStream in"),

    # ---- jsoup: in-memory parse(String) touches nothing — must stay pure (parse(File) above is the Fs leaf).
    ("jsoupParseStringPure", "org.jsoup.nodes.Document d = Jsoup.parse(\"<p>x\")", ""),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 2) — pure anchors ===============
    # Caffeine is an IN-MEMORY cache — getIfPresent touches no I/O. candor must stay pure (no fab).
    ("caffeineGetPure", "Object v = c.getIfPresent(\"k\")", "com.github.benmanes.caffeine.cache.Cache<String,Object> c"),
    ("caffeinePutPure", "c.put(\"k\", new Object())", "com.github.benmanes.caffeine.cache.Cache<String,Object> c"),
    # Tika parseToString(InputStream) — caller supplies the stream; the parse itself is pure
    # (the file open is the caller's, the File overload above is the Fs leaf). Ambiguous-receiver class.
    ("tikaParseStreamPure", "String s = t.parseToString(in)", "org.apache.tika.Tika t, InputStream in"),
    # PDFBox loadPDF(byte[]) — in-memory bytes, no disk read (loadPDF(File) above is the Fs leaf).
    ("pdfboxLoadBytesPure", "org.apache.pdfbox.pdmodel.PDDocument d = org.apache.pdfbox.Loader.loadPDF(new byte[1])", ""),
    # Commons Compress over a caller-supplied SeekableByteChannel — the channel open is the caller's;
    # the ZipFile(channel) ctor reads from an already-opened handle (caller-stream class, like SnakeYAML).
    ("compressChannelPure",
        "org.apache.commons.compress.archivers.zip.ZipFile z = new org.apache.commons.compress.archivers.zip.ZipFile(chan)",
        "java.nio.channels.SeekableByteChannel chan"),
]


# Library jars FETCHED ON DEMAND from Maven Central into LIBDIR (gitignored — 14 MB, not vendored).
# To test a new library: add its coordinate here and a case to EFFECT_CASES.
_MVN = "https://repo1.maven.org/maven2"
JARS = {
    "slf4j-api-2.0.13.jar": f"{_MVN}/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar",
    "jackson-databind-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/core/jackson-databind/2.17.1/jackson-databind-2.17.1.jar",
    "jackson-core-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/core/jackson-core/2.17.1/jackson-core-2.17.1.jar",
    "jackson-annotations-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/core/jackson-annotations/2.17.1/jackson-annotations-2.17.1.jar",
    "guava-33.2.1-jre.jar": f"{_MVN}/com/google/guava/guava/33.2.1-jre/guava-33.2.1-jre.jar",
    "okhttp-4.12.0.jar": f"{_MVN}/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar",
    "okio-jvm-3.9.0.jar": f"{_MVN}/com/squareup/okio/okio-jvm/3.9.0/okio-jvm-3.9.0.jar",
    "kotlin-stdlib-1.9.24.jar": f"{_MVN}/org/jetbrains/kotlin/kotlin-stdlib/1.9.24/kotlin-stdlib-1.9.24.jar",
    "commons-io-2.16.1.jar": f"{_MVN}/commons-io/commons-io/2.16.1/commons-io-2.16.1.jar",
    "spring-jdbc-6.1.10.jar": f"{_MVN}/org/springframework/spring-jdbc/6.1.10/spring-jdbc-6.1.10.jar",
    "spring-core-6.1.10.jar": f"{_MVN}/org/springframework/spring-core/6.1.10/spring-core-6.1.10.jar",
    "spring-beans-6.1.10.jar": f"{_MVN}/org/springframework/spring-beans/6.1.10/spring-beans-6.1.10.jar",
    "spring-tx-6.1.10.jar": f"{_MVN}/org/springframework/spring-tx/6.1.10/spring-tx-6.1.10.jar",
    "spring-web-6.1.10.jar": f"{_MVN}/org/springframework/spring-web/6.1.10/spring-web-6.1.10.jar",
    # --- added 2026-06-19 sweep ---
    "snakeyaml-2.2.jar": f"{_MVN}/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar",
    "httpclient5-5.3.1.jar": f"{_MVN}/org/apache/httpcomponents/client5/httpclient5/5.3.1/httpclient5-5.3.1.jar",
    "httpcore5-5.2.4.jar": f"{_MVN}/org/apache/httpcomponents/core5/httpcore5/5.2.4/httpcore5-5.2.4.jar",
    "commons-exec-1.4.0.jar": f"{_MVN}/org/apache/commons/commons-exec/1.4.0/commons-exec-1.4.0.jar",
    "poi-5.2.5.jar": f"{_MVN}/org/apache/poi/poi/5.2.5/poi-5.2.5.jar",
    "poi-ooxml-5.2.5.jar": f"{_MVN}/org/apache/poi/poi-ooxml/5.2.5/poi-ooxml-5.2.5.jar",
    "jakarta.persistence-api-3.1.0.jar": f"{_MVN}/jakarta/persistence/jakarta.persistence-api/3.1.0/jakarta.persistence-api-3.1.0.jar",
    "mongodb-driver-sync-5.1.1.jar": f"{_MVN}/org/mongodb/mongodb-driver-sync/5.1.1/mongodb-driver-sync-5.1.1.jar",
    "mongodb-driver-core-5.1.1.jar": f"{_MVN}/org/mongodb/mongodb-driver-core/5.1.1/mongodb-driver-core-5.1.1.jar",
    "bson-5.1.1.jar": f"{_MVN}/org/mongodb/bson/5.1.1/bson-5.1.1.jar",
    "jedis-5.1.3.jar": f"{_MVN}/redis/clients/jedis/5.1.3/jedis-5.1.3.jar",
    "kafka-clients-3.7.1.jar": f"{_MVN}/org/apache/kafka/kafka-clients/3.7.1/kafka-clients-3.7.1.jar",
    "jsoup-1.18.1.jar": f"{_MVN}/org/jsoup/jsoup/1.18.1/jsoup-1.18.1.jar",
    "log4j-api-2.23.1.jar": f"{_MVN}/org/apache/logging/log4j/log4j-api/2.23.1/log4j-api-2.23.1.jar",
    # --- added 2026-06-19 batch 2 ---
    # Netty (split modules — transport carries Bootstrap/Channel; the rest are compile-time deps)
    "netty-transport-4.1.111.Final.jar": f"{_MVN}/io/netty/netty-transport/4.1.111.Final/netty-transport-4.1.111.Final.jar",
    "netty-common-4.1.111.Final.jar": f"{_MVN}/io/netty/netty-common/4.1.111.Final/netty-common-4.1.111.Final.jar",
    "netty-buffer-4.1.111.Final.jar": f"{_MVN}/io/netty/netty-buffer/4.1.111.Final/netty-buffer-4.1.111.Final.jar",
    "netty-resolver-4.1.111.Final.jar": f"{_MVN}/io/netty/netty-resolver/4.1.111.Final/netty-resolver-4.1.111.Final.jar",
    # AWS SDK v2 — S3
    "s3-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/s3/2.25.60/s3-2.25.60.jar",
    "sdk-core-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/sdk-core/2.25.60/sdk-core-2.25.60.jar",
    "aws-core-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/aws-core/2.25.60/aws-core-2.25.60.jar",
    "aws-utils-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/utils/2.25.60/utils-2.25.60.jar",
    "aws-http-client-spi-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/http-client-spi/2.25.60/http-client-spi-2.25.60.jar",
    # gRPC
    "grpc-api-1.64.0.jar": f"{_MVN}/io/grpc/grpc-api/1.64.0/grpc-api-1.64.0.jar",
    "grpc-stub-1.64.0.jar": f"{_MVN}/io/grpc/grpc-stub/1.64.0/grpc-stub-1.64.0.jar",
    "grpc-context-1.64.0.jar": f"{_MVN}/io/grpc/grpc-context/1.64.0/grpc-context-1.64.0.jar",
    # JGit
    "org.eclipse.jgit-6.10.0.202406032230-r.jar": f"{_MVN}/org/eclipse/jgit/org.eclipse.jgit/6.10.0.202406032230-r/org.eclipse.jgit-6.10.0.202406032230-r.jar",
    # Apache Commons Net (FTP) + Compress
    "commons-net-3.11.1.jar": f"{_MVN}/commons-net/commons-net/3.11.1/commons-net-3.11.1.jar",
    "commons-compress-1.26.2.jar": f"{_MVN}/org/apache/commons/commons-compress/1.26.2/commons-compress-1.26.2.jar",
    # Flyway / Liquibase (DB migration)
    "flyway-core-10.15.0.jar": f"{_MVN}/org/flywaydb/flyway-core/10.15.0/flyway-core-10.15.0.jar",
    "liquibase-core-4.28.0.jar": f"{_MVN}/org/liquibase/liquibase-core/4.28.0/liquibase-core-4.28.0.jar",
    # Apache Tika / PDFBox (file parsers)
    "tika-core-2.9.2.jar": f"{_MVN}/org/apache/tika/tika-core/2.9.2/tika-core-2.9.2.jar",
    "pdfbox-3.0.2.jar": f"{_MVN}/org/apache/pdfbox/pdfbox/3.0.2/pdfbox-3.0.2.jar",
    "pdfbox-io-3.0.2.jar": f"{_MVN}/org/apache/pdfbox/pdfbox-io/3.0.2/pdfbox-io-3.0.2.jar",
    # Spring WebClient (reactive) + reactor deps (RestClient is in spring-web, already present)
    "spring-webflux-6.1.10.jar": f"{_MVN}/org/springframework/spring-webflux/6.1.10/spring-webflux-6.1.10.jar",
    "reactor-core-3.6.7.jar": f"{_MVN}/io/projectreactor/reactor-core/3.6.7/reactor-core-3.6.7.jar",
    "reactive-streams-1.0.4.jar": f"{_MVN}/org/reactivestreams/reactive-streams/1.0.4/reactive-streams-1.0.4.jar",
    # Hibernate ORM
    "hibernate-core-6.5.2.Final.jar": f"{_MVN}/org/hibernate/orm/hibernate-core/6.5.2.Final/hibernate-core-6.5.2.Final.jar",
    # Caffeine (in-memory cache — pure anchor)
    "caffeine-3.1.8.jar": f"{_MVN}/com/github/ben-manes/caffeine/caffeine/3.1.8/caffeine-3.1.8.jar",
}


def classpath():
    os.makedirs(LIBDIR, exist_ok=True)
    missing = [(n, u) for n, u in JARS.items() if not os.path.exists(os.path.join(LIBDIR, n))]
    if missing:
        print(f"kappa-libs: fetching {len(missing)} jar(s) into {LIBDIR} …")
        for name, url in missing:
            dest = os.path.join(LIBDIR, name)
            r = subprocess.run(["curl", "-fsSL", "-o", dest, url])
            if r.returncode != 0 or not os.path.exists(dest):
                print(f"kappa-libs: FAIL — could not fetch {url}", file=sys.stderr); sys.exit(2)
    jars = sorted(glob.glob(os.path.join(LIBDIR, "*.jar")))
    if not jars:
        print(f"kappa-libs: FAIL — no jars in {LIBDIR}", file=sys.stderr); sys.exit(2)
    return os.pathsep.join(jars), jars


def build_fixture():
    lines = [IMPORTS, "public class KL {"]
    for name, _eff, params, body in EFFECT_CASES:
        lines.append(f"  static void {name}({params}) throws Exception {{ {body}; }}")
    for name, body, params in PURE_CASES:
        lines.append(f"  static void {name}({params}) throws Exception {{ {body}; }}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def candor_cmd(launcher, cls, out):
    """CJ may be an -all.jar (run via `java -jar`) or an executable launcher script."""
    if launcher.endswith(".jar"):
        return ["java", "-jar", launcher, cls, "--json", out]
    return [launcher, cls, "--json", out]


def main():
    launcher = os.environ.get("CJ")
    if not launcher:
        # default to the newest -all.jar in build/libs
        cands = sorted(glob.glob(os.path.join(HERE, "..", "build", "libs", "candor-java-*-all.jar")))
        launcher = cands[-1] if cands else None
    if not launcher or not os.path.exists(launcher):
        print("kappa-libs: FAIL — set CJ to the candor-java launcher or -all.jar"); sys.exit(2)

    cp, jars = classpath()
    with tempfile.TemporaryDirectory() as work:
        src = os.path.join(work, "KL.java")
        with open(src, "w") as f:
            f.write(build_fixture())
        cls = os.path.join(work, "cls")
        os.makedirs(cls)
        jc = subprocess.run(["javac", "-cp", cp, "-d", cls, src], capture_output=True, text=True)
        if jc.returncode != 0:
            print("kappa-libs: GEN BUG — fixture does not compile:\n" + jc.stderr.strip()); sys.exit(2)
        out = os.path.join(work, "out.json")
        # NB: no CANDOR_DEPS — κ is name-based; the jars were only needed to compile. The classes dir is
        # scanned alone; candor classifies cross-jar calls from the owner name in the bytecode.
        r = subprocess.run(candor_cmd(launcher, cls, out), capture_output=True, text=True)
        if not os.path.exists(out):
            print("kappa-libs: FAIL — no report\n" + r.stderr.strip()); sys.exit(2)
        report = json.load(open(out))
        fns = report.get("functions", []) if isinstance(report, dict) else report
        inferred = {e["fn"].split("(")[0]: e.get("inferred", []) for e in fns if isinstance(e, dict)}

    rows, gaps, fabs = [], [], []
    for name, eff, _p, body in EFFECT_CASES:
        got = inferred.get("KL." + name, [])
        ok = eff in got or "Unknown" in got
        verdict = f"ok({eff})" if eff in got else ("ok(Unknown)" if "Unknown" in got else "GAP")
        rows.append((name, eff, got or [], verdict))
        if not ok:
            gaps.append(f"  GAP  KL.{name} [{body}] -> {got or 'pure/omitted'}  (must surface {eff} or Unknown)")
    for name, body, _p in PURE_CASES:
        got = inferred.get("KL." + name, [])
        rows.append((name, "(pure)", got or [], "ok(pure)" if not got else "FABRICATION"))
        if got:
            fabs.append(f"  FABRICATION  KL.{name} [{body}] -> {got}  (must stay pure)")

    w = max(len(r[0]) for r in rows)
    print(f"{'leaf'.ljust(w)}  {'expect':8}  {'candor':22}  verdict")
    print("-" * (w + 40))
    for name, eff, got, verdict in rows:
        print(f"{name.ljust(w)}  {eff:8}  {str(got)[:22]:22}  {verdict}")

    n = len(EFFECT_CASES) + len(PURE_CASES)
    if gaps or fabs:
        print(f"\nkappa-libs: {len(gaps)} coverage gap(s), {len(fabs)} over-classification(s) of {n} library leaves:")
        for g in gaps + fabs:
            print(g)
        sys.exit(1)
    print(f"\nkappa-libs: OK — {len(EFFECT_CASES)} library effect leaves classified "
          f"(slf4j/log4j/jackson/commons-io/commons-exec/guava/okhttp/httpclient5/spring/poi/"
          f"jpa/mongo/jedis/kafka/jsoup/aws-s3/grpc/webclient/restclient/hibernate/+gaps), "
          f"{len(PURE_CASES)} pure neighbours unflooded")


if __name__ == "__main__":
    main()
