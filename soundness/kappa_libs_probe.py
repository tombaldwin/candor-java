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
    # ====================== ADDED LIBRARIES (2026-06-19 batch 3) ======================
    # Datastores/DB: Cassandra, MyBatis, jOOQ, Spring Data, Lettuce.
    # Messaging: RabbitMQ, Jakarta JMS, Spring AMQP.
    # Cloud: AWS v2 DynamoDB/SQS/SNS (over HTTP).
    # HTTP clients: Retrofit, OpenFeign, Apache HttpClient 4.x.
    # File/config: Avro, Typesafe Config, Commons Configuration2; protobuf/Gson/KeyStore pure anchors.
    # All referenced by FULLY-QUALIFIED name in the bodies (no wildcard imports) — same clash-avoidance
    # discipline as batch 2 (Response/Channel/Configuration/Session all collide across these libs).
    # ====================== ADDED LIBRARIES (2026-06-19 batch 4) ======================
    # Jackson format modules: XmlMapper/YAMLMapper/CsvMapper (subclasses of ObjectMapper but a DIFFERENT
    #   owner — the exact-owner jackson κ rule keys on com.fasterxml.jackson.databind.ObjectMapper, so the
    #   File overloads called on a subclass-typed receiver carry the subclass owner and likely read pure).
    # Email: jakarta.mail Transport.send, Spring JavaMailSender/JavaMailSenderImpl.send.
    # Cloud storage: Google Cloud Storage, MinIO, Azure Blob.
    # Datastores: Neo4j, R2DBC, Spring Data MongoTemplate, Spring Data RedisTemplate/ValueOperations.
    # Messaging: Apache Pulsar, Spring Kafka.
    # File/PDF/image: iText PdfWriter/PdfReader, Thumbnailator.
    # Pure anchors: OpenCSV CSVReader(Reader), Commons CSV CSVParser.parse(Reader), jackson XmlMapper(String).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2/3.
    # ====================== ADDED LIBRARIES (2026-06-19 batch 5) ======================
    # SSH/SFTP: JSch (Session.connect / ChannelSftp.get|put), SSHJ (SSHClient.connect).
    # Search: Elasticsearch + OpenSearch low-level RestClient.performRequest (HTTP; the high-level
    #   typed clients drag in a heavy jakarta.json tree — the low-level client is self-contained over httpcore).
    # Datastores: InfluxDB WriteApi.writeRecord, Couchbase Collection.get|upsert (both wire datastores → Net).
    # HTTP/async: AsyncHttpClient.executeRequest, Vert.x WebClient HttpRequest.send.
    # Templating: FreeMarker Configuration.getTemplate(String) (Fs — reads the template file);
    #   Velocity getTemplate/mergeTemplate (Fs). Caller-writer terminals (Template.process(model,Writer),
    #   Velocity Template.merge(ctx,Writer)) are PURE anchors.
    # File formats / IO: Apache Commons VFS FileObject.getInputStream (Fs for local scheme);
    #   univocity CsvParser.parse(File) (Fs), parse(Reader)/parse(InputStream) PURE anchors.
    # Config/secrets: dotenv-java Dotenv.load() (Fs — reads .env off disk).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2/3/4.
    # SKIPPED (heavy dep trees, noted in the report): Apache Parquet/ORC (Hadoop tree); the high-level
    #   Elasticsearch/OpenSearch typed Java clients (jakarta.json + transport); Thymeleaf (its core leaf is a
    #   caller-supplied Writer like FreeMarker.process — covered by the FreeMarker/Velocity caller-writer anchors).
    # ====================== ADDED LIBRARIES (2026-06-19 batch 6) ======================
    # Embedded on-disk stores: Lucene (IndexWriter.addDocument / DirectoryReader.open → Fs), MapDB
    #   (DBMaker.fileDB(...).make → Fs), RocksDB (RocksDB.open/get/put → Fs, native JNI). Ehcache 3 is
    #   IN-MEMORY (Cache.get/put → PURE anchors, unless disk-tiered which the API call alone can't tell).
    # Containers/automation: Testcontainers GenericContainer.start (spawns Docker → Exec+Net), Selenium
    #   WebDriver.get / RemoteWebDriver.get (drives a browser over the wire → Net).
    # Integration/messaging: Apache Camel ProducerTemplate.sendBody/requestBody (→ Net — routes to an
    #   endpoint, often remote), JeroMQ ZMQ.Socket.send/recv (→ Net — a 0MQ socket over TCP), Apache
    #   Thrift TTransport.open/read/write (→ Net — the RPC transport).
    # JNDI/LDAP: javax.naming.directory.DirContext.search / InitialDirContext.search (→ Net — LDAP query;
    #   candor already models InitialContext.lookup as Net — does DirContext.search share that coverage?).
    # Native crypto: BouncyCastle org.bouncycastle.crypto.generators.RSAKeyPairGenerator.generateKeyPair
    #   (→ Rand — draws entropy via the configured SecureRandom). Most BC digest/cipher ops are pure compute.
    # AWS more (VERIFY shared-namespace coverage): SecretsManagerClient.getSecretValue / KmsClient.encrypt /
    #   SsmClient.getParameter (→ Net; candor keys AWS v2 on the services namespace, so they likely PASS).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2/3/4/5.
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

    # ====================== ADDED LIBRARIES (2026-06-19 batch 3) ======================
    # ---- Db (Cassandra java-driver — CqlSession.execute(String); inherited default from SyncCqlSession,
    #      so the call-site owner is the static receiver type CqlSession) ----
    ("cassandraExecute", "Db", "com.datastax.oss.driver.api.core.CqlSession s",
        'com.datastax.oss.driver.api.core.cql.ResultSet r = s.execute("select 1")'),

    # ---- Db (MyBatis SqlSession — selectList / insert / update terminals run SQL) ----
    ("mybatisSelectList", "Db", "org.apache.ibatis.session.SqlSession s",
        'java.util.List<?> r = s.selectList("ns.q")'),
    ("mybatisInsert", "Db", "org.apache.ibatis.session.SqlSession s", 'int n = s.insert("ns.ins")'),
    ("mybatisUpdate", "Db", "org.apache.ibatis.session.SqlSession s", 'int n = s.update("ns.upd")'),

    # ---- Db (jOOQ DSLContext — fetch / execute against the configured connection) ----
    ("jooqFetch", "Db", "org.jooq.DSLContext d",
        'org.jooq.Result<org.jooq.Record> r = d.fetch("select 1")'),
    ("jooqExecute", "Db", "org.jooq.DSLContext d", 'int n = d.execute("update t set x=1")'),

    # ---- Db (Spring Data CrudRepository — save/findAll/findById/delete; impl is generated at runtime,
    #      so the leaf candor sees is the interface method, exactly as in the PetClinic dogfood) ----
    ("springDataSave", "Db", "org.springframework.data.repository.CrudRepository<Object,Long> repo, Object e",
        'Object r = repo.save(e)'),
    ("springDataFindAll", "Db", "org.springframework.data.repository.CrudRepository<Object,Long> repo",
        'Iterable<Object> r = repo.findAll()'),
    ("springDataFindById", "Db", "org.springframework.data.repository.CrudRepository<Object,Long> repo",
        'java.util.Optional<Object> r = repo.findById(1L)'),
    ("springDataDelete", "Db", "org.springframework.data.repository.CrudRepository<Object,Long> repo, Object e",
        'repo.delete(e)'),

    # ---- Net (Lettuce sync RedisCommands — get/set over the Redis socket) ----
    ("lettuceGet", "Net", "io.lettuce.core.api.sync.RedisCommands<String,String> c", 'String v = c.get("k")'),
    ("lettuceSet", "Net", "io.lettuce.core.api.sync.RedisCommands<String,String> c", 'String v = c.set("k","v")'),

    # ---- Net (RabbitMQ Channel — basicPublish / basicConsume over the AMQP socket) ----
    ("rabbitPublish", "Net", "com.rabbitmq.client.Channel ch",
        'ch.basicPublish("ex", "rk", null, new byte[1])'),
    ("rabbitConsume", "Net", "com.rabbitmq.client.Channel ch, com.rabbitmq.client.Consumer cons",
        'String tag = ch.basicConsume("q", cons)'),

    # ---- Net (Jakarta JMS — MessageProducer.send; JMSContext.createProducer is setup but opens the link) ----
    ("jmsSend", "Net", "jakarta.jms.MessageProducer p, jakarta.jms.Message m", 'p.send(m)'),

    # ---- Net (Spring AMQP RabbitTemplate — convertAndSend publishes to the broker) ----
    ("springAmqpSend", "Net", "org.springframework.amqp.rabbit.core.RabbitTemplate t, Object o",
        't.convertAndSend(o)'),

    # ---- Net (AWS SDK v2 DynamoDB/SQS/SNS — all HTTP under the hood, like S3 already modeled) ----
    ("awsDynamoGetItem", "Net",
        "software.amazon.awssdk.services.dynamodb.DynamoDbClient c, "
        "software.amazon.awssdk.services.dynamodb.model.GetItemRequest req",
        'software.amazon.awssdk.services.dynamodb.model.GetItemResponse r = c.getItem(req)'),
    ("awsDynamoPutItem", "Net",
        "software.amazon.awssdk.services.dynamodb.DynamoDbClient c, "
        "software.amazon.awssdk.services.dynamodb.model.PutItemRequest req",
        'software.amazon.awssdk.services.dynamodb.model.PutItemResponse r = c.putItem(req)'),
    ("awsSqsSendMessage", "Net",
        "software.amazon.awssdk.services.sqs.SqsClient c, "
        "software.amazon.awssdk.services.sqs.model.SendMessageRequest req",
        'software.amazon.awssdk.services.sqs.model.SendMessageResponse r = c.sendMessage(req)'),
    ("awsSnsPublish", "Net",
        "software.amazon.awssdk.services.sns.SnsClient c, "
        "software.amazon.awssdk.services.sns.model.PublishRequest req",
        'software.amazon.awssdk.services.sns.model.PublishResponse r = c.publish(req)'),

    # ---- Net (Retrofit — Call.execute() performs the HTTP round-trip) ----
    ("retrofitExecute", "Net", "retrofit2.Call<String> call",
        'retrofit2.Response<String> r = call.execute()'),

    # ---- Net (OpenFeign — feign.Client.execute(Request,Options) is the real wire send the generated
    #      proxy delegates to; the @RequestLine interface itself has no body) ----
    ("feignClientExecute", "Net",
        "feign.Client c, feign.Request req, feign.Request.Options opts",
        'feign.Response r = c.execute(req, opts)'),

    # ---- Net (Apache HttpClient 4.x — org.apache.http.client.HttpClient.execute; older package than
    #      the modeled httpclient5 org.apache.hc.*) ----
    ("hc4Execute", "Net",
        "org.apache.http.client.HttpClient c, org.apache.http.client.methods.HttpUriRequest req",
        'org.apache.http.HttpResponse r = c.execute(req)'),

    # ---- Fs (Apache Avro — DataFileReader(File,..) reads the container off disk; DataFileWriter.create(Schema,File) opens it) ----
    ("avroReaderFile", "Fs",
        "File f, org.apache.avro.io.DatumReader<Object> dr",
        'org.apache.avro.file.DataFileReader<Object> rdr = new org.apache.avro.file.DataFileReader<>(f, dr)'),
    ("avroWriterCreateFile", "Fs",
        "org.apache.avro.file.DataFileWriter<Object> w, org.apache.avro.Schema sc, File f",
        'org.apache.avro.file.DataFileWriter<Object> r = w.create(sc, f)'),

    # ---- Fs (Typesafe Config — ConfigFactory.parseFile(File) reads the config off disk) ----
    ("typesafeParseFile", "Fs", "File f",
        'com.typesafe.config.Config c = com.typesafe.config.ConfigFactory.parseFile(f)'),

    # ---- Fs (Apache Commons Configuration2 — Configurations.properties(File) opens+reads the file) ----
    ("commonsConfigProps", "Fs",
        "org.apache.commons.configuration2.builder.fluent.Configurations cfgs, File f",
        'org.apache.commons.configuration2.PropertiesConfiguration c = cfgs.properties(f)'),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 4) ======================
    # ---- Fs/Net (jackson FORMAT MODULES — XmlMapper/YAMLMapper/CsvMapper are SUBCLASSES of ObjectMapper.
    #      readValue(File)/writeValue(File) are inherited, but the invokevirtual call-site owner is the
    #      SUBCLASS type, not com.fasterxml.jackson.databind.ObjectMapper, so candor's exact-owner jackson
    #      κ rule likely MISSES these → silent-pure. Expected Fs (File) / Net (URL). String overloads are
    #      pure anchors below.) ----
    ("xmlMapperReadFile",  "Fs",  "com.fasterxml.jackson.dataformat.xml.XmlMapper m, File f",
        'Object o = m.readValue(f, String.class)'),
    ("xmlMapperWriteFile", "Fs",  "com.fasterxml.jackson.dataformat.xml.XmlMapper m, File f",
        'm.writeValue(f, "x")'),
    ("xmlMapperReadUrl",   "Net", "com.fasterxml.jackson.dataformat.xml.XmlMapper m, java.net.URL u",
        'Object o = m.readValue(u, String.class)'),
    ("yamlMapperReadFile", "Fs",  "com.fasterxml.jackson.dataformat.yaml.YAMLMapper m, File f",
        'Object o = m.readValue(f, String.class)'),
    ("yamlMapperWriteFile","Fs",  "com.fasterxml.jackson.dataformat.yaml.YAMLMapper m, File f",
        'm.writeValue(f, "x")'),
    ("csvMapperReadFile",  "Fs",  "com.fasterxml.jackson.dataformat.csv.CsvMapper m, File f",
        'Object o = m.readValue(f, String.class)'),
    ("csvMapperWriteFile", "Fs",  "com.fasterxml.jackson.dataformat.csv.CsvMapper m, File f",
        'm.writeValue(f, "x")'),

    # ---- Net (Email — jakarta.mail Transport.send is a static SMTP send; Spring JavaMailSender.send wraps it) ----
    ("jakartaMailSend", "Net", "jakarta.mail.Message msg",
        'jakarta.mail.Transport.send(msg)'),
    ("springMailSend", "Net", "org.springframework.mail.javamail.JavaMailSender s, jakarta.mail.internet.MimeMessage m",
        's.send(m)'),
    ("springMailImplSend", "Net", "org.springframework.mail.javamail.JavaMailSenderImpl s, jakarta.mail.internet.MimeMessage m",
        's.send(m)'),

    # ---- Net (Cloud storage — GCS/MinIO/Azure are all object stores over HTTP) ----
    ("gcsGet", "Net", "com.google.cloud.storage.Storage st, com.google.cloud.storage.BlobId id",
        'com.google.cloud.storage.Blob b = st.get(id)'),
    ("gcsCreate", "Net", "com.google.cloud.storage.Storage st, com.google.cloud.storage.BlobInfo bi",
        'com.google.cloud.storage.Blob b = st.create(bi, new byte[1])'),
    ("gcsReadAllBytes", "Net", "com.google.cloud.storage.Storage st, com.google.cloud.storage.BlobId id",
        'byte[] b = st.readAllBytes(id)'),
    ("minioGetObject", "Net", "io.minio.MinioClient c, io.minio.GetObjectArgs a",
        'io.minio.GetObjectResponse r = c.getObject(a)'),
    ("minioPutObject", "Net", "io.minio.MinioClient c, io.minio.PutObjectArgs a",
        'io.minio.ObjectWriteResponse r = c.putObject(a)'),
    ("azureBlobDownload", "Net", "com.azure.storage.blob.BlobClient bc",
        'com.azure.core.util.BinaryData d = bc.downloadContent()'),
    ("azureBlobUpload", "Net", "com.azure.storage.blob.BlobClient bc, com.azure.core.util.BinaryData d",
        'bc.upload(d)'),

    # ---- Db/Net (Datastores) ----
    # Neo4j Session.run — Cypher over the bolt protocol (a remote graph DB; Db is the right layer here).
    ("neo4jRun", "Db", "org.neo4j.driver.Session s", 'org.neo4j.driver.Result r = s.run("MATCH (n) RETURN n")'),
    # R2DBC Statement.execute — REACTIVE: returns a Publisher, the actual query is deferred to subscribe.
    #   Expected to be Unknown or pure (lazy reactive boundary); tested honestly (PASS on Db or Unknown).
    ("r2dbcExecute", "Db", "io.r2dbc.spi.Statement st",
        'org.reactivestreams.Publisher<? extends io.r2dbc.spi.Result> p = st.execute()'),
    # Spring Data MongoTemplate find/insert — the Spring-Data Mongo DB leaves.
    ("mongoTemplateFind", "Db", "org.springframework.data.mongodb.core.MongoTemplate t, org.springframework.data.mongodb.core.query.Query q",
        'java.util.List<?> r = t.find(q, String.class)'),
    ("mongoTemplateInsert", "Db", "org.springframework.data.mongodb.core.MongoTemplate t, Object o",
        'Object r = t.insert(o)'),
    # Spring Data Redis — RedisTemplate.opsForValue() is a factory; the terminal get/set on ValueOperations
    #   is the wire leaf (Redis over TCP → Net, same as Jedis/Lettuce).
    ("redisTemplateOpsGet", "Net", "org.springframework.data.redis.core.RedisTemplate<String,String> t",
        'String v = t.opsForValue().get("k")'),
    ("redisValueOpsSet", "Net", "org.springframework.data.redis.core.ValueOperations<String,String> ops",
        'ops.set("k", "v")'),

    # ---- Net (Messaging) ----
    # Pulsar Producer.send — publishes to the broker over TCP.
    ("pulsarSend", "Net", "org.apache.pulsar.client.api.Producer<byte[]> p",
        'org.apache.pulsar.client.api.MessageId id = p.send(new byte[1])'),
    # Spring KafkaTemplate.send — produces to the Kafka broker (wraps the Kafka producer, modeled as Net).
    ("springKafkaSend", "Net", "org.springframework.kafka.core.KafkaTemplate<String,String> t",
        'java.util.concurrent.CompletableFuture<?> f = t.send("topic", "v")'),

    # ---- Fs (File/PDF/image — iText/Thumbnailator open files on disk) ----
    # iText PdfWriter(File) / PdfWriter(String) open the output PDF on disk.
    ("itextPdfWriterFile", "Fs", "File f",
        'com.itextpdf.kernel.pdf.PdfWriter w = new com.itextpdf.kernel.pdf.PdfWriter(f)'),
    ("itextPdfWriterString", "Fs", "String path",
        'com.itextpdf.kernel.pdf.PdfWriter w = new com.itextpdf.kernel.pdf.PdfWriter(path)'),
    # iText PdfReader(File) reads the PDF off disk.
    ("itextPdfReaderFile", "Fs", "File f",
        'com.itextpdf.kernel.pdf.PdfReader r = new com.itextpdf.kernel.pdf.PdfReader(f)'),
    # Thumbnailator Thumbnails.of(File...) reads the source image(s) off disk.
    ("thumbnailatorOfFile", "Fs", "File f",
        'net.coobird.thumbnailator.Thumbnails.Builder<File> b = net.coobird.thumbnailator.Thumbnails.of(f)'),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 5) ======================
    # ---- Net (JSch SSH/SFTP — Session.connect opens the SSH socket; ChannelSftp.get/put move bytes over it) ----
    ("jschSessionConnect", "Net", "com.jcraft.jsch.Session s", 's.connect()'),
    ("jschSftpGet", "Net", "com.jcraft.jsch.ChannelSftp c", 'c.get("remote", "local")'),
    ("jschSftpPut", "Net", "com.jcraft.jsch.ChannelSftp c", 'c.put("local", "remote")'),

    # ---- Net (SSHJ — SSHClient.connect(String) opens the SSH socket; declared on the SocketClient superclass) ----
    ("sshjConnect", "Net", "net.schmizz.sshj.SSHClient c", 'c.connect("host")'),

    # ---- Net (Elasticsearch / OpenSearch low-level RestClient — performRequest is the HTTP round-trip) ----
    ("esRestPerformRequest", "Net",
        "org.elasticsearch.client.RestClient c, org.elasticsearch.client.Request req",
        'org.elasticsearch.client.Response r = c.performRequest(req)'),
    ("opensearchRestPerformRequest", "Net",
        "org.opensearch.client.RestClient c, org.opensearch.client.Request req",
        'org.opensearch.client.Response r = c.performRequest(req)'),

    # ---- Net (InfluxDB — WriteApi.writeRecord writes a line-protocol record to the server over HTTP) ----
    ("influxWriteRecord", "Net",
        "com.influxdb.client.WriteApi w, com.influxdb.client.domain.WritePrecision p",
        'w.writeRecord(p, "m,t=v f=1")'),

    # ---- Net (Couchbase — Collection.get/upsert do KV round-trips to the cluster over the wire) ----
    ("couchbaseGet", "Net", "com.couchbase.client.java.Collection c",
        'com.couchbase.client.java.kv.GetResult r = c.get("id")'),
    ("couchbaseUpsert", "Net", "com.couchbase.client.java.Collection c, Object doc",
        'com.couchbase.client.java.kv.MutationResult r = c.upsert("id", doc)'),

    # ---- Net (AsyncHttpClient — executeRequest(Request) fires the HTTP request) ----
    ("asyncHttpExecute", "Net",
        "org.asynchttpclient.AsyncHttpClient c, org.asynchttpclient.Request req",
        'org.asynchttpclient.ListenableFuture<org.asynchttpclient.Response> f = c.executeRequest(req)'),

    # ---- Net (Vert.x WebClient — HttpRequest.send() dispatches the HTTP request; returns a Future, but the
    #      send is the wire leaf. Reactive/deferred boundary → Net or Unknown both PASS, tested honestly) ----
    ("vertxWebClientSend", "Net", "io.vertx.ext.web.client.HttpRequest<io.vertx.core.buffer.Buffer> req",
        'io.vertx.core.Future<io.vertx.ext.web.client.HttpResponse<io.vertx.core.buffer.Buffer>> f = req.send()'),

    # ---- Fs (FreeMarker — Configuration.getTemplate(String) loads+reads the template file off disk) ----
    ("freemarkerGetTemplate", "Fs", "freemarker.template.Configuration cfg",
        'freemarker.template.Template t = cfg.getTemplate("t.ftl")'),

    # ---- Fs (Velocity — getTemplate(String) reads the template file; mergeTemplate(name,..) also reads it) ----
    ("velocityGetTemplate", "Fs", "org.apache.velocity.app.VelocityEngine e",
        'org.apache.velocity.Template t = e.getTemplate("t.vm")'),
    ("velocityMergeTemplate", "Fs",
        "org.apache.velocity.app.VelocityEngine e, org.apache.velocity.context.Context ctx, Writer w",
        'boolean ok = e.mergeTemplate("t.vm", "UTF-8", ctx, w)'),

    # ---- Fs/Net (Commons VFS — FileContent.getInputStream opens the resource (getContent() is a lazy view;
    #      the terminal getInputStream is the leaf). Local scheme is Fs, remote schemes (ftp/http/sftp) would
    #      be Net. Ambiguous-receiver/scheme → Fs|Net|Unknown all PASS) ----
    ("vfsGetInputStream", "Fs", "org.apache.commons.vfs2.FileObject fo",
        'InputStream in = fo.getContent().getInputStream()'),

    # ---- Fs (univocity — CsvParser.parse(File) opens+reads the CSV off disk; parse(Reader) is a pure anchor) ----
    ("univocityParseFile", "Fs", "com.univocity.parsers.csv.CsvParser p, File f", 'p.parse(f)'),

    # ---- Fs (dotenv-java — Dotenv.load() reads the .env file off the working directory) ----
    ("dotenvLoad", "Fs", "", 'io.github.cdimascio.dotenv.Dotenv d = io.github.cdimascio.dotenv.Dotenv.load()'),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 6) ======================
    # ---- Fs (Lucene — IndexWriter.addDocument writes to the on-disk index; DirectoryReader.open(Directory)
    #      opens the index off disk. The Directory could be a ByteBuffersDirectory (RAM) so candor cannot
    #      always tell from the static type — Fs|Unknown both PASS; the canonical use is an FSDirectory.) ----
    # FSDirectory.open(Path) ALWAYS opens an on-disk index dir → the fabrication-safe Fs leaf. (IndexWriter
    # .addDocument / DirectoryReader.open(Directory) are AMBIGUOUS-RECEIVER — the Directory may be a RAM
    # ByteBuffersDirectory — so they're accepted gaps, not modeled, to avoid fabricating on in-memory Lucene.)
    ("luceneFsDirOpen", "Fs", "java.nio.file.Path p",
        'org.apache.lucene.store.FSDirectory d = org.apache.lucene.store.FSDirectory.open(p)'),

    # ---- Fs (MapDB — DBMaker.fileDB(File).make() opens/creates the on-disk store; the make() terminal is
    #      the leaf. memoryDB().make() is a pure anchor below.) ----
    ("mapdbFileMake", "Fs", "File f",
        'org.mapdb.DB db = org.mapdb.DBMaker.fileDB(f).make()'),

    # ---- Fs (RocksDB — open(String)/get/put hit the on-disk LSM store via native JNI. The effect is real
    #      disk I/O even though these are native methods; Fs is the right layer, Unknown also acceptable.) ----
    ("rocksdbOpen", "Fs", "String path",
        'org.rocksdb.RocksDB db = org.rocksdb.RocksDB.open(path)'),
    ("rocksdbGet", "Fs", "org.rocksdb.RocksDB db", 'byte[] v = db.get(new byte[1])'),
    ("rocksdbPut", "Fs", "org.rocksdb.RocksDB db", 'db.put(new byte[1], new byte[1])'),

    # ---- Exec+Net (Testcontainers — GenericContainer.start spawns a Docker container; it shells out to the
    #      docker daemon (Exec) over its socket/HTTP (Net). Either Exec or Net or Unknown is an acceptable
    #      PASS — the point is it must NOT read silent-pure.) ----
    ("testcontainersStart", "Exec", "org.testcontainers.containers.GenericContainer<?> c", 'c.start()'),

    # ---- Net (Selenium — WebDriver.get drives a browser to a URL over the wire; RemoteWebDriver.get talks
    #      to a remote WebDriver server over HTTP) ----
    ("seleniumWebDriverGet", "Net", "org.openqa.selenium.WebDriver d", 'd.get("http://h/")'),
    ("seleniumRemoteGet", "Net", "org.openqa.selenium.remote.RemoteWebDriver d", 'd.get("http://h/")'),

    # ---- Net (Apache Camel — ProducerTemplate.sendBody/requestBody routes the body to an endpoint, often a
    #      remote one (http/jms/etc). Net is the representative layer; Unknown also acceptable.) ----
    ("camelSendBody", "Net", "org.apache.camel.ProducerTemplate t", 't.sendBody("body")'),
    ("camelRequestBody", "Net", "org.apache.camel.ProducerTemplate t",
        'Object r = t.requestBody((Object) "body")'),

    # ---- Net (JeroMQ — ZMQ.Socket.send/recv move bytes over a 0MQ socket (TCP by default). Ipc is also
    #      defensible for inproc/ipc transports — Net|Ipc|Unknown all PASS.) ----
    ("jeromqSend", "Net", "org.zeromq.ZMQ.Socket s", 'boolean ok = s.send("x")'),
    ("jeromqRecv", "Net", "org.zeromq.ZMQ.Socket s", 'byte[] b = s.recv()'),

    # ---- Net (Apache Thrift — TTransport.open/read/write are the RPC wire transport leaves) ----
    # Thrift: key the SOCKET transports (TSocket) — abstract TTransport has an in-memory TMemoryBuffer
    # subclass, so a TTransport-typed receiver is ambiguous and correctly NOT modeled (would fabricate).
    ("thriftSocketOpen", "Net", "org.apache.thrift.transport.TSocket t", 't.open()'),
    ("thriftSocketWrite", "Net", "org.apache.thrift.transport.TSocket t", 't.write(new byte[1])'),

    # ---- Net (JNDI/LDAP — DirContext.search / InitialDirContext.search issue an LDAP query over the wire.
    #      candor already models InitialContext.lookup as Net; this checks the directory search siblings.) ----
    ("dirContextSearch", "Net", "javax.naming.directory.DirContext c, javax.naming.directory.Attributes attrs",
        'javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> r = c.search("ou=x", attrs)'),
    ("initialDirContextSearch", "Net", "javax.naming.directory.InitialDirContext c, javax.naming.directory.Attributes attrs",
        'javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> r = c.search("ou=x", attrs)'),

    # ---- Rand (BouncyCastle — the lightweight RSAKeyPairGenerator.generateKeyPair draws entropy from the
    #      SecureRandom set via init(). The owner is the BC type, not the JDK KeyPairGenerator. Rand|Unknown
    #      both PASS; a silent-pure here is the gap.) ----
    ("bcRsaGenerateKeyPair", "Rand", "org.bouncycastle.crypto.generators.RSAKeyPairGenerator g",
        'org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = g.generateKeyPair()'),

    # ---- Net (AWS SDK v2 more services — SecretsManager/KMS/SSM are all HTTP under the hood, like S3/Dynamo
    #      already modeled. VERIFY the shared-namespace AWS rule covers these too.) ----
    ("awsSecretsGetValue", "Net",
        "software.amazon.awssdk.services.secretsmanager.SecretsManagerClient c, "
        "software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest req",
        'software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse r = c.getSecretValue(req)'),
    ("awsKmsEncrypt", "Net",
        "software.amazon.awssdk.services.kms.KmsClient c, "
        "software.amazon.awssdk.services.kms.model.EncryptRequest req",
        'software.amazon.awssdk.services.kms.model.EncryptResponse r = c.encrypt(req)'),
    ("awsSsmGetParameter", "Net",
        "software.amazon.awssdk.services.ssm.SsmClient c, "
        "software.amazon.awssdk.services.ssm.model.GetParameterRequest req",
        'software.amazon.awssdk.services.ssm.model.GetParameterResponse r = c.getParameter(req)'),
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
    # JMS createProducer() is a LOCAL factory call (no broker round-trip) — the wire leaf is JMSProducer/
    # MessageProducer.send (modeled as Net, see jmsSend). Setup stays pure (accepted, not a gap).
    ("jmsCreateProducerPure", "jakarta.jms.JMSProducer p = ctx.createProducer()", "jakarta.jms.JMSContext ctx"),
    # R2DBC createStatement() is a LOCAL factory (returns a Statement); the wire leaf is Statement.execute()
    # (modeled Db, see r2dbcExecute). Setup stays pure (accepted, not a gap).
    ("r2dbcCreateStatementPure", "io.r2dbc.spi.Statement st = c.createStatement(\"select 1\")", "io.r2dbc.spi.Connection c"),
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

    # ====================== ADDED LIBRARIES (2026-06-19 batch 3) — pure anchors ===============
    # protobuf parseFrom(byte[]) — in-memory wire-format decode, no I/O (Timestamp is a well-known type
    # shipped in protobuf-java; any generated message's static parseFrom(byte[]) is the same shape).
    ("protobufParseBytesPure",
        "com.google.protobuf.Timestamp t = com.google.protobuf.Timestamp.parseFrom(new byte[1])", ""),
    # KeyStore.load(InputStream, char[]) — caller supplies the stream; the file open is the caller's
    # `new FileInputStream`, so the load itself is pure (caller-stream class, like SnakeYAML/POI).
    ("keystoreLoadStreamPure",
        "ks.load(in, new char[0])", "java.security.KeyStore ks, InputStream in"),
    # Gson fromJson(String) — in-memory JSON parse, no File overload exists (mirror of SnakeYAML/jackson string).
    ("gsonFromStringPure",
        "Object o = g.fromJson(\"{}\", Object.class)", "com.google.gson.Gson g"),
    # Typesafe Config parseString — in-memory, no disk read (parseFile above is the Fs leaf).
    ("typesafeParseStringPure",
        "com.typesafe.config.Config c = com.typesafe.config.ConfigFactory.parseString(\"a=1\")", ""),
    # Avro DataFileWriter.create(Schema, OutputStream) — caller-supplied stream; pure (the File overload is the Fs leaf).
    ("avroWriterStreamPure",
        "org.apache.avro.file.DataFileWriter<Object> r = w.create(sc, os)",
        "org.apache.avro.file.DataFileWriter<Object> w, org.apache.avro.Schema sc, OutputStream os"),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 4) — pure anchors ===============
    # OpenCSV CSVReader(Reader) — the caller supplies the Reader (its file open is the caller's `new
    #   FileReader`), so the CSVReader ctor itself touches no file (caller-stream class, like SnakeYAML/POI).
    ("opencsvReaderPure", "com.opencsv.CSVReader r = new com.opencsv.CSVReader(rd)", "Reader rd"),
    # Apache Commons CSV CSVParser.parse(Reader, CSVFormat) — caller-supplied Reader; the file open is the
    #   caller's. The File/Path/URL overloads ARE Fs leaves, but parse(Reader) must stay pure.
    ("commonsCsvParseReaderPure",
        "org.apache.commons.csv.CSVParser p = org.apache.commons.csv.CSVParser.parse(rd, org.apache.commons.csv.CSVFormat.DEFAULT)",
        "Reader rd"),
    # jackson FORMAT MODULE in-memory String (de)serialization touches no file/socket — must stay pure even
    #   after the File siblings above are modeled (guards against over-classifying the whole subclass owner).
    ("xmlMapperReadStringPure",
        "Object o = m.readValue(\"<x/>\", Object.class)", "com.fasterxml.jackson.dataformat.xml.XmlMapper m"),
    ("yamlMapperReadStringPure",
        "Object o = m.readValue(\"a: 1\", Object.class)", "com.fasterxml.jackson.dataformat.yaml.YAMLMapper m"),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 5) — pure anchors ===============
    # FreeMarker Template.process(model, Writer) — the caller supplies the Writer (its file open is the
    #   caller's `new FileWriter`), so the render itself touches no file. getTemplate(String) above is the Fs leaf.
    ("freemarkerProcessWriterPure",
        "t.process(new Object(), w)", "freemarker.template.Template t, Writer w"),
    # Velocity Template.merge(ctx, Writer) — caller-supplied Writer; the render is pure (getTemplate is the Fs leaf).
    ("velocityMergeWriterPure",
        "t.merge(ctx, w)", "org.apache.velocity.Template t, org.apache.velocity.context.Context ctx, Writer w"),
    # univocity CsvParser.parse(Reader) / parse(InputStream) — caller-supplied stream; the file open is the
    #   caller's. parse(File) above is the Fs leaf; these caller-stream overloads must stay pure.
    ("univocityParseReaderPure", "p.parse(rd)", "com.univocity.parsers.csv.CsvParser p, Reader rd"),
    ("univocityParseStreamPure", "p.parse(in)", "com.univocity.parsers.csv.CsvParser p, InputStream in"),
    # Couchbase Bucket.collection(name) is a LOCAL factory (returns a Collection handle, no wire round-trip);
    #   the wire leaf is Collection.get/upsert (modeled Net above). Setup stays pure (accepted, not a gap).
    ("couchbaseCollectionFactoryPure",
        "com.couchbase.client.java.Collection c = b.defaultCollection()", "com.couchbase.client.java.Bucket b"),

    # ====================== ADDED LIBRARIES (2026-06-19 batch 6) — pure anchors ===============
    # Ehcache 3 is an IN-MEMORY (heap) cache by default — Cache.get/put touch no I/O. candor must stay pure
    #   (a disk-tiered config would do Fs, but the get/put call alone cannot reveal that — fabricating Fs here
    #   would over-classify the common heap-cache case, same accepted tradeoff as Caffeine).
    ("ehcacheGetPure", "Object v = c.get(\"k\")", "org.ehcache.Cache<String,Object> c"),
    ("ehcachePutPure", "c.put(\"k\", new Object())", "org.ehcache.Cache<String,Object> c"),
    # MapDB memoryDB().make() is the in-memory store — no disk (fileDB(File).make() above is the Fs leaf).
    #   Pins that candor must not flood the make() terminal as Fs regardless of the maker source.
    ("mapdbMemoryMakePure", "org.mapdb.DB db = org.mapdb.DBMaker.memoryDB().make()", ""),
    # Lucene ByteBuffersDirectory is an IN-MEMORY Directory — opening a reader over it touches no disk. The
    #   DirectoryReader.open leaf above is modeled Fs (canonical FSDirectory); this anchors that the RAM
    #   directory CONSTRUCTION itself is pure (the ambiguity is why Unknown is an accepted PASS on the reader).
    ("luceneRamDirPure",
        "org.apache.lucene.store.ByteBuffersDirectory d = new org.apache.lucene.store.ByteBuffersDirectory()", ""),
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
    # --- added 2026-06-19 batch 3 ---
    # Datastores/DB
    "java-driver-core-4.17.0.jar": f"{_MVN}/com/datastax/oss/java-driver-core/4.17.0/java-driver-core-4.17.0.jar",
    "mybatis-3.5.16.jar": f"{_MVN}/org/mybatis/mybatis/3.5.16/mybatis-3.5.16.jar",
    "jooq-3.19.10.jar": f"{_MVN}/org/jooq/jooq/3.19.10/jooq-3.19.10.jar",
    "spring-data-commons-3.3.1.jar": f"{_MVN}/org/springframework/data/spring-data-commons/3.3.1/spring-data-commons-3.3.1.jar",
    "lettuce-core-6.3.2.RELEASE.jar": f"{_MVN}/io/lettuce/lettuce-core/6.3.2.RELEASE/lettuce-core-6.3.2.RELEASE.jar",
    # Messaging
    "amqp-client-5.21.0.jar": f"{_MVN}/com/rabbitmq/amqp-client/5.21.0/amqp-client-5.21.0.jar",
    "jakarta.jms-api-3.1.0.jar": f"{_MVN}/jakarta/jms/jakarta.jms-api/3.1.0/jakarta.jms-api-3.1.0.jar",
    "spring-rabbit-3.1.6.jar": f"{_MVN}/org/springframework/amqp/spring-rabbit/3.1.6/spring-rabbit-3.1.6.jar",
    "spring-amqp-3.1.6.jar": f"{_MVN}/org/springframework/amqp/spring-amqp/3.1.6/spring-amqp-3.1.6.jar",
    "spring-context-6.1.10.jar": f"{_MVN}/org/springframework/spring-context/6.1.10/spring-context-6.1.10.jar",
    "spring-messaging-6.1.10.jar": f"{_MVN}/org/springframework/spring-messaging/6.1.10/spring-messaging-6.1.10.jar",
    # Cloud (AWS v2 — DynamoDB/SQS/SNS; core SDK jars already present from S3)
    "dynamodb-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/dynamodb/2.25.60/dynamodb-2.25.60.jar",
    "sqs-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/sqs/2.25.60/sqs-2.25.60.jar",
    "sns-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/sns/2.25.60/sns-2.25.60.jar",
    # HTTP clients
    "retrofit-2.11.0.jar": f"{_MVN}/com/squareup/retrofit2/retrofit/2.11.0/retrofit-2.11.0.jar",
    "feign-core-13.2.1.jar": f"{_MVN}/io/github/openfeign/feign-core/13.2.1/feign-core-13.2.1.jar",
    "httpclient-4.5.14.jar": f"{_MVN}/org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar",
    "httpcore-4.4.16.jar": f"{_MVN}/org/apache/httpcomponents/httpcore/4.4.16/httpcore-4.4.16.jar",
    # File/config
    "avro-1.11.3.jar": f"{_MVN}/org/apache/avro/avro/1.11.3/avro-1.11.3.jar",
    "config-1.4.3.jar": f"{_MVN}/com/typesafe/config/1.4.3/config-1.4.3.jar",
    "commons-configuration2-2.10.1.jar": f"{_MVN}/org/apache/commons/commons-configuration2/2.10.1/commons-configuration2-2.10.1.jar",
    # Pure anchors (protobuf in-memory decode, Gson in-memory parse; KeyStore is JDK)
    "protobuf-java-3.25.3.jar": f"{_MVN}/com/google/protobuf/protobuf-java/3.25.3/protobuf-java-3.25.3.jar",
    "gson-2.11.0.jar": f"{_MVN}/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar",
    # --- added 2026-06-19 batch 4 ---
    # Jackson format modules (subclasses of ObjectMapper; jackson-core/databind/annotations already present)
    "jackson-dataformat-xml-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/dataformat/jackson-dataformat-xml/2.17.1/jackson-dataformat-xml-2.17.1.jar",
    "jackson-dataformat-yaml-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/2.17.1/jackson-dataformat-yaml-2.17.1.jar",
    "jackson-dataformat-csv-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/dataformat/jackson-dataformat-csv/2.17.1/jackson-dataformat-csv-2.17.1.jar",
    "stax2-api-4.2.2.jar": f"{_MVN}/org/codehaus/woodstox/stax2-api/4.2.2/stax2-api-4.2.2.jar",  # XmlMapper compile dep
    # Email — jakarta.mail API + Spring context-support (JavaMailSender)
    "jakarta.mail-api-2.1.3.jar": f"{_MVN}/jakarta/mail/jakarta.mail-api/2.1.3/jakarta.mail-api-2.1.3.jar",
    "jakarta.activation-api-2.1.3.jar": f"{_MVN}/jakarta/activation/jakarta.activation-api/2.1.3/jakarta.activation-api-2.1.3.jar",
    "spring-context-support-6.1.10.jar": f"{_MVN}/org/springframework/spring-context-support/6.1.10/spring-context-support-6.1.10.jar",
    # Cloud storage — GCS / MinIO / Azure Blob (all HTTP object stores)
    "google-cloud-storage-2.40.0.jar": f"{_MVN}/com/google/cloud/google-cloud-storage/2.40.0/google-cloud-storage-2.40.0.jar",
    "gax-2.50.0.jar": f"{_MVN}/com/google/api/gax/2.50.0/gax-2.50.0.jar",  # GCS compile dep (com.google.api.gax)
    "google-cloud-core-2.40.0.jar": f"{_MVN}/com/google/cloud/google-cloud-core/2.40.0/google-cloud-core-2.40.0.jar",  # com.google.cloud.Service
    "minio-8.5.10.jar": f"{_MVN}/io/minio/minio/8.5.10/minio-8.5.10.jar",
    "azure-storage-blob-12.26.1.jar": f"{_MVN}/com/azure/azure-storage-blob/12.26.1/azure-storage-blob-12.26.1.jar",
    "azure-core-1.49.1.jar": f"{_MVN}/com/azure/azure-core/1.49.1/azure-core-1.49.1.jar",  # BinaryData type
    # Datastores — Neo4j / R2DBC / Spring Data Mongo / Spring Data Redis
    "neo4j-java-driver-5.21.0.jar": f"{_MVN}/org/neo4j/driver/neo4j-java-driver/5.21.0/neo4j-java-driver-5.21.0.jar",
    "r2dbc-spi-1.0.0.RELEASE.jar": f"{_MVN}/io/r2dbc/r2dbc-spi/1.0.0.RELEASE/r2dbc-spi-1.0.0.RELEASE.jar",
    "spring-data-mongodb-4.3.1.jar": f"{_MVN}/org/springframework/data/spring-data-mongodb/4.3.1/spring-data-mongodb-4.3.1.jar",
    "spring-data-redis-3.3.1.jar": f"{_MVN}/org/springframework/data/spring-data-redis/3.3.1/spring-data-redis-3.3.1.jar",
    # Messaging — Apache Pulsar / Spring Kafka (kafka-clients already present)
    "pulsar-client-api-3.2.4.jar": f"{_MVN}/org/apache/pulsar/pulsar-client-api/3.2.4/pulsar-client-api-3.2.4.jar",
    "spring-kafka-3.1.5.jar": f"{_MVN}/org/springframework/kafka/spring-kafka/3.1.5/spring-kafka-3.1.5.jar",
    # File/PDF/image — iText (kernel/io/commons split) + Thumbnailator
    "itext-kernel-8.0.4.jar": f"{_MVN}/com/itextpdf/kernel/8.0.4/kernel-8.0.4.jar",
    "itext-io-8.0.4.jar": f"{_MVN}/com/itextpdf/io/8.0.4/io-8.0.4.jar",
    "itext-commons-8.0.4.jar": f"{_MVN}/com/itextpdf/commons/8.0.4/commons-8.0.4.jar",
    "thumbnailator-0.4.20.jar": f"{_MVN}/net/coobird/thumbnailator/0.4.20/thumbnailator-0.4.20.jar",
    # Pure anchors — OpenCSV / Apache Commons CSV (caller-stream ctors must stay pure)
    "opencsv-5.9.jar": f"{_MVN}/com/opencsv/opencsv/5.9/opencsv-5.9.jar",
    "commons-csv-1.11.0.jar": f"{_MVN}/org/apache/commons/commons-csv/1.11.0/commons-csv-1.11.0.jar",
    # --- added 2026-06-19 batch 5 ---
    # SSH/SFTP — JSch (the maintained mwiede fork; same com.jcraft.jsch package) + SSHJ
    "jsch-0.2.18.jar": f"{_MVN}/com/github/mwiede/jsch/0.2.18/jsch-0.2.18.jar",
    "sshj-0.38.0.jar": f"{_MVN}/com/hierynomus/sshj/0.38.0/sshj-0.38.0.jar",
    # Search — Elasticsearch + OpenSearch low-level REST clients (self-contained over httpcore, already present)
    "elasticsearch-rest-client-8.14.1.jar": f"{_MVN}/org/elasticsearch/client/elasticsearch-rest-client/8.14.1/elasticsearch-rest-client-8.14.1.jar",
    "opensearch-rest-client-2.14.0.jar": f"{_MVN}/org/opensearch/client/opensearch-rest-client/2.14.0/opensearch-rest-client-2.14.0.jar",
    # Datastores — InfluxDB (api + core for WritePrecision) + Couchbase (java-client + core-io 2.6.2)
    "influxdb-client-java-7.1.0.jar": f"{_MVN}/com/influxdb/influxdb-client-java/7.1.0/influxdb-client-java-7.1.0.jar",
    "influxdb-client-core-7.1.0.jar": f"{_MVN}/com/influxdb/influxdb-client-core/7.1.0/influxdb-client-core-7.1.0.jar",
    "couchbase-java-client-3.6.2.jar": f"{_MVN}/com/couchbase/client/java-client/3.6.2/java-client-3.6.2.jar",
    "couchbase-core-io-2.6.2.jar": f"{_MVN}/com/couchbase/client/core-io/2.6.2/core-io-2.6.2.jar",
    # HTTP/async — AsyncHttpClient + Vert.x WebClient (vertx-core for Future/Buffer types)
    "async-http-client-3.0.0.jar": f"{_MVN}/org/asynchttpclient/async-http-client/3.0.0/async-http-client-3.0.0.jar",
    "vertx-web-client-4.5.8.jar": f"{_MVN}/io/vertx/vertx-web-client/4.5.8/vertx-web-client-4.5.8.jar",
    "vertx-core-4.5.8.jar": f"{_MVN}/io/vertx/vertx-core/4.5.8/vertx-core-4.5.8.jar",
    # Templating — FreeMarker + Velocity (velocity needs commons-lang3 for compile)
    "freemarker-2.3.32.jar": f"{_MVN}/org/freemarker/freemarker/2.3.32/freemarker-2.3.32.jar",
    "velocity-engine-core-2.3.jar": f"{_MVN}/org/apache/velocity/velocity-engine-core/2.3/velocity-engine-core-2.3.jar",
    "commons-lang3-3.14.0.jar": f"{_MVN}/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
    # File formats / IO — Apache Commons VFS + univocity-parsers
    "commons-vfs2-2.9.0.jar": f"{_MVN}/org/apache/commons/commons-vfs2/2.9.0/commons-vfs2-2.9.0.jar",
    "univocity-parsers-2.9.1.jar": f"{_MVN}/com/univocity/univocity-parsers/2.9.1/univocity-parsers-2.9.1.jar",
    # Config/secrets — dotenv-java
    "dotenv-java-3.0.0.jar": f"{_MVN}/io/github/cdimascio/dotenv-java/3.0.0/dotenv-java-3.0.0.jar",
    # --- added 2026-06-19 batch 6 ---
    # Embedded on-disk stores — Lucene / MapDB / RocksDB (JNI). Ehcache 3 (in-memory anchor).
    "lucene-core-9.11.1.jar": f"{_MVN}/org/apache/lucene/lucene-core/9.11.1/lucene-core-9.11.1.jar",
    "mapdb-3.1.0.jar": f"{_MVN}/org/mapdb/mapdb/3.1.0/mapdb-3.1.0.jar",
    "rocksdbjni-9.2.1.jar": f"{_MVN}/org/rocksdb/rocksdbjni/9.2.1/rocksdbjni-9.2.1.jar",
    "ehcache-3.10.8.jar": f"{_MVN}/org/ehcache/ehcache/3.10.8/ehcache-3.10.8.jar",
    # Containers/automation — Testcontainers / Selenium (api + remote-driver)
    "testcontainers-1.19.8.jar": f"{_MVN}/org/testcontainers/testcontainers/1.19.8/testcontainers-1.19.8.jar",
    # junit is a COMPILE-only dep of Testcontainers (GenericContainer implements org.junit.rules.TestRule) —
    # needed to give javac the type; not under test (no junit EFFECT_CASE).
    "junit-4.13.2.jar": f"{_MVN}/junit/junit/4.13.2/junit-4.13.2.jar",
    "selenium-api-4.21.0.jar": f"{_MVN}/org/seleniumhq/selenium/selenium-api/4.21.0/selenium-api-4.21.0.jar",
    "selenium-remote-driver-4.21.0.jar": f"{_MVN}/org/seleniumhq/selenium/selenium-remote-driver/4.21.0/selenium-remote-driver-4.21.0.jar",
    # Integration/messaging — Apache Camel / JeroMQ / Apache Thrift
    "camel-api-4.6.0.jar": f"{_MVN}/org/apache/camel/camel-api/4.6.0/camel-api-4.6.0.jar",
    "jeromq-0.6.0.jar": f"{_MVN}/org/zeromq/jeromq/0.6.0/jeromq-0.6.0.jar",
    "libthrift-0.20.0.jar": f"{_MVN}/org/apache/thrift/libthrift/0.20.0/libthrift-0.20.0.jar",
    # Native crypto — BouncyCastle (provider jar carries the crypto.generators package)
    "bcprov-jdk18on-1.78.1.jar": f"{_MVN}/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar",
    # AWS SDK v2 more services — SecretsManager / KMS / SSM (core SDK jars already present from S3)
    "secretsmanager-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/secretsmanager/2.25.60/secretsmanager-2.25.60.jar",
    "kms-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/kms/2.25.60/kms-2.25.60.jar",
    "ssm-2.25.60.jar": f"{_MVN}/software/amazon/awssdk/ssm/2.25.60/ssm-2.25.60.jar",
    # JNDI/LDAP DirContext is in the JDK (javax.naming.directory) — no jar needed.
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
          f"jpa/mongo/jedis/kafka/jsoup/aws-s3/grpc/webclient/restclient/hibernate/"
          f"cassandra/mybatis/jooq/rabbitmq/jms/spring-amqp/aws-dynamo-sqs-sns/retrofit/httpclient4/+gaps), "
          f"{len(PURE_CASES)} pure neighbours unflooded")


if __name__ == "__main__":
    main()
