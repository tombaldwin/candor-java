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
    # ====================== ADDED LIBRARIES (2026-06-20 batch 7) ======================
    # Distributed caches/grids → Net (the get/put hit a remote partition/cluster over the wire). CRITICAL
    #   nuance: Hazelcast IMap and Infinispan BasicCache EXTEND java.util.concurrent.ConcurrentMap, so get/put
    #   are inherited Map verbs — but the invoke* call-site owner is the CACHE interface (IMap / BasicCache),
    #   not java.util.Map, so an owner-scoped κ rule keyed on the cache type is fabrication-safe. Ignite
    #   IgniteCache extends javax.cache.Cache (JCache), not Map. A java.util.Map-typed PURE anchor below proves
    #   the rule does NOT flood the JDK Map.
    # DB toolkits → Db: JDBI (Jdbi.withHandle / Handle.execute / Handle.createQuery), Spring Data Cassandra
    #   (CassandraTemplate.select/insert), Spring Data Couchbase (CouchbaseTemplate.save).
    # SaaS SDKs → Net: Stripe (com.stripe.model.Charge.create/retrieve — STATIC leaf that delegates to the
    #   ApiResource request machinery), Twilio (MessageCreator.create() — the no-arg terminal that uses the
    #   default TwilioRestClient and hits the wire), SendGrid (com.sendgrid.SendGrid.api(Request) — api() is
    #   declared on BaseInterface; the call-site owner is the SendGrid static type).
    # Reactive/HTTP → Net (lazy — Net or Unknown both PASS): reactor-netty HttpClient.get().responseContent()
    #   / .response() (the leaf owner is HttpClient$ResponseReceiver, NOT HttpClient).
    # Email → Net: Apache Commons Email Email.send() (opens an SMTP transport and sends).
    # Scheduling → documented: Quartz Scheduler.scheduleJob — pure/Unknown unless a JDBCJobStore is wired;
    #   the API call alone can't tell, so a silent-pure is ACCEPTED (documented), not a hard GAP.
    # spring-data-couchbase ships a querydsl annotation Processor service file — the probe's javac now runs
    #   with -proc:none (it only needs type resolution, never annotation processing).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2/3/4/5/6.
    # ====================== ADDED LIBRARIES (2026-06-20 batch 8) ======================
    # Observability -> Net (export hits the wire; batched/lazy export -> Net OR Unknown both PASS):
    #   Sentry (io.sentry.Sentry.captureException/captureMessage — STATIC leaves that delegate to the hub and
    #     transport; the wire send is queued/async, so Net or Unknown both PASS, documented if pure).
    #   OpenTelemetry SpanExporter.export(Collection<SpanData>) -> Net (the actual span batch flush). The
    #     user-facing Span.end() is DEFERRED to the BatchSpanProcessor (no synchronous wire) — silent-pure is
    #     ACCEPTED+documented there (ambiguous/lazy class, like Quartz). Span.setAttribute is a PURE anchor.
    #   Micrometer Counter.increment() is IN-MEMORY (the registry holds the count; PUSH registries flush on a
    #     background scheduler) -> PURE anchor. StatsdMeterRegistry.counter(...) is a FACTORY (pure anchor).
    # Native-tool wrappers -> Exec (spawn a process / native lib; Exec|Unknown both PASS, must NOT be pure):
    #   im4java org.im4java.core.ImageCommand.run(Operation, Object...) -> Exec (shells out to ImageMagick).
    #   Tess4J net.sourceforge.tess4j.Tesseract.doOCR(File) -> native JNA into libtesseract (Exec|Fs|Unknown).
    # HTTP clients -> Net: Google HTTP client (com.google.api.client.http.HttpRequest.execute), Eclipse Jetty
    #   client (org.eclipse.jetty.client.HttpClient.GET / Request.send), Unirest (kong.unirest.GetRequest.
    #   asString/asJson).
    # Messaging -> Net: NATS (io.nats.client.Connection.publish/request), ActiveMQ Artemis
    #   (org.apache.activemq.artemis.api.core.client.ClientProducer.send).
    # Crypto -> Rand: Google Tink (com.google.crypto.tink.KeysetHandle.generateNew — draws entropy for key
    #   material). Jasypt StandardPBEStringEncryptor.encrypt — random-salt mode draws a salt (Rand) but the
    #   call site can't reveal the salt-generator config, so Rand|Unknown PASS and a pure result is documented.
    # Serialization -> PURE anchor: Kryo writeObject(Output, Object) is caller-stream (the Output wraps the
    #   caller's OutputStream; the file open is the caller's) — no File overload, so it must stay pure.
    # SKIPPED (noted in the report): ArangoDB java-driver — the published arangodb-java-driver jar is an
    #   aggregator/shaded stub with NO .class files for com.arangodb.* (only 19 entries, no ArangoDatabase),
    #   so the fixture can't compile against it without resolving split shaded modules; skipped as heavy.
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2/3/4/5/6/7.
    # ====================== ADDED LIBRARIES (2026-06-20 batch 9) ======================
    # Cloud-native infra clients, secrets, more datastores. KEY FINDING: unlike AWS v2 (which keys on the
    #   software.amazon.awssdk.services.* shared namespace), the GCP services do NOT share a namespace — each
    #   service is a DISTINCT top-level class: com.google.cloud.bigquery.BigQuery, com.google.cloud.firestore
    #   .CollectionReference, com.google.cloud.pubsub.v1.Publisher, com.google.cloud.storage.Storage (already
    #   modeled). So each GCP service needs its own owner-scoped rule; there is no single com.google.cloud.*
    #   wire-namespace (com.google.cloud also hosts pure value types like Timestamp/Date/Policy).
    # GCP -> Net: BigQuery.query/insertAll (owner com.google.cloud.bigquery.BigQuery); Firestore
    #   CollectionReference.get / DocumentReference.get (the get() is inherited from Query but the call-site
    #   owner is the concrete CollectionReference/DocumentReference); Pub/Sub Publisher.publish (owner
    #   com.google.cloud.pubsub.v1.Publisher). All return ApiFuture (async) — Net or Unknown both PASS.
    # Kubernetes -> Net: fabric8 — the fluent DSL terminal is MixedOperation.list() (the call-site owner of
    #   `client.pods().list()` is io.fabric8.kubernetes.client.dsl.MixedOperation; the intermediate pods() is a
    #   pure DSL accessor). The clean modellable leaf is the Listable.list / Createable.create terminal verb,
    #   NOT the per-resource accessors (pods()/nodes()/…). Listable/Createable/Gettable are the terminal mixins.
    # Docker -> Net/Exec: docker-java — the *Cmd.exec() terminal hits the Docker daemon (the call-site owner is
    #   the per-command type, e.g. com.github.dockerjava.api.command.PingCmd, all extending SyncDockerCmd.exec).
    #   The modellable leaf is SyncDockerCmd.exec (or each *Cmd.exec); the *Cmd() accessors on DockerClient are
    #   pure builders. Net (daemon socket/HTTP) or Exec or Unknown all PASS.
    # Secrets -> Net: Spring Vault VaultTemplate.read/write (owner org.springframework.vault.core.VaultTemplate);
    #   vault-java-driver (jopenlibs fork) Logical.read/write (owner io.github.jopenlibs.vault.api.Logical;
    #   Vault.logical() is a pure accessor).
    # Datastores -> Net: Redisson RBucket.get/set (owner org.redisson.api.RBucket; RedissonClient.getBucket is
    #   a pure factory -> anchor); etcd jetcd KV.get/put (owner io.etcd.jetcd.KV; returns CompletableFuture -
    #   async, Net|Unknown PASS); Consul orbitz KeyValueClient.getValue/putValue (owner com.orbitz.consul
    #   .KeyValueClient).
    # LDAP -> Net: UnboundID LDAPConnection.search/bind/connect (owner com.unboundid.ldap.sdk.LDAPConnection).
    # Memory-mapped file store -> Fs: Chronicle Queue ChronicleQueue.singleBuilder(File).build() opens/creates
    #   the on-disk queue dir; the call-site owner of build() is SingleChronicleQueueBuilder (NOT ChronicleQueue).
    # WebDAV -> Net: Sardine.get/put (owner com.github.sardine.Sardine).
    # PURE anchors: Redisson getBucket factory, BigQuery QueryJobConfiguration builder, Vault.logical() accessor,
    #   DockerClient.pingCmd() accessor, KubernetesClient.pods() DSL accessor (all builders/factories pure-
    #   until-terminal). A java.util.Map anchor is unnecessary here (no new Map-implementing owner added).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2/3/4/5/6/7/8.
    # SKIPPED: ecwid Consul (com.ecwid.consul.v1.ConsulClient) — redundant with orbitz; not added to keep the
    #   datastore set lean (one Consul client suffices to characterize the gap).
    # ====================== ADDED LIBRARIES (2026-06-20 batch 10) ======================
    # Service discovery/coordination, workflow, search, more cloud, reactive RPC, feature flags, HTTP clients.
    # Coordination -> Net: ZooKeeper (org.apache.zookeeper.ZooKeeper.getData/create/setData/exists — the
    #   synchronous client methods do a round-trip to the ensemble over TCP). Curator (the FLUENT terminal is
    #   forPath: `cf.create().forPath(p,b)` / `cf.getData().forPath(p)` — the call-site owner of forPath with a
    #   CreateBuilder/GetDataBuilder-typed receiver is org.apache.curator.framework.api.CreateBuilder /
    #   GetDataBuilder (the static receiver type of the invokeinterface); create()/getData() are pure accessor
    #   anchors). Eureka client (com.netflix.discovery.EurekaClient.getApplications()/getNextServerFromEureka —
    #   inherited from LookupService but the call-site owner is EurekaClient; NB Eureka reads from the LOCAL
    #   cached registry the client polls in the background, so a silent-pure is the documented accepted outcome,
    #   like LaunchDarkly local-eval — Net|Unknown PASS, pure documented).
    # Workflow -> Net: Temporal — the WorkflowClient.start/execute API is STUB-PROXY-heavy (needs a generated
    #   workflow-interface stub), so the clean wire terminal tested is WorkflowServiceStubs.newServiceStubs
    #   (opens the gRPC channel to the Temporal frontend). Net|Unknown PASS; a pure factory result documented.
    # Search -> Net: Apache Solr (org.apache.solr.client.solrj.SolrClient.query/add/commit — each is an HTTP
    #   round-trip to the Solr server; the base SolrClient is the call-site owner of the concrete subclass).
    # More cloud:
    #   GCP Spanner -> Net/Db: the wire leaf is ReadContext.executeQuery(Statement) (owner com.google.cloud
    #     .spanner.ReadContext). DatabaseClient.singleUse() is a pure accessor (returns a ReadContext, no wire) ->
    #     anchor. Db or Net or Unknown all PASS (Spanner is a distributed SQL DB over the wire).
    #   Azure CosmosDB -> Net: com.azure.cosmos.CosmosContainer.readItem/createItem (HTTP to the Cosmos endpoint).
    #     CosmosDatabase.getContainer(name) is a pure accessor -> anchor.
    #   Azure Service Bus -> Net: com.azure.messaging.servicebus.ServiceBusSenderClient.sendMessage (AMQP send).
    #   Azure Key Vault -> Net: com.azure.security.keyvault.secrets.SecretClient.getSecret/setSecret (HTTPS).
    #   GCP Secret Manager -> Net: com.google.cloud.secretmanager.v1.SecretManagerServiceClient
    #     .accessSecretVersion(String) (gRPC/HTTP to the Secret Manager API).
    # Reactive RPC -> Net: RSocket (io.rsocket.RSocket.requestResponse/fireAndForget — reactive; returns a Mono,
    #   the wire is deferred to subscribe, so Net OR Unknown both PASS).
    # Feature flags: LaunchDarkly (com.launchdarkly.sdk.server.LDClient.boolVariation — evaluates against the
    #   LOCAL in-memory flag store the SDK keeps in sync via a background streaming connection; the variation call
    #   itself does NO synchronous wire, so a silent-pure is the documented ACCEPTED outcome, NOT a hard gap —
    #   modeling Net here would fabricate on every flag check). Unleash (io.getunleash.Unleash.isEnabled — same
    #   local-cache eval shape; documented accepted-pure). Both tested honestly: Net|Unknown PASS, pure documented.
    # HTTP clients -> Net: Micronaut (io.micronaut.http.client.BlockingHttpClient.exchange(String) — the blocking
    #   HTTP round-trip; the reactive HttpClient.exchange returns a Publisher so the wire is deferred).
    # PURE anchors: Curator create()/getData() fluent intermediates; Spanner singleUse() accessor; Cosmos
    #   getContainer() accessor; any DSL builder pure-until-terminal.
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2..9.
    # ====================== ADDED LIBRARIES (2026-06-20 batch 11) ======================
    # AI/LLM clients, vector DBs, more caches/datastores, graph, blockchain, more cloud.
    # AI/LLM -> Net (the generate/chat call is an HTTP round-trip to the model API):
    #   theokanning OpenAI (com.theokanning.openai.service.OpenAiService.createChatCompletion — the SDK leaf;
    #     OkHttp/Retrofit run under the hood but the call-site owner is OpenAiService, so it's silent unless
    #     candor models the SDK terminal). LangChain4j (dev.langchain4j.model.chat.ChatLanguageModel.generate —
    #     the abstract wire method; the concrete OpenAiChatModel.generate is the impl, both worth modelling;
    #     NB generate(String) is a default that delegates to generate(List), so test the List overload too).
    #     Anthropic Java SDK (com.anthropic.services.blocking.MessageService.create(MessageCreateParams) — the
    #     blocking message create; the SDK is Kotlin, the real classes are in anthropic-java-CORE, not the
    #     305-byte anthropic-java aggregator stub). All return eagerly (blocking) -> Net; Unknown also PASS.
    # Vector DBs -> Net (query/upsert/search hit the vector store over gRPC/HTTP):
    #   Pinecone (io.pinecone.clients.Index.upsert/query — the gRPC data-plane terminal; Pinecone the top-level
    #     client is a control-plane builder). Qdrant (io.qdrant.client.QdrantClient.upsertAsync/searchAsync —
    #     returns a guava ListenableFuture (async) -> Net|Unknown PASS). Milvus (io.milvus.client
    #     .MilvusServiceClient.search/insert — returns io.milvus.param.R wrapper; the gRPC call is eager).
    #   Weaviate SKIPPED: its wire terminal is buried in a fluent DSL (client.data().creator()....run()); the
    #     run() owner is a per-builder type, not WeaviateClient — same deep-DSL shape as the k8s/curator terminals
    #     already characterized, and the builder set is large; skipped to keep the vector set lean (Pinecone/
    #     Qdrant/Milvus already characterize the gRPC-vector-DB gap).
    # Caches/KV -> Net (get/set hit a remote memcached/aerospike node over TCP):
    #   Spymemcached (net.spy.memcached.MemcachedClient.get/set). Xmemcached (net.rubyeye.xmemcached
    #     .XMemcachedClient.get/set). Aerospike (com.aerospike.client.AerospikeClient.get/put — the get/put take
    #     a Policy+Key, NOT a String, so they can't be confused with java.util.Map verbs). NB MemcachedClient is
    #     NOT a java.util.Map (no inheritance), so an owner-scoped rule is fabrication-safe; the java.util.Map
    #     PURE anchors from batch 7 still guard the JDK Map.
    # Graph -> Net: Apache TinkerPop Gremlin driver (org.apache.tinkerpop.gremlin.driver.Client.submit — submits
    #   a Gremlin query to the remote server over the wire; returns a ResultSet, eager submit).
    # Blockchain -> Net: web3j (org.web3j.protocol.core.Request.send() — the JSON-RPC round-trip to the Ethereum
    #   node; Request<T,R>.send() is the generic terminal every web3j call (ethBlockNumber, ethGetBalance, …)
    #   bottoms out in, so modelling Request.send covers the whole web3j surface in one rule).
    # More cloud -> Net: Azure Event Hubs (com.azure.messaging.eventhubs.EventHubProducerClient.send — AMQP send
    #   to the hub). Azure Table Storage (com.azure.data.tables.TableClient.createEntity/getEntity — HTTP to the
    #   Table endpoint).
    # PURE anchors: OpenAiService construction (a builder/factory, no wire); MilvusServiceClient construction
    #   (factory); an in-memory java.util.List vector (computed locally, no wire). Plus the existing batch-7
    #   java.util.Map anchors continue to guard against cache rules flooding the JDK Map.
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2..10.
    # ====================== ADDED LIBRARIES (2026-06-20 batch 12) ======================
    # Spring AI, chat/comms SDKs, identity, payments, maps, more DB. RESULT: a strong gap-rich batch — the
    # vein is NOT dry for vertical SaaS SDKs. (See the batch-12 report.)
    # Spring AI -> Net (FLOOR-SUPPRESSED — note like Spring Vault): the wire terminal is the ChatClient
    #   fluent chain `cc.prompt().user(..).call().content()` (owner of content()/chatResponse() is
    #   org.springframework.ai.chat.client.ChatClient$CallResponseSpec) and OpenAiChatModel.call(Prompt)
    #   (owner org.springframework.ai.openai.OpenAiChatModel). BOTH owners are org.springframework.*, so
    #   candor DROPS these functions from the report ENTIRELY (Spring floor-suppression — same accepted
    #   tradeoff as Spring Vault VaultTemplate; the probe records absence as the documented floor-suppress
    #   outcome, NOT a hard gap, since modelling would require narrowing the org.springframework.* floor).
    # Chat/comms -> Net: Slack (com.slack.api.methods.MethodsClient.chatPostMessage — the impl holds a
    #   SlackHttpClient and POSTs to slack.com). Discord JDA (net.dv8tion.jda.api.requests.RestAction.queue
    #   /complete — the REST terminal; queue() enqueues the wire call, complete() blocks on it). Telegram
    #   (org.telegram.telegrambots.meta.bots.AbsSender.execute(BotApiMethod) — the synchronous Bot-API send;
    #   the meta jar carries AbsSender, no heavy longpolling client needed).
    # Identity -> Net: Keycloak admin (org.keycloak.admin.client.resource.UsersResource.create / .search —
    #   JAX-RS proxy methods that round-trip to the Keycloak admin REST API). Okta (com.okta.sdk.resource
    #   .client.ApiClient.invokeAPI — the generic Swagger-generated wire leaf every Okta call bottoms out in).
    # Payments -> Net: Braintree (com.braintreegateway.TransactionGateway.sale — the gateway holds a
    #   com.braintreegateway.util.Http and POSTs to the Braintree API; reached via gateway.transaction().sale()).
    # Comms/email -> Net: Mailgun (net.sargue.mailgun.Mail.send — calls jakarta.ws.rs Invocation$Builder.post
    #   to the Mailgun messages endpoint).
    # Maps/geo -> Net: Google Maps services (com.google.maps.PendingResult.await — the fluent terminal of
    #   `GeocodingApi.geocode(ctx, q).await()`; await() blocks on the OkHttp request to the Maps API. The
    #   call-site owner of await() is com.google.maps.PendingResult — the per-API *Request types implement it).
    # DB -> Net/Db: ClickHouse native client (com.clickhouse.client.ClickHouseClient.execute(ClickHouseRequest)
    #   — async, returns CompletableFuture, Net|Db|Unknown PASS; and the STATIC ClickHouseClient.send(node,sql)
    #   one-shot). NB JDBC (com.clickhouse.jdbc) is already covered via java.sql, so only the NATIVE client tested.
    # PURE anchors: Braintree gateway construction (new BraintreeGateway(env,m,k,s) — holds the Http but does no
    #   wire); Spring AI prompt builder (cc.prompt().user(..) — the fluent builder before .call(), no wire).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2..11.
    # ====================== ADDED LIBRARIES (2026-06-20 batch 13) ======================
    # SPRING-ECOSYSTEM FLOOR-SUPPRESSION SWEEP + a few datastores. PURPOSE: map the blast radius of the
    # org.springframework.* κ-FLOOR. candor treats org.springframework.* as a κ-COVERED prefix, so for a
    # Spring SUB-LIBRARY candor does NOT model, the effectful leaf is DROPPED FROM THE REPORT ENTIRELY —
    # not even disclosed as `invisible`/Unknown — which is strictly WORSE than a normal silent-pure. (A
    # normal unmodeled NON-Spring package surfaces a per-function `invisible: [pkg]` disclosure; a Spring
    # one is silently absent.) This already bit Spring Vault (VaultTemplate, batch 9) and Spring AI
    # (ChatClient/ChatModel, batch 12); this batch hunts the rest. The runner now prints a FLOOR? column:
    #   FLOOR   = function ABSENT from the report (silently dropped) AND the owner is org.springframework.*
    #             (a real effect made invisible — the structural finding).
    #   INVIS   = function PRESENT with a per-fn `invisible:[pkg]` disclosure (the NON-Spring κ-unknown-
    #             package soft gap — disclosed, not silent; candor is honest it can't see the package).
    #   pure    = function ABSENT and NOT a Spring owner (genuinely pure / accepted in-memory).
    # Spring sub-libs ADDED (each tested DIRECTLY at the real terminal an app calls):
    #   Spring Integration core MessagingTemplate.send/convertAndSend -> Net/Unknown (routes to a channel,
    #     often remote). MessageChannel.send tested too — a channel can be in-memory (DirectChannel) so it
    #     is the ambiguous-receiver case, but it is ALSO floor-dropped here (org.springframework.messaging).
    #   Spring Batch JobLauncher.run -> Db (writes the JobRepository).
    #   Spring Cloud OpenFeign FeignBlockingLoadBalancerClient.execute -> Net. NB the underlying effect is
    #     feign.Client.execute (already modeled) but the call-site owner is the org.springframework.cloud
    #     wrapper class, so the FLOOR drops it — a clean demonstration the floor hides even a wrapper whose
    #     delegate IS modeled.
    #   Spring Data Elasticsearch ElasticsearchOperations.save/search -> Net.
    #   Spring Data Neo4j Neo4jTemplate.save/findById -> Db (Cypher over bolt).
    #   Spring LDAP LdapTemplate.lookup/search/bind -> Net (LDAP over the wire).
    #   Spring Session SessionRepository.save/findById -> Db/Net (backend-dependent; ambiguous like a cache,
    #     a JDBC/Redis backend is Db/Net but a MapSessionRepository is in-memory). Tested+documented; the
    #     floor drops it regardless of backend. MapSessionRepository.save = the in-memory anchor (also dropped).
    #   Spring Data Redis RedisTemplate.execute(RedisCallback) -> Db expected; VERIFY it is NOT floored (it
    #     is the only Spring case here that is already correctly modeled — see RESULTS, a WIN).
    #   (Spring RestTemplate/RestClient/WebClient, JdbcTemplate, KafkaTemplate, Spring AI: already in earlier
    #     batches as correctly-modeled EFFECT_CASES — they prove the floor is NOT blanket; what's modeled shows.)
    # NON-Spring datastores ADDED (breadth; these surface the `invisible`-package disclosure, NOT the floor):
    #   OrientDB ODatabaseSession.query/command -> Db; ArangoDB ArangoDatabase.query/getVersion -> Net (the
    #     com.arangodb:CORE artifact, NOT the 19-entry shaded aggregator stub which is still skipped);
    #     RethinkDB ReqlExpr.run / connection().connect() -> Net; H2 native MVStore.open/openMap -> Fs
    #     (on-disk MVStore file; openMap on an already-open store is the in-memory map view — anchor).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2..12.
    # ====================== ADDED LIBRARIES (2026-06-20 batch 14) ======================
    # HTTP SERVER frameworks, streaming, datastores/caches, document/media, templating, email, ML/native.
    # FOCUS this batch = NON-Spring libraries (0.7.8's STRUCTURAL Spring-floor fix already auto-discloses
    #   Unknown for any org.springframework.* *Template/*Operations/*Repository/*Gateway type).
    # HTTP SERVER frameworks -> Net (the server .start()/.init() BINDS a listening socket = the clearest leaf):
    #   Javalin (io.javalin.Javalin.start(int) -> Net binds the port). Spark Java (spark.Spark.init() -> Net
    #     binds; NB Spark.get(path,Route) is a LAZY route REGISTRATION that delegates to Service.get and does
    #     NOT bind until init() — so init() is the clean Net leaf, get() is pure route setup). Undertow
    #     (io.undertow.Undertow.start() -> Net). Eclipse Jetty SERVER (org.eclipse.jetty.server.Server.start()
    #     -> Net; start() is declared on the LifeCycle interface but the invokevirtual call-site owner with a
    #     Server-typed receiver is org.eclipse.jetty.server.Server). Javalin Context.result(String) is BUFFERED
    #     (wraps the body into a ByteArrayInputStream, verified by javap -c — no synchronous socket write) ->
    #     PURE anchor. Ratpack SKIPPED (heavy netty/guice/reactor tree; the server vein is covered by 4 others).
    # Streaming -> Net: Kafka Streams (org.apache.kafka.streams.KafkaStreams.start() -> binds/consumes over the
    #   broker socket).
    # Datastores/caches -> Net: Apache Geode (org.apache.geode.cache.Region.get/put -> hits a remote partition
    #   over the wire). CRITICAL nuance (same as batch 7 Hazelcast/Infinispan): Region<K,V> EXTENDS
    #   java.util.concurrent.ConcurrentMap, so get/put are inherited Map verbs — but the invoke call-site owner
    #   with a Region-typed receiver is org.apache.geode.cache.Region, NOT java.util.Map, so an owner-scoped κ
    #   rule keyed on Region is fabrication-safe; the batch-7 java.util.Map pure anchors still guard the JDK Map.
    #   ScyllaDB uses the Cassandra driver (already covered — NOTED, not re-added). Couchbase already done.
    # Document/media -> Fs/Exec: docx4j (org.docx4j.openpackaging.packages.WordprocessingMLPackage.load(File)
    #   /save(File) -> Fs, descriptor-gated; load(InputStream)/save(OutputStream) are caller-stream PURE anchors).
    #   ffmpeg wrapper net.bramp.ffmpeg.FFmpeg.run(FFmpegBuilder) -> Exec (forks the ffmpeg binary). ZXing
    #   MultiFormatWriter.encode / MultiFormatReader.decode -> PURE (in-memory barcode image math). Apache FOP
    #   SKIPPED: its only testable leaf is FopFactory.newFop(mime, OutputStream) = a CALLER-STREAM pure anchor
    #   (redundant with the many existing caller-stream anchors) AND it needs xmlgraphics-commons; noted.
    # Templating -> Fs (loads a template FILE via the loader) / pure (in-memory string template):
    #   Handlebars (com.github.jknack.handlebars.Handlebars.compile(String) -> Fs (loads via the TemplateLoader);
    #     .compileInline(String) is in-memory -> PURE anchor). mustache.java
    #     (com.github.mustachejava.DefaultMustacheFactory.compile(String) -> Fs (loads the named template file);
    #     compile(Reader,name) is caller-stream -> PURE anchor). Pebble
    #     (io.pebbletemplates.pebble.PebbleEngine.getTemplate(String) -> Fs; getLiteralTemplate(String) is
    #     in-memory -> PURE anchor). JMustache (com.samskivert.mustache.Mustache$Compiler.compile(String) takes
    #     a template TEXT string, NOT a filename -> PURE anchor — JMustache has no file-loading leaf).
    # Email -> Net: SimpleJavaMail (org.simplejavamail.api.mailer.Mailer.sendMail(Email) -> opens an SMTP
    #   transport; returns CompletableFuture (async) so Net|Unknown both PASS. The api.* types live in the
    #   simplejavamail CORE-MODULE jar, not the impl jar.).
    # ML/native -> Fs/Exec: ONNX Runtime (ai.onnxruntime.OrtEnvironment.createSession(String) -> Fs (loads the
    #   model file off disk; createSession(byte[]) is in-memory -> PURE anchor); ai.onnxruntime.OrtSession.run
    #   (Map) -> native inference, Exec|Unknown acceptable). Stanford CoreNLP (new
    #   edu.stanford.nlp.pipeline.StanfordCoreNLP(String) -> Fs (loads serialized models off disk/classpath)).
    #   DJL SKIPPED (heavy native engine tree).
    # All FULLY-QUALIFIED in the bodies (no wildcard imports) — same clash discipline as batches 2..13.
    # ====================== ADDED LIBRARIES (2026-06-20 batch 15) ======================
    # GOAL: confirm whether any SILENT-PURE / FLOOR cardinal sins remain, vs only disclosed (invisible/Unknown)
    #   precision gaps. Batch 14 found 0 silent-pure (all invisible-disclosed). KEY INSIGHT for where the real
    #   cardinal sins still hide: candor's `invisible:[pkg]` disclosure fires PER-PACKAGE at the call site even
    #   when OTHER members of the same 3rd-party owner ARE modeled — VERIFIED here: okhttp3.Cache.evictAll (a
    #   sibling of the modeled okhttp3.Call.execute) reports invisible:[okhttp3], NOT silent-pure; Hibernate
    #   StatelessSession.get/insert report invisible:[org.hibernate]; Mongo GridFSBucket.downloadToStream reports
    #   invisible:[com.mongodb.client.gridfs]. So "partially-modeled 3rd-party package" does NOT yield silent-pure
    #   — candor falls back to the honest package-level disclosure. The ONLY place an unmodeled effectful member
    #   reads SILENT (no effect, no invisible, no unknownWhy) is a κ-COVERED JDK prefix (java.*/javax.*/jakarta.*):
    #   there candor suppresses the invisible disclosure (it "knows" the JDK), so an unmodeled member is
    #   FLOOR-DROPPED from the report ENTIRELY — the worst kind. This batch therefore targets PARTIALLY-MODELED
    #   JDK TYPES (candor models SOME verbs of the owner, so the type is not "unknown", and the unmodeled verbs
    #   fall through silently). NO new jars — every leaf is a JDK type already on the boot classpath.
    # java.util.prefs.Preferences is PARTIALLY MODELED -> Fs: put/get/flush/sync/remove/putInt are classified Fs,
    #   but removeNode()/clear()/exportNode(OutputStream)/exportSubtree(OutputStream) and the static
    #   importPreferences(InputStream) are FLOOR-DROPPED silent — yet they ALL hit the same backing store
    #   (disk/registry). removeNode/clear DELETE persisted data; exportNode/exportSubtree READ the store to emit
    #   XML; importPreferences WRITES the store. These are genuine Fs the floor hides -> SILENT-PURE cardinal sins.
    # javax.sql.rowset.RowSet.execute() / execute(Connection) connects to the data source and runs the command
    #   = a DB round-trip -> Db. candor models javax.sql.DataSource (Db) but NOT the javax.sql.rowset.* RowSet
    #   types, and javax.* is κ-covered so the leaf is FLOOR-DROPPED silent -> a SILENT-PURE Db cardinal sin.
    # PURE/DISCLOSED CONTROLS proving the distinction (not gaps): okhttpCacheEvict/hibernateStatelessGet/
    #   gridfsDownload surface invisible:[pkg] (sound, low-value); java.sql DatabaseMetaData.getTables/getColumns,
    #   CallableStatement.execute, Connection.commit/rollback, RowSet's sibling java.sql verbs, java.util.zip
    #   ZipFile(File), java.util.jar JarFile(File), javax.imageio ImageIO.read(File/URL), java.util.Scanner(File),
    #   java.util.logging FileHandler(String), java.net.Socket.connect, java.rmi Naming.lookup, java.net.http
    #   HttpClient.send/sendAsync are all ALREADY MODELED (verified during the batch — they classify correctly).
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

    # ====================== ADDED LIBRARIES (2026-06-20 batch 7) ======================
    # ---- Net (Distributed caches/grids — get/put hit a remote partition over the wire). The receiver is the
    #      CACHE interface, so the call-site owner is IMap / IgniteCache / BasicCache (NOT java.util.Map even
    #      though Hazelcast/Infinispan inherit Map). java.util.Map-typed PURE anchors below prove no flooding.) ----
    ("hazelcastGet", "Net", "com.hazelcast.map.IMap<String,String> m", 'String v = m.get("k")'),
    ("hazelcastPut", "Net", "com.hazelcast.map.IMap<String,String> m", 'String v = m.put("k","v")'),
    ("igniteGet", "Net", "org.apache.ignite.IgniteCache<String,String> c", 'String v = c.get("k")'),
    ("ignitePut", "Net", "org.apache.ignite.IgniteCache<String,String> c", 'c.put("k","v")'),
    ("infinispanGet", "Net", "org.infinispan.commons.api.BasicCache<String,String> c", 'String v = c.get("k")'),
    ("infinispanPut", "Net", "org.infinispan.commons.api.BasicCache<String,String> c", 'String v = c.put("k","v")'),

    # ---- Db (JDBI — Jdbi.withHandle opens a connection callback; Handle.execute/createQuery run SQL) ----
    ("jdbiWithHandle", "Db", "org.jdbi.v3.core.Jdbi j",
        'Object o = j.withHandle(h -> h.execute("delete from t"))'),
    ("jdbiExecute", "Db", "org.jdbi.v3.core.Handle h", 'int n = h.execute("delete from t")'),
    ("jdbiCreateQuery", "Db", "org.jdbi.v3.core.Handle h",
        'org.jdbi.v3.core.statement.Query q = h.createQuery("select 1")'),

    # ---- Db (Spring Data Cassandra — CassandraTemplate.select/insert run CQL against the cluster) ----
    ("cassandraTemplateSelect", "Db", "org.springframework.data.cassandra.core.CassandraTemplate t",
        'java.util.List<?> r = t.select("select 1", String.class)'),
    ("cassandraTemplateInsert", "Db", "org.springframework.data.cassandra.core.CassandraTemplate t, Object o",
        'Object r = t.insert(o)'),

    # ---- Db (Spring Data Couchbase — CouchbaseTemplate.save persists to the cluster) ----
    ("couchbaseTemplateSave", "Db", "org.springframework.data.couchbase.core.CouchbaseTemplate t, Object o",
        'Object r = t.save(o)'),

    # ---- Net (Stripe — Charge.create/retrieve are STATIC leaves that delegate to the ApiResource HTTP
    #      machinery. The user calls the SDK's own method whose owner is com.stripe.model.Charge — silent
    #      unless candor models the Stripe SDK leaf, even though OkHttp/HttpClient run under the hood.) ----
    ("stripeChargeCreate", "Net", "java.util.Map<String,Object> p",
        'com.stripe.model.Charge c = com.stripe.model.Charge.create(p)'),
    ("stripeChargeRetrieve", "Net", "",
        'com.stripe.model.Charge c = com.stripe.model.Charge.retrieve("ch_1")'),

    # ---- Net (Twilio — MessageCreator.create() is the no-arg terminal; it uses the default TwilioRestClient
    #      and performs the HTTP round-trip. Owner is the Twilio creator type.) ----
    ("twilioMessageCreate", "Net", "com.twilio.rest.api.v2010.account.MessageCreator mc",
        'com.twilio.rest.api.v2010.account.Message m = mc.create()'),

    # ---- Net (SendGrid — SendGrid.api(Request) sends the email over HTTP; api() is declared on BaseInterface
    #      but the call-site owner is the SendGrid static type.) ----
    ("sendgridApi", "Net", "com.sendgrid.SendGrid sg, com.sendgrid.Request req",
        'com.sendgrid.Response r = sg.api(req)'),

    # ---- Net (reactor-netty HttpClient — get().responseContent()/.response() dispatch the HTTP request.
    #      REACTIVE/lazy: the leaf owner is HttpClient$ResponseReceiver (the get() return type), not
    #      HttpClient. Net or Unknown both PASS (deferred-subscribe boundary).) ----
    ("reactorNettyResponseContent", "Net", "reactor.netty.http.client.HttpClient hc",
        'reactor.netty.ByteBufFlux f = hc.get().responseContent()'),
    ("reactorNettyResponse", "Net", "reactor.netty.http.client.HttpClient hc",
        'reactor.core.publisher.Mono<reactor.netty.http.client.HttpClientResponse> m = hc.get().response()'),

    # ---- Net (Apache Commons Email — Email.send() opens an SMTP transport and sends the message) ----
    ("commonsEmailSend", "Net", "org.apache.commons.mail.Email e", 'String id = e.send()'),

    # ---- Scheduling (Quartz — Scheduler.scheduleJob is pure/Unknown unless a JDBCJobStore is configured;
    #      the API call alone cannot reveal the store, so silent-pure is an ACCEPTED, documented outcome,
    #      not a hard GAP. Listed with expect=Unknown so a disclosed-Unknown passes; a pure result is noted.) ----

    # ====================== ADDED LIBRARIES (2026-06-20 batch 8) ======================
    # ---- Net (Sentry — captureException/captureMessage are STATIC leaves that delegate to the hub/transport;
    #      the wire send is queued/async, so Net or Unknown both PASS. Owner is io.sentry.Sentry.) ----
    ("sentryCaptureException", "Net", "Throwable t",
        'io.sentry.protocol.SentryId id = io.sentry.Sentry.captureException(t)'),
    ("sentryCaptureMessage", "Net", "",
        'io.sentry.protocol.SentryId id = io.sentry.Sentry.captureMessage("x")'),

    # ---- Net (OpenTelemetry — SpanExporter.export(Collection<SpanData>) is the actual span batch flush over
    #      the wire (OTLP/HTTP). The owner is the SpanExporter interface. Net or Unknown both PASS. NB: the
    #      user-facing Span.end() is deferred to the BatchSpanProcessor (no synchronous wire) — a silent-pure
    #      THERE is accepted/documented, NOT tested as a hard leaf.) ----
    ("otelSpanExport", "Net",
        "io.opentelemetry.sdk.trace.export.SpanExporter ex, java.util.Collection<io.opentelemetry.sdk.trace.data.SpanData> spans",
        'io.opentelemetry.sdk.common.CompletableResultCode r = ex.export(spans)'),
    # Span.end() — documented deferred boundary: tested honestly (Net|Unknown PASS, pure is the documented
    #   accepted outcome since the export is async on the BatchSpanProcessor, not at end()).

    # ---- Exec (im4java — ImageCommand.run(Operation, Object...) forks ImageMagick's `convert` process.
    #      Owner is org.im4java.core.ConvertCmd (the receiver's static type); Exec or Unknown both PASS.) ----
    ("im4javaConvertRun", "Exec",
        "org.im4java.core.ConvertCmd cmd, org.im4java.core.IMOperation op",
        'cmd.run(op)'),

    # ---- Exec (Tess4J — Tesseract.doOCR(File) calls into libtesseract via JNA (native code reading the
    #      image file). The effect is real native execution + file read; Exec|Fs|Unknown all PASS, must not
    #      read silent-pure.) ----
    ("tess4jDoOcrFile", "Fs", "net.sourceforge.tess4j.Tesseract t, File f", 'String s = t.doOCR(f)'),

    # ---- Net (Google HTTP client — HttpRequest.execute() performs the HTTP round-trip) ----
    ("googleHttpExecute", "Net", "com.google.api.client.http.HttpRequest req",
        'com.google.api.client.http.HttpResponse r = req.execute()'),

    # ---- Net (Eclipse Jetty client — HttpClient.GET(String) blocks on the GET; Request.send() blocks on the
    #      exchange) ----
    ("jettyHttpGet", "Net", "org.eclipse.jetty.client.HttpClient c",
        'org.eclipse.jetty.client.ContentResponse r = c.GET("http://h/")'),
    ("jettyRequestSend", "Net", "org.eclipse.jetty.client.Request req",
        'org.eclipse.jetty.client.ContentResponse r = req.send()'),

    # ---- Net (Unirest — GetRequest.asString()/asJson() execute the HTTP request and block for the body) ----
    ("unirestAsString", "Net", "kong.unirest.GetRequest g",
        'kong.unirest.HttpResponse<String> r = g.asString()'),
    ("unirestAsJson", "Net", "kong.unirest.GetRequest g",
        'kong.unirest.HttpResponse<kong.unirest.JsonNode> r = g.asJson()'),

    # ---- Net (NATS — Connection.publish writes to the NATS server socket; request() does a req/reply RTT) ----
    ("natsPublish", "Net", "io.nats.client.Connection c", 'c.publish("subj", new byte[1])'),
    ("natsRequest", "Net", "io.nats.client.Connection c",
        'java.util.concurrent.CompletableFuture<io.nats.client.Message> f = c.request("subj", new byte[1])'),

    # ---- Net (ActiveMQ Artemis — ClientProducer.send writes the message to the broker over the core socket) ----
    ("artemisProducerSend", "Net",
        "org.apache.activemq.artemis.api.core.client.ClientProducer p, org.apache.activemq.artemis.api.core.Message m",
        'p.send(m)'),

    # ---- Rand (Google Tink — KeysetHandle.generateNew draws entropy from SecureRandom to mint key material.
    #      Owner is the static com.google.crypto.tink.KeysetHandle; Rand or Unknown both PASS.) ----
    ("tinkGenerateNew", "Rand", "",
        'com.google.crypto.tink.KeysetHandle h = com.google.crypto.tink.KeysetHandle.generateNew('
        'com.google.crypto.tink.aead.AeadKeyTemplates.AES128_GCM)'),

    # ---- Rand (Jasypt — StandardPBEStringEncryptor.encrypt draws a random salt in the default random-salt
    #      mode. The call site can't reveal a fixed-salt config, so Rand|Unknown PASS; a pure result (compute
    #      only) is the documented accepted outcome.) ----
    ("jasyptEncrypt", "Rand", "org.jasypt.encryption.pbe.StandardPBEStringEncryptor enc",
        'String s = enc.encrypt("secret")'),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 9) ======================
    # ---- Net (GCP BigQuery — query/insertAll hit the BigQuery REST API. Owner com.google.cloud.bigquery
    #      .BigQuery. NB: GCP does NOT share a wire-namespace like AWS; each service is its own class.) ----
    ("gcpBigQueryQuery", "Net", "com.google.cloud.bigquery.BigQuery b",
        'com.google.cloud.bigquery.TableResult r = b.query(null)'),
    ("gcpBigQueryInsertAll", "Net", "com.google.cloud.bigquery.BigQuery b",
        'com.google.cloud.bigquery.InsertAllResponse r = b.insertAll(null)'),

    # ---- Net (GCP Firestore — CollectionReference.get() / DocumentReference.get() run a query over the wire.
    #      get() is inherited from Query but the call-site owner is the concrete reference type. Returns
    #      ApiFuture (async) -> Net|Unknown PASS.) ----
    ("gcpFirestoreCollGet", "Net", "com.google.cloud.firestore.CollectionReference c",
        'com.google.api.core.ApiFuture<com.google.cloud.firestore.QuerySnapshot> r = c.get()'),
    ("gcpFirestoreDocGet", "Net", "com.google.cloud.firestore.DocumentReference d",
        'com.google.api.core.ApiFuture<com.google.cloud.firestore.DocumentSnapshot> r = d.get()'),

    # ---- Net (GCP Pub/Sub — Publisher.publish queues+sends to the topic. Owner com.google.cloud.pubsub.v1
    #      .Publisher; returns ApiFuture -> Net|Unknown PASS.) ----
    ("gcpPubsubPublish", "Net", "com.google.cloud.pubsub.v1.Publisher p",
        'com.google.api.core.ApiFuture<String> r = p.publish(com.google.pubsub.v1.PubsubMessage.getDefaultInstance())'),

    # ---- Net (Kubernetes fabric8 — client.pods().list() lists pods via the API server. The call-site owner of
    #      the .list() terminal is io.fabric8.kubernetes.client.dsl.MixedOperation (extends Listable). The
    #      pods() accessor is a pure DSL view; the list()/create() terminal verbs are the wire leaves.) ----
    ("k8sPodsList", "Net", "io.fabric8.kubernetes.client.KubernetesClient c",
        'io.fabric8.kubernetes.api.model.PodList l = c.pods().list()'),

    # ---- Net/Exec (Docker docker-java — *Cmd.exec() hits the Docker daemon over its socket/HTTP. The call-site
    #      owner of exec() is the per-command type (PingCmd/InfoCmd), all extending SyncDockerCmd.exec. The
    #      pingCmd()/infoCmd() accessors are pure builders. Net|Exec|Unknown all PASS.) ----
    ("dockerPingExec", "Net", "com.github.dockerjava.api.DockerClient c", 'c.pingCmd().exec()'),
    ("dockerInfoExec", "Net", "com.github.dockerjava.api.DockerClient c",
        'com.github.dockerjava.api.model.Info i = c.infoCmd().exec()'),

    # ---- Net (Spring Vault — VaultTemplate.read/write hit the Vault HTTP API. Owner org.springframework.vault
    #      .core.VaultTemplate. NB: candor currently DROPS these functions from the report entirely (no entry),
    #      not just classifies them pure — recorded as a GAP, see report.) ----
    ("springVaultRead", "Net", "org.springframework.vault.core.VaultTemplate t",
        'org.springframework.vault.support.VaultResponse r = t.read("secret/x")'),
    ("springVaultWrite", "Net", "org.springframework.vault.core.VaultTemplate t",
        'org.springframework.vault.support.VaultResponse r = t.write("secret/x", "v")'),

    # ---- Net (vault-java-driver jopenlibs fork — Logical.read/write hit the Vault HTTP API. Owner
    #      io.github.jopenlibs.vault.api.Logical; Vault.logical() is a pure accessor.) ----
    ("vaultDriverRead", "Net", "io.github.jopenlibs.vault.Vault v",
        'io.github.jopenlibs.vault.response.LogicalResponse r = v.logical().read("secret/x")'),

    # ---- Net (Redisson — RBucket.get/set do KV round-trips to Redis over TCP. Owner org.redisson.api.RBucket;
    #      RedissonClient.getBucket is a pure factory -> anchor below.) ----
    ("redissonBucketGet", "Net", "org.redisson.api.RBucket<String> b", 'String v = b.get()'),
    ("redissonBucketSet", "Net", "org.redisson.api.RBucket<String> b", 'b.set("v")'),

    # ---- Net (etcd jetcd — KV.get/put hit the etcd cluster over gRPC. Owner io.etcd.jetcd.KV; returns
    #      CompletableFuture (async) -> Net|Unknown PASS.) ----
    ("jetcdKvGet", "Net", "io.etcd.jetcd.KV kv, io.etcd.jetcd.ByteSequence k",
        'java.util.concurrent.CompletableFuture<io.etcd.jetcd.kv.GetResponse> r = kv.get(k)'),
    ("jetcdKvPut", "Net", "io.etcd.jetcd.KV kv, io.etcd.jetcd.ByteSequence k",
        'java.util.concurrent.CompletableFuture<io.etcd.jetcd.kv.PutResponse> r = kv.put(k, k)'),

    # ---- Net (Consul orbitz — KeyValueClient.getValue/putValue hit the Consul HTTP API. Owner com.orbitz
    #      .consul.KeyValueClient.) ----
    ("consulGetValue", "Net", "com.orbitz.consul.KeyValueClient c",
        'java.util.Optional<com.orbitz.consul.model.kv.Value> r = c.getValue("k")'),
    ("consulPutValue", "Net", "com.orbitz.consul.KeyValueClient c", 'boolean ok = c.putValue("k", "v")'),

    # ---- Net (UnboundID LDAP — LDAPConnection.search/bind/connect issue LDAP ops over the socket. Owner
    #      com.unboundid.ldap.sdk.LDAPConnection.) ----
    ("ldapSearch", "Net", "com.unboundid.ldap.sdk.LDAPConnection c, com.unboundid.ldap.sdk.SearchRequest req",
        'com.unboundid.ldap.sdk.SearchResult r = c.search(req)'),
    ("ldapBind", "Net", "com.unboundid.ldap.sdk.LDAPConnection c",
        'com.unboundid.ldap.sdk.BindResult r = c.bind("uid=x", "pw")'),
    ("ldapConnect", "Net", "com.unboundid.ldap.sdk.LDAPConnection c", 'c.connect("host", 389)'),

    # ---- Fs (Chronicle Queue — singleBuilder(File).build() opens/creates the on-disk memory-mapped queue dir.
    #      The call-site owner of build() is SingleChronicleQueueBuilder, NOT ChronicleQueue.) ----
    ("chronicleQueueBuild", "Fs", "File f",
        'net.openhft.chronicle.queue.ChronicleQueue q = net.openhft.chronicle.queue.ChronicleQueue.singleBuilder(f).build()'),

    # ---- Net (Sardine WebDAV — get/put move bytes to/from the WebDAV server over HTTP. Owner com.github
    #      .sardine.Sardine.) ----
    ("sardineGet", "Net", "com.github.sardine.Sardine s", 'InputStream in = s.get("http://h/f")'),
    ("sardinePut", "Net", "com.github.sardine.Sardine s", 's.put("http://h/f", new byte[1])'),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 10) ======================
    # ---- Net (ZooKeeper — getData/create/setData/exists are synchronous round-trips to the ensemble over TCP.
    #      Owner org.apache.zookeeper.ZooKeeper.) ----
    ("zkGetData", "Net", "org.apache.zookeeper.ZooKeeper z", 'byte[] b = z.getData("/p", false, null)'),
    ("zkCreate", "Net", "org.apache.zookeeper.ZooKeeper z",
        'String r = z.create("/p", new byte[1], java.util.Collections.<org.apache.zookeeper.data.ACL>emptyList(), org.apache.zookeeper.CreateMode.PERSISTENT)'),
    ("zkSetData", "Net", "org.apache.zookeeper.ZooKeeper z",
        'org.apache.zookeeper.data.Stat s = z.setData("/p", new byte[1], -1)'),
    ("zkExists", "Net", "org.apache.zookeeper.ZooKeeper z",
        'org.apache.zookeeper.data.Stat s = z.exists("/p", false)'),

    # ---- Net (Curator — the FLUENT terminal is forPath; with a CreateBuilder/GetDataBuilder-typed receiver the
    #      call-site owner of forPath is org.apache.curator.framework.api.CreateBuilder / GetDataBuilder.
    #      create()/getData() are pure accessor anchors below.) ----
    ("curatorCreateForPath", "Net", "org.apache.curator.framework.CuratorFramework cf",
        'String r = cf.create().forPath("/p", new byte[1])'),
    ("curatorGetDataForPath", "Net", "org.apache.curator.framework.CuratorFramework cf",
        'byte[] b = cf.getData().forPath("/p")'),

    # NB Eureka getApplications()/getNextServerFromEureka, LaunchDarkly boolVariation, Unleash isEnabled, and
    #   Temporal newServiceStubs were tested and found to be LOCAL-cache / factory leaves (no synchronous wire) —
    #   they are ACCEPTED-PURE anchors in PURE_CASES below, NOT hard gaps (see the batch-10 report). Verified by
    #   javap: DiscoveryClient.getApplications reads the localRegionApps AtomicReference; LDClient.boolVariation
    #   calls EvaluatorInterface.evalAndFlag (in-memory flag store); Unleash.isEnabled reads a local
    #   IFeatureRepository; WorkflowServiceStubs.newServiceStubs is a lazy gRPC channel FACTORY.

    # ---- Net (Solr — query/add/commit are HTTP round-trips to the Solr server. Owner is the base SolrClient,
    #      the static receiver type of the concrete subclass.) ----
    ("solrQuery", "Net", "org.apache.solr.client.solrj.SolrClient c, org.apache.solr.common.params.SolrParams p",
        'org.apache.solr.client.solrj.response.QueryResponse r = c.query(p)'),
    ("solrAdd", "Net", "org.apache.solr.client.solrj.SolrClient c, org.apache.solr.common.SolrInputDocument d",
        'org.apache.solr.client.solrj.response.UpdateResponse r = c.add(d)'),
    ("solrCommit", "Net", "org.apache.solr.client.solrj.SolrClient c",
        'org.apache.solr.client.solrj.response.UpdateResponse r = c.commit()'),

    # ---- Net/Db (GCP Spanner — the wire leaf is ReadContext.executeQuery(Statement). DatabaseClient.singleUse()
    #      is a pure accessor anchor below. Db|Net|Unknown all PASS.) ----
    ("spannerExecuteQuery", "Db", "com.google.cloud.spanner.ReadContext rc",
        'com.google.cloud.spanner.ResultSet r = rc.executeQuery(com.google.cloud.spanner.Statement.of("select 1"))'),

    # ---- Net (Azure CosmosDB — readItem/createItem are HTTP to the Cosmos endpoint. Owner CosmosContainer.) ----
    ("cosmosReadItem", "Net", "com.azure.cosmos.CosmosContainer c, com.azure.cosmos.models.PartitionKey pk",
        'com.azure.cosmos.models.CosmosItemResponse<String> r = c.readItem("id", pk, String.class)'),
    ("cosmosCreateItem", "Net", "com.azure.cosmos.CosmosContainer c",
        'com.azure.cosmos.models.CosmosItemResponse<String> r = c.createItem("doc")'),

    # ---- Net (Azure Service Bus — ServiceBusSenderClient.sendMessage sends over AMQP.) ----
    ("serviceBusSend", "Net",
        "com.azure.messaging.servicebus.ServiceBusSenderClient s, com.azure.messaging.servicebus.ServiceBusMessage m",
        's.sendMessage(m)'),

    # ---- Net (Azure Key Vault — SecretClient.getSecret/setSecret over HTTPS.) ----
    ("keyVaultGetSecret", "Net", "com.azure.security.keyvault.secrets.SecretClient c",
        'com.azure.security.keyvault.secrets.models.KeyVaultSecret s = c.getSecret("name")'),
    ("keyVaultSetSecret", "Net", "com.azure.security.keyvault.secrets.SecretClient c",
        'com.azure.security.keyvault.secrets.models.KeyVaultSecret s = c.setSecret("name", "val")'),

    # ---- Net (GCP Secret Manager — accessSecretVersion(String) is a gRPC/HTTP round-trip. Owner
    #      com.google.cloud.secretmanager.v1.SecretManagerServiceClient.) ----
    ("gcpSecretAccess", "Net", "com.google.cloud.secretmanager.v1.SecretManagerServiceClient c",
        'com.google.cloud.secretmanager.v1.AccessSecretVersionResponse r = c.accessSecretVersion("projects/p/secrets/s/versions/1")'),

    # ---- Net (RSocket — requestResponse/fireAndForget are REACTIVE (return a Mono; wire deferred to subscribe).
    #      Net OR Unknown both PASS.) ----
    ("rsocketRequestResponse", "Net", "io.rsocket.RSocket s, io.rsocket.Payload p",
        'reactor.core.publisher.Mono<io.rsocket.Payload> m = s.requestResponse(p)'),
    ("rsocketFireAndForget", "Net", "io.rsocket.RSocket s, io.rsocket.Payload p",
        'reactor.core.publisher.Mono<Void> m = s.fireAndForget(p)'),

    # (Feature flags LaunchDarkly/Unleash -> accepted-pure anchors in PURE_CASES; see note above.)

    # ---- Net (Micronaut — BlockingHttpClient.exchange(String) is the blocking HTTP round-trip.) ----
    ("micronautExchange", "Net", "io.micronaut.http.client.BlockingHttpClient c",
        'io.micronaut.http.HttpResponse<String> r = c.exchange("http://h/", String.class)'),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 11) ======================
    # ---- Net (theokanning OpenAI — OpenAiService.createChatCompletion does the HTTP round-trip to the OpenAI
    #      API. The owner is com.theokanning.openai.service.OpenAiService; OkHttp/Retrofit run under the hood.) ----
    ("openaiChatCompletion", "Net",
        "com.theokanning.openai.service.OpenAiService s, com.theokanning.openai.completion.chat.ChatCompletionRequest r",
        'com.theokanning.openai.completion.chat.ChatCompletionResult x = s.createChatCompletion(r)'),
    ("openaiCompletion", "Net",
        "com.theokanning.openai.service.OpenAiService s, com.theokanning.openai.completion.CompletionRequest r",
        'com.theokanning.openai.completion.CompletionResult x = s.createCompletion(r)'),

    # ---- Net (LangChain4j — ChatLanguageModel.generate(List) is the abstract wire method; OpenAiChatModel
    #      .generate is the concrete impl. generate(String) is a default delegating to the List overload, so
    #      the List overload is the canonical leaf candor must model. Owner = the model type.) ----
    ("lc4jChatGenerate", "Net",
        "dev.langchain4j.model.chat.ChatLanguageModel m, java.util.List<dev.langchain4j.data.message.ChatMessage> ms",
        'dev.langchain4j.model.output.Response<dev.langchain4j.data.message.AiMessage> r = m.generate(ms)'),
    ("lc4jChatGenerateString", "Net", "dev.langchain4j.model.chat.ChatLanguageModel m",
        'String s = m.generate("hi")'),
    ("lc4jOpenAiGenerate", "Net",
        "dev.langchain4j.model.openai.OpenAiChatModel m, java.util.List<dev.langchain4j.data.message.ChatMessage> ms",
        'dev.langchain4j.model.output.Response<dev.langchain4j.data.message.AiMessage> r = m.generate(ms)'),

    # ---- Net (Anthropic Java SDK — MessageService.create(MessageCreateParams) is the blocking message create
    #      (HTTP to the Anthropic API). Owner com.anthropic.services.blocking.MessageService; the real classes
    #      are in anthropic-java-CORE (the anthropic-java jar is a 305-byte aggregator stub).) ----
    ("anthropicMessageCreate", "Net",
        "com.anthropic.services.blocking.MessageService svc, com.anthropic.models.messages.MessageCreateParams p",
        'com.anthropic.models.messages.Message m = svc.create(p)'),

    # ---- Net (Pinecone — Index.upsert/query are the gRPC data-plane terminals to the Pinecone index. Owner
    #      io.pinecone.clients.Index; the top-level Pinecone client is a control-plane builder.) ----
    ("pineconeUpsert", "Net", "io.pinecone.clients.Index idx",
        'io.pinecone.proto.UpsertResponse r = idx.upsert("id", java.util.Arrays.asList(1.0f))'),
    ("pineconeQuery", "Net", "io.pinecone.clients.Index idx",
        'Object r = idx.query(1, java.util.Arrays.asList(1.0f), null, null, "ns", null, null, false, false)'),

    # ---- Net (Qdrant — QdrantClient.upsertAsync/searchAsync hit the Qdrant server over gRPC. Returns a guava
    #      ListenableFuture (async) -> Net|Unknown PASS. Owner io.qdrant.client.QdrantClient.) ----
    ("qdrantUpsert", "Net", "io.qdrant.client.QdrantClient c, io.qdrant.client.grpc.Points.UpsertPoints p",
        'com.google.common.util.concurrent.ListenableFuture<io.qdrant.client.grpc.Points.UpdateResult> f = c.upsertAsync(p)'),
    ("qdrantSearch", "Net", "io.qdrant.client.QdrantClient c, io.qdrant.client.grpc.Points.SearchPoints p",
        'com.google.common.util.concurrent.ListenableFuture<java.util.List<io.qdrant.client.grpc.Points.ScoredPoint>> f = c.searchAsync(p)'),

    # ---- Net (Milvus — MilvusServiceClient.search/insert do gRPC round-trips to the Milvus cluster. Owner
    #      io.milvus.client.MilvusServiceClient; the result is wrapped in io.milvus.param.R (the call is eager).) ----
    ("milvusSearch", "Net", "io.milvus.client.MilvusServiceClient c, io.milvus.param.dml.SearchParam p",
        'io.milvus.param.R<io.milvus.grpc.SearchResults> r = c.search(p)'),
    ("milvusInsert", "Net", "io.milvus.client.MilvusServiceClient c, io.milvus.param.dml.InsertParam p",
        'io.milvus.param.R<io.milvus.grpc.MutationResult> r = c.insert(p)'),

    # ---- Net (Spymemcached — MemcachedClient.get/set hit the remote memcached node over TCP. Owner
    #      net.spy.memcached.MemcachedClient (NOT a java.util.Map — no inheritance).) ----
    ("spymemGet", "Net", "net.spy.memcached.MemcachedClient c", 'Object o = c.get("k")'),
    ("spymemSet", "Net", "net.spy.memcached.MemcachedClient c",
        'net.spy.memcached.internal.OperationFuture<Boolean> f = c.set("k", 0, "v")'),

    # ---- Net (Xmemcached — XMemcachedClient.get/set hit the remote memcached node over TCP. Owner
    #      net.rubyeye.xmemcached.XMemcachedClient.) ----
    ("xmemGet", "Net", "net.rubyeye.xmemcached.XMemcachedClient c", 'Object o = c.get("k")'),
    ("xmemSet", "Net", "net.rubyeye.xmemcached.XMemcachedClient c", 'boolean b = c.set("k", 0, "v")'),

    # ---- Net (Aerospike — AerospikeClient.get/put hit the remote Aerospike node over TCP. The get/put take a
    #      Policy+Key (NOT a String), so they cannot be confused with java.util.Map verbs. Owner
    #      com.aerospike.client.AerospikeClient.) ----
    ("aerospikeGet", "Net",
        "com.aerospike.client.AerospikeClient c, com.aerospike.client.policy.Policy p, com.aerospike.client.Key k",
        'com.aerospike.client.Record r = c.get(p, k)'),
    ("aerospikePut", "Net",
        "com.aerospike.client.AerospikeClient c, com.aerospike.client.policy.WritePolicy p, com.aerospike.client.Key k, com.aerospike.client.Bin b",
        'c.put(p, k, b)'),

    # ---- Net (Apache TinkerPop Gremlin driver — Client.submit submits a Gremlin query to the remote server
    #      over the wire (eager submit, returns a ResultSet). Owner org.apache.tinkerpop.gremlin.driver.Client.) ----
    ("gremlinSubmit", "Net", "org.apache.tinkerpop.gremlin.driver.Client c",
        'org.apache.tinkerpop.gremlin.driver.ResultSet r = c.submit("g.V()")'),

    # ---- Net (web3j — Request<T,R>.send() is the JSON-RPC round-trip to the Ethereum node; the generic terminal
    #      every web3j call bottoms out in. Owner org.web3j.protocol.core.Request.) ----
    ("web3jRequestSend", "Net",
        "org.web3j.protocol.core.Request<?,? extends org.web3j.protocol.core.Response> req",
        'org.web3j.protocol.core.Response r = req.send()'),

    # ---- Net (Azure Event Hubs — EventHubProducerClient.send does an AMQP send to the hub. Owner
    #      com.azure.messaging.eventhubs.EventHubProducerClient.) ----
    ("azureEventHubSend", "Net",
        "com.azure.messaging.eventhubs.EventHubProducerClient p, com.azure.messaging.eventhubs.EventDataBatch b",
        'p.send(b)'),

    # ---- Net (Azure Table Storage — TableClient.createEntity/getEntity are HTTP round-trips to the Table
    #      endpoint. Owner com.azure.data.tables.TableClient.) ----
    ("azureTableCreate", "Net",
        "com.azure.data.tables.TableClient c, com.azure.data.tables.models.TableEntity e", 'c.createEntity(e)'),
    ("azureTableGet", "Net", "com.azure.data.tables.TableClient c",
        'com.azure.data.tables.models.TableEntity e = c.getEntity("p", "r")'),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 12) ======================
    # NB: the Spring AI leaves (ChatClient/OpenAiModel) were FLOOR-SUPPRESSED (org.springframework.*
    # dropped, like Spring Vault) until candor-java 0.7.8 modeled them explicitly; they now surface Net
    # and are gated as normal EFFECT_CASES below.

    # ---- Net (Slack — MethodsClient.chatPostMessage POSTs to slack.com via SlackHttpClient) ----
    ("slackChatPostMessage", "Net",
        "com.slack.api.methods.MethodsClient c, com.slack.api.methods.request.chat.ChatPostMessageRequest r",
        'com.slack.api.methods.response.chat.ChatPostMessageResponse resp = c.chatPostMessage(r)'),

    # ---- Net (Discord JDA — RestAction.queue enqueues / complete blocks on the Discord REST call) ----
    ("jdaQueue", "Net", "net.dv8tion.jda.api.requests.RestAction<?> a", 'a.queue()'),
    ("jdaComplete", "Net", "net.dv8tion.jda.api.requests.RestAction<?> a", 'Object o = a.complete()'),

    # ---- Net (Telegram — AbsSender.execute(BotApiMethod) is the synchronous Bot-API send) ----
    ("telegramExecute", "Net",
        "org.telegram.telegrambots.meta.bots.AbsSender s, org.telegram.telegrambots.meta.api.methods.send.SendMessage m",
        'org.telegram.telegrambots.meta.api.objects.Message r = s.execute(m)'),

    # ---- Net (Keycloak admin — UsersResource.create/search are JAX-RS proxy round-trips to the admin REST API) ----
    ("keycloakUsersCreate", "Net",
        "org.keycloak.admin.client.resource.UsersResource u, org.keycloak.representations.idm.UserRepresentation rep",
        'jakarta.ws.rs.core.Response r = u.create(rep)'),
    ("keycloakUsersSearch", "Net", "org.keycloak.admin.client.resource.UsersResource u",
        'java.util.List<org.keycloak.representations.idm.UserRepresentation> r = u.search("a")'),

    # ---- Net (Okta — ApiClient.invokeAPI is the generic wire leaf every Okta SDK call bottoms out in) ----
    ("oktaInvokeApi", "Net", "com.okta.sdk.resource.client.ApiClient c",
        'Object o = c.invokeAPI("/p","GET",null,null,null,null,null,null,null,null,null,null,null)'),

    # ---- Net (Braintree — TransactionGateway.sale POSTs to the Braintree API; reached via gateway.transaction()) ----
    ("braintreeSale", "Net",
        "com.braintreegateway.BraintreeGateway g, com.braintreegateway.TransactionRequest r",
        'com.braintreegateway.Result<com.braintreegateway.Transaction> res = g.transaction().sale(r)'),

    # ---- Net (Mailgun — Mail.send calls jakarta.ws.rs Invocation$Builder.post to the Mailgun endpoint) ----
    ("mailgunSend", "Net", "net.sargue.mailgun.Mail m", 'net.sargue.mailgun.Response r = m.send()'),

    # ---- Net (Google Maps — PendingResult.await() blocks on the OkHttp request; terminal of geocode(..).await()) ----
    ("mapsAwait", "Net", "com.google.maps.GeoApiContext ctx",
        'com.google.maps.model.GeocodingResult[] r = com.google.maps.GeocodingApi.geocode(ctx, "x").await()'),

    # ---- Net/Db (ClickHouse NATIVE client — execute(request) async + static send(node,sql). JDBC is java.sql-covered.) ----
    ("clickhouseExecute", "Db",
        "com.clickhouse.client.ClickHouseClient c, com.clickhouse.client.ClickHouseRequest<?> req",
        'java.util.concurrent.CompletableFuture<com.clickhouse.client.ClickHouseResponse> f = c.execute(req)'),
    ("clickhouseSend", "Db", "com.clickhouse.client.ClickHouseNode n",
        'java.util.concurrent.CompletableFuture<java.util.List<com.clickhouse.client.ClickHouseResponseSummary>> f = '
        'com.clickhouse.client.ClickHouseClient.send(n, "select 1")'),
    # Spring AI — was FLOOR-SUPPRESSED (org.springframework.* dropped, like Spring Vault); now modeled
    # explicitly (CallResponseSpec terminal + ChatModel.call) so it surfaces Net. The fluent
    # cc.prompt().user(..).call().content() terminal owner is ChatClient$CallResponseSpec.content.
    ("springAiChatClientContent", "Net", "org.springframework.ai.chat.client.ChatClient cc",
        'String s = cc.prompt().user("hi").call().content()'),
    ("springAiChatClientResponse", "Net", "org.springframework.ai.chat.client.ChatClient cc",
        'org.springframework.ai.chat.model.ChatResponse cr = cc.prompt().user("hi").call().chatResponse()'),
    ("springAiOpenAiModelCall", "Net",
        "org.springframework.ai.openai.OpenAiChatModel m, org.springframework.ai.chat.prompt.Prompt p",
        'org.springframework.ai.chat.model.ChatResponse cr = m.call(p)'),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 13) ======================
    # --- Spring sub-libraries (FLOOR-SUPPRESSION sweep — owner org.springframework.*; a GAP here is a
    #     SILENT DROP, the structural finding; see the FLOOR? column in the RESULTS table) ---
    # Spring Integration MessagingTemplate.send is AMBIGUOUS-receiver (DirectChannel in-process → pure; an
    #   outbound-adapter channel is Net) — candor can't tell, so a concrete Net rule would FABRICATE. Under
    #   the STRUCTURAL Spring-floor fix it now discloses Unknown (the honest answer for the ambiguous I/O type;
    #   MessagingTemplate ends in *Template). Was previously SILENTLY floor-dropped.
    ("springIntegrationSend", "Unknown",
        "org.springframework.integration.core.MessagingTemplate t, org.springframework.messaging.Message<?> m",
        't.send(m)'),
    # Spring Batch — JobLauncher.run writes the JobRepository (the job/step metadata DB).
    ("springBatchJobRun", "Db",
        "org.springframework.batch.core.launch.JobLauncher l, org.springframework.batch.core.Job job, "
        "org.springframework.batch.core.JobParameters p",
        'org.springframework.batch.core.JobExecution e = l.run(job, p)'),

    # Spring Cloud OpenFeign — FeignBlockingLoadBalancerClient.execute is the blocking wire send (delegates to
    #   feign.Client.execute, which IS modeled — but the call-site owner is the org.springframework.cloud
    #   wrapper, so the FLOOR drops it even though the delegate is covered).
    ("springFeignLbExecute", "Net",
        "org.springframework.cloud.openfeign.loadbalancer.FeignBlockingLoadBalancerClient c, "
        "feign.Request req, feign.Request.Options o",
        'feign.Response r = c.execute(req, o)'),

    # Spring Data Elasticsearch — ElasticsearchOperations.save/search hit the ES cluster over HTTP.
    ("springDataEsSave", "Net",
        "org.springframework.data.elasticsearch.core.ElasticsearchOperations ops, Object o",
        'Object r = ops.save(o)'),
    ("springDataEsSearch", "Net",
        "org.springframework.data.elasticsearch.core.ElasticsearchOperations ops, "
        "org.springframework.data.elasticsearch.core.query.Query q",
        'org.springframework.data.elasticsearch.core.SearchHits<String> h = ops.search(q, String.class)'),

    # Spring Data Neo4j — Neo4jTemplate.save/findById run Cypher over the bolt protocol (a remote graph DB).
    ("springDataNeo4jSave", "Db",
        "org.springframework.data.neo4j.core.Neo4jTemplate t, Object o", 'Object r = t.save(o)'),
    ("springDataNeo4jFindById", "Db",
        "org.springframework.data.neo4j.core.Neo4jTemplate t",
        'java.util.Optional<String> r = t.findById("id", String.class)'),

    # Spring LDAP — LdapTemplate.lookup/search/bind issue LDAP ops over the wire.
    ("springLdapLookup", "Net", "org.springframework.ldap.core.LdapTemplate t", 'Object o = t.lookup("ou=x")'),
    ("springLdapSearch", "Net",
        "org.springframework.ldap.core.LdapTemplate t, org.springframework.ldap.core.AttributesMapper<String> am",
        'java.util.List<String> r = t.search("ou=x", "(cn=*)", am)'),
    ("springLdapBind", "Net", "org.springframework.ldap.core.LdapTemplate t", 't.bind("cn=x", null, null)'),

    # Spring Session SessionRepository.save is AMBIGUOUS-receiver (JDBC/Redis/Mongo = Db/Net; MapSessionRepository
    #   = in-memory) — a concrete rule would fabricate. Under the STRUCTURAL Spring-floor fix it discloses
    #   Unknown (the honest answer; SessionRepository ends in *Repository). Was previously SILENTLY floor-dropped.
    ("springSessionSave", "Unknown",
        "org.springframework.session.SessionRepository<org.springframework.session.Session> r, "
        "org.springframework.session.Session s",
        'r.save(s)'),

    # Spring Data Redis — RedisTemplate.execute(RedisCallback) runs against the Redis connection. VERIFY it is
    #   already modeled (NOT floored) — the one Spring case here expected to PASS (a WIN; the opsForValue
    #   path was modeled in batch 4, this checks the execute(callback) sibling).
    ("springRedisTemplateExecute", "Db",
        "org.springframework.data.redis.core.RedisTemplate<String,String> t",
        'Object o = t.execute((org.springframework.data.redis.core.RedisCallback<Object>) c -> null)'),

    # --- Non-Spring datastores (breadth; these surface the per-fn `invisible:[pkg]` disclosure = INVIS, NOT
    #     the floor — candor is honest it can't see the package) ---
    # OrientDB — ODatabaseSession.query/command run SQL against the (often remote) OrientDB server.
    ("orientdbQuery", "Db", "com.orientechnologies.orient.core.db.ODatabaseSession db",
        'com.orientechnologies.orient.core.sql.executor.OResultSet rs = db.query("select 1")'),
    ("orientdbCommand", "Db", "com.orientechnologies.orient.core.db.ODatabaseSession db",
        'com.orientechnologies.orient.core.sql.executor.OResultSet rs = db.command("insert into x set y=1")'),

    # ArangoDB — ArangoDatabase.query/getVersion hit the ArangoDB server over HTTP (the com.arangodb:CORE
    #   artifact carries the real classes; the published arangodb-java-driver jar is a 19-entry shaded stub).
    ("arangoQuery", "Net", "com.arangodb.ArangoDatabase db",
        'com.arangodb.ArangoCursor<String> c = db.query("FOR x IN c RETURN x", String.class)'),
    ("arangoVersion", "Net", "com.arangodb.ArangoDatabase db",
        'com.arangodb.entity.ArangoDBVersion v = db.getVersion()'),

    # RethinkDB — ReqlExpr.run(Connection) is the JSON-protocol query round-trip; connection().connect()
    #   opens the socket.
    ("rethinkRun", "Net", "com.rethinkdb.gen.ast.ReqlExpr e, com.rethinkdb.net.Connection conn",
        'com.rethinkdb.net.Result<Object> r = e.run(conn)'),
    ("rethinkConnect", "Net", "",
        'com.rethinkdb.net.Connection conn = com.rethinkdb.RethinkDB.r.connection().hostname("h").port(28015).connect()'),

    # NOTE: H2 MVStore.open(String fileName) is AMBIGUOUS — a null fileName opens an IN-MEMORY store, so the
    #   (String) descriptor can't be soundly gated to Fs (would fabricate on the in-memory case). Candor
    #   already discloses it INVISIBLE (the org.h2.mvstore package is κ-unknown → sound soft gap), so it is
    #   left accepted, not modeled.

    # ====================== ADDED LIBRARIES (2026-06-20 batch 14) ======================
    # ---- Net (HTTP SERVER frameworks — .start()/.init() BINDS a listening socket = the clearest Net leaf) ----
    # Javalin — start(int) binds the port.
    ("javalinStart", "Net", "io.javalin.Javalin a", 'a.start(7000)'),
    # Spark Java — init() binds the embedded Jetty server. (Spark.get is lazy route registration — pure anchor.)
    ("sparkInit", "Net", "", 'spark.Spark.init()'),
    # Undertow — start() binds the listeners.
    ("undertowStart", "Net", "io.undertow.Undertow u", 'u.start()'),
    # Eclipse Jetty SERVER — start() binds the connectors (call-site owner = org.eclipse.jetty.server.Server).
    ("jettyServerStart", "Net", "org.eclipse.jetty.server.Server s", 's.start()'),

    # ---- Net (Streaming — Kafka Streams start() consumes/produces over the broker socket) ----
    ("kafkaStreamsStart", "Net", "org.apache.kafka.streams.KafkaStreams ks", 'ks.start()'),

    # ---- Net (Apache Geode — Region.get/put hit a remote partition over the wire. Region<K,V> EXTENDS
    #      ConcurrentMap, but the call-site owner with a Region-typed receiver is org.apache.geode.cache.Region,
    #      so an owner-scoped rule is fabrication-safe; the batch-7 java.util.Map anchors still guard the JDK Map.) ----
    ("geodeRegionGet", "Net", "org.apache.geode.cache.Region<String,String> r", 'String v = r.get("k")'),
    ("geodeRegionPut", "Net", "org.apache.geode.cache.Region<String,String> r", 'String v = r.put("k","v")'),

    # ---- Fs (docx4j — WordprocessingMLPackage.load(File) reads the .docx off disk; save(File) writes it.
    #      The InputStream/OutputStream overloads are caller-stream PURE anchors below.) ----
    ("docx4jLoadFile", "Fs", "File f",
        'org.docx4j.openpackaging.packages.WordprocessingMLPackage p = org.docx4j.openpackaging.packages.WordprocessingMLPackage.load(f)'),
    ("docx4jSaveFile", "Fs", "org.docx4j.openpackaging.packages.WordprocessingMLPackage p, File f", 'p.save(f)'),

    # ---- Exec (ffmpeg wrapper — FFmpeg.run(FFmpegBuilder) forks the ffmpeg binary; Exec|Unknown both PASS) ----
    ("ffmpegRun", "Exec", "net.bramp.ffmpeg.FFmpeg ff, net.bramp.ffmpeg.builder.FFmpegBuilder b", 'ff.run(b)'),

    # ---- Fs (Templating — load a template FILE via the loader. The in-memory/caller-stream overloads are
    #      PURE anchors below.) ----
    # Handlebars compile(String) loads the named template via the TemplateLoader. (compileInline = in-memory anchor.)
    ("handlebarsCompile", "Fs", "com.github.jknack.handlebars.Handlebars h",
        'com.github.jknack.handlebars.Template t = h.compile("tmpl")'),
    # mustache.java DefaultMustacheFactory.compile(String) loads the named template file. (compile(Reader,n)=anchor.)
    ("mustacheCompile", "Fs", "com.github.mustachejava.DefaultMustacheFactory f",
        'com.github.mustachejava.Mustache m = f.compile("t.mustache")'),
    # Pebble getTemplate(String) loads+reads the template file. (getLiteralTemplate(String) = in-memory anchor.)
    ("pebbleGetTemplate", "Fs", "io.pebbletemplates.pebble.PebbleEngine e",
        'io.pebbletemplates.pebble.template.PebbleTemplate t = e.getTemplate("t.peb")'),

    # ---- Net (SimpleJavaMail — Mailer.sendMail(Email) opens an SMTP transport; returns a CompletableFuture
    #      (async) so Net|Unknown both PASS. Owner org.simplejavamail.api.mailer.Mailer.) ----
    ("simpleJavaMailSend", "Net",
        "org.simplejavamail.api.mailer.Mailer m, org.simplejavamail.api.email.Email e", 'm.sendMail(e)'),

    # ---- Fs/Exec (ML/native) ----
    # ONNX Runtime — OrtEnvironment.createSession(String) loads the model file off disk (Fs). createSession(byte[])
    #   is in-memory -> PURE anchor below.
    ("onnxCreateSessionFile", "Fs", "ai.onnxruntime.OrtEnvironment env, String path",
        'ai.onnxruntime.OrtSession s = env.createSession(path)'),
    # ONNX Runtime — OrtSession.run(Map) is native inference (JNI). Exec|Unknown acceptable; must NOT read pure.
    ("onnxSessionRun", "Exec", "ai.onnxruntime.OrtSession s, java.util.Map<String,? extends ai.onnxruntime.OnnxTensorLike> in",
        'ai.onnxruntime.OrtSession.Result r = s.run(in)'),
    # Stanford CoreNLP — new StanfordCoreNLP(String) loads serialized models off disk/classpath -> Fs.
    ("corenlpNew", "Fs", "",
        'edu.stanford.nlp.pipeline.StanfordCoreNLP p = new edu.stanford.nlp.pipeline.StanfordCoreNLP("props")'),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 15) ======================
    # ---- Fs (java.util.prefs.Preferences PARTIALLY-MODELED siblings — the floor-dropped backing-store verbs) ----
    # removeNode() DELETES a whole subtree from the backing store (disk/registry) -> Fs. Modeled siblings
    #   put/get/flush/sync/remove are Fs, but removeNode is FLOOR-DROPPED silent. Expect Fs|Unknown; got: silent.
    ("prefsRemoveNode", "Fs", "java.util.prefs.Preferences p", 'p.removeNode()'),
    # clear() removes ALL keys at this node from the backing store -> Fs. (remove(String) IS modeled; clear is not.)
    ("prefsClear", "Fs", "java.util.prefs.Preferences p", 'p.clear()'),
    # exportNode(OutputStream) READS the backing store for this node and emits XML to the stream -> Fs (the read).
    ("prefsExportNode", "Fs", "java.util.prefs.Preferences p, OutputStream os", 'p.exportNode(os)'),
    # exportSubtree(OutputStream) READS the whole subtree from the backing store -> Fs.
    ("prefsExportSubtree", "Fs", "java.util.prefs.Preferences p, OutputStream os", 'p.exportSubtree(os)'),
    # static importPreferences(InputStream) parses the XML and WRITES the backing store -> Fs.
    ("prefsImport", "Fs", "InputStream in", 'java.util.prefs.Preferences.importPreferences(in)'),

    # ---- Db (javax.sql.rowset.RowSet.execute — connects to the data source and runs the command = DB round-trip.
    #      candor models javax.sql.DataSource (Db) but NOT javax.sql.rowset.*; javax.* is κ-covered so it is
    #      FLOOR-DROPPED silent rather than `invisible`-disclosed. Expect Db|Unknown.) ----
    ("rowsetExecuteNoArg", "Db", "javax.sql.rowset.JdbcRowSet rs", 'rs.execute()'),
    ("rowsetExecuteConn", "Db", "javax.sql.rowset.CachedRowSet rs, java.sql.Connection c", 'rs.execute(c)'),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 16) ======================
    # FRONTIER: PARTIALLY-MODELED κ-COVERED (java.*/javax.*/jakarta.*) types where candor models SOME verbs
    #   but an effectful SIBLING verb falls through. Where the sibling is ABSENT from the report (covered prefix
    #   suppresses the `invisible` disclosure) it is FLOOR-SUPPRESSED (silent) = the worst cardinal sin.
    # --- java.sql.Connection TRANSACTION CONTROL → Db. commit/rollback/setAutoCommit ARE modeled (verified ok);
    #     setSavepoint/releaseSavepoint are the gap: SAVEPOINT/RELEASE SAVEPOINT are SQL statements sent to the
    #     server (a real round-trip), yet they are FLOOR-DROPPED silent. Expect Db|Unknown; got: silent (FLOOR). ---
    ("connSetSavepoint",     "Db", "java.sql.Connection c", 'java.sql.Savepoint s = c.setSavepoint()'),
    ("connReleaseSavepoint", "Db", "java.sql.Connection c, java.sql.Savepoint s", 'c.releaseSavepoint(s)'),
    # --- jakarta.persistence.EntityTransaction.commit/rollback → Db. EntityManager flush/refresh/lock/remove ARE
    #     modeled (verified ok), but EntityTransaction.commit FLUSHES the persistence context to the DB and
    #     rollback issues ROLLBACK — both genuine Db round-trips, FLOOR-DROPPED silent. Very common JPA idiom.
    #     Expect Db|Unknown; got: silent (FLOOR). ---
    ("etCommit",   "Db", "jakarta.persistence.EntityTransaction t", 't.commit()'),
    ("etRollback", "Db", "jakarta.persistence.EntityTransaction t", 't.rollback()'),
    # --- jakarta.jms transacted-session COMMIT/ROLLBACK → Net (broker round-trip). MessageProducer.send IS modeled
    #     (jmsSend, Net), but Session.commit/rollback and JMSContext.commit flush/ack to the broker over the wire,
    #     FLOOR-DROPPED silent. Expect Net|Unknown; got: silent (FLOOR). ---
    ("jmsSessionCommit",   "Net", "jakarta.jms.Session s", 's.commit()'),
    ("jmsSessionRollback", "Net", "jakarta.jms.Session s", 's.rollback()'),
    ("jmsCtxCommit",       "Net", "jakarta.jms.JMSContext c", 'c.commit()'),
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
    # Quartz Scheduler.scheduleJob is pure with the DEFAULT RAMJobStore (in-memory) and Db only with a
    # JDBCJobStore — the call site can't reveal the store, so silent-pure is ACCEPTED (ambiguous-receiver
    # class, like Ehcache/Caffeine; modeling Db would fabricate on the common RAM case).
    ("quartzScheduleJobPure", "java.util.Date d = s.scheduleJob(jd, tr)",
        "org.quartz.Scheduler s, org.quartz.JobDetail jd, org.quartz.Trigger tr"),
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

    # ====================== ADDED LIBRARIES (2026-06-20 batch 7) — pure anchors ===============
    # CRITICAL anti-flooding anchors: a get/put on a java.util.Map-TYPED receiver must stay PURE even after the
    #   distributed caches (IMap/IgniteCache/BasicCache) are modeled Net. This proves the cache κ rule is
    #   OWNER-SCOPED to the cache interface and does NOT key java.util.Map/ConcurrentMap (which Hazelcast and
    #   Infinispan inherit) — otherwise every HashMap.get in every codebase would read Net. The call-site owner
    #   here is java.util.Map, so it must be silent-pure.
    ("mapGetPure", "String v = m.get(\"k\")", "java.util.Map<String,String> m"),
    ("mapPutPure", "String v = m.put(\"k\",\"v\")", "java.util.Map<String,String> m"),
    ("concurrentMapGetPure", "String v = m.get(\"k\")", "java.util.concurrent.ConcurrentMap<String,String> m"),
    # JDBI Handle.createQuery returns a Query builder — the wire leaf is the terminal mapTo/list/execute. But
    #   createQuery is modeled Db above (it carries the SQL and is the canonical leaf candor sees). For the
    #   builder-pure discipline, the Jdbi.open() factory (returns a Handle, no SQL yet) must stay pure.
    ("jdbiOpenPure", "org.jdbi.v3.core.Handle h = j.open()", "org.jdbi.v3.core.Jdbi j"),
    # SendGrid Request is a plain POJO — building one (setEndpoint/setMethod) touches no wire. Pins that only
    #   api()/makeCall are Net, not the request setup (fluent-builder-pure-until-terminal anchor).
    ("sendgridRequestBuildPure",
        "req.setMethod(com.sendgrid.Method.POST); req.setEndpoint(\"mail/send\")", "com.sendgrid.Request req"),
    # reactor-netty HttpClient.get() is a LOCAL factory returning a ResponseReceiver — no request dispatched
    #   until the terminal responseContent()/response() (modeled Net above). The get() setup stays pure.
    ("reactorNettyGetPure",
        "reactor.netty.http.client.HttpClient.ResponseReceiver<?> r = hc.get()", "reactor.netty.http.client.HttpClient hc"),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 8) — pure anchors ===============
    # Micrometer Counter.increment() is IN-MEMORY — the registry holds the running count; PUSH registries
    #   (Statsd/Datadog) flush on a BACKGROUND scheduler, not at the increment call. So the user-facing
    #   increment must stay pure (modeling Net here would fabricate on the common in-memory/non-push case).
    ("micrometerCounterIncrementPure", "c.increment()", "io.micrometer.core.instrument.Counter c"),
    # MeterRegistry.counter(name, tags) is a FACTORY (registers/returns a Counter, no wire) — pure-until-terminal.
    ("micrometerCounterFactoryPure",
        "io.micrometer.core.instrument.Counter c = r.counter(\"m\")",
        "io.micrometer.core.instrument.MeterRegistry r"),
    # StatsdMeterRegistry.counter(...) — even on a PUSH registry the counter() factory does no wire (the push
    #   is the background scheduler's job). Pins that the factory on a push registry stays pure too.
    ("statsdCounterFactoryPure",
        "io.micrometer.core.instrument.Counter c = r.counter(\"m\")",
        "io.micrometer.statsd.StatsdMeterRegistry r"),
    # OpenTelemetry Span.setAttribute(String, String) mutates the in-memory span — no wire (export is deferred
    #   to the processor). Must stay pure even after SpanExporter.export is modeled Net.
    ("otelSetAttributePure", "s.setAttribute(\"k\", \"v\")", "io.opentelemetry.api.trace.Span s"),
    # OTel Span.end() does NOT flush synchronously — OTLP export is deferred to the BatchSpanProcessor
    # background scheduler, so the call site is genuinely pure (the wire leaf is SpanExporter.export, Net).
    # Modeling end()->Net would fabricate on every span. Accepted (deferred class).
    ("otelSpanEndPure", "s.end()", "io.opentelemetry.api.trace.Span s"),
    # Kryo writeObject(Output, Object) is CALLER-STREAM — the Output wraps the caller's OutputStream (the file
    #   open is the caller's `new FileOutputStream`). No File overload exists, so the serialize itself is pure
    #   (caller-stream class, like SnakeYAML/POI/OpenCSV).
    ("kryoWriteObjectPure",
        "k.writeObject(out, new Object())",
        "com.esotericsoftware.kryo.Kryo k, com.esotericsoftware.kryo.io.Output out"),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 9) — pure anchors ===============
    # Redisson getBucket(name) is a LOCAL factory — it returns an RBucket handle, no Redis round-trip until the
    #   terminal get/set (modeled Net above). Must stay pure (fluent-builder-pure-until-terminal anchor).
    ("redissonGetBucketPure",
        "org.redisson.api.RBucket<String> b = rc.getBucket(\"k\")", "org.redisson.api.RedissonClient rc"),
    # BigQuery QueryJobConfiguration.newBuilder(sql) is a pure request BUILDER — no wire until BigQuery.query
    #   (modeled Net above) consumes it. Pins that GCP option/builder setup stays pure.
    ("bigQueryBuilderPure",
        "com.google.cloud.bigquery.QueryJobConfiguration.Builder bld = com.google.cloud.bigquery.QueryJobConfiguration.newBuilder(\"select 1\")",
        ""),
    # Vault.logical() is a pure ACCESSOR — returns the Logical API view, no wire until read/write (modeled Net
    #   above). Pins that the accessor stays pure (the wire leaf is Logical.read/write).
    ("vaultLogicalAccessorPure",
        "io.github.jopenlibs.vault.api.Logical lg = v.logical()", "io.github.jopenlibs.vault.Vault v"),
    # DockerClient.pingCmd() is a pure BUILDER — returns a PingCmd, no daemon round-trip until exec() (Net/Exec
    #   above). Pins the *Cmd() accessors stay pure (the wire leaf is the exec() terminal).
    ("dockerPingCmdBuilderPure",
        "com.github.dockerjava.api.command.PingCmd cmd = c.pingCmd()", "com.github.dockerjava.api.DockerClient c"),
    # KubernetesClient.pods() is a pure DSL ACCESSOR — returns a MixedOperation view, no API-server round-trip
    #   until the terminal list()/create() (modeled Net above). Pins the per-resource accessors stay pure.
    ("k8sPodsAccessorPure",
        "io.fabric8.kubernetes.client.dsl.MixedOperation<io.fabric8.kubernetes.api.model.Pod,"
        "io.fabric8.kubernetes.api.model.PodList,io.fabric8.kubernetes.client.dsl.PodResource> op = c.pods()",
        "io.fabric8.kubernetes.client.KubernetesClient c"),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 10) — pure anchors ===============
    # Curator create()/getData() are pure fluent ACCESSORS — they return a builder, no round-trip to the ensemble
    #   until the terminal forPath (modeled Net above). Must stay pure (fluent-builder-pure-until-terminal anchor).
    ("curatorCreateAccessorPure",
        "org.apache.curator.framework.api.CreateBuilder b = cf.create()", "org.apache.curator.framework.CuratorFramework cf"),
    ("curatorGetDataAccessorPure",
        "org.apache.curator.framework.api.GetDataBuilder b = cf.getData()", "org.apache.curator.framework.CuratorFramework cf"),
    # Spanner DatabaseClient.singleUse() is a pure ACCESSOR — returns a ReadContext, no wire until executeQuery
    #   (modeled Db above). Must stay pure.
    ("spannerSingleUsePure",
        "com.google.cloud.spanner.ReadContext rc = dc.singleUse()", "com.google.cloud.spanner.DatabaseClient dc"),
    # Azure CosmosDatabase.getContainer(name) is a pure ACCESSOR — returns a CosmosContainer handle, no wire until
    #   readItem/createItem (modeled Net above). Must stay pure.
    ("cosmosGetContainerPure",
        "com.azure.cosmos.CosmosContainer c = db.getContainer(\"c\")", "com.azure.cosmos.CosmosDatabase db"),
    # ACCEPTED-PURE service-discovery / feature-flag reads — these serve from a LOCAL in-memory cache the client
    #   keeps in sync via a BACKGROUND connection; the read call itself does NO synchronous wire, so it is
    #   genuinely pure and must STAY pure (modeling Net would fabricate on every flag check / registry read).
    #   Verified by javap (batch-10 report):
    #     Eureka DiscoveryClient.getApplications() -> getfield localRegionApps (AtomicReference, local registry).
    #     LaunchDarkly LDClient.boolVariation -> EvaluatorInterface.evalAndFlag (in-memory flag store).
    #     Unleash DefaultUnleash.isEnabled -> reads a local IFeatureRepository.
    ("eurekaGetApplicationsPure",
        "com.netflix.discovery.shared.Applications a = ec.getApplications()", "com.netflix.discovery.EurekaClient ec"),
    ("eurekaNextServerPure",
        "com.netflix.appinfo.InstanceInfo i = ec.getNextServerFromEureka(\"vip\", false)",
        "com.netflix.discovery.EurekaClient ec"),
    ("ldBoolVariationPure",
        "boolean b = c.boolVariation(\"flag\", ctx, false)",
        "com.launchdarkly.sdk.server.LDClient c, com.launchdarkly.sdk.LDContext ctx"),
    ("unleashIsEnabledPure", "boolean b = u.isEnabled(\"toggle\")", "io.getunleash.Unleash u"),
    # Temporal WorkflowServiceStubs.newServiceStubs is a lazy gRPC channel FACTORY (the channel connects on the
    #   first RPC, not here) — a setup/factory leaf, like the deferred class. Accepted-pure (the wire happens on
    #   the workflow stub RPCs, which are proxy-generated and not statically resolvable).
    ("temporalServiceStubsPure",
        "io.temporal.serviceclient.WorkflowServiceStubs s = io.temporal.serviceclient.WorkflowServiceStubs.newServiceStubs(opts)",
        "io.temporal.serviceclient.WorkflowServiceStubsOptions opts"),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 11) — pure anchors ===============
    # theokanning OpenAiService.builder() is a FACTORY/builder — constructing the client touches no wire (the
    #   wire leaf is createChatCompletion, modeled Net above). Must stay pure (factory-pure anchor).
    ("openaiServiceBuilderPure",
        "com.theokanning.openai.service.OpenAiService s = new com.theokanning.openai.service.OpenAiService(\"key\")", ""),
    # MilvusServiceClient(ConnectParam) construction is a FACTORY — the gRPC channel connects lazily; the wire
    #   leaf is search/insert (modeled Net above). The constructor itself must stay pure.
    ("milvusClientCtorPure",
        "io.milvus.client.MilvusServiceClient c = new io.milvus.client.MilvusServiceClient(p)",
        "io.milvus.param.ConnectParam p"),
    # An in-memory vector (a java.util.List<Float> built locally, e.g. an embedding computed in-process) touches
    #   no wire — must stay pure even after the vector-DB upsert/query leaves are modeled Net. The owner here is
    #   java.util.List (a JDK type), so it must be silent-pure (anti-flooding anchor for the vector batch).
    ("inMemoryVectorPure",
        "java.util.List<Float> v = new java.util.ArrayList<>(); v.add(1.0f); float x = v.get(0)", ""),
    # ====================== ADDED LIBRARIES (2026-06-20 batch 12) — pure anchors ===============
    # Braintree gateway construction holds a com.braintreegateway.util.Http but does NO wire — the wire leaf
    #   is transaction().sale() (modeled Net above). Must stay pure (factory/ctor-pure anchor).
    ("braintreeGatewayCtorPure",
        'com.braintreegateway.BraintreeGateway g = new com.braintreegateway.BraintreeGateway('
        'com.braintreegateway.Environment.SANDBOX, "m", "k", "s")', ""),
    # Spring AI prompt builder (cc.prompt().user("hi")) is the fluent builder BEFORE the .call() wire terminal
    #   — no wire. NB Spring AI is org.springframework.* so this owner is also floor-suppressed (absent from the
    #   report); absence == pure for the anchor (got == []), so it correctly reads pure here either way.
    ("springAiPromptBuilderPure",
        'var s = cc.prompt().user("hi")', "org.springframework.ai.chat.client.ChatClient cc"),
    # CRITICAL anti-flood anchor for the STRUCTURAL Spring-floor fix (batch 13): a PURE Spring utility class
    # (StringUtils — NOT an I/O-convention *Template/*Operations/*Repository/*Gateway type) must STILL be
    # floored/pure, NOT disclosed Unknown. This proves the structural fix's owner-suffix gate is tight and
    # doesn't flood the (very common) pure Spring-util surface — the reason the κ floor exists in the first place.
    ("springStringUtilsPure", 'boolean b = org.springframework.util.StringUtils.hasText("x")', ""),
    ("springObjectUtilsPure", 'boolean b = org.springframework.util.ObjectUtils.isEmpty("x")', ""),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 13) — pure anchors ===============
    # NB: MapSessionRepository (the in-memory Spring Session backend) is NO LONGER a pure anchor — under the
    #   STRUCTURAL Spring-floor fix (batch 13), a *Repository (an I/O-convention Spring type) discloses Unknown
    #   even on the in-memory impl, because candor's name-based κ can't distinguish MapSessionRepository (pure)
    #   from a JDBC/Redis-backed one at the call site. Unknown is the honest ambiguous answer (NOT a fabricated
    #   concrete effect); the mild over-disclosure on the rare in-memory case is the accepted cost of catching
    #   every unmodeled backed Spring repo/template. (See springSessionSave/springIntegrationSend → Unknown.)
    # H2 MVStore.openMap on an ALREADY-OPEN store is the in-memory map view (the disk open was MVStore.open,
    #   the Fs leaf above) — must stay pure. NB org.h2.mvstore is a κ-unknown package, so candor discloses
    #   `invisible:[org.h2.mvstore]` here rather than fabricating — which reads pure (got==[]) for the anchor.
    ("mvstoreOpenMapPure",
        'org.h2.mvstore.MVMap<String,String> m = s.openMap("d")', "org.h2.mvstore.MVStore s"),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 14) — pure anchors ===============
    # Javalin Context.result(String) is BUFFERED — it wraps the body into a ByteArrayInputStream (verified by
    #   javap -c), no synchronous socket write. Must stay pure even after the server .start() leaves are modeled
    #   Net (the wire happens in the request loop, not at result()).
    ("javalinResultPure", 'c.result("hi")', "io.javalin.http.Context c"),
    # Spark.get(path, Route) is LAZY route REGISTRATION (delegates to Service.get; the port binds at init(),
    #   modeled Net above). The registration itself does no wire — must stay pure.
    ("sparkGetPure", 'spark.Spark.get("/p", r)', "spark.Route r"),
    # ZXing barcode encode/decode is in-memory image MATH — no I/O. Must stay pure.
    ("zxingEncodePure",
        'com.google.zxing.common.BitMatrix m = new com.google.zxing.MultiFormatWriter().encode("x", com.google.zxing.BarcodeFormat.QR_CODE, 100, 100)',
        ""),
    ("zxingDecodePure",
        'com.google.zxing.Result res = new com.google.zxing.MultiFormatReader().decode(b)',
        "com.google.zxing.BinaryBitmap b"),
    # Handlebars compileInline(String) is in-memory (the template TEXT is the argument, no loader) — pure
    #   (compile(String) above is the Fs leaf that loads via the TemplateLoader).
    ("handlebarsCompileInlinePure",
        'com.github.jknack.handlebars.Template t = h.compileInline("{{x}}")',
        "com.github.jknack.handlebars.Handlebars h"),
    # JMustache Compiler.compile(String) takes a template TEXT string (NOT a filename) — JMustache has no
    #   file-loading leaf, so the compile is pure in-memory parsing. Must stay pure.
    ("jmustacheCompilePure",
        'com.samskivert.mustache.Template t = c.compile("Hello {{name}}")',
        "com.samskivert.mustache.Mustache.Compiler c"),
    # mustache.java compile(Reader, name) is CALLER-STREAM — the Reader's file open is the caller's `new
    #   FileReader` (compile(String) above loads the file by name = the Fs leaf). Must stay pure.
    ("mustacheCompileReaderPure",
        'com.github.mustachejava.Mustache m = f.compile(rd, "name")',
        "com.github.mustachejava.DefaultMustacheFactory f, Reader rd"),
    # Pebble getLiteralTemplate(String) compiles the template TEXT in-memory (no loader read) — pure
    #   (getTemplate(String) above is the Fs leaf).
    ("pebbleLiteralTemplatePure",
        'io.pebbletemplates.pebble.template.PebbleTemplate t = e.getLiteralTemplate("{{x}}")',
        "io.pebbletemplates.pebble.PebbleEngine e"),
    # docx4j load(InputStream)/save(OutputStream) are CALLER-STREAM — the file open is the caller's (load(File)
    #   /save(File) above are the Fs leaves). Must stay pure.
    ("docx4jLoadStreamPure",
        'org.docx4j.openpackaging.packages.WordprocessingMLPackage p = org.docx4j.openpackaging.packages.WordprocessingMLPackage.load(in)',
        "InputStream in"),
    ("docx4jSaveStreamPure",
        'p.save(os)', "org.docx4j.openpackaging.packages.WordprocessingMLPackage p, OutputStream os"),
    # ONNX Runtime createSession(byte[]) loads the model from IN-MEMORY bytes — no disk read (createSession(String)
    #   above is the Fs leaf). Must stay pure.
    ("onnxCreateSessionBytesPure",
        'ai.onnxruntime.OrtSession s = env.createSession(new byte[1])', "ai.onnxruntime.OrtEnvironment env"),

    # ====================== ADDED LIBRARIES (2026-06-20 batch 16) — pure anchors ===============
    # These guard the batch-16 frontier fixes (Connection/EntityTransaction/JMS transaction verbs): the
    #   modeled effectful verbs sit beside LOCAL-only siblings that must NOT be over-classified by a κ widening.
    # java.io.File NAME/PATH accessors are pure STRING ops — they touch no FS. The stat/mutate verbs
    #   (exists/length/delete/mkdir/listFiles/renameTo/createNewFile/canRead/lastModified/setLastModified —
    #   all already modeled Fs) are the leaves; these accessors must STAY pure (anti-fabrication anchor).
    ("fileGetNamePure",         "String s = f.getName()",         "File f"),
    ("fileGetPathPure",         "String s = f.getPath()",         "File f"),
    ("fileGetParentPure",       "String s = f.getParent()",       "File f"),
    ("fileToPathPure",          "java.nio.file.Path p = f.toPath()", "File f"),
    ("fileGetAbsolutePathPure", "String s = f.getAbsolutePath()", "File f"),
    # java.sql.Statement.addBatch BUFFERS the SQL string LOCALLY (no round-trip; executeBatch is the Db leaf,
    #   modeled). getGeneratedKeys returns ALREADY-BUFFERED keys from the prior execute (no round-trip). Both
    #   pure — must not be over-classified Db when the savepoint/EntityTransaction verbs are modeled.
    ("stmtAddBatchPure",          "s.addBatch(\"x\")",                          "java.sql.Statement s"),
    ("stmtGetGeneratedKeysPure",  "java.sql.ResultSet r = s.getGeneratedKeys()", "java.sql.Statement s"),
    # java.sql.Connection.getMetaData returns a DatabaseMetaData VALUE object lazily (no round-trip; the
    #   metadata QUERIES getTables/getColumns ARE modeled Db). Must stay pure.
    ("connGetMetaDataPure",  "java.sql.DatabaseMetaData m = c.getMetaData()", "java.sql.Connection c"),
    # jakarta.persistence.EntityManager.detach EVICTS an entity from the in-memory persistence context — a
    #   purely local op, NO DB round-trip (unlike flush/refresh/lock/remove which ARE modeled Db). Must stay pure.
    ("emDetachPure", "em.detach(o)", "jakarta.persistence.EntityManager em, Object o"),
    # java.net.URLClassLoader constructor just STORES the URL[] (no I/O until a findClass/findResource); pure.
    ("urlClassLoaderCtorPure",
        "java.net.URLClassLoader cl = new java.net.URLClassLoader(u)", "java.net.URL[] u"),
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
    # --- added 2026-06-20 batch 7 ---
    # Distributed caches/grids — Hazelcast / Apache Ignite (+ JCache api for IgniteCache's supertype) / Infinispan
    "hazelcast-5.3.7.jar": f"{_MVN}/com/hazelcast/hazelcast/5.3.7/hazelcast-5.3.7.jar",
    "ignite-core-2.16.0.jar": f"{_MVN}/org/apache/ignite/ignite-core/2.16.0/ignite-core-2.16.0.jar",
    "cache-api-1.1.1.jar": f"{_MVN}/javax/cache/cache-api/1.1.1/cache-api-1.1.1.jar",  # IgniteCache extends javax.cache.Cache
    "infinispan-core-14.0.27.Final.jar": f"{_MVN}/org/infinispan/infinispan-core/14.0.27.Final/infinispan-core-14.0.27.Final.jar",
    "infinispan-commons-14.0.27.Final.jar": f"{_MVN}/org/infinispan/infinispan-commons/14.0.27.Final/infinispan-commons-14.0.27.Final.jar",
    # DB toolkits — JDBI / Spring Data Cassandra / Spring Data Couchbase
    "jdbi3-core-3.45.1.jar": f"{_MVN}/org/jdbi/jdbi3-core/3.45.1/jdbi3-core-3.45.1.jar",
    "spring-data-cassandra-4.3.1.jar": f"{_MVN}/org/springframework/data/spring-data-cassandra/4.3.1/spring-data-cassandra-4.3.1.jar",
    "spring-data-couchbase-5.3.1.jar": f"{_MVN}/org/springframework/data/spring-data-couchbase/5.3.1/spring-data-couchbase-5.3.1.jar",
    # SaaS SDKs — Stripe / Twilio / SendGrid (+ java-http-client for SendGrid's Request/Response/Method types)
    "stripe-java-25.12.0.jar": f"{_MVN}/com/stripe/stripe-java/25.12.0/stripe-java-25.12.0.jar",
    "twilio-10.1.5.jar": f"{_MVN}/com/twilio/sdk/twilio/10.1.5/twilio-10.1.5.jar",
    "sendgrid-java-4.10.2.jar": f"{_MVN}/com/sendgrid/sendgrid-java/4.10.2/sendgrid-java-4.10.2.jar",
    "java-http-client-4.5.0.jar": f"{_MVN}/com/sendgrid/java-http-client/4.5.0/java-http-client-4.5.0.jar",
    # Reactive/HTTP — reactor-netty (http + core; netty codec/handler for compile; reactor-core already present)
    "reactor-netty-http-1.1.20.jar": f"{_MVN}/io/projectreactor/netty/reactor-netty-http/1.1.20/reactor-netty-http-1.1.20.jar",
    "reactor-netty-core-1.1.20.jar": f"{_MVN}/io/projectreactor/netty/reactor-netty-core/1.1.20/reactor-netty-core-1.1.20.jar",
    "netty-codec-http-4.1.111.Final.jar": f"{_MVN}/io/netty/netty-codec-http/4.1.111.Final/netty-codec-http-4.1.111.Final.jar",
    "netty-codec-4.1.111.Final.jar": f"{_MVN}/io/netty/netty-codec/4.1.111.Final/netty-codec-4.1.111.Final.jar",
    "netty-handler-4.1.111.Final.jar": f"{_MVN}/io/netty/netty-handler/4.1.111.Final/netty-handler-4.1.111.Final.jar",
    # Email — Apache Commons Email
    "commons-email-1.6.0.jar": f"{_MVN}/org/apache/commons/commons-email/1.6.0/commons-email-1.6.0.jar",
    # Scheduling — Quartz
    "quartz-2.3.2.jar": f"{_MVN}/org/quartz-scheduler/quartz/2.3.2/quartz-2.3.2.jar",
    # --- added 2026-06-20 batch 8 ---
    # Observability — Sentry / OpenTelemetry (api + sdk-trace + sdk-common + context) / Micrometer (core +
    #   commons + observation + registry-statsd)
    "sentry-7.10.0.jar": f"{_MVN}/io/sentry/sentry/7.10.0/sentry-7.10.0.jar",
    "opentelemetry-api-1.39.0.jar": f"{_MVN}/io/opentelemetry/opentelemetry-api/1.39.0/opentelemetry-api-1.39.0.jar",
    "opentelemetry-context-1.39.0.jar": f"{_MVN}/io/opentelemetry/opentelemetry-context/1.39.0/opentelemetry-context-1.39.0.jar",
    "opentelemetry-sdk-trace-1.39.0.jar": f"{_MVN}/io/opentelemetry/opentelemetry-sdk-trace/1.39.0/opentelemetry-sdk-trace-1.39.0.jar",
    "opentelemetry-sdk-common-1.39.0.jar": f"{_MVN}/io/opentelemetry/opentelemetry-sdk-common/1.39.0/opentelemetry-sdk-common-1.39.0.jar",
    "micrometer-core-1.13.1.jar": f"{_MVN}/io/micrometer/micrometer-core/1.13.1/micrometer-core-1.13.1.jar",
    "micrometer-commons-1.13.1.jar": f"{_MVN}/io/micrometer/micrometer-commons/1.13.1/micrometer-commons-1.13.1.jar",
    "micrometer-observation-1.13.1.jar": f"{_MVN}/io/micrometer/micrometer-observation/1.13.1/micrometer-observation-1.13.1.jar",
    "micrometer-registry-statsd-1.13.1.jar": f"{_MVN}/io/micrometer/micrometer-registry-statsd/1.13.1/micrometer-registry-statsd-1.13.1.jar",
    # Native-tool wrappers — im4java (ImageMagick) / Tess4J (Tesseract via JNA; jna for the native binding type)
    "im4java-1.4.0.jar": f"{_MVN}/org/im4java/im4java/1.4.0/im4java-1.4.0.jar",
    "tess4j-5.11.0.jar": f"{_MVN}/net/sourceforge/tess4j/tess4j/5.11.0/tess4j-5.11.0.jar",
    "jna-5.13.0.jar": f"{_MVN}/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar",  # Tess4J compile dep (com.sun.jna)
    # HTTP clients — Google HTTP client / Eclipse Jetty client (http/io/util) / Unirest
    "google-http-client-1.44.2.jar": f"{_MVN}/com/google/http-client/google-http-client/1.44.2/google-http-client-1.44.2.jar",
    "jetty-client-12.0.10.jar": f"{_MVN}/org/eclipse/jetty/jetty-client/12.0.10/jetty-client-12.0.10.jar",
    "jetty-http-12.0.10.jar": f"{_MVN}/org/eclipse/jetty/jetty-http/12.0.10/jetty-http-12.0.10.jar",
    "jetty-io-12.0.10.jar": f"{_MVN}/org/eclipse/jetty/jetty-io/12.0.10/jetty-io-12.0.10.jar",
    "jetty-util-12.0.10.jar": f"{_MVN}/org/eclipse/jetty/jetty-util/12.0.10/jetty-util-12.0.10.jar",
    "unirest-java-3.14.5.jar": f"{_MVN}/com/konghq/unirest-java/3.14.5/unirest-java-3.14.5.jar",
    # Messaging — NATS / ActiveMQ Artemis (core-client + commons for the API types)
    "jnats-2.18.1.jar": f"{_MVN}/io/nats/jnats/2.18.1/jnats-2.18.1.jar",
    "artemis-core-client-2.33.0.jar": f"{_MVN}/org/apache/activemq/artemis-core-client/2.33.0/artemis-core-client-2.33.0.jar",
    "artemis-commons-2.33.0.jar": f"{_MVN}/org/apache/activemq/artemis-commons/2.33.0/artemis-commons-2.33.0.jar",
    # Crypto — Google Tink / Jasypt (key generation draws entropy -> Rand)
    "tink-1.13.0.jar": f"{_MVN}/com/google/crypto/tink/tink/1.13.0/tink-1.13.0.jar",
    "jasypt-1.9.3.jar": f"{_MVN}/org/jasypt/jasypt/1.9.3/jasypt-1.9.3.jar",
    # Serialization — Kryo (caller-stream writeObject -> pure anchor)
    "kryo-5.6.0.jar": f"{_MVN}/com/esotericsoftware/kryo/5.6.0/kryo-5.6.0.jar",
    # SKIPPED: ArangoDB java-driver — the published jar is an aggregator/shaded stub with no com.arangodb
    #   .class files (only 19 entries); compiling the fixture against it needs split shaded modules. Skipped.
    # --- added 2026-06-20 batch 9 ---
    # GCP services — BigQuery / Firestore / Pub-Sub. (google-cloud-core + gax already present from GCS batch 4.)
    # api-common carries com.google.api.core.ApiFuture; proto-google-cloud-pubsub-v1 carries the PubsubMessage
    # proto type used in the publish fixture.
    "google-cloud-bigquery-2.40.0.jar": f"{_MVN}/com/google/cloud/google-cloud-bigquery/2.40.0/google-cloud-bigquery-2.40.0.jar",
    "google-cloud-firestore-3.21.0.jar": f"{_MVN}/com/google/cloud/google-cloud-firestore/3.21.0/google-cloud-firestore-3.21.0.jar",
    "google-cloud-pubsub-1.130.0.jar": f"{_MVN}/com/google/cloud/google-cloud-pubsub/1.130.0/google-cloud-pubsub-1.130.0.jar",
    "api-common-2.33.0.jar": f"{_MVN}/com/google/api/api-common/2.33.0/api-common-2.33.0.jar",  # com.google.api.core.ApiFuture
    "proto-google-cloud-pubsub-v1-1.130.0.jar": f"{_MVN}/com/google/api/grpc/proto-google-cloud-pubsub-v1/1.130.0/proto-google-cloud-pubsub-v1-1.130.0.jar",  # PubsubMessage proto
    # Kubernetes — fabric8 client-api + model (model-core/common for the api.model types like PodList)
    "kubernetes-client-api-6.13.1.jar": f"{_MVN}/io/fabric8/kubernetes-client-api/6.13.1/kubernetes-client-api-6.13.1.jar",
    "kubernetes-model-core-6.13.1.jar": f"{_MVN}/io/fabric8/kubernetes-model-core/6.13.1/kubernetes-model-core-6.13.1.jar",
    "kubernetes-model-common-6.13.1.jar": f"{_MVN}/io/fabric8/kubernetes-model-common/6.13.1/kubernetes-model-common-6.13.1.jar",
    # Docker — docker-java-api (the API/command interfaces; no transport jar needed to compile the fixture)
    "docker-java-api-3.3.6.jar": f"{_MVN}/com/github/docker-java/docker-java-api/3.3.6/docker-java-api-3.3.6.jar",
    # Secrets — Spring Vault (spring-core/beans/web already present) + vault-java-driver (jopenlibs fork)
    "spring-vault-core-3.1.1.jar": f"{_MVN}/org/springframework/vault/spring-vault-core/3.1.1/spring-vault-core-3.1.1.jar",
    "vault-java-driver-6.2.0.jar": f"{_MVN}/io/github/jopenlibs/vault-java-driver/6.2.0/vault-java-driver-6.2.0.jar",
    # Datastores — Redisson / etcd jetcd / Consul (orbitz)
    "redisson-3.31.0.jar": f"{_MVN}/org/redisson/redisson/3.31.0/redisson-3.31.0.jar",
    "jetcd-core-0.8.2.jar": f"{_MVN}/io/etcd/jetcd-core/0.8.2/jetcd-core-0.8.2.jar",
    "consul-client-1.5.3.jar": f"{_MVN}/com/orbitz/consul/consul-client/1.5.3/consul-client-1.5.3.jar",
    # LDAP — UnboundID LDAP SDK
    "unboundid-ldapsdk-7.0.1.jar": f"{_MVN}/com/unboundid/unboundid-ldapsdk/7.0.1/unboundid-ldapsdk-7.0.1.jar",
    # Memory-mapped file store — Chronicle Queue (+ chronicle-core/bytes/wire for the Closeable supertype/build)
    "chronicle-queue-5.25ea0.jar": f"{_MVN}/net/openhft/chronicle-queue/5.25ea0/chronicle-queue-5.25ea0.jar",
    "chronicle-core-2.25ea0.jar": f"{_MVN}/net/openhft/chronicle-core/2.25ea0/chronicle-core-2.25ea0.jar",
    "chronicle-bytes-2.25ea0.jar": f"{_MVN}/net/openhft/chronicle-bytes/2.25ea0/chronicle-bytes-2.25ea0.jar",
    "chronicle-wire-2.25ea0.jar": f"{_MVN}/net/openhft/chronicle-wire/2.25ea0/chronicle-wire-2.25ea0.jar",
    # WebDAV — Sardine
    "sardine-5.12.jar": f"{_MVN}/com/github/lookfirst/sardine/5.12/sardine-5.12.jar",
    # --- added 2026-06-20 batch 10 ---
    # Coordination/service-discovery — ZooKeeper (+ jute for the wire types) / Curator framework (+ client) / Eureka
    "zookeeper-3.9.2.jar": f"{_MVN}/org/apache/zookeeper/zookeeper/3.9.2/zookeeper-3.9.2.jar",
    "zookeeper-jute-3.9.2.jar": f"{_MVN}/org/apache/zookeeper/zookeeper-jute/3.9.2/zookeeper-jute-3.9.2.jar",
    "curator-framework-5.6.0.jar": f"{_MVN}/org/apache/curator/curator-framework/5.6.0/curator-framework-5.6.0.jar",
    "curator-client-5.6.0.jar": f"{_MVN}/org/apache/curator/curator-client/5.6.0/curator-client-5.6.0.jar",
    "eureka-client-2.0.3.jar": f"{_MVN}/com/netflix/eureka/eureka-client/2.0.3/eureka-client-2.0.3.jar",
    # Workflow — Temporal (serviceclient carries WorkflowServiceStubs; sdk for the client API surface)
    "temporal-serviceclient-1.24.1.jar": f"{_MVN}/io/temporal/temporal-serviceclient/1.24.1/temporal-serviceclient-1.24.1.jar",
    "temporal-sdk-1.24.1.jar": f"{_MVN}/io/temporal/temporal-sdk/1.24.1/temporal-sdk-1.24.1.jar",
    # Search — Apache Solr SolrJ (+ solr-common shipped inside; needs http2/jetty? the SolrParams/InputDocument
    #   types are in solr-solrj itself)
    "solr-solrj-9.6.1.jar": f"{_MVN}/org/apache/solr/solr-solrj/9.6.1/solr-solrj-9.6.1.jar",
    # More cloud — GCP Spanner / Azure Cosmos / Azure Service Bus / Azure Key Vault / GCP Secret Manager
    #   (google-cloud-core + gax + api-common already present from earlier GCP batches)
    "google-cloud-spanner-6.69.0.jar": f"{_MVN}/com/google/cloud/google-cloud-spanner/6.69.0/google-cloud-spanner-6.69.0.jar",
    "azure-cosmos-4.61.1.jar": f"{_MVN}/com/azure/azure-cosmos/4.61.1/azure-cosmos-4.61.1.jar",
    "azure-messaging-servicebus-7.17.1.jar": f"{_MVN}/com/azure/azure-messaging-servicebus/7.17.1/azure-messaging-servicebus-7.17.1.jar",
    "azure-security-keyvault-secrets-4.8.1.jar": f"{_MVN}/com/azure/azure-security-keyvault-secrets/4.8.1/azure-security-keyvault-secrets-4.8.1.jar",
    "google-cloud-secretmanager-2.43.0.jar": f"{_MVN}/com/google/cloud/google-cloud-secretmanager/2.43.0/google-cloud-secretmanager-2.43.0.jar",
    "proto-google-cloud-secretmanager-v1-2.43.0.jar": f"{_MVN}/com/google/api/grpc/proto-google-cloud-secretmanager-v1/2.43.0/proto-google-cloud-secretmanager-v1-2.43.0.jar",  # AccessSecretVersionResponse/Request protos
    # Reactive RPC — RSocket (reactor-core + reactive-streams already present)
    "rsocket-core-1.1.4.jar": f"{_MVN}/io/rsocket/rsocket-core/1.1.4/rsocket-core-1.1.4.jar",
    # Feature flags — LaunchDarkly server SDK (shaded; carries com.launchdarkly.sdk.*) / Unleash
    "launchdarkly-java-server-sdk-7.4.1.jar": f"{_MVN}/com/launchdarkly/launchdarkly-java-server-sdk/7.4.1/launchdarkly-java-server-sdk-7.4.1.jar",
    "unleash-client-java-9.2.5.jar": f"{_MVN}/io/getunleash/unleash-client-java/9.2.5/unleash-client-java-9.2.5.jar",
    # HTTP clients — Micronaut (http-client-core for BlockingHttpClient + http for HttpResponse/HttpRequest)
    "micronaut-http-client-core-4.5.1.jar": f"{_MVN}/io/micronaut/micronaut-http-client-core/4.5.1/micronaut-http-client-core-4.5.1.jar",
    "micronaut-http-4.5.1.jar": f"{_MVN}/io/micronaut/micronaut-http/4.5.1/micronaut-http-4.5.1.jar",
    "micronaut-core-4.5.1.jar": f"{_MVN}/io/micronaut/micronaut-core/4.5.1/micronaut-core-4.5.1.jar",  # io.micronaut.core.type.Argument
    # --- added 2026-06-20 batch 11 ---
    # AI/LLM clients. theokanning OpenAI (service carries OpenAiService; api carries the request/result types).
    "openai-service-0.18.2.jar": f"{_MVN}/com/theokanning/openai-gpt3-java/service/0.18.2/service-0.18.2.jar",
    "openai-api-0.18.2.jar": f"{_MVN}/com/theokanning/openai-gpt3-java/api/0.18.2/api-0.18.2.jar",
    "openai-client-0.18.2.jar": f"{_MVN}/com/theokanning/openai-gpt3-java/client/0.18.2/client-0.18.2.jar",
    # LangChain4j (core carries ChatLanguageModel + data/message/output types; open-ai carries OpenAiChatModel)
    "langchain4j-core-0.33.0.jar": f"{_MVN}/dev/langchain4j/langchain4j-core/0.33.0/langchain4j-core-0.33.0.jar",
    "langchain4j-open-ai-0.33.0.jar": f"{_MVN}/dev/langchain4j/langchain4j-open-ai/0.33.0/langchain4j-open-ai-0.33.0.jar",
    # Anthropic Java SDK — anthropic-java-CORE carries the real classes (the anthropic-java jar is a 305-byte
    #   aggregator stub with no .class files; the -core artifact is the one to compile against).
    "anthropic-java-core-0.8.0.jar": f"{_MVN}/com/anthropic/anthropic-java-core/0.8.0/anthropic-java-core-0.8.0.jar",
    # Vector DBs — Pinecone / Qdrant / Milvus (all carry their own client + proto/grpc types; guava already present
    #   supplies qdrant's ListenableFuture; protobuf-java already present supplies the *Response proto bases).
    "pinecone-client-2.0.0.jar": f"{_MVN}/io/pinecone/pinecone-client/2.0.0/pinecone-client-2.0.0.jar",
    "qdrant-client-1.9.1.jar": f"{_MVN}/io/qdrant/client/1.9.1/client-1.9.1.jar",
    "milvus-sdk-java-2.4.1.jar": f"{_MVN}/io/milvus/milvus-sdk-java/2.4.1/milvus-sdk-java-2.4.1.jar",
    # Caches/KV — Spymemcached / Xmemcached / Aerospike
    "spymemcached-2.12.3.jar": f"{_MVN}/net/spy/spymemcached/2.12.3/spymemcached-2.12.3.jar",
    "xmemcached-2.4.8.jar": f"{_MVN}/com/googlecode/xmemcached/xmemcached/2.4.8/xmemcached-2.4.8.jar",
    "aerospike-client-7.2.0.jar": f"{_MVN}/com/aerospike/aerospike-client/7.2.0/aerospike-client-7.2.0.jar",
    # Graph — Apache TinkerPop Gremlin driver (+ gremlin-core for the Traversal/Bytecode types in submit overloads)
    "gremlin-driver-3.7.2.jar": f"{_MVN}/org/apache/tinkerpop/gremlin-driver/3.7.2/gremlin-driver-3.7.2.jar",
    "gremlin-core-3.7.2.jar": f"{_MVN}/org/apache/tinkerpop/gremlin-core/3.7.2/gremlin-core-3.7.2.jar",
    # Blockchain — web3j core (carries org.web3j.protocol.core.Request/Response)
    "web3j-core-4.12.0.jar": f"{_MVN}/org/web3j/core/4.12.0/core-4.12.0.jar",
    # More cloud — Azure Event Hubs / Azure Table Storage (azure-core already present supplies BinaryData/etc.)
    "azure-messaging-eventhubs-5.18.4.jar": f"{_MVN}/com/azure/azure-messaging-eventhubs/5.18.4/azure-messaging-eventhubs-5.18.4.jar",
    "azure-data-tables-12.4.4.jar": f"{_MVN}/com/azure/azure-data-tables/12.4.4/azure-data-tables-12.4.4.jar",
    # SKIPPED: Weaviate (io.weaviate.client) — its wire terminal is a deep fluent DSL (data().creator()...run()),
    #   the run() owner is a per-builder type not WeaviateClient; same deep-DSL shape already characterized by the
    #   k8s/curator terminals. Skipped to keep the vector set lean (Pinecone/Qdrant/Milvus cover the gRPC gap).
    # SKIPPED: Anthropic-java aggregator (com.anthropic:anthropic-java:0.8.0) — 305-byte stub, no classes; use
    #   anthropic-java-core above instead.
    # --- added 2026-06-20 batch 12 ---
    # Spring AI (client-chat carries ChatClient/CallResponseSpec; openai carries OpenAiChatModel; model+commons
    #   supply Prompt/ChatResponse/ModelRequest base types). NB all FLOOR-SUPPRESSED at scan time (org.springframework.*).
    "spring-ai-client-chat-1.0.0.jar": f"{_MVN}/org/springframework/ai/spring-ai-client-chat/1.0.0/spring-ai-client-chat-1.0.0.jar",
    "spring-ai-openai-1.0.0.jar": f"{_MVN}/org/springframework/ai/spring-ai-openai/1.0.0/spring-ai-openai-1.0.0.jar",
    "spring-ai-model-1.0.0.jar": f"{_MVN}/org/springframework/ai/spring-ai-model/1.0.0/spring-ai-model-1.0.0.jar",
    "spring-ai-commons-1.0.0.jar": f"{_MVN}/org/springframework/ai/spring-ai-commons/1.0.0/spring-ai-commons-1.0.0.jar",
    # Slack (client carries MethodsClient; model carries the request/response types)
    "slack-api-client-1.40.3.jar": f"{_MVN}/com/slack/api/slack-api-client/1.40.3/slack-api-client-1.40.3.jar",
    "slack-api-model-1.40.3.jar": f"{_MVN}/com/slack/api/slack-api-model/1.40.3/slack-api-model-1.40.3.jar",
    # Discord JDA (self-contained for RestAction; okhttp already present supplies the http client)
    "JDA-5.0.0-beta.24.jar": f"{_MVN}/net/dv8tion/JDA/5.0.0-beta.24/JDA-5.0.0-beta.24.jar",
    # Telegram bots — the META jar carries AbsSender + SendMessage (the synchronous Bot-API send terminal)
    "telegrambots-meta-6.9.7.1.jar": f"{_MVN}/org/telegram/telegrambots-meta/6.9.7.1/telegrambots-meta-6.9.7.1.jar",
    # Keycloak admin client + keycloak-core (UserRepresentation) + jakarta.ws.rs-api (Response on create())
    "keycloak-admin-client-24.0.5.jar": f"{_MVN}/org/keycloak/keycloak-admin-client/24.0.5/keycloak-admin-client-24.0.5.jar",
    "keycloak-core-24.0.5.jar": f"{_MVN}/org/keycloak/keycloak-core/24.0.5/keycloak-core-24.0.5.jar",
    "jakarta.ws.rs-api-3.1.0.jar": f"{_MVN}/jakarta/ws/rs/jakarta.ws.rs-api/3.1.0/jakarta.ws.rs-api-3.1.0.jar",
    # Okta SDK api (carries com.okta.sdk.resource.client.ApiClient — the generic invokeAPI wire leaf)
    "okta-sdk-api-15.0.0.jar": f"{_MVN}/com/okta/sdk/okta-sdk-api/15.0.0/okta-sdk-api-15.0.0.jar",
    # Braintree (self-contained — carries BraintreeGateway/TransactionGateway/util.Http)
    "braintree-java-3.25.0.jar": f"{_MVN}/com/braintreepayments/gateway/braintree-java/3.25.0/braintree-java-3.25.0.jar",
    # Mailgun (net.sargue fork — Mail.send over jakarta.ws.rs; jakarta.ws.rs-api above supplies the client types)
    "mailgun-2.0.0.jar": f"{_MVN}/net/sargue/mailgun/2.0.0/mailgun-2.0.0.jar",
    # Google Maps services (carries GeoApiContext/GeocodingApi/PendingResult; okhttp+gson under the hood)
    "google-maps-services-2.2.0.jar": f"{_MVN}/com/google/maps/google-maps-services/2.2.0/google-maps-services-2.2.0.jar",
    # ClickHouse native client (carries ClickHouseClient/ClickHouseRequest/ClickHouseNode). JDBC is java.sql-covered.
    "clickhouse-client-0.6.0.jar": f"{_MVN}/com/clickhouse/clickhouse-client/0.6.0/clickhouse-client-0.6.0.jar",
    # --- added 2026-06-20 batch 13 ---
    # SPRING-ECOSYSTEM FLOOR sweep (all org.springframework.* — floor-dropped at scan time):
    # Spring Integration core (MessagingTemplate; spring-messaging already present supplies MessageChannel/Message).
    "spring-integration-core-6.3.1.jar": f"{_MVN}/org/springframework/integration/spring-integration-core/6.3.1/spring-integration-core-6.3.1.jar",
    # Spring Batch (core carries JobLauncher/Job/JobParameters/JobExecution; infrastructure is a compile dep).
    "spring-batch-core-5.1.2.jar": f"{_MVN}/org/springframework/batch/spring-batch-core/5.1.2/spring-batch-core-5.1.2.jar",
    "spring-batch-infrastructure-5.1.2.jar": f"{_MVN}/org/springframework/batch/spring-batch-infrastructure/5.1.2/spring-batch-infrastructure-5.1.2.jar",
    # Spring Cloud OpenFeign (FeignBlockingLoadBalancerClient; feign-core already present supplies feign.Client/Request/Response).
    "spring-cloud-openfeign-core-4.1.3.jar": f"{_MVN}/org/springframework/cloud/spring-cloud-openfeign-core/4.1.3/spring-cloud-openfeign-core-4.1.3.jar",
    # Spring Data Elasticsearch (ElasticsearchOperations + query.Query/SearchHits; spring-data-commons already present).
    "spring-data-elasticsearch-5.3.1.jar": f"{_MVN}/org/springframework/data/spring-data-elasticsearch/5.3.1/spring-data-elasticsearch-5.3.1.jar",
    # Spring Data Neo4j (Neo4jTemplate; neo4j-java-driver + spring-data-commons already present).
    "spring-data-neo4j-7.3.1.jar": f"{_MVN}/org/springframework/data/spring-data-neo4j/7.3.1/spring-data-neo4j-7.3.1.jar",
    # Spring LDAP (LdapTemplate + AttributesMapper).
    "spring-ldap-core-3.2.4.jar": f"{_MVN}/org/springframework/ldap/spring-ldap-core/3.2.4/spring-ldap-core-3.2.4.jar",
    # Spring Session (SessionRepository/Session/MapSessionRepository).
    "spring-session-core-3.3.1.jar": f"{_MVN}/org/springframework/session/spring-session-core/3.3.1/spring-session-core-3.3.1.jar",
    # NON-Spring datastores (these surface the `invisible:[pkg]` disclosure, NOT the floor):
    # OrientDB (orientdb-core is self-contained for ODatabaseSession.query/command + OResultSet).
    "orientdb-core-3.2.30.jar": f"{_MVN}/com/orientechnologies/orientdb-core/3.2.30/orientdb-core-3.2.30.jar",
    # RethinkDB (rethinkdb-driver carries ReqlExpr/RethinkDB/Connection; jackson already present is its compile dep).
    "rethinkdb-driver-2.4.4.jar": f"{_MVN}/com/rethinkdb/rethinkdb-driver/2.4.4/rethinkdb-driver-2.4.4.jar",
    # ArangoDB — the com.arangodb:CORE artifact (408 classes incl. ArangoDatabase). The published
    #   com.arangodb:arangodb-java-driver jar is a 19-entry shaded aggregator STUB (no .class files) — skipped.
    "arangodb-core-7.7.1.jar": f"{_MVN}/com/arangodb/core/7.7.1/core-7.7.1.jar",
    # H2 (org.h2.mvstore.MVStore lives in the main h2 jar — native MVStore engine; JDBC is java.sql-covered).
    "h2-2.2.224.jar": f"{_MVN}/com/h2database/h2/2.2.224/h2-2.2.224.jar",
    # --- added 2026-06-20 batch 14 ---
    # HTTP SERVER frameworks (each self-contained for the .start()/.init() leaf — verified to compile against
    #   their own + already-present deps; slf4j already present).
    "javalin-6.1.6.jar": f"{_MVN}/io/javalin/javalin/6.1.6/javalin-6.1.6.jar",
    "spark-core-2.9.4.jar": f"{_MVN}/com/sparkjava/spark-core/2.9.4/spark-core-2.9.4.jar",
    "undertow-core-2.3.13.Final.jar": f"{_MVN}/io/undertow/undertow-core/2.3.13.Final/undertow-core-2.3.13.Final.jar",
    # Eclipse Jetty SERVER (jetty-util/http/io already present from the batch-8 jetty-client).
    "jetty-server-12.0.10.jar": f"{_MVN}/org/eclipse/jetty/jetty-server/12.0.10/jetty-server-12.0.10.jar",
    # Streaming — Kafka Streams (kafka-clients already present).
    "kafka-streams-3.7.1.jar": f"{_MVN}/org/apache/kafka/kafka-streams/3.7.1/kafka-streams-3.7.1.jar",
    # Datastore/cache — Apache Geode (Region extends ConcurrentMap; owner-scoped rule fabrication-safe).
    "geode-core-1.15.1.jar": f"{_MVN}/org/apache/geode/geode-core/1.15.1/geode-core-1.15.1.jar",
    # Document — docx4j (core is self-contained for WordprocessingMLPackage.load/save).
    "docx4j-core-11.4.11.jar": f"{_MVN}/org/docx4j/docx4j-core/11.4.11/docx4j-core-11.4.11.jar",
    # Media — ffmpeg wrapper (commons-lang3 + gson already present supply its compile deps).
    "ffmpeg-0.8.0.jar": f"{_MVN}/net/bramp/ffmpeg/ffmpeg/0.8.0/ffmpeg-0.8.0.jar",
    # Media — ZXing core (in-memory barcode math = pure anchors).
    "zxing-core-3.5.3.jar": f"{_MVN}/com/google/zxing/core/3.5.3/core-3.5.3.jar",
    # Templating — Handlebars / mustache.java / Pebble / JMustache (slf4j already present).
    "handlebars-4.4.0.jar": f"{_MVN}/com/github/jknack/handlebars/4.4.0/handlebars-4.4.0.jar",
    "mustache-compiler-0.9.14.jar": f"{_MVN}/com/github/spullara/mustache/java/compiler/0.9.14/compiler-0.9.14.jar",
    "pebble-3.2.2.jar": f"{_MVN}/io/pebbletemplates/pebble/3.2.2/pebble-3.2.2.jar",
    "jmustache-1.16.jar": f"{_MVN}/com/samskivert/jmustache/1.16/jmustache-1.16.jar",
    # Email — SimpleJavaMail (the api.* types live in the CORE-MODULE jar, not the impl jar).
    "simplejavamail-core-module-8.11.3.jar": f"{_MVN}/org/simplejavamail/core-module/8.11.3/core-module-8.11.3.jar",
    # ML/native — ONNX Runtime (94 MB single self-contained jar; native libs bundled — see report note) +
    #   Stanford CoreNLP (8.5 MB, self-contained for the StanfordCoreNLP(String) model-loading ctor).
    "onnxruntime-1.18.0.jar": f"{_MVN}/com/microsoft/onnxruntime/onnxruntime/1.18.0/onnxruntime-1.18.0.jar",
    "stanford-corenlp-4.5.7.jar": f"{_MVN}/edu/stanford/nlp/stanford-corenlp/4.5.7/stanford-corenlp-4.5.7.jar",
    # SKIPPED: Apache FOP — only testable leaf is FopFactory.newFop(mime, OutputStream) = a caller-stream pure
    #   anchor (redundant) and it needs xmlgraphics-commons; noted, not added. Ratpack / DJL skipped (heavy trees).
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
        # -proc:none: some jars on the classpath (e.g. spring-data-couchbase) ship a querydsl annotation
        # Processor service file; the probe only needs type resolution, never annotation processing.
        jc = subprocess.run(["javac", "-proc:none", "-cp", cp, "-d", cls, src], capture_output=True, text=True)
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
        # per-function `invisible:[pkg]` disclosure (a κ-unknown package candor is honest it can't see
        # through) — distinct from the Spring FLOOR (silent drop) and from a fabricated effect.
        invisible = {e["fn"].split("(")[0]: e.get("invisible", []) for e in fns if isinstance(e, dict)}
        present = set(inferred.keys())

    # FLOOR detection: candor treats org.springframework.* as a κ-COVERED prefix, so a Spring leaf it does
    # NOT model is DROPPED from the report ENTIRELY (silently absent — not even an `invisible` disclosure),
    # strictly worse than a normal silent-pure. A leaf is FLOOR-SUPPRESSED iff it is ABSENT from the report
    # AND its call-site owner is org.springframework.* (i.e. the case touches a Spring type). This is the
    # structural finding this batch maps. (Genuinely-pure functions are ALSO absent, but a Spring leaf that
    # really does I/O being absent == the floor hid a real effect; the non-Spring equivalent would surface
    # an `invisible:[pkg]` disclosure instead of vanishing.)
    # κ-COVERED prefixes: candor treats these namespaces as "known", so it SUPPRESSES the `invisible:[pkg]`
    # disclosure for them. An UNMODELED effectful member of a covered prefix is therefore DROPPED from the
    # report ENTIRELY (silently absent — no effect, no invisible, no unknownWhy), strictly worse than a normal
    # silent-pure. org.springframework.* is one such prefix; the JDK prefixes (java.*/javax.*/jakarta.*/kotlin.*)
    # are the others. A leaf is FLOOR-SUPPRESSED iff it is ABSENT from the report AND its call-site owner is a
    # covered prefix. (Genuinely-pure functions are ALSO absent, but a covered-prefix leaf that really does I/O
    # being absent == the floor hid a real effect; a NON-covered package would surface `invisible:[pkg]` instead.)
    COVERED = ("org.springframework", "java.", "javax.", "jakarta.", "kotlin.")

    def covered_owner(params, body):
        text = params + " " + body
        return any(p in text for p in COVERED)

    def floor_state(name, params, body):
        """STATE column: '' (present, effect/Unknown — ok), 'INVIS' (present + invisible disclosure — sound,
        low-value precision gap), 'SILENT' (present but inferred=[] AND no invisible AND no unknownWhy — a
        cardinal sin: candor thinks it is pure), 'FLOOR' (ABSENT + covered-prefix owner — the floor silently
        dropped a real effect, the worst kind), 'drop' (ABSENT + non-covered owner — genuinely pure/omitted)."""
        key = "KL." + name
        if key in present:
            if invisible.get(key):
                return "INVIS"
            return "" if inferred.get(key) else "SILENT"
        return "FLOOR" if covered_owner(params, body) else "drop"

    rows, gaps, fabs, floored = [], [], [], []
    for name, eff, params, body in EFFECT_CASES:
        got = inferred.get("KL." + name, [])
        fs = floor_state(name, params, body)
        ok = eff in got or "Unknown" in got
        verdict = f"ok({eff})" if eff in got else ("ok(Unknown)" if "Unknown" in got else "GAP")
        rows.append((name, eff, got or [], fs, verdict))
        if not ok:
            tag = {"FLOOR": "FLOOR-SUPPRESSED", "SILENT": "SILENT-PURE",
                   "INVIS": "INVISIBLE-pkg"}.get(fs, "GAP")
            gaps.append(f"  {tag}  KL.{name} [{body}] -> "
                        f"{got or (invisible.get('KL.'+name) and 'invisible:'+str(invisible['KL.'+name]) or 'pure/DROPPED')}"
                        f"  (must surface {eff} or Unknown)")
            if fs in ("FLOOR", "SILENT"):
                floored.append(f"{fs}:{name}")
    for name, body, params in PURE_CASES:
        got = inferred.get("KL." + name, [])
        fs = floor_state(name, params, body)
        rows.append((name, "(pure)", got or [], fs, "ok(pure)" if not got else "FABRICATION"))
        if got:
            fabs.append(f"  FABRICATION  KL.{name} [{body}] -> {got}  (must stay pure)")

    w = max(len(r[0]) for r in rows)
    print(f"{'leaf'.ljust(w)}  {'expect':8}  {'candor':22}  {'FLOOR?':6}  verdict")
    print("-" * (w + 48))
    for name, eff, got, fs, verdict in rows:
        print(f"{name.ljust(w)}  {eff:8}  {str(got)[:22]:22}  {fs:6}  {verdict}")

    n = len(EFFECT_CASES) + len(PURE_CASES)
    if floored:
        print(f"\nkappa-libs: {len(floored)} CARDINAL-SIN leaf(s) — a κ-covered prefix "
              f"(org.springframework.*/java.*/javax.*/jakarta.*) hid a real effect (silent, no `invisible` "
              f"disclosure, no unknownWhy — candor thinks it is pure):")
        for f in floored:
            print(f"  {f.split(':',1)[0]}  KL.{f.split(':',1)[1]}")
    if gaps or fabs:
        print(f"\nkappa-libs: {len(gaps)} coverage gap(s) ({len(floored)} of them SILENT/FLOOR cardinal sins), "
              f"{len(fabs)} over-classification(s) of {n} library leaves:")
        for g in gaps + fabs:
            print(g)
        sys.exit(1)
    print(f"\nkappa-libs: OK — {len(EFFECT_CASES)} library effect leaves classified "
          f"(slf4j/log4j/jackson/commons-io/commons-exec/guava/okhttp/httpclient5/spring/poi/"
          f"jpa/mongo/jedis/kafka/jsoup/aws-s3/grpc/webclient/restclient/hibernate/"
          f"cassandra/mybatis/jooq/rabbitmq/jms/spring-amqp/aws-dynamo-sqs-sns/retrofit/httpclient4/"
          f"gcp-bigquery-firestore-pubsub/k8s/docker/vault/redisson/jetcd/consul/ldap/chronicle/sardine/+gaps), "
          f"{len(PURE_CASES)} pure neighbours unflooded")


if __name__ == "__main__":
    main()
