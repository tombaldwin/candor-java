package io.poly.candor;

import java.util.*;
import java.util.stream.Collectors;
import org.objectweb.asm.tree.*;
import io.poly.candor.model.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Candor.*;

/** The engine's CURATED RULE TABLES — the declarative knowledge the scan consults, split out of
 *  Candor so the code (the mechanism) and the tables (the policy/knowledge) read separately:
 *  framework markers (Spring/Jakarta/Micronaut/Panache persistence, Feign + declarative HTTP
 *  clients), the entry-point rooting annotations and RUNTIME_OVERRIDES rows, the executor/CF/timer
 *  hand-off verb sets, the effect vocabularies (AS-EFF-004/007/008), the structural-indy bootstrap
 *  set, the bounded-CHA limit, and the κ-coverage prefix ledger. Table-interpreting predicates
 *  (isSpringDataRepoBase, inheritsArDbVerb, isHttpClientType, …) live beside their tables.
 *  Everything here is package-private and referenced via {@code import static io.poly.candor.Rules.*}
 *  — pure code motion from Candor.java (byte-identical output). */
final class Rules {
    private Rules() {}

    // --- Spring markers (internal names / annotation-desc substrings) ---
    static final Set<String> REPO_MARKERS = Set.of(
            "org/springframework/data/repository/Repository",
            "org/springframework/data/repository/CrudRepository",
            "org/springframework/data/repository/ListCrudRepository",
            "org/springframework/data/repository/PagingAndSortingRepository",
            "org/springframework/data/jpa/repository/JpaRepository");
    /** Any Spring Data repository BASE interface — under `org/springframework/data/` and ending in
     *  `Repository`. Covers JPA, reactive (ReactiveCrudRepository), and every store module
     *  (Mongo/Cassandra/Elasticsearch/R2dbc)
     *  without enumerating each: the framework bases all live under this package and end in "Repository".
     *  REPO_MARKERS stays as the JPA/JDBC-core fast set; this catches the rest (those bases are framework
     *  interfaces NOT in the scanned classes, so the transitive marker chain breaks at them → silent-pure
     *  inherited CRUD on reactive/NoSQL repos). */
    static boolean isSpringDataRepoBase(String internal) {
        return internal.startsWith("org/springframework/data/") && internal.endsWith("Repository");
    }
    /** Any Jakarta Data repository BASE interface — under `jakarta/data/repository/` and ending in
     *  `Repository` (DataRepository/BasicRepository/CrudRepository/PageableRepository). The Hibernate-6-era
     *  analog of {@link #isSpringDataRepoBase}: a project interface `extends CrudRepository<Fruit,Integer>`
     *  is the persistence boundary, but its CRUD methods are inherited from a framework base NOT in the
     *  scanned classes (so the marker chain breaks there → silent-pure inherited CRUD). Detecting the base
     *  promotes such project interfaces into repoTypes, exactly as for Spring Data. */
    static boolean isJakartaDataRepoBase(String internal) {
        return internal.startsWith("jakarta/data/repository/") && internal.endsWith("Repository");
    }
    /** A Quarkus Panache REPOSITORY base — `io.quarkus.*.panache.*Repository[Base]` (hibernate-orm,
     *  reactive, and mongodb variants). A project interface extending one is promoted into repoTypes (like
     *  Spring/Jakarta Data), so its inherited CRUD calls attribute Db instead of reading silent-pure. */
    static boolean isPanacheRepoBase(String internal) {
        // EXTERNAL only (`!byName`): the `/panache/` substring is loose, so without this a project's OWN
        // interface in a `…/panache/…Repository` package would be promoted into repoTypes → fabricated Db.
        // The framework's real base is a dependency (never scanned), so it's correctly external. (code-review)
        return !ctx().byName.containsKey(internal) && internal.contains("/panache/")
                && (internal.endsWith("Repository") || internal.endsWith("RepositoryBase"));
    }
    /** An EXTERNAL Quarkus Panache ENTITY base — `io.quarkus.*.panache.*Entity[Base]` (active-record). The
     *  `!byName` gate stops a project's own `…/panache/…Entity` class from self-matching the loose substring
     *  and fabricating Db; the real base is always an unscanned dependency. */
    static boolean isPanacheEntityBase(String internal) {
        return !ctx().byName.containsKey(internal) && internal.contains("/panache/")
                && (internal.endsWith("Entity") || internal.endsWith("EntityBase"));
    }
    /** Owner's type hierarchy includes an external Panache entity base (or IS one) — the active-record marker. */
    static boolean extendsPanacheEntity(String internalOwner) {
        if (isPanacheEntityBase(internalOwner)) return true;
        for (String s : transSupers(internalOwner)) if (isPanacheEntityBase(s)) return true;
        return false;
    }
    /** Panache ACTIVE-RECORD persistence + finder verbs that EXECUTE, inherited from the entity base. Gated by
     *  {@link #extendsPanacheEntity}, so a project method merely named `persist`/`list` is untouched. NB `find`
     *  is excluded — it's a LAZY builder returning a PanacheQuery (no DB until a terminal); the PanacheQuery
     *  terminal classify rule attributes the actual round-trip, so listing `find` here over-reported a pure call. */
    static final Set<String> PANACHE_ENTITY_VERBS = Set.of(
            "persist", "delete", "flush", "persistAndFlush", "update",
            "listAll", "list", "findAll", "findById", "findByIdOptional",
            "count", "deleteAll", "deleteById", "stream", "streamAll");
    /** A Micronaut Data repository BASE interface — `io.micronaut.data.repository.**Repository` (incl. the
     *  reactive sub-package). Mirrors {@link #isSpringDataRepoBase}: a project sub-interface is promoted into
     *  repoTypes so its inherited CRUD attributes Db instead of reading silent-pure. */
    static boolean isMicronautDataRepoBase(String internal) {
        return internal.startsWith("io/micronaut/data/repository/") && internal.endsWith("Repository");
    }
    /** Active-record / DAO base CLASSES whose persistence verbs, INHERITED into a project subtype, are Db: the
     *  call-site owner is the PROJECT class (`customer.save()`), so neither classify (keyed on the base) nor
     *  repoTypes fires, and the inherited body lives in the framework (unscanned) → silent-pure (the same shape
     *  as Panache active-record). Keyed by the base's internal name → its DB verb set, so a verb valid for one
     *  base doesn't fire for another. Found by a dogfood probe (Ebean/ActiveJDBC/jOOQ DAO read silent-pure). */
    static final Map<String, Set<String>> AR_DB_BASES = Map.of(
            "io/ebean/Model", Set.of("save", "delete", "update", "insert", "refresh", "deletePermanent", "markAsDirty"),
            "org/javalite/activejdbc/Model", Set.of("save", "saveIt", "insert", "delete", "deleteCascade",
                    "deleteAll", "findAll", "findById", "where", "count", "first", "findFirst", "findBySQL"),
            "org/jooq/impl/DAOImpl", Set.of("insert", "update", "delete", "merge", "findById", "findAll",
                    "fetch", "fetchOne", "fetchOptional", "fetchRange", "exists", "count"));
    /** Does this call inherit a Db persistence verb from an active-record/DAO base (AR_DB_BASES)? Checks the
     *  owner itself and its supertypes; per-base verb gating avoids cross-base false positives. */
    static boolean inheritsArDbVerb(String internalOwner, String method) {
        Set<String> v = AR_DB_BASES.get(internalOwner);
        if (v != null && v.contains(method)) return true;
        for (String s : transSupers(internalOwner)) {
            Set<String> sv = AR_DB_BASES.get(s);
            if (sv != null && sv.contains(method)) return true;
        }
        return false;
    }
    /** Curated JVM model-provider SDK packages — the SPEC §1 ⟨0.13⟩ `Llm` model-SDK surface. A call
     *  resolving into one of these packages' request-dispatch surfaces classifies `Llm` + `Net` (the
     *  client dispatches a request → it IS network I/O, exactly as {@link Literals#modelHostEffects}
     *  keeps Net on a model-host literal). DOTTED package prefixes (the owner is dotted at the call site).
     *  A curated STARTER list — the §7 coverage ledger discloses an uncovered provider package like any
     *  other; the sibling engines share the same starter set. Mirrors the AR_DB_BASES / declarative-HTTP
     *  approach: package-prefix → boundary effect, no method-name gating (any call into these clients is a
     *  model dispatch; the clients are single-purpose). */
    static final List<String> MODEL_SDK_PACKAGES = List.of(
            "software.amazon.awssdk.services.bedrockruntime.",   // AWS Bedrock runtime (v2 SDK)
            "com.amazonaws.services.bedrockruntime.",            // AWS Bedrock runtime (v1 SDK)
            "dev.langchain4j.model.",                            // langchain4j chat/embedding model invoke surfaces
            "com.openai.",                                       // openai-java (official)
            "com.theokanning.openai.",                          // openai-java (theokanning community client)
            "org.springframework.ai.",                           // Spring AI ChatClient/EmbeddingClient
            "com.google.cloud.vertexai.",                        // Google Vertex AI
            "com.google.genai.");                                // Google GenAI SDK

    /** Whether a resolved call OWNER (dotted) is a curated model-provider SDK surface (MODEL_SDK_PACKAGES)
     *  → the SPEC §1 ⟨0.13⟩ `Llm` model-SDK classification (the caller also gets `Net`). */
    static boolean isModelSdkOwner(String dottedOwner) {
        for (String p : MODEL_SDK_PACKAGES)
            if (dottedOwner.startsWith(p)) return true;
        return false;
    }

    static final String TX = "springframework/transaction/annotation/Transactional";
    static final String SCHEDULED = "springframework/scheduling/annotation/Scheduled";
    // Jackson invokes a @JsonCreator-annotated constructor/factory REFLECTIVELY during deserialization,
    // with no in-project call site — an effectful creator body (validation that logs, a resource opened
    // on construction) is orphaned from every root, the serialization-callback shape. Root it.
    static final String JSON_CREATOR = "JsonCreator";
    static final String FEIGN = "openfeign/FeignClient";
    // Declarative HTTP-client interfaces — the proxy makes the wire call, the user interface has no body, so a
    // call to such an interface is Net (the OpenFeign analog for the rest of the ecosystem; turns the honest
    // `Unknown` these read into precise Net so `deny Net <layer>` catches them). TYPE-annotated families +
    // METHOD-annotated ones (Retrofit verbs, Spring HTTP-interface `@*Exchange`).
    static final List<String> HTTP_CLIENT_TYPE_ANNOS = List.of(
            "micronaut/http/client/annotation/Client",                 // Micronaut @Client
            "microprofile/rest/client/inject/RegisterRestClient",      // MicroProfile Rest Client
            "springframework/web/service/annotation/HttpExchange");    // Spring 6 HTTP interface (on the type)
    static final List<String> HTTP_CLIENT_METHOD_ANNOS = List.of(
            "retrofit2/http/",                                         // Retrofit @GET/@POST/@PUT/@DELETE/@HTTP/…
            "springframework/web/service/annotation/");               // Spring @GetExchange/@PostExchange/…
    /** A declarative HTTP-client interface: a recognized client TYPE annotation, or any method carrying a
     *  client METHOD annotation (Retrofit verb / Spring `@*Exchange`). Server-side annotations live in other
     *  packages (`web/bind/annotation` for Spring MVC, JAX-RS `@Path` resources), so no false positives. */
    static boolean isHttpClientType(ClassNode cn) {
        if (annoPresentAny(cn.visibleAnnotations, HTTP_CLIENT_TYPE_ANNOS)) return true;
        if (cn.methods != null)
            for (MethodNode mn : cn.methods)
                if (annoPresentAny(mn.visibleAnnotations, HTTP_CLIENT_METHOD_ANNOS)) return true;
        return false;
    }
    // Ambient authorities for AS-EFF-004 / CANDOR_NO_AMBIENT — the spec's `Ambient = 𝔼 \ {Log}`
    // (SEMANTICS.md §, every effect except cross-cutting Log; Unknown is not an authority). Was missing
    // Ipc + Clipboard, so direct Unix-socket/clipboard reaches slipped the no-ambient check (the Rust
    // reference flags them).
    // AS-EFF-004 ambient authority = 𝔼 \ {Log} (the model's spec-defined set).
    static final Set<Effect> AMBIENT = Effect.AMBIENT_AUTHORITY;
    // The effect vocabulary candor-java emits — spec §1. KNOWN_EFFECTS stays a NAME set: it validates
    // raw policy/query TOKEN strings (parsePolicy, Query.whatif), not effect-set membership.
    static final Set<String> KNOWN_EFFECTS =
            Effect.KNOWN.stream().map(Effect::specName).collect(Collectors.toUnmodifiableSet());
    // AS-EFF-007 (CANDOR_TAINT): the injection-class effects whose argument, if caller-derived, is an
    // injection surface (path traversal / command / SQL / SSRF). Clock/Rand/Log/Clipboard aren't injectable.
    static final Set<Effect> INJECTION = Effect.INJECTION;
    // java.io types whose <init> takes a file PATH as its first String arg (for AS-EFF-008 `paths`).
    static final Set<String> PATH_CTOR_OWNERS = Set.of("java.io.File", "java.io.FileInputStream",
            "java.io.FileOutputStream", "java.io.FileReader", "java.io.FileWriter", "java.io.RandomAccessFile",
            // java.util.logging.FileHandler(String pattern) opens the named log file — its path must reach the
            // AS-EFF-008 surface, else a forbidden log path (e.g. /etc/shadow.copy) is invisible and a benign
            // co-located Fs literal MASKS it (a gate evasion — the 0.5.27 FileHandler Fs rule without surfacing).
            "java.util.logging.FileHandler");

    /** The JVM's STRUCTURAL invokedynamic bootstrap factories: lambda/method-ref creation, string
     *  concatenation, record ObjectMethods (equals/hashCode/toString), pattern-switch, and
     *  constant-dynamic. An indy whose bootstrap is NONE of these is dynamic-language dispatch
     *  (Groovy `IndyInterface`, JRuby, …) — opaque like reflection, so it raises Unknown rather than
     *  going silent-pure. */
    static final Set<String> STRUCTURAL_INDY_BSM = Set.of(
            "java/lang/invoke/LambdaMetafactory",
            "java/lang/invoke/StringConcatFactory",
            "java/lang/runtime/ObjectMethods",
            "java/lang/runtime/SwitchBootstraps",
            "java/lang/invoke/ConstantBootstraps");

    // entry-point annotation substrings (HTTP mappings + message listeners + container-invoked methods).
    // Each names a method the FRAMEWORK invokes with no in-project call site (Spring proxy, JAX-RS/Micronaut
    // container, AspectJ weaver, Kafka listener container, @Bean factory at startup) — so an effectful body
    // is orphaned from every reachability root without rooting it (the finalize shape). Rooting is sound,
    // never fabrication: each is genuinely framework-invoked. Substrings cover javax/ + jakarta/ variants.
    static final List<String> MAPPING_OR_LISTENER = List.of(
            "web/bind/annotation/RequestMapping", "web/bind/annotation/GetMapping",
            "web/bind/annotation/PostMapping", "web/bind/annotation/PutMapping",
            "web/bind/annotation/DeleteMapping", "web/bind/annotation/PatchMapping",
            "kafka/annotation/KafkaListener", "amqp/rabbit/annotation/RabbitListener",
            "jms/annotation/JmsListener", "context/event/EventListener",
            // Spring @Async (proxy invokes it on another thread, decoupled from the call site) + @Bean
            // factory methods (Spring calls them at context startup) + the multi-method @KafkaHandler form.
            "scheduling/annotation/Async", "context/annotation/Bean", "kafka/annotation/KafkaHandler",
            // JAX-RS / Jakarta REST resource methods (container-invoked) — covers javax.ws.rs + jakarta.ws.rs.
            "ws/rs/GET", "ws/rs/POST", "ws/rs/PUT", "ws/rs/DELETE", "ws/rs/PATCH", "ws/rs/HEAD", "ws/rs/Path",
            // Micronaut HTTP controller methods (container-invoked).
            "micronaut/http/annotation/Get", "micronaut/http/annotation/Post",
            "micronaut/http/annotation/Put", "micronaut/http/annotation/Delete",
            "micronaut/http/annotation/Patch",
            // AspectJ advice — the weaver invokes it at every matched join point; effectful advice (audit
            // logging, metrics push) has no in-project call site.
            "aspectj/lang/annotation/Around", "aspectj/lang/annotation/Before",
            "aspectj/lang/annotation/After", "aspectj/lang/annotation/AfterReturning",
            "aspectj/lang/annotation/AfterThrowing",
            // Event-bus subscribers — the bus invokes the @Subscribe method on event delivery with no
            // project call site (the @EventListener shape). Guava EventBus (`common/eventbus/Subscribe`)
            // + Greenrobot EventBus (`greenrobot/eventbus/Subscribe`, method-name `onEvent*` historically
            // but @Subscribe in v3). A handler that persists/pushes is otherwise orphaned.
            "common/eventbus/Subscribe", "greenrobot/eventbus/Subscribe",
            // Spring Integration @ServiceActivator (the EIP handler the messaging runtime invokes) + the
            // related endpoint annotations; Spring Shell @ShellMethod (the shell invokes it per command).
            "integration/annotation/ServiceActivator", "integration/annotation/Transformer",
            "integration/annotation/Filter", "integration/annotation/Router",
            "integration/annotation/Splitter", "shell/standard/ShellMethod");

    /** Container-invoked bean lifecycle callbacks (`@PostConstruct` init, `@PreDestroy` shutdown). Like
     *  the mappings/listeners they're called by the framework with no project call site — a `@PreDestroy`
     *  that flushes/closes does real I/O at shutdown. The substring matches both `javax/` and `jakarta/`. */
    static final List<String> LIFECYCLE = List.of(
            "annotation/PostConstruct", "annotation/PreDestroy",
            // JPA entity lifecycle callbacks — invoked by the persistence provider (Hibernate/…) on
            // persist/load/update/remove events, no project call site. An @PrePersist that stamps audit
            // fields or an @PostLoad that fetches does real I/O. Covers javax/ and jakarta/ persistence.
            "persistence/PrePersist", "persistence/PostPersist", "persistence/PreUpdate",
            "persistence/PostUpdate", "persistence/PreRemove", "persistence/PostRemove",
            "persistence/PostLoad");

    static final List<String[]> RUNTIME_OVERRIDES = List.of(
            // {supertype-substring, method, descriptor}
            new String[] {"java/lang/Runnable", "run", "()V"},
            new String[] {"java/lang/Thread", "run", "()V"},
            new String[] {"java/util/concurrent/Callable", "call", "()Ljava/lang/Object;"},
            // Spring bean lifecycle (interface form of @PostConstruct/@PreDestroy) + startup runners.
            new String[] {"springframework/beans/factory/InitializingBean", "afterPropertiesSet", "()V"},
            new String[] {"springframework/beans/factory/DisposableBean", "destroy", "()V"},
            new String[] {"springframework/boot/CommandLineRunner", "run", "([Ljava/lang/String;)V"},
            new String[] {"springframework/boot/ApplicationRunner", "run",
                    "(Lorg/springframework/boot/ApplicationArguments;)V"},
            // Servlet container lifecycle (raw servlets/filters/listeners — Spring MVC uses @*Mapping).
            new String[] {"servlet/http/HttpServlet", "doGet", null},
            new String[] {"servlet/http/HttpServlet", "doPost", null},
            new String[] {"servlet/http/HttpServlet", "doPut", null},
            new String[] {"servlet/http/HttpServlet", "doDelete", null},
            new String[] {"servlet/http/HttpServlet", "service", null},
            new String[] {"servlet/Filter", "doFilter", null},
            new String[] {"servlet/ServletContextListener", "contextInitialized", null},
            new String[] {"servlet/ServletContextListener", "contextDestroyed", null},
            // Function-interface bodies: a Kotlin/Scala/Groovy lambda or a NAMED class implementing
            // one is invoked by whatever higher-order function received it (often external) — a
            // runtime-invoked root, like a Runnable. Marking them entry points is what keeps a named
            // implementor's I/O from being orphaned when bounded CHA drops the broad fan-out (the
            // /code-review finding). `iface` matches as a substring, so "kotlin/jvm/functions/Function"
            // covers Function0..Function22 and "scala/Function" covers Function0..N.
            new String[] {"kotlin/jvm/functions/Function", "invoke", null},
            new String[] {"scala/Function", "apply", null},
            new String[] {"scala/PartialFunction", "apply", null},
            new String[] {"groovy/lang/Closure", "call", null},
            // JDK reflective/runtime invocation — the runtime calls these on a project IMPLEMENTOR with no
            // in-project call site, so an effectful body is orphaned from every root (the finalize/
            // serialization shape). `Comparator.compare`/`Comparable.compareTo` are invoked by the sort
            // machinery (Collections.sort, stream.sorted, TreeMap/TreeSet); `InvocationHandler.invoke` by
            // the JDK dynamic-proxy runtime. GATED on actually implementing the interface (the supertype
            // filter above), so a same-named method on an unrelated class is never fabricated as a root.
            // A null descriptor on compare/compareTo also roots the synthetic erased BRIDGE — sound, since
            // the bridge forwards to the typed body. (compareTo stays CHA-exempt for DISPATCH fan-out — a
            // separate concern from rooting its own effects.)
            new String[] {"java/util/Comparator", "compare", null},
            new String[] {"java/lang/Comparable", "compareTo", null},
            new String[] {"java/lang/reflect/InvocationHandler", "invoke",
                    "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;"},
            // Bean Validation: the validator runtime invokes isValid on a project ConstraintValidator with
            // no in-project call site (covers javax/ + jakarta/ via the substring).
            new String[] {"validation/ConstraintValidator", "isValid", null},
            // java.util.TimerTask is scheduled and run by a Timer thread. It implements Runnable, so the
            // Runnable row would cover it ONCE transSupers walks the external TimerTask supertype — but root
            // it explicitly too (cheap, and independent of external-supertype resolution being available).
            new String[] {"java/util/TimerTask", "run", "()V"},
            // Servlet async lifecycle callbacks — the container invokes them on a registered AsyncListener.
            new String[] {"servlet/AsyncListener", "onComplete", null},
            new String[] {"servlet/AsyncListener", "onTimeout", null},
            new String[] {"servlet/AsyncListener", "onError", null},
            new String[] {"servlet/AsyncListener", "onStartAsync", null},
            // Fork/join task bodies: a RecursiveTask/RecursiveAction's compute() is invoked by the
            // ForkJoinPool runtime (`pool.invoke(t)`, `t.fork()`, `ForkJoinTask.invokeAll(...)`) with no
            // in-project call site. ForkJoinTask implements Future/Serializable — NOT Runnable/Callable —
            // so the Runnable row never covered it (silent-pure). null desc matches compute()V (Action),
            // compute()Object (Task + its erased bridge).
            new String[] {"java/util/concurrent/ForkJoinTask", "compute", null},
            // (DE)SERIALIZATION-framework callbacks — the framework invokes a project implementor reflectively
            // with NO in-project call site (the finalize/serialization shape). Supertype-substring gated, so a
            // same-named method on an unrelated class is never fabricated. One substring per interface covers
            // its javax/jakarta + library-variant FQNs.
            new String[] {"JsonDeserializer", "deserialize", null},      // Jackson + Gson (both end JsonDeserializer)
            new String[] {"JsonSerializer", "serialize", null},          // Jackson + Gson
            new String[] {"databind/KeyDeserializer", "deserializeKey", null},
            new String[] {"databind/util/StdConverter", "convert", null},
            new String[] {"gson/TypeAdapter", "read", null},
            new String[] {"gson/TypeAdapter", "write", null},
            new String[] {"gson/InstanceCreator", "createInstance", null},
            new String[] {"kryo/Serializer", "read", null},
            new String[] {"kryo/Serializer", "write", null},
            new String[] {"kryo/KryoSerializable", "read", null},
            new String[] {"kryo/KryoSerializable", "write", null},
            new String[] {"adapters/XmlAdapter", "unmarshal", null},
            new String[] {"adapters/XmlAdapter", "marshal", null},
            new String[] {"ws/rs/ext/MessageBodyReader", "readFrom", null},
            new String[] {"ws/rs/ext/MessageBodyWriter", "writeTo", null},
            new String[] {"core/convert/converter/Converter", "convert", null},   // Spring conversion service
            new String[] {"springframework/format/Formatter", "parse", null},
            new String[] {"springframework/format/Formatter", "print", null},
            // RUNTIME-GENERATED PROXY interceptors — invoked by the CGLIB/ByteBuddy-generated subclass at
            // runtime, the same orphan shape as the JDK InvocationHandler (already rooted). cglib's substring
            // covers BOTH net.sf.cglib and the Spring-repackaged org.springframework.cglib; cglib has its OWN
            // InvocationHandler (a DIFFERENT FQN from java.lang.reflect's).
            new String[] {"cglib/proxy/MethodInterceptor", "intercept", null},
            new String[] {"cglib/proxy/InvocationHandler", "invoke", null},
            // LOGGING appender/handler callbacks — the logging framework invokes a project-defined appender
            // with no in-project call site; a network/file appender does real Net/Fs. (The Log EMIT is config;
            // the appender BODY is the effect that matters.) Covers logback Appender, jul Handler, log4j1/2.
            new String[] {"logback/core/Appender", "append", null},
            new String[] {"logback/core/Appender", "doAppend", null},
            new String[] {"java/util/logging/Handler", "publish", null},
            new String[] {"logging/log4j/core/Appender", "append", null},
            new String[] {"apache/log4j/Appender", "doAppend", null},
            // SCHEDULING / JOB / BATCH / WORKFLOW / serverless callbacks — invoked by the scheduler/engine/
            // runtime with no in-project call site (the finalize/Runnable shape). Supertype-substring gated
            // (one row per interface; covers javax/jakarta + impl variants), so a same-named non-implementor
            // is never fabricated as a root.
            new String[] {"org/quartz/Job", "execute", null},
            new String[] {"springframework/batch/core/step/tasklet/Tasklet", "execute", null},
            new String[] {"springframework/batch/item/ItemReader", "read", null},
            new String[] {"springframework/batch/item/ItemWriter", "write", null},
            new String[] {"springframework/batch/item/ItemProcessor", "process", null},
            new String[] {"springframework/batch/core/StepExecutionListener", "beforeStep", null},
            new String[] {"springframework/batch/core/StepExecutionListener", "afterStep", null},
            new String[] {"engine/delegate/JavaDelegate", "execute", null},   // Camunda + Activiti
            new String[] {"lambda/runtime/RequestHandler", "handleRequest", null},        // AWS Lambda
            new String[] {"lambda/runtime/RequestStreamHandler", "handleRequest", null},
            new String[] {"io/vertx/core/Verticle", "start", null},
            new String[] {"io/vertx/core/Handler", "handle", null},
            new String[] {"org/apache/camel/Processor", "process", null},
            new String[] {"kafka/streams/processor/Processor", "process", null},
            new String[] {"jobrunr/jobs/lambdas/JobRequestHandler", "run", null},
            // Android component lifecycle — the framework instantiates + invokes these with no project call
            // site (the servlet-doGet shape). The dominant Android entry points.
            new String[] {"android/app/Activity", "onCreate", null},
            new String[] {"android/app/Activity", "onStart", null},
            new String[] {"android/app/Activity", "onResume", null},
            new String[] {"android/app/Service", "onStartCommand", null},
            new String[] {"android/app/Service", "onBind", null},
            new String[] {"android/app/Service", "onCreate", null},
            new String[] {"android/app/IntentService", "onHandleIntent", null},
            new String[] {"android/content/BroadcastReceiver", "onReceive", null},
            new String[] {"android/app/Application", "onCreate", null},
            // Reactive-streams Subscriber callbacks (Reactor/RxJava/project publishers invoke them) + NIO
            // async-I/O CompletionHandler (invoked by the AsynchronousChannelGroup on completion) — both the
            // runtime-invoked-callback orphan shape, like ForkJoinTask.compute.
            new String[] {"reactivestreams/Subscriber", "onNext", null},
            new String[] {"reactivestreams/Subscriber", "onError", null},
            new String[] {"reactivestreams/Subscriber", "onComplete", null},
            new String[] {"java/nio/channels/CompletionHandler", "completed", null},
            new String[] {"java/nio/channels/CompletionHandler", "failed", null},
            // JPA AttributeConverter — the persistence provider invokes convert* on a project @Converter
            // during entity load/store with NO project call site (the orphan shape); an encrypting/
            // remote-resolving converter does real I/O. Covers javax/ + jakarta/ persistence.
            new String[] {"persistence/AttributeConverter", "convertToDatabaseColumn", null},
            new String[] {"persistence/AttributeConverter", "convertToEntityAttribute", null},
            // Netflix Hystrix command body + fallback — the Hystrix runtime invokes run()/getFallback() on
            // a worker thread when the command is executed/queued, no direct project call site.
            new String[] {"netflix/hystrix/HystrixCommand", "run", null},
            new String[] {"netflix/hystrix/HystrixCommand", "getFallback", null},
            new String[] {"netflix/hystrix/HystrixObservableCommand", "construct", null},
            // Spring Boot Actuator health check — the actuator endpoint invokes health() on a registered
            // HealthIndicator (often pinging a DB/remote) with no project call site.
            new String[] {"boot/actuate/health/HealthIndicator", "health", null},
            new String[] {"boot/actuate/info/InfoContributor", "contribute", null},
            // GUI event callbacks — the UI toolkit's event-dispatch thread invokes these on a registered
            // listener with no project call site (the servlet/Runnable shape). Swing/AWT ActionListener +
            // SwingWorker background work; JavaFX EventHandler + Application lifecycle; Android click/message
            // handlers. A handler that hits the network/disk/DB is otherwise orphaned from every root.
            new String[] {"java/awt/event/ActionListener", "actionPerformed", null},
            new String[] {"javax/swing/SwingWorker", "doInBackground", null},
            new String[] {"javax/swing/SwingWorker", "done", null},
            new String[] {"javafx/event/EventHandler", "handle", null},
            new String[] {"javafx/application/Application", "start", null},
            new String[] {"javafx/application/Application", "init", null},
            new String[] {"android/view/View$OnClickListener", "onClick", null},
            new String[] {"android/os/Handler", "handleMessage", null},
            // JDK runtime-invoked callbacks orphaned from every reachability root (the finalize/serialization
            // shape) — invoked by the JVM/executor/bean machinery with no project call site:
            // java.util.concurrent.Flow.Subscriber (JDK reactive — registered with SubmissionPublisher; the
            // direct analog of the already-rooted reactivestreams Subscriber, the inconsistency a sweep
            // flagged); Thread.UncaughtExceptionHandler (set as the default/per-thread handler, run by the
            // JVM on an uncaught throw — often remote crash reporting); the executor-config callbacks
            // RejectedExecutionHandler/ThreadFactory; the bean/Swing PropertyChangeListener; the custom
            // Spliterator/ResourceBundle.Control loaders. Supertype-substring gated → no fabrication on a
            // same-named non-implementor (verified by the entrypoint probe's decoy).
            new String[] {"java/util/concurrent/Flow$Subscriber", "onNext", null},
            new String[] {"java/util/concurrent/Flow$Subscriber", "onError", null},
            new String[] {"java/util/concurrent/Flow$Subscriber", "onComplete", null},
            new String[] {"java/util/concurrent/Flow$Subscriber", "onSubscribe", null},
            new String[] {"java/lang/Thread$UncaughtExceptionHandler", "uncaughtException", null},
            new String[] {"java/util/concurrent/RejectedExecutionHandler", "rejectedExecution", null},
            new String[] {"java/util/concurrent/ThreadFactory", "newThread", null},
            new String[] {"java/beans/PropertyChangeListener", "propertyChange", null},
            new String[] {"java/util/Spliterator", "tryAdvance", null},
            new String[] {"java/util/ResourceBundle$Control", "newBundle", null},
            // Framework runtime-invoked callbacks (INTERFACE forms — candor roots the ANNOTATION forms like
            // @EventListener/@JmsListener/@RabbitListener, but a raw interface implementor has no project
            // call site either). Spring: ApplicationListener (event), Smart/Lifecycle (bean start/stop),
            // HandlerInterceptor (per-request MVC), BeanPostProcessor (per-bean startup), FactoryBean
            // (bean materialization). Messaging: JMS/AMQP MessageListener, Kafka ConsumerRebalanceListener.
            // Servlet session/request listeners. All container-invoked, segment-gated (no over-root).
            new String[] {"springframework/context/ApplicationListener", "onApplicationEvent", null},
            new String[] {"springframework/context/Lifecycle", "start", null},
            new String[] {"springframework/context/Lifecycle", "stop", null},
            new String[] {"springframework/web/servlet/HandlerInterceptor", "preHandle", null},
            new String[] {"springframework/web/servlet/HandlerInterceptor", "postHandle", null},
            new String[] {"springframework/web/servlet/HandlerInterceptor", "afterCompletion", null},
            new String[] {"springframework/beans/factory/config/BeanPostProcessor", "postProcessBeforeInitialization", null},
            new String[] {"springframework/beans/factory/config/BeanPostProcessor", "postProcessAfterInitialization", null},
            new String[] {"springframework/beans/factory/FactoryBean", "getObject", null},
            new String[] {"jms/MessageListener", "onMessage", null},                 // javax/jakarta jms
            new String[] {"amqp/core/MessageListener", "onMessage", null},           // Spring AMQP
            new String[] {"amqp/rabbit/listener/api/ChannelAwareMessageListener", "onMessage", null},
            new String[] {"kafka/clients/consumer/ConsumerRebalanceListener", "onPartitionsAssigned", null},
            new String[] {"kafka/clients/consumer/ConsumerRebalanceListener", "onPartitionsRevoked", null},
            new String[] {"servlet/http/HttpSessionListener", "sessionCreated", null},
            new String[] {"servlet/http/HttpSessionListener", "sessionDestroyed", null},
            new String[] {"servlet/ServletRequestListener", "requestInitialized", null},
            new String[] {"servlet/ServletRequestListener", "requestDestroyed", null},
            // More container-invoked framework callbacks (round-13): Spring Security auth (loadUserByUsername
            // — a DB/LDAP lookup on every login), Spring *Aware injected setters + SmartInitializingSingleton,
            // JAX-RS container filters + ExceptionMapper, RxJava Observer (distinct from reactivestreams),
            // LMAX Disruptor EventHandler, jakarta.websocket Endpoint. All runtime-invoked, segment-gated.
            new String[] {"security/core/userdetails/UserDetailsService", "loadUserByUsername", null},
            new String[] {"context/ApplicationContextAware", "setApplicationContext", null},
            new String[] {"context/EnvironmentAware", "setEnvironment", null},
            new String[] {"beans/factory/BeanFactoryAware", "setBeanFactory", null},
            new String[] {"beans/factory/BeanNameAware", "setBeanName", null},
            new String[] {"context/ResourceLoaderAware", "setResourceLoader", null},
            new String[] {"context/ApplicationEventPublisherAware", "setApplicationEventPublisher", null},
            new String[] {"web/context/ServletContextAware", "setServletContext", null},
            new String[] {"beans/factory/SmartInitializingSingleton", "afterSingletonsInstantiated", null},
            new String[] {"ws/rs/container/ContainerRequestFilter", "filter", null},
            new String[] {"ws/rs/container/ContainerResponseFilter", "filter", null},
            new String[] {"ws/rs/ext/ExceptionMapper", "toResponse", null},
            new String[] {"io/reactivex/Observer", "onNext", null},               // RxJava 2
            new String[] {"io/reactivex/Observer", "onError", null},
            new String[] {"io/reactivex/Observer", "onComplete", null},
            new String[] {"io/reactivex/rxjava3/core/Observer", "onNext", null},   // RxJava 3
            new String[] {"io/reactivex/rxjava3/core/Observer", "onError", null},
            new String[] {"io/reactivex/rxjava3/core/Observer", "onComplete", null},
            new String[] {"lmax/disruptor/EventHandler", "onEvent", null},
            new String[] {"jakarta/websocket/Endpoint", "onOpen", null},
            new String[] {"javax/websocket/Endpoint", "onOpen", null},
            // Spring StateMachine action body — the state-machine runtime invokes execute() on a transition.
            new String[] {"springframework/statemachine/action/Action", "execute", null},
            // More mainstream runtime-invoked callbacks (round-15): Spring OncePerRequestFilter (the base
            // declares doFilter final + dispatches to the project's doFilterInternal override — extremely
            // common in Spring Security/MVC filters); Spring WebFlux WebFilter; GCP Cloud Functions (the
            // official serverless model — the runtime invokes service/accept on the deployed class); Pulsar
            // consumer MessageListener.
            new String[] {"web/filter/OncePerRequestFilter", "doFilterInternal", null},
            new String[] {"web/server/WebFilter", "filter", null},
            new String[] {"cloud/functions/HttpFunction", "service", null},
            new String[] {"cloud/functions/BackgroundFunction", "accept", null},
            new String[] {"cloud/functions/CloudEventsFunction", "accept", null},
            new String[] {"pulsar/client/api/MessageListener", "received", null});

    /** The number of CHA targets above which a CHA-EXEMPT dispatch (Object protocol / function-interface
     *  / task verb) is treated as a broad smear and its fan-out dropped. An app's handful of Runnables /
     *  closures resolve precisely (attributed); a library's hundreds of FunctionN/Closure impls exceed
     *  this and are dropped (their bodies stay reachable via the RUNTIME_OVERRIDES entry points). */
    static final int CHA_FANOUT_LIMIT = 12;

    /** The single-ABSTRACT-method names of java.util.function.* (Function/BiFunction/operators → apply*;
     *  Consumer → accept; Predicate → test; Supplier → get*). Matched by NAME so the package's pure DEFAULT
     *  methods (andThen/compose/and/or/negate — known JDK plumbing that wraps the receiver into a new
     *  composed lambda, no effect at the call site) are NOT treated as the SAM. Without this, idiomatic
     *  function composition (`a.andThen(b)`) flooded Unknown — a precision regression. */
    static final Set<String> FUNCTION_PKG_SAM = Set.of(
            "apply", "applyAsInt", "applyAsLong", "applyAsDouble", "applyAsBoolean",
            "accept", "test", "get", "getAsInt", "getAsLong", "getAsDouble", "getAsBoolean");

    /** All the entry-point-rooting annotation markers (HTTP mappings/listeners/lifecycle + @Scheduled +
     *  @JsonCreator), as one list for the meta-annotation-aware matcher. */
    static final List<String> ROOT_ANNOTATIONS;
    static {
        List<String> r = new ArrayList<>(MAPPING_OR_LISTENER);
        r.addAll(LIFECYCLE);
        r.add(SCHEDULED);
        r.add(JSON_CREATOR);
        // Jackson serialization callbacks invoked reflectively during (de)serialization, no project call
        // site: @JsonValue (custom serialize), @JsonAnySetter (deser overflow), @JsonAnyGetter (ser).
        r.add("annotation/JsonValue");
        r.add("annotation/JsonAnySetter");
        r.add("annotation/JsonAnyGetter");
        r.add("ejb/Schedule");   // EJB timer (jakarta/javax) — container-invoked on a schedule
        // Micronaut + Quarkus @Scheduled — the inconsistency with the already-rooted Spring @Scheduled (a
        // container-invoked timer on a top-tier framework).
        r.add("micronaut/scheduling/annotation/Scheduled");
        r.add("quarkus/scheduler/Scheduled");
        r.add("azure/functions/annotation/FunctionName");   // Azure Functions (the official Java model)
        // jakarta/javax.websocket POJO @ServerEndpoint handlers — the container invokes the @OnMessage/
        // @OnOpen/@OnClose/@OnError methods with no project call site, and there's no interface form for the
        // annotated style (round-13). The substring covers javax/ + jakarta/ websocket.
        r.add("websocket/OnMessage"); r.add("websocket/OnOpen");
        r.add("websocket/OnClose"); r.add("websocket/OnError");
        ROOT_ANNOTATIONS = List.copyOf(r);
    }

    /** Marker annotations that appear on a PARAMETER (not the method) yet still mean the runtime invokes
     *  the method with no project call site. CDI's `@Observes`/`@ObservesAsync` are the canonical case:
     *  `void on(@Observes E e)` is a container-fired event observer. Covers javax/ + jakarta/ enterprise. */
    static final List<String> PARAM_ROOT_ANNOTATIONS = List.of(
            "enterprise/event/Observes", "enterprise/event/ObservesAsync");

    /** JDK executor owners whose submit/execute/schedule verbs invoke a Runnable/Callable TASK argument. */
    static final Set<String> EXECUTOR_OWNERS = Set.of(
            "java/util/concurrent/Executor", "java/util/concurrent/ExecutorService",
            "java/util/concurrent/ScheduledExecutorService", "java/util/concurrent/AbstractExecutorService",
            "java/util/concurrent/ThreadPoolExecutor", "java/util/concurrent/ScheduledThreadPoolExecutor",
            "java/util/concurrent/ForkJoinPool");

    /** CompletableFuture verbs whose FIRST argument is a deferred task (Runnable/Supplier/Function/Consumer/
     *  BiConsumer/BiFunction) invoked OUTSIDE project code by a CF stage. The `*Async` family + the two
     *  static factories. (The non-Async siblings — thenApply/thenRun/… — run the function inline on the
     *  completing thread; their callbacks are already edged at the indy/NEW site, so they are NOT listed.) */
    static final Set<String> COMPLETABLE_FUTURE_VERBS = Set.of(
            "runAsync", "supplyAsync", "thenRunAsync", "thenApplyAsync", "thenAcceptAsync",
            "thenComposeAsync", "whenCompleteAsync", "handleAsync");

    /** java/util/Timer verbs whose FIRST argument is a TimerTask invoked OUTSIDE project code by the timer. */
    static final Set<String> TIMER_VERBS = Set.of(
            "schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay");

    /** Functional-interface descriptors that, as the FIRST parameter, name a deferred TASK whose body is
     *  invoked by the runtime (executor/CF stage/timer) with no in-project call site. */
    static final Set<String> TASK_ARG_PREFIXES = Set.of(
            "(Ljava/lang/Runnable;", "(Ljava/util/concurrent/Callable;", "(Ljava/util/function/Supplier;",
            "(Ljava/util/function/Function;", "(Ljava/util/function/Consumer;",
            "(Ljava/util/function/BiConsumer;", "(Ljava/util/function/BiFunction;",
            "(Ljava/util/TimerTask;");

    /** Packages OUTSIDE the ledger: the platform/runtime frontier (κ's builtin job — JDK, the
     *  language runtimes) and the verb-precise third-party packages κ already covers, where zero
     *  classifications can be legitimate (the app only touches their pure surface). Segment-exact
     *  prefixes so `javassist` is not mistaken for `java`. Hoisted to a static (the check runs in
     *  the per-instruction hot loop). */
    // The namespaces κ treats as its FRONTIER — a floored call into one is a known-pure op (the stdlib's
    // pure collections/strings/paths; the effectful surface is either classified or, for the JVM-language
    // lambdas, handled by the FunctionN smear in classify), NOT a blind spot, so it is excluded from the
    // ledger to avoid flooding pure stdlib calls with `invisible` disclosure. (sweep [2] was REVERTED:
    // removing these over-disclosed pure ops — e.g. kotlin.io.path.Path — breaking the kotlin soundness
    // probe; the genuine gap is an UNMODELED EFFECTFUL member of a covered framework like
    // org.springframework.util.FileCopyUtils, which κ can't distinguish from a pure unmodeled member —
    // the real fix is to MODEL that specific member (precision), not to drop the namespace's coverage.)
    static final String[] KAPPA_COVERED_PREFIXES = { "java", "javax", "jakarta", "jdk", "sun", "com.sun",
            "kotlin", "kotlinx", "scala", "groovy", "org.codehaus.groovy", "org.jetbrains",
            "org.springframework", "io.ktor", "org.slf4j", "org.apache.logging", "ch.qos.logback",
            // κ batch 28 (the legacy-enterprise frontier; effectful members classified — see Classifier):
            // JCL, commons-lang3 (Rand/Env classified), Joda (Clock classified), the LEGACY Hibernate
            // Criteria BUILDER package (execution lives on the classified Session/Criteria terminals;
            // org.hibernate broadly stays LEDGERED — its unclassified surface is not vouched for), and
            // Struts 1.x (TagUtils→Net + FormFile→Fs classified; the rest is bean plumbing — verified
            // against a real app's complete 169-member frontier).
            "org.apache.commons.logging", "org.apache.commons.lang3", "org.joda.time",
            "org.hibernate.criterion", "org.apache.struts",
            // κ batch 29 (the next tier, same inventory discipline): pure predicate/bean/DOM/decorator
            // surfaces (validator, beanutils, displaytag, w3c.dom — a JDK namespace missing above) +
            // four with their effectful members classified (threeten now→Clock, jjwt parse→Clock +
            // Keys→Rand, jdom2 input by source, ehcache persistence→Fs / clustered→Net).
            "org.apache.commons.validator", "org.apache.commons.beanutils", "org.threeten.extra",
            "io.jsonwebtoken", "org.jdom2", "org.displaytag", "org.ehcache", "org.w3c.dom",
            // κ batch 30: Jackson — ONE descriptor-driven rule classifies its whole effectful surface
            // (File/Path → Fs, URL → Net, uniform across the stack); the rest is pure or pure-relative.
            "com.fasterxml.jackson",
            // NB com.amazonaws and org.apache.commons.io are CLASSIFIED (see Classifier) but deliberately
            // NOT ledger-covered: both are dominated by pure helpers that a blanket grant would silence,
            // and batch 30b's com.amazonaws grant induced a DynamoDBMapper silent-pure (reverted, review
            // 0.8.3). An unmodeled member of either discloses `invisible` — the honest floor.
            // κ batch 31 (the long-tail sweep; effectful members classified — see Classifier): CSV stacks
            // (pure-relative over caller sources; javacsv path-ctors → Fs), codecs (pure CPU),
            // commons-lang v2 (Rand/Env/StopWatch→Clock), OSCache + Guava base/math + maps.model +
            // Xerces serialize + SAX + naming (pure/pure-relative), Twilio (REST terminals + lazy paging →
            // Net), Redisson (create → Db), DbUnit (execute → Db), hibernate's internal jdbc pkg
            // (execution → Db, logger → Log, formatter pure), awspring SES (send → Net), v2 creds → Env.
            "com.csvreader", "org.supercsv", "org.apache.commons.codec",
            "org.apache.commons.lang", "org.apache.commons.csv", "com.opensymphony.oscache",
            "com.google.common.base", "com.google.common.math", "com.google.maps.model",
            "org.apache.xml.serialize", "org.xml.sax", "org.aopalliance",
            "com.twilio", "org.redisson", "org.dbunit", "org.hibernate.engine.jdbc.internal",
            "org.hibernate.boot.model.naming", "org.hibernate.jpa", "io.awspring.cloud.ses",
            "software.amazon.awssdk.auth.credentials", "org.postgresql.util" };
}
