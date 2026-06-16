package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Native unit tests (JUnit 5) for candor-java's PURE static helpers — the policy scope matcher, the
 * Net host-literal parser, the §6.2 literal-coverage rules, and the classification predicates. The
 * smoke + fabrication suites exercise these only through a full scan; this pins their edge cases at
 * the method boundary (package-private, so this same-package test calls them directly — no extraction).
 */
class HelpersTest {

    @Test
    void scopeMatchesIsSegmentPrefix() {
        assertTrue(Candor.scopeMatches("a.b.foo", "b"));            // last part start-matches a segment
        assertTrue(Candor.scopeMatches("svc.Handler.run", "svc.Handler"));
        assertTrue(Candor.scopeMatches("anything", ""));           // empty scope = whole project
        assertFalse(Candor.scopeMatches("a.b", "x"));
        assertFalse(Candor.scopeMatches("a", "a.b"));              // scope longer than the name
    }

    /** A policy scope written with `::` (spec §6.2 + the conformance battery use it; a Rust report names
     *  fns with `::`) must match a candor-java DOTTED node id — it silently never did (dead rule →
     *  gate-evasion). nameSegments splits on both `.` and `::`. */
    @Test
    void scopeMatchesDoubleColonAndDot() {
        assertTrue(Candor.scopeMatches("app.db.Dao.query", "app::db"));   // :: scope vs dotted name
        assertTrue(Candor.scopeMatches("app.db.Dao.query", "app.db"));    // dot scope still works
        assertTrue(Candor.scopeMatches("app.web.Web.handle", "app::web"));
        assertFalse(Candor.scopeMatches("app.db.Dao.query", "other::scope")); // no over-match
        assertFalse(Candor.scopeMatches("app.db.Dao.query", "app::web"));     // wrong segment
    }

    /** An EMPTY query matches NOTHING (tier 0), never the whole codebase — `name.contains("")` was always
     *  true, so an unset/empty fn arg selected every function (false whole-graph blast-radius). */
    @Test
    void matchTierEmptyQuerySelectsNothing() {
        assertEquals(0, Query.matchTier("com.foo.Bar.baz", ""));     // empty → no match
        assertEquals(3, Query.matchTier("com.foo.Bar.baz", "com.foo.Bar.baz")); // exact still 3
        assertEquals(2, Query.matchTier("com.foo.Bar.baz", "Bar.baz"));          // segment-suffix still 2
        assertEquals(1, Query.matchTier("com.foo.Bar.baz", "foo"));              // substring still 1
    }

    @Test
    void looksLikeIpv4IsStrict() {
        assertTrue(Candor.looksLikeIpv4("127.0.0.1"));
        assertTrue(Candor.looksLikeIpv4("10.0.0.255"));
        assertFalse(Candor.looksLikeIpv4("256.0.0.1"));           // octet > 255
        assertFalse(Candor.looksLikeIpv4("1.2.3"));               // not four parts
        assertFalse(Candor.looksLikeIpv4("a.b.c.d"));             // non-numeric
    }

    @Test
    void hostPartStripsSchemeUserinfoPathPort() {
        assertEquals("host.com", Candor.hostPart("https://user@host.com:8080/path"));
        assertEquals("host.com", Candor.hostPart("host.com"));
        assertEquals("host.com", Candor.hostPart("host.com:443"));
    }

    @Test
    void netHostLiteralAcceptsOnlyUnambiguousHosts() {
        assertEquals("api.example.com", Candor.netHostLiteral("https://api.example.com/v1"));
        assertEquals("api.example.com:8080", Candor.netHostLiteral("api.example.com:8080")); // dotted host + numeric port
        assertEquals("127.0.0.1", Candor.netHostLiteral("127.0.0.1"));                       // a bare literal IPv4
        assertNull(Candor.netHostLiteral("localhost"));   // a bare non-IP token is ambiguous → no claim
        assertNull(Candor.netHostLiteral("some sentence")); // whitespace → not a host literal
        assertNull(Candor.netHostLiteral(""));
        assertNull(Candor.netHostLiteral(null));
    }

    @Test
    void pathArgIsSingleStringDetectsLeadingStringArg() {
        assertTrue(Candor.pathArgIsSingleString("(Ljava/lang/String;)V"));        // (String)
        assertTrue(Candor.pathArgIsSingleString("(Ljava/lang/String;[B)V"));      // (String, byte[])
        assertFalse(Candor.pathArgIsSingleString("(Ljava/lang/String;Ljava/lang/String;)V")); // (String, String)
        assertFalse(Candor.pathArgIsSingleString("(I)V"));                        // not String-first
        assertFalse(Candor.pathArgIsSingleString("()V"));                         // no arg
    }

    @Test
    void isLogEmitVerbCoversTheFrameworkVerbs() {
        assertTrue(Candor.isLogEmitVerb("info"));
        assertTrue(Candor.isLogEmitVerb("error"));
        assertTrue(Candor.isLogEmitVerb("severe"));   // jul
        assertTrue(Candor.isLogEmitVerb("doAppend")); // backend append
        assertFalse(Candor.isLogEmitVerb("process")); // not a log verb (the precision the gate exists for)
        assertFalse(Candor.isLogEmitVerb("run"));
    }

    @Test
    void pathCoveredIsPrefixAndTraversalSafe() {
        assertTrue(Candor.pathCovered("/etc", "/etc/passwd"));
        assertTrue(Candor.pathCovered("/etc", "/etc"));
        assertFalse(Candor.pathCovered("/etc", "/var/log"));
        assertFalse(Candor.pathCovered("/a", "/a/../b"));  // `..` in the reached path never covers
        assertFalse(Candor.pathCovered("etc", "/etc"));    // relative allow vs absolute reach
    }

    /** The Net classifier matches socket owners by exact type. MulticastSocket extends DatagramSocket;
     *  a receiver typed as MulticastSocket emits invokevirtual owner=java/net/MulticastSocket for the
     *  inherited send/receive, which the DatagramSocket row misses — a silent Net under-report until
     *  MulticastSocket got its own row. (Pinned here so the row can't be dropped by a future cleanup.) */
    /** javax.sql.DataSource.getConnection() — the pooled-connection entry point every HikariCP/Spring
     *  DataSource app uses — is Db; the java.sql-only list missed it. */
    @Test
    void dataSourceGetConnectionClassifiesAsDb() {
        assertEquals("Db", Candor.classify("javax.sql.DataSource", "getConnection", "()Ljava/sql/Connection;"));
        assertEquals("Db", Candor.classify("java.sql.Connection", "prepareStatement", "(Ljava/lang/String;)Ljava/sql/PreparedStatement;"));
    }

    /** The full java.time `.now()` surface reads the clock — not just Instant/LocalDateTime/LocalDate/
     *  ZonedDateTime; OffsetDateTime in particular is very common. The arithmetic ops stay pure. */
    @Test
    void javaTimeNowClassifiesAsClock() {
        assertEquals("Clock", Candor.classify("java.time.OffsetDateTime", "now", "()Ljava/time/OffsetDateTime;"));
        assertEquals("Clock", Candor.classify("java.time.LocalTime", "now", "()Ljava/time/LocalTime;"));
        assertEquals("Clock", Candor.classify("java.time.Year", "now", "()Ljava/time/Year;"));
        assertNull(Candor.classify("java.time.OffsetDateTime", "plusDays", "(J)Ljava/time/OffsetDateTime;"));
    }

    @Test
    void multicastSocketClassifiesAsNet() {
        assertEquals("Net", Candor.classify("java.net.MulticastSocket", "receive", "(Ljava/net/DatagramPacket;)V"));
        assertEquals("Net", Candor.classify("java.net.MulticastSocket", "send", "(Ljava/net/DatagramPacket;)V"));
        assertEquals("Net", Candor.classify("java.net.MulticastSocket", "joinGroup", "(Ljava/net/SocketAddress;Ljava/net/NetworkInterface;)V"));
        // control: the DatagramSocket base it extends was already classified
        assertEquals("Net", Candor.classify("java.net.DatagramSocket", "receive", "(Ljava/net/DatagramPacket;)V"));
    }

    /** java.net.http: only HttpClient.send/sendAsync transmit. The old blanket `java.net.http.` prefix
     *  FABRICATED Net on the pure builder/factory surface (the cardinal sin); the real wire I/O on a
     *  HttpURLConnection obtained elsewhere went silent-pure. Pin verb-precision in both directions. */
    @Test
    void javaNetHttpIsVerbPreciseNoBuilderFabrication() {
        // the send verbs DO transmit → Net
        assertEquals("Net", Candor.classify("java.net.http.HttpClient", "send",
                "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/net/http/HttpResponse;"));
        assertEquals("Net", Candor.classify("java.net.http.HttpClient", "sendAsync",
                "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/util/concurrent/CompletableFuture;"));
        // the pure BUILDER/FACTORY surface must NOT fabricate Net (no transmission)
        assertNull(Candor.classify("java.net.http.HttpRequest", "newBuilder", "()Ljava/net/http/HttpRequest$Builder;"));
        assertNull(Candor.classify("java.net.http.HttpRequest$Builder", "build", "()Ljava/net/http/HttpRequest;"));
        assertNull(Candor.classify("java.net.http.HttpRequest$Builder", "uri", "(Ljava/net/URI;)Ljava/net/http/HttpRequest$Builder;"));
        assertNull(Candor.classify("java.net.http.HttpClient", "newBuilder", "()Ljava/net/http/HttpClient$Builder;"));
        // J-2: the wire verbs on a lazy URLConnection/HttpURLConnection DO transmit → Net
        assertEquals("Net", Candor.classify("java.net.HttpURLConnection", "getInputStream", "()Ljava/io/InputStream;"));
        assertEquals("Net", Candor.classify("java.net.HttpURLConnection", "getResponseCode", "()I"));
        assertEquals("Net", Candor.classify("java.net.URLConnection", "connect", "()V"));
        assertEquals("Net", Candor.classify("java.net.URLConnection", "getOutputStream", "()Ljava/io/OutputStream;"));
        // ...but the pure getters do not
        assertNull(Candor.classify("java.net.HttpURLConnection", "getRequestMethod", "()Ljava/lang/String;"));
        assertNull(Candor.classify("java.net.HttpURLConnection", "setRequestProperty", "(Ljava/lang/String;Ljava/lang/String;)V"));
    }

    /** ProcessBuilder spawns via start() AND the Java 9+ static startPipeline(List) — both are Exec. */
    @Test
    void processBuilderStartPipelineIsExec() {
        assertEquals("Exec", Candor.classify("java.lang.ProcessBuilder", "start", "()Ljava/lang/Process;"));
        assertEquals("Exec", Candor.classify("java.lang.ProcessBuilder", "startPipeline", "(Ljava/util/List;)Ljava/util/List;"));
    }

    /** java.net.http.WebSocket wire verbs + the SSLSocket/factory family are Net (the WebSocket case was a
     *  REGRESSION from the 0.5.15 java.net.http prefix narrowing; SSLSocket extends Socket like Multicast). */
    @Test
    void webSocketAndTlsSocketsAreNet() {
        assertEquals("Net", Candor.classify("java.net.http.WebSocket", "sendText", "(Ljava/lang/CharSequence;Z)Ljava/util/concurrent/CompletableFuture;"));
        assertEquals("Net", Candor.classify("java.net.http.WebSocket", "sendBinary", "(Ljava/nio/ByteBuffer;Z)Ljava/util/concurrent/CompletableFuture;"));
        assertEquals("Net", Candor.classify("java.net.http.WebSocket", "request", "(J)V"));
        assertEquals("Net", Candor.classify("java.net.http.WebSocket$Builder", "buildAsync", "(Ljava/net/URI;Ljava/net/http/WebSocket$Listener;)Ljava/util/concurrent/CompletableFuture;"));
        // the factory that vends a builder stays pure
        assertNull(Candor.classify("java.net.http.HttpClient", "newWebSocketBuilder", "()Ljava/net/http/WebSocket$Builder;"));
        assertEquals("Net", Candor.classify("javax.net.ssl.SSLSocket", "getInputStream", "()Ljava/io/InputStream;"));
        assertEquals("Net", Candor.classify("javax.net.ssl.SSLSocket", "startHandshake", "()V"));
        assertEquals("Net", Candor.classify("javax.net.ssl.SSLSocketFactory", "createSocket", "(Ljava/lang/String;I)Ljava/net/Socket;"));
        assertEquals("Net", Candor.classify("javax.net.SocketFactory", "createSocket", "(Ljava/lang/String;I)Ljava/net/Socket;"));
    }

    /** EntityManager whole-owner Db FABRICATED on its pure builder/cache surface; gate to the round-tripping
     *  methods. Connection.commit/rollback/setAutoCommit are real DB I/O the execute*-gate missed. */
    @Test
    void entityManagerDbIsMethodGatedNoBuilderFabrication() {
        // round-trips → Db
        assertEquals("Db", Candor.classify("jakarta.persistence.EntityManager", "find", "(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals("Db", Candor.classify("jakarta.persistence.EntityManager", "persist", "(Ljava/lang/Object;)V"));
        assertEquals("Db", Candor.classify("jakarta.persistence.EntityManager", "flush", "()V"));
        // pure builders / persistence-context ops must NOT fabricate Db
        assertNull(Candor.classify("jakarta.persistence.EntityManager", "createQuery", "(Ljava/lang/String;)Ljakarta/persistence/Query;"));
        assertNull(Candor.classify("jakarta.persistence.EntityManager", "createNativeQuery", "(Ljava/lang/String;)Ljakarta/persistence/Query;"));
        assertNull(Candor.classify("jakarta.persistence.EntityManager", "clear", "()V"));
        assertNull(Candor.classify("jakarta.persistence.EntityManager", "detach", "(Ljava/lang/Object;)V"));
        assertNull(Candor.classify("jakarta.persistence.EntityManager", "getCriteriaBuilder", "()Ljakarta/persistence/criteria/CriteriaBuilder;"));
        // Connection transaction control → Db
        assertEquals("Db", Candor.classify("java.sql.Connection", "commit", "()V"));
        assertEquals("Db", Candor.classify("java.sql.Connection", "rollback", "()V"));
        assertEquals("Db", Candor.classify("java.sql.Connection", "setAutoCommit", "(Z)V"));
    }

    /** JPA/Hibernate query EXECUTION verbs are the round-trip (createQuery is a pure builder) — without
     *  these the whole JPA query path read pure. */
    @Test
    void jpaQueryExecutionVerbsAreDb() {
        assertEquals("Db", Candor.classify("jakarta.persistence.Query", "getResultList", "()Ljava/util/List;"));
        assertEquals("Db", Candor.classify("jakarta.persistence.TypedQuery", "getSingleResult", "()Ljava/lang/Object;"));
        assertEquals("Db", Candor.classify("jakarta.persistence.Query", "executeUpdate", "()I"));
        assertEquals("Db", Candor.classify("jakarta.persistence.StoredProcedureQuery", "execute", "()Z"));
        assertEquals("Db", Candor.classify("org.hibernate.Session", "get", "(Ljava/lang/Class;Ljava/io/Serializable;)Ljava/lang/Object;"));
        assertEquals("Db", Candor.classify("org.hibernate.query.Query", "list", "()Ljava/util/List;"));
    }

    /** NIO Fs deep: memory-mapped file I/O (MappedByteBuffer), FileStore disk stats, FileDescriptor.sync. */
    @Test
    void nioMappedBufferAndFileStoreAreFs() {
        assertEquals("Fs", Candor.classify("java.nio.MappedByteBuffer", "put", "(IB)Ljava/nio/ByteBuffer;"));
        assertEquals("Fs", Candor.classify("java.nio.MappedByteBuffer", "force", "()Ljava/nio/MappedByteBuffer;"));
        assertEquals("Fs", Candor.classify("java.nio.file.FileStore", "getTotalSpace", "()J"));
        assertEquals("Fs", Candor.classify("java.io.FileDescriptor", "sync", "()V"));
    }

    /** Groovy GDK + Scala stdlib I/O — the dialects' OWN stdlib, as fundamental as java.io. Was silent-pure
     *  (no classify row + κ-"covered"). URL-receiver GDK reads are Net; the pure GDK surface stays pure. */
    @Test
    void groovyGdkAndScalaStdlibIo() {
        assertEquals("Fs", Candor.classify("org.codehaus.groovy.runtime.ResourceGroovyMethods", "getText", "(Ljava/io/File;)Ljava/lang/String;"));
        assertEquals("Fs", Candor.classify("org.codehaus.groovy.runtime.ResourceGroovyMethods", "leftShift", "(Ljava/io/File;Ljava/lang/Object;)Ljava/io/File;"));
        assertEquals("Net", Candor.classify("org.codehaus.groovy.runtime.ResourceGroovyMethods", "getText", "(Ljava/net/URL;)Ljava/lang/String;"));
        assertEquals("Exec", Candor.classify("org.codehaus.groovy.runtime.ProcessGroovyMethods", "execute", "(Ljava/lang/String;)Ljava/lang/Process;"));
        assertEquals("Fs", Candor.classify("scala.io.Source$", "fromFile", "(Ljava/lang/String;)Lscala/io/BufferedSource;"));
        // the pure GDK surface (a non-I/O helper) must NOT be classified
        assertNull(Candor.classify("org.codehaus.groovy.runtime.ResourceGroovyMethods", "size", "(Ljava/io/File;)J"));
    }

    /** Subprocess/native/env deep: Process pipe & control verbs (Exec), System/Runtime.load* (native-code
     *  load → Exec), ProcessBuilder.environment (Env). Pure Process getters (toHandle/exitValue) stay pure. */
    @Test
    void processNativeAndEnvDeep() {
        assertEquals("Exec", Candor.classify("java.lang.Process", "getInputStream", "()Ljava/io/InputStream;"));
        assertEquals("Exec", Candor.classify("java.lang.Process", "getOutputStream", "()Ljava/io/OutputStream;"));
        assertEquals("Exec", Candor.classify("java.lang.Process", "waitFor", "()I"));
        assertNull(Candor.classify("java.lang.Process", "exitValue", "()I"));
        assertNull(Candor.classify("java.lang.Process", "toHandle", "()Ljava/lang/ProcessHandle;"));
        assertEquals("Exec", Candor.classify("java.lang.System", "loadLibrary", "(Ljava/lang/String;)V"));
        assertEquals("Exec", Candor.classify("java.lang.System", "load", "(Ljava/lang/String;)V"));
        assertEquals("Exec", Candor.classify("java.lang.Runtime", "load", "(Ljava/lang/String;)V"));
        assertEquals("Env", Candor.classify("java.lang.ProcessBuilder", "environment", "()Ljava/util/Map;"));
    }

    /** Fs deep: Scanner(File/Path) ctor, WatchService take/poll, Path.toRealPath/register. Scanner(String)
     *  and pure Path manipulation (getParent/normalize) must NOT fabricate Fs. */
    @Test
    void fsDeepScannerWatchPath() {
        assertEquals("Fs", Candor.classify("java.util.Scanner", "<init>", "(Ljava/io/File;)V"));
        assertEquals("Fs", Candor.classify("java.util.Scanner", "<init>", "(Ljava/nio/file/Path;)V"));
        assertNull(Candor.classify("java.util.Scanner", "<init>", "(Ljava/lang/String;)V"));   // string source — pure
        assertNull(Candor.classify("java.util.Scanner", "<init>", "(Ljava/io/InputStream;)V")); // source-deferred — pure
        assertEquals("Fs", Candor.classify("java.nio.file.WatchService", "take", "()Ljava/nio/file/WatchKey;"));
        assertEquals("Fs", Candor.classify("java.nio.file.Path", "toRealPath", "([Ljava/nio/file/LinkOption;)Ljava/nio/file/Path;"));
        assertEquals("Fs", Candor.classify("java.nio.file.Path", "register", "(Ljava/nio/file/WatchService;[Ljava/nio/file/WatchEvent$Kind;)Ljava/nio/file/WatchKey;"));
        assertNull(Candor.classify("java.nio.file.Path", "getParent", "()Ljava/nio/file/Path;"));      // pure path op
        assertNull(Candor.classify("java.nio.file.Path", "normalize", "()Ljava/nio/file/Path;"));
        assertNull(Candor.classify("java.nio.file.Path", "resolve", "(Ljava/nio/file/Path;)Ljava/nio/file/Path;"));
    }

    /** Clock/Rand completeness: no-arg Date()/GregorianCalendar()/Calendar.getInstance() read the clock;
     *  RandomGenerator (Java 17+ interface) draws entropy. Valued ctors stay pure (arity-precise, no fab). */
    @Test
    void clockRandCompleteness() {
        assertEquals("Clock", Candor.classify("java.util.Date", "<init>", "()V"));
        assertEquals("Clock", Candor.classify("java.util.GregorianCalendar", "<init>", "()V"));
        assertEquals("Clock", Candor.classify("java.util.Calendar", "getInstance", "()Ljava/util/Calendar;"));
        assertNull(Candor.classify("java.util.Date", "<init>", "(J)V"));                  // value, not clock — pure
        assertNull(Candor.classify("java.util.GregorianCalendar", "<init>", "(III)V"));   // pure
        assertEquals("Rand", Candor.classify("java.util.random.RandomGenerator", "nextInt", "()I"));
        assertEquals("Rand", Candor.classify("java.util.random.RandomGenerator", "nextLong", "()J"));
    }

    /** UUID.randomUUID() draws v4 entropy from SecureRandom → Rand; the rest of UUID is pure value ops
     *  (classifying the whole owner would fabricate Rand onto fromString/getMostSignificantBits/…). Also
     *  pins that a JDK functional-interface SAM is recognized for the unpinned-dispatch Unknown rule. */
    @Test
    void uuidRandomIsRandButUuidValueOpsArePure() {
        assertEquals("Rand", Candor.classify("java.util.UUID", "randomUUID", "()Ljava/util/UUID;"));
        assertNull(Candor.classify("java.util.UUID", "fromString", "(Ljava/lang/String;)Ljava/util/UUID;"));
        assertNull(Candor.classify("java.util.UUID", "getMostSignificantBits", "()J"));
        assertTrue(Candor.isJdkFunctionalSam("java/lang/Runnable", "run"));
        assertTrue(Candor.isJdkFunctionalSam("java/util/function/Supplier", "get"));
        assertTrue(Candor.isJdkFunctionalSam("java/util/function/Function", "apply"));
        assertTrue(Candor.isJdkFunctionalSam("java/util/function/Predicate", "test"));
        assertTrue(Candor.isJdkFunctionalSam("java/util/concurrent/Callable", "call"));
        assertFalse(Candor.isJdkFunctionalSam("java/util/List", "size")); // stdlib, not a SAM → no flood
        // the package's pure DEFAULT methods are NOT the SAM — composing functions is not an effect
        assertFalse(Candor.isJdkFunctionalSam("java/util/function/Function", "andThen"));
        assertFalse(Candor.isJdkFunctionalSam("java/util/function/Function", "compose"));
        assertFalse(Candor.isJdkFunctionalSam("java/util/function/Predicate", "and"));
        assertFalse(Candor.isJdkFunctionalSam("java/util/function/Predicate", "negate"));
    }

    @Test
    void tableCoveredIsExactOrSchemaWildcard() {
        assertTrue(Candor.tableCovered("users", "USERS"));         // case-insensitive
        assertTrue(Candor.tableCovered("public.*", "public.orders")); // schema wildcard
        assertFalse(Candor.tableCovered("users", "orders"));
        assertFalse(Candor.tableCovered("public.*", "private.orders"));
    }

    /** Helper: register a project class (name, super) declaring the given concrete methods, mirroring
     *  the load-time wiring of {@code byName}/{@code overloadDescs} the resolver reads. */
    private static void registerClass(String internal, String superName, String... methodNames) {
        ClassNode cn = new ClassNode();
        cn.name = internal;
        cn.superName = superName;
        for (String m : methodNames) {
            MethodNode mn = new MethodNode(Opcodes.ASM9, Opcodes.ACC_PUBLIC, m, "()I", null, null);
            cn.methods.add(mn);
            Candor.overloadDescs.computeIfAbsent(internal.replace('/', '.') + "." + m,
                    k -> new java.util.HashSet<>()).add("()I");
        }
        Candor.byName.put(internal, cn);
    }

    /** monomorphicTarget resolves a provable `new T` dispatch to exactly the method T invokes — itself
     *  when it declares the impl, its nearest concrete super otherwise, and null when no project impl is
     *  visible (the receiver-provenance soundness fix's resolution step). */
    @Test
    void monomorphicTargetResolvesLikeVirtualDispatch() {
        Candor.byName.clear();
        Candor.transSupersCache.clear();
        Candor.overloadDescs.clear();
        registerClass("p/Base", "java/lang/Object", "compute");          // Base declares compute()
        registerClass("p/Dirty", "p/Base", "compute");                   // Dirty overrides compute()
        registerClass("p/Plain", "p/Base");                              // Plain inherits Base.compute()
        registerClass("p/Lonely", "java/lang/Object");                   // declares nothing

        // a `new Base` dispatch resolves to Base.compute itself
        assertEquals("p.Base.compute", Candor.monomorphicTarget("p/Base", "compute", "()I"));
        // a `new Dirty` dispatch resolves to Dirty's OWN override, never the pure sibling Base
        assertEquals("p.Dirty.compute", Candor.monomorphicTarget("p/Dirty", "compute", "()I"));
        // a `new Plain` (no override) resolves UP to the nearest concrete super that declares it
        assertEquals("p.Base.compute", Candor.monomorphicTarget("p/Plain", "compute", "()I"));
        // no project impl anywhere in the chain → null, so the caller keeps the CHA (sound fall-through)
        assertNull(Candor.monomorphicTarget("p/Lonely", "compute", "()I"));
    }

    /** Arbitrary-code-execution / opaque security sinks → Unknown (eval / untrusted-deser RCE / XXE / FFI). */
    @Test
    void codeExecutionAndDeserSinksAreUnknown() {
        assertEquals("Unknown", Candor.classify("javax.script.ScriptEngine", "eval", "(Ljava/lang/String;)Ljava/lang/Object;"));
        assertEquals("Unknown", Candor.classify("org.springframework.expression.Expression", "getValue", "(Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals("Unknown", Candor.classify("ognl.Ognl", "getValue", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals("Unknown", Candor.classify("org.mvel2.MVEL", "eval", "(Ljava/lang/String;)Ljava/lang/Object;"));
        assertEquals("Unknown", Candor.classify("java.io.ObjectInputStream", "readObject", "()Ljava/lang/Object;"));
        assertEquals("Unknown", Candor.classify("java.beans.XMLDecoder", "readObject", "()Ljava/lang/Object;"));
        assertEquals("Unknown", Candor.classify("javax.xml.parsers.DocumentBuilder", "parse", "(Ljava/io/InputStream;)Lorg/w3c/dom/Document;"));
        assertEquals("Unknown", Candor.classify("com.sun.jna.Function", "invoke", "(Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals("Exec", Candor.classify("com.sun.jna.Native", "load", "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"));
        assertEquals("Exec", Candor.classify("com.sun.tools.attach.VirtualMachine", "loadAgent", "(Ljava/lang/String;)V"));
    }

    /** Mail/MQ clients + raw cache clients → Net (the ubiquitous ones, parallel to the modeled templates);
     *  the message BUILDERS stay pure. PrintStream/Writer/Formatter file ctors → Fs; in-memory overloads pure. */
    @Test
    void messagingCacheNetAndFileStreamFs() {
        assertEquals("Net", Candor.classify("javax.mail.Transport", "send", "(Ljavax/mail/Message;)V"));
        assertEquals("Net", Candor.classify("org.apache.kafka.clients.producer.KafkaProducer", "send", "(Lorg/apache/kafka/clients/producer/ProducerRecord;)Ljava/util/concurrent/Future;"));
        assertEquals("Net", Candor.classify("com.rabbitmq.client.Channel", "basicPublish", "(Ljava/lang/String;Ljava/lang/String;Lcom/rabbitmq/client/AMQP$BasicProperties;[B)V"));
        assertEquals("Net", Candor.classify("redis.clients.jedis.Jedis", "get", "(Ljava/lang/String;)Ljava/lang/String;"));
        assertEquals("Net", Candor.classify("net.spy.memcached.MemcachedClient", "get", "(Ljava/lang/String;)Ljava/lang/Object;"));
        // a pure builder must NOT be Net
        assertNull(Candor.classify("javax.mail.internet.MimeMessage", "setText", "(Ljava/lang/String;)V"));
        // file-opening Print*/Formatter ctors → Fs; the OutputStream/Writer overloads stay pure
        assertEquals("Fs", Candor.classify("java.io.PrintStream", "<init>", "(Ljava/lang/String;)V"));
        assertEquals("Fs", Candor.classify("java.io.PrintWriter", "<init>", "(Ljava/io/File;)V"));
        assertEquals("Fs", Candor.classify("java.util.Formatter", "<init>", "(Ljava/lang/String;)V"));
        assertNull(Candor.classify("java.io.PrintStream", "<init>", "(Ljava/io/OutputStream;)V"));
        assertNull(Candor.classify("java.io.PrintWriter", "<init>", "(Ljava/io/Writer;)V"));
    }

    /** Android SDK κ rows: SQLite→Db, ContentResolver→Ipc, WebView→Net, Settings→Env, ClipboardManager,
     *  SharedPreferences.Editor→Fs. */
    @Test
    void androidSdkEffects() {
        assertEquals("Db", Candor.classify("android.database.sqlite.SQLiteDatabase", "rawQuery", "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"));
        assertEquals("Ipc", Candor.classify("android.content.ContentResolver", "query", "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"));
        assertEquals("Net", Candor.classify("android.webkit.WebView", "loadUrl", "(Ljava/lang/String;)V"));
        assertEquals("Env", Candor.classify("android.provider.Settings$Secure", "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;"));
        assertEquals("Clipboard", Candor.classify("android.content.ClipboardManager", "setPrimaryClip", "(Landroid/content/ClipData;)V"));
        assertEquals("Fs", Candor.classify("android.content.SharedPreferences$Editor", "commit", "()Z"));
        assertEquals("Ipc", Candor.classify("android.content.Context", "startActivity", "(Landroid/content/Intent;)V"));
    }
}
