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
    void hostPartStripsOnlyPortAndBrackets() {
        // The GATE-side normalizer mirrors candor-rust policy::host_part: it strips ONLY a [ipv6] bracket
        // or a trailing :port. It does NOT strip scheme/userinfo/path — that's netHostLiteral's job at
        // EXTRACTION (the reached host is already clean). Stripping them here diverged from rust and
        // silently WIDENED a policy author's allow literal (`build@github.com` → `github.com`).
        assertEquals("host.com", Candor.hostPart("host.com"));
        assertEquals("host.com", Candor.hostPart("host.com:443"));
        // a URL/userinfo-form allow literal is taken VERBATIM (no auto-clean) — as rust does
        assertEquals("https://user@host.com:8080/path", Candor.hostPart("https://user@host.com:8080/path"));
        assertEquals("build@github.com", Candor.hostPart("build@github.com"));
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

    /** sweep [21]/[22]: whole-owner fabrication carve-outs — pure predicate/metadata reads stay pure. */
    @Test
    void wholeOwnerPureAccessorsAreNotFabricated() {
        // Jedis isConnected/isBroken read the cached local socket-state flag — no command, no round-trip.
        assertNull(Candor.classify("redis.clients.jedis.Jedis", "isConnected", "()Z"));
        assertNull(Candor.classify("redis.clients.jedis.Jedis", "isBroken", "()Z"));
        assertEquals("Net", Candor.classify("redis.clients.jedis.Jedis", "get", "(Ljava/lang/String;)Ljava/lang/String;"));
        // RandomGenerator.isDeprecated is a pure metadata default method; draws stay Rand.
        assertNull(Candor.classify("java.util.random.RandomGenerator", "isDeprecated", "()Z"));
        assertEquals("Rand", Candor.classify("java.util.random.RandomGenerator", "nextInt", "()I"));
    }

    /** sweep [2] precision follow-up: known-effectful members of the κ-COVERED `org.springframework`
     *  namespace must be MODELED (not floored silently because the namespace is "covered"). */
    @Test
    void springFilesystemUtilitiesClassifyAsFs() {
        // FileSystemUtils is whole-owner Fs — both methods walk the live filesystem.
        assertEquals("Fs", Candor.classify("org.springframework.util.FileSystemUtils", "deleteRecursively",
                "(Ljava/io/File;)Z"));
        assertEquals("Fs", Candor.classify("org.springframework.util.FileSystemUtils", "copyRecursively",
                "(Ljava/io/File;Ljava/io/File;)V"));
        // FileCopyUtils is Fs only in its File-typed overloads (the cited gap: copy(File,File) → Fs read+write).
        assertEquals("Fs", Candor.classify("org.springframework.util.FileCopyUtils", "copy",
                "(Ljava/io/File;Ljava/io/File;)I"));
        assertEquals("Fs", Candor.classify("org.springframework.util.FileCopyUtils", "copyToByteArray",
                "(Ljava/io/File;)[B"));
        // ...but the InputStream/OutputStream pumps are NOT Fs — they defer to the stream's own owner, so
        // an in-memory copy never fabricates (the cardinal sin we avoid by descriptor-gating, not owner-gating).
        assertNull(Candor.classify("org.springframework.util.FileCopyUtils", "copy",
                "(Ljava/io/InputStream;Ljava/io/OutputStream;)I"));
        assertNull(Candor.classify("org.springframework.util.FileCopyUtils", "copyToByteArray",
                "(Ljava/io/InputStream;)[B"));
    }

    /** okio coverage calibration: okhttp routes ALL its socket + disk-cache I/O through okio (the #1
     *  disclosed package in an okhttp scan: 953 invisible okio calls). Model PRECISELY at the
     *  construction boundary — the `okio.Okio` static factory, descriptor-gated on the receiver type —
     *  NOT on the in-memory `okio.Buffer` (which must stay pure) nor on the buffered read/write (which
     *  can't be distinguished from a Buffer-backed sink, so stays disclosed). */
    @Test
    void okioConstructionBoundaryClassifiesPrecisely() {
        // Okio.source/sink/appendingSink(Socket) open socket I/O → Net.
        assertEquals("Net", Candor.classify("okio.Okio", "source", "(Ljava/net/Socket;)Lokio/Source;"));
        assertEquals("Net", Candor.classify("okio.Okio", "sink", "(Ljava/net/Socket;)Lokio/Sink;"));
        // Okio.source/sink/appendingSink(File|Path) open file I/O → Fs.
        assertEquals("Fs", Candor.classify("okio.Okio", "source", "(Ljava/io/File;)Lokio/Source;"));
        assertEquals("Fs", Candor.classify("okio.Okio", "appendingSink", "(Ljava/io/File;)Lokio/Sink;"));
        assertEquals("Fs", Candor.classify("okio.Okio", "sink", "(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Lokio/Sink;"));
        // PURE: the (InputStream)/(OutputStream) overloads wrap a caller stream (effect is on that
        // stream's own owner); buffer()/blackhole() are pure wrappers. NONE may fabricate an effect.
        assertNull(Candor.classify("okio.Okio", "source", "(Ljava/io/InputStream;)Lokio/Source;"));
        assertNull(Candor.classify("okio.Okio", "sink", "(Ljava/io/OutputStream;)Lokio/Sink;"));
        assertNull(Candor.classify("okio.Okio", "buffer", "(Lokio/Source;)Lokio/BufferedSource;"));
        assertNull(Candor.classify("okio.Okio", "buffer", "(Lokio/Sink;)Lokio/BufferedSink;"));
        assertNull(Candor.classify("okio.Okio", "blackhole", "()Lokio/Sink;"));
        // PURE: okio.Buffer is an in-memory byte buffer — writeUtf8/size/readByte/write must stay pure
        // (a whole-owner okio rule would fabricate Fs/Net on the dominant okhttp okio usage — cardinal sin).
        assertNull(Candor.classify("okio.Buffer", "writeUtf8", "(Ljava/lang/String;)Lokio/Buffer;"));
        assertNull(Candor.classify("okio.Buffer", "size", "()J"));
        assertNull(Candor.classify("okio.Buffer", "readByte", "()B"));
        assertNull(Candor.classify("okio.Buffer", "writeByte", "(I)Lokio/Buffer;"));
        // PURE: the BufferedSink/BufferedSource read/write/flush layer is AMBIGUOUS (may wrap a Buffer or
        // a socket/file) — stays DISCLOSED, not classified, so an in-memory sink never fabricates.
        assertNull(Candor.classify("okio.BufferedSink", "writeUtf8", "(Ljava/lang/String;)Lokio/BufferedSink;"));
        assertNull(Candor.classify("okio.BufferedSink", "flush", "()V"));
        assertNull(Candor.classify("okio.BufferedSource", "readByte", "()B"));
        // okio.FileSystem (okio 3's java.nio.file.Files analog) — the FS verbs hit disk → Fs; the concrete
        // JvmSystemFileSystem too. canonicalize is pure path math → stays pure.
        assertEquals("Fs", Candor.classify("okio.FileSystem", "read",
                "(Lokio/Path;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;"));
        assertEquals("Fs", Candor.classify("okio.FileSystem", "delete", "(Lokio/Path;Z)V"));
        assertEquals("Fs", Candor.classify("okio.FileSystem", "list", "(Lokio/Path;)Ljava/util/List;"));
        assertEquals("Fs", Candor.classify("okio.JvmSystemFileSystem", "sink",
                "(Lokio/Path;Z)Lokio/Sink;"));
        assertNull(Candor.classify("okio.FileSystem", "canonicalize", "(Lokio/Path;)Lokio/Path;"));
    }

    /** Conscrypt TLS sockets (Google's dominant alternative SSLSocket backend) extend
     *  javax.net.ssl.SSLSocket; a receiver typed as the CONCRETE conscrypt class emits owner=org/conscrypt/*
     *  for the inherited socket I/O, otherwise silent. Verb-gated to the wire boundary; pure config getters
     *  stay pure (no fabrication — BouncyCastle/OpenJSSE rejected: package-private impls / pure-config-only
     *  public surface; jgss rejected: initSecContext produces tokens, the wire I/O is on the app's socket). */
    @Test
    void conscryptTlsSocketIoClassifiesAsNet() {
        assertEquals("Net", Candor.classify("org.conscrypt.OpenSSLSocketImpl", "startHandshake", "()V"));
        assertEquals("Net", Candor.classify("org.conscrypt.ConscryptEngineSocket", "getInputStream",
                "()Ljava/io/InputStream;"));
        assertEquals("Net", Candor.classify("org.conscrypt.ConscryptFileDescriptorSocket", "getOutputStream",
                "()Ljava/io/OutputStream;"));
        // PURE config/probe surface stays pure (not fabricated) — these are what a real okhttp scan actually
        // calls in org.conscrypt (isAvailable / get-application-protocol), and they do no wire I/O.
        assertNull(Candor.classify("org.conscrypt.Conscrypt", "isAvailable", "()Z"));
        assertNull(Candor.classify("org.conscrypt.OpenSSLSocketImpl", "getApplicationProtocol",
                "()Ljava/lang/String;"));
        // jgss + BouncyCastle config are NOT modeled (rejected) — must read null, never a fabricated Net.
        assertNull(Candor.classify("org.ietf.jgss.GSSContext", "initSecContext", "([BII)[B"));
        assertNull(Candor.classify("org.bouncycastle.jsse.BCSSLSocket", "getParameters",
                "()Lorg/bouncycastle/jsse/BCSSLParameters;"));
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

    /** Round-9 FABRICATION fixes — whole-owner rules must NOT fire on the conventionally-pure / config
     *  surface (these were cardinal-sin regressions from the 0.5.16–0.5.20 rows). */
    @Test
    void wholeOwnerRulesDoNotFabricateOnPureMethods() {
        // MappedByteBuffer: get*/put*/force = Fs; capacity/position/limit (pure Buffer queries) = NOT Fs
        assertEquals("Fs", Candor.classify("java.nio.MappedByteBuffer", "force", "()Ljava/nio/MappedByteBuffer;"));
        assertEquals("Fs", Candor.classify("java.nio.MappedByteBuffer", "put", "(IB)Ljava/nio/ByteBuffer;"));
        assertNull(Candor.classify("java.nio.MappedByteBuffer", "capacity", "()I"));
        assertNull(Candor.classify("java.nio.MappedByteBuffer", "position", "()I"));
        assertNull(Candor.classify("java.nio.MappedByteBuffer", "order", "()Ljava/nio/ByteOrder;"));
        // Jedis: a command = Net; getDB/toString/equals = pure
        assertEquals("Net", Candor.classify("redis.clients.jedis.Jedis", "get", "(Ljava/lang/String;)Ljava/lang/String;"));
        assertNull(Candor.classify("redis.clients.jedis.Jedis", "getDB", "()I"));
        assertNull(Candor.classify("redis.clients.jedis.Jedis", "toString", "()Ljava/lang/String;"));
        assertNull(Candor.classify("org.apache.zookeeper.ZooKeeper", "getSessionId", "()J"));
        // SocketChannel config verbs = pure (not Net); read/write still Net
        assertEquals("Net", Candor.classify("java.nio.channels.SocketChannel", "read", "(Ljava/nio/ByteBuffer;)I"));
        assertNull(Candor.classify("java.nio.channels.SocketChannel", "setOption", "(Ljava/net/SocketOption;Ljava/lang/Object;)Ljava/nio/channels/SocketChannel;"));
        assertNull(Candor.classify("java.nio.channels.SocketChannel", "configureBlocking", "(Z)Ljava/nio/channels/SelectableChannel;"));
        assertNull(Candor.classify("java.nio.channels.SocketChannel", "register", "(Ljava/nio/channels/Selector;I)Ljava/nio/channels/SelectionKey;"));
        // Settings: EXACT owner+method (the startsWith over-match fabricated on NameValueCache helpers)
        assertEquals("Env", Candor.classify("android.provider.Settings$Secure", "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;"));
        assertNull(Candor.classify("android.provider.Settings$NameValueCache", "getStringForUser", "(Ljava/lang/String;)Ljava/lang/String;"));
    }

    /** Round-9 silent-pure adds: resource/bundle/ServiceLoader → Fs; Process.destroy/ProcessHandle.destroy →
     *  Exec; Selector.select/MulticastChannel.join → Net; OkHttp/Apache/AWS clients → Net (builders pure). */
    @Test
    void round9SilentPureAdds() {
        assertEquals("Fs", Candor.classify("java.lang.Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;"));
        assertEquals("Fs", Candor.classify("java.lang.ClassLoader", "getResource", "(Ljava/lang/String;)Ljava/net/URL;"));
        assertEquals("Fs", Candor.classify("java.util.ResourceBundle", "getBundle", "(Ljava/lang/String;)Ljava/util/ResourceBundle;"));
        assertEquals("Fs", Candor.classify("java.util.ServiceLoader", "load", "(Ljava/lang/Class;)Ljava/util/ServiceLoader;"));
        assertEquals("Exec", Candor.classify("java.lang.Process", "destroy", "()V"));
        assertEquals("Exec", Candor.classify("java.lang.ProcessHandle", "destroyForcibly", "()Z"));
        assertEquals("Net", Candor.classify("java.nio.channels.Selector", "select", "()I"));
        assertEquals("Net", Candor.classify("java.nio.channels.MulticastChannel", "join", "(Ljava/net/InetAddress;Ljava/nio/channels/MembershipKey;)Ljava/nio/channels/MembershipKey;"));
        assertEquals("Net", Candor.classify("okhttp3.Call", "execute", "()Lokhttp3/Response;"));
        assertEquals("Net", Candor.classify("org.apache.http.impl.client.CloseableHttpClient", "execute", "(Lorg/apache/http/client/methods/HttpUriRequest;)Lorg/apache/http/client/methods/CloseableHttpResponse;"));
        assertEquals("Net", Candor.classify("software.amazon.awssdk.services.s3.S3Client", "getObject", "(Lsoftware/amazon/awssdk/services/s3/model/GetObjectRequest;)Ljava/lang/Object;"));
        // an AWS model getter (v1 get*) must NOT be Net (client-class gate)
        assertNull(Candor.classify("com.amazonaws.services.s3.model.GetObjectRequest", "getBucketName", "()Ljava/lang/String;"));
    }

    /** Round-9 over-rooting fix: the RUNTIME_OVERRIDES supertype match is now segment-anchored. */
    @Test
    void supertypeMatchesIsSegmentAnchored() {
        assertTrue(Candor.supertypeMatches("com/fasterxml/jackson/databind/JsonDeserializer", "JsonDeserializer"));
        assertTrue(Candor.supertypeMatches("com/google/gson/JsonDeserializer", "JsonDeserializer"));
        assertFalse(Candor.supertypeMatches("com/acme/JsonDeserializerMetrics", "JsonDeserializer")); // infix → no
        assertTrue(Candor.supertypeMatches("net/sf/cglib/proxy/MethodInterceptor", "cglib/proxy/MethodInterceptor"));
        assertFalse(Candor.supertypeMatches("com/co/batch/item/ItemReader", "springframework/batch/item/ItemReader"));
        assertTrue(Candor.supertypeMatches("org/springframework/batch/item/ItemReader", "springframework/batch/item/ItemReader"));
        // the FunctionN prefix convention still works
        assertTrue(Candor.supertypeMatches("kotlin/jvm/functions/Function1", "kotlin/jvm/functions/Function"));
        assertTrue(Candor.supertypeMatches("scala/Function2", "scala/Function"));
    }

    /** Round-10 AWS-client config-getter FABRICATION regression (0.5.21): the `*Client` Net rule matched
     *  the client's OWN pure config getters (getRegion/getUrl/getCachedResponseMetadata) → fabricated Net.
     *  They must be pure; a real op (getObject) and the HEAD-issuing getBucketRegionViaHeadRequest stay Net. */
    @Test
    void awsClientConfigGettersAreNotFabricatedAsNet() {
        assertNull(Candor.classify("com.amazonaws.services.s3.AmazonS3Client", "getRegion", "()Lcom/amazonaws/services/s3/model/Region;"));
        assertNull(Candor.classify("com.amazonaws.services.s3.AmazonS3Client", "getRegionName", "()Ljava/lang/String;"));
        assertNull(Candor.classify("com.amazonaws.services.s3.AmazonS3Client", "getUrl", "(Ljava/lang/String;Ljava/lang/String;)Ljava/net/URL;"));
        assertNull(Candor.classify("com.amazonaws.services.s3.AmazonS3Client", "getCachedResponseMetadata", "(Lcom/amazonaws/AmazonWebServiceRequest;)Ljava/lang/Object;"));
        assertNull(Candor.classify("com.amazonaws.services.s3.AmazonS3Client", "getResourceUrl", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        // real ops stay Net
        assertEquals("Net", Candor.classify("com.amazonaws.services.s3.AmazonS3Client", "getObject", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;"));
        assertEquals("Net", Candor.classify("com.amazonaws.services.s3.AmazonS3Client", "getBucketRegionViaHeadRequest", "(Ljava/lang/String;)Ljava/lang/String;"));
    }

    /** Round-11: the AWS carve-out was INCOMPLETE — the pure config getters inherited from
     *  AmazonWebServiceClient (getTimeOffset/getSignerOverride/getRequestMetricsCollector/
     *  getMonitoringListeners/getSignerByURI) still fabricated Net. They must be pure. */
    @Test
    void awsInheritedBaseGettersAreNotFabricatedAsNet() {
        for (String g : new String[] {"getTimeOffset", "getSignerOverride", "getRequestMetricsCollector",
                "getMonitoringListeners", "getSignerByURI", "getEndpoint"})
            assertNull(Candor.classify("com.amazonaws.services.s3.AmazonS3Client", g, "()Ljava/lang/Object;"),
                    g + " is a pure config getter, must NOT be Net");
    }

    /** Round-11: the DatabaseMetaData catalog-query verb list was incomplete (getColumnPrivileges/getUDTs/…
     *  run a system-catalog SELECT) and Druid/Oracle/PG/H2 pools were missing → silent-pure. Capability
     *  getters stay pure. */
    @Test
    void round11JdbcCompleteness() {
        for (String q : new String[] {"getColumnPrivileges", "getTablePrivileges", "getUDTs",
                "getCrossReference", "getTypeInfo", "getSuperTables", "getAttributes", "getProcedureColumns"})
            assertEquals("Db", Candor.classify("java.sql.DatabaseMetaData", q, "()Ljava/sql/ResultSet;"),
                    q + " runs a catalog SELECT");
        assertNull(Candor.classify("java.sql.DatabaseMetaData", "supportsTransactions", "()Z")); // capability flag pure
        assertEquals("Db", Candor.classify("com.alibaba.druid.pool.DruidDataSource", "getConnection", "()Ljava/sql/Connection;"));
        assertEquals("Db", Candor.classify("org.postgresql.ds.PGSimpleDataSource", "getConnection", "()Ljava/sql/Connection;"));
    }

    /** Round-12: raw data-store DRIVERS (under the already-modeled Spring templates) — Mongo/Cassandra/
     *  R2DBC/jOOQ/MyBatis/Neo4j → Db; the gRPC client + okhttp WebSocket + Micronaut/Vert.x/Reactor HTTP →
     *  Net. Verb-gated, so each driver's BUILDERS/metadata getters stay pure (no fabrication). */
    @Test
    void round12RawDriverClassifier() {
        // Db drivers — the operation verbs
        assertEquals("Db", Candor.classify("com.mongodb.client.MongoCollection", "insertOne", "(Ljava/lang/Object;)Lcom/mongodb/client/result/InsertOneResult;"));
        assertEquals("Db", Candor.classify("com.mongodb.client.MongoCollection", "find", "()Lcom/mongodb/client/FindIterable;"));
        assertEquals("Db", Candor.classify("com.datastax.oss.driver.api.core.CqlSession", "execute", "(Ljava/lang/String;)Lcom/datastax/oss/driver/api/core/cql/ResultSet;"));
        assertEquals("Db", Candor.classify("io.r2dbc.spi.Statement", "execute", "()Lorg/reactivestreams/Publisher;"));
        assertEquals("Db", Candor.classify("org.jooq.DSLContext", "fetch", "(Ljava/lang/String;)Lorg/jooq/Result;"));
        assertEquals("Db", Candor.classify("org.apache.ibatis.session.SqlSession", "selectList", "(Ljava/lang/String;)Ljava/util/List;"));
        assertEquals("Db", Candor.classify("org.neo4j.driver.Session", "run", "(Ljava/lang/String;)Lorg/neo4j/driver/Result;"));
        // Net clients
        assertEquals("Net", Candor.classify("io.grpc.stub.ClientCalls", "blockingUnaryCall", "(Lio/grpc/Channel;Lio/grpc/MethodDescriptor;Lio/grpc/CallOptions;Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals("Net", Candor.classify("okhttp3.WebSocket", "send", "(Ljava/lang/String;)Z"));
        assertEquals("Net", Candor.classify("io.vertx.ext.web.client.HttpRequest", "send", "()Lio/vertx/core/Future;")); // terminal, not the get/post builder
        assertEquals("Net", Candor.classify("reactor.netty.http.client.HttpClient", "response", "()Lreactor/core/publisher/Mono;"));
        assertEquals("Net", Candor.classify("io.micronaut.http.client.HttpClient", "retrieve", "(Lio/micronaut/http/HttpRequest;)Lorg/reactivestreams/Publisher;"));
        // FABRICATION-avoidance: builders / metadata getters of these drivers stay pure (verb-gated)
        assertNull(Candor.classify("com.mongodb.client.MongoCollection", "getNamespace", "()Lcom/mongodb/MongoNamespace;"));
        assertNull(Candor.classify("com.mongodb.client.MongoCollection", "withReadPreference", "(Lcom/mongodb/ReadPreference;)Lcom/mongodb/client/MongoCollection;"));
        assertNull(Candor.classify("com.datastax.oss.driver.api.core.CqlSession", "getMetadata", "()Lcom/datastax/oss/driver/api/core/metadata/Metadata;"));
        assertNull(Candor.classify("org.jooq.DSLContext", "render", "(Lorg/jooq/QueryPart;)Ljava/lang/String;"));
        assertNull(Candor.classify("org.jooq.DSLContext", "selectFrom", "(Lorg/jooq/Table;)Lorg/jooq/SelectWhereStep;")); // builder
        assertNull(Candor.classify("io.r2dbc.spi.Connection", "createStatement", "(Ljava/lang/String;)Lio/r2dbc/spi/Statement;")); // builder
        // HTTP-client BUILDERS stay pure (only the terminals are Net)
        assertNull(Candor.classify("io.vertx.ext.web.client.WebClient", "get", "(Ljava/lang/String;)Lio/vertx/ext/web/client/HttpRequest;"));
        assertNull(Candor.classify("reactor.netty.http.client.HttpClient", "post", "()Lreactor/netty/http/client/HttpClient$RequestSender;"));
        assertNull(Candor.classify("io.micronaut.http.client.HttpClient", "toBlocking", "()Lio/micronaut/http/client/BlockingHttpClient;"));
    }

    /** Round-12: jOOQ DSLContext.batch(Query…) is a pure BUILDER (FABRICATION fixed) — only the
     *  batchStore/batchInsert/… variants execute; and the classifier-completeness batch (commons-io/
     *  commons-exec/jdbi/HttpAsyncClient/guava-Files/JdbcAggregateTemplate/SystemUtils). */
    @Test
    void round12FixesAndCompleteness() {
        // jOOQ batch: builder pure, executor variants Db
        assertNull(Candor.classify("org.jooq.DSLContext", "batch", "(Lorg/jooq/Query;)Lorg/jooq/Batch;")); // builder
        assertEquals("Db", Candor.classify("org.jooq.DSLContext", "batchStore", "(Ljava/util/Collection;)[I"));
        // completeness
        assertEquals("Fs", Candor.classify("org.apache.commons.io.FileUtils", "readFileToString", "(Ljava/io/File;)Ljava/lang/String;"));
        assertEquals("Fs", Candor.classify("org.apache.commons.io.FileUtils", "writeStringToFile", "(Ljava/io/File;Ljava/lang/String;)V"));
        assertEquals("Fs", Candor.classify("com.google.common.io.Files", "toByteArray", "(Ljava/io/File;)[B"));
        assertEquals("Exec", Candor.classify("org.apache.commons.exec.DefaultExecutor", "execute", "(Lorg/apache/commons/exec/CommandLine;)I"));
        assertEquals("Exec", Candor.classify("org.zeroturnaround.exec.ProcessExecutor", "execute", "()Lorg/zeroturnaround/exec/ProcessResult;"));
        assertEquals("Db", Candor.classify("org.jdbi.v3.core.Handle", "execute", "(Ljava/lang/String;)I"));
        assertEquals("Db", Candor.classify("org.springframework.data.jdbc.core.JdbcAggregateTemplate", "save", "(Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals("Net", Candor.classify("org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient", "execute", "(Lorg/apache/hc/core5/http/nio/AsyncRequestProducer;Lorg/apache/hc/core5/http/nio/AsyncResponseConsumer;Lorg/apache/hc/core5/concurrent/FutureCallback;)Ljava/util/concurrent/Future;"));
        assertEquals("Env", Candor.classify("org.apache.commons.lang3.SystemUtils", "getEnvironmentVariable", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        // fabrication-avoidance: config setters / builders of these owners stay pure
        assertNull(Candor.classify("org.zeroturnaround.exec.ProcessExecutor", "directory", "(Ljava/io/File;)Lorg/zeroturnaround/exec/ProcessExecutor;"));
        assertNull(Candor.classify("org.apache.commons.io.FileUtils", "getTempDirectory", "()Ljava/io/File;")); // returns a path, no I/O
    }

    /** Round-13: guava as*Source/as*Sink are LAZY FACTORIES (FABRICATION fixed → pure); ImageIO File
     *  overloads (Fs) + URL overload (Net); JMXConnectorFactory.connect (Net). */
    @Test
    void round13FixesAndCompleteness() {
        // guava lazy factories must be PURE (were fabricating Fs)
        assertNull(Candor.classify("com.google.common.io.Files", "asByteSource", "(Ljava/io/File;)Lcom/google/common/io/ByteSource;"));
        assertNull(Candor.classify("com.google.common.io.Files", "asCharSink", "(Ljava/io/File;Ljava/nio/charset/Charset;)Lcom/google/common/io/CharSink;"));
        // but the eager verbs stay Fs
        assertEquals("Fs", Candor.classify("com.google.common.io.Files", "write", "([BLjava/io/File;)V"));
        // ImageIO: File → Fs, URL → Net, write(File) → Fs; stream overloads pure
        assertEquals("Fs", Candor.classify("javax.imageio.ImageIO", "read", "(Ljava/io/File;)Ljava/awt/image/BufferedImage;"));
        assertEquals("Net", Candor.classify("javax.imageio.ImageIO", "read", "(Ljava/net/URL;)Ljava/awt/image/BufferedImage;"));
        assertEquals("Fs", Candor.classify("javax.imageio.ImageIO", "write", "(Ljava/awt/image/RenderedImage;Ljava/lang/String;Ljava/io/File;)Z"));
        assertNull(Candor.classify("javax.imageio.ImageIO", "read", "(Ljava/io/InputStream;)Ljava/awt/image/BufferedImage;")); // stream overload pure
        // JMX remote
        assertEquals("Net", Candor.classify("javax.management.remote.JMXConnectorFactory", "connect", "(Ljavax/management/remote/JMXServiceURL;)Ljavax/management/remote/JMXConnector;"));
        // the new SQL-bearing owners (so their table literals reach the gate)
        assertTrue(Candor.isSqlBearingOwner("org/jooq/DSLContext"));
        assertTrue(Candor.isSqlBearingOwner("org/jdbi/v3/core/Handle"));
        assertFalse(Candor.isSqlBearingOwner("com/mongodb/client/MongoCollection")); // a collection name is not SQL
    }

    /** Round-14: logging RESOURCE handlers/appenders (SocketHandler→Net, FileHandler→Fs, DBAppender→Db) are
     *  no longer swallowed by the logging-package gate; JavaFX Clipboard; Kotlin collection-entropy → Rand.
     *  Config getters of the handlers stay pure (verb-gated). */
    @Test
    void round14Completeness() {
        // logging resource handlers — the ctor opens a socket/file/DB
        assertEquals("Net", Candor.classify("java.util.logging.SocketHandler", "<init>", "(Ljava/lang/String;I)V"));
        assertEquals("Fs", Candor.classify("java.util.logging.FileHandler", "<init>", "(Ljava/lang/String;)V"));
        assertEquals("Net", Candor.classify("ch.qos.logback.classic.net.SocketAppender", "start", "()V"));
        assertEquals("Fs", Candor.classify("ch.qos.logback.core.FileAppender", "openFile", "(Ljava/lang/String;)V"));
        assertEquals("Db", Candor.classify("org.apache.logging.log4j.core.appender.db.jdbc.JDBCAppender", "append", "(Lorg/apache/logging/log4j/core/LogEvent;)V"));
        // config getter of a handler stays pure (verb-gated, not whole-owner)
        assertNull(Candor.classify("java.util.logging.SocketHandler", "getLevel", "()Ljava/util/logging/Level;"));
        // a plain Logger emit is still Log (not swallowed)
        assertEquals("Log", Candor.classify("java.util.logging.Logger", "info", "(Ljava/lang/String;)V"));
        // JavaFX clipboard
        assertEquals("Clipboard", Candor.classify("javafx.scene.input.Clipboard", "setContent", "(Ljavafx/scene/input/ClipboardContent;)Z"));
        assertEquals("Clipboard", Candor.classify("javafx.scene.input.Clipboard", "getString", "()Ljava/lang/String;"));
        assertNull(Candor.classify("javafx.scene.input.Clipboard", "toString", "()Ljava/lang/String;")); // §4 pure
        // Kotlin collection entropy
        assertEquals("Rand", Candor.classify("kotlin.collections.CollectionsKt", "random", "(Ljava/util/Collection;Lkotlin/random/Random;)Ljava/lang/Object;"));
        assertEquals("Rand", Candor.classify("kotlin.ranges.RangesKt", "random", "(Lkotlin/ranges/IntRange;Lkotlin/random/Random;)I"));
        assertNull(Candor.classify("kotlin.collections.CollectionsKt", "first", "(Ljava/util/List;)Ljava/lang/Object;")); // pure verb stays pure
    }

    /** Round-15: MulticastSocket/SSLSocket inherited + SSL-config accessors must NOT fabricate Net (the
     *  whole-owner Net rule sailed past the isPureHandleAccessor carve-out); Apache fluent Request.execute. */
    @Test
    void round15FabricationAndCompleteness() {
        // inherited Socket accessors on the subclass — PURE (were fabricating Net)
        assertNull(Candor.classify("java.net.MulticastSocket", "getPort", "()I"));
        assertNull(Candor.classify("java.net.MulticastSocket", "isClosed", "()Z"));
        assertNull(Candor.classify("javax.net.ssl.SSLSocket", "getPort", "()I"));
        // SSLSocket's own handshake-config surface — PURE (touch no wire)
        assertNull(Candor.classify("javax.net.ssl.SSLSocket", "getEnabledCipherSuites", "()[Ljava/lang/String;"));
        assertNull(Candor.classify("javax.net.ssl.SSLSocket", "setEnabledCipherSuites", "([Ljava/lang/String;)V"));
        assertNull(Candor.classify("javax.net.ssl.SSLSocket", "setUseClientMode", "(Z)V"));
        // but the real I/O on these types stays Net
        assertEquals("Net", Candor.classify("java.net.MulticastSocket", "send", "(Ljava/net/DatagramPacket;)V"));
        assertEquals("Net", Candor.classify("javax.net.ssl.SSLSocket", "startHandshake", "()V"));
        assertEquals("Net", Candor.classify("javax.net.ssl.SSLSocket", "getOutputStream", "()Ljava/io/OutputStream;"));
        // Apache fluent facade
        assertEquals("Net", Candor.classify("org.apache.hc.client5.http.fluent.Request", "execute", "()Lorg/apache/hc/client5/http/fluent/Response;"));
    }

    /** Round-10 JDBC silent-pure adds: ResultSet cursor moves, Connection.isValid, Driver.connect,
     *  DatabaseMetaData catalog queries, concrete-pool getConnection → Db; scalar reads + capability
     *  getters stay pure (no fabrication). */
    @Test
    void round10JdbcSilentPureAdds() {
        assertEquals("Db", Candor.classify("java.sql.ResultSet", "next", "()Z"));
        assertEquals("Db", Candor.classify("java.sql.ResultSet", "refreshRow", "()V"));
        assertNull(Candor.classify("java.sql.ResultSet", "getString", "(I)Ljava/lang/String;"));   // in-memory row read
        assertEquals("Db", Candor.classify("java.sql.Connection", "isValid", "(I)Z"));
        assertEquals("Db", Candor.classify("java.sql.Driver", "connect", "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;"));
        assertEquals("Db", Candor.classify("java.sql.DatabaseMetaData", "getTables", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Ljava/sql/ResultSet;"));
        assertNull(Candor.classify("java.sql.DatabaseMetaData", "getDatabaseProductName", "()Ljava/lang/String;")); // capability getter pure
        assertEquals("Db", Candor.classify("com.zaxxer.hikari.HikariDataSource", "getConnection", "()Ljava/sql/Connection;"));
    }

    /** Round-10 IPv6 hostPart gate-evasion: a naive first-colon split collapsed `2001:db8::1` to `2001`, so
     *  one allowed IPv6 covered the whole block. Bracketed and bare IPv6 are now handled; host:port splits. */
    @Test
    void hostPartIsIpv6Aware() {
        assertEquals("api.stripe.com", Candor.hostPart("api.stripe.com:443"));
        assertEquals("10.0.0.1", Candor.hostPart("10.0.0.1:6379"));
        // NB: a raw URL never reaches hostPart — netHostLiteral cleans the reached host to a bare authority
        // at extraction, and a policy author writes a bare host. (A URL has >1 colon so the bare-IPv6 guard
        // returns it verbatim, which is harmless — it simply won't match a clean reached host.)
        // bracketed IPv6 with/without port → the bracketed host
        assertEquals("2001:db8::1", Candor.hostPart("[2001:db8::1]:443"));
        assertEquals("2001:db8::1", Candor.hostPart("[2001:db8::1]"));
        // bare IPv6 (no brackets, >1 colon) → returned whole, NOT collapsed to "2001"
        assertEquals("2001:db8::1", Candor.hostPart("2001:db8::1"));
        assertEquals("::1", Candor.hostPart("::1"));
    }
}
