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
}
