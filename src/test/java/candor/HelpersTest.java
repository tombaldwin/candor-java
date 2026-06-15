package candor;

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
    void isStdlibContainerDispatchIsInterfacesOnly() {
        assertTrue(Candor.isStdlibContainerDispatch("java/util/List"));
        assertTrue(Candor.isStdlibContainerDispatch("java/util/Map"));
        assertTrue(Candor.isStdlibContainerDispatch("java/util/Iterator"));
        assertFalse(Candor.isStdlibContainerDispatch("java/util/ArrayList")); // a concrete impl, not the iface
        assertFalse(Candor.isStdlibContainerDispatch("com/example/MyList"));
    }

    @Test
    void pathCoveredIsPrefixAndTraversalSafe() {
        assertTrue(Candor.pathCovered("/etc", "/etc/passwd"));
        assertTrue(Candor.pathCovered("/etc", "/etc"));
        assertFalse(Candor.pathCovered("/etc", "/var/log"));
        assertFalse(Candor.pathCovered("/a", "/a/../b"));  // `..` in the reached path never covers
        assertFalse(Candor.pathCovered("etc", "/etc"));    // relative allow vs absolute reach
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

    /** The numeric semver-tuple compare behind `--check-update`: equal, patch-newer, minor-newer, older,
     *  and the trailing-zero padding ("0.5" == "0.5.0") so a 2-component spec never spuriously trips. */
    @Test
    void compareSemverIsNumericTuple() {
        assertEquals(0, Candor.compareSemver("0.5.0", "0.5.0"));        // equal
        assertTrue(Candor.compareSemver("0.5.1", "0.5.0") > 0);         // patch newer
        assertTrue(Candor.compareSemver("0.6.0", "0.5.9") > 0);         // minor newer beats higher patch
        assertTrue(Candor.compareSemver("0.5.0", "0.6.0") < 0);         // older
        assertTrue(Candor.compareSemver("0.10.0", "0.9.0") > 0);        // NUMERIC, not lexical (10 > 9)
        assertEquals(0, Candor.compareSemver("0.5", "0.5.0"));          // missing components pad to 0
    }
}
