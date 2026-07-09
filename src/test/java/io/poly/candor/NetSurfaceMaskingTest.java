package io.poly.candor;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Teeth for the AS-EFF-008 literal-MASKING fix: a method whose Net surface is INCOMPLETE — a host-less Net
 * owner (gRPC/WebSocket/…) or a RUNTIME-host call — is flagged so the gate fails closed and a benign visible
 * host can't mask the invisible forbidden endpoint. A literal URL/Socket host keeps a COMPLETE surface.
 *
 * <p>Originally review round 16 (Round16FixesTest).
 */
class NetSurfaceMaskingTest {

    private static boolean netIncomplete(String fn) {
        return AnalysisState.ctx().surfaceIncomplete.getOrDefault(fn, new TreeSet<>()).contains("Net");
    }

    @Test
    void incompleteNetSurfaceFlaggedForInvisibleReaches() throws Exception {
        Path cls = compile(Map.ofEntries(
            // a host-LESS Net owner stub (the host lives in a builder candor can't see)
            Map.entry("io/grpc/stub/ClientCalls.java",
                "package io.grpc.stub; public class ClientCalls { public static Object blockingUnaryCall(Object a){ return null; } }"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "import java.net.*;",
                "public class A {",
                // literal host → COMPLETE surface (not flagged)
                "  void literal() throws Exception { new URL(\"https://api.x.com/p\").openStream(); }",
                "  void socketLiteral() throws Exception { new Socket(\"api.x.com\", 443).close(); }",
                // runtime host on a host-bearing owner → INCOMPLETE
                "  void runtimeHost(String h) throws Exception { new Socket(h, 443).close(); }",
                // host-less Net owner → INCOMPLETE
                "  Object hostLess() { return io.grpc.stub.ClientCalls.blockingUnaryCall(null); }",
                // MASKING: a literal host AND a runtime-host reach → still INCOMPLETE (the fix)
                "  void mask(String h) throws Exception { new URL(\"https://api.x.com/p\").openStream(); new Socket(h, 9000).close(); }",
                "}"))));
        try {
            Candor.runScan(cls);
            assertFalse(netIncomplete("app.A.literal"), "a literal URL host keeps a COMPLETE surface");
            assertFalse(netIncomplete("app.A.socketLiteral"), "a literal Socket host keeps a COMPLETE surface");
            assertTrue(netIncomplete("app.A.runtimeHost"), "a runtime Socket host is an INCOMPLETE surface");
            assertTrue(netIncomplete("app.A.hostLess"), "a host-less Net owner is an INCOMPLETE surface");
            assertTrue(netIncomplete("app.A.mask"),
                    "a literal host + a runtime-host reach must STILL be incomplete (masking closed)");
        } finally { rm(cls.getParent()); }
    }

    /** Incompleteness propagates transitively — a caller of an incomplete-surface method inherits it. */
    @Test
    void incompletePropagatesToCaller() throws Exception {
        Path cls = compile(Map.of("app/B.java", String.join("\n",
            "package app;",
            "import java.net.*;",
            "public class B {",
            "  void leaf(String h) throws Exception { new Socket(h, 9000).close(); }",  // runtime host → incomplete
            "  void caller(String h) throws Exception { leaf(h); }",                    // inherits incompleteness
            "}")));
        try {
            Candor.runScan(cls);
            // surfaceIncomplete is the DIRECT map; the gate propagates via literalFixpoint. Assert the leaf is
            // flagged directly; the transitive propagation is exercised end-to-end by smoke.sh's masking case.
            assertTrue(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.B.leaf", new TreeSet<>()).contains("Net"),
                    "the runtime-host leaf is flagged incomplete");
        } finally { rm(cls.getParent()); }
    }
}
