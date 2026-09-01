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
 * R86 teeth: a backward literal-argument walk must bound at a control-flow JOIN, not walk through it.
 * Before the fix, a ternary/switch-expression feeding a literal straight into a call argument compiled
 * to two branches merging immediately before the call — the walker saw only whichever branch's literal
 * sat physically ADJACENT to the call, a POSITIVE claim about the WRONG destination, never an omission.
 *
 * <p>{@code new Socket(cond ? "danger.example.net" : "safe-partner.example.com", 443)} reported ONLY
 * "safe-partner.example.com" and nothing else — {@code danger.example.net} was entirely absent from the
 * report, so a `deny Net[unknown-host]` policy passed on the strength of the wrong host.
 */
class LiteralJoinBoundTest {

    /** THE CARDINAL SIN, reproduced directly: a ternary host feeding a Socket ctor must not certify
     *  either branch — the merged call must read as NO literal captured (host surface incomplete),
     *  never the branch that happens to sit adjacent to the join in bytecode. */
    @Test
    void ternaryHostNotCapturedFromAdjacentBranch() throws Exception {
        Path cls = compile(Map.of("app/A.java", String.join("\n",
            "package app;",
            "import java.net.Socket;",
            "public class A {",
            "  void call(boolean cond) throws Exception {",
            "    Socket s = new Socket(cond ? \"danger.example.net\" : \"safe-partner.example.com\", 443);",
            "    s.close();",
            "  }",
            "}")));
        try {
            Candor.runScan(cls);
            TreeSet<String> hosts = AnalysisState.ctx().hostsDirect.getOrDefault("app.A.call", new TreeSet<>());
            assertFalse(hosts.contains("danger.example.net"),
                    "must never fabricate the dangerous branch as the host, got " + hosts);
            assertTrue(hosts.isEmpty(), "a ternary-merged host must capture NEITHER branch (never the "
                    + "adjacent one alone, either) — the caller reads this as incomplete, not certified, "
                    + "got " + hosts);
            assertTrue(AnalysisState.ctx().surfaceIncomplete.getOrDefault("app.A.call", new TreeSet<>())
                    .contains("Net"), "the merged call must be surface-incomplete (fail-closed), not silently pure/certified");
        } finally { rm(cls.getParent()); }
    }

    /** Order-independence: a switch-expression directly in the ctor argument must not capture whichever
     *  case compiles adjacent to the merge, in EITHER branch order. */
    @Test
    void switchExpressionHostNotCapturedEitherOrder() throws Exception {
        Path cls = compile(Map.of("app/B.java", String.join("\n",
            "package app;",
            "import java.net.Socket;",
            "public class B {",
            "  void dangerFirst(int x) throws Exception {",
            "    Socket s = new Socket(switch (x) {",
            "      case 1 -> \"danger.example.net\";",
            "      default -> \"safe-partner.example.com\";",
            "    }, 443);",
            "    s.close();",
            "  }",
            "  void dangerDefault(int x) throws Exception {",
            "    Socket s = new Socket(switch (x) {",
            "      case 1 -> \"safe-partner.example.com\";",
            "      default -> \"danger.example.net\";",
            "    }, 443);",
            "    s.close();",
            "  }",
            "}")));
        try {
            Candor.runScan(cls);
            for (String fn : new String[] { "app.B.dangerFirst", "app.B.dangerDefault" }) {
                TreeSet<String> hosts = AnalysisState.ctx().hostsDirect.getOrDefault(fn, new TreeSet<>());
                assertTrue(hosts.isEmpty(), fn + ": a switch-expression-merged host must capture neither "
                        + "branch regardless of which arm sits adjacent to the merge, got " + hosts);
            }
        } finally { rm(cls.getParent()); }
    }

    /** CONTROL 1: a plain single-branch literal (no merge at all) must still be captured EXACTLY as
     *  before — the join bound must not cost the walkers their existing precision. */
    @Test
    void plainSingleBranchLiteralStillCaptured() throws Exception {
        Path cls = compile(Map.of("app/C.java", String.join("\n",
            "package app;",
            "import java.net.Socket;",
            "public class C {",
            "  void call() throws Exception { new Socket(\"api.stripe.com\", 443).close(); }",
            "}")));
        try {
            Candor.runScan(cls);
            TreeSet<String> hosts = AnalysisState.ctx().hostsDirect.getOrDefault("app.C.call", new TreeSet<>());
            assertTrue(hosts.contains("api.stripe.com:443"),
                    "an unmerged single-branch literal must still be captured exactly as before, got " + hosts);
        } finally { rm(cls.getParent()); }
    }

    /** CONTROL 2 (the over-charge direction): a literal in an UNRELATED statement before a
     *  runtime-computed call must still NOT be attributed to it — the join bound must not widen the
     *  window past what the pre-existing NEW/store bounds already refuse. */
    @Test
    void unrelatedPriorLiteralStillNotAttributed() throws Exception {
        Path cls = compile(Map.of("app/D.java", String.join("\n",
            "package app;",
            "import java.net.Socket;",
            "public class D {",
            "  void call(String runtimeHost) throws Exception {",
            "    String tag = \"internal.metrics.svc\";",
            "    Socket s = new Socket(runtimeHost, 443);",
            "    s.close();",
            "  }",
            "}")));
        try {
            Candor.runScan(cls);
            TreeSet<String> hosts = AnalysisState.ctx().hostsDirect.getOrDefault("app.D.call", new TreeSet<>());
            assertFalse(hosts.contains("internal.metrics.svc"),
                    "an unrelated prior statement's literal must never be attributed to a runtime host arg, got "
                            + hosts);
        } finally { rm(cls.getParent()); }
    }
}
