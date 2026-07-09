package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The AS-EFF-007 taint dataflow ({@link Interp.TaintInterpreter}) — specifically the frame-JOIN and
 * operation arms that had never executed under any harness: {@code merge} (control-flow join: tainted if
 * tainted on EITHER path), {@code binaryOperation} (arithmetic carries taint), and {@code
 * ternaryOperation} (array stores). AS-EFF-007 is a HEURISTIC ADVISORY (SEMANTICS §6): these tests pin
 * the documented semantics — over- and under-flagging arms included — not an aspiration.
 *
 * <p>Taint is enabled the way main() does it (the config layer), by installing a config whose
 * {@code taint} key is truthy before {@link Candor#runScan}; restored to empty after each test.
 */
class TaintPropagationTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void enableTaint() throws Exception {
        Candor.resetState();
        Path cfg = Files.createTempFile(tmp, "cfg", "");
        Files.writeString(cfg, "taint true\n");
        Candor.config = Config.load(cfg);
        Candor.gateViolations.clear();
        Candor.gateCapture = true;
    }

    @AfterEach
    void restore() {
        Candor.config = Config.empty();
        Candor.gateCapture = false;
        Candor.gateViolations.clear();
    }

    private static EffectSet taintedOf(String fn) {
        return AnalysisState.ctx().tainted.getOrDefault(fn, EffectSet.empty());
    }

    // ── merge: a control-flow JOIN is tainted if tainted on either path ───────────────────────────────

    @Test
    void valueTaintedOnOneIfBranchStillFlagsAtTheSink() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/S.java", """
                package app;
                public class S {
                  public void go(String p, boolean c) {
                    String x = "safe";
                    if (c) x = p;                       // tainted on ONE path only
                    try { Runtime.getRuntime().exec(x); } catch (Exception e) {}
                  }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        assertTrue(taintedOf("app.S.go").effects().contains(Effect.EXEC),
                "a join of {safe, param} is tainted — tainted-on-either-path (TaintInterpreter.merge)");
        int advisories = Policy.checkTaint(inferred);
        assertEquals(1, advisories, "one AS-EFF-007 advisory");
        assertEquals("AS-EFF-007", Candor.gateViolations.get(0).get("rule"));
        assertEquals("app.S.go", Candor.gateViolations.get(0).get("fn"));
    }

    @Test
    void ternaryConditionalJoinCarriesTaint() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/T.java", """
                package app;
                public class T {
                  public void go(String p, boolean c) {
                    try { Runtime.getRuntime().exec(c ? p : "safe"); } catch (Exception e) {}
                  }
                }
                """));
        Candor.runScan(cls);
        assertTrue(taintedOf("app.T.go").effects().contains(Effect.EXEC),
                "the ?: operator is a branch join — tainted when either arm derives from a parameter");
    }

    @Test
    void bothBranchesCleanStaysClean() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/C.java", """
                package app;
                public class C {
                  public void go(boolean c) {
                    String x = c ? "ls" : "pwd";        // constants on BOTH paths
                    try { Runtime.getRuntime().exec(x); } catch (Exception e) {}
                  }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        assertTrue(taintedOf("app.C.go").isEmpty(),
                "a join of two constants is clean — no false AS-EFF-007 from the merge itself");
        assertEquals(0, Policy.checkTaint(inferred));
    }

    // ── binaryOperation: arithmetic carries taint ─────────────────────────────────────────────────────

    @Test
    void arithmeticOnAParameterCarriesTaintToTheSink() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/B.java", """
                package app;
                public class B {
                  public void go(int p) {
                    int port = p + 1;                   // IADD: tainted ⊕ constant → tainted
                    try { new java.net.Socket("h", port).close(); } catch (Exception e) {}
                  }
                }
                """));
        Candor.runScan(cls);
        assertTrue(taintedOf("app.B.go").effects().contains(Effect.NET),
                "binaryOperation propagates taint through arithmetic to an injection-class (Net) sink");
    }

    @Test
    void arithmeticOnConstantsStaysClean() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/D.java", """
                package app;
                public class D {
                  public void go(int p) {
                    int port = 80 + 363;                // constants only; the param is never used
                    try { new java.net.Socket("h", port).close(); } catch (Exception e) {}
                  }
                }
                """));
        Candor.runScan(cls);
        assertTrue(taintedOf("app.D.go").isEmpty(), "constant arithmetic is clean — no blanket taint");
    }

    // ── ternaryOperation: array stores (xASTORE) — the pinned under-flag ──────────────────────────────

    @Test
    void arrayRoundTripDropsTaintThePinnedHeuristicLimit() throws Exception {
        // AASTORE is the interpreter's ternaryOperation (array, index, value → no result); the store
        // cannot mark the ARRAY value, so reading the element back (AALOAD, binaryOperation over the
        // clean array ref + clean index) reads UNTAINTED. This is the documented under-flagging of the
        // intraprocedural heuristic (SEMANTICS §6 "advisory"; the diagnostic itself says "may over- or
        // under-flag") — pinned here as current semantics, NOT as desirable: if the interpreter ever
        // learns array-element taint, flip this assertion deliberately.
        Path cls = TestCompiler.compile(Map.of("app/A.java", """
                package app;
                public class A {
                  public void go(String p) {
                    String[] a = new String[1];
                    a[0] = p;                            // ternaryOperation (AASTORE) executes here
                    try { Runtime.getRuntime().exec(a[0]); } catch (Exception e) {}
                  }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        assertTrue(taintedOf("app.A.go").isEmpty(),
                "array round-trip loses taint (intraprocedural heuristic limit, pinned)");
        assertEquals(0, Policy.checkTaint(inferred));
        // The Exec itself is still reported, of course — only the taint ADVISORY is absent.
        assertTrue(inferred.getOrDefault("app.A.go", EffectSet.empty()).effects().contains(Effect.EXEC));
    }

    @Test
    void taintedArrayIndexTaintsTheLoadedElement() throws Exception {
        // The over-approximating half of the same pair: AALOAD is binaryOperation(arrayref, index) and
        // taint flows from EITHER operand — so a parameter-derived INDEX taints the loaded element.
        Path cls = TestCompiler.compile(Map.of("app/I.java", """
                package app;
                public class I {
                  public void go(int p) {
                    String[] cmds = {"ls", "pwd"};
                    try { Runtime.getRuntime().exec(cmds[p]); } catch (Exception e) {}
                  }
                }
                """));
        Candor.runScan(cls);
        assertTrue(taintedOf("app.I.go").effects().contains(Effect.EXEC),
                "a caller-derived array index selects the command — flagged (over-approximation, by design)");
    }

    // ── the advisory contract: findings never fail the gate ───────────────────────────────────────────

    @Test
    void taintFindingsAreAdvisoryNotViolations() throws Exception {
        // checkTaint returns a count for MESSAGING only; main() keeps it out of `violations` (exit 1).
        // The unit-level pin: the diagnostics carry AS-EFF-007 and nothing else fires.
        Path cls = TestCompiler.compile(Map.of("app/S.java", """
                package app;
                public class S {
                  public void go(String p) {
                    try { Runtime.getRuntime().exec(p); } catch (Exception e) {}
                  }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int advisories = Policy.checkTaint(inferred);
        assertEquals(1, advisories);
        assertTrue(Candor.gateViolations.stream().allMatch(m -> "AS-EFF-007".equals(m.get("rule"))));
        assertFalse(taintedOf("app.S.go").isEmpty(), "the direct param-to-sink base case flags");
    }
}
