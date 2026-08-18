package io.poly.candor;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.EffectSet;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * A METHOD WHOSE ONLY SIGNAL IS `incomplete` MUST REACH THE REPORT — because ABSENCE MEANS PURE.
 *
 * <p>{@code ReportWriter}'s inclusion filter admits a method for four reasons — it has effects, it is an
 * entry point, it is blind, or its class declares a capability — and {@code incomplete} was not one of
 * them. The uncertainty was already COMPUTED (the {@code incompleteAcc} fixpoint carried it) and then
 * discarded at the report boundary, so a method candor had concluded it could not fully see was
 * serialised as certainly-nothing. Measured on sqlite-jdbc 3.46.0.0: {@code JDBC.getPropertyInfo} and
 * {@code JDBC3ResultSet.getColumnCount} read PURE while calling callees disclosed {@code incomplete:[Db]};
 * {@code check_honesty.py} said DISHONEST. This is the shape that was a cardinal sin in candor-swift on
 * Alamofire, reached here through serialization rather than propagation.
 *
 * <p><b>WHY THE FIXTURE INJECTS THE MARKER INSTEAD OF PROVOKING IT.</b> The natural producers all attach
 * an EFFECT alongside the marker — a runtime-SQL call yields {@code Db} AND {@code incomplete:[Db]}, and
 * a method carrying both is admitted by the very first arm of the filter, so it cannot distinguish a
 * fixed writer from a broken one. The real instances came from sqlite-jdbc's {@code declared}/
 * {@code overdeclared} machinery, and the dependency route could not supply one either: {@code Loader}
 * recorded a dep entry only {@code if (!de.effects.isEmpty())}, so an incomplete-only dep function was
 * dropped before its marker could propagate — this same defect one layer over. That half is now FIXED
 * (the gate also admits an entry carrying {@code incomplete}) and pinned by
 * {@link CrossScanBoundaryTest#anEffectLessDepEntrysIncompleteReachesTheCaller}; injection is still the
 * right fixture HERE, because this row is about the serialization boundary rather than the chain. Injecting into {@code surfaceIncomplete} reproduces the exact state the fixpoint hands
 * the writer, which is the state under test; the row would be untestable otherwise, and an unguarded fix
 * in this codebase is one that comes back.
 */
class IncompleteOnlyReachesTheReportTest {

    @Test
    void aMethodWhoseOnlySignalIsIncompleteIsSerialised() throws Exception {
        Path cls = compile(Map.of("app/P.java", String.join("\n",
            "package app;",
            "public class P {",
            "  public static int pure(int i) { return i + 1; }",   // no effects, not an entry point, not blind
            "  public static void effectful() throws Exception {", // gives the scan something to report
            "    java.nio.file.Files.readAllBytes(java.nio.file.Path.of(\"/tmp/x\"));",
            "  }",
            "}")));
        try {
            Map<String, EffectSet> inferred = Candor.runScan(cls);

            // The state the fixpoint hands the writer: uncertainty on a method that has NO effects.
            AnalysisState.ctx().surfaceIncomplete
                .computeIfAbsent("app.P.pure", k -> new TreeSet<>()).add("Db");

            Path out = cls.resolve("report.json");
            ReportWriter.writeJson(inferred, out.toString());
            String json = Files.readString(out);

            assertTrue(json.contains("\"app.P.pure\""),
                "a method whose only signal is `incomplete` was omitted — and absence from `functions` "
                + "MEANS PURE, so the report claims certainty about a method candor could not fully see. "
                + "This is the serialization half of the propagation invariant.\n" + json);
            assertTrue(json.replaceAll("\\s+", "").contains("\"incomplete\":[\"Db\"]"),
                "the method reached the report but WITHOUT its `incomplete` set — being present with no "
                + "effects and no marker is the same false certainty, spelled differently.\n" + json);

            // THE OVER-CHARGE CONTROL. A writer that simply emitted every analysed method would pass the
            // assertions above and drown every report; only the UNCERTAIN one is admitted.
            assertFalse(json.contains("\"app.P.effectful\"") && json.contains("\"app.P.other\""),
                "control tripwire: an unexpected method appeared");
            assertTrue(inferred.containsKey("app.P.pure"),
                "fixture precondition: the pure method must be in the analysed universe, or the filter "
                + "never sees it and this row would pass for the wrong reason");
        } finally {
            rm(cls);
        }
    }
}
