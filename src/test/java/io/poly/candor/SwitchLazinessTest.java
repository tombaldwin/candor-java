package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * SPEC §3.4 (a) ⟨0.42⟩, SOUNDNESS R1634: "an engine MUST NOT satisfy this by reading every switch at process start, because that
 * makes a clean report's verdict depend on which engine hoists its reads." Java's switches were {@code static final boolean} fields
 * initialised at class load, and the main class, the report writer, the policy and the loader are loaded by EVERY verb — so reading
 * them through {@link Env} unchanged would have listed (and refused over) a switch that {@code gate --report} never ran.
 *
 * <p>This test enumerates every registered switch FROM SOURCE (the engine has no list — {@link EnvLint#registeredSwitches}), sets all
 * of them at once to the value that selects the non-default branch, and {@link SwitchesCliTest} then runs the evaluator verbs in that
 * environment. The enumeration is checked against the table of non-kill values below, so a NEW opt-in switch fails here until it is
 * given a value — a test that silently skipped it would have proven nothing about it.
 */
class SwitchLazinessTest {

    /** The value that SELECTS the non-default branch, for the switches that are not default-ON kill switches. */
    private static final Map<String, String> OPT_IN_SET = Map.of(
            "CANDOR_R1201_FLOOR", "none",      // default: the full floor
            "CANDOR_R1217_TOP", "cha",         // default: `floor`
            "CANDOR_SITE_FALLBACK", "A",       // default: unset
            "CANDOR_R1461", "off",             // the property/env spelling of the kill switch is `off`, not `0`
            "CANDOR_R1461_WIDE", "1");         // default: off

    /** Every registered switch, each set to the value that makes it SET. */
    static Map<String, String> everySwitchSet() throws Exception {
        Map<String, String> found = EnvLint.registeredSwitches(Path.of("src/main/java"));
        found.keySet().stream().filter(k -> k.startsWith("<non-literal")).findFirst().ifPresent(k -> {
            throw new AssertionError("a switch registered under a computed name cannot be enumerated (and so cannot be set by "
                    + "this test): " + k + " — pass the name as a string literal at the registering call");
        });
        Map<String, String> out = new TreeMap<>();
        for (var e : found.entrySet()) {
            if (e.getValue().startsWith("property")) continue;   // a JVM property switch: see everyPropertySet
            boolean kill = e.getValue().startsWith("killSwitch");
            String v = kill ? "0" : OPT_IN_SET.get(e.getKey());
            assertTrue(v != null, "switch " + e.getKey() + " (" + e.getValue() + ") has no SET value here — add it to OPT_IN_SET");
            out.put(e.getKey(), v);
        }
        return out;
    }

    /** The value that SELECTS the non-default branch of each JVM-property switch (SOUNDNESS R1645), keyed {@code -D<name>} for the CLI harness. */
    private static final Map<String, String> PROPERTY_SET = Map.of(
            "candor.r1078", "off", "candor.r1461", "off", "candor.r1461.wide", "on", "candor.frameworkReach", "off",
            "candor.frameworkPure", "/dev/null");   // a PATH: any value is SET, and a gate that never ran the logic must never read it

    /** Every registered JVM-property switch, each set. Enumerated FROM SOURCE like the variables, so a new property fails here until it is given a value. */
    static Map<String, String> everyPropertySet() throws Exception {
        Map<String, String> out = new TreeMap<>();
        for (var e : EnvLint.registeredSwitches(Path.of("src/main/java")).entrySet()) {
            if (!e.getValue().startsWith("property")) continue;
            String v = PROPERTY_SET.get(e.getKey());
            assertTrue(v != null, "property switch " + e.getKey() + " has no SET value here — add it to PROPERTY_SET");
            out.put("-D" + e.getKey(), v);
        }
        return out;
    }

    @Test
    void thePropertySwitchesAreEnumeratedFromSource() throws Exception {
        assertEquals(5, everyPropertySet().size(), "the five candor.* properties SOUNDNESS R1645 measured: " + everyPropertySet().keySet());
        for (String k : PROPERTY_SET.keySet()) assertTrue(everyPropertySet().containsKey("-D" + k), "stale PROPERTY_SET row " + k);
    }

    @Test
    void theEnumerationIsRealAndComplete() throws Exception {
        Map<String, String> all = everySwitchSet();
        // the census (candor-handoff/r1634/env-classified.tsv) counted 20 result-moving java variables; SOUNDNESS R1574
        // added CANDOR_R1574 (a kill switch, like R1573's)
        assertEquals(21, all.size(), "the registered switches are not the census's 20 + CANDOR_R1574: " + all.keySet());
        for (String known : new String[]{"CANDOR_R1304", "CANDOR_R1565", "CANDOR_D1", "CANDOR_D1_SEED", "CANDOR_R1336", "CANDOR_SITE_FALLBACK"})
            assertTrue(all.containsKey(known), known + " is missing from the source enumeration — the AST walk has a hole: " + all.keySet());
        // and the opt-in table has no entry for a switch that is gone (a stale row would hide a rename)
        for (String k : OPT_IN_SET.keySet()) assertTrue(all.containsKey(k), "stale OPT_IN_SET row " + k);
    }
}
