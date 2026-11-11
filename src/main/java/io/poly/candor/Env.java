package io.poly.candor;

import java.util.Map;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.function.Predicate;

/**
 * THE ONE PLACE THIS ENGINE READS ITS ENVIRONMENT (SPEC §3.4 ⟨0.42⟩, SOUNDNESS R1634).
 *
 * <p>Every {@code System.getenv} and every enumeration of the process environment in {@code src/main} lives in this
 * class, and {@code EnvLintTest} fails the suite on any other. That is what makes the clause enforceable without a
 * list: SPEC §3.4 says "the registration is the read", because a list of switch names beside the code that reads
 * them is an allowlist, and it fails in the absence direction — a switch added without its entry is exactly the
 * silent one. There is no table of names in this file.
 *
 * <p>FOUR KINDS OF READ, and the kind is chosen at the call site by what the variable does:
 * <ul>
 *   <li>{@link #switchRead}, {@link #killSwitchOn}, {@link #killSwitch}, {@link #optIn} — a RESULT-MOVING switch: a
 *       kill switch for a closed defect or an opt-in mode, whose value selects which logic runs. When the value, as
 *       the caller reads it, selects a branch other than the one an unset variable selects ({@code isSet}), the name
 *       is recorded. Recorded names are the report's {@code switches} (§2) and make a gate refuse (§3.3 cause (e)).
 *       Java's kill switches are default-ON, so {@code CANDOR_Rnnnn=0} is SET and {@code =1}, or unset, is not.</li>
 *   <li>{@link #trace} — a DIAGNOSTIC: the value only decides whether something is written to stderr. No report or
 *       verdict byte can depend on it, so nothing is recorded (§3.4: "a read that only writes to stderr is out of
 *       scope"). A trace read that moves a result is a switch: reclassify it.</li>
 *   <li>{@link #operator} — an INPUT the operator documents: a path to a policy, baseline, dependency report or
 *       configuration file, the report locator, a gate-mode or scan-mode config key's environment spelling, a tooling
 *       knob. Configuration, out of scope (§3.4).</li>
 *   <li>{@link #childEnvironment} — the environment handed to a child process the engine starts. An enumeration, so it
 *       lives here too; it reads nothing on behalf of this process's answer.</li>
 * </ul>
 *
 * <p>AN ENGINE MUST NOT READ EVERY SWITCH AT PROCESS START (§3.4 (a)): a read happens where the logic the variable
 * selects is reached, and a name is consulted only when that read executes. A static initialiser counts for the
 * process that ran it — so a switch field in a class that {@code gate --report} also loads (the main class, the
 * report writer, the policy, the loader) is a {@link Switch}, read on first USE, never a {@code static final boolean}
 * read at class initialisation. {@code SwitchLazinessTest} sets every registered switch and runs the evaluator verbs.
 */
public final class Env {
    private Env() {}

    /** The switches set AND consulted by this process so far, sorted by code point (names are ASCII; the comparator is
     *  the contract's, not the String default's UTF-16 order). */
    private static final ConcurrentSkipListSet<String> CONSULTED = new ConcurrentSkipListSet<>(Env::byCodePoint);

    /** Code-point order, as SPEC §2 ({@code switches}) requires. */
    static int byCodePoint(String a, String b) {
        int i = 0, j = 0;
        while (i < a.length() && j < b.length()) {
            int x = a.codePointAt(i), y = b.codePointAt(j);
            if (x != y) return Integer.compare(x, y);
            i += Character.charCount(x);
            j += Character.charCount(y);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    /** A RESULT-MOVING read. Returns the raw value; records {@code name} when {@code isSet} says the value selects a
     *  branch other than the one an unset variable selects. */
    public static String switchRead(String name, Predicate<String> isSet) {
        return recorded(name, isSet, System.getenv(name));
    }

    /** A RESULT-MOVING read of a JVM SYSTEM PROPERTY (SPEC §3.4 ⟨0.42⟩ "THE CLASS BINDS THE EFFECT, NOT THE CHANNEL",
     *  SOUNDNESS R1645). The same rule as {@link #switchRead}: a property reaches the JVM by the command line,
     *  {@code JAVA_TOOL_OPTIONS}, {@code JDK_JAVA_OPTIONS}, {@code _JAVA_OPTIONS} or a start script's options, and one
     *  {@code System.getProperty} cannot tell them apart. Recorded under {@code name} as the engine reads it
     *  ({@code candor.r1078}), no {@code -D}, never the value. */
    public static String propertySwitchRead(String name, Predicate<String> isSet) {
        return recorded(name, isSet, System.getProperty(name));
    }

    private static String recorded(String name, Predicate<String> isSet, String v) {
        if (isSet.test(v)) CONSULTED.add(name);
        return v;
    }

    /** A JDK-OWN property that DESCRIBES THE HOST ({@code java.io.tmpdir}, {@code org.graalvm.nativeimage.imagecode}):
     *  configuration, out of scope (§3.4: "a property that … describes the host"). Excluded BY NAME: a {@code candor.}
     *  name is the engine's own and can only be a switch or an operator input, so this refuses one loudly. */
    public static String hostProperty(String name) {
        if (name.regionMatches(true, 0, "candor.", 0, 7))
            throw new IllegalArgumentException("hostProperty is for JDK-own properties; " + name + " is the engine's: use propertySwitchRead");
        return System.getProperty(name);
    }

    /** A default-ON kill switch read now: {@code =0} is SET. {@code CANDOR_Rnnnn=1}, or unset, is the default. For a
     *  class that only a scan loads; a class the evaluator verbs also load holds a {@link #killSwitch} instead. */
    public static boolean killSwitchOn(String name) {
        return !"0".equals(switchRead(name, "0"::equals));
    }

    /** A DIAGNOSTIC read: the value only decides what is written to stderr. Never recorded. */
    public static String trace(String name) {
        return System.getenv(name);
    }

    /** A documented INPUT or configuration read (a path, a locator, a config key's environment spelling). */
    public static String operator(String name) {
        return System.getenv(name);
    }

    /** The environment of a child process this engine is about to start (the {@code candor verify --run} program). */
    public static Map<String, String> childEnvironment(ProcessBuilder pb) {
        return pb.environment();
    }

    /** The result-moving switches set AND consulted by THIS process so far (SPEC §2 {@code switches}). Empty when no
     *  switch is set — and then the report carries no key, so a scan under no switch is byte-identical to one before. */
    public static java.util.List<String> consultedSwitches() {
        return new java.util.ArrayList<>(CONSULTED);
    }

    /** The refusal's {@code reason} (§3.3 (e); §3.1: a refusal always says why): names every switch and says to unset them. */
    public static String switchRefusalReason(java.util.List<String> names) {
        return "a result-moving switch is set: " + String.join(", ", names) + " — the answer depends on an environment "
                + "variable or JVM system property (however it was delivered: -D, JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS) that selects which logic ran, so the gate cannot say whether the code passes (SPEC §3.4). "
                + "Unset " + (names.size() == 1 ? "it" : "them") + " and re-run.";
    }

    /** Test seam: forget what was consulted (an in-process harness that runs several scans). */
    static void resetConsultedSwitches() {
        CONSULTED.clear();
    }

    /** A switch read on first USE, not at class initialisation. See the class comment: a field of this type is what a
     *  class that the evaluator verbs also load must hold, so that merely loading it consults nothing. */
    public static final class Switch {
        private final String name;
        private final Predicate<String> isSet;
        private final boolean property;
        private volatile boolean read, set;

        private Switch(String name, Predicate<String> isSet, boolean property) {
            this.name = name;
            this.isSet = isSet;
            this.property = property;
        }

        /** Does the value select the non-default branch? Reads the variable the first time it is asked. */
        public boolean set() {
            if (!read) {
                synchronized (this) {
                    if (!read) {
                        set = isSet.test(property ? propertySwitchRead(name, isSet) : switchRead(name, isSet));
                        read = true;
                    }
                }
            }
            return set;
        }

        /** The default-ON reading of a kill switch: the fix runs unless the variable is set. */
        public boolean on() {
            return !set();
        }
    }

    /** A default-ON kill switch read lazily: {@code =0} is SET. */
    public static Switch killSwitch(String name) {
        return new Switch(name, "0"::equals, false);
    }

    /** An opt-in mode read lazily: SET when {@code isSet} accepts the value. */
    public static Switch optIn(String name, Predicate<String> isSet) {
        return new Switch(name, isSet, false);
    }

    /** A JVM-system-property switch read lazily, for a class the evaluator verbs also load (R1645). */
    public static Switch propertyOptIn(String name, Predicate<String> isSet) {
        return new Switch(name, isSet, true);
    }
}
