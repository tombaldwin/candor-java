package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SPEC §3.4 ⟨0.42⟩ "THE REGISTRATION IS THE READ" (SOUNDNESS R1634): the engine reads its environment in ONE class,
 * {@link Env}, and nowhere else. {@link EnvLint} is the gate; THIS test is what shows the gate can fail. A lint that
 * has only ever passed is a lint nobody has seen fire — and this family has paid for that shape repeatedly
 * (a census whose pattern matched a JSON key elsewhere in the file; a check a heredoc had emptied).
 *
 * <p>Three parts, in the order that makes each one mean something:
 * <ol>
 *   <li>every SEEDED spelling is flagged — including the two that matter most for this engine, a STATIC INITIALISER in a
 *       class other than {@code Env} (a switch consulted at class load, in a process that never ran its logic) and a
 *       DYNAMIC name (so no list of literals could have caught it);</li>
 *   <li>the CONTROLS are not flagged — the engine's own classifier table spells {@code "getenv"} as a string and {@code Env}
 *       itself reads the environment, and a lint that flagged either would be one nobody could keep green;</li>
 *   <li>a REAL shipped file with ONE read appended is flagged, and the shipped tree as it stands is clean.</li>
 * </ol>
 */
class EnvLintTest {

    /** name → source. Each must produce at least one hit. */
    private static final Map<String, String> SEEDED = new LinkedHashMap<>();
    static {
        SEEDED.put("literal getenv", "class A { String v = System.getenv(\"CANDOR_X\"); }");
        SEEDED.put("static initialiser in another class",
                "class A { static final boolean R1 = !\"0\".equals(System.getenv(\"CANDOR_R1\")); }");
        SEEDED.put("static block", "class A { static boolean r; static { r = System.getenv(\"CANDOR_X\") != null; } }");
        SEEDED.put("dynamic name", "class A { String f(String n) { return System.getenv(n); } }");
        SEEDED.put("computed name", "class A { String f(String r) { return System.getenv(\"CANDOR_\" + r + \"_OFF\"); } }");
        SEEDED.put("whole environment", "class A { java.util.Map<String,String> m = System.getenv(); }");
        SEEDED.put("whole environment, enumerated", "class A { void f() { for (var e : System.getenv().entrySet()) {} } }");
        SEEDED.put("fully qualified", "class A { String v = java.lang.System.getenv(\"X\"); }");
        SEEDED.put("static import", "import static java.lang.System.getenv;\nclass A { String v = getenv(\"X\"); }");
        SEEDED.put("method reference", "class A { java.util.function.Function<String,String> f = System::getenv; }");
        SEEDED.put("in a lambda", "class A { Runnable r = () -> System.getenv(\"X\"); }");
        SEEDED.put("in an inner class", "class A { class B { String v = System.getenv(\"X\"); } }");
        SEEDED.put("in an interface default", "interface A { default String v() { return System.getenv(\"X\"); } }");
        SEEDED.put("in a record", "record A(int x) { String v() { return System.getenv(\"X\"); } }");
        SEEDED.put("in an enum constant body",
                "enum A { ONE { String v() { return System.getenv(\"X\"); } }; abstract String v(); }");
        SEEDED.put("receiver held in a variable", "class A { String v(Object o) { var s = System.class; return null; } String w() { return System.getenv(\"X\"); } }");
        SEEDED.put("child environment", "class A { void f(ProcessBuilder pb) { pb.environment().put(\"X\", \"1\"); } }");
        SEEDED.put("child environment of a fresh builder",
                "class A { Object f() { return new ProcessBuilder(\"ls\").environment(); } }");
        SEEDED.put("child environment as a method reference",
                "class A { java.util.function.Function<ProcessBuilder, java.util.Map<String,String>> f = ProcessBuilder::environment; }");
        SEEDED.put("reflective getenv",
                "class A { Object f() throws Exception { return System.class.getMethod(\"getenv\", String.class); } }");
        SEEDED.put("reflective via a method handle",
                "class A { Object f() throws Exception { return java.lang.invoke.MethodHandles.lookup().findStatic(System.class, \"getenv\", null); } }");
        SEEDED.put("the JDK's private environment class",
                "class A { Object f() throws Exception { return Class.forName(\"java.lang.ProcessEnvironment\"); } }");
    }

    @Test
    void everySeededSpellingIsFlagged() throws Exception {
        for (var e : SEEDED.entrySet()) {
            List<EnvLint.Hit> hits = EnvLint.findEnvAccess(e.getValue(), "Seeded.java");
            assertFalse(hits.isEmpty(), "the lint did NOT fire on a seeded read — `" + e.getKey() + "`:\n" + e.getValue());
        }
        assertTrue(SEEDED.size() >= 20, "the seed set shrank — this is the calibration of the lint, do not thin it");
    }

    @Test
    void controlsAreNotFlagged() throws Exception {
        // the engine's classifier table names the JDK method for the code it ANALYSES — a string, never a call
        assertTrue(EnvLint.findEnvAccess(
                "class C { boolean f(String o, String m) { return o.equals(\"java.lang.System\") && m.equals(\"getenv\"); } }", "C.java").isEmpty(),
                "a string literal \"getenv\" outside a reflective call is data, not a read");
        // a comment and a javadoc that DISCUSS the environment
        assertTrue(EnvLint.findEnvAccess("class C { /** System.getenv(\"X\") — discussed, not called */ int x; // System.getenv()\n }", "C.java").isEmpty());
        // routing through Env is the sanctioned spelling
        assertTrue(EnvLint.findEnvAccess("class C { boolean v = Env.killSwitchOn(\"CANDOR_R1\"); String t = Env.trace(\"CANDOR_X_DEBUG\"); }", "C.java").isEmpty());
        // the unrelated words
        assertTrue(EnvLint.findEnvAccess("class C { int environmentCount; String getenvLike() { return \"\"; } }", "C.java").isEmpty());
        // and Env itself is the one file allowed to read
        assertTrue(EnvLint.shippedFiles(Path.of("src/main/java")).stream().noneMatch(f -> f.getFileName().toString().equals(EnvLint.ENV_FILE)));
        assertFalse(EnvLint.findEnvAccess(Files.readString(Path.of("src/main/java/io/poly/candor/Env.java")), "Env.java").isEmpty(),
                "the control is only meaningful if Env.java really does read the environment");
    }

    @Test
    void aRealShippedFileWithOneReadAppendedIsFlagged() throws Exception {
        Path root = Path.of("src/main/java");
        for (String rel : new String[]{"io/poly/candor/Policy.java", "io/poly/candor/Loader.java", "io/poly/candor/verify/Trace.java"}) {
            String clean = Files.readString(root.resolve(rel));
            assertEquals(List.of(), EnvLint.findEnvAccess(clean, rel), "the shipped " + rel + " must be clean before the seed");
            String dirty = clean + "\nclass LintSeed { static final boolean S = System.getenv(\"CANDOR_NEW_SWITCH\") != null; }\n";
            assertEquals(1, EnvLint.findEnvAccess(dirty, rel).size(), "one appended read in " + rel + " must be exactly one hit");
        }
    }

    @Test
    void theShippedTreeReadsTheEnvironmentOnlyThroughEnv() throws Exception {
        List<EnvLint.Hit> bad = EnvLint.lintTree(Path.of("src/main/java"));
        assertTrue(bad.isEmpty(), "environment access outside Env.java — route it through Env.killSwitch/optIn/switchRead (a "
                + "result-moving switch), Env.trace (stderr only) or Env.operator (a documented input):\n"
                + String.join("\n", bad.stream().map(EnvLint.Hit::toString).toList()));
        assertTrue(EnvLint.shippedFiles(Path.of("src/main/java")).size() > 20, "the lint walked almost nothing — a vacuous pass");
    }
}
