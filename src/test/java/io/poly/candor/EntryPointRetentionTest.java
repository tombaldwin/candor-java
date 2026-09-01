package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * R87 teeth: {@code Candor.markEntryPoints} must see a root-marker annotation regardless of its
 * RETENTION POLICY. A marker declared WITHOUT an explicit {@code @Retention(RUNTIME)} gets Java's
 * DEFAULT class retention and lands in {@code invisibleAnnotations} — the single most common mistake in
 * writing such an annotation, so a visible-only check silently misses exactly the real-world case.
 * Measured with retention as the ONLY variable held non-constant: CLASS retention read {@code
 * entryPoint:false} and {@code candor reachable} answered zero entry points over a method that genuinely
 * writes a file; RUNTIME retention read correctly.
 *
 * <p>Each retention variant needs its own compile unit (the annotation type and its user share one fully
 * qualified name across variants), so this uses THREE separate {@link TestCompiler#compile} calls rather
 * than one fixture map.
 */
class EntryPointRetentionTest {

    private static final String PKG = "org.springframework.scheduling.annotation";

    /** THE BUG: a marker with Java's DEFAULT (CLASS) retention — no explicit {@code @Retention} — must
     *  still root the method it marks. */
    @Test
    void classRetentionMarkerStillRootsEntryPoint() throws Exception {
        Path cls = compile(Map.of(
            "org/springframework/scheduling/annotation/Scheduled.java", String.join("\n",
                "package " + PKG + ";",
                "public @interface Scheduled { }"),  // no @Retention -> default CLASS
            "app/Job.java", String.join("\n",
                "package app;",
                "import " + PKG + ".Scheduled;",
                "import java.io.FileWriter;",
                "public class Job {",
                "  @Scheduled",
                "  public void run() throws Exception {",
                "    FileWriter fw = new FileWriter(\"/tmp/candor-r87-test-class.txt\");",
                "    fw.write(\"effect\"); fw.close();",
                "  }",
                "}")));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Job.run"),
                    "a CLASS-retention root marker must still be seen and root the method — R87");
        } finally { rm(cls.getParent()); }
    }

    /** CONTROL: explicit RUNTIME retention must keep working exactly as before. */
    @Test
    void runtimeRetentionMarkerStillWorks() throws Exception {
        Path cls = compile(Map.of(
            "org/springframework/scheduling/annotation/Scheduled.java", String.join("\n",
                "package " + PKG + ";",
                "import java.lang.annotation.Retention;",
                "import java.lang.annotation.RetentionPolicy;",
                "@Retention(RetentionPolicy.RUNTIME)",
                "public @interface Scheduled { }"),
            "app/Job.java", String.join("\n",
                "package app;",
                "import " + PKG + ".Scheduled;",
                "import java.io.FileWriter;",
                "public class Job {",
                "  @Scheduled",
                "  public void run() throws Exception {",
                "    FileWriter fw = new FileWriter(\"/tmp/candor-r87-test-runtime.txt\");",
                "    fw.write(\"effect\"); fw.close();",
                "  }",
                "}")));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Job.run"),
                    "an explicit RUNTIME-retention root marker must root the method (control, unaffected)");
        } finally { rm(cls.getParent()); }
    }

    /** CONTROL: no marker annotation at all must NOT fabricate an entry point on a same-shaped method —
     *  the join/retention fix must not turn every method into a root. */
    @Test
    void noMarkerAtAllNotFabricated() throws Exception {
        Path cls = compile(Map.of("app/Job.java", String.join("\n",
            "package app;",
            "import java.io.FileWriter;",
            "public class Job {",
            "  public void run() throws Exception {",
            "    FileWriter fw = new FileWriter(\"/tmp/candor-r87-test-none.txt\");",
            "    fw.write(\"effect\"); fw.close();",
            "  }",
            "}")));
        try {
            Candor.runScan(cls);
            assertFalse(AnalysisState.ctx().entryPoints.contains("app.Job.run"),
                    "a method carrying NO root marker must not be fabricated as an entry point");
        } finally { rm(cls.getParent()); }
    }
}
