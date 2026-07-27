package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link Loader#entryPackage} — the ENTRY-LEVEL package fallback, the only package registration a chained
 * report with no {@code package}/{@code packages} envelope gets.
 *
 * <p>THE DEFECT IT PINS. The fallback took the last {@code /} in the WHOLE hash. This engine's hash is
 * {@code owner/Class.method(descriptor)} and a JVM descriptor is full of slashes
 * ({@code (Ljava/lang/String;)V}), so for every method that takes or returns a reference type the last
 * {@code /} lands inside the DESCRIPTOR and the parse yielded
 * {@code com.example.Svc.save(Ljava.lang} — a string that is not a package and cannot be one.
 *
 * <p>WHAT THE GARBAGE DID, measured rather than assumed, because the two registrations it feeds fail in
 * OPPOSITE directions:
 * <ul>
 *   <li>It never FABRICATED coverage. Whenever the parse runs into the descriptor the result necessarily
 *       contains the {@code (} that opens it, and no JVM package name can, so the bogus name could not
 *       collide with a real package in {@code depCoveredPkgs} — the harmless-looking half, and it is
 *       genuinely harmless. Asserted below so it stays that way.
 *   <li>The cost is the registration that did NOT happen. {@code depChainedPkgs} is conjunct 3 of
 *       {@link Candor#untypedDepReceiver}, so a package-field-less chained report left the half-1
 *       unanswerable-key disclosure SILENT: an INVOKEINTERFACE into a dep whose implementation candor
 *       cannot name read as a confident purity claim, and `deny Fs Unknown[dispatch]` sat at 0 violations
 *       against a single-tree control that is 1 in both arms. A silent under-report, which is why this is
 *       filed as more than a cosmetic parse bug.
 * </ul>
 *
 * <p>The {@code pkg#qual} form (rust/ts) was always parsed correctly and has ALWAYS granted per-entry
 * coverage, so the fix does not invent a policy — it makes this engine's own hash form behave like the
 * spec form the same lines already handle.
 */
class DepEntryPackageTest {

    // ── the parse itself ────────────────────────────────────────────────────────────────────────────

    /** THE SECOND FIXTURE, WRITTEN FIRST (standing bar item 0). Every hash shape the fallback already got
     *  right must still parse the same way, or "fixed the parse" is indistinguishable from "moved the
     *  breakage". Note that every dep-report fixture in this suite predating the fix used a descriptor with
     *  NO reference type ({@code ()V}, {@code (I)V}) — which is exactly why they all passed. */
    @Test
    void theFormsThatAlreadyParsedStillParseTheSameWay() {
        assertEquals("deplib", Loader.entryPackage("deplib#save"), "the spec `pkg#qual` join key");
        assertEquals("deplib.sub", Loader.entryPackage("deplib.sub#mod::f"), "a dotted spec package");
        assertEquals("dep", Loader.entryPackage("dep/Lib.phone()V"), "a no-argument descriptor");
        assertEquals("dep", Loader.entryPackage("dep/Lib.n(I)V"), "primitives carry no slash");
        assertEquals("com.example", Loader.entryPackage("com/example/Svc.go()V"), "a nested package");
        assertNull(Loader.entryPackage("just-a-name"), "a hash naming no package still names none");
    }

    /** THE DEFECT. A descriptor slash is not a package separator. */
    @Test
    void aDescriptorSlashIsNotAPackageSeparator() {
        assertEquals("com.example", Loader.entryPackage("com/example/Svc.save(Ljava/lang/String;)V"),
                "a reference-type PARAMETER put the last / inside the descriptor");
        assertEquals("a.b", Loader.entryPackage("a/b/C.m(Ljava/lang/String;)Ljava/lang/String;"),
                "a reference-type RETURN does it too, even with a primitive-free argument list");
        assertEquals("com.example", Loader.entryPackage("com/example/Svc.<init>(Ljava/util/List;)V"),
                "a constructor hash is the same shape");
        assertNull(Loader.entryPackage("Svc.save(Ljava/lang/String;)V"),
                "a DEFAULT-package owner names no package — the descriptor must not manufacture one");
    }

    /** The fabrication direction, pinned rather than argued: the fallback may only ever name something that
     *  could BE a package. This is what makes the pre-fix behaviour merely inert in {@code depCoveredPkgs}
     *  instead of a false coverage grant, and it is cheap to keep true. */
    @Test
    void theParseCanNeverNameAThingThatIsNotAPackage() {
        for (String h : List.of("com/example/Svc.save(Ljava/lang/String;)V",
                                "a/b/C.m(Ljava/lang/String;)Ljava/lang/String;",
                                "com/example/Svc.<init>(Ljava/util/List;)V",
                                "Svc.save(Ljava/lang/String;)V",
                                "dep/Lib.phone()V",
                                "deplib#save")) {
            String pkg = Loader.entryPackage(h);
            if (pkg == null) continue;
            assertTrue(pkg.chars().allMatch(c -> Character.isJavaIdentifierPart(c) || c == '.'),
                    "entryPackage(" + h + ") = '" + pkg + "' — a JVM package name is dot-separated "
                    + "identifiers, so anything else is a parse that ran into the descriptor");
        }
    }

    // ── what the missing registration cost, end to end ──────────────────────────────────────────────

    /** A dependency whose report carries NO envelope package field — the only case the entry-level fallback
     *  exists for. `ch.qos.logback.candorfixture` is inside a κ-CURATED prefix, so the ledger's
     *  `invisible: [pkg]` is silent about it whatever the chain does: the dispatch disclosure is the ONLY
     *  channel there is, exactly as in {@link StaleDepTrustTest}'s stale twin. */
    private static final Map<String, String> LIB = Map.of(
        "ch/qos/logback/candorfixture/Store.java",
            "package ch.qos.logback.candorfixture;\npublic interface Store { void save(String s); }\n",
        "ch/qos/logback/candorfixture/FileStore.java",
            "package ch.qos.logback.candorfixture;\nimport java.io.*;\n"
            + "public class FileStore implements Store {\n"
            + "  public void save(String s){ try { new FileWriter(\"/tmp/x\").close(); } catch (Exception e) {} }\n}\n");

    private static final Map<String, String> APP = Map.of(
        "app/T.java", "package app;\nimport ch.qos.logback.candorfixture.Store;\n"
            + "public class T {\n  public void run(Store s){ s.save(\"x\"); }\n}\n");

    /** A hand-written dep report in the LEGACY shape this fallback serves: a verifiable build id (so §2.1
     *  trusts it), a real entry — and no `package`/`packages` envelope, so the entry hash is the only thing
     *  naming the package. The entry's descriptor takes a String, which is the whole point. */
    private static String legacyDepReport() {
        return "{\"candor\":{\"version\":\"" + ReportWriter.provenance()[0] + "\",\"spec\":\""
            + Candor.SPEC_VERSION + "\"},\"functions\":[{"
            + "\"fn\":\"ch.qos.logback.candorfixture.FileStore.save\","
            + "\"hash\":\"ch/qos/logback/candorfixture/FileStore.save(Ljava/lang/String;)V\","
            + "\"inferred\":[\"Fs\"]}]}";
    }

    private static Path policy(Path dir, String body) throws Exception {
        Path p = dir.resolve("p.policy");
        Files.writeString(p, body);
        return p;
    }

    /** THE BOUNDARY DEFECT, with its single-tree control. `deny Fs Unknown[dispatch]` must fire on the
     *  chained arm — either on the effect (single tree) or on the disclosure (chained) — and before the fix
     *  the chained arm was 0: the package was never registered as chained, conjunct 3 refused, and an
     *  unresolvable INVOKEINTERFACE into a filesystem-writing implementation vanished. */
    @Test
    void aPackageFieldLessChainedReportStillDisclosesUnresolvedDispatch() throws Exception {
        Path appDir = compileApp(LIB, APP);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Path depReport = base.resolve("dep.json");
            Files.deleteIfExists(depReport);                 // standing bar item 7
            Files.writeString(depReport, legacyDepReport());
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            Map<String, EffectSet> scan = Candor.runScan(appDir);
            // The GATE first: it is the observable claim, and it is what the mutation round has to show
            // moving (0 violations with the old whole-hash parse, 1 with the owner-only one).
            assertEquals(1, Policy.checkPolicy(scan, policy(base, "deny Fs Unknown[dispatch]\n").toString()),
                    "CHAINED: the gate must catch the unresolvable dispatch");
            assertTrue(AnalysisState.ctx().depChainedPkgs.contains("ch.qos.logback.candorfixture"),
                    "the entry hash is the ONLY thing naming this report's package — it must register, "
                    + "got " + AnalysisState.ctx().depChainedPkgs);
            assertTrue(scan.getOrDefault("app.T.run", EffectSet.empty()).hasUnknown(),
                    "an INVOKEINTERFACE into a chained dep with no project impl is an unanswerable key; "
                    + "got " + scan.get("app.T.run"));
            assertTrue(AnalysisState.ctx().unknownWhy
                            .getOrDefault("app.T.run", new java.util.TreeSet<>()).stream()
                            .anyMatch(w -> w.kind() == io.poly.candor.model.UnknownReason.Kind.DISPATCH),
                    "the Unknown carries its dispatch reason so a reason-scoped gate can bite, got "
                    + AnalysisState.ctx().unknownWhy.get("app.T.run"));
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    /** THE CONTROL that makes the row above a BOUNDARY defect and not a general limitation: over the same
     *  sources in ONE tree the gate fires on the effect itself, in both arms, fix or no fix. */
    @Test
    void theSingleTreeControlCatchesItInBothArms() throws Exception {
        java.util.Map<String, String> all = new java.util.HashMap<>(LIB);
        all.putAll(APP);
        Path dir = compile(all);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Map<String, EffectSet> scan = Candor.runScan(dir);
            assertEquals(1, Policy.checkPolicy(scan, policy(dir.getParent(),
                            "deny Fs Unknown[dispatch] app\n").toString()),
                    "SINGLE TREE: `app.T.run` resolves to FileStore.save and is charged Fs — this arm is "
                    + "exit 1 before and after, which is what makes the chained arm a boundary defect");
        } finally {
            Candor.config = saved;
            rm(dir.getParent());
        }
    }

    /** THE COVERAGE HALF, and it moves a disclosure OUT — so it is stated rather than left implicit. A
     *  trusted, complete report's silence under a formed key IS a purity claim (SPEC §2 rule 3), which is
     *  the coverage a chained report is supposed to buy; the broken parse withheld it, so a
     *  package-field-less chain over-disclosed `invisible: [dep]`. The `pkg#qual` form of the very same two
     *  lines has always granted this, so aligning the java form invents no policy. (An INCOMPLETE report
     *  does not get it — see {@link StaleDepTrustTest}.) */
    @Test
    void aPackageFieldLessChainedReportGrantsCoverageForItsOwnPackage() throws Exception {
        Path dir = Files.createTempDirectory("candor-deps");
        try {
            Files.writeString(dir.resolve("lib.json"),
                "{\"candor\":{\"version\":\"vSAME\",\"spec\":\"0.23\"},\"functions\":[{"
                + "\"fn\":\"dep.sub.Lib.save\",\"hash\":\"dep/sub/Lib.save(Ljava/lang/String;)V\","
                + "\"inferred\":[\"Fs\"]}]}");
            Candor.resetState();
            Loader.loadCrossDeps(dir.toString(), "vSAME");
            assertTrue(AnalysisState.ctx().depCoveredPkgs.contains("dep.sub"),
                    "a trusted report's entry names its package exactly, as the `pkg#qual` form always did; "
                    + "got " + AnalysisState.ctx().depCoveredPkgs);
            assertFalse(AnalysisState.ctx().depCoveredPkgs.stream().anyMatch(p -> p.contains("(")),
                    "and nothing that is not a package, got " + AnalysisState.ctx().depCoveredPkgs);
        } finally { rm(dir); }
    }
}
