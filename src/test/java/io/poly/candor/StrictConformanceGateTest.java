package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The CANDOR_STRICT conformance gate ({@link Candor#checkConformance}, both overloads) — AS-EFF-001/002/003,
 * candor-spec SEMANTICS §6 read through the DI idiom: a class's injected-collaborator FIELDS are its declared
 * capabilities ({@code declared}), the union of its methods' inferred sets is what it performs
 * ({@code performed}). This surface shipped for months with ZERO coverage in any harness (the TESTING.md §2
 * pin-1 incident); these are the behavioral pins:
 *
 * <ul>
 *   <li>AS-EFF-001: {@code performed \ declared \ {Unknown} ≠ ∅} — an effect no collaborator provides;</li>
 *   <li>AS-EFF-002: {@code declared \ performed ≠ ∅} — an injected capability never used;</li>
 *   <li>AS-EFF-003: {@code Unknown ∈ performed} — unresolvable calls, the set is not provably complete;</li>
 *   <li>the SPEC §6 program-entry-point exemption from AS-EFF-001 (`main` mints the bundle) — this pin
 *       demonstrably FAILED before the exemption was implemented (the gate fired AS-EFF-001 on the
 *       composition root; red-then-green in the same commit, TESTING.md §8);</li>
 *   <li>scope filtering (gateScopeCovers) and the two-overload agreement (the {@code --json +
 *       CANDOR_STRICT} reuse path in main() must reach the same verdict as the gate-only path).</li>
 * </ul>
 */
class StrictConformanceGateTest {

    @BeforeEach
    void fresh() {
        Candor.resetState();
        Candor.gateViolations.clear();
        Candor.gateCapture = true;   // capture {rule, fn, effects} structurally — assert codes, not console text
    }

    @AfterEach
    void clearCapture() {
        Candor.gateCapture = false;
        Candor.gateViolations.clear();
    }

    /** The captured spec codes fired for {@code cls} (rule strings, e.g. "AS-EFF-001"). */
    private static List<String> codesFor(String cls) {
        return Candor.gateViolations.stream()
                .filter(m -> cls.equals(m.get("fn")))
                .map(m -> (String) m.get("rule"))
                .sorted()
                .toList();
    }

    @SuppressWarnings("unchecked")
    private static List<String> effectsOf(String cls, String rule) {
        return Candor.gateViolations.stream()
                .filter(m -> cls.equals(m.get("fn")) && rule.equals(m.get("rule")))
                .map(m -> (List<String>) m.get("effects"))
                .findFirst().orElse(List.of());
    }

    private static String detailOf(String cls, String rule) {
        return Candor.gateViolations.stream()
                .filter(m -> cls.equals(m.get("fn")) && rule.equals(m.get("rule")))
                .map(m -> (String) m.get("detail"))
                .findFirst().orElse("");
    }

    private static final String FS_WORKER = """
            package app;
            import java.nio.file.*;
            public class FsWorker {
              public void doIt() { try { Files.readAllBytes(Path.of("/tmp/x")); } catch (Exception e) {} }
            }
            """;

    // ── AS-EFF-001: performs an effect no injected collaborator provides ──────────────────────────────

    @Test
    void undeclaredEffectFiresAsEff001() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/Svc.java", """
                package app;
                import java.nio.file.*;
                public class Svc {
                  public void run() { try { Files.readAllBytes(Path.of("/tmp/x")); } catch (Exception e) {} }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "1");
        assertEquals(1, v, "one violation: Fs performed with no injected capability");
        assertEquals(List.of("AS-EFF-001"), codesFor("app.Svc"));
        assertEquals(List.of("Fs"), effectsOf("app.Svc", "AS-EFF-001"),
                "the violation carries the specific undeclared effect");
        assertTrue(detailOf("app.Svc", "AS-EFF-001").contains("no injected capability"),
                "an empty declared set reads 'no injected capability'");
    }

    @Test
    void injectedProjectCollaboratorCoversItsEffect() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/FsWorker.java", FS_WORKER, "app/Svc.java", """
                package app;
                public class Svc {
                  private final FsWorker w = new FsWorker();
                  public void run() { w.doIt(); }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        // Scoped to the consuming class: it performs {Fs} (transitively) and holds a collaborator whose
        // own effect set is {Fs} — conformant. (The leaf FsWorker itself is out of scope; as a whole-unit
        // scan it would rightly fire AS-EFF-001, being the class that reaches for ambient authority.)
        assertEquals(0, Candor.checkConformance(inferred, "app.Svc"),
                "a performed effect covered by an injected collaborator's effects is conformant");
    }

    @Test
    void asEff001FlagsOnlyTheUncoveredEffect() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/FsWorker.java", FS_WORKER, "app/Svc.java", """
                package app;
                public class Svc {
                  private final FsWorker w = new FsWorker();
                  public void run() { w.doIt(); try { new java.net.Socket("h", 80).close(); } catch (Exception e) {} }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "app.Svc");
        assertEquals(1, v);
        assertEquals(List.of("Net"), effectsOf("app.Svc", "AS-EFF-001"),
                "only the effect BEYOND the collaborators is undeclared — Fs is covered, Net is not");
        assertTrue(detailOf("app.Svc", "AS-EFF-001").contains("only { Fs }"),
                "the diagnostic names what the class DOES hold");
    }

    // ── AS-EFF-002: declares (injects) a capability it never uses ─────────────────────────────────────

    @Test
    void unusedInjectedCapabilityFiresAsEff002() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/FsWorker.java", FS_WORKER, "app/Holder.java", """
                package app;
                public class Holder {
                  private FsWorker w;   // injected, never called
                  public int idle() { return 1; }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "app.Holder");
        assertEquals(1, v, "one violation: an injected capability never exercised");
        assertEquals(List.of("AS-EFF-002"), codesFor("app.Holder"));
        assertEquals(List.of("Fs"), effectsOf("app.Holder", "AS-EFF-002"));
    }

    // ── AS-EFF-003: unresolved calls — the set is not provably complete ───────────────────────────────

    @Test
    void unresolvedCallFiresAsEff003NotAsEff001() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/Refl.java", """
                package app;
                public class Refl {
                  public Object go(String n) throws Exception {
                    return Class.forName(n).getDeclaredConstructor().newInstance();
                  }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "app.Refl");
        assertEquals(1, v, "Unknown is AS-EFF-003's concern, never an AS-EFF-001 'undeclared effect'");
        assertEquals(List.of("AS-EFF-003"), codesFor("app.Refl"));
    }

    @Test
    void concreteAndUnknownEffectsFireBoth001And003() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/Both.java", """
                package app;
                import java.nio.file.*;
                public class Both {
                  public Object go(String n) throws Exception {
                    Files.readAllBytes(Path.of("/tmp/x"));
                    return Class.forName(n).getDeclaredConstructor().newInstance();
                  }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "app.Both");
        assertEquals(2, v);
        assertEquals(List.of("AS-EFF-001", "AS-EFF-003"), codesFor("app.Both"));
        assertEquals(List.of("Fs"), effectsOf("app.Both", "AS-EFF-001"),
                "Unknown is excluded from the AS-EFF-001 undeclared set (SEMANTICS §6)");
    }

    // ── the SPEC §6 program-entry-point exemption from AS-EFF-001 ─────────────────────────────────────
    // "The program entry point (e.g. `main`) is exempt from AS-EFF-001 — it legitimately mints/holds the
    // whole capability bundle." At this gate's class granularity: the class declaring
    // `public static void main(String[])` (the composition root). BUG FOUND BY THIS PIN: the gate fired
    // AS-EFF-001 on the entry class (the Rust reference has exempted tcx.entry_fn all along); fixed in
    // the same commit (TESTING.md §8, red-then-green).

    @Test
    void programEntryPointClassIsExemptFromAsEff001() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/Main.java", """
                package app;
                import java.nio.file.*;
                public class Main {
                  public static void main(String[] a) throws Exception { Files.writeString(Path.of("/tmp/x"), "y"); }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        assertEquals(0, Candor.checkConformance(inferred, "1"),
                "the psvm entry class mints the capability bundle — exempt from AS-EFF-001 (SPEC §6)");
    }

    @Test
    void entryPointExemptionIsAsEff001Only() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/Main.java", """
                package app;
                public class Main {
                  public static void main(String[] a) throws Exception {
                    Class.forName(a[0]).getDeclaredConstructor().newInstance();
                  }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "1");
        assertEquals(1, v, "AS-EFF-003 (and 002) still apply to the entry class — the exemption is 001-only");
        assertEquals(List.of("AS-EFF-003"), codesFor("app.Main"));
    }

    @Test
    void mainLookalikesAreNotExempt() throws Exception {
        // The anti-fabrication twins (TESTING.md §8 "pin the class"): an INSTANCE main(String[]) and a
        // static main with a different descriptor are NOT the JVM launch entry — no exemption.
        Path cls = TestCompiler.compile(Map.of("app/FakeA.java", """
                package app;
                import java.nio.file.*;
                public class FakeA {
                  public void main(String[] a) throws Exception { Files.writeString(Path.of("/t"), "y"); }
                }
                """, "app/FakeB.java", """
                package app;
                import java.nio.file.*;
                public class FakeB {
                  public static void main(String a) throws Exception { Files.writeString(Path.of("/t"), "y"); }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "1");
        assertEquals(2, v, "a main lookalike (instance / wrong descriptor) still fires AS-EFF-001");
        assertEquals(List.of("AS-EFF-001"), codesFor("app.FakeA"));
        assertEquals(List.of("AS-EFF-001"), codesFor("app.FakeB"));
    }

    // ── scope filtering + the two-overload agreement ──────────────────────────────────────────────────

    @Test
    void scopedGateSkipsOutOfScopeClasses() throws Exception {
        Path cls = TestCompiler.compile(Map.of("app/Svc.java", """
                package app;
                import java.nio.file.*;
                public class Svc {
                  public void run() { try { Files.readAllBytes(Path.of("/tmp/x")); } catch (Exception e) {} }
                }
                """, "other/Bad.java", """
                package other;
                public class Bad {
                  public void hit() { try { new java.net.Socket("h", 80).close(); } catch (Exception e) {} }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        int v = Candor.checkConformance(inferred, "app.Svc");
        assertEquals(1, v, "only the in-scope class is gated");
        assertEquals(List.of("AS-EFF-001"), codesFor("app.Svc"));
        assertEquals(List.of(), codesFor("other.Bad"), "the out-of-scope violation is not evaluated");
    }

    @Test
    void gateOnlyAndReportReusePathsAgree() throws Exception {
        // main() has two routes to the verdict: gate-only (checkConformance(inferred, scope), declared
        // scope-filtered) and the --json reuse path (checkConformance(ccFull, scope), declared built for
        // ALL classes). The declared-scoping optimization must never change the verdict.
        Path cls = TestCompiler.compile(Map.of("app/FsWorker.java", FS_WORKER, "app/Svc.java", """
                package app;
                public class Svc {
                  private final FsWorker w = new FsWorker();
                  public void run() { w.doIt(); try { new java.net.Socket("h", 80).close(); } catch (Exception e) {} }
                }
                """, "app/Holder.java", """
                package app;
                public class Holder {
                  private FsWorker w;
                  public int idle() { return 1; }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        for (String scope : new String[] {"1", "app.Svc", "app.Holder", "app"}) {
            Candor.gateViolations.clear();
            int gateOnly = Candor.checkConformance(inferred, scope);
            Candor.gateViolations.clear();
            int viaReport = Candor.checkConformance(Candor.classConformance(inferred), scope);
            assertEquals(gateOnly, viaReport, "scope '" + scope + "': both overloads reach the same verdict");
        }
    }

    // ── declared via a LIBRARY collaborator type (the classifyType arm of typeEffects) ────────────────

    @Test
    void libraryCollaboratorTypesDeclareTheirEffects() throws Exception {
        // Stub the external types (two-phase compile: the lib dir is classpath-only, never scanned) —
        // an EntityManager field grants Db, a RestTemplate field grants Net (Candor.classifyType).
        Map<String, String> lib = Map.of(
                "jakarta/persistence/EntityManager.java", """
                        package jakarta.persistence;
                        public interface EntityManager { void persist(Object o); }
                        """,
                "org/springframework/web/client/RestTemplate.java", """
                        package org.springframework.web.client;
                        public class RestTemplate { public Object getForObject(String u, Class<?> t) { return null; } }
                        """);
        Path cls = TestCompiler.compileApp(lib, Map.of("app/Repo.java", """
                package app;
                import jakarta.persistence.EntityManager;
                public class Repo {
                  private EntityManager em;
                  public void save(Object o) { em.persist(o); }
                }
                """, "app/Client.java", """
                package app;
                import org.springframework.web.client.RestTemplate;
                public class Client {
                  private RestTemplate rt;   // injected, never used → AS-EFF-002 { Net }
                  public int idle() { return 2; }
                }
                """));
        Map<String, EffectSet> inferred = Candor.runScan(cls);
        assertEquals(0, Candor.checkConformance(inferred, "app.Repo"),
                "an EntityManager field declares Db, covering the persist call");
        Candor.gateViolations.clear();
        int v = Candor.checkConformance(inferred, "app.Client");
        assertEquals(1, v);
        assertEquals(List.of("AS-EFF-002"), codesFor("app.Client"));
        assertEquals(List.of("Net"), effectsOf("app.Client", "AS-EFF-002"),
                "a RestTemplate field declares Net — injected here but never used");
        assertTrue(inferred.getOrDefault("app.Repo.save", EffectSet.empty()).effects().contains(Effect.DB),
                "sanity: the persist call classifies Db (the declared/performed pair is real, not vacuous)");
    }
}
