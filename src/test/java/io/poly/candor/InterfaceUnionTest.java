package io.poly.candor;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * ⟨0.23⟩ THE {@code interfaceUnion} PRODUCER (candor-spec SPEC §2, {@code WORKSPACE-CHAINING-DESIGN.md},
 * conformance PART 18) — candor-java joining the rung candor-scan / candor-ts / candor-swift already ship.
 *
 * <p>candor-java was marked N/A for PART 18 on the grounds that "whole-classpath bytecode resolves
 * cross-module dispatch natively". That is true of an UNCHAINED whole-classpath scan and false across the
 * scan boundary, where the implementer is in the other tree — the same "ask separately what an engine does
 * at the BOUNDARY" lesson the initializer-edge vein taught. The CONSUMER needed no change at all (this
 * engine keys entries by {@code owner.name+desc}, exactly the key {@code crossDepJoin} forms for an
 * INVOKEINTERFACE site); only the producer was missing.
 *
 * <p>Half the tests here are the SECOND FIXTURE — the cases that must NOT change. Four of five fixes in
 * this repo family on 2026-07-26 were wrong in the other direction, and a synthetic report entry is exactly
 * the kind of thing that grows a report unboundedly if the implementer walk is wrong.
 */
class InterfaceUnionTest {

    @AfterEach
    void resetGate() {
        ReportWriter.workspaceChainOverride = null;
    }

    // ---- harness ---------------------------------------------------------------------------------------

    /** Scan {@code lib} alone and return its WRITTEN report entries keyed by `hash`, with the workspace-chain
     *  rung either on or off. The written report is the only view that shows what a chained consumer sees. */
    private static Map<String, Map<String, Object>> depReport(Map<String, String> lib, boolean chainFlag)
            throws Exception {
        return byHash(depReportText(lib, chainFlag));
    }

    /** The raw report TEXT for {@code lib} — what the byte-identity check compares. */
    private static String depReportText(Map<String, String> lib, boolean chainFlag) throws Exception {
        Path libDir = TestCompiler.compile(lib);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            ReportWriter.workspaceChainOverride = chainFlag;
            Path out = libDir.getParent().resolve("dep.json");
            Files.deleteIfExists(out);              // standing-bar item 7: never read a stale arm
            ReportWriter.writeJson(Candor.runScan(libDir), out.toString());
            return Files.readString(out);
        } finally {
            Candor.config = saved;
            ReportWriter.workspaceChainOverride = null;
            rm(libDir.getParent());
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> byHash(String reportText) {
        Map<String, Object> root = new Gson().fromJson(reportText, Map.class);
        Map<String, Map<String, Object>> byHash = new java.util.HashMap<>();
        for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
            byHash.put((String) e.get("hash"), e);
        return byHash;
    }

    @SuppressWarnings("unchecked")
    private static List<String> inferred(Map<String, Map<String, Object>> r, String hash) {
        Map<String, Object> e = r.get(hash);
        return e == null ? null : (List<String>) e.get("inferred");
    }

    /** The two-tree arrangement: {@code lib} scanned alone (rung per {@code chainFlag}), its report chained,
     *  {@code app} scanned alone with the rung OFF — a consumer never sets the producer flag. Returns the
     *  app's written report keyed by `fn`. */
    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> chainedApp(Map<String, String> lib, Map<String, String> app,
            boolean chainFlag) throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Path depReport = base.resolve("dep.json");
            Files.deleteIfExists(depReport);
            ReportWriter.workspaceChainOverride = chainFlag;
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            ReportWriter.workspaceChainOverride = false;   // the CONSUMER never emits union entries
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            Path out = base.resolve("app.json");
            Files.deleteIfExists(out);
            ReportWriter.writeJson(Candor.runScan(appDir), out.toString());
            Map<String, Object> root = new Gson().fromJson(Files.readString(out), Map.class);
            Map<String, Map<String, Object>> byFn = new java.util.HashMap<>();
            for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
                byFn.put((String) e.get("fn"), e);
            return byFn;
        } finally {
            Candor.config = saved;
            ReportWriter.workspaceChainOverride = null;
            rm(base);
        }
    }

    // ---- fixtures --------------------------------------------------------------------------------------

    /** An interface with ONE effectful implementer — the motivating shape. */
    private static final String STORE =
            "package lib;\npublic interface Store { void save(String s); }\n";
    private static final String FILE_STORE = "package lib;\nimport java.io.*;\n"
            + "public class FileStore implements Store {\n"
            + "  public void save(String s) { try { new FileWriter(\"/tmp/x\").write(s); } catch (IOException e) {} }\n}\n";

    // ---- the rung --------------------------------------------------------------------------------------

    @Test
    void aUnionEntryIsEmittedForAnInterfaceMethodWithALocalImplementer() throws Exception {
        Map<String, Map<String, Object>> r =
                depReport(Map.of("lib/Store.java", STORE, "lib/FileStore.java", FILE_STORE), true);
        Map<String, Object> u = r.get("lib/Store.save(Ljava/lang/String;)V");
        assertNotNull(u, "the interface method must carry a synthetic union entry under the key a consumer's"
                + " INVOKEINTERFACE site forms; got hashes " + r.keySet());
        assertEquals(Boolean.TRUE, u.get("interfaceUnion"),
                "the entry MUST be marked on the wire — conformance PART 18 asserts f.get(\"interfaceUnion\")");
        assertEquals(List.of("Fs"), u.get("inferred"),
                "effects = the union over the local implementers' same-signature methods");
        assertEquals("lib.Store.save", u.get("fn"));
    }

    @Test
    void aUnionEntryCarriesTheLiteralSurfacesTheConsumerJoinInherits() throws Exception {
        // crossDepJoin inherits hosts/cmds/paths/tables/netClass alongside `inferred`, so a union entry that
        // omitted them would resolve the effect and silently drop its surface.
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/Fetch.java", "package lib;\npublic interface Fetch { void go(); }\n",
                "lib/HttpFetch.java", "package lib;\nimport java.net.*;\n"
                        + "public class HttpFetch implements Fetch {\n"
                        + "  public void go() { try { new URL(\"http://example.com/x\").openStream(); }"
                        + " catch (Exception e) {} }\n}\n"), true);
        Map<String, Object> u = r.get("lib/Fetch.go()V");
        assertNotNull(u, "union entry missing; hashes " + r.keySet());
        assertTrue(((List<?>) u.get("inferred")).contains("Net"), "got " + u.get("inferred"));
        assertEquals(List.of("example.com"), u.get("hosts"), "the implementer's literal host must travel");
        assertNotNull(u.get("netClass"), "⟨0.20⟩ netClass must travel with a Net union");
    }

    // ---- the gate --------------------------------------------------------------------------------------

    @Test
    void withTheRungOffNoEntryGainsTheKeyAndNoSyntheticEntryAppears() throws Exception {
        Map<String, String> lib = Map.of("lib/Store.java", STORE, "lib/FileStore.java", FILE_STORE);
        String off = depReportText(lib, false);
        assertFalse(off.contains("interfaceUnion"),
                "with the rung off the wire must not carry the key at all — an unaffected entry never gains it");
        assertNull(byHash(off).get("lib/Store.save(Ljava/lang/String;)V"), "no synthetic entry with the rung off");
        // The rung is ADDITIVE: turning it on must not touch a single ordinary entry.
        List<Map<String, Object>> onOrdinary = new ArrayList<>();
        for (Map<String, Object> e : byHash(depReportText(lib, true)).values())
            if (e.get("interfaceUnion") == null) onOrdinary.add(e);
        assertEquals(new java.util.HashSet<>(byHash(off).values()), new java.util.HashSet<>(onOrdinary),
                "the ordinary entries must be identical between the two arms");
    }

    @Test
    void theRungIsInertOnATreeWithNoInterfaces() throws Exception {
        // The strongest form of "byte-identical when nothing qualifies": the same source, both arms, compared
        // as TEXT. (The whole-corpus byte-identity check is the flag-OFF measurement; this is its unit pin.)
        Map<String, String> lib = Map.of("lib/Plain.java",
                "package lib;\npublic class Plain { public String home() { return System.getenv(\"HOME\"); } }\n");
        assertEquals(depReportText(lib, false), depReportText(lib, true),
                "with nothing to publish the two arms must produce the same bytes");
    }

    @Test
    void theEnvironmentVariableIsTheGate() throws Exception {
        // The in-process tests drive `workspaceChainOverride`; this one proves the PRODUCTION gate — the env
        // var candor-scan and candor-swift already read — is what turns the rung on, via a real subprocess.
        Path libDir = TestCompiler.compile(Map.of("lib/Store.java", STORE, "lib/FileStore.java", FILE_STORE));
        Path off = libDir.getParent().resolve("off.json"), on = libDir.getParent().resolve("on.json");
        try {
            Files.deleteIfExists(off);
            Files.deleteIfExists(on);
            runCli(null, libDir.toString(), "--json", off.toString());
            runCli("1", libDir.toString(), "--json", on.toString());
            assertFalse(Files.readString(off).contains("interfaceUnion"),
                    "CANDOR_WORKSPACE_CHAIN unset must produce a report with no union entries");
            assertNotNull(byHash(Files.readString(on)).get("lib/Store.save(Ljava/lang/String;)V"),
                    "CANDOR_WORKSPACE_CHAIN=1 must produce the union entry");
        } finally {
            rm(libDir.getParent());
        }
    }

    /** Run the CLI in a subprocess (main() calls System.exit), with CANDOR_WORKSPACE_CHAIN set or REMOVED. */
    private static void runCli(String chain, String... args) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(System.getProperty("java.home") + "/bin/java",
                "-cp", System.getProperty("java.class.path"), "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (chain == null) pb.environment().remove("CANDOR_WORKSPACE_CHAIN");
        else pb.environment().put("CANDOR_WORKSPACE_CHAIN", chain);
        Process p = pb.start();
        drain(p.getInputStream());
        drain(p.getErrorStream());
        p.waitFor();
    }

    private static void drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
    }

    // ---- THE SECOND FIXTURE: what must NOT change ------------------------------------------------------

    @Test
    void aPureImplementerContributesNothing() throws Exception {
        // Silence IS the purity claim (SPEC §2 rule 3): a dep report omits its pure functions, so an
        // interface whose every implementer is pure must gain no entry — emitting an empty one would make
        // the report grow with data that says nothing.
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/Quiet.java", "package lib;\npublic interface Quiet { String tag(); }\n",
                "lib/QuietImpl.java", "package lib;\npublic class QuietImpl implements Quiet {\n"
                        + "  public String tag() { return \"q\"; }\n}\n"), true);
        assertNull(r.get("lib/Quiet.tag()Ljava/lang/String;"),
                "a pure implementer must contribute nothing; got " + r.get("lib/Quiet.tag()Ljava/lang/String;"));
    }

    @Test
    void anInterfaceWithNoLocalImplementerEmitsNoEntry() throws Exception {
        // `Lonely` has no implementer and no inherited body, so `chaTargets` finds nothing to union. This is
        // where "no implementer → no entry" actually comes from — there is no separate guard, and adding one
        // was measured inert on twelve real jars (see ReportWriter#appendInterfaceUnions).
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/Lonely.java", "package lib;\npublic interface Lonely { void save(String s); }\n"), true);
        assertNull(r.get("lib/Lonely.save(Ljava/lang/String;)V"), "no implementer, no entry");
        for (Map.Entry<String, Map<String, Object>> e : r.entrySet())
            assertNull(e.getValue().get("interfaceUnion"), "nothing to publish; got " + e.getKey());
    }

    @Test
    void aReAbstractedMethodPublishesTheSuperInterfaceDefaultThatWouldRun() throws Exception {
        // The other side of the same walk, pinned because the first version of this rung SUPPRESSED it. An
        // interface with no local implementer still has a runnable body when its method's only implementation
        // is a super-interface `default`: an implementer written by the CONSUMER inherits exactly that body,
        // and the consumer cannot see it (a dep supertype is not on candor's classpath). Publishing it is the
        // union doing its job, not a fabrication — `chaTargets` named a body this scan analysed.
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/Base.java", "package lib;\n"
                        + "public interface Base { default void go() { System.getenv(\"HOME\"); } }\n",
                "lib/Orphan.java", "package lib;\npublic interface Orphan extends Base { void go(); }\n"), true);
        Map<String, Object> u = r.get("lib/Orphan.go()V");
        assertNotNull(u, "the inherited default is what an external implementer runs; hashes " + r.keySet());
        assertEquals(Boolean.TRUE, u.get("interfaceUnion"));
        assertEquals(List.of("Env"), u.get("inferred"));
    }

    @Test
    void aNonInterfaceMethodIsUntouched() throws Exception {
        // The rung is scoped to INTERFACES. An abstract dependency CLASS receiver is the documented residual
        // (DEP-RECEIVER-TYPING-DESIGN.md: INVOKEVIRTUAL on a dep class usually names the body itself), and a
        // concrete class method already has a real entry when it is effectful. Neither may gain a synthetic
        // one — that would be a second entry under a key the join already answers.
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/AbstractStore.java", "package lib;\npublic abstract class AbstractStore {\n"
                        + "  public abstract void save(String s);\n}\n",
                "lib/DiskStore.java", "package lib;\nimport java.io.*;\n"
                        + "public class DiskStore extends AbstractStore {\n"
                        + "  public void save(String s) { try { new FileWriter(\"/tmp/x\").write(s); }"
                        + " catch (IOException e) {} }\n}\n"), true);
        for (Map.Entry<String, Map<String, Object>> e : r.entrySet())
            assertNull(e.getValue().get("interfaceUnion"),
                    "no interface here — nothing may be synthesized; got " + e.getKey());
    }

    @Test
    void aStaticInterfaceMethodIsNotUnionedWithASameSignatureInstanceImplementation() throws Exception {
        // A `static` (or `private`) interface method is invoked by INVOKESTATIC / INVOKESPECIAL on the exact
        // declaration — it cannot be overridden, so there is nothing to union. This is the fixture that makes
        // the filter LOAD-BEARING rather than tidy: `Util.home()` is PURE, so no real entry claims its hash,
        // and `UtilImpl` declares an INSTANCE `home()` with the same name+desc that reads Env. Without the
        // filter that instance body is unioned onto `lib/Util.home()…`, and every consumer's `Util.home()`
        // — a static call to a pure method — is charged Env. That is a fabrication, not a widening.
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/Util.java", "package lib;\npublic interface Util {\n"
                        + "  static String home() { return \"const\"; }\n"
                        + "  String tag();\n}\n",
                "lib/UtilImpl.java", "package lib;\npublic class UtilImpl implements Util {\n"
                        + "  public String home() { return System.getenv(\"HOME\"); }\n"
                        + "  public String tag() { return \"t\"; }\n}\n"), true);
        assertNull(r.get("lib/Util.home()Ljava/lang/String;"),
                "a pure STATIC interface method must not inherit an implementer's same-signature instance"
                + " body; got " + r.get("lib/Util.home()Ljava/lang/String;"));
    }

    @Test
    void anEffectfulDefaultMethodKeepsItsOwnRealEntryAndIsNotDuplicated() throws Exception {
        // A synthetic entry must never DISPLACE a body candor actually analysed: the hash is already claimed,
        // so the real entry stays (unmarked, with its own `loc`, `direct` and declared/undeclared surfaces).
        // But it must not SUPPRESS the union either — see theOverridingImplementersEffectReachesADefaultsHash.
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/Cfg.java", "package lib;\n"
                        + "public interface Cfg { default void load() { System.getenv(\"HOME\"); } }\n",
                "lib/DiskCfg.java", "package lib;\nimport java.io.*;\n"
                        + "public class DiskCfg implements Cfg {\n"
                        + "  public void load() { try { new FileWriter(\"/tmp/x\").write(\"c\"); }"
                        + " catch (IOException e) {} }\n}\n"), true);
        Map<String, Object> e = r.get("lib/Cfg.load()V");
        assertNotNull(e, "the default method's own entry; hashes " + r.keySet());
        assertNull(e.get("interfaceUnion"), "the REAL entry stays real — it is not replaced by a synthetic one");
        assertEquals(List.of("Env"), e.get("direct"),
                "`direct` describes the analysed BODY at `loc` and is never widened by the dispatch union");
        assertEquals(1, r.values().stream().filter(x -> "lib/Cfg.load()V".equals(x.get("hash"))).count(),
                "exactly one entry may carry the hash — a duplicate would make the consumer's join order-dependent");
    }

    @Test
    void theOverridingImplementersEffectReachesADefaultsHash() throws Exception {
        // THE CARDINAL SIN this rung nearly shipped. An effectful `default` claims the hash a consumer's
        // INVOKEINTERFACE keys on, and the union was SKIPPED for a claimed hash — so `S3Store implements
        // Store` overriding a logging `default` with an HTTP call published only ["Log"], and `deny Net`
        // passed on code that makes an HTTP call. Publishing under a hash is answering "what can running
        // this member do", and in-scan the same `iface.load()` is already charged the CHA union — so the
        // boundary answer must be the union too, or the two disagree.
        Map<String, Map<String, Object>> r = depReport(Map.of(
                "lib/Cfg.java", "package lib;\n"
                        + "public interface Cfg { default void load() { System.getenv(\"HOME\"); } }\n",
                "lib/DiskCfg.java", "package lib;\nimport java.io.*;\n"
                        + "public class DiskCfg implements Cfg {\n"
                        + "  public void load() { try { new FileWriter(\"/tmp/x\").write(\"c\"); }"
                        + " catch (IOException e) {} }\n}\n"), true);
        assertEquals(List.of("Env", "Fs"), inferred(r, "lib/Cfg.load()V"),
                "the published effects for the hash must cover the default body AND every overrider");
    }

    @Test
    void aDefaultMethodWithOnlyPureImplementersIsNotWidenedAtAll() throws Exception {
        // THE SECOND FIXTURE for the widening. Merging into a claimed hash must be a no-op when there is
        // nothing to merge: the entry must be byte-for-byte the entry the unflagged scan writes, or the rung
        // is mutating ordinary report content instead of adding to it.
        Map<String, String> lib = Map.of(
                "lib/Cfg.java", "package lib;\n"
                        + "public interface Cfg { default void load() { System.getenv(\"HOME\"); } }\n",
                "lib/QuietCfg.java", "package lib;\n"
                        + "public class QuietCfg implements Cfg { public void load() { } }\n");
        assertEquals(byHash(depReportText(lib, false)).get("lib/Cfg.load()V"),
                byHash(depReportText(lib, true)).get("lib/Cfg.load()V"),
                "a claimed hash with nothing new to publish must be untouched by the rung");
    }

    @Test
    void theOverridingImplementersEffectReachesTheConsumerAcrossTheBoundary() throws Exception {
        // The end-to-end form of the same defect: `deny Net` must bite. The consumer's INVOKEINTERFACE
        // resolves to the default's REAL entry, so before the fix it read Env only and the override's Net
        // was never charged to anyone.
        Map<String, String> lib = Map.of(
                "lib/Store.java", "package lib;\n"
                        + "public interface Store { default void save(String s) { System.getenv(\"HOME\"); } }\n",
                "lib/S3Store.java", "package lib;\nimport java.net.*;\n"
                        + "public class S3Store implements Store {\n"
                        + "  public void save(String s) { try { new URL(\"http://s3.example.com/x\").openStream(); }"
                        + " catch (Exception e) {} }\n}\n");
        Map<String, String> app = Map.of("app/Go.java",
                "package app;\nimport lib.Store;\npublic class Go { public void run(Store s) { s.save(\"x\"); } }\n");
        List<?> after = (List<?>) chainedApp(lib, app, true).get("app.Go.run").get("inferred");
        assertTrue(after.contains("Net"),
                "the overrider's Net must reach the consumer through the default's hash; got " + after);
    }

    // ---- THE FAN-OUT BOUND: the second fixtures come first ---------------------------------------------

    /** A lib with an interface {@code Chan.go()} and {@code n} implementers, the LAST one effectful (Net to
     *  {@code s3.example.com}), every other one pure. {@code sealTo} != null makes the interface SEALED over
     *  exactly those implementers — a PROVABLY complete hierarchy, which is what earns the carve-out. */
    private static Map<String, String> chanLib(int n, boolean sealed) {
        Map<String, String> m = new java.util.HashMap<>();
        StringBuilder permits = new StringBuilder();
        for (int i = 0; i < n; i++) permits.append(i == 0 ? "" : ", ").append("C").append(i);
        m.put("lib/Chan.java", "package lib;\npublic " + (sealed ? "sealed " : "") + "interface Chan"
                + (sealed ? " permits " + permits : "") + " { void go(); }\n");
        for (int i = 0; i < n - 1; i++)
            m.put("lib/C" + i + ".java", "package lib;\npublic " + (sealed ? "final " : "")
                    + "class C" + i + " implements Chan { public void go() { } }\n");
        m.put("lib/C" + (n - 1) + ".java", "package lib;\nimport java.net.*;\npublic " + (sealed ? "final " : "")
                + "class C" + (n - 1) + " implements Chan {\n"
                + "  public void go() { try { new URL(\"http://s3.example.com/x\").openStream(); }"
                + " catch (Exception e) {} }\n}\n");
        return m;
    }

    @Test
    void anInterfaceAtTheFanoutBoundStillPublishesItsPreciseUnion() throws Exception {
        // THE SECOND FIXTURE, written before the bound was applied. Bounding the union at CHA_FANOUT_LIMIT is
        // a NARROWING, and the fixture that proves a narrowing closed a fabrication cannot notice the reaches
        // it closed with it. Exactly 12 implementers = the widest hierarchy in-scan dispatch resolves, so the
        // union must still be published, precisely.
        Map<String, Map<String, Object>> r = depReport(chanLib(12, false), true);
        assertEquals(List.of("Net"), inferred(r, "lib/Chan.go()V"),
                "a hierarchy AT the bound must keep resolving; got " + r.get("lib/Chan.go()V"));
        assertEquals(List.of("s3.example.com"), r.get("lib/Chan.go()V").get("hosts"));
    }

    @Test
    void aProvablyClosedSealedHierarchyPublishesItsUnionPastTheBound() throws Exception {
        // The other half of the second fixture: `isClosedHierarchy` is the in-scan carve-out for a hierarchy
        // that is PROVABLY complete (a sealed family's `permits` list is the whole subtype set), so the union
        // over it is exact rather than an open-world guess. Applying the bound without the carve-out would
        // throw away a precise answer on every sealed ADT with more than 12 cases.
        Map<String, Map<String, Object>> r = depReport(chanLib(14, true), true);
        assertEquals(List.of("Net"), inferred(r, "lib/Chan.go()V"),
                "a fully-closed sealed family is exact at any size; got " + r.get("lib/Chan.go()V"));
    }

    @Test
    void aBroadOpenHierarchyPublishesUnknownRatherThanTheSmearedUnion() throws Exception {
        // THE FABRICATION. In-scan, `chan.go()` over a 13-deep OPEN hierarchy drops to Unknown (Candor:
        // `broad = cha.size() > CHA_FANOUT_LIMIT && !isClosedHierarchy(owner)`) precisely because an unseen
        // external subtype may exist and the visible union is an open-world guess. The union entry ignored
        // that bound, so a chained consumer holding one PURE implementer read Net and failed `deny Net` —
        // and only the consumer failed, because the producer's own gate reads `inferred`, never the report.
        // Unknown, not silence: silence IS a purity claim (§2 rule 3), and 12 of these implementers being
        // pure does not make the 13th pure.
        Map<String, Map<String, Object>> r = depReport(chanLib(13, false), true);
        Map<String, Object> u = r.get("lib/Chan.go()V");
        assertNotNull(u, "a bound must not produce SILENCE — that is the cardinal sin, not a bound");
        assertEquals(List.of("Unknown"), u.get("inferred"), "the broad union must not be published");
        assertEquals(List.of("dispatch:lib.Chan.go"), u.get("unknownWhy"),
                "the Unknown must say why, so a reason-scoped `deny E Unknown[dispatch]` can bite");
        assertNull(u.get("hosts"), "no literal surface may travel with an unresolved dispatch");
        assertEquals(Boolean.TRUE, u.get("interfaceUnion"));
    }

    @Test
    void aBroadHierarchyDoesNotFabricateNetOnTheConsumer() throws Exception {
        // The boundary form: the consumer must not inherit the smear (fabrication), and must not read pure
        // (the cardinal sin). Unknown is the answer that is true of candor's state.
        Map<String, String> app = Map.of("app/Go.java",
                "package app;\nimport lib.Chan;\npublic class Go { public void run(Chan c) { c.go(); } }\n");
        Map<String, Object> after = chainedApp(chanLib(13, false), app, true).get("app.Go.run");
        assertNotNull(after, "the consumer must not vanish from the report (that is a purity claim)");
        assertEquals(List.of("Unknown"), after.get("inferred"),
                "a broad dep hierarchy is honest indeterminacy, not Net; got " + after);
    }

    // ---- THE Net DESTINATION CLASS: fail-closed across the union ---------------------------------------

    /** {@code Fetch.go()} with a telemetry-host implementer and, optionally, one whose host is computed at
     *  runtime (invisible to the scan — the shape `netClass` exists to fail closed on). */
    private static Map<String, String> netLib(boolean withRuntimeHost) {
        Map<String, String> m = new java.util.HashMap<>();
        m.put("lib/Fetch.java", "package lib;\npublic interface Fetch { void go(); }\n");
        m.put("lib/Telemetry.java", "package lib;\nimport java.net.*;\n"
                + "public class Telemetry implements Fetch {\n"
                + "  public void go() { try { new URL(\"https://sentry.io/api\").openStream(); }"
                + " catch (Exception e) {} }\n}\n");
        m.put("lib/Telemetry2.java", "package lib;\nimport java.net.*;\n"
                + "public class Telemetry2 implements Fetch {\n"
                + "  public void go() { try { new URL(\"https://logtail.com/in\").openStream(); }"
                + " catch (Exception e) {} }\n}\n");
        // `Wild`'s endpoint lives in a connection built somewhere candor cannot see, so its Net has NO
        // visible host and no masking marker either — the `hosts.isEmpty()` branch of the ⟨0.20⟩ rule, which
        // is exactly the branch a merged host set destroys. (A `new URL(getenv).openStream()` would NOT
        // reproduce the defect: that shape sets the AS-EFF-008 masked marker, and the union already ORs it.)
        if (withRuntimeHost)
            m.put("lib/Wild.java", "package lib;\nimport java.net.*;\n"
                    + "public class Wild implements Fetch {\n"
                    + "  URLConnection c;\n"
                    + "  public void go() { try { c.getInputStream(); } catch (Exception e) {} }\n}\n");
        return m;
    }

    @Test
    void aRuntimeHostImplementerIsNotCertifiedByATelemetrySibling() throws Exception {
        // ⟨0.20⟩ netClass is FAIL-CLOSED by design: a Net with no visible host is `unknown-host`, never a
        // benign class. The union merged `hosts` ACROSS implementers first and classified afterwards, so
        // `Telemetry`'s literal sentry.io made the merged host set non-empty and `Wild`'s runtime endpoint —
        // which alone is unknown-host — was certified `known-telemetry`. `deny Net[unknown-host]` then passed
        // on a dep that posts to an endpoint read from the environment. Classify PER IMPLEMENTER and union
        // the CLASSES; a union of hosts is not a host.
        Map<String, Object> u = depReport(netLib(true), true).get("lib/Fetch.go()V");
        assertNotNull(u, "union entry missing");
        assertTrue(((List<?>) u.get("netClass")).contains("unknown-host"),
                "an implementer with no visible host must keep the union unknown-host; got " + u.get("netClass"));
    }

    @Test
    void aUnionOfTelemetryOnlyImplementersStaysKnownTelemetry() throws Exception {
        // THE SECOND FIXTURE for the fail-closed fix: failing closed must be driven by an actual invisible
        // destination, not by the mere fact of unioning. Two implementers, both with a literal telemetry
        // host — the class stays exactly `known-telemetry`, or `deny Net[unknown-host]` becomes a rule that
        // fires on every chained interface and stops meaning anything.
        Map<String, Object> u = depReport(netLib(false), true).get("lib/Fetch.go()V");
        assertNotNull(u, "union entry missing");
        assertEquals(List.of("known-telemetry"), u.get("netClass"),
                "two literal telemetry hosts must not manufacture an unknown-host");
        assertEquals(List.of("logtail.com", "sentry.io"), u.get("hosts"),
                "the literal hosts still travel — the fix is to the CLASSIFICATION, not to the surface");
    }

    // ---- the boundary: the motivating experiment, end to end -------------------------------------------

    @Test
    void theUnionEntryResolvesACrossPackageInterfaceDispatch() throws Exception {
        Map<String, String> lib = Map.of("lib/Store.java", STORE, "lib/FileStore.java", FILE_STORE);
        Map<String, String> app = Map.of("app/Go.java",
                "package app;\nimport lib.Store;\npublic class Go { public void run(Store s) { s.save(\"hello\"); } }\n");
        // CONTROL — the dep report as produced today: the site discloses half 1's Unknown, never the effect.
        Map<String, Object> before = chainedApp(lib, app, false).get("app.Go.run");
        assertNotNull(before, "the control must disclose, not vanish");
        assertEquals(List.of("Unknown"), before.get("inferred"), "half 1 discloses; it does not resolve");
        assertEquals(List.of("dispatch:lib.Store.save"), before.get("unknownWhy"));
        // WITH the rung — the same consumer, unchanged, resolves through the union entry.
        Map<String, Object> after = chainedApp(lib, app, true).get("app.Go.run");
        assertNotNull(after, "app.Go.run must be in the report");
        assertEquals(List.of("Fs"), after.get("inferred"),
                "the union entry lands on the key the INVOKEINTERFACE site already forms; got " + after);
    }

    @Test
    void aPureDepInterfaceStillReadsPureAcrossTheBoundary() throws Exception {
        // The fabrication control for the boundary half: the rung must add NOTHING when the dependency's
        // own report says every implementer is pure.
        Map<String, String> lib = Map.of(
                "lib/Quiet.java", "package lib;\npublic interface Quiet { String tag(); }\n",
                "lib/QuietImpl.java", "package lib;\npublic class QuietImpl implements Quiet {\n"
                        + "  public String tag() { return \"q\"; }\n}\n");
        Map<String, String> app = Map.of("app/Go.java",
                "package app;\nimport lib.Quiet;\npublic class Go { public String run(Quiet q) { return q.tag(); } }\n");
        assertNull(chainedApp(lib, app, true).get("app.Go.run"),
                "a pure dep interface must leave the consumer pure (absent from `functions`)");
    }
}
