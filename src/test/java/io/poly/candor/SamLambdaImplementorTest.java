package io.poly.candor;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import io.poly.candor.model.EffectSet;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R530b — A LAMBDA IS AN IMPLEMENTOR, AND THE EMPTY-CHA TEST IS WHAT ARMED THE DISCLOSURE.
 *
 * <p>{@link Cha#chaTargets} answers "which project bodies implement this member" from loaded
 * {@code ClassNode}s. A Java lambda has none — javac emits its body as a synthetic {@code lambda$…}
 * method on the CAPTURING class and binds it to the interface at runtime through
 * {@code LambdaMetafactory} — so a lambda was never in any implementor set this engine built. With ZERO
 * named implementors that cost nothing, because every arm that discloses an unresolvable dispatch is
 * armed by an EMPTY candidate set. The sin is the TOGGLE: adding ONE unrelated, pure
 * {@code class Repaint implements Runnable} makes the set non-empty, the disclosure goes silent, the
 * dispatch resolves to the pure sibling, and the dispatching method is reported ABSENT — a SPEC §2 rule 3
 * claim of purity over a real socket.
 *
 * <p><b>EVERY TEST HERE WAS RUN RED AGAINST THE PUBLISHED 0.39.0 JAR BEFORE THE FIX EXISTED.</b> The
 * shape is absence-based, so §E3 applies twice over: an absent row and a genuinely pure one are the same
 * bytes, and a fixture that does not compile produces the passing answer. Every fixture below therefore
 * asserts on a POSITIVE effect, and the over-charge controls assert a named sibling IS present so a
 * broken fixture cannot read as a clean control.
 *
 * <p><b>THE BOUNDARY WAS NOT DRAWN AROUND THE TRIGGER (brief §9).</b> The row arrived with two arms — a
 * JDK SAM passed to a project dispatcher, and a chained consumer. A sweep of every site that BUILDS an
 * implementor set found four, and all four are pinned here:
 * <ol>
 *   <li>the in-scan virtual dispatch ({@code Candor#virtualDispatch});
 *   <li>an UNBOUND abstract project method-ref CHA-fanned at its creation site;
 *   <li>a SAM-forwarding method-ref ({@code task::run}) at the same site;
 *   <li>the published {@code interfaceUnion} entry ({@code ReportWriter#appendInterfaceUnions}), plus
 *       its new ARM 3 key for an abstraction NO class in the scan implements.
 * </ol>
 * Three further {@code chaTargets} callers were examined and deliberately LEFT ALONE, because each reads
 * emptiness as "disclose" and widening it would DELETE a disclosure: the abstract-dep-Unknown suppression
 * ({@code Candor}'s {@code inherited = null} guard), {@code untypedDepReceiver}'s conjunct 4, and the
 * Object-protocol reentry walk (whose contracts are exempt by §4 and unreachable through
 * {@code LambdaMetafactory} anyway).
 */
class SamLambdaImplementorTest {

    @AfterEach
    void resetGate() {
        ReportWriter.publishUnionsOverrideForTest = null;
    }

    // ---- harness ---------------------------------------------------------------------------------------

    private static Map<String, EffectSet> scan(Map<String, String> sources) throws Exception {
        Path out = TestCompiler.compile(sources);
        try {
            return Candor.runScan(out);
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** The WRITTEN report for {@code lib}, keyed by entry hash — the only view that shows a chained
     *  consumer what this package publishes. Mirrors {@code InterfaceUnionTest}'s harness rather than
     *  growing a second one. */
    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> depReport(Map<String, String> lib) throws Exception {
        Path libDir = TestCompiler.compile(lib);
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            ReportWriter.publishUnionsOverrideForTest = true;
            Path out = libDir.getParent().resolve("dep.json");
            Files.deleteIfExists(out);
            ReportWriter.writeJson(Candor.runScan(libDir), out.toString());
            Map<String, Object> root = new Gson().fromJson(Files.readString(out), Map.class);
            Map<String, Map<String, Object>> byHash = new java.util.HashMap<>();
            for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
                byHash.put((String) e.get("hash"), e);
            return byHash;
        } finally {
            Candor.config = saved;
            ReportWriter.publishUnionsOverrideForTest = null;
            rm(libDir.getParent());
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> inferred(Map<String, Map<String, Object>> r, String hash) {
        Map<String, Object> e = r.get(hash);
        return e == null ? null : (List<String>) e.get("inferred");
    }

    /** {@code lib} scanned and chained, then {@code app} scanned against it — the cross-scan arrangement,
     *  which is where an implementor the producer could not name becomes a purity claim at the consumer. */
    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> chainedApp(Map<String, String> lib, Map<String, String> app)
            throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Path depReport = base.resolve("dep.json");
            Files.deleteIfExists(depReport);
            ReportWriter.publishUnionsOverrideForTest = true;
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            ReportWriter.publishUnionsOverrideForTest = false;   // the CONSUMER never emits union entries
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
            ReportWriter.publishUnionsOverrideForTest = null;
            rm(base);
        }
    }

    private static final String SINK =
            "  static void io(){ try { new java.io.FileInputStream(\"/x\").read(); } catch(Exception e){} }\n";

    // ---- SITE 1: the in-scan virtual dispatch -----------------------------------------------------------

    /** THE ROW'S OWN ARM (conformance PART 87 `argstore`). The lambda is not stored in a field — it is
     *  handed straight to a project dispatcher, which is the most ordinary spelling Java has. RED on
     *  published 0.39.0: {@code W.dispatch} is ABSENT from the report entirely. */
    @Test
    void aLambdaHandedToAProjectDispatcherReachesItPastAnUnrelatedPureImplementor() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("W.java", String.join("\n",
            "public class W {",
            SINK,
            "  static void dispatch(Runnable h){ h.run(); }",
            "  static void fire(){ dispatch(() -> io()); }",
            "}"),
            "Repaint.java", "public class Repaint implements Runnable { static int n; public void run(){ n++; } }"));
        assertTrue(eff(r, "W.dispatch").toNames().contains("Fs"),
                "the dispatcher must reach the lambda body's Fs even though an unrelated pure Runnable "
                + "makes the CHA non-empty; got " + r.get("W.dispatch"));
    }

    /** THE OVER-CHARGE CONTROL, and it is the half that decides the shape of the fix. The fixture differs
     *  from the one above in exactly ONE thing — what the lambda DOES. A blanket hedge ("any SAM dispatch
     *  with a lambda about becomes Unknown") passes the test above and fails here, which is why this fix
     *  COMPLETES the candidate set instead of disclosing. {@code Repaint.run} is asserted present so a
     *  fixture that did not compile cannot read as a clean control (brief §E3). */
    @Test
    void aPureLambdaThroughTheSameDispatcherGainsNothingAndIsNotHedged() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("W.java", String.join("\n",
            "public class W {",
            "  static int n;",
            "  static void quiet(){ n++; }",
            "  static void dispatch(Runnable h){ h.run(); }",
            "  static void fire(){ dispatch(() -> quiet()); }",
            "}"),
            "Repaint.java", "public class Repaint implements Runnable { static int n; public void run(){ n++; } }"));
        assertTrue(r.containsKey("Repaint.run"),
                "LIVENESS: this control asserts an ABSENCE, so the scan must be shown to have seen the "
                + "fixture at all — Repaint.run is analysed in every arm");
        assertTrue(eff(r, "W.dispatch").isEmpty(),
                "a PURE lambda through the identical shape must neither gain an effect nor be hedged into "
                + "Unknown — the fix resolves, it does not smear; got " + r.get("W.dispatch"));
    }

    /** THE DISCLOSURE THAT ALREADY WORKED MUST SURVIVE. With no named implementor the engine emits
     *  {@code callback:}; the widening is deliberately scoped OFF the empty-CHA path, because that is the
     *  path the private functional-param forwarding gate runs on and a project-wide union into
     *  {@code chaTargets} broke it once before ({@code Cha#collectFieldLambdaBindings}'s doc). */
    @Test
    void theZeroImplementorDisclosureIsUntouched() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("W.java", String.join("\n",
            "public class W {",
            SINK,
            "  static void dispatch(Runnable h){ h.run(); }",
            "  static void fire(){ dispatch(() -> io()); }",
            "}")));
        assertTrue(eff(r, "W.dispatch").toNames().contains("Unknown"),
                "with no named implementor the callback: disclosure must still fire; got " + r.get("W.dispatch"));
    }

    /** The same toggle over a PROJECT-declared abstraction rather than a JDK SAM — the {@code dispatch:}
     *  arm rather than the {@code callback:} one. Two arms of one branch, so both are pinned. */
    @Test
    void aLambdaOverAProjectInterfaceReachesTheDispatcherToo() throws Exception {
        Map<String, EffectSet> r = scan(Map.of(
            "H.java", "public interface H { void go(); }",
            "Pure.java", "public class Pure implements H { static int n; public void go(){ n++; } }",
            "W.java", String.join("\n",
            "public class W {",
            SINK,
            "  static void dispatch(H h){ h.go(); }",
            "  static void fire(){ dispatch(() -> io()); }",
            "}")));
        assertTrue(eff(r, "W.dispatch").toNames().contains("Fs"),
                "a project interface with one pure named implementor must not certify a lambda's body "
                + "pure; got " + r.get("W.dispatch"));
    }

    // ---- SITE 2: an UNBOUND abstract project method-ref, CHA-fanned at its creation site -----------------

    /** {@code forEach(H::go)} names an ABSTRACT project method, so the body that runs is decided by the
     *  element the HOF supplies. That site CHA-fans over the project's named implementors and could not
     *  see a lambda either. Unlike the dispatch site this one has NO disclosure arm at all, so it is
     *  widened whether the CHA is empty or not — here it is empty, and pre-fix the caller was silent. */
    @Test
    void anUnboundProjectMethodRefFansToLambdaImplementorsToo() throws Exception {
        Map<String, EffectSet> r = scan(Map.of(
            "H.java", "public interface H { void go(); }",
            "W.java", String.join("\n",
            "import java.util.*;",
            "public class W {",
            SINK,
            "  static H mk(){ return () -> io(); }",
            "  static void run(List<H> xs){ xs.forEach(H::go); }",
            "}")));
        assertTrue(eff(r, "W.run").toNames().contains("Fs"),
                "the unbound method-ref's only implementor is a lambda; the caller must reach it rather "
                + "than read silent-pure; got " + r.get("W.run"));
    }

    // ---- SITE 3: a SAM-forwarding method-ref (`task::run`) ----------------------------------------------

    /** {@code Runnable::run} / {@code task::run} forwards to a SAM that HAS no body, so the answer is
     *  whatever implements that SAM. One unrelated pure {@code Runnable} was enough to make this branch
     *  claim it had resolved the question. The empty arm above it still discloses {@code callback:} and is
     *  untouched. */
    @Test
    void aSamForwardingMethodRefReachesLambdaImplementors() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("W.java", String.join("\n",
            "import java.util.*;",
            "public class W {",
            SINK,
            "  static Runnable mk(){ return () -> io(); }",
            "  static void run(List<Runnable> xs){ xs.forEach(Runnable::run); }",
            "}"),
            "Repaint.java", "public class Repaint implements Runnable { static int n; public void run(){ n++; } }"));
        assertTrue(eff(r, "W.run").toNames().contains("Fs"),
                "the forwarded SAM's implementors include the project's lambda; got " + r.get("W.run"));
    }

    // ---- SITE 4: the published interfaceUnion entry -----------------------------------------------------

    /** ARM 3 — the implementor with NO ClassNode at all. Arms 1 and 2 of {@code unionCandidates} both
     *  enumerate loaded classes, so a package whose only implementor of a foreign abstraction is a LAMBDA
     *  published NOTHING under that abstraction, and a chained consumer read the silence as purity. */
    @Test
    void aPackageWhoseOnlyImplementorIsALambdaStillPublishesTheUnionEntry() throws Exception {
        Map<String, Map<String, Object>> dep = depReport(Map.of(
            "iface/Backend.java", "package iface; public interface Backend { int size(); }",
            "lib/Factory.java", String.join("\n",
            "package lib;",
            "public class Factory {",
            "  public static iface.Backend mk(){ return () -> { try { new java.net.Socket(\"h\",80); }"
                    + " catch(Exception e){} return 1; }; }",
            "}")));
        List<String> inf = inferred(dep, "iface/Backend.size()I");
        assertNotNull(inf, "the abstraction's union entry must be published even though no CLASS in this "
                + "scan implements it — the implementor is a lambda. Published hashes: " + dep.keySet());
        assertTrue(inf.contains("Net"), "the lambda body's Net must ride on the published entry, got " + inf);
    }

    /** THE CHAINED CONSUMER, which is the shape the row was measured on: three packages, one variable —
     *  {@code () -> {…}} versus {@code new Handler(){…}}. Pre-fix the lambda arm's consumer was ABSENT
     *  from {@code functions[]} while the anonymous-class arm read {@code ['Net']}. */
    @Test
    void aChainedConsumerLearnsOfTheProducersLambdaImplementor() throws Exception {
        Map<String, Map<String, Object>> app = chainedApp(
            Map.of(
                "iface/Backend.java", "package iface; public interface Backend { int size(); }",
                "iface/Pure.java", "package iface; public class Pure implements Backend { public int size(){ return 7; } }",
                "iface/Terminal.java", "package iface; public class Terminal { public static int term(Backend b){ return b.size(); } }",
                "lib/Factory.java", String.join("\n",
                "package lib;",
                "public class Factory {",
                "  public static iface.Backend mk(){ return () -> { try { new java.net.Socket(\"h\",80); }"
                        + " catch(Exception e){} return 1; }; }",
                "}")),
            Map.of("app/App.java",
                "package app; public class App { public static int go(){ return iface.Terminal.term(lib.Factory.mk()); } }"));
        Map<String, Object> go = app.get("app.App.go");
        assertNotNull(go, "the consumer must not be ABSENT — absence is a purity claim over a real socket. "
                + "Reported: " + app.keySet());
        assertTrue(((List<?>) go.get("inferred")).contains("Net"),
                "the consumer carries the producer's lambda implementor's Net, got " + go.get("inferred"));
    }

    /** THE BOUND, AND THE REGRESSION IT WAS WRITTEN FROM. The first version of the union widening folded
     *  the lambdas into {@code impls} BEFORE the fan-out bound was computed, so bodies this scan had
     *  actually SEEN pushed entries past {@code CHA_FANOUT_LIMIT} and the entry published a bare
     *  {@code Unknown} in place of the precise union it published before. MEASURED on the 372-jar corpus:
     *  49 rows lost their effects, {@code org.jooq.RecordMapper.map} among them
     *  ({Clock, Db, Fs, Log, Rand, Unknown} -> {Unknown}). A widening must not be able to DELETE what it
     *  widens, so the bound prices the CHA alone and the lambdas are dropped in favour of an ADDED hedge.
     *
     *  <p>Thirteen lambdas over a one-implementor abstraction: the entry keeps the named implementor's
     *  Fs AND gains Unknown. Both halves are asserted — dropping either makes this test pass against the
     *  version it exists to catch. */
    @Test
    void pastTheFanoutBoundTheUnionKeepsItsEffectsAndAddsTheHedge() throws Exception {
        StringBuilder lambdas = new StringBuilder();
        for (int i = 0; i < 13; i++)
            lambdas.append("  public static iface.Backend mk").append(i)
                   .append("(){ return () -> ").append(i).append("; }\n");
        Map<String, Map<String, Object>> dep = depReport(Map.of(
            "iface/Backend.java", "package iface; public interface Backend { int size(); }",
            "iface/Named.java", String.join("\n",
            "package iface;",
            "public class Named implements Backend {",
            "  public int size(){ try { new java.io.FileInputStream(\"/x\").read(); } catch(Exception e){} return 1; }",
            "}"),
            "lib/Factory.java", "package lib; public class Factory {\n" + lambdas + "}"));
        List<String> inf = inferred(dep, "iface/Backend.size()I");
        assertNotNull(inf, "the entry must still be published; hashes: " + dep.keySet());
        assertTrue(inf.contains("Fs"),
                "the named implementor's effect must SURVIVE the bound — this is the 49-row regression; got " + inf);
        assertTrue(inf.contains("Unknown"),
                "and past the bound the lambdas it could not enumerate must be DISCLOSED, not dropped "
                + "silently; got " + inf);
    }

    // ---- the index itself ------------------------------------------------------------------------------

    /** The key is the SAM's own {@code owner.name+desc} — the same string {@code chaTargets} is asked
     *  with and {@code dispatchesOn} publishes. §F1 q7: a key two paths can spell differently is this
     *  family's most-repeated defect, so the spelling is pinned rather than assumed. A method REFERENCE
     *  and an inline lambda must land on the identical key. */
    @Test
    void theIndexKeysOnTheSamsOwnEntryHashForBothSpellings() throws Exception {
        Path dir = TestCompiler.compile(Map.of("W.java", String.join("\n",
            "public class W {",
            "  static int n;",
            "  static void bump(){ n++; }",
            "  static Runnable a(){ return () -> bump(); }",
            "  static Runnable b(){ return W::bump; }",
            "}")));
        try {
            Candor.runScan(dir);
            List<String> impls = Cha.samLambdaImplementors("java/lang/Runnable", "run", "()V");
            assertEquals(2, impls.size(),
                    "both the inline lambda and the method reference must be indexed under the SAM's own "
                    + "hash; got " + impls);
            assertTrue(impls.stream().anyMatch(s -> s.contains("lambda$a$")), "the inline lambda: " + impls);
            assertTrue(impls.contains("W.bump"), "the method reference's real target: " + impls);
            assertTrue(Cha.samLambdaImplementors("java/lang/Runnable", "run", "()I").isEmpty(),
                    "a DIFFERENT descriptor must not collide with the SAM's key");
        } finally {
            rm(dir.getParent());
        }
    }
}
