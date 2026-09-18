package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * ⟨0.39⟩ THE CHAINED-DISPATCH UNION — SPEC §4, SOUNDNESS R475, conformance PART 92.
 *
 * <p><b>The defect is a TOGGLE, and it runs the wrong way.</b> A library whose public abstraction has ZERO
 * local implementers gives a chained consumer a disclosed {@code Unknown}; add ONE PURE implementer to that
 * library and the consumer is SILENTLY CERTIFIED PURE. So <i>adding a pure implementation to a library
 * REMOVES a disclosure from every consumer of it</i> — the ⟨0.21⟩ cardinal sin reached by a route no single
 * scan can see, because nothing is wrong with either package on its own and the loss exists only in the
 * join. Measured live on ratatui: {@code ratatui-core}'s {@code Terminal::size} dispatches
 * {@code Backend::size} over its sole local implementer {@code TestBackend} (pure), while
 * {@code ratatui-crossterm}'s {@code CrosstermBackend::size} performs IPC, and an app chained onto both
 * reports that function ABSENT with {@code deny Ipc} and {@code pure} over it BOTH exiting 0.
 *
 * <p><b>Why every fixture here has THREE packages.</b> The effectful implementer lives in a THIRD package —
 * neither the dispatching dependency nor the consumer — so no two-package arm can express the finding, and
 * §4 says so in the clause: "no two of them are separable".
 *
 * <p><b>Why the abstraction is in a NESTED package</b> ({@code iface.backend.Backend}, never
 * {@code iface.Backend}). candor-scan's first fixture for this rung put the trait at the crate ROOT and
 * passed whether or not the LOCAL half of obligation 3 worked, because the unqualified key happened to be
 * the qualified one. The JVM's hash is always fully qualified so this engine cannot have that exact bug —
 * which is precisely why the fixture has to be able to SEE it, rather than being arranged so it could not.
 *
 * <p><b>The controls are not optional.</b> Widening a union is where this family has repeatedly turned a
 * silence into a fabrication, so: an only-pure library must stay pure ({@link #aMissAddsNothing}), a
 * zero-implementer library must stay a disclosed {@code Unknown}
 * ({@link #theZeroImplementerDisclosureSurvives}), a foreign union entry must NOT be read as coverage of
 * the package it names ({@link #aForeignUnionEntryIsNotCoverageOfThePackageItNames}, with a near-miss
 * poison that fails on the broad version), and a κ-frontier owner publishes nothing
 * ({@link #aKappaFrontierOwnerPublishesNoUnionEntry}).
 */
class ChainedDispatchUnionTest {

    // ---- the fixture, three packages -------------------------------------------------------------------

    private static final String NET_SINK = "try { new java.net.Socket(\"h\", 1); } catch (Exception e) {}";

    /** The abstraction, NESTED one package down from the dispatcher that owns it. */
    private static final String BACKEND =
            "package iface.backend;\npublic interface Backend { int size(); }\n";
    /** The dispatcher: a PURE function whose only visible implementer is PURE — the toggle's silent side. */
    private static final String TERMINAL = "package iface;\nimport iface.backend.Backend;\n"
            + "public class Terminal { public static int termSize(Backend b) { return b.size(); } }\n";
    /** {@code ratatui-core}'s {@code TestBackend}: the ONE PURE implementer that deleted the disclosure. */
    private static final String TEST_BACKEND = "package iface;\nimport iface.backend.Backend;\n"
            + "public class TestBackend implements Backend { public int size() { return 7; } }\n";
    /** {@code ratatui-crossterm}'s {@code CrosstermBackend}: the effectful implementer, in a THIRD package. */
    private static final String CROSSTERM = "package effimpl;\nimport iface.backend.Backend;\n"
            + "public class Crossterm implements Backend { public int size() { " + NET_SINK + " return 0; } }\n";
    /** The consumer. {@code appSize} is BYTE-IDENTICAL across every arm below; only {@code appRun} — which
     *  supplies the foreign implementer, and is what makes the union legitimate rather than a minted edge —
     *  comes and goes with the third package. */
    private static final String APP = "package app;\nimport iface.backend.Backend;\n"
            + "public class App {\n"
            + "  public static int appSize(Backend b) { return iface.Terminal.termSize(b); }\n"
            + "  public static int appRun() { return appSize(new effimpl.Crossterm()); }\n}\n";
    private static final String APP_NO_THIRD = "package app;\nimport iface.backend.Backend;\n"
            + "public class App {\n"
            + "  public static int appSize(Backend b) { return iface.Terminal.termSize(b); }\n}\n";

    private static Map<String, String> ifacePkg(boolean withPureImpl) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("iface/backend/Backend.java", BACKEND);
        m.put("iface/Terminal.java", TERMINAL);
        if (withPureImpl) m.put("iface/TestBackend.java", TEST_BACKEND);
        return m;
    }

    // ---- obligation 1: the producer names the member, even on a PURE row --------------------------------

    @Test
    void aPureDispatchingFunctionIsEmittedAndNamesTheMemberItDispatchesOn() throws Exception {
        Tree t = Tree.of(ifacePkg(true));
        try {
            Map<String, Map<String, Object>> r = byHash(t.scan("iface"));
            Map<String, Object> row = r.get("iface/Terminal.termSize(Liface/backend/Backend;)I");
            assertNotNull(row, "§2 rule 3 omits pure functions, and THAT ABSENCE IS THE DEFECT: a dispatching"
                    + " function whose only visible implementer is pure vanished from the report, so adding a"
                    + " pure implementation to a library deleted a disclosure from every consumer of it."
                    + " ⟨0.39⟩ obligation 1 makes this the one deliberate exception. Got " + r.keySet());
            assertEquals(List.of(), row.get("inferred"),
                    "…and it is emitted EFFECT-FREE. The row speaks by naming the dispatch, not by claiming"
                    + " an effect it does not have — a hedge here would be the fabrication direction.");
            assertEquals(List.of("iface/backend/Backend.size()I"), row.get("dispatchesOn"),
                    "the member must be named with the FULL owner, in the OWNING package's namespace — the"
                    + " ⟨0.23⟩ rule, which on the JVM is just this engine's ordinary entry hash, so no second"
                    + " spelling is invented and a consumer resolves it through the ordinary index");
        } finally {
            t.close();
        }
    }

    /**
     * ⟨0.39⟩ THE MEMBER REACHES A CALLER THAT NEVER SPELLS THE DISPATCH — and on this engine it reaches it
     * through {@code calls}, not by being copied onto the caller's row.
     *
     * <p>§4 obligation 1 says "transitively", and the literal wire reading of that is unaffordable here:
     * the JVM dispatches through interfaces everywhere, so the member SETS unioned up the call graph grow
     * the report eleven-fold on avro and could not be serialised at all on jooq (see
     * {@code ReportWriter#dispatchReach}). The transitivity therefore lives at the JOIN, exactly where this
     * engine already puts it for {@code unknownWhy} ({@code Candor#depTransitiveWhy}) — so the two things
     * this test pins are the two things that walk has to have: the PURE intermediary must be IN the report
     * with the dispatching callee named in its {@code calls}, and the consumer must end up with the effect.
     * A test that only asserted the caller's own {@code dispatchesOn} would pin one implementation route to
     * the property rather than the property.
     */
    @Test
    void theMemberReachesACallerThatNeverSpellsTheDispatch() throws Exception {
        Map<String, String> lib = ifacePkg(true);
        lib.put("iface/Outer.java", "package iface;\nimport iface.backend.Backend;\n"
                + "public class Outer { public static int outer(Backend b) { return Terminal.termSize(b); } }\n");
        Map<String, String> app = Map.of("app/App.java", "package app;\nimport iface.backend.Backend;\n"
                + "public class App {\n"
                + "  public static int appSize(Backend b) { return iface.Outer.outer(b); }\n"
                + "  public static int appRun() { return appSize(new effimpl.Crossterm()); }\n}\n");
        Tree t = Tree.of(lib, Map.of("effimpl/Crossterm.java", CROSSTERM), app);
        try {
            Map<String, Map<String, Object>> r = byHash(t.scan("iface"));
            Map<String, Object> outer = r.get("iface/Outer.outer(Liface/backend/Backend;)I");
            assertNotNull(outer, "the PURE intermediary must be in the report at all: it is the hop the"
                    + " consumer's walk passes through, and a report that omits it breaks the chain one"
                    + " short of the row the consumer joins. Got " + r.keySet());
            assertEquals(List.of("iface.Terminal.termSize"), outer.get("calls"),
                    "…and it must NAME the dispatching callee. `calls` used to carry effectful callees only,"
                    + " and a dispatching one is pure by construction in exactly the arm R475 is about.");

            String iface = t.scan("iface"), eff = t.scan("effimpl");
            Map<String, Object> row = byFn(t.scanChained("app", iface, eff)).get("app.App.appSize");
            assertNotNull(row, "and the consumer, two hops from the dispatch it never spells, must not be"
                    + " ABSENT — absence IS the purity claim");
            assertTrue(((List<?>) row.get("inferred")).contains("Net"), "got " + row);
        } finally {
            t.close();
        }
    }

    // ---- obligation 2: the FOREIGN union entry ---------------------------------------------------------

    @Test
    void aPackageImplementingAForeignAbstractionPublishesTheUnionUnderTheOwningPackage() throws Exception {
        Tree t = Tree.of(ifacePkg(true), Map.of("effimpl/Crossterm.java", CROSSTERM));
        try {
            Map<String, Map<String, Object>> r = byHash(t.scan("effimpl"));
            Map<String, Object> u = r.get("iface/backend/Backend.size()I");
            assertNotNull(u, "the union entry must be keyed under the package that OWNS the abstraction, not"
                    + " under the one that implements it — without this leg the measured instance is missed"
                    + " entirely, because `iface` sees only its own pure implementer. Got " + r.keySet());
            assertEquals(Boolean.TRUE, u.get("interfaceUnion"), "it is SYNTHETIC and must say so");
            assertEquals(List.of("Net"), u.get("inferred"), "= the union over the implementers THIS package"
                    + " supplies");
            assertNotNull(r.get("effimpl/Crossterm.size()I"),
                    "and the implementer's own ordinary entry is untouched — the rung is additive");
        } finally {
            t.close();
        }
    }

    @Test
    void aKappaFrontierOwnerPublishesNoUnionEntry() throws Exception {
        // THE NARROWING, STATED AS THE TRADE IT IS. `java/lang/Runnable.run()V` is a foreign abstraction
        // nearly every jar implements: a union under it would charge ONE library's effectful Runnable onto
        // every `r.run()` in every consumer — the fabrication direction §4 forbids, and the same shape
        // candor-scan's manifest gate (the owner must be a DECLARED dependency, never `std`) refuses with a
        // manifest this engine does not have. What it costs is an abstraction owned by a MODELLED framework,
        // whose consumers keep reading exactly what they read before this rung.
        Tree t = Tree.of(Map.of("lib/Worker.java", "package lib;\npublic class Worker implements Runnable {\n"
                + "  public void run() { " + NET_SINK + " }\n}\n"));
        try {
            Map<String, Map<String, Object>> r = byHash(t.scan("lib"));
            assertNull(r.get("java/lang/Runnable.run()V"),
                    "a κ-frontier owner must publish no union entry; got " + r.keySet());
            assertNotNull(r.get("lib/Worker.run()V"), "the implementer's own entry is unaffected");
        } finally {
            t.close();
        }
    }

    // ---- obligation 3: the consumer's join -------------------------------------------------------------

    @Test
    void theToggleIsClosed() throws Exception {
        // c1_foreign_effectful. THE ROW. `appSize` is byte-identical to the arm in `aMissAddsNothing`; the
        // only thing that differs in the whole experiment is the EXISTENCE of the third package.
        Tree t = Tree.of(ifacePkg(true), Map.of("effimpl/Crossterm.java", CROSSTERM), Map.of("app/App.java", APP));
        try {
            String iface = t.scan("iface"), eff = t.scan("effimpl");
            Map<String, Map<String, Object>> app = byFn(t.scanChained("app", iface, eff));
            Map<String, Object> row = app.get("app.App.appSize");
            assertNotNull(row, "the consumer must not be ABSENT — absence IS a purity claim, and it is the"
                    + " whole sin: `deny Net app.App.appSize` and `pure app.App.appSize` both exit 0");
            assertTrue(((List<?>) row.get("inferred")).contains("Net"),
                    "the foreign implementer's effect must reach the consumer, got " + row);
        } finally {
            t.close();
        }
    }

    @Test
    void aMissAddsNothing() throws Exception {
        // c3_pure_only — THE FABRICATION GUARD. A consumer over a library whose only implementer ANYWHERE is
        // pure is LEGITIMATELY pure and must STAY pure. An engine that hedged on "a dispatch occurred"
        // rather than on "an implementer is invisible" would charge every consumer of every dispatching
        // library for effects nobody implements, and it would redden here and nowhere else.
        Tree t = Tree.of(ifacePkg(true), Map.of("app/App.java", APP_NO_THIRD));
        try {
            String iface = t.scan("iface");
            Map<String, Map<String, Object>> app = byFn(t.scanChained("app", iface));
            Map<String, Object> row = app.get("app.App.appSize");
            if (row != null) {
                assertFalse(((List<?>) row.get("inferred")).contains("Net"), "FABRICATED Net: " + row);
                assertFalse(((List<?>) row.get("inferred")).contains("Unknown"),
                        "a legitimately-pure consumer must not acquire a HEDGE either — the union adds a"
                        + " CONTRIBUTOR, not a resolution rule, and a miss adds nothing. Got " + row);
            }
        } finally {
            t.close();
        }
    }

    @Test
    void theZeroImplementerDisclosureSurvives() throws Exception {
        // c2_zero_impl — the toggle's OTHER side, and the one a fix can quietly trade away: a library with
        // no implementer at all must remain a disclosed `Unknown`. A fix that reddens c1 and greys this has
        // swapped one silence for another and deleted the contrast the row exists to pin.
        Tree t = Tree.of(ifacePkg(false), Map.of("app/App.java", APP_NO_THIRD));
        try {
            String iface = t.scan("iface");
            Map<String, Map<String, Object>> app = byFn(t.scanChained("app", iface));
            Map<String, Object> row = app.get("app.App.appSize");
            assertNotNull(row, "zero implementers must stay DISCLOSED, not silent; got " + app.keySet());
            assertTrue(((List<?>) row.get("inferred")).contains("Unknown"), "got " + row);
        } finally {
            t.close();
        }
    }

    @Test
    void theConsumersOwnVisibleImplementerIsUnionedToo() throws Exception {
        // §4 names TWO contributors — "its own visible implementers with every chained entry carrying that
        // key" — and the LOCAL one is the half candor-scan shipped broken, because its first fixture put the
        // abstraction where an unqualified key happened to work. Here the consumer itself supplies the
        // effectful implementer; there is no third package at all, and `appSize` still never spells the
        // dispatch. The abstraction is NESTED, which is the only difference that could hide this.
        Map<String, String> app = new LinkedHashMap<>();
        app.put("app/App.java", "package app;\nimport iface.backend.Backend;\n"
                + "public class App {\n"
                + "  public static int appSize(Backend b) { return iface.Terminal.termSize(b); }\n"
                + "  public static int appRun() { return appSize(new Local()); }\n}\n");
        app.put("app/Local.java", "package app;\nimport iface.backend.Backend;\n"
                + "public class Local implements Backend { public int size() { " + NET_SINK + " return 0; } }\n");
        Tree t = Tree.of(ifacePkg(true), app);
        try {
            String iface = t.scan("iface");
            Map<String, Map<String, Object>> r = byFn(t.scanChained("app", iface));
            Map<String, Object> row = r.get("app.App.appSize");
            assertNotNull(row, "the consumer's OWN implementer must reach it; got " + r.keySet());
            assertTrue(((List<?>) row.get("inferred")).contains("Net"),
                    "the local implementer joins as an ordinary call EDGE so its effects flow through the"
                    + " same fixpoint every other local call uses. Got " + row);
        } finally {
            t.close();
        }
    }

    /**
     * ⟨0.39⟩ THE MIDDLE PACKAGE — a FOUR-package chain where the dispatcher owns nothing.
     *
     * <p>Scoping obligation 1 to abstractions the producer DECLARES (which is where this port started, and
     * where candor-scan's `dispatch_sites` also sits) leaves a silence one package further out, and it was
     * MEASURED rather than imagined: {@code iface.backend.Backend} · {@code middle.Mid.mid(Backend)} ·
     * {@code effimpl.Crossterm} · an app chained onto all three. {@code middle} owns no abstraction, so it
     * named no member; {@code mid} was ABSENT from middle's report and so was the app's caller. Nothing else
     * covered it either — the untyped-receiver disclosure's fifth conjunct ("the dep demonstrably holds an
     * effectful body with this signature") is FALSE while {@code iface}'s own implementers are all pure, and
     * {@code iface.backend} is chained so the κ ledger is correctly silent.
     *
     * <p>Two arms, because the fix has two halves one package apart: {@code middle} must NAME the member it
     * dispatches on even though it owns neither the abstraction nor any implementer, and the app must then
     * reach {@code effimpl}'s union through it.
     */
    @Test
    void aMiddlePackageDispatchingOverItsOwnDependencysAbstractionNamesTheMemberToo() throws Exception {
        Tree t = Tree.of(
                Map.of("iface/backend/Backend.java", BACKEND),
                Map.of("middle/Mid.java", "package middle;\nimport iface.backend.Backend;\n"
                        + "public class Mid { public static int mid(Backend b) { return b.size(); } }\n"),
                Map.of("effimpl/Crossterm.java", CROSSTERM),
                Map.of("app/App.java", "package app;\nimport iface.backend.Backend;\n"
                        + "public class App {\n"
                        + "  public static int appSize(Backend b) { return middle.Mid.mid(b); }\n"
                        + "  public static int appRun() { return appSize(new effimpl.Crossterm()); }\n}\n"));
        try {
            String iface = t.scan("iface");
            Map<String, Map<String, Object>> mid = byFn(t.scanChained("middle", iface));
            Map<String, Object> midRow = mid.get("middle.Mid.mid");
            assertNotNull(midRow, "the MIDDLE package must name the dependency's member it dispatches on,"
                    + " even though it owns neither the abstraction nor any implementer of it — the key is"
                    + " the dependency's and is already fully qualified, so naming it invents nothing."
                    + " Got " + mid.keySet());
            assertEquals(List.of("iface/backend/Backend.size()I"), midRow.get("dispatchesOn"));
            assertEquals(List.of(), midRow.get("inferred"), "…effect-free: it names, it does not hedge");

            String middle = t.scanChained("middle", iface), eff = t.scanChained("effimpl", iface);
            Map<String, Object> app = byFn(t.scanChained("app", iface, middle, eff)).get("app.App.appSize");
            assertNotNull(app, "and the app reaches the THIRD package's implementer through it; absence here"
                    + " is the purity claim R475 is about, four packages out");
            assertTrue(((List<?>) app.get("inferred")).contains("Net"), "got " + app);
        } finally {
            t.close();
        }
    }

    /**
     * ⟨0.39⟩ A BROAD LOCAL IMPLEMENTER SET DISCLOSES, exactly as it does at an in-scan dispatch site.
     *
     * <p>Contributor 2 of obligation 3 resolves the consumer's OWN implementers of a dependency's
     * abstraction, and it applies the same bounded-CHA bound every in-scan site applies. Past the bound an
     * open hierarchy may hold a body this scan never saw, so the visible union is an open-world guess —
     * §4's rule is that such a dispatch is disclosed indeterminacy, never silence. Dropping the fan-out
     * quietly instead would leave this engine answering `Unknown` in-scan and NOTHING across the chain for
     * the identical program, which is the in-scan/chained drift {@code crossDepJoin}'s own comment records
     * paying for once already.
     *
     * <p>13 implementers: one past {@code Rules.CHA_FANOUT_LIMIT}, which is the only number that matters.
     */
    @Test
    void aBroadLocalImplementerSetDisclosesRatherThanResolving() throws Exception {
        Map<String, String> app = new LinkedHashMap<>();
        StringBuilder run = new StringBuilder();
        for (int i = 0; i < 13; i++) {
            app.put("app/Impl" + i + ".java", "package app;\nimport iface.backend.Backend;\n"
                    + "public class Impl" + i + " implements Backend { public int size() { "
                    + (i == 0 ? NET_SINK : "") + " return " + i + "; } }\n");
            run.append("    n += appSize(new Impl").append(i).append("());\n");
        }
        app.put("app/App.java", "package app;\nimport iface.backend.Backend;\n"
                + "public class App {\n"
                + "  public static int appSize(Backend b) { return iface.Terminal.termSize(b); }\n"
                + "  public static int appRun() { int n = 0;\n" + run + "    return n; }\n}\n");
        Tree t = Tree.of(ifacePkg(true), app);
        try {
            Map<String, Object> row = byFn(t.scanChained("app", t.scan("iface"))).get("app.App.appSize");
            assertNotNull(row, "a broad dispatch must be DISCLOSED, not dropped into silence; got the"
                    + " consumer absent from `functions`, which is a purity claim");
            assertTrue(((List<?>) row.get("inferred")).contains("Unknown"), "got " + row);
            assertTrue(((List<?>) row.get("unknownWhy")).stream()
                            .anyMatch(w -> String.valueOf(w).startsWith("dispatch:iface.backend.Backend.size")),
                    "…and it names the dispatch it could not bound, got " + row.get("unknownWhy"));
        } finally {
            t.close();
        }
    }

    // ---- the thing the FIX must not break --------------------------------------------------------------

    /**
     * A FOREIGN UNION ENTRY IS NOT COVERAGE OF THE PACKAGE IT NAMES — R475's own shape, manufactured by
     * R475's own fix if this is got wrong.
     *
     * <p>{@code depCoveredPkgs} is the single authority that turns a report's SILENCE into a purity claim.
     * Reading {@code effimpl}'s {@code iface/backend/Backend.size()I} as "iface.backend was analyzed" would
     * withdraw {@code invisible: [iface.backend]} from every call into that package — a disclosure deleted
     * by a join, which is exactly what this rung exists to stop. And this is the engine where a coverage
     * grant ALREADY silently certified unmodelled members (SOUNDNESS R492/R493): there must not be a third
     * way to earn one.
     *
     * <p><b>The control is a NEAR-MISS POISON, not an absence.</b> The second arm chains the SAME document
     * with the SAME entry under the SAME key, differing in exactly one field's VALUE —
     * {@code interfaceUnion} dropped — and it must lose the disclosure. Without that arm this test passes on
     * a build that never looks at the marker at all.
     */
    @Test
    void aForeignUnionEntryIsNotCoverageOfThePackageItNames() throws Exception {
        Map<String, String> lib = ifacePkg(true);
        lib.put("iface/backend/Util.java",
                "package iface.backend;\npublic class Util { public static int helper() { return 1; } }\n");
        Tree t = Tree.of(lib, Map.of("effimpl/Crossterm.java", CROSSTERM),
                Map.of("app/App.java", "package app;\n"
                        + "public class App { public static int go() { return iface.backend.Util.helper(); } }\n"));
        try {
            String eff = t.scan("effimpl");                       // `iface` is NOT scanned and NOT chained
            List<String> withMarker = invisibleOf(t.scanChained("app", eff), "app.App.go");
            assertTrue(withMarker.contains("iface.backend"),
                    "a synthetic union entry names a package it does not cover, so the κ ledger must still"
                    + " disclose it. Got invisible=" + withMarker);

            Path poisoned = t.base.resolve("effimpl-poisoned.json");
            String doc = Files.readString(Path.of(eff));
            assertTrue(doc.contains("\"interfaceUnion\": true"),
                    "the poison must differ from the good document in exactly one field's VALUE, and the"
                    + " field has to be there to remove: " + doc);
            Files.writeString(poisoned, doc.replace("\"interfaceUnion\": true,", "")
                    .replace(",\n      \"interfaceUnion\": true", ""));
            List<String> withoutMarker = invisibleOf(t.scanChained("app", poisoned.toString()), "app.App.go");
            assertFalse(withoutMarker.contains("iface.backend"),
                    "THE CONTROL DID NOT DISCRIMINATE: with the `interfaceUnion` marker stripped the entry"
                    + " is an ORDINARY one and its package IS covered, so the disclosure must disappear."
                    + " That it did not means the arm above passes whatever the code does. Got "
                    + withoutMarker);

            // …AND THE SHAPE IS READ FAIL-CLOSED. ⟨0.32⟩ measured `"interfaceUnion": "true"` taking a gate
            // from exit 1 to exit 0 through a Boolean coercion one reader over. Here the permissive default
            // is "ordinary", which GRANTS coverage of a package the report may never have analysed — so
            // anything that is not literally `false` (or absent) must withhold the grant.
            Path corrupt = t.base.resolve("effimpl-corrupt.json");
            Files.writeString(corrupt, doc.replace("\"interfaceUnion\": true", "\"interfaceUnion\": \"true\""));
            assertTrue(invisibleOf(t.scanChained("app", corrupt.toString()), "app.App.go")
                            .contains("iface.backend"),
                    "an UNREADABLE `interfaceUnion` marker must fail CLOSED — withholding coverage only ever"
                    + " adds disclosure, while reading it as an ordinary entry certifies a package nothing"
                    + " analysed");
        } finally {
            t.close();
        }
    }

    // ---- determinism -----------------------------------------------------------------------------------

    /** candor-scan's port of this rung made its entry sort NON-TOTAL — one class implementing the same
     *  member of TWO owners' abstractions emitted two rows with one {@code fn}, and a stable sort then
     *  preserved whatever the hash-map iteration happened to produce, so two runs of one binary over one
     *  tree gave different bytes with an identical row multiset. This engine sorts union entries by HASH,
     *  which is unique by construction, and the union's CONTENT is a pure function of (owner, name, desc) —
     *  so class iteration order cannot reach it either. Measured rather than argued, on the shape that
     *  broke the other engine. */
    @Test
    void theReportIsByteStableWhenOneClassImplementsTwoForeignAbstractions() throws Exception {
        Tree t = Tree.of(Map.of(
                "a/backend/Iface.java", "package a.backend;\npublic interface Iface { int size(); }\n",
                "b/backend/Iface.java", "package b.backend;\npublic interface Iface { int size(); }\n",
                "both/Two.java", "package both;\npublic class Two implements a.backend.Iface, b.backend.Iface {\n"
                        + "  public int size() { " + NET_SINK + " return 0; }\n}\n"));
        try {
            Map<String, Map<String, Object>> r = byHash(t.scan("both"));
            assertNotNull(r.get("a/backend/Iface.size()I"), "got " + r.keySet());
            assertNotNull(r.get("b/backend/Iface.size()I"), "got " + r.keySet());
            assertEquals(t.scanText("both"), t.scanText("both"),
                    "two scans of one tree must produce identical bytes");
        } finally {
            t.close();
        }
    }

    // ---- harness ---------------------------------------------------------------------------------------

    /** One compiled tree split into per-package CLASS DIRECTORIES — the same arrangement conformance
     *  PART 92 renders for this engine, and the only way to express a THREE-package chain: everything is
     *  compiled together so the fixture is guaranteed to build, then the class files are dealt out so each
     *  scan sees exactly one package. */
    private static final class Tree implements AutoCloseable {
        final Path base;
        private final Config saved = Candor.config;

        private Tree(Path base) {
            this.base = base;
        }

        @SafeVarargs
        static Tree of(Map<String, String>... pkgs) throws Exception {
            Map<String, String> all = new LinkedHashMap<>();
            for (Map<String, String> p : pkgs) all.putAll(p);
            Path cls = TestCompiler.compile(all);              // javac over the WHOLE fixture: it compiles
            Path base = cls.getParent();
            try (var s = Files.list(cls)) {
                for (Path top : s.toList()) {
                    if (!Files.isDirectory(top)) continue;
                    Path dir = base.resolve("d_" + top.getFileName());
                    Files.createDirectories(dir);
                    copyTree(top, dir.resolve(top.getFileName()));
                }
            }
            return new Tree(base);
        }

        /** Scan one package directory unchained; returns the report PATH. */
        String scan(String pkg) throws Exception {
            return scanChained(pkg);
        }

        String scanText(String pkg) throws Exception {
            return Files.readString(Path.of(scanChained(pkg)));
        }

        /** Scan one package directory with zero or more dependency reports chained. */
        String scanChained(String pkg, String... deps) throws Exception {
            Path dir = base.resolve("d_" + pkg);
            Path out = base.resolve(pkg + "-" + Math.abs(String.join(",", deps).hashCode()) + ".json");
            Files.deleteIfExists(out);                          // standing-bar item 7: never read a stale arm
            Files.createDirectories(base.resolve(".candor"));
            if (deps.length == 0) {
                Files.deleteIfExists(base.resolve(".candor/config"));
                Candor.config = Config.empty();
            } else {
                Files.writeString(base.resolve(".candor/config"), "deps " + String.join(" ", deps) + "\n");
                Candor.config = Config.forTarget(dir);
            }
            ReportWriter.writeJson(Candor.runScan(dir), out.toString());
            return out.toString();
        }

        @Override
        public void close() {
            Candor.config = saved;
            rm(base);
        }
    }

    private static void copyTree(Path from, Path to) throws Exception {
        Files.createDirectories(to);
        try (var s = Files.list(from)) {
            for (Path p : s.toList()) {
                if (Files.isDirectory(p)) copyTree(p, to.resolve(p.getFileName()));
                else Files.copy(p, to.resolve(p.getFileName()));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> keyed(String reportPath, String key) throws Exception {
        Map<String, Object> root = new Gson().fromJson(Files.readString(Path.of(reportPath)), Map.class);
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
            out.put((String) e.get(key), e);
        return out;
    }

    private static Map<String, Map<String, Object>> byHash(String reportPath) throws Exception {
        return keyed(reportPath, "hash");
    }

    private static Map<String, Map<String, Object>> byFn(String reportPath) throws Exception {
        return keyed(reportPath, "fn");
    }

    @SuppressWarnings("unchecked")
    private static List<String> invisibleOf(String reportPath, String fn) throws Exception {
        Map<String, Object> e = byFn(reportPath).get(fn);
        if (e == null) return new ArrayList<>();
        return (List<String>) e.getOrDefault("invisible", new ArrayList<String>());
    }
}
