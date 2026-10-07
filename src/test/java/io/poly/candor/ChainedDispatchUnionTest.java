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
            // SOUNDNESS R533 changed this line on purpose. `iface` here declares `Backend` and NOTHING
            // implements it in either package `middle` can see — the zero-implementor shape (PART 92 c9), not
            // an all-pure one (the javadoc's "all pure" predates the fixture; with a pure implementor `iface`
            // now publishes a pure-only union, R919, and this row would stay `[]`). So the row names AND
            // hedges; the THIRD package's Net still reaches the app below, which is what this test is for.
            assertEquals(List.of("Unknown"), midRow.get("inferred"), "…it names, and (R533) it hedges");

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

    /** SOUNDNESS R919 — the PRODUCER half of R533. A pure-only implementer set is published as an
     *  {@code interfaceUnion} entry with {@code inferred: []}, so a consumer can tell it from an abstraction
     *  NOTHING implements, which still publishes nothing. One variable: the pure implementer's presence. */
    @Test
    void aPureOnlyUnionIsPublishedAndAZeroImplementorAbstractionIsNot() throws Exception {
        Tree withImpl = Tree.of(Map.of("iface/backend/Backend.java", BACKEND, "iface/TestBackend.java", TEST_BACKEND));
        Tree bare = Tree.of(Map.of("iface/backend/Backend.java", BACKEND));
        try {
            Map<String, Object> u = byFn(withImpl.scan("iface")).get("iface.backend.Backend.size");
            assertNotNull(u, "a pure-only union must be PUBLISHED, not dropped (R919)");
            assertEquals(Boolean.TRUE, u.get("interfaceUnion"), "got " + u);
            assertEquals(List.of(), u.get("inferred"), "…and it charges nothing, got " + u);
            assertNull(byFn(bare.scan("iface")).get("iface.backend.Backend.size"),
                    "a zero-implementor abstraction publishes NOTHING — that absence is what R533 hedges");
        } finally { withImpl.close(); bare.close(); }
    }

    /** SOUNDNESS R764's shape, ported to java BEFORE it could bite: package {@code b} is chained and PURELY
     *  implements an abstraction owned by package {@code a}, which is NOT chained. {@code b} now publishes
     *  {@code a/Svc.run()V {inferred: []}} under {@code a}'s key (obligation 2). If that entry were a join
     *  HIT it could short-circuit the owner's ledger and delete {@code invisible: [a]}. It must not. */
    @Test
    void aForeignPureOnlyUnionDoesNotDeleteTheUnchainedOwnersInvisible() throws Exception {
        Tree t = Tree.of(
                Map.of("a/Svc.java", "package a;\npublic interface Svc { void run(); }\n"),
                Map.of("b/PureSvc.java", "package b;\npublic class PureSvc implements a.Svc { public void run() { } }\n"),
                Map.of("app/App.java", "package app;\npublic class App { public static void go(a.Svc s) { s.run(); } }\n"));
        try {
            String b = t.scan("b");
            assertTrue(Files.readString(Path.of(b)).contains("a/Svc.run()V"),
                    "precondition: b publishes the pure union under a's key, else this guard measures nothing");
            Map<String, Object> row = byFn(t.scanChained("app", b)).get("app.App.go");
            assertNotNull(row, "the dispatching row must be present, got nothing");
            assertTrue(((List<?>) row.getOrDefault("invisible", List.of())).contains("a"),
                    "the unchained owner's invisible disclosure must survive a foreign pure-only union, got " + row);
        } finally { t.close(); }
    }

    // ---- SOUNDNESS R917: the abstract-CLASS twin of R533 ------------------------------------------------

    private static final String FS_SINK = "try { new java.io.FileOutputStream(\"/tmp/r917\").close(); } catch (Exception e) {}";

    /** The producer half. A public abstract class's abstract member that NOTHING implements publishes a union
     *  entry carrying {@code Unknown[dispatch:]} — the in-scan answer for the same dispatch. The scope bounds
     *  are pinned with it: a package-private class, a concrete member, and an all-pure hierarchy publish no
     *  {@code Unknown} (the last is R919's empty union, unchanged). */
    @Test
    void r917AZeroImplementorAbstractClassMemberPublishesItsUnknown() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("lib/AbsH.java", "package lib;\npublic abstract class AbsH { public abstract int handle();"
                + " public int tag() { return 1; } }\n");
        lib.put("lib/Hidden.java", "package lib;\nabstract class Hidden { public abstract int handle(); }\n");
        lib.put("lib/AbsP.java", "package lib;\npublic abstract class AbsP { public abstract int handle(); }\n");
        lib.put("lib/PureP.java", "package lib;\npublic class PureP extends AbsP { public int handle() { return 7; } }\n");
        Tree t = Tree.of(lib);
        try {
            Map<String, Map<String, Object>> r = byHash(t.scan("lib"));
            Map<String, Object> u = r.get("lib/AbsH.handle()I");
            assertNotNull(u, "R917: the zero-implementer abstract member must publish; got " + r.keySet());
            assertEquals(List.of("Unknown"), u.get("inferred"), "got " + u);
            assertEquals(List.of("dispatch:lib.AbsH.handle"), u.get("unknownWhy"), "got " + u);
            assertEquals(Boolean.TRUE, u.get("interfaceUnion"), "a union entry, never a unit; got " + u);
            assertNull(r.get("lib/AbsH.tag()I"), "a CONCRETE pure member's absence is a true purity claim");
            assertNull(r.get("lib/Hidden.handle()I"), "a package-private class cannot be subclassed abroad");
            assertEquals(List.of(), r.get("lib/AbsP.handle()I").get("inferred"), "R919's all-pure union stays empty");
        } finally {
            t.close();
        }
    }

    /** The R917 RESIDUAL, closed once R682 made both routes gate the same entries. {@code AbsC} declares a field of
     *  an effect-performing type, so its abstract {@code handle} is kept as a REAL bodiless entry, and that entry
     *  used to publish {@code inferred: []} — a consumer join HIT reading purity on a key nothing can answer
     *  (executed: a plugin subclass writes a file, `deny Unknown` 0). The zero-implementer {@code Unknown} is now
     *  merged into it, on the producer's report AND its scan verdict. */
    @Test
    void r917AZeroImplementorMemberWithARealBodilessEntryDisclosesToo() throws Exception {
        Tree t = Tree.of(
                Map.of("lib/Eff.java", "package lib;\npublic class Eff { public void w() { " + FS_SINK + " } }\n",
                        "lib/AbsC.java", "package lib;\npublic abstract class AbsC { protected Eff e = new Eff(); public abstract int handle(); }\n"),
                Map.of("app/A.java", "package app;\npublic class A { public static int goClaimed(lib.AbsC h) { return h.handle(); } }\n"));
        try {
            String lib = t.scan("lib");
            Map<String, Object> real = byHash(lib).get("lib/AbsC.handle()I");
            assertNotNull(real, "the bodiless entry is kept (its class declares a capability)");
            assertNull(real.get("interfaceUnion"), "…as a REAL entry, which is what made this the residual");
            assertEquals(List.of("Unknown"), real.get("inferred"), "got " + real);
            Map<String, Object> app = byFn(t.scanChained("app", lib)).get("app.A.goClaimed");
            assertNotNull(app, "the consumer's caller must not be ABSENT");
            assertTrue(((List<?>) app.get("inferred")).contains("Unknown"), "got " + app);
        } finally {
            t.close();
        }
    }

    /** The consumer half, with its three controls. {@code goAbs} is the defect: zero implementors, ABSENT before.
     *  {@code goLocal}: the consumer's OWN pure subclass answers the dispatch, so — as in the one-tree scan, and
     *  as conjunct 4 does for an interface — no hedge. {@code goLocalFs}: an effectful own subclass carries its
     *  effect and no hedge. {@code goBroad}: thirteen dependency subclasses (a BROAD union, also
     *  {@code Unknown}-only) plus an own subclass KEEPS the {@code Unknown} — the case the sidecar test exists
     *  to tell apart; dropping it there would delete the disclosure for the unseen bodies. */
    @Test
    void r917AChainedConsumerDisclosesAZeroImplementorAbstractClassAndOnlyThat() throws Exception {
        Map<String, String> lib = new LinkedHashMap<>();
        lib.put("lib/AbsH.java", "package lib;\npublic abstract class AbsH { public abstract int handle(); }\n");
        lib.put("lib/AbsL.java", "package lib;\npublic abstract class AbsL { public abstract int handle(); }\n");
        lib.put("lib/AbsF.java", "package lib;\npublic abstract class AbsF { public abstract int handle(); }\n");
        lib.put("lib/AbsB.java", "package lib;\npublic abstract class AbsB { public abstract int handle(); }\n");
        for (int i = 0; i < 13; i++)
            lib.put("lib/B" + i + ".java", "package lib;\npublic class B" + i + " extends AbsB { public int handle() { return "
                    + i + "; } }\n");
        Map<String, String> app = new LinkedHashMap<>();
        app.put("app/LocL.java", "package app;\npublic class LocL extends lib.AbsL { public int handle() { return 2; } }\n");
        app.put("app/LocF.java", "package app;\npublic class LocF extends lib.AbsF { public int handle() { " + FS_SINK
                + " return 2; } }\n");
        app.put("app/LocB.java", "package app;\npublic class LocB extends lib.AbsB { public int handle() { return 2; } }\n");
        app.put("app/A.java", "package app;\nimport lib.*;\npublic class A {\n"
                + "  public static int goAbs(AbsH h) { return h.handle(); }\n"
                + "  public static int callerOfGoAbs(AbsH h) { return goAbs(h); }\n"
                + "  public static int goLocal(AbsL h) { return h.handle(); }\n"
                + "  public static int goLocalFs(AbsF h) { return h.handle(); }\n"
                + "  public static int goBroad(AbsB h) { return h.handle(); }\n}\n");
        Tree t = Tree.of(lib, app);
        try {
            // Without the hierarchy sidecar the consumer cannot tell the zero-implementer union from a broad
            // one, so it keeps the hedge everywhere — over-disclosure, the safe direction, pinned as such.
            Map<String, Map<String, Object>> bare = byFn(t.scanChained("app", t.scan("lib")));
            assertTrue(((List<?>) bare.get("app.A.goLocal").get("inferred")).contains("Unknown"),
                    "no sidecar: the hedge is kept; got " + bare.get("app.A.goLocal"));
            Map<String, Map<String, Object>> r = byFn(t.scanChained("app", t.scanWithSidecars("lib")));
            assertNotNull(r.get("app.A.goAbs"), "R917: absence IS the purity claim; got " + r.keySet());
            assertTrue(((List<?>) r.get("app.A.goAbs").get("inferred")).contains("Unknown"), "got " + r.get("app.A.goAbs"));
            assertTrue(((List<?>) r.get("app.A.callerOfGoAbs").get("inferred")).contains("Unknown"),
                    "the caller inherits it; got " + r.get("app.A.callerOfGoAbs"));
            Map<String, Object> loc = r.get("app.A.goLocal");
            assertTrue(loc == null || ((List<?>) loc.get("inferred")).isEmpty(),
                    "the consumer's own pure subclass answers — no hedge; got " + loc);
            assertEquals(List.of("Fs"), r.get("app.A.goLocalFs").get("inferred"),
                    "the own effectful subclass carries its effect and no hedge; got " + r.get("app.A.goLocalFs"));
            assertTrue(((List<?>) r.get("app.A.goBroad").get("inferred")).contains("Unknown"),
                    "a BROAD dependency union keeps its Unknown beside an own subclass; got " + r.get("app.A.goBroad"));
        } finally {
            t.close();
        }
    }

    /** The obligation-1 half, four packages out: the ratatui toggle at an abstract CLASS. {@code iface}'s only
     *  implementer of {@code AbsP} is pure (so it publishes R919's pure-only union), {@code middle} dispatches on
     *  it, the effectful subclass is in a THIRD package. Before: {@code middle.Mid.mid} absent with no
     *  {@code dispatchesOn}, and the app's caller ABSENT — `deny Fs` 0 over an executed write. */
    @Test
    void r917AMiddlePackageNamesADependencyAbstractClassMember() throws Exception {
        Tree t = Tree.of(
                Map.of("iface/AbsP.java", "package iface;\npublic abstract class AbsP { public abstract int handle(); }\n",
                        "iface/PureP.java", "package iface;\npublic class PureP extends AbsP { public int handle() { return 7; } }\n"),
                Map.of("middle/Mid.java", "package middle;\npublic class Mid { public static int mid(iface.AbsP p) { return p.handle(); } }\n"),
                Map.of("effimpl/Eff.java", "package effimpl;\npublic class Eff extends iface.AbsP { public int handle() { "
                        + FS_SINK + " return 1; } }\n"),
                Map.of("app/App.java", "package app;\npublic class App {\n"
                        + "  public static int useP(iface.AbsP p) { return middle.Mid.mid(p); }\n"
                        + "  public static int run() { return useP(new effimpl.Eff()); }\n}\n"));
        try {
            String iface = t.scan("iface");
            Map<String, Object> mid = byFn(t.scanChained("middle", iface)).get("middle.Mid.mid");
            assertNotNull(mid, "the middle package must name the member it dispatches on");
            assertEquals(List.of("iface/AbsP.handle()I"), mid.get("dispatchesOn"), "got " + mid);
            assertEquals(List.of(), mid.get("inferred"), "…and charge nothing: the visible implementer is pure");
            String middle = t.scanChained("middle", iface), eff = t.scanChained("effimpl", iface);
            Map<String, Object> app = byFn(t.scanChained("app", iface, middle, eff)).get("app.App.useP");
            assertNotNull(app, "R917: the third package's subclass must reach the app; absence is the R475 claim");
            assertEquals(List.of("Fs"), app.get("inferred"), "got " + app);
        } finally {
            t.close();
        }
    }

    // ---- SOUNDNESS R601: a reassignable field whose member cannot be named ----------------------------

    /** {@code public static Consumer<String> hook = s -> {}; fire(x){ hook.accept(x); }}: the binding resolves
     *  {@code fire} to the pure default, the field is externally reassignable (R595), and the member is
     *  κ-covered so it cannot be NAMED. Before: no row for {@code fire} and none for a consumer's caller of it;
     *  a consumer that reassigned {@code hook} to an {@code Fs} lambda read its caller ABSENT. Now the producer
     *  discloses {@code Unknown[callback:]} and the consumer inherits it. Controls: a PRIVATE and a FINAL field
     *  of the same type stay pure (their write set IS the scan's), and a field typed by a PUBLIC project
     *  interface keeps R595's answer — the member is named, so no hedge is added beside it. */
    @Test
    void r601AReassignableFieldWhoseMemberCannotBeNamedDiscloses() throws Exception {
        Tree t = Tree.of(
                Map.of("lib3/Jdk.java", "package lib3;\nimport java.util.function.Consumer;\npublic class Jdk {\n"
                        + "  public static Consumer<String> hook = s -> {};\n"
                        + "  private static Consumer<String> priv = s -> {};\n"
                        + "  public static final Consumer<String> fin = s -> {};\n"
                        + "  static Consumer<String> pkg = s -> {};\n"
                        + "  protected static Consumer<String> prot = s -> {};\n"
                        + "  public static Hook named = s -> {};\n"
                        + "  public static void fire(String x) { hook.accept(x); }\n"
                        + "  public static void firePriv(String x) { priv.accept(x); }\n"
                        + "  public static void fireFin(String x) { fin.accept(x); }\n"
                        + "  public static void firePkg(String x) { pkg.accept(x); }\n"
                        + "  public static void fireProt(String x) { prot.accept(x); }\n"
                        + "  public static void fireNamed(String x) { named.on(x); }\n}\n",
                        "lib3/Hook.java", "package lib3;\npublic interface Hook { void on(String s); }\n"),
                Map.of("app/C.java", "package app;\npublic class C {\n"
                        + "  public static void run() { lib3.Jdk.fire(\"/tmp/r601\"); }\n"
                        + "  public static void main(String[] a) { lib3.Jdk.hook = s -> { " + FS_SINK + " }; run(); }\n}\n"));
        try {
            String lib = t.scan("lib3");
            Map<String, Map<String, Object>> r = byFn(lib);
            assertNotNull(r.get("lib3.Jdk.fire"), "R601: the producer must not read silent; got " + r.keySet());
            assertEquals(List.of("Unknown"), r.get("lib3.Jdk.fire").get("inferred"), "got " + r.get("lib3.Jdk.fire"));
            assertEquals(List.of("callback:java.util.function.Consumer.accept"), r.get("lib3.Jdk.fire").get("unknownWhy"));
            assertNull(r.get("lib3.Jdk.firePriv"), "a private field's write set is the scan's — pure");
            assertNull(r.get("lib3.Jdk.fireFin"), "a final field's write set is the scan's — pure");
            assertNull(r.get("lib3.Jdk.firePkg"), "a package-private field: no consumer in another package can write it");
            // SOUNDNESS R965 — INVERTED, not deleted. This line pinned "a PROTECTED field stays unhedged" while
            // PART 87's inherited-field control required it; that left a chained consumer's subclass able to
            // reassign the field silently (executed). The control was amended alongside this change; see
            // Cha#foreignReassignableField and r965AProtectedFieldAConsumerSubclassReassignsDiscloses below.
            assertEquals(List.of("callback:java.util.function.Consumer.accept"),
                    r.getOrDefault("lib3.Jdk.fireProt", Map.of()).get("unknownWhy"),
                    "R965: a PROTECTED field of a subclassable class is writable from another package — hedged");
            Map<String, Object> named = r.get("lib3.Jdk.fireNamed");
            assertNotNull(named, "R595: a nameable member is named");
            assertEquals(List.of("lib3/Hook.on(Ljava/lang/String;)V"), named.get("dispatchesOn"), "got " + named);
            assertEquals(List.of(), named.get("inferred"), "…and only named: no hedge beside it; got " + named);
            Map<String, Object> run = byFn(t.scanChained("app", lib)).get("app.C.run");
            assertNotNull(run, "R601: the consumer's caller must not be ABSENT");
            assertTrue(((List<?>) run.get("inferred")).contains("Unknown"), "got " + run);
        } finally {
            t.close();
        }
    }

    /** SOUNDNESS R965 — R601's PROTECTED half. A dependency's {@code protected Runnable task = () -> {}} is
     *  dispatched by its own {@code fire()}; a CHAINED consumer's subclass in another package reassigns it to an
     *  effectful lambda. Before: {@code fire} published nothing and the consumer's callers read ABSENT (executed
     *  in the lane fixture: {@code deny Unknown} exit 0 over a written file). Now the producer discloses
     *  {@code Unknown[callback:java.lang.Runnable.run]} and the consumer's callers inherit it — through a
     *  {@code Base} receiver and through the inherited {@code Sub.fire}. Bare {@code Fs} is NOT claimed: naming
     *  the consumer's lambda needs the field-keyed join. Controls: a protected field of a FINAL class (no
     *  subclass outside the package can exist) stays unhedged, and the in-scan binding still resolves its edge
     *  (an effectful default still charges {@code Fs} — the hedge is added beside it, never in its place). */
    @Test
    void r965AProtectedFieldAConsumerSubclassReassignsDiscloses() throws Exception {
        Tree t = Tree.of(
                Map.of("lib5/Base.java", "package lib5;\npublic class Base {\n"
                                + "  protected Runnable task = () -> {};\n"
                                + "  public void fire() { task.run(); }\n}\n",
                        "lib5/Sealed.java", "package lib5;\npublic final class Sealed {\n"
                                + "  protected Runnable task = () -> {};\n"
                                + "  public void fire() { task.run(); }\n}\n",
                        "lib5/Loud.java", "package lib5;\npublic class Loud {\n"
                                + "  protected Runnable task = () -> { " + FS_SINK + " };\n"
                                + "  public void fire() { task.run(); }\n}\n"),
                Map.of("app/Sub.java", "package app;\npublic class Sub extends lib5.Base {\n"
                                + "  public void arm() { task = () -> { " + FS_SINK + " }; }\n}\n",
                        "app/C.java", "package app;\npublic class C {\n"
                                + "  public static void run(lib5.Base b) { b.fire(); }\n"
                                + "  public static void runSub(Sub s) { s.fire(); }\n}\n"));
        try {
            String lib = t.scan("lib5");
            Map<String, Map<String, Object>> r = byFn(lib);
            Map<String, Object> fire = r.get("lib5.Base.fire");
            assertNotNull(fire, "R965: the producer must not read silent; got " + r.keySet());
            assertEquals(List.of("Unknown"), fire.get("inferred"), "got " + fire);
            assertEquals(List.of("callback:java.lang.Runnable.run"), fire.get("unknownWhy"));
            assertNull(r.get("lib5.Sealed.fire"), "a protected field of a FINAL class has no foreign writer — pure");
            Map<String, Object> loud = r.get("lib5.Loud.fire");
            assertNotNull(loud, "the bound effectful default still resolves");
            assertTrue(((List<?>) loud.get("inferred")).contains("Fs"), "edge kept, hedge beside it: " + loud);
            Map<String, Map<String, Object>> app = byFn(t.scanChained("app", lib));
            for (String fn : List.of("app.C.run", "app.C.runSub")) {
                Map<String, Object> row = app.get(fn);
                assertNotNull(row, fn + " ABSENT — the purity claim R965 is about; got " + app.keySet());
                assertTrue(((List<?>) row.get("inferred")).contains("Unknown"), fn + " got " + row);
                assertFalse(((List<?>) row.get("inferred")).contains("Fs"),
                        fn + ": Fs needs the field-keyed join and must not be minted here; got " + row);
            }
        } finally {
            t.close();
        }
    }

    // ---- harness ---------------------------------------------------------------------------------------

    /** One compiled tree split into per-package CLASS DIRECTORIES — the same arrangement conformance
     *  PART 92 renders for this engine, and the only way to express a THREE-package chain: everything is
     *  compiled together so the fixture is guaranteed to build, then the class files are dealt out so each
     *  scan sees exactly one package. */
    /**
     * SOUNDNESS R939 — THE METHOD-REFERENCE SPELLING OF OBLIGATION 1. {@code ns.forEach(b::size)} and
     * {@code List.of(b).forEach(Backend::size)} dispatch on {@code Backend.size} exactly as {@code b.size()}
     * does, and named nothing: the middle row was ABSENT and the app's caller read pure over a real effect
     * (executed in the lane fixture, {@code deny Fs app.Main.go} exit 0 over a written file). Three arms per
     * abstraction owner — FOREIGN (the middle package dispatches over its dependency's interface) and PROJECT
     * (over its own) — and in each the dependency holds ONE PURE implementer, the toggle's silent side.
     *
     * <p>Controls: a STATIC method reference on the same public interface and a reference to a CONCRETE
     * class's method dispatch on nothing and must name nothing.
     */
    @Test
    void aMethodReferenceNamesTheMemberItDispatchesOn() throws Exception {
        String midSrc = "package middle;\nimport iface.backend.Backend;\n"
                + "public class Mid {\n"
                + "  public static void boundRef(Backend b) { java.util.function.IntSupplier s = b::size; s.getAsInt(); }\n"
                + "  public static void unboundRef(Backend b) { java.util.List.of(b).forEach(Backend::size); }\n"
                + "  public static void own(Doer d) { java.util.List.of(d).forEach(Doer::go); }\n"
                + "  public static void staticRef() { Runnable r = Doer::util; r.run(); }\n"
                + "  public static void concreteRef(Plain p) { Runnable r = p::run; r.run(); }\n}\n";
        Tree t = Tree.of(
                Map.of("iface/backend/Backend.java", BACKEND, "iface/TestBackend.java", TEST_BACKEND),
                Map.of("middle/Mid.java", midSrc,
                        "middle/Doer.java", "package middle;\npublic interface Doer { void go(); static void util() { } }\n",
                        "middle/Quiet.java", "package middle;\npublic class Quiet implements Doer { public void go() { } }\n",
                        "middle/Plain.java", "package middle;\npublic class Plain { public void run() { } }\n"),
                Map.of("effimpl/Crossterm.java", CROSSTERM),
                Map.of("app/App.java", "package app;\nimport iface.backend.Backend;\n"
                        + "public class App {\n"
                        + "  public static void viaBoundRef() { middle.Mid.boundRef(new effimpl.Crossterm()); }\n"
                        + "  public static void viaUnboundRef() { middle.Mid.unboundRef(new effimpl.Crossterm()); }\n"
                        + "  public static void viaOwn() { middle.Mid.own(new App.NetDoer()); }\n"
                        + "  static class NetDoer implements middle.Doer { public void go() { " + NET_SINK + " } }\n}\n"));
        try {
            String iface = t.scan("iface");
            String middle = t.scanChained("middle", iface);
            Map<String, Map<String, Object>> mid = byFn(middle);
            assertEquals(List.of("iface/backend/Backend.size()I"),
                    mid.getOrDefault("middle.Mid.boundRef", Map.of()).get("dispatchesOn"),
                    "a BOUND reference to a dependency's abstraction names it, as the call spelling does. Got " + mid.keySet());
            assertEquals(List.of("iface/backend/Backend.size()I"),
                    mid.getOrDefault("middle.Mid.unboundRef", Map.of()).get("dispatchesOn"), "…and an UNBOUND one");
            assertEquals(List.of("middle/Doer.go()V"),
                    mid.getOrDefault("middle.Mid.own", Map.of()).get("dispatchesOn"), "…and over its OWN public abstraction");
            assertNull(mid.getOrDefault("middle.Mid.staticRef", Map.of()).get("dispatchesOn"),
                    "a STATIC interface method reference dispatches on nothing");
            assertNull(mid.getOrDefault("middle.Mid.concreteRef", Map.of()).get("dispatchesOn"),
                    "a reference to a CONCRETE class's method dispatches on nothing");

            String eff = t.scanChained("effimpl", iface);
            Map<String, Map<String, Object>> app = byFn(t.scanChained("app", iface, middle, eff));
            for (String fn : List.of("app.App.viaBoundRef", "app.App.viaUnboundRef", "app.App.viaOwn")) {
                Map<String, Object> r = app.get(fn);
                assertNotNull(r, fn + " ABSENT — the purity claim R939 is about. Got " + app.keySet());
                assertTrue(((List<?>) r.get("inferred")).contains("Net"), fn + " got " + r);
            }
        } finally {
            t.close();
        }
    }

    /**
     * SOUNDNESS R939 — the DEFAULT-METHOD shape the corpus A/B found (langchain4j
     * {@code DocumentTransformer.transformAll}, telegrambots {@code LongPollingBot.onUpdatesReceived}): an
     * interface's default method maps {@code this::transform} over its argument. The dependency published only a
     * pure-only {@code interfaceUnion} entry for {@code transformAll} and no {@code dispatchesOn}, so a consumer
     * supplying an effectful {@code transform} read its caller ABSENT (executed: {@code deny Fs} exit 0 over a
     * written file). Now the default body is a real row naming {@code transform}, and the caller carries it.
     */
    @Test
    void aDefaultMethodMappingThisMethodReferenceNamesTheMember() throws Exception {
        Tree t = Tree.of(
                Map.of("dt/T.java", "package dt;\nimport java.util.*; import java.util.stream.*;\n"
                                + "public interface T { String transform(String s);\n"
                                + "  default List<String> transformAll(List<String> xs) {"
                                + " return xs.stream().map(this::transform).collect(Collectors.toList()); } }\n",
                        "dt/Up.java", "package dt;\npublic class Up implements T { public String transform(String s) { return s; } }\n"),
                Map.of("app/App.java", "package app;\n"
                        + "public class App {\n"
                        + "  public static void direct(java.util.List<String> xs) { new NetT().transformAll(xs); }\n"
                        + "  static class NetT implements dt.T { public String transform(String s) { " + NET_SINK + " return s; } }\n}\n"));
        try {
            String dt = t.scan("dt");
            assertEquals(List.of("dt/T.transform(Ljava/lang/String;)Ljava/lang/String;"),
                    byFn(dt).getOrDefault("dt.T.transformAll", Map.of()).get("dispatchesOn"), "got " + byFn(dt).keySet());
            Map<String, Object> r = byFn(t.scanChained("app", dt)).get("app.App.direct");
            assertNotNull(r, "ABSENT — the purity claim R939 is about");
            assertTrue(((List<?>) r.get("inferred")).contains("Net"), "got " + r);
        } finally {
            t.close();
        }
    }

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

        /** As {@link #scan} but through the CLI's {@code writeReport}, so the §2.2 sidecars are written beside the
         *  report — R917's consumer reads the HIERARCHY sidecar to tell a zero-implementer union from a broad one. */
        String scanWithSidecars(String pkg) throws Exception {
            Path dir = base.resolve("d_" + pkg);
            Path out = base.resolve(pkg + "-sidecars.json");
            Files.deleteIfExists(out);
            Files.createDirectories(base.resolve(".candor"));
            Files.deleteIfExists(base.resolve(".candor/config"));
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(dir), out.toString(), null);
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
