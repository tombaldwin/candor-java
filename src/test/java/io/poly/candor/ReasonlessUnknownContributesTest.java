package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import io.poly.candor.model.EffectSet;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * §6.2 ⟨0.24⟩ — A REASONLESS {@code Unknown} <b>CONTRIBUTES</b> {@code unresolved}; IT DOES NOT DEFAULT TO IT.
 *
 * <p>The old rule keyed on ABSENCE: if a function's computed reason-class set came out EMPTY, substitute
 * {@code {unresolved}}. Emptiness is not upward-closed, so acquiring a SECOND, classifiable reason
 * <b>removed</b> the default. Measured on this engine, under {@code deny Net Unknown[unresolved]}:
 *
 * <pre>
 *   row 1  one()    calls one reasonless dep unit    {}          -> defaulted to {unresolved}  REJECTED
 *   row 2  two()    reflects                         {reflect}                                 passes
 *   row 3  three()  does BOTH                        {reflect}                                 PASSES   &lt;- defect
 * </pre>
 *
 * <p>Row 3 is strictly worse-known than row 1 and passed where row 1 was rejected: adding a call turned a
 * red verdict green. That is the silent relaxation {@code reference/policy_model.py} Lemma 2 forbids
 * ({@code Reject} is upward-closed). Rows 2 and 3 have the SAME class set, which is why no rewriting of
 * the emptiness test could separate them — the missing information is not in the class set at all.
 *
 * <p><b>The repair is PRODUCER-side, not matcher-side.</b> A reasonless {@code Unknown} is not
 * representable in the formal model — Def 6 makes the reason set the CARRIER of the {@code Unknown}, so
 * "Unknown present, no reasons" is the same signature as "no Unknown". So the state is made UNREACHABLE:
 * a dependency entry that classified nothing gets an actual reason recorded at the point the
 * {@code Unknown} is created ({@code dep:<hash>} / {@code dep-stale:<pkg>}, both projecting to
 * {@code unresolved}), per dependency ENTRY. A caller of a reasonless entry and a reasoned one then
 * accumulates {@code {unresolved, reflect}} with no join-time special case. candor-swift arrived at this
 * shape independently; SPEC §6.2 ⟨0.24⟩ now names it as the one to copy.
 *
 * <p><b>Where java could reach it.</b> Every in-project {@code Unknown} this engine raises already records
 * an {@code unknownWhy} beside it, so the hole is entirely at the DEPENDENCY boundary: a §2.1 STALE report
 * (effects downgraded to {@code Unknown}, {@code fn}/{@code calls}/{@code unknownWhy} never even parsed) and
 * any entry whose {@code Unknown} neither its own tags nor its published {@code calls} chain can account
 * for. Measured on a real target (candor-java's own 3k-method tree, asm+gson chained): 0 empty class sets
 * with fresh reports, <b>78 of 145</b> {@code Unknown}-bearing functions with the same reports staled.
 *
 * <p>Every test here asserts BOTH directions. {@link #aClassifiableUnknownStillDoesNotMatchUnresolved} is
 * the control that separates this fix from "contribute {@code unresolved} unconditionally", which would
 * make every narrowed {@code [class]} gate match everything and delete the feature.
 */
class ReasonlessUnknownContributesTest {

    /** The dependency. {@code io()} is effectful, so §2 rule 3 keeps it in the report and the app's call
     *  into it forms a cross-jar join. Under a STALE report its effect is downgraded to {@code Unknown}
     *  with nothing recorded about why — the reasonless {@code Unknown} this class is about. */
    private static final Map<String, String> LIB = Map.of(
        "lib/Thing.java", "package lib;\nimport java.io.*;\npublic class Thing {\n"
            + "  public void io() { try { new FileInputStream(\"/etc/hosts\").close(); } catch (Exception e) {} }\n}\n");

    /** The three rows plus the transitive control. {@code two()} reflects (a {@code reflect:} reason);
     *  {@code three()} does BOTH; {@code four()} only CALLS {@code two()}, so its {@code Unknown} is fully
     *  accounted for by an inherited, classifiable reason and nothing reasonless. */
    private static final Map<String, String> APP = Map.of(
        "app/A.java", "package app;\npublic class A {\n"
            + "  public void one() { new lib.Thing().io(); }\n"
            + "  public void two() throws Exception { Class.forName(\"x.Y\").getMethod(\"m\").invoke(null); }\n"
            + "  public void three() throws Exception { new lib.Thing().io(); two(); }\n"
            + "  public void four() throws Exception { two(); }\n}\n");

    /** The ACCOUNTED-FOR dependency, and the reason it is a separate fixture: its {@code Unknown} is real
     *  and CHAINED, so an unconditional "an Unknown-bearing dep entry contributes unresolved" rule fires on
     *  it — while the correct rule does not, because the report says exactly where the reason lives.
     *  {@code Deep.go} publishes a {@code reflect:} tag; {@code Shallow.call} publishes NONE (⟨0.19⟩:
     *  {@code unknownWhy} is direct-by-contract) and is accounted for only through its {@code calls} edge. */
    private static final Map<String, String> LIB_REFLECT = Map.of(
        "lib/Deep.java", "package lib;\npublic class Deep {\n"
            + "  public void go() throws Exception { Class.forName(\"x.Y\").getMethod(\"m\").invoke(null); }\n}\n",
        "lib/Shallow.java", "package lib;\npublic class Shallow {\n"
            + "  public void call() throws Exception { new Deep().go(); }\n}\n");

    private static final Map<String, String> APP_REFLECT = Map.of(
        "app/B.java", "package app;\npublic class B {\n"
            + "  public void direct() throws Exception { new lib.Deep().go(); }\n"
            + "  public void viaShallow() throws Exception { new lib.Shallow().call(); }\n}\n");

    private record Scan(Map<String, EffectSet> inferred, Path base) {}

    private static Scan scanChained(boolean stale) throws Exception {
        return scanChained(stale, LIB, APP);
    }

    /** Scan {@code app} with {@code lib}'s own report chained, staled if asked. The STALE arm differs from
     *  the fresh one in the producing build id and NOTHING else (standing-bar item 7d). */
    private static Scan scanChained(boolean stale, Map<String, String> lib, Map<String, String> app)
            throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Path depReport = base.resolve("dep.json");
            Files.deleteIfExists(depReport);            // standing-bar item 7: never read a stale artifact
            Candor.config = Config.empty();
            ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
            if (stale) {
                String json = Files.readString(depReport);
                String own = ReportWriter.provenance()[0];
                assertTrue(json.contains(own), "the fresh dep report must carry THIS build's id, else the "
                        + "arms differ in nothing: " + json.substring(0, Math.min(300, json.length())));
                Files.writeString(depReport, json.replace(own, own + "-NOT-THIS-BUILD"));
            }
            Files.createDirectories(base.resolve(".candor"));
            Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
            Candor.config = Config.forTarget(appDir);
            return new Scan(Candor.runScan(appDir), base);
        } finally {
            Candor.config = saved;
        }
    }

    /** Run ONE rule against an already-scanned context and return the functions it flagged, read from the
     *  STRUCTURAL --gate-json capture rather than parsed console text. {@code parsePolicy} APPENDS, so the
     *  rule clear is load-bearing (standing-bar item 7d), and so is the violation clear. */
    private static java.util.List<String> flagged(Map<String, EffectSet> inferred, Path dir, String rule)
            throws Exception {
        AnalysisState.ctx().denyRules.clear();
        AnalysisState.ctx().allowRules.clear();
        AnalysisState.ctx().forbidRules.clear();
        Path p = dir.resolve(rule.replaceAll("[^a-zA-Z]", "") + ".policy");
        Files.writeString(p, rule + "\n");
        java.io.PrintStream savedOut = Candor.diagOut;
        boolean savedCap = Candor.gateCapture;
        int v;
        try {
            Candor.diagOut = new java.io.PrintStream(java.io.OutputStream.nullOutputStream(), true,
                    java.nio.charset.StandardCharsets.UTF_8);
            Candor.gateCapture = true;
            Candor.gateViolations.clear();
            v = Policy.checkPolicy(inferred, p.toString());
        } finally {
            Candor.diagOut = savedOut;
            Candor.gateCapture = savedCap;
        }
        java.util.List<String> out = new java.util.ArrayList<>();
        for (var m : Candor.gateViolations)
            if ("AS-EFF-006".equals(m.get("rule"))) out.add((String) m.get("fn"));
        assertEquals(v, out.size(), "the fixture must produce only AS-EFF-006 violations: "
                + Candor.gateViolations);
        Candor.gateViolations.clear();
        java.util.Collections.sort(out);
        return out;
    }

    /** THE COUNTEREXAMPLE, and the fix. Under the old rule row 3 (`three`, which does strictly MORE than
     *  row 1) passed a gate row 1 failed. Under ⟨0.24⟩ both are rejected and row 2 is still not. */
    @Test
    void aReasonlessUnknownContributesUnresolvedEvenBesideAClassifiedOne() throws Exception {
        Scan s = scanChained(true);
        try {
            for (String fn : java.util.List.of("app.A.one", "app.A.two", "app.A.three", "app.A.four"))
                assertTrue(s.inferred().get(fn).toNames().contains("Unknown"), fn + " must carry Unknown");
            assertEquals(java.util.List.of("app.A.one", "app.A.three"),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[unresolved] app"),
                    "row 1 (one reasonless dep) and row 3 (a reasonless dep BESIDE a classified reflect) must "
                    + "BOTH be rejected. Row 3 is strictly worse-known than row 1; a rule keyed on an EMPTY "
                    + "class set let the extra, classifiable reason REMOVE the default and turned row 3 green");
        } finally { rm(s.base()); }
    }

    /** THE CONTROL THAT MATTERS. {@code CONTRIBUTES} matches a strict SUPERSET, so it can turn green gates
     *  red — intended for row 3 and NOWHERE ELSE. A function whose {@code Unknown} reasons are ALL
     *  classifiable, and none of them {@code unresolved}, must still NOT match {@code Unknown[unresolved]}.
     *  Without this the fix is indistinguishable from contributing {@code unresolved} unconditionally,
     *  which floods every narrowed gate and makes the whole {@code [class]} filter useless. {@code four}
     *  is the sharper half: its {@code Unknown} is INHERITED, so it has no direct reason of its own and a
     *  "no direct tag ⇒ unresolved" reading would wrongly claim it. */
    @Test
    void aClassifiableUnknownStillDoesNotMatchUnresolved() throws Exception {
        Scan s = scanChained(true);
        try {
            assertEquals(java.util.List.of("app.A.one", "app.A.three"),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[unresolved] app"),
                    "two() (reflect only) and four() (reflect INHERITED, no direct tag at all) must not be "
                    + "claimed by an [unresolved] gate — the contribution is per reasonless SOURCE, never "
                    + "per Unknown-bearing function");
            assertEquals(java.util.List.of("app.A.four", "app.A.three", "app.A.two"),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[reflect] app"),
                    "and the other direction still discriminates: the reflect-scoped gate takes exactly the "
                    + "three reflect-reaching functions and leaves the reasonless-only one alone");
            assertEquals(java.util.List.of(),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[dispatch] app"),
                    "and a class the fixture produces NOWHERE claims nothing at all. This is the sharpest "
                    + "form of the control: `unresolved` is a real class now, not a stand-in for 'no class', "
                    + "so a [dispatch] filter tolerates one() rather than sweeping it in. The reason that is "
                    + "safe is that a narrowed filter omitting `unresolved` gets §6.2's under-gating advisory "
                    + "(see parsePolicy) — the hole is disclosed to the policy AUTHOR, not charged to a rule "
                    + "that did not ask for it");
        } finally { rm(s.base()); }
    }

    /** The FRESH arm — the control for the whole fixture. Nothing here is about chaining or about the app's
     *  shape: with a trusted report the dep's effects are read, {@code one()} is {@code Fs} rather than
     *  {@code Unknown}, and no reason-scoped verdict changes at all. If this arm ever moved, the arms above
     *  would be measuring the boundary rather than the reasonless {@code Unknown}. */
    @Test
    void aTrustedDependencyIsUnaffected() throws Exception {
        Scan s = scanChained(false);
        try {
            assertEquals("Fs", String.join(",", s.inferred().get("app.A.one").toNames()),
                    "a trusted dep's effect is INHERITED, not downgraded — so there is no reasonless Unknown");
            assertEquals(java.util.List.of(),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[unresolved] app"),
                    "and no function in the fixture matches [unresolved] when every Unknown is classified");
            assertEquals(java.util.List.of("app.A.four", "app.A.three", "app.A.two"),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[reflect] app"));
        } finally { rm(s.base()); }
    }

    /**
     * THE CONTROL THAT SEPARATES THE FIX FROM THE FLOOD — and the one the fixture above could NOT provide.
     *
     * <p>Written second, deliberately: with only the stale arm, the naive rule ("any {@code Unknown}-bearing
     * dep entry contributes {@code unresolved}") passes every assertion in this class, because under a
     * stale report NO entry has an accounted-for reason and the two rules agree everywhere. The distinction
     * only exists where a chained dependency's {@code Unknown} IS accounted for, which is what this arm is.
     *
     * <p>Both app methods reach a real, chained {@code Unknown} whose reason the dependency's report
     * explains — {@code direct()} through the entry's own {@code reflect:} tag, {@code viaShallow()} through
     * the {@code calls} edge of an entry that publishes no tag of its own. Neither may be claimed by
     * {@code Unknown[unresolved]}: nothing about them is unaccounted for. The naive form marks both, which
     * is the flood in miniature — on candor-swift's corpus the same rule marked 435 functions where the
     * legitimate count was 0, and it would make every narrowed {@code [class]} gate match everything.
     */
    @Test
    void anAccountedForChainedUnknownIsNotMarkedUnresolved() throws Exception {
        Scan s = scanChained(false, LIB_REFLECT, APP_REFLECT);
        try {
            for (String fn : java.util.List.of("app.B.direct", "app.B.viaShallow"))
                assertTrue(s.inferred().get(fn).toNames().contains("Unknown"),
                        fn + " must carry a real, chained Unknown — else this arm proves nothing");
            assertEquals(java.util.List.of("app.B.direct", "app.B.viaShallow"),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[reflect] app"),
                    "both reach the dependency's reflection, one through the entry's own tag and one through "
                    + "the calls chain — the reason class arrives either way (⟨0.19⟩, TransitiveUnknownReasonTest)");
            assertEquals(java.util.List.of(),
                    flagged(s.inferred(), s.base(), "deny Net Unknown[unresolved] app"),
                    "and NEITHER is unresolved. An Unknown the dependency EXPLAINS must not acquire an "
                    + "`unresolved` class just for having crossed a scan boundary: contributing on the "
                    + "presence of Unknown rather than on the absence of an accounting is the flood, and it "
                    + "is the one failure mode this whole rung has to avoid");
        } finally { rm(s.base()); }
    }

    /** BARE {@code deny Unknown} is unchanged, in both arms. ⟨0.24⟩ narrows nothing and widens nothing about
     *  which functions carry {@code Unknown} — it is only about which CLASS a narrowed filter sees. A fix
     *  that changed the effect set itself would pass every assertion above and fail this one. */
    @Test
    void bareDenyUnknownIsByteIdentical() throws Exception {
        Scan s = scanChained(true);
        try {
            assertEquals(java.util.List.of("app.A.four", "app.A.one", "app.A.three", "app.A.two"),
                    flagged(s.inferred(), s.base(), "deny Net Unknown app"),
                    "bare deny Unknown takes all four — it always did, which is exactly why the missing "
                    + "CLASS was invisible until a narrowed gate asked");
        } finally { rm(s.base()); }
    }
}
