package io.poly.candor;

import com.google.gson.Gson;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * §2.1 STALENESS AND COVERAGE ARE THE SAME QUESTION ASKED TWICE.
 *
 * <p>A dep report whose producing build cannot be verified has its EFFECTS downgraded to Unknown — the
 * engine refuses to trust what it says. The second half of trusting a report is registering its packages
 * as COVERED, which is what silences the κ ledger's {@code invisible: [pkg]} disclosure for every key the
 * report does NOT contain. Registering coverage from a report the engine has just refused to trust turns
 * that silence into a purity claim on the untrusted report's authority: absent from {@code functions},
 * counted in ⟨0.21⟩ {@code analyzed}, with nothing anywhere saying the package was unreadable.
 *
 * <p>The three arms below are the whole argument. The UNCHAINED arm is the honest baseline; the FRESH arm
 * is the coverage a trusted report legitimately buys (SPEC §2 rule 3 — a dep report omits its pure
 * functions, so silence under a formed key is a real answer); the STALE arm must match the UNCHAINED one,
 * because a report whose effects are not trusted cannot vouch for its own completeness either.
 *
 * <p>⟨0.21⟩ THE FOURTH ARM IS THE SAME DOOR WITH A DIFFERENT KEY. A report carrying a non-empty
 * {@code unanalyzed} has just said it never read some of its own source, so its SILENCE about that source
 * answers nothing — and it was still registering full coverage. Chaining it was strictly WORSE than not
 * chaining it: the dependency's own gate refuses to certify itself over unanalyzed code (exit 2), and the
 * consumer certified one on its behalf. Its TREATMENT differs from the stale arm's and that difference is
 * the point — its entries were derived from source it DID read, so they are KEPT unchanged and only the
 * silence hedges. candor-ts closed this first (`21277eb`); this is the JVM half.
 *
 * <p>⟨0.24⟩ THE FIFTH ARM IS THE SAME DOOR AGAIN, AND IT ARRIVES WITH ITS OWN NEGATIVE CONTROL. A report
 * with {@code functions: []} and {@code analyzed.count: 0} judged nothing, so it has nothing to be silent
 * ABOUT — yet chaining it was strictly more confident than the UNCHAINED arm, which discloses. Measured here
 * before the fix: the consumer's report went from 2 entries carrying {@code invisible: [lib]} plus a
 * {@code coverage} envelope to ZERO entries and no envelope, i.e. a positive purity claim for both callers
 * with no advisory anywhere. The SIXTH arm is why this is not a one-liner: {@code functions: []} with
 * {@code analyzed.count} LEFT ALONE is a legitimate all-pure claim SPEC §2 chaining rule 3 requires a
 * consumer to BELIEVE, and a fix hedging both would have disabled the rule rather than implemented it. The
 * two arms are byte-identical apart from one integer, so they must DIVERGE — which is exactly what
 * conformance PART 26's CONTROL SEPARATION row asks, and what all four engines failed.
 */
class StaleDepTrustTest {

    /** A dependency with one method the app calls and the lib report will not mention (it is pure, and
     *  SPEC §2 rule 3 omits pure functions) plus one it will. */
    private static final Map<String, String> LIB = Map.of(
        "lib/Blind.java", "package lib;\npublic class Blind {\n"
            + "  public void hidden(){ }\n"
            + "  public void phone(){ try { new java.net.Socket(\"h\", 1).close(); } catch (Exception e) {} }\n}\n");

    private static final Map<String, String> APP = Map.of(
        "app/S.java", "package app;\npublic class S {\n"
            + "  public void go(){ new lib.Blind().hidden(); }\n"
            + "  public void dial(){ new lib.Blind().phone(); }\n}\n");

    private enum Arm { UNCHAINED, FRESH, STALE, INCOMPLETE, JUDGED_NOTHING, ALL_PURE_EMPTY,
                       UNREADABLE_MANIFEST_NO_PKG }

    /** Scan the app with lib's report chained fresh / staled / not at all, and return the written report
     *  root (so the coverage envelope AND the entry set are both visible — absence from {@code functions}
     *  is itself a purity claim, so an effects-map view could not see this defect). */
    private static Map<String, Object> reportFor(Arm arm) throws Exception {
        return reportFor(arm, LIB, APP);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> reportFor(Arm arm, Map<String, String> lib, Map<String, String> app)
            throws Exception {
        Path appDir = compileApp(lib, app);
        Path base = appDir.getParent();
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            if (arm != Arm.UNCHAINED) {
                Path depReport = base.resolve("dep.json");
                Files.deleteIfExists(depReport);            // standing-bar item 7: never read a stale arm
                ReportWriter.writeReport(Candor.runScan(base.resolve("lib")), depReport.toString(), null);
                if (arm == Arm.INCOMPLETE) {
                    // The ONE thing this arm differs in (standing-bar item 7d): the report now declares an
                    // `unanalyzed` unit. Same build id, same packages, same `functions` — byte-identical
                    // apart from the envelope key, which is what makes "the entries are kept" a real claim.
                    String json = Files.readString(depReport);
                    String marker = "\"functions\"";
                    assertTrue(json.contains(marker), "the dep report must carry a functions array: " + json);
                    Files.writeString(depReport, json.replace(marker,
                            "\"unanalyzed\": [{\"path\": \"lib/Unreadable.class\","
                            + " \"reason\": \"class file failed to parse: injected\"}], " + marker));
                }
                if (arm == Arm.JUDGED_NOTHING || arm == Arm.ALL_PURE_EMPTY) {
                    // ⟨0.24⟩ The two arms this rung turns on, built from ONE dep report so they differ in
                    // exactly one integer (standing-bar item 7d). Both empty `functions`; only
                    // JUDGED_NOTHING zeroes `analyzed.count`. Built structurally rather than by string
                    // surgery because the whole property is about that field's VALUE, and a replace() that
                    // silently matched nothing would leave two identical arms and a green run.
                    com.google.gson.JsonObject o = new Gson().fromJson(Files.readString(depReport),
                            com.google.gson.JsonObject.class);
                    assertTrue(o.has("analyzed") && o.getAsJsonObject("analyzed").get("count").getAsInt() > 0,
                            "the produced dep report must carry a POSITIVE analyzed.count, else the two arms "
                            + "differ in nothing: " + o);
                    o.add("functions", new com.google.gson.JsonArray());
                    if (arm == Arm.JUDGED_NOTHING) o.getAsJsonObject("analyzed").addProperty("count", 0);
                    Files.writeString(depReport, o.toString());
                }
                if (arm == Arm.UNREADABLE_MANIFEST_NO_PKG) {
                    // ⟨0.24⟩ COVERAGE IS ANCHORED TWICE — the envelope's `packages` and, as a fallback for
                    // reports that carry none, each ENTRY's hash prefix. Gating only one would have been a
                    // no-op wearing a fix's clothes (the ⟨0.21⟩ arm learned this the same way), and a
                    // count-0 report has no entries, so it cannot exercise the second anchor at all. This
                    // arm can: the envelope field is DELETED, so only the entry-level gate is left, and the
                    // manifest is an unreadable `null` — a judgment claim that cannot be read is not a
                    // claim. Its entries are real and must survive: this is also the additivity row.
                    com.google.gson.JsonObject o = new Gson().fromJson(Files.readString(depReport),
                            com.google.gson.JsonObject.class);
                    assertTrue(o.has("packages"), "the produced dep report must carry `packages`, else "
                            + "deleting it proves nothing about the entry-level anchor: " + o);
                    o.remove("packages");
                    o.remove("package");
                    o.add("analyzed", com.google.gson.JsonNull.INSTANCE);
                    Files.writeString(depReport, o.toString());
                }
                if (arm == Arm.STALE) {
                    // The ONE thing the two chained arms differ in (standing-bar item 7d): the producing
                    // build id. Same bytes otherwise, same packages, same functions.
                    String json = Files.readString(depReport);
                    String own = ReportWriter.provenance()[0];
                    assertTrue(json.contains("\"version\": \"" + own + "\"")
                            || json.contains("\"version\":\"" + own + "\""),
                            "the fresh dep report must carry THIS build's version, else the arms differ in "
                            + "nothing: " + json.substring(0, Math.min(300, json.length())));
                    Files.writeString(depReport, json.replace(own, own + "-NOT-THIS-BUILD"));
                }
                Files.createDirectories(base.resolve(".candor"));
                Files.writeString(base.resolve(".candor/config"), "deps " + depReport + "\n");
                Candor.config = Config.forTarget(appDir);
            }
            Path out = base.resolve("app.json");
            Files.deleteIfExists(out);                       // standing-bar item 7
            ReportWriter.writeJson(Candor.runScan(appDir), out.toString());
            return new Gson().fromJson(Files.readString(out), Map.class);
        } finally {
            Candor.config = saved;
            rm(base);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> invisibleOf(Map<String, Object> root, String fn) {
        for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
            if (fn.equals(e.get("fn"))) return (List<String>) e.getOrDefault("invisible", List.of());
        return null;                                        // ABSENT from functions == a purity claim
    }

    @SuppressWarnings("unchecked")
    private static List<String> listField(Map<String, Object> root, String fn, String key) {
        for (Map<String, Object> e : (List<Map<String, Object>>) root.get("functions"))
            if (fn.equals(e.get("fn"))) return (List<String>) e.getOrDefault(key, List.of());
        return List.of();
    }

    private static List<String> inferredOf(Map<String, Object> root, String fn) {
        return listField(root, fn, "inferred");
    }

    private static List<String> unknownWhyOf(Map<String, Object> root, String fn) {
        return listField(root, fn, "unknownWhy");
    }

    @SuppressWarnings("unchecked")
    private static List<String> coveragePkgs(Map<String, Object> root) {
        Map<String, Object> cov = (Map<String, Object>) root.get("coverage");
        if (cov == null) return List.of();
        return ((List<Map<String, Object>>) cov.get("uncovered")).stream()
                .map(u -> (String) u.get("name")).sorted().toList();
    }

    /** The honest baseline: nothing chained, so the dep package is a NAMED blind spot on the caller and in
     *  the envelope. This is the answer the untrusted-report arm has to reproduce. */
    @Test
    void unchainedDiscloses() throws Exception {
        Map<String, Object> r = reportFor(Arm.UNCHAINED);
        assertEquals(List.of("lib"), invisibleOf(r, "app.S.go"),
                "unchained: the caller discloses the package it cannot see");
        assertTrue(coveragePkgs(r).contains("lib"), "unchained: the envelope names lib uncovered");
    }

    /** The coverage a TRUSTED report legitimately buys: its silence under a formed key is a real purity
     *  claim (SPEC §2 rule 3), so no disclosure is owed. This is the case that must still work. */
    @Test
    void aTrustedReportStillGrantsCoverage() throws Exception {
        Map<String, Object> r = reportFor(Arm.FRESH);
        assertFalse(coveragePkgs(r).contains("lib"),
                "a same-build dep report covers its package — this is the case the fix must not break");
        assertEquals(List.of(), invisibleOf(r, "app.S.go") == null ? List.of() : invisibleOf(r, "app.S.go"),
                "a trusted report owes no blind-spot disclosure");
    }

    /** THE DEFECT: §2.1 refuses to trust the report's effects and then trusts its coverage. */
    @Test
    void anUntrustedReportGrantsNoCoverage() throws Exception {
        Map<String, Object> r = reportFor(Arm.STALE);
        assertEquals(List.of("lib"), invisibleOf(r, "app.S.go"),
                "a report whose build cannot be verified cannot vouch for the keys it does NOT contain — "
                + "the caller must disclose the package exactly as if nothing were chained");
        assertTrue(coveragePkgs(r).contains("lib"),
                "the envelope must name lib uncovered: coverage claimed on an untrusted report's authority "
                + "is a purity claim the engine has no evidence for");
    }

    // ── ⟨0.21⟩ the INCOMPLETE arm ───────────────────────────────────────────────────────────────────

    /** THE DEFECT: the dependency's own scan says it never read some of its own source, and its silence
     *  about that source was still buying a purity claim. The answer must match the UNCHAINED baseline. */
    @Test
    void aSelfDeclaredIncompleteReportGrantsNoCoverage() throws Exception {
        Map<String, Object> r = reportFor(Arm.INCOMPLETE);
        assertEquals(List.of("lib"), invisibleOf(r, "app.S.go"),
                "a report that names source it could not analyze cannot vouch for the keys it does NOT "
                + "contain — the caller must disclose the package exactly as if nothing were chained");
        assertTrue(coveragePkgs(r).contains("lib"),
                "the envelope must name lib uncovered: `unanalyzed` is the report saying its own silence "
                + "is not a completeness claim");
    }

    /** THE TREATMENT THAT DIFFERS FROM STALENESS, and the row that makes the difference a requirement
     *  rather than a comment. An entry the incomplete report DOES carry was derived from source it really
     *  did read, so it is applied UNCHANGED — no downgrade, no Unknown bolted on. Only the silence hedges,
     *  which is what makes the fix strictly additive: no effect is ever removed. */
    @Test
    void anEntryTheIncompleteReportDoesCarryIsAppliedUnchanged() throws Exception {
        Map<String, Object> r = reportFor(Arm.INCOMPLETE);
        assertEquals(List.of("Net"), inferredOf(r, "app.S.dial"),
                "the dep's own answer for a key it DID analyze survives the completeness hedge — treating "
                + "it like a stale report would read ['Unknown'] here, and would remove a concrete effect "
                + "from a consumer that had one");
        assertEquals(List.of("Net"), inferredOf(reportFor(Arm.FRESH), "app.S.dial"),
                "…and it is the same answer the COMPLETE report gives, so the arms differ only in silence");
    }

    // ── ⟨0.24⟩ the JUDGED-NOTHING arm and its all-pure control ──────────────────────────────────────

    /** THE DEFECT: a report that judged NO units has nothing to be silent about, and its silence was
     *  buying a purity claim — strictly more confidence than not chaining the package at all. The answer
     *  must match the UNCHAINED baseline exactly, in both channels. */
    @Test
    void aReportThatJudgedNothingGrantsNoCoverage() throws Exception {
        Map<String, Object> r = reportFor(Arm.JUDGED_NOTHING);
        assertEquals(List.of("lib"), invisibleOf(r, "app.S.go"),
                "a report with `analyzed.count: 0` judged no unit in `lib`, so it vouches for nothing there "
                + "— the caller must disclose the package exactly as if nothing were chained. Before the "
                + "fix `app.S.go` was ABSENT from `functions` entirely, which is a ⟨0.21⟩ purity claim");
        assertEquals(List.of("lib"), invisibleOf(r, "app.S.dial"),
                "…and so must the caller whose dep method really does perform an effect: this is the reach "
                + "that vanished, `deny Fs`/`deny Net` exit 1 → exit 0 against the TRUSTED arm");
        assertTrue(coveragePkgs(r).contains("lib"),
                "the envelope must name lib uncovered: `analyzed.count: 0` is the producer saying it judged "
                + "nothing, which cannot be read as full coverage");
    }

    /** THE NEGATIVE CONTROL, and the reason this rung is not a one-liner. The SAME file with the SAME empty
     *  `functions` and `analyzed.count` left as produced is a legitimate all-pure claim — SPEC §2 chaining
     *  rule 3: "an all-pure dependency's empty report is a claim, not a blind spot" — and a consumer MUST
     *  believe it, unhedged. A fix that hedged both arms would not have implemented ⟨0.24⟩'s table; it would
     *  have deleted its second row. Conformance PART 26 carries the same pair and prints their divergence. */
    @Test
    void anAllPureEmptyReportIsStillBelieved() throws Exception {
        Map<String, Object> r = reportFor(Arm.ALL_PURE_EMPTY);
        assertNull(invisibleOf(r, "app.S.go"),
                "an all-pure dep report (`functions: []`, `analyzed.count` > 0) makes a positive purity "
                + "claim, so the caller is pure and drops out of `functions` — no hedge is owed and none "
                + "may be added");
        assertFalse(coveragePkgs(r).contains("lib"),
                "…and the envelope must NOT name lib uncovered: hedging this arm disables the claim §2 "
                + "chaining rule 3 requires a consumer to believe");
    }

    /** THE DIVERGENCE ITSELF, asserted as its own row rather than inferred from the two above. The arms are
     *  byte-identical apart from one integer, so an engine that does not READ `analyzed.count` answers them
     *  identically — which is precisely what PART 26's CONTROL SEPARATION row measured on all four engines,
     *  and what a passing pair of rows above could still hide if the fixture ever stopped differing. */
    @Test
    void theTwoEmptyArmsMustDiverge() throws Exception {
        Map<String, Object> zero = reportFor(Arm.JUDGED_NOTHING);
        Map<String, Object> allPure = reportFor(Arm.ALL_PURE_EMPTY);
        // The two channels an engine can answer in, and both must move: the ⟨0.21⟩ entry set (absence is a
        // purity claim) and the κ envelope. Compared as a PROJECTION rather than whole-report equality so a
        // future envelope field cannot make this row pass for an unrelated reason.
        // (asList, not List.of: `coverage` is OMITTED — a null value — on the all-pure arm, and that
        // omission is half of what is being compared.)
        assertFalse(java.util.Arrays.asList(zero.get("functions"), zero.get("coverage"))
                        .equals(java.util.Arrays.asList(allPure.get("functions"), allPure.get("coverage"))),
                "`analyzed.count: 0` and `analyzed.count: n>0` over the SAME empty `functions` mean opposite "
                + "things — judged nothing vs judged n and found nothing. An engine answering them "
                + "identically is not reading the field at all");
        assertEquals(List.of("lib"), invisibleOf(zero, "app.S.go"), "the count-0 arm hedges");
        assertNull(invisibleOf(allPure, "app.S.go"), "the count-n arm does not");
    }

    /** THE SECOND ANCHOR, and the reason the ⟨0.24⟩ conjunct is on BOTH coverage registrations rather than
     *  only the obvious one. A report with no `packages` envelope field registers coverage from each ENTRY's
     *  hash prefix instead; a count-0 report has no entries, so nothing in the two arms above can tell
     *  whether that second gate exists. Here it is the only gate there is — and the row doubles as the
     *  ADDITIVITY check: the entries the report DOES carry are still applied, so `dial` keeps its Net. Only
     *  the silence hedges, exactly as on the ⟨0.21⟩ incomplete arm. */
    @Test
    void anUnreadableManifestWithdrawsOnlyTheSilence() throws Exception {
        Map<String, Object> r = reportFor(Arm.UNREADABLE_MANIFEST_NO_PKG);
        assertEquals(List.of("lib"), invisibleOf(r, "app.S.go"),
                "`analyzed: null` is a judgment claim that cannot be READ, so the report's silence licenses "
                + "nothing — and with no `packages` field the entry-level registration is the ONLY thing "
                + "that could have granted coverage here");
        assertEquals(List.of("Net"), inferredOf(r, "app.S.dial"),
                "…while the entry it DOES carry is applied unchanged: withdrawing coverage must never "
                + "remove an effect a consumer already had");
    }

    /** THE SHAPE TABLE, unit-level, so every row of ⟨0.24⟩'s three-row table has an assertion rather than a
     *  comment — including the two the end-to-end arms above cannot reach (a pre-⟨0.21⟩ producer, and a
     *  manifest that cannot be READ). A claim that cannot be read is not a claim: it fails closed, the same
     *  posture {@link Loader#declaresItselfIncomplete} takes for a malformed `unanalyzed`. */
    @Test
    void onlyAPositiveAnalyzedCountIsAJudgmentClaim() {
        Gson g = new Gson();
        com.google.gson.JsonArray empty = new com.google.gson.JsonArray();
        com.google.gson.JsonArray oneFn = g.fromJson("[{\"hash\":\"lib/A.b()V\"}]",
                com.google.gson.JsonArray.class);
        // row 2 — the CONTROL. n>0 is a judgment claim whatever `functions` holds.
        assertFalse(Loader.claimsToHaveJudgedNothing(
                        g.fromJson("{\"analyzed\":{\"count\":2}}", com.google.gson.JsonObject.class), empty),
                "n>0 with empty functions = n units judged, all pure — §2 chaining rule 3 says believe it");
        assertFalse(Loader.claimsToHaveJudgedNothing(
                        g.fromJson("{\"analyzed\":{\"count\":9}}", com.google.gson.JsonObject.class), oneFn),
                "n>0 with entries = the ordinary report, untouched by this rung");
        // row 1 — the defect.
        assertTrue(Loader.claimsToHaveJudgedNothing(
                        g.fromJson("{\"analyzed\":{\"count\":0}}", com.google.gson.JsonObject.class), empty),
                "count 0 = judged nothing: the shape a facade package scans to");
        assertTrue(Loader.claimsToHaveJudgedNothing(
                        g.fromJson("{\"analyzed\":{\"count\":0}}", com.google.gson.JsonObject.class), oneFn),
                "count 0 while LISTING functions is self-contradictory — fail closed, do not pick a side");
        // row 3 — a pre-⟨0.21⟩ producer, which has no manifest and so makes no claim about its silence.
        assertTrue(Loader.claimsToHaveJudgedNothing(g.fromJson("{}", com.google.gson.JsonObject.class), empty),
                "no manifest + no functions: nothing on the wire says whether anything was judged, so it "
                + "falls back to the unchained reading");
        assertFalse(Loader.claimsToHaveJudgedNothing(g.fromJson("{}", com.google.gson.JsonObject.class), oneFn),
                "no manifest but functions LISTED: units were demonstrably judged, and a pre-⟨0.21⟩ report "
                + "keeps the coverage it has always had — this rung must not retroactively hedge every "
                + "report written before the manifest existed");
        assertTrue(Loader.claimsToHaveJudgedNothing(null, empty),
                "the bare-ARRAY root form has no envelope at all, so it makes no judgment claim either");
        // the fourth direction: present but unreadable.
        for (String malformed : List.of("null", "\"some\"", "7", "[]", "{}", "{\"count\":null}",
                                        "{\"count\":\"3\"}")) {
            assertTrue(Loader.claimsToHaveJudgedNothing(g.fromJson(
                            "{\"analyzed\":" + malformed + "}", com.google.gson.JsonObject.class), oneFn),
                    "a judgment claim that cannot be READ is not a claim — `analyzed: " + malformed
                    + "` must fail closed. A denylist of proven-safe shapes, not an allowlist of rejected ones");
        }
    }

    /** THE SECOND FIXTURE FOR THE COMPLETENESS HALF, written before the fix (standing bar item 0): a report
     *  whose `unanalyzed` is EXPLICITLY EMPTY, and one with the key ABSENT, are both COMPLETE and must keep
     *  their coverage. `ReportJson` omits the key when the manifest is empty, so absence is this engine's
     *  own way of saying "I read everything" — reading absence as incompleteness would hedge every report
     *  ever written and delete chained coverage outright. A MALFORMED value is the third direction and goes
     *  the other way: a completeness claim that cannot be read is not a claim. */
    @Test
    void onlyAnAbsentOrEmptyManifestIsACompletenessClaim() {
        assertFalse(Loader.declaresItselfIncomplete(new Gson().fromJson("{}", com.google.gson.JsonObject.class)),
                "absent — the shape EVERY complete candor-java report has");
        assertFalse(Loader.declaresItselfIncomplete(
                        new Gson().fromJson("{\"unanalyzed\":[]}", com.google.gson.JsonObject.class)),
                "explicitly empty — an engine that always emits the key still claims completeness");
        assertTrue(Loader.declaresItselfIncomplete(new Gson().fromJson(
                        "{\"unanalyzed\":[{\"path\":\"a\",\"reason\":\"b\"}]}", com.google.gson.JsonObject.class)),
                "non-empty — the defect this closes");
        for (String malformed : List.of("null", "\"some\"", "{}", "7")) {
            assertTrue(Loader.declaresItselfIncomplete(new Gson().fromJson(
                            "{\"unanalyzed\":" + malformed + "}", com.google.gson.JsonObject.class)),
                    "a completeness claim that cannot be READ is not a claim — `unanalyzed: " + malformed
                    + "` must fail closed, the same way a malformed `inferred` becomes Unknown rather than "
                    + "pure. A denylist of proven-safe shapes, not an allowlist of rejected ones");
        }
    }

    /** THE SECOND DIRECTION, and it is not hypothetical — the first version of this fix failed it on real
     *  code (standing-bar item 0).
     *
     *  <p>{@link Candor#untypedDepReceiver}'s conjunct 3 asks "is a report chained for this package", and
     *  it asks only to avoid disclosing twice where the κ ledger already speaks. That question has an
     *  answer whatever §2.1 thinks of the report's effects. Routing it through the trust-gated coverage
     *  set silenced it on a STALE chain, and for a κ-CURATED-covered package (`ch.qos.logback`,
     *  `com.fasterxml.jackson`, `org.slf4j` — see {@code Rules.KAPPA_COVERED_PREFIXES}) nothing replaces
     *  it, because {@code invisible} is never emitted for those either. Measured on logback-classic
     *  chained to a staled logback-core: `ContextInitializer.printConfiguratorOrder` went
     *  {@code ['Unknown']} to {@code []} and `printDuration` lost its Unknown — an entry reduced to an
     *  empty purity claim by a fix whose whole argument was that it disclosed more.
     *
     *  <p>The fixture puts the dependency in a κ-CURATED package so no {@code invisible} can mask the
     *  loss, exactly as the real corpus case did. */
    @Test
    void anUntrustedReportStillDisclosesUnresolvedDispatch() throws Exception {
        // `ch.qos.logback.candorfixture` is inside a KAPPA_COVERED_PREFIXES entry, so the κ ledger is
        // silent about it whatever the chain does — the dispatch disclosure is the ONLY channel there is.
        Map<String, String> lib = Map.of(
            "ch/qos/logback/candorfixture/Store.java",
                "package ch.qos.logback.candorfixture;\npublic interface Store { void save(String s); }\n",
            "ch/qos/logback/candorfixture/FileStore.java",
                "package ch.qos.logback.candorfixture;\nimport java.io.*;\n"
                + "public class FileStore implements Store {\n"
                + "  public void save(String s){ try { new FileWriter(\"/tmp/x\").close(); } catch (Exception e) {} }\n}\n");
        Map<String, String> app = Map.of(
            "app/T.java", "package app;\nimport ch.qos.logback.candorfixture.Store;\n"
                + "public class T {\n  public void run(Store s){ s.save(\"x\"); }\n}\n");
        // ⟨0.21⟩ INCOMPLETE is the third arm here, and it is the SAME trade one key over. candor-ts
        // measured it happening: withholding coverage sent the site to the κ-ledger arm, which returns, so
        // half 1's Unknown was silently REPLACED by the hedge and `deny Fs Unknown[dispatch]` went exit 1 →
        // exit 0 — a gate lost to a fix whose whole argument is that it adds disclosure. It cannot happen
        // here for a structural reason rather than a lucky one: conjunct 3 reads `depChainedPkgs`, which
        // `7e41327` gave its own ungated set precisely so a trust decision could not reach it, and the
        // completeness gate is on `depCoveredPkgs` only. That is an argument, so it is a row.
        //
        // MEASURED, and the measurement corrected the argument. Gating only the FILE-level
        // `depChainedPkgs.addAll` on completeness fails NOTHING — the entry-level fallback re-registers the
        // same package from the hash, so chained-ness here is anchored TWICE and either anchor alone keeps
        // half 1 speaking. Only gating BOTH silences it, and then this row fails on the INCOMPLETE arm
        // specifically ("INCOMPLETE: an unresolvable dispatch … must stay disclosed"). Coverage is anchored
        // twice the same way, which is why the fix had to gate both of those too: gating one would have
        // been a no-op wearing a fix's clothes.
        for (Arm arm : List.of(Arm.FRESH, Arm.STALE, Arm.INCOMPLETE)) {
            Map<String, Object> r = reportFor(arm, lib, app);
            assertTrue(inferredOf(r, "app.T.run").contains("Unknown"),
                    arm + ": an unresolvable dispatch into a chained dep must stay disclosed — neither §2.1 "
                    + "distrust of the report's EFFECTS nor its own incompleteness is a reason to stop "
                    + "saying the dispatch is unresolved. Got " + inferredOf(r, "app.T.run"));
            assertTrue(unknownWhyOf(r, "app.T.run").stream().anyMatch(w -> w.startsWith("dispatch:")),
                    arm + ": the Unknown carries its dispatch reason, got " + unknownWhyOf(r, "app.T.run"));
            assertEquals(List.of(), invisibleOf(r, "app.T.run"),
                    arm + ": a κ-CURATED package emits no `invisible`, which is why losing the dispatch "
                    + "disclosure here would be silent");
        }
    }
}
