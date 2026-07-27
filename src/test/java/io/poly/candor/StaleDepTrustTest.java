package io.poly.candor;

import com.google.gson.Gson;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
            + "  public void go(){ new lib.Blind().hidden(); }\n}\n");

    private enum Arm { UNCHAINED, FRESH, STALE }

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
        for (Arm arm : List.of(Arm.FRESH, Arm.STALE)) {
            Map<String, Object> r = reportFor(arm, lib, app);
            assertTrue(inferredOf(r, "app.T.run").contains("Unknown"),
                    arm + ": an unresolvable dispatch into a chained dep must stay disclosed — §2.1 "
                    + "distrust of the report's EFFECTS is not a reason to stop saying the dispatch is "
                    + "unresolved. Got " + inferredOf(r, "app.T.run"));
            assertTrue(unknownWhyOf(r, "app.T.run").stream().anyMatch(w -> w.startsWith("dispatch:")),
                    arm + ": the Unknown carries its dispatch reason, got " + unknownWhyOf(r, "app.T.run"));
            assertEquals(List.of(), invisibleOf(r, "app.T.run"),
                    arm + ": a κ-CURATED package emits no `invisible`, which is why losing the dispatch "
                    + "disclosure here would be silent");
        }
    }
}
