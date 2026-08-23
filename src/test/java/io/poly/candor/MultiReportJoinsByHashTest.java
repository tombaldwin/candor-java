package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.32⟩ SPEC §2.2 — <b>A MULTI-REPORT GATE JOINS BY {@code hash}, NEVER BY BARE {@code fn}</b> ("names
 * may legitimately repeat across packages").
 *
 * <p><b>MEASURED on this engine at 0.31.0, and it is a cardinal sin.</b> {@code gate --report} over one
 * member refused a scoped rule at exit 2; the SAME member gated beside an unrelated sibling exited 0 with
 * {@code policy ✓}. A false green produced by ADDING a report.
 *
 * <p>The harm was never two functions' effects merging. {@code app.Main.run} had an {@code Unknown} with
 * no reachable reason — UNANSWERABLE, so the gate refused. The sibling gave that NAME a reason, the filter
 * saw a class set the rule does not deny, and tolerated. <b>Union is safe for EFFECTS and unsafe for
 * REASONS</b>: adding an effect can only add violations, adding a reason turns "I cannot say" into "I
 * checked, it's fine".
 *
 * <p>The four tests below are the four ways this goes wrong, and three of them are ways the FIX goes
 * wrong rather than ways the defect does. They belong in one file because each is the other's control:
 * <ul>
 *   <li>{@link #aSiblingReportCannotAnswerForAnotherMember} — the defect itself, with the sibling gated
 *       ALONE as the control that excludes an engine that simply refuses every merge.</li>
 *   <li>{@link #anAmbiguousCalleeContributesUnknownDispatch} — the SECOND false green, caused by the fix
 *       for the first. Keying on {@code hash} means an ambiguous callee NAME resolves to nothing, which
 *       is right (picking a declarer would invent a reach) — but dropping it SILENTLY made the caller lose
 *       an INHERITED reason class while staying answerable through its own, and a red verdict went green
 *       by adding a report.</li>
 *   <li>{@link #aPolicyScopeStillMatchesOnceTheKeysAreHashes} — the fix's own false green. A hash on this
 *       engine is {@code owner/name(desc)ret}; a policy scope is written against the NAME. Keying the
 *       accumulators by hash without carrying names beside them stops every scope matching, silently.</li>
 *   <li>{@link #theVerdictRowCarriesTheNameNotTheKey} — §3.3.1 pins {@code gate --report}'s rows
 *       byte-equal to {@code scan --policy}'s, and the scan route has only names to print.</li>
 * </ul>
 */
class MultiReportJoinsByHashTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void fresh() {
        Candor.resetState();
        Candor.gateViolations.clear();
        Candor.gateCapture = false;
    }

    @AfterEach
    void clear() {
        Candor.gateCapture = false;
        Candor.gateViolations.clear();
        Candor.resetState();
    }

    // ── fixtures ───────────────────────────────────────────────────────────────────────────────────────

    /** One report entry, stating an EXACT (S, D) plus the {@code hash} that identifies the unit. */
    private static Map<String, Object> entry(String fn, String hash, List<String> inferred,
                                             List<String> direct, List<String> why, List<String> calls) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", fn);
        m.put("loc", "X.java:1");
        m.put("inferred", inferred);
        m.put("direct", direct);
        m.put("declared", List.of());
        m.put("undeclared", List.of());
        m.put("overdeclared", List.of());
        m.put("entryPoint", false);
        m.put("unresolved", inferred.contains("Unknown"));
        if (!why.isEmpty()) m.put("unknownWhy", why);
        m.put("hash", hash);
        if (!calls.isEmpty()) m.put("calls", calls);
        return m;
    }

    /** Write {@code <dir>/report.<member>.scan.json}, so {@code --report <dir>/report} names the SET. */
    private Path member(String dir, String name, List<Map<String, Object>> entries) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", entries.size(), "digest", "0"));
        env.put("functions", entries);
        Path p = tmp.resolve(dir).resolve("report." + name + ".scan.json");
        Files.createDirectories(p.getParent());
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    private Path policy(String body) throws Exception {
        Path p = tmp.resolve("p" + Math.abs(body.hashCode()) + ".policy");
        Files.writeString(p, body);
        return p;
    }

    /** Run the verb the way a user does — through the CLI dispatcher. Returns the exit code. */
    private int gate(String dir, Path policy, String... more) {
        List<String> a = new ArrayList<>(List.of("gate",
                "--report", tmp.resolve(dir).resolve("report").toString(),
                "--policy", policy.toString()));
        a.addAll(List.of(more));
        return Query.run(a.toArray(new String[0]));
    }

    // ── 1. the defect ──────────────────────────────────────────────────────────────────────────────────

    /**
     * {@code a} carries an {@code Unknown} it names NO reason for and reaches none — UNANSWERABLE under
     * {@code deny Unknown[dispatch]}, so the gate refuses (exit 2). {@code b} declares a DIFFERENT unit
     * that happens to share the name (a different descriptor: overloads, or the same class shipped by two
     * members) and reaches a {@code callback:} reason.
     *
     * <p>Gating {@code a} beside {@code b} must still refuse. Before the fix it exited 0 with
     * {@code policy ✓}: {@code b}'s reason made {@code a}'s Unknown answerable, the filter saw
     * {@code {indirect} ∌ dispatch}, and tolerated.
     */
    @Test
    void aSiblingReportCannotAnswerForAnotherMember() throws Exception {
        List<Map<String, Object>> a = List.of(
                entry("app.Main.run", "app/Main.run(Ljava/lang/String;)V",
                        List.of("Unknown"), List.of(), List.of(), List.of()));
        List<Map<String, Object>> b = List.of(
                entry("app.Main.run", "app/Main.run(I)V",
                        List.of("Unknown"), List.of("Unknown"), List.of("callback:cb"), List.of()));
        member("alone", "a", a);
        member("both", "a", a);
        member("both", "b", b);
        member("sibling", "b", b);
        Path pol = policy("deny Unknown[dispatch]\n");

        assertEquals(2, gate("alone", pol),
                "`a`'s Unknown names no reason and reaches none — the narrowing cannot be evaluated, so "
                + "the gate REFUSES rather than tolerating for lack of evidence");
        assertEquals(2, gate("both", pol),
                "and ADDING an unrelated same-named sibling must not answer for it (SPEC §2.2: join by "
                + "`hash`, never by bare `fn`) — this exited 0 `policy ✓` before the fix");

        // THE CONTROL. Without it this passes for an engine that refuses every multi-report gate, which
        // is a different defect wearing the same exit code.
        assertEquals(0, gate("sibling", pol),
                "the sibling gated ALONE is answerable and clean — so the refusal above is a fact about "
                + "`a`, not about the verb");
    }

    // ── 2. the false green the FIX introduces ──────────────────────────────────────────────────────────

    /**
     * Keying on {@code hash} makes a callee NAME declared by two units unresolvable. Dropping that edge is
     * right; dropping it SILENTLY is not. {@code caller} carries its OWN {@code callback:} reason, so it
     * stays ANSWERABLE after losing the {@code dispatch} class it would have inherited — and
     * {@code deny Unknown[dispatch] caller} goes from firing to passing BY ADDING A REPORT.
     *
     * <p>So the ambiguity is CONTRIBUTED as evidence at the caller's entry, before the fixpoint.
     * {@code dispatch} is the class the §4 vocabulary already defines as "unresolved virtual/dynamic
     * dispatch, SAME-NAME AMBIGUITY", and it is evidence the MERGE holds (it saw two declarers) rather
     * than a class borrowed from another function's body — so it cannot make some OTHER function's
     * Unknown answerable, which is the defect in test 1.
     *
     * <p><b>Where this test's teeth are, because they are NOT where a reader would look.</b> It passes
     * against the pre-fix, name-keyed engine — merging the two {@code go}s hands the caller the
     * {@code dispatch} class anyway, by luck. It fails against the INTERMEDIATE state: hash-keyed with the
     * contribution removed, {@code amb} exits 0 while {@code ctrl} stays at 1. That was measured directly,
     * by building the contribution out, and it is the state this file's other three tests all pass in.
     */
    @Test
    void anAmbiguousCalleeContributesUnknownDispatch() throws Exception {
        List<Map<String, Object>> a = List.of(
                entry("app.Helper.go", "app/Helper.go()V", List.of("Exec", "Unknown"),
                        List.of("Exec", "Unknown"), List.of("dispatch:vtable"), List.of()));
        List<Map<String, Object>> c = List.of(
                entry("app.Caller.go", "app/Caller.go()V", List.of("Unknown"), List.of("Unknown"),
                        List.of("callback:cb"), List.of("app.Helper.go")));
        List<Map<String, Object>> b = List.of(
                entry("app.Helper.go", "app/Helper.go(I)V", List.of(), List.of(), List.of(), List.of()));
        member("ctrl", "a", a);
        member("ctrl", "c", c);
        member("amb", "a", a);
        member("amb", "c", c);
        member("amb", "b", b);
        Path pol = policy("deny Unknown[dispatch] app.Caller\n");

        assertEquals(1, gate("ctrl", pol),
                "one declarer: the edge resolves, `caller` INHERITS `dispatch`, the rule fires");
        assertEquals(1, gate("amb", pol),
                "two declarers: the edge is dropped (picking would invent a reach) but the ambiguity is "
                + "CONTRIBUTED as Unknown[dispatch] at the caller — adding a report must not turn a RED "
                + "verdict green");
    }

    // ── 3. the false green the fix introduces if the NAMES do not travel ───────────────────────────────

    /**
     * A hash on this engine is {@code owner/name(desc)ret} — {@code app/Svc.call()V}. A policy scope is
     * written against the dotted NAME — {@code app.Svc}. Key the accumulators by hash without carrying the
     * name beside them and {@code scopeMatches} is handed a string no operator's scope can match: every
     * scoped rule silently stops binding, and a fix for a false green becomes a bigger false green.
     *
     * <p>Both directions are asserted, because "the scope matched" only means something if the same
     * machinery can also NOT match.
     */
    @Test
    void aPolicyScopeStillMatchesOnceTheKeysAreHashes() throws Exception {
        member("scoped", "a", List.of(
                entry("app.Svc.call", "app/Svc.call()V", List.of("Net"), List.of("Net"),
                        List.of(), List.of())));
        member("scoped", "b", List.of(
                entry("other.Thing.ping", "other/Thing.ping()V", List.of("Net"), List.of("Net"),
                        List.of(), List.of())));

        assertEquals(1, gate("scoped", policy("deny Net app.Svc\n")),
                "a scope written against the NAME must still bind the unit, whose KEY is a JVM descriptor");
        assertTrue(Candor.gateZeroMatch.isEmpty(),
                "…and the ⟨0.27⟩ zero-match disclosure — which counts matches over the SAME key set — must "
                + "not call that rule unbound");

        // THE OTHER DIRECTION, and it is the control: a scope that genuinely names nothing must still be
        // reported as binding nothing. Without it, "the scope matched" is equally consistent with a
        // matcher that says yes to everything. Exit stays 0 — ⟨0.27⟩ makes a zero-match rule a DISCLOSURE,
        // never a refusal, because one policy shared across repos legitimately has rules that bind here.
        assertEquals(0, gate("scoped", policy("deny Net nosuch.Layer\n")));
        assertEquals(List.of("deny Net nosuch.Layer"), Candor.gateZeroMatch,
                "a scope naming nothing is disclosed as bound-nothing — over hash keys, EVERY scope would "
                + "look like this one");
    }

    // ── 4. the row a machine consumer reads ───────────────────────────────────────────────────────────

    /**
     * §3.3.1 pins {@code gate --report}'s violation rows byte-equal to {@code scan --policy}'s, and the
     * scan route has only names to print. A row carrying {@code app/Svc.call()V} would break that
     * equality in the OTHER direction from the defect this rung is about.
     */
    @Test
    void theVerdictRowCarriesTheNameNotTheKey() throws Exception {
        member("row", "a", List.of(
                entry("app.Svc.call", "app/Svc.call()V", List.of("Net"), List.of("Net"),
                        List.of(), List.of())));
        Candor.gateCapture = true;
        assertEquals(1, gate("row", policy("deny Net\n")));
        assertEquals(1, Candor.gateViolations.size());
        assertEquals("app.Svc.call", Candor.gateViolations.get(0).get("fn"),
                "the row names the FUNCTION, never the unit key");
        assertTrue(String.valueOf(Candor.gateViolations.get(0).get("detail")).contains("`app.Svc.call`"),
                "…and so does the human-readable detail the same document carries");
    }
}
