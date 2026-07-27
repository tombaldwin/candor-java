package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * {@code callers --include-unknown} ⟨0.7⟩ — the unresolved-dispatch frontier. The confirmed transitive
 * callers never include a function that reaches the target only through a dispatch candor declined to
 * resolve (an unresolved dispatch, `dispatch:`, disclosed as Unknown). The flag discloses
 * those "MAY also reach" functions — a function F carrying {@code dispatch:OWNER.M} is listed iff a
 * confirmed reacher is an override of OWNER.M (same method name AND a subtype of OWNER per the hierarchy).
 * The subtype check makes it precise; with no hierarchy it falls back to a simple-name match (over-lists).
 * Default output (no flag) stays byte-for-byte unchanged.
 */
class QueryIncludeUnknownTest {

    // app.Impl.run -> app.Sink.touch is the only resolved edge; app.Frontier.go's real (broad) call was
    // dropped to Unknown. app.Impl is a subtype of app.Base.
    private static Map<String, List<String>> graph() {
        Map<String, List<String>> cg = new TreeMap<>();
        cg.put("app.Impl.run", List.of("app.Sink.touch"));
        cg.put("app.Sink.touch", List.of());
        cg.put("app.Frontier.go", List.of());
        // A function in the graph that carries NO dispatch reason at all — the control candidate for the
        // ⟨0.24⟩ dot-free rule below. It reaches nothing and is not a broad-dispatch source, so it changes
        // no existing expectation; it must never appear in the frontier.
        cg.put("app.Quiet.idle", List.of());
        return cg;
    }

    private static Map<String, List<String>> hierarchy() {
        return Map.of("app.Impl", List.of("app.Base")); // Impl <: Base
    }

    @Test void disclosesFrontierWhenDispatchOwnerMatches() {
        // Frontier.go broad-dispatches app.Base.run; the confirmed reacher app.Impl.run IS an override
        // of Base.run (Impl <: Base) -> go MAY reach the target.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("app.Base.run"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, hierarchy()));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertTrue(o.getAsJsonArray("transitive").toString().contains("app.Impl.run"));
        var poss = o.getAsJsonArray("possibleViaUnknownDispatch");
        assertEquals(1, poss.size(), "the broad-dispatch frontier function is disclosed");
        assertEquals("app.Frontier.go", poss.get(0).getAsJsonObject().get("fn").getAsString());
        assertEquals("run", poss.get(0).getAsJsonObject().get("viaDispatchOn").getAsString());
    }

    @Test void precisionDropsUnrelatedSameNamedDispatch() {
        // Frontier.go broad-dispatches app.Unrelated.run. The only confirmed reacher with method `run`
        // is app.Impl.run, and Impl is NOT a subtype of Unrelated -> the dispatch cannot land on it ->
        // NOT disclosed. (A bare simple-name match would wrongly list it; the hierarchy check prevents that.)
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("app.Unrelated.run"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, hierarchy()));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(0, o.getAsJsonArray("possibleViaUnknownDispatch").size(),
                "an unrelated same-named dispatch is not disclosed when the hierarchy rules it out");
    }

    @Test void fallsBackToSimpleNameWithoutHierarchy() {
        // Same unrelated dispatch, but no hierarchy sidecar (hier == null) -> simple-name match -> the
        // documented over-list (safe direction). Confirms graceful degradation.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("app.Unrelated.run"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, null));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(1, o.getAsJsonArray("possibleViaUnknownDispatch").size(),
                "no hierarchy -> simple-name match over-lists (lower-bound disclosure, safe direction)");
    }

    @Test void confirmedCallerIsNotRelistedAsPossible() {
        Map<String, Set<String>> broad = Map.of("app.Impl.run", Set.of("app.Sink.touch"));
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, hierarchy()));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertEquals(0, o.getAsJsonArray("possibleViaUnknownDispatch").size(),
                "a confirmed caller is not re-listed as a possible reacher");
    }

    // ---- ⟨0.24⟩ the DOT-FREE `dispatch:` detail ---------------------------------------------------

    /** The frontier entries as `fn -> viaDispatchOn`, for one run of the query. */
    private static Map<String, String> frontier(Map<String, Set<String>> broad,
                                                Map<String, List<String>> hier) {
        String out = capture(() ->
                Query.callersViaCallgraph(graph(), "app.Sink.touch", true, broad, hier));
        Map<String, String> m = new TreeMap<>();
        for (var el : JsonParser.parseString(out).getAsJsonObject()
                .getAsJsonArray("possibleViaUnknownDispatch"))
            m.put(el.getAsJsonObject().get("fn").getAsString(),
                    el.getAsJsonObject().get("viaDispatchOn").getAsString());
        return m;
    }

    @Test void dotFreeDispatchDetailIsDisclosedVerbatimInBothArms() {
        // MEASURED BEFORE THE FIX: `dispatch:untyped cross-package receiver` (candor-rust's reason when no
        // owner type could be formed at all) was SILENTLY DROPPED in BOTH arms, with no diagnostic. With no
        // dot there is no OWNER and no M, so condition (3) — "is a confirmed reacher an override of OWNER.M?"
        // — is UNANSWERABLE, and an unanswerable condition must not be scored as a failed one (SPEC §3.1
        // ⟨0.24⟩). Disclose it with the RAW DETAIL verbatim. The CONTROL rides in the same call: a dotted
        // `app.Unrelated.run` that genuinely FAILS condition (3) stays OUT under the hierarchy, so this is a
        // fix and not a blanket.
        String dotFree = "untyped cross-package receiver";
        Map<String, Set<String>> broad = new TreeMap<>(Map.of(
                "app.Frontier.go", Set.of(dotFree),
                "app.Frontier.other", Set.of("app.Unrelated.run"),   // CONTROL: dotted, fails condition (3)
                "app.Frontier.hit", Set.of("app.Base.run")));        // dotted, PASSES condition (3)

        Map<String, String> withHier = frontier(broad, hierarchy());
        assertEquals(dotFree, withHier.get("app.Frontier.go"),
                "hierarchy arm: the dot-free source is disclosed with the raw detail verbatim");
        assertTrue(withHier.containsKey("app.Frontier.hit"), "the genuine dotted override is still disclosed");
        assertFalse(withHier.containsKey("app.Frontier.other"),
                "CONTROL: a dotted dispatch that fails the subtype test must still be OUT — "
                        + "disclosing the unanswerable case must not become disclosing everything");

        Map<String, String> noHier = frontier(broad, null);
        assertEquals(dotFree, noHier.get("app.Frontier.go"),
                "no-hierarchy arm: same — the dot-free source is disclosed with the raw detail verbatim");
        assertTrue(noHier.containsKey("app.Frontier.other"),
                "and the documented simple-name over-list still applies to the dotted ones here");
    }

    @Test void aFunctionWithNoDispatchReasonIsNeverAFrontierSource() {
        // CONTROL 2: `app.Quiet.idle` exists in the graph but carries no `dispatch:` reason at all, so it is
        // absent from broadByFn. It must not appear however permissive the dot-free rule is.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("untyped cross-package receiver"));
        for (Map<String, List<String>> h : java.util.Arrays.asList(hierarchy(), null, Map.<String, List<String>>of())) {
            Map<String, String> f = frontier(broad, h);
            assertEquals(Set.of("app.Frontier.go"), f.keySet(),
                    "only a function that CARRIES a dispatch reason is ever a frontier source");
        }
    }

    @Test void dotFreeDetailCollidingWithAReacherSimpleNameIsStillJustTheRawDetail() {
        // THE FALSE-POSITIVE LANE, checked rather than reasoned away: `simpleMethod`/`declaringType` BOTH
        // fall back to the WHOLE string when there is no dot, so a dot-free detail that happens to equal a
        // confirmed reacher's simple method name (`run`, from `app.Impl.run`) used to match by accident —
        // disclosed in the no-hierarchy arm, dropped in the hierarchy arm (isSubtypeOf("app.Impl","run") is
        // false). The structural dot-free branch runs BEFORE that lookup, so the accidental lane is no longer
        // reachable: both arms now disclose it, labelled with the raw detail, exactly like any other dot-free
        // detail. No new false positive — the label was already the raw string — and no arm-dependent answer.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("run"));
        assertEquals("run", frontier(broad, hierarchy()).get("app.Frontier.go"));
        assertEquals("run", frontier(broad, null).get("app.Frontier.go"));
    }

    @Test void anEmptyHierarchySidecarIsTheSameInputAsAnAbsentOne() {
        // MEASURED BEFORE THE FIX: the guard was `hier == null`, so a sidecar that exists and parses to `{}`
        // was NON-null and honoured as a real hierarchy — `isSubtypeOf` then failed for every type, condition
        // (3) failed for every dotted source, and the frontier collapsed to EMPTY. `{}` is not the claim "no
        // type has a supertype"; it is the hierarchy pass finding nothing / not running / writing a stub, and
        // scoring condition (3) as FAILED on it turns a disclosed over-list into a silent empty answer. rust
        // (`has_hier`, callers.rs) and ts (`hasHier`, query-core.mjs) already treat empty == absent; java now
        // agrees. All three arms asserted so the distinction cannot silently come back.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("app.Unrelated.run"));
        assertEquals(Set.of(), frontier(broad, hierarchy()).keySet(),
                "POPULATED sidecar: the subtype test is answerable and rules this one out");
        assertEquals(Set.of("app.Frontier.go"), frontier(broad, null).keySet(),
                "ABSENT sidecar: unanswerable -> simple-name over-list");
        assertEquals(Set.of("app.Frontier.go"), frontier(broad, Map.of()).keySet(),
                "EMPTY `{}` sidecar: the SAME unanswerable input as absent -> the same over-list, never []");
    }

    @Test void defaultOutputUnchangedWithoutFlag() {
        String out = capture(() -> Query.callersViaCallgraph(graph(), "app.Sink.touch", true, null, null));
        JsonObject o = JsonParser.parseString(out).getAsJsonObject();
        assertFalse(o.has("possibleViaUnknownDispatch"),
                "no flag -> no possibleViaUnknownDispatch key (cross-engine parity preserved)");
    }

    @Test void aSidecarSiblingKeyDoesNotDiscardTheWholeHierarchy() throws Exception {
        // THE SECOND READER. `ReportWriter.writeHierarchy` gained a sibling key whose value is an OBJECT,
        // and the compatibility argument for it — "the reader skips any non-array value" — was true of
        // `Loader.loadDepHierarchy` and untrue HERE: `getAsJsonArray()` throws on an object, the catch
        // returns null, and the WHOLE hierarchy is discarded, dropping the dispatch frontier back to a bare
        // simple-name match. Nothing in the suite could see it. Mutate the `isJsonArray` skip out of
        // `Query.loadHierarchy` and this test fails.
        java.nio.file.Path base = java.nio.file.Files.createTempDirectory("candor-side");
        try {
            java.nio.file.Path rep = base.resolve("r.json");
            java.nio.file.Files.writeString(rep, "{\"candor\":{},\"functions\":[]}");
            // BOTH shapes, because they are skipped by DIFFERENT guards. The OBJECT is the 0.23.1 shape and
            // is caught by the non-array skip; the ARRAY is what the writer emits now (so candor-rust's
            // strictly typed reader does not discard the whole file), and it is caught ONLY by the
            // reserved-`@`-namespace skip. Mutate either guard out of `Query.loadHierarchy` and this fails.
            for (String marker : List.of("{\"app.Impl\": \"app.Base\"}", "[\"app.Impl\", \"app.Base\"]")) {
                java.nio.file.Files.writeString(base.resolve("r.hierarchy.json"),
                        "{\"app.Impl\": [\"app.Base\"], \"" + ReportWriter.SUPERCLASS_KEY
                                + "\": " + marker + ", \"app.Other\": [\"app.Base\"]}");
                Map<String, List<String>> h = Query.loadHierarchy(rep.toString());
                assertTrue(h != null, "one unreadable sibling key discarded the entire hierarchy: " + marker);
                assertEquals(List.of("app.Base"), h.get("app.Impl"), "the class keys must survive: " + marker);
                assertEquals(List.of("app.Base"), h.get("app.Other"),
                        "a class key AFTER the sibling key must survive too — the loop must skip, not abort");
                assertFalse(h.containsKey(ReportWriter.SUPERCLASS_KEY),
                        "the sibling key must not become a phantom TYPE in the subtype walk: " + marker);
            }
        } finally {
            TestCompiler.rm(base);
        }
    }

    private static String capture(Runnable r) {
        PrintStream orig = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buf));
        try {
            r.run();
        } finally {
            System.setOut(orig);
        }
        return buf.toString();
    }
}
