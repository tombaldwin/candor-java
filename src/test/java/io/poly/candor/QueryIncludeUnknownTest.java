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
import java.util.TreeSet;
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
        return frontier(graph(), broad, hier);
    }

    private static Map<String, String> frontier(Map<String, List<String>> cg,
                                                Map<String, Set<String>> broad,
                                                Map<String, List<String>> hier) {
        String out = capture(() ->
                Query.callersViaCallgraph(cg, "app.Sink.touch", true, broad, hier));
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

    @Test void dotFreeDetailCollidingWithAReacherSimpleNameIsDisclosedIDENTICALLYInBothArms() {
        // SPEC §3.1 ⟨0.24⟩ hazard 2, the ARM-DEPENDENCE — the shape that makes the short-circuit a MUST
        // rather than a style note, and the reason it must run BEFORE the owner/member split.
        // `simpleMethod`/`declaringType` BOTH fall back to the WHOLE string when there is no dot, so the
        // override test degenerates into string equality between a reason detail and a function name.
        // MEASURED BEFORE THE FIX on `dispatch:run` against the confirmed reacher `app.Impl.run`:
        //   no-hierarchy arm  -> DISCLOSED  (byMethod.get("run") hits, and with no sidecar that is enough)
        //   hierarchy arm     -> DROPPED    (isSubtypeOf("app.Impl", "run") — "run" is not a type — is false)
        // Same input, opposite outputs, decided by nothing but whether a sidecar happens to exist. The
        // structural branch short-circuits before `simpleMethod`, before `declaringType` and before
        // `reacherTypesByMethod` is consulted at all, so neither arm can reach that lane: both now disclose
        // it with the raw detail. Asserted as a WHOLE-FRONTIER equality, not two lookups — the arms must be
        // indistinguishable, not merely both non-empty.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("run"));
        Map<String, String> withHier = frontier(broad, hierarchy());
        assertEquals(Map.of("app.Frontier.go", "run"), withHier, "hierarchy arm: disclosed, raw detail");
        assertEquals(withHier, frontier(broad, null), "no-hierarchy arm must be IDENTICAL, not arm-dependent");
        assertEquals(withHier, frontier(broad, Map.of()), "empty-sidecar arm must be identical too");
    }

    @Test void dotFreeDetailEqualToAWholeReacherQualIsDisclosedForTheRIGHTReason() {
        // SPEC §3.1 ⟨0.24⟩ hazard 1, RIGHT FOR THE WRONG REASON. JVM quals are dotted, so a detail equal to
        // a whole qual is normally dotted and never reaches this branch — but the query also reads reports
        // written by other producers, and a report CAN carry a dot-free unit name (a top-level `main`). Then
        // detail == qual == owner == member, and the pre-fix subtype check passed by REFLEXIVITY
        // (isSubtypeOf("main","main") is true before the sidecar is even opened) — a match over a string that
        // is not a type name, landing the right answer for a reason that would not survive any change to the
        // detail's wording. Measured pre-fix: disclosed in BOTH arms, so the OUTPUT was already correct here
        // and this test cannot distinguish the fix by output alone — that is the point of the shape, and why
        // the guard against it is structural placement rather than an output assertion. What is pinned is
        // that the answer stays correct and arm-independent once the reflexive accident is gone.
        Map<String, List<String>> cg = new TreeMap<>(graph());
        cg.put("main", List.of("app.Sink.touch")); // a DOT-FREE confirmed reacher
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", Set.of("main"));
        Map<String, String> withHier = frontier(cg, broad, hierarchy());
        assertEquals(Map.of("app.Frontier.go", "main"), withHier);
        assertEquals(withHier, frontier(cg, broad, null));
        assertEquals(withHier, frontier(cg, broad, Map.of()));
        // ...and the reflexive lane is genuinely gone rather than merely agreeing: a DOTTED detail whose
        // owner is that same dot-free reacher name still has to pass the real subtype test, and fails it.
        assertEquals(Map.of(), frontier(cg, Map.of("app.Frontier.go", Set.of("main.run")), hierarchy()),
                "CONTROL: `main.run` is dotted -> owner `main`, member `run`; app.Impl is not a subtype of "
                        + "`main`, so the subtype test still decides it and it stays OUT");
    }

    /** The mixed-source graph: TWO confirmed reachers with different simple names, so two dotted reasons
     *  can both pass condition (3) and be joined with a dot-free one. `write` is here to sort AFTER the
     *  dot-free detail — see the test. */
    private static Map<String, List<String>> mixedGraph() {
        Map<String, List<String>> cg = new TreeMap<>();
        cg.put("app.Impl.run", List.of("app.Sink.touch"));
        cg.put("app.Zed.write", List.of("app.Sink.touch"));
        cg.put("app.Sink.touch", List.of());
        cg.put("app.Frontier.go", List.of());
        return cg;
    }

    @Test void aMixedSourceJoinsTheUnionSortedAndDeduplicated() {
        // SPEC §3.1 ⟨0.24⟩: one function carrying SEVERAL `dispatch:` reasons gets ONE entry, whose
        // `viaDispatchOn` is the SORTED, DEDUPLICATED, comma-joined union of the dispatched members (`M`, per
        // dotted reason that passed condition (3)) and the RAW DETAILS (per dot-free one). Sorted and
        // deduplicated precisely so two engines cannot drift on a field neither of them re-parses — and the
        // cross-impl differential only does a SUBSTRING check on this field, so it cannot catch a drift here.
        // This asserts the LITERAL string.
        //
        // The fixture is built so encounter order and sort order DISAGREE: `write` sorts AFTER the dot-free
        // detail, so the expected string INTERLEAVES the two kinds. A "dotted members first, then dot-free"
        // join, or any encounter-order join, produces a different literal and fails here.
        Map<String, List<String>> hier = Map.of("app.Impl", List.of("app.Base"), "app.Zed", List.of("app.Base"));
        Map<String, Set<String>> broad = Map.of("app.Frontier.go", new java.util.LinkedHashSet<>(
                List.of("untyped cross-package receiver",  // dot-free    -> the raw detail
                        "app.Base.write",                  // dotted, app.Zed  <: app.Base -> `write`
                        "app.Base.run")));                 // dotted, app.Impl <: app.Base -> `run`
        assertEquals(Map.of("app.Frontier.go", "run,untyped cross-package receiver,write"),
                frontier(mixedGraph(), broad, hier),
                "one entry; the union sorted by code point, comma-joined, kinds interleaved");
    }

    @Test void theJoinSortsByCODEPOINTNotUtf16CodeUnit() {
        // SPEC §3.1 ⟨0.24⟩: "sorted" means by UNICODE CODE POINT, equivalently UTF-8 byte order. Java's
        // NATURAL String order is by UTF-16 CODE UNIT, so `new TreeSet<>()` did NOT conform: it agrees with
        // code-point order on ASCII (which is why the literal above is unaffected) and disagrees above the
        // BMP. Reachable, not theoretical — the dotted form is <owner>.<member>, built from USER IDENTIFIERS,
        // and all four analysed languages permit non-ASCII ones. Both members below are letters, so this is a
        // real identifier pair rather than a synthetic string.
        //
        // THE FIXTURE HAS TO DISTINGUISH THE TWO ORDERS or it pins nothing:
        //   MATH = U+1D400 MATHEMATICAL BOLD CAPITAL A — supplementary, stored as the pair D835 DC00
        //   LIG  = U+FB00  LATIN SMALL LIGATURE FF     — BMP, above the surrogate block
        // UTF-16 code unit: 0xD835  < 0xFB00 -> MATH first — the old, non-conforming answer
        // code point:       0x1D400 > 0xFB00 -> LIG  first — what ⟨0.24⟩ requires
        // Restore `new TreeSet<>()` in Query and this fails on exactly that flip.
        String math = new String(Character.toChars(0x1D400));
        String lig = "ﬀ";
        Map<String, List<String>> cg = new TreeMap<>();
        cg.put("app.Impl." + math, List.of("app.Sink.touch"));
        cg.put("app.Zed." + lig, List.of("app.Sink.touch"));
        cg.put("app.Sink.touch", List.of());
        cg.put("app.Frontier.go", List.of());
        Map<String, List<String>> hier = Map.of("app.Impl", List.of("app.Base"), "app.Zed", List.of("app.Base"));
        Map<String, Set<String>> broad = Map.of("app.Frontier.go",
                new java.util.LinkedHashSet<>(List.of("app.Base." + math, "app.Base." + lig)));
        assertEquals(Map.of("app.Frontier.go", lig + "," + math), frontier(cg, broad, hier),
                "the join must be in CODE POINT order (U+FB00 before U+1D400), not UTF-16 code-unit order");
    }

    @Test void aLoneSurrogateDetailIsNotCollapsedIntoAnother() {
        // WHY THE COMPARATOR IS CODE-POINT-WISE AND NOT OVER `getBytes(UTF_8)` — the shorter spelling of the
        // SAME order. A TreeSet treats compare == 0 as a DUPLICATE, and UTF-8 encoding is LOSSY on an
        // unpaired surrogate: every one of them encodes to `?`. Under a byte-array comparator these two
        // distinct details compare EQUAL and one is silently DROPPED from the join — a conformance fix
        // reintroducing the very drop class this rung exists to close, in the one place the rung is about.
        // Code-point decomposition is injective over char sequences, so both survive.
        assertTrue(Query.BY_CODE_POINT.compare("\uD800", "\uDC00") < 0,
                "distinct lone surrogates must not compare EQUAL — equal means duplicate, means dropped");
        TreeSet<String> set = new TreeSet<>(Query.BY_CODE_POINT);
        set.add("\uDC00");
        set.add("\uD800");
        assertEquals(2, set.size(), "both survive the set the join is built from");

        // End-to-end the COUNT is what can be asserted, not the identity: a lone surrogate is not
        // representable in UTF-8 at all, so the test's byte-stream capture — and the JSON wire itself —
        // replaces each one with `?` (measured: `?,?`). That lossiness is a property of the output channel
        // and no comparator can change it. The collapse hazard is about CARDINALITY, and cardinality is
        // exactly what survives: two elements, not one.
        Map<String, Set<String>> broad = Map.of("app.Frontier.go",
                new java.util.LinkedHashSet<>(List.of("\uDC00", "\uD800"))); // lone LOW then lone HIGH
        assertEquals(2, frontier(broad, hierarchy()).get("app.Frontier.go").split(",", -1).length,
                "two distinct details must BOTH be listed — never collapsed into one");
    }

    @Test void twoDottedReasonsOnTheSameMemberYieldThatMemberOnce() {
        // DEDUPLICATION, its own case: two DISTINCT dotted reasons whose member name is the same `M` collapse
        // to one `M`. `app.Impl` is a subtype of BOTH `app.Base` and `app.Other`, so `app.Base.run` and
        // `app.Other.run` both pass condition (3) and both contribute `run` — it must appear ONCE. (Two
        // identical raw details cannot arise: the per-function reason collection is already a set upstream.)
        Map<String, List<String>> hier = Map.of("app.Impl", List.of("app.Base", "app.Other"));
        Map<String, Set<String>> broad = Map.of("app.Frontier.go",
                new java.util.LinkedHashSet<>(List.of("app.Base.run", "app.Other.run")));
        assertEquals(Map.of("app.Frontier.go", "run"), frontier(broad, hier),
                "the same member reached through two owners is listed once, not `run,run`");
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
