package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * §2.2 ⟨0.24⟩ — THE RESERVED SIDECAR SEGMENTS, AND WHY THE SHORT LIST WAS A LIVE LOSS RATHER THAN A
 * COSMETIC ONE.
 *
 * <p>The spec enumerates the reserved trailing segments family-wide — {@code callgraph}, {@code hierarchy},
 * {@code calibrated}, {@code layerreach}, {@code locs}, {@code gate}, and the {@code encountered-*} family
 * — because the engines were drifting: this one excluded two of them, candor-ts six. Cross-engine reading
 * is not hypothetical (the conformance frontier differential has one engine produce and another consume),
 * so a consumer with the shorter list claims another engine's sidecar as a report.
 *
 * <p><b>Measured on this engine before the fix, in a directory holding a real report and two foreign
 * sidecars.</b> It is not a warning; it is the whole query surface:
 *
 * <pre>
 *   candor map
 *   candor: locator `…/.candor/report` matches 3 reports; using …/report.asm.gate.json
 *   candor: cannot read report …/report.asm.gate.json (not a candor report: object has no 'functions' array)
 * </pre>
 *
 * Two losses in three lines. A FALSE AMBIGUITY DISCLOSURE (three reports, where there is one), and then
 * the engine picks a sidecar — {@code gate} sorts before {@code jvm}, and the resolver takes the
 * lexicographically first hit — and REFUSES every query with a parse complaint about a file the user never
 * named, while the report it wanted sits beside it. That is java's form of the reference engine's
 * "refusing to report an empty all-clear over a corrupt report": exit 2 and no answer, over data that is
 * intact. The reference engine's other two consequences do NOT apply here — this engine reads provenance
 * from the report it resolved rather than from the first file by sorted path, and it has no {@code reports}
 * verb to mislist.
 *
 * <p>The exclusion is a DENYLIST over the reserved segment and must stay one. The inversion — accept only
 * known backends — is an ALLOWLIST, and a report whose type segment nobody anticipated becomes silently
 * invisible to every query: a false all-clear. A denylist can only be incomplete, and incompleteness here
 * is LOUD (the unregistered suffix falls into the candidate set and the locator discloses it).
 */
class SidecarIsNotAReportTest {

    /** A minimal but genuine report: the shape {@code Query.load} accepts. */
    private static final String REPORT =
            "{\"candor\":{\"version\":\"t\",\"spec\":\"0.24\"},\"functions\":["
            + "{\"fn\":\"app.Svc.save\",\"inferred\":[\"Db\"],\"direct\":[\"Db\"]}]}";

    private static Path dir(String... files) throws Exception {
        Path base = Files.createTempDirectory("candor-sidecar");
        Path c = base.resolve(".candor");
        Files.createDirectories(c);
        for (int i = 0; i < files.length; i += 2) Files.writeString(c.resolve(files[i]), files[i + 1]);
        return base;
    }

    private static String resolved(Path base) {
        return Query.resolveReportLocator(base.resolve(".candor").resolve("report").toString());
    }

    /**
     * THE DEFECT. Every reserved segment the spec names, each one sitting beside the real report, each one
     * asserted SEPARATELY — a fix that happened to cover the two that sort first would pass a single
     * combined assertion. {@code gate}/{@code calibrated}/{@code encountered-*} all sort BEFORE {@code jvm},
     * so under the old two-suffix list they were not merely counted, they were CHOSEN.
     */
    @Test
    void everyReservedSegmentIsExcludedFromPrefixDiscovery() throws Exception {
        for (String seg : new String[]{"callgraph", "hierarchy", "calibrated", "layerreach", "locs", "gate",
                                       "encountered-hosts"}) {
            Path base = dir("report.asm.jvm.json", REPORT,
                            "report.asm." + seg + ".json", "{\"not\":\"a report\"}");
            try {
                assertEquals(base.resolve(".candor").resolve("report.asm.jvm.json").toString(), resolved(base),
                        "`" + seg + "` is a RESERVED sidecar segment (§2.2) — the real report must be the "
                        + "one and only hit, and the resolver must not be able to pick the sidecar over it");
                assertEquals(1, Query.prefixHits(base.resolve(".candor").resolve("report").toString()).size(),
                        "…and the candidate set must hold exactly one file, or the locator discloses an "
                        + "ambiguity that does not exist");
            } finally { rm(base); }
        }
    }

    /**
     * THE CONTROL. The word is reserved in the SIDECAR SEGMENT POSITION, not banned from the name — a
     * package legitimately called {@code hierarchy} or {@code gate} sits in the {@code <crate>} position and
     * must still resolve. Without this the fix would be indistinguishable from banning the word outright,
     * which silently hides a real report: the false all-clear the denylist exists to avoid.
     */
    @Test
    void aPackageNamedAfterAReservedWordStillResolves() throws Exception {
        for (String crate : new String[]{"hierarchy", "gate", "locs", "callgraph"}) {
            Path base = dir("report." + crate + ".jvm.json", REPORT);
            try {
                assertEquals(base.resolve(".candor").resolve("report." + crate + ".jvm.json").toString(),
                        resolved(base),
                        "a crate NAMED `" + crate + "` is not a sidecar — the reserved position is the "
                        + "trailing segment, and this word is in the <crate> one");
                assertTrue(Query.quietPrefixMatches(base.resolve(".candor").resolve("report").toString()),
                        "and the quiet probe must agree with the resolver — two lists that can drift apart "
                        + "is how the short list survived");
            } finally { rm(base); }
        }
    }

    /** The two globs answer from ONE rule, so they cannot disagree about one file — which is the shape of
     *  the defect the spec describes (a sidecar loader and a report locator disagreeing inside one binary).
     *  Asserted over the full reserved set plus the shapes that must stay reports. */
    @Test
    void bothGlobsAgreeAndTheRuleIsOneRule() throws Exception {
        for (String name : new String[]{"report.a.callgraph.json", "report.a.hierarchy.json",
                "report.a.calibrated.json", "report.a.layerreach.json", "report.a.locs.json",
                "report.a.gate.json", "report.encountered-x.jvm.json"})
            assertTrue(Loader.isSidecarName(name), name + " must read as a sidecar");
        for (String name : new String[]{"report.a.jvm.json", "report.a.scan.json", "report.json",
                "report.hierarchy.jvm.json", "report.gate.scan.json", "report.a.somefutureengine.json"})
            assertEquals(false, Loader.isSidecarName(name), name + " must read as a REPORT — an unregistered "
                    + "backend segment falls into the candidate set (loud), never out of it (silent)");

        // The two globs, on one directory holding one report and one sidecar of every reserved kind.
        Path base = dir("report.a.jvm.json", REPORT,
                        "report.a.callgraph.json", "{}", "report.a.hierarchy.json", "{}",
                        "report.a.calibrated.json", "{}", "report.a.layerreach.json", "{}",
                        "report.a.locs.json", "{}", "report.a.gate.json", "{}",
                        "report.a.encountered-hosts.json", "{}");
        try {
            String prefix = base.resolve(".candor").resolve("report").toString();
            assertEquals(java.util.List.of(base.resolve(".candor").resolve("report.a.jvm.json").toString()),
                    Query.prefixHits(prefix),
                    "seven sidecars and one report: the candidate set is the report, alone");
            assertTrue(Query.quietPrefixMatches(prefix), "and the quiet probe finds it");
        } finally { rm(base); }
    }

    /** A directory holding ONLY sidecars has no report, and must say so rather than claim one. The
     *  fail-loud direction: `quietPrefixMatches` false, `resolveReportLocator` null (its caller prints the
     *  not-found reason and exits 2). */
    @Test
    void aDirectoryOfOnlySidecarsNamesNoReport() throws Exception {
        Path base = dir("report.a.callgraph.json", "{}", "report.a.gate.json", "{}",
                        "report.a.locs.json", "{}");
        java.io.PrintStream saved = System.err;
        try {
            System.setErr(new java.io.PrintStream(java.io.OutputStream.nullOutputStream(), true,
                    java.nio.charset.StandardCharsets.UTF_8));
            assertEquals(null, resolved(base), "no report here — and the engine must not adopt a sidecar as one");
            assertEquals(false, Query.quietPrefixMatches(base.resolve(".candor").resolve("report").toString()));
        } finally { System.setErr(saved); rm(base); }
    }
}
