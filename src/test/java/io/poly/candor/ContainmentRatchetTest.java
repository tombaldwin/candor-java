package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The `containment` AS-EFF-010 ratchet — the architecture-drift gate's exit-code contract: 1 when a boundary
 * effect enters a layer it wasn't in vs the baseline, 0 when unchanged/improved, 2 when the baseline can't be
 * read. (The cross-engine containment diagnostic is also gated by candor-spec conformance PART 11; this is the
 * fast in-engine guard on the gate verdict that fails CI.)
 */
class ContainmentRatchetTest {

    @TempDir
    Path tmp;

    // base: Fs lives only in `repo`; svc does Net. (Both effects present so the common layer prefix is `c`.)
    private static final String BASE = """
        {"functions":[
          {"fn":"c.repo.Repo.readA","direct":["Fs"]},
          {"fn":"c.repo.Repo.readB","direct":["Fs"]},
          {"fn":"c.svc.Svc.net","direct":["Net"]}
        ]}""";
    // current: svc has started touching the filesystem too — Fs drifted into a new layer.
    private static final String LEAK = """
        {"functions":[
          {"fn":"c.repo.Repo.readA","direct":["Fs"]},
          {"fn":"c.repo.Repo.readB","direct":["Fs"]},
          {"fn":"c.svc.Svc.net","direct":["Net"]},
          {"fn":"c.svc.Svc.leak","direct":["Fs"]}
        ]}""";

    private Path write(String name, String json) throws Exception {
        Path p = Files.createTempFile(tmp, name, ".json");
        Files.writeString(p, json);
        return p;
    }

    /** A boundary effect entering a new layer vs the baseline → AS-EFF-010, exit 1. */
    @Test
    void leakIntoNewLayerFailsTheRatchet() throws Exception {
        Path base = write("cbase", BASE);
        Path cur = write("ccur", LEAK);
        assertEquals(1, Query.containment(Query.load(cur.toString()), base.toString(), false),
            "Fs leaking into `svc` (absent in the baseline) must fail the ratchet (exit 1)");
    }

    /** No new layer (current == baseline) → clean, exit 0. */
    @Test
    void noNewLayerPassesTheRatchet() throws Exception {
        Path base = write("cbase2", LEAK);
        Path cur = write("ccur2", LEAK);
        assertEquals(0, Query.containment(Query.load(cur.toString()), base.toString(), false),
            "an unchanged layer map must pass the ratchet (exit 0)");
    }

    /** A boundary effect that LEFT a layer (cleanup, no new layer) is an improvement, not a regression → 0. */
    @Test
    void cleanupOnlyPassesTheRatchet() throws Exception {
        Path base = write("cbase3", LEAK);   // baseline had Fs in repo+svc
        Path cur = write("ccur3", BASE);     // now Fs only in repo — improved
        assertEquals(0, Query.containment(Query.load(cur.toString()), base.toString(), false),
            "an effect leaving a layer (no new leak) must not fail the ratchet (exit 0)");
    }

    /** An unreadable baseline must NOT silently pass as clean — it returns 2 (distinct from a 0 pass). */
    @Test
    void unreadableBaselineReturns2() throws Exception {
        Path cur = write("ccur4", LEAK);
        assertEquals(2, Query.containment(Query.load(cur.toString()), "/no/such/baseline.json", false),
            "an unreadable baseline must surface as exit 2, not a silent clean pass");
    }
}
