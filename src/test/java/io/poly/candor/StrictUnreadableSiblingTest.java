package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.28⟩ #79 — SPEC §3.2: <i>"an INCOMPLETE report joins the 2 … `--strict` (the CI form) exits 2."</i>
 *
 * <p>MEASURED on the jar before this change, over a locator naming one good report and one unparsable
 * sibling:
 * <pre>
 *   gate --report r --policy P            exit 2   (refuses: a member did not load)
 *   unverified --report r --policy P --strict --json
 *       → {"unverified": [], "incomplete": true}    exit 0   ← the caveat KEYS travel; the EXIT is short
 * </pre>
 * The §3.2 pessimism relation makes that exit 0 a claim of having got further than the gate on identical
 * bytes — and `--strict` is exactly how CI consumes the verb. The DECLARED-`unanalyzed` cause already
 * exited 2; the unreadable-member cause is the same incompleteness one resolution step out
 * ({@code ReportCompleteness.incomplete()} covers both, and count-0 deliberately neither).
 */
class StrictUnreadableSiblingTest {

    @TempDir Path tmp;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private PrintStream priorOut, priorErr;

    @BeforeEach void capture() {
        priorOut = System.out;
        priorErr = System.err;
        System.setOut(new PrintStream(out, true));
        System.setErr(new PrintStream(err, true));
    }

    @AfterEach void restore() {
        System.setOut(priorOut);
        System.setErr(priorErr);
        Candor.resetState();
    }

    private static Map<String, Object> entry(String fn, List<String> inferred) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", fn);
        m.put("loc", "X.java:1");
        m.put("inferred", inferred);
        m.put("direct", inferred);
        m.put("declared", List.of());
        m.put("undeclared", List.of());
        m.put("overdeclared", List.of());
        m.put("entryPoint", false);
        m.put("unresolved", false);
        m.put("hash", "");
        return m;
    }

    /** One readable report + one unparsable sibling under the prefix `r`; returns the prefix locator. */
    private String goodPlusUnparsable() throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", 3, "digest", "0"));
        env.put("functions", List.of(entry("app.repo.read", List.of("Fs"))));
        Files.writeString(tmp.resolve("r.A.jvm.json"), io.poly.candor.model.ReportJson.pretty(env));
        Files.writeString(tmp.resolve("r.B.jvm.json"), "{ \"candor\": { \"spec\": \"0.27\" }, \"functio");
        return tmp.resolve("r").toString();
    }

    private Path policy(String text) throws Exception {
        Path p = tmp.resolve("p.policy");
        Files.writeString(p, text);
        return p;
    }

    private String[] run(String... args) {
        out.reset();
        err.reset();
        int rc = Query.run(args);
        return new String[]{out.toString(), err.toString(), String.valueOf(rc)};
    }

    @Test void unverifiedStrictExitsTwoOverAnUnreadableSibling() throws Exception {
        String loc = goodPlusUnparsable();
        Path pol = policy("deny Net app\n");
        String[] r = run("unverified", "--report", loc, "--policy", pol.toString(), "--strict", "--json");
        assertEquals("2", r[2],
                "the gate exits 2 over these bytes, and an advisory verb may be LESS certain than the "
                + "gate, never MORE — `--strict` is the CI form (SPEC §3.2 ⟨0.24⟩, #79)");
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.get("incomplete").getAsBoolean(), "the caveat keys travel, as they already did: " + r[0]);
    }

    @Test void fixGateStrictExitsTwoOverAnUnreadableSibling() throws Exception {
        String loc = goodPlusUnparsable();
        Path pol = policy("deny Net app\n");
        String[] r = run("fix-gate", "--report", loc, "--policy", pol.toString(), "--strict", "--json");
        assertEquals("2", r[2], "the same §3.2 law binds every advisory verb that answers `ok`");
    }

    @Test void fixGateStrictExitsTwoEvenBesideAFoundCrossing() throws Exception {
        // Could-not-fully-evaluate OUTRANKS found-a-crossing (the ⟨0.24⟩ precedence): a plan EXISTS here
        // (deny Fs fires on the readable member) and the unreadable sibling still moves the exit to 2.
        String loc = goodPlusUnparsable();
        Path pol = policy("deny Fs app\n");
        String[] r = run("fix-gate", "--report", loc, "--policy", pol.toString(), "--strict", "--json");
        assertEquals("2", r[2], "measured pre-change as exit 1 — a red check that reads as an ordinary "
                + "crossing while the report set is not even readable: " + r[0]);
    }

    @Test void theHumanArmMovesWithTheJsonArm() throws Exception {
        String loc = goodPlusUnparsable();
        Path pol = policy("deny Net app\n");
        assertEquals("2", run("unverified", "--report", loc, "--policy", pol.toString(), "--strict")[2],
                "the exit is a property of the run, not of the output format");
        assertEquals("2", run("fix-gate", "--report", loc, "--policy", pol.toString(), "--strict")[2]);
    }

    @Test void withoutStrictTheExitStaysZero() throws Exception {
        // Control: the verbs stay ADVISORY — the disclosure travels, the plain exit does not move.
        String loc = goodPlusUnparsable();
        Path pol = policy("deny Net app\n");
        assertEquals("0", run("unverified", "--report", loc, "--policy", pol.toString(), "--json")[2]);
        assertEquals("0", run("fix-gate", "--report", loc, "--policy", pol.toString(), "--json")[2]);
    }

    @Test void aReadableSetUnderStrictIsUntouched() throws Exception {
        // Control: no unreadable member, no declared manifest → --strict answers as before (exit 0 clean).
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", 3, "digest", "0"));
        env.put("functions", List.of(entry("app.repo.read", List.of("Fs"))));
        Files.writeString(tmp.resolve("ok.app.jvm.json"), io.poly.candor.model.ReportJson.pretty(env));
        Path pol = policy("deny Net app\n");
        assertEquals("0", run("unverified", "--report", tmp.resolve("ok.app.jvm.json").toString(),
                "--policy", pol.toString(), "--strict", "--json")[2]);
    }
}
