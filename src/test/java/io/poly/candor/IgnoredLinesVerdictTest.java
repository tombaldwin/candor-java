package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
 * ⟨0.28⟩ SPEC §6.2 "AND THE CONDITION IS A DROPPED LINE, NOT AN EMPTY POLICY" — the verdict document
 * carries {@code ignored: [ { line, text, reason } ]} for every policy line the parse dropped, omitted
 * when nothing was dropped.
 *
 * <p>The zero-rule refusal fires only at zero survivors, so the discontinuity was stark and the wrong way
 * round: {@code 0 of 10 rules parse → exit 2}; {@code 1 of 10 → {"ok": true, "violations": []}} and the
 * document says NOTHING about the nine gates that were never asked — a 90%-gateless green, arriving at
 * every fraction below 100%. MEASURED on the jar before this change (all four engines warn per dropped
 * line on stderr; every verdict document was silent). Refusal is the wrong remedy — it would break the
 * forward-compat leniency §6.2 defends — so DISCLOSURE is the remedy, on the machine channel.
 *
 * <p>Distinct from {@code unevaluated} and the distinction is load-bearing: {@code unevaluated} carries
 * rules that PARSED and could not be answered; {@code ignored} carries text that never became a rule at
 * all. No engine implemented it — a MUST with no consumer, the exact defect this rung spent a day on.
 */
class IgnoredLinesVerdictTest {

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

    private Path report(String name) throws Exception {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("fn", "app.repo.read");
        entry.put("loc", "X.java:1");
        entry.put("inferred", List.of("Fs"));
        entry.put("direct", List.of("Fs"));
        entry.put("declared", List.of());
        entry.put("undeclared", List.of());
        entry.put("overdeclared", List.of());
        entry.put("entryPoint", false);
        entry.put("unresolved", false);
        entry.put("hash", "");
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", 1, "digest", "0"));
        env.put("functions", List.of(entry));
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    private String[] gate(Path rep, Path pol) {
        out.reset();
        err.reset();
        int rc = Query.run(new String[]{"gate", "--report", rep.toString(),
                "--policy", pol.toString(), "--json"});
        return new String[]{out.toString(), err.toString(), String.valueOf(rc)};
    }

    @Test void aDroppedLineReachesTheVerdictDocument() throws Exception {
        // The sharp case is the GREEN verdict: `ok: true` over a policy where a gate was never asked.
        Path pol = tmp.resolve("p.policy");
        Files.writeString(pol, "# header\nfrobnicate the gate\ndeny Net app\n");
        String[] r = gate(report("a.app.jvm.json"), pol);
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertTrue(o.get("ok").getAsBoolean(), "the surviving rule passes — the exit posture is UNTOUCHED");
        assertEquals("0", r[2]);
        JsonObject row = o.getAsJsonArray("ignored").get(0).getAsJsonObject();
        assertEquals(2, row.get("line").getAsInt(), "1-based source line: " + r[0]);
        assertEquals("frobnicate the gate", row.get("text").getAsString(),
                "the source line, VERBATIM: " + r[0]);
        assertTrue(row.get("reason").getAsString().contains("unknown rule kind"),
                "the same reason the stderr warning names: " + r[0]);
    }

    @Test void theTextIsVerbatimIncludingAnInlineComment() throws Exception {
        // The parser matches on the comment-stripped, trimmed form; §6.2 pins the VERBATIM line — the
        // operator diffs the document against the file they wrote, not against the parser's view of it.
        Path pol = tmp.resolve("p2.policy");
        Files.writeString(pol, "deny Net app\n  frobnicate x  # a note\n");
        String[] r = gate(report("b.app.jvm.json"), pol);
        JsonObject row = JsonParser.parseString(r[0]).getAsJsonObject()
                .getAsJsonArray("ignored").get(0).getAsJsonObject();
        assertEquals("  frobnicate x  # a note", row.get("text").getAsString());
        assertEquals(2, row.get("line").getAsInt());
    }

    @Test void aCleanPolicysVerdictOmitsTheKeyEntirely() throws Exception {
        Path pol = tmp.resolve("clean.policy");
        Files.writeString(pol, "# fine\ndeny Net app\n");
        String[] r = gate(report("c.app.jvm.json"), pol);
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertFalse(o.has("ignored"),
                "omitted when nothing was dropped — a clean policy's verdict stays byte-identical: " + r[0]);
    }

    @Test void aFiringVerdictCarriesTheRowsToo() throws Exception {
        // The disclosure is about the POLICY, not the verdict direction — an exit-1 document carries it
        // identically ("a route is not covered by its sibling").
        Path pol = tmp.resolve("fire.policy");
        Files.writeString(pol, "frobnicate y\ndeny Fs app\n");
        String[] r = gate(report("d.app.jvm.json"), pol);
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertEquals("1", r[2], "deny Fs fires on app.repo.read");
        assertFalse(o.get("ok").getAsBoolean());
        assertEquals(1, o.getAsJsonArray("ignored").size(), r[0]);
        assertEquals(1, o.getAsJsonArray("violations").size(), r[0]);
    }

    @Test void ignoredIsDistinctFromUnevaluated() throws Exception {
        // One policy holding BOTH: a dropped line (never became a rule) and a `forbid` rule this verb
        // discloses as unevaluated (parsed, cannot be answered from a report). A `deny Fs` FIRES, so the
        // verdict is written (violation dominates refusal, §3.1) and must carry both lists — and the two
        // must not absorb each other.
        Path pol = tmp.resolve("both.policy");
        Files.writeString(pol, "frobnicate z\nforbid app -> infra\ndeny Fs app\n");
        String[] r = gate(report("e.app.jvm.json"), pol);
        JsonObject o = JsonParser.parseString(r[0]).getAsJsonObject();
        assertEquals("1", r[2], "the certain violation decides the exit: " + r[1]);
        assertEquals(1, o.getAsJsonArray("ignored").size(), r[0]);
        assertTrue(o.has("unevaluated"), r[0]);
        String unevalRule = o.getAsJsonArray("unevaluated").get(0).getAsJsonObject()
                .get("rule").getAsString();
        assertTrue(unevalRule.contains("forbid"),
                "`unevaluated` carries the rule that PARSED; `ignored` the text that never became one: " + r[0]);
    }
}
