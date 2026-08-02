package io.poly.candor;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.21⟩ The completeness manifest (COMPLETENESS-MANIFEST-DESIGN.md): distinguish provably-pure from
 * never-seen, and make incompleteness MACHINE-legible so a --gate-json/agent consumer can't read `ok:true`
 * over source candor never analyzed.
 *
 * <ul>
 *   <li>Gap 1 — the report envelope + gate verdict carry `analyzed:{count,digest}` / `analyzed:{count}`;
 *       pure count = analyzed.count − |functions|; the digest is stable across a same-input re-scan.</li>
 *   <li>Gap 2 — an un-analyzable class (skipped) appears in the report's `unanalyzed`, and a CONFIGURED gate
 *       over it fails closed: the verdict carries `ok:false, incomplete:true, unanalyzed:[…]` and the run
 *       exits 2 (could-not-evaluate) — never a green gate over unseen code. A real violation still exits 1.</li>
 * </ul>
 */
class CompletenessManifestTest {

    @TempDir Path tmp;

    private record Run(int exit, String stdout, String stderr) {}

    private static Run runCli(String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    /** An app with one effectful method (Fs) and one pure method → analyzed universe > |functions|.
     *  Returns the classes dir (the scan target). */
    private Path app() throws Exception {
        return compile(Map.of("A.java", String.join("\n",
            "package app;",
            "public class A {",
            "  public void reads(){ try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of(\"/tmp/x\")); } catch (Exception e) {} }",
            "  public int pure(int x){ return x + 1; }",
            "}")));
    }

    @Test void analyzedSummaryLetsAConsumerComputeThePureCount() throws Exception {
        Path app = app();
        try {
            Path report = tmp.resolve("r.json");
            Run r = runCli(app.toString(), "--json", report.toString());
            assertEquals(0, r.exit(), r.stderr());
            JsonObject root = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
            assertTrue(root.has("analyzed"), "the envelope carries the completeness manifest");
            int count = root.getAsJsonObject("analyzed").get("count").getAsInt();
            int functions = root.getAsJsonArray("functions").size();
            assertTrue(count > functions, "analyzed count includes pure methods the report omits (count=" + count + ", |functions|=" + functions + ")");
            assertTrue(count - functions >= 1, "at least the one pure method is analyzed-but-omitted");
            assertFalse(root.getAsJsonObject("analyzed").get("digest").getAsString().isEmpty(), "a digest is present");
            assertFalse(root.has("unanalyzed"), "a complete scan carries no `unanalyzed` (byte-compatible)");
            // the digest is stable across a same-input re-scan (Gap 1 conformance).
            Path report2 = tmp.resolve("r2.json");
            runCli(app.toString(), "--json", report2.toString());
            JsonObject root2 = JsonParser.parseString(Files.readString(report2)).getAsJsonObject();
            assertEquals(root.getAsJsonObject("analyzed").get("digest").getAsString(),
                    root2.getAsJsonObject("analyzed").get("digest").getAsString(),
                    "the analyzed-set digest is stable across a same-input re-scan");
        } finally { rm(app.getParent()); }
    }

    @Test void anUnanalyzableClassIsMachineLegibleAndFailsAConfiguredGateClosed() throws Exception {
        Path app = app();
        try {
            // a class ASM cannot parse — its effects are invisible, so a gate over it must NOT read green.
            Files.write(app.resolve("Corrupt.class"), new byte[]{(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 0, 9});

            // (a) BARE scan: exit 0, but `unanalyzed` is disclosed in the report (was stderr-only).
            Path report = tmp.resolve("r.json");
            Run bare = runCli(app.toString(), "--json", report.toString());
            assertEquals(0, bare.exit(), "a bare scan does not fail on an unparseable class — it discloses it");
            JsonObject root = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
            assertTrue(root.has("unanalyzed") && root.getAsJsonArray("unanalyzed").size() == 1,
                    "the unparseable class is machine-legible in the report's `unanalyzed`");
            assertTrue(root.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().get("path").getAsString().contains("Corrupt"),
                    "the unanalyzed entry names the offending file");

            // (b) a CONFIGURED gate that finds NO violation still cannot certify → exit 2, verdict incomplete.
            Path pol = tmp.resolve("p.policy");
            Files.writeString(pol, "deny Db\n"); // the app performs Fs, not Db — no violation
            Path verdict = tmp.resolve("v.json");
            Run gated = runCli(app.toString(), "--policy", pol.toString(), "--gate-json", verdict.toString());
            assertEquals(2, gated.exit(), "a gate over unanalyzed code cannot be green — exit 2 (could-not-evaluate)");
            JsonObject v = JsonParser.parseString(Files.readString(verdict)).getAsJsonObject();
            assertFalse(v.get("ok").getAsBoolean(), "ok:false — the gate did not certify");
            assertTrue(v.has("incomplete") && v.get("incomplete").getAsBoolean(), "incomplete:true");
            assertTrue(v.has("unanalyzed") && v.getAsJsonArray("unanalyzed").size() == 1,
                    "the verdict names the unanalyzed unit (a machine learns WHY, not just from stderr)");

            // (c) a real violation still dominates (exit 1), and the verdict still discloses incompleteness.
            Path pol2 = tmp.resolve("p2.policy");
            Files.writeString(pol2, "deny Fs\n"); // the app performs Fs → a real violation
            Path verdict2 = tmp.resolve("v2.json");
            Run gated2 = runCli(app.toString(), "--policy", pol2.toString(), "--gate-json", verdict2.toString());
            assertEquals(1, gated2.exit(), "a real violation outranks the incompleteness (exit 1)");
            JsonObject v2 = JsonParser.parseString(Files.readString(verdict2)).getAsJsonObject();
            assertTrue(v2.has("incomplete") && v2.get("incomplete").getAsBoolean(),
                    "the incompleteness is still disclosed on a violating run");
        } finally { rm(app.getParent()); }
    }

    /**
     * ⟨0.24⟩ SPEC §3.2 (candor-spec {@code 0075987}) — <b>{@code whatif} OVER AN INCOMPLETE REPORT OMITS
     * {@code ok}: it does not answer {@code true}, and it does not answer {@code false} either.</b>
     *
     * <p>MEASURED independently by candor-rust and this engine, and REPORTED rather than decided, which is
     * why it became a ruling: {@code whatif} returned {@code ok: true} over a report declaring
     * {@code unanalyzed} units. Its {@code affected} set is a transitive-CALLER closure, so a caller sitting
     * in a file nothing parsed is invisible to it — the blast radius is a LOWER BOUND and the verdict drawn
     * from it cannot be more certain than that. {@code whatif} is not a gate, but <b>its {@code ok} reads as
     * one</b>, and the standing rule is that the naive read of a field must be the safe one.
     *
     * <p>Neither boolean is honest, which is why the answer is neither. {@code ok: true} asserts "nothing
     * this hypothetical touches is denied" over a knowingly partial set; {@code ok: false} would assert a
     * VIOLATION the analysis never found — the fabrication mirror, and worse than the thing it replaces. So
     * the field is OMITTED: {@code if (r.ok)} gets a falsy value and fails safe, and a consumer that looks
     * further learns exactly what was unread. This is deliberately NOT the gate verdict's shape
     * ({@code ok:false} + {@code incomplete:true}, pinned in the test above) — there {@code ok:false} is
     * TRUE, because the gate did not certify. A shape is copied for its reasoning, not its familiarity.
     *
     * <p>THE MIRROR, asserted below: a COMPLETE report must still carry {@code ok}. Omitting it everywhere
     * would make the absence mean nothing, and this verb's whole answer is that field.
     */
    @Test void whatifOverAnIncompleteReportOmitsOkEntirely() throws Exception {
        Path app = app();
        try {
            Path pol = tmp.resolve("wp.policy");
            Files.writeString(pol, "deny Fs app\n");     // `reads` performs Fs → a real violation is available

            // ── (a) the CONTROL, first: a COMPLETE report still answers `ok`. Written before the corrupt
            // class exists, so the two runs differ in exactly one input.
            Path good = tmp.resolve("wi-good.json");
            assertEquals(0, runCli(app.toString(), "--json", good.toString()).exit());
            Run okRun = runCli("whatif", "--report", good.toString(),
                    "app.A.pure", "Net", "--policy", pol.toString(), "--json");
            JsonObject okDoc = JsonParser.parseString(okRun.stdout()).getAsJsonObject();
            assertTrue(okDoc.has("ok"), "MIRROR: a complete report still carries `ok` — if it were omitted "
                    + "everywhere the absence would mean nothing: " + okRun.stdout());
            assertTrue(okDoc.get("ok").getAsBoolean(), "…and it is `true`: `deny Fs` does not deny Net");
            assertFalse(okDoc.has("incomplete"), "…and says nothing about incompleteness it does not have");

            // ── (b) the same target, plus one class ASM cannot parse.
            Files.write(app.resolve("Corrupt.class"),
                    new byte[]{(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 0, 9});
            Path bad = tmp.resolve("wi-bad.json");
            assertEquals(0, runCli(app.toString(), "--json", bad.toString()).exit());
            assertTrue(JsonParser.parseString(Files.readString(bad)).getAsJsonObject().has("unanalyzed"),
                    "precondition: the report this verdict is computed from declares unanalyzed units");

            Run badRun = runCli("whatif", "--report", bad.toString(),
                    "app.A.pure", "Net", "--policy", pol.toString(), "--json");
            JsonObject doc = JsonParser.parseString(badRun.stdout()).getAsJsonObject();
            // THE ASSERTION THIS TEST EXISTS FOR: `ok` is ABSENT, not false.
            assertFalse(doc.has("ok"),
                    "`ok` must be OMITTED over an incomplete report — `if (r.ok)` then fails safe: "
                    + badRun.stdout());
            assertFalse(badRun.stdout().contains("\"ok\""),
                    "…and not hidden anywhere else in the document either: " + badRun.stdout());
            // …and NOT replaced by `ok:false`, which would assert a violation nothing found.
            assertEquals(0, doc.getAsJsonArray("violations").size(),
                    "this run found no violation, so an `ok:false` here would be an INVENTION — the "
                    + "fabrication mirror of the `ok:true` it replaces");
            assertTrue(doc.has("incomplete") && doc.get("incomplete").getAsBoolean(),
                    "`incomplete:true` takes its place: " + badRun.stdout());
            assertTrue(doc.has("unanalyzed") && doc.getAsJsonArray("unanalyzed").size() >= 1,
                    "…with the manifest, so a consumer learns exactly what was unread: " + badRun.stdout());
            assertTrue(doc.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().has("path")
                            && doc.getAsJsonArray("unanalyzed").get(0).getAsJsonObject().has("reason"),
                    "…in the same {path, reason} shape the report and the gate verdict use");
            // The partial answer STILL SHIPS: a partial answer that says it is partial beats a refusal, and
            // whatif is consulted BEFORE an edit, where the alternative is the operator guessing.
            assertTrue(doc.has("affected") && doc.getAsJsonArray("affected").size() >= 1,
                    "`affected` still ships: " + badRun.stdout());
            assertTrue(doc.has("violations"), "`violations` still ships: " + badRun.stdout());
            assertEquals(0, badRun.exit(),
                    "the exit code answers `did I find a violation`, which this run CAN still answer");

            // …and a real violation over the same incomplete report is still reported, still without `ok`.
            Run viol = runCli("whatif", "--report", bad.toString(),
                    "app.A.reads", "Fs", "--policy", pol.toString(), "--json");
            JsonObject vd = JsonParser.parseString(viol.stdout()).getAsJsonObject();
            assertFalse(vd.has("ok"), "still omitted when a violation IS found: " + viol.stdout());
            assertTrue(vd.getAsJsonArray("violations").size() >= 1, "…and the violation is reported anyway");
            assertEquals(1, viol.exit(), "…exit 1, as it would be over a complete report");

            // THE PROSE CHANNEL carries the same limit — closing the JSON one and leaving "✓ within policy"
            // standing would move the identical false all-clear to the channel the human reads.
            Run human = runCli("whatif", "--report", bad.toString(),
                    "app.A.pure", "Net", "--policy", pol.toString());
            assertFalse(human.stdout().contains("✓ within policy"),
                    "no ✓ all-clear over an incomplete report: " + human.stdout());
            assertTrue(human.stdout().contains("unanalyzed"),
                    "…the incompleteness is named instead: " + human.stdout());
        } finally { rm(app.getParent()); }
    }

    /**
     * AN UNREADABLE SIGNATURE KEY IMPEACHES THE DOCUMENT — SPEC §2 ⟨0.24⟩: *"SIGNATURE keys — `functions`,
     * `inferred`, `direct`, `unknownWhy`, `netClass`, `analyzed`, `unanalyzed` — carry the claim. One
     * unreadable among them means the document's claim cannot be trusted, whatever this particular policy
     * happens to ask. **Refuse.**"*
     *
     * <p>{@code readEnvelope} tested {@code has("unanalyzed") && isJsonArray()}, so a PRESENT but non-array
     * manifest failed the condition and was SILENTLY SKIPPED: the key whose entire job is to say "there is
     * code I could not analyze" was read as "there is none". Measured against the other three engines on
     * the same report, with nothing else to report — rust, ts and swift all exit 2; java exited <b>0</b>.
     *
     * <p>BOTH CONTROLS MATTER MORE THAN THE ROW. Refusing on any odd byte is the mirror defect, and this
     * rule turns on present-AND-GARBLED, never on missing: a report with NO {@code unanalyzed} key is a
     * complete scan (or a pre-⟨0.21⟩ producer) and must still gate normally, while a WELL-FORMED
     * {@code unanalyzed} must fail closed as INCOMPLETE rather than be refused as corrupt. Those are
     * different exits for different reasons and a fix that collapsed them would pass the first assertion.
     */
    @Test void anUnreadableUnanalyzedKeyImpeachesTheReport() throws Exception {
        Path dir = Files.createTempDirectory("candor-impeach");
        try {
            String base = "{\"candor\":{\"version\":\"x\",\"toolchain\":\"t\",\"spec\":\"0.24\"},"
                    + "\"package\":\"p\",\"analyzed\":{\"count\":3,\"digest\":\"d\"},%s"
                    + "\"functions\":[{\"fn\":\"pure\",\"inferred\":[],\"hash\":\"p#pure\"}]}";
            Path pol = dir.resolve("p.txt");
            Files.writeString(pol, "deny Net\n");

            // (a) THE ROW: present but unreadable -> the document is impeached, so the gate must refuse.
            Path bad = dir.resolve("bad.scan.json");
            Files.writeString(bad, String.format(base, "\"unanalyzed\":\"not-an-array\","));
            Run r = runCli("gate", "--report", bad.toString(), "--policy", pol.toString());
            assertEquals(2, r.exit(), "an unreadable SIGNATURE key must impeach the document: " + r.stderr());
            assertTrue(r.stderr().contains("unanalyzed"), "and the refusal must name the key: " + r.stderr());

            // (b) CONTROL — ABSENT is not unreadable. A complete scan carries no `unanalyzed` at all.
            Path none = dir.resolve("none.scan.json");
            Files.writeString(none, String.format(base, ""));
            assertEquals(0, runCli("gate", "--report", none.toString(), "--policy", pol.toString()).exit(),
                    "a report with no `unanalyzed` key is a COMPLETE scan and must gate normally");

            // (c) CONTROL — a WELL-FORMED manifest fails closed as INCOMPLETE, which is a different exit
            //     for a different reason. Collapsing (a) and (c) would satisfy (a) and lose the distinction.
            Path decl = dir.resolve("decl.scan.json");
            Files.writeString(decl, String.format(base,
                    "\"unanalyzed\":[{\"path\":\"src/x\",\"reason\":\"failed to parse\"}],"));
            Run d = runCli("gate", "--report", decl.toString(), "--policy", pol.toString());
            assertEquals(2, d.exit(), "a declared-incomplete report must still fail closed: " + d.stderr());
            assertFalse(d.stderr().contains("cannot read report"),
                    "…but as INCOMPLETE, not as an impeached document: " + d.stderr());
        } finally { rm(dir); }
    }
}
