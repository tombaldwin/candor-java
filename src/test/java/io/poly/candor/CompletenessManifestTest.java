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
}
