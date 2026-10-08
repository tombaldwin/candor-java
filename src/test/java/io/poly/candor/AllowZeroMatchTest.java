package io.poly.candor;

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
 * SOUNDNESS R952 — A SCOPED {@code allow} WHOSE SCOPE BINDS NOTHING IS DISCLOSED LIKE A {@code deny}.
 *
 * <p>SPEC §4 ⟨0.27⟩ is headed "a rule whose SCOPE matches no function" and names no rule form, but the
 * zero-match pass ({@link Policy#discloseZeroMatchRules}) enrolled deny/forbid/only and never
 * {@code allow}. Measured on 0.40.0 over a fixture whose {@code entry} opens a socket to {@code h}:
 * <pre>
 *   allow Net in zzz.nomatch h        → exit 0, ok:true, NO stderr line, NO zeroMatch   (the hole)
 *   deny  Net zzz.nomatch             → exit 0 + "matched NO function" + zeroMatch       (its twin)
 *   allow Net in app.G zzz.example    → exit 1 AS-EFF-008                                (it binds)
 * </pre>
 * An {@code allow} is a CERTIFICATION, so one that binds nothing is the worse typo: the operator believes
 * a surface was checked. Each test below differs from its neighbour in ONE thing — the rule form, or
 * whether the scope binds. Conformance PART 36 (c5)-(c7) pins the same three arms four-way.
 */
class AllowZeroMatchTest {

    @TempDir Path tmp;

    private record Run(int exit, String stdout, String stderr) {
        String out() { return stdout + stderr; }
    }

    private static Run runCli(String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().remove("CANDOR_POLICY");
        pb.environment().remove("CANDOR_CONFIG");
        pb.environment().remove("CANDOR_BASELINE");
        Process p = pb.start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        return new Run(p.waitFor(), out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }

    /** `app.G.entry` performs Fs and Net (host `h`); nothing else is in the tree. */
    private Path classes() throws Exception {
        return compile(Map.of("G.java", String.join("\n",
            "package app;",
            "public class G {",
            "  public static void entry() throws Exception {",
            "    java.nio.file.Files.readString(java.nio.file.Path.of(\"/x\"));",
            "    new java.net.Socket(\"h\", 80);",
            "  }",
            "}")));
    }

    private Path policy(String name, String body) throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, body + "\n");
        return p;
    }

    /** Scan route with a --gate-json file sink; returns the run and the document text. */
    private String[] gate(Path cls, String policyBody, String tag) throws Exception {
        Path doc = tmp.resolve(tag + ".gate.json");
        Run r = runCli(cls.toString(), "--policy", policy(tag + ".pol", policyBody).toString(),
                       "--gate-json", doc.toString());
        return new String[] { String.valueOf(r.exit()), r.out(), Files.readString(doc) };
    }

    /** The row R952 names: disclosed on BOTH channels, and the verdict is untouched by the disclosure. */
    @Test void aScopedAllowThatBindsNothingIsDisclosedAndTheVerdictIsUnchanged() throws Exception {
        Path cls = classes();
        try {
            String raw = "allow Net in zzz.nomatch h";
            String[] r = gate(cls, raw, "miss");
            assertEquals("0", r[0], "a zero-match rule is a DISCLOSURE, never a verdict change: " + r[1]);
            assertTrue(r[1].contains("matched NO function — `" + raw + "`"),
                "the console line a `deny` gets, verbatim: " + r[1]);
            assertTrue(r[2].contains("\"zeroMatch\""), "the machine channel: " + r[2]);
            assertTrue(r[2].contains("\"" + raw + "\""), "the raw rule, verbatim: " + r[2]);
            assertTrue(r[2].replaceAll("\\s", "").contains("\"ok\":true"), r[2]);

            // its `deny` twin — the disclosure the `allow` must now match (and already did)
            String[] d = gate(cls, "deny Net zzz.nomatch", "twin");
            assertEquals("0", d[0], d[1]);
            assertTrue(d[1].contains("matched NO function — `deny Net zzz.nomatch`"), d[1]);

            // every literal-bearing effect: the enrolment is not keyed on Net
            for (String e : List.of("Exec", "Fs", "Db", "Llm")) {
                String rr = "allow " + e + " in zzz.nomatch x";
                String[] x = gate(cls, rr, "eff" + e);
                assertEquals("0", x[0], e + ": " + x[1]);
                assertTrue(x[2].contains("\"" + rr + "\""), e + ": " + x[2]);
            }
        } finally { rm(cls.getParent()); }
    }

    /** Two unbound rules of different forms ride ONE list, code-point sorted (§4's collation). */
    @Test void anUnboundAllowAndAnUnboundDenyShareOneSortedList() throws Exception {
        Path cls = classes();
        try {
            String[] r = gate(cls, "deny Fs zzz.a\nallow Net in zzz.b h", "both");
            assertEquals("0", r[0], r[1]);
            String compact = r[2].replaceAll("\\s", "");
            assertTrue(compact.contains("\"zeroMatch\":[\"allowNetinzzz.bh\",\"denyFszzz.a\"]"),
                "both rules, sorted by code point (`a` < `d`): " + r[2]);
        } finally { rm(cls.getParent()); }
    }

    /** THE FLOOR: the same form scoped to a function that EXISTS binds, gates, and is not disclosed —
     *  so the row above is about binding, not about `allow` being ignored altogether. */
    @Test void aScopedAllowThatBindsStaysQuietAndStillGates() throws Exception {
        Path cls = classes();
        try {
            String[] r = gate(cls, "allow Net in app.G zzz.example", "bind");
            assertEquals("1", r[0], "`entry` reaches `h`, which the list does not cover: " + r[1]);
            assertTrue(r[1].contains("AS-EFF-008"), r[1]);
            assertFalse(r[1].contains("matched NO function"), r[1]);
            assertFalse(r[2].contains("zeroMatch"), r[2]);
        } finally { rm(cls.getParent()); }
    }

    /** A SCOPELESS `allow` binds every function by construction — exempt, like a scopeless `deny`. */
    @Test void aScopelessAllowIsExempt() throws Exception {
        Path cls = classes();
        try {
            String[] r = gate(cls, "allow Net zzz.example", "scopeless");
            assertEquals("1", r[0], r[1]);
            assertFalse(r[1].contains("matched NO function"), r[1]);
            assertFalse(r[2].contains("zeroMatch"), r[2]);
        } finally { rm(cls.getParent()); }
    }

    /** `gate --report` REFUSES every `allow` (§3.1 answerability), and a refusal document never carries
     *  `zeroMatch` — a refused run evaluated nothing, so it cannot claim a rule bound nothing. */
    @Test void theReportRouteStillRefusesAndCarriesNoZeroMatch() throws Exception {
        Path cls = classes();
        try {
            Path rep = tmp.resolve("rep.json");
            Run s = runCli(cls.toString(), "--json", rep.toString());
            assertEquals(0, s.exit(), s.stderr());
            Path doc = tmp.resolve("route.gate.json");
            Run g = runCli("gate", "--report", rep.toString(),
                           "--policy", policy("route.pol", "allow Net in zzz.nomatch h").toString(),
                           "--gate-json", doc.toString());
            assertEquals(2, g.exit(), g.out());
            String d = Files.readString(doc);
            assertTrue(d.replaceAll("\\s", "").contains("\"refused\":true"), d);
            assertFalse(d.contains("zeroMatch"), d);
        } finally { rm(cls.getParent()); }
    }
}
