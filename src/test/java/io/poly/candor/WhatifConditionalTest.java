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
 * ⟨0.24⟩ <b>{@code whatif} NAMES THE OPERATOR'S OWN RULE, AND SAYS WHAT A NARROWED VERDICT RESTS ON</b> —
 * SPEC §3.1 (candor-spec {@code 6f30540}, corrected by {@code 901f14d}).
 *
 * <p>{@code whatif} asks about an effect the code <b>does not have yet</b>. A narrowing filter quantifies
 * over a CLASS of that effect — {@code deny Net[unknown-host]} asks about a destination the hypothetical
 * call has not got, because the call does not exist. There is nothing to match, so the filter cannot be
 * evaluated and the answer is fail-closed <b>but conditional</b>.
 *
 * <p><b>Neither obvious answer is right, and that is the whole design.</b> Printing the rule stripped of
 * its filter ({@code deny Net} for {@code deny Net[unknown-host]}) misattributes the verdict to a rule the
 * operator never wrote. Printing the raw line with an UNCONDITIONAL verdict is <b>worse than that bug</b>,
 * because it reads as a filter candor evaluated and did not. §3.1's own rule settles it — <i>an unanswerable
 * condition is DISCLOSED, never scored as a failed one</i> — so the raw line is printed and the unevaluated
 * narrowing is named beside it. The two halves only work together, which is why they land in one change.
 *
 * <p><b>This does NOT carry over from the sibling fix</b> ({@code NarrowedRuleAdvisoryVerbTest}, where
 * {@code unverified}/{@code fix-gate} learned to APPLY the narrowing through
 * {@link Policy#classNarrowingFires}). Those two read a signature that EXISTS, so the filter has something
 * to match; {@code whatif} does not, so the verdict stays fail-closed — a pre-edit gate must not guess which
 * class the edit lands in — and the CONDITION rides beside it instead.
 *
 * <p>MEASURED on this engine before the change, against candor-rust's own emitted JSON (the normative form;
 * the pin was mis-transcribed once from a description rather than the artifact, which is what {@code
 * 901f14d} corrects):
 *
 * <pre>
 *   rule written                              java printed          rust prints
 *   deny Unknown[reflect] app.nat             deny Unknown app.nat  deny Unknown[reflect] app.nat  + conditional
 *   deny Net[unknown-host] app                deny Net app          deny Net[unknown-host] app     + conditional
 *   deny Net Db  app  # keep the app pure     deny Net app          deny Net Db  app
 * </pre>
 *
 * The first two are the sharp ones: a NARROWED rule shown as the WIDE one, in the verb an agent reads
 * BEFORE editing — so the operator's own scoping is invisible at exactly the moment they are deciding
 * whether it protects them. The third shows the same root cause with no filter in sight: the line was
 * REBUILT from the effect being ASKED ABOUT rather than quoted from the rule, so the operator's other
 * denied effect ({@code Db}) vanished too.
 *
 * <p><b>THE MIRROR, and it is the point of half these assertions:</b> a rule that does NOT narrow rests on
 * no condition, so the key is ABSENT and the document is byte-identical to a pre-⟨0.24⟩ one. A
 * {@code conditional} on every violation would train the reader to ignore it — the same failure as naming a
 * config that changed nothing. The filter must also key on the effect being INTRODUCED rather than on the
 * rule merely carrying a bracket: {@code deny Net[unknown-host] Fs app} asked about {@code Fs} charges
 * {@code Fs} unconditionally, because a {@code Net} filter says nothing about an introduced {@code Fs}.
 */
class WhatifConditionalTest {

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

    /** One pure method — {@code whatif} asks about an effect it does NOT have, which is the whole point. */
    private Path app() throws Exception {
        return compile(Map.of("A.java", String.join("\n",
            "package app;",
            "public class A {",
            "  public int pure(int x){ return x + 1; }",
            "}")));
    }

    private Path policy(String body) throws Exception {
        Path p = tmp.resolve("p" + Math.abs(body.hashCode()) + ".policy");
        Files.writeString(p, body);
        return p;
    }

    /** The single violation object {@code whatif} emits for `app.A.pure` under `rule`, asked about `effect`. */
    private JsonObject only(Path report, String rule, String effect) throws Exception {
        Run r = runCli("whatif", "--report", report.toString(), "app.A.pure", effect,
                "--policy", policy(rule).toString(), "--json");
        JsonObject doc = JsonParser.parseString(r.stdout()).getAsJsonObject();
        assertEquals(1, doc.getAsJsonArray("violations").size(),
                "precondition: exactly one hypothetical violation to qualify — " + r.stdout() + r.stderr());
        return doc.getAsJsonArray("violations").get(0).getAsJsonObject();
    }

    private static String str(JsonObject v, String k) {
        return v.has(k) ? v.get(k).getAsString() : null;
    }

    @Test void whatifQuotesTheOperatorsRuleAndNamesTheNarrowingItCouldNotEvaluate() throws Exception {
        Path app = app();
        try {
            Path rep = tmp.resolve("r.json");
            assertEquals(0, runCli(app.toString(), "--json", rep.toString()).exit());

            // ── ARM 1: the rule is quoted VERBATIM — comment stripped and ends trimmed, but everything the
            // operator wrote inside the line kept, INCLUDING the effects the question did not ask about.
            assertEquals("deny Net Db  app", str(only(rep, "deny Net Db  app     # keep the app layer pure\n",
                    "Net"), "rule"),
                    "the operator's own line, not one rebuilt from the effect they happened to ask about "
                    + "(the rebuild dropped `Db` and the internal spacing alike)");
            assertEquals("pure app", str(only(rep, "pure app\n", "Net"), "rule"),
                    "a `pure` rule reads back as itself");

            // ── ARM 2: a NARROWED rule keeps its bracket. The sharp one — the operator's scoping was being
            // erased in the verb they consult before editing.
            JsonObject u = only(rep, "deny Unknown[reflect,unresolved] app\n", "Unknown");
            assertEquals("deny Unknown[reflect,unresolved] app", str(u, "rule"));
            JsonObject n = only(rep, "deny Net[unknown-host] app\n", "Net");
            assertEquals("deny Net[unknown-host] app", str(n, "rule"));

            // ── ARM 3, THE HALF THAT KEEPS ARM 2 HONEST: the verdict on a narrowed rule is CONDITIONAL and
            // says so. Without it, `rule` alone attributes an UNFILTERED verdict to a FILTERED line, which
            // §3.1 calls worse than the bug it replaces. Wording is candor-rust's emitted string verbatim
            // (multi-class sorted and joined ` / `) — this is a machine-consumed field, so a fifth spelling
            // is a conformance failure, not a synonym.
            assertEquals("the `Unknown` you introduce is of reason class reflect / unresolved",
                    str(u, "conditional"),
                    "a rule that NARROWS cannot be evaluated against an effect that does not exist yet");
            assertEquals("the `Net` you introduce reaches destination class unknown-host",
                    str(n, "conditional"));
            assertEquals("the `Net` you introduce reaches destination class known-partner / unknown-host",
                    str(only(rep, "deny Net[known-partner,unknown-host] app\n", "Net"), "conditional"),
                    "several classes are sorted and joined ` / `");

            // ── THE MIRROR: an UNFILTERED rule has NO condition to disclose, so the key is ABSENT and the
            // document is byte-identical to a pre-⟨0.24⟩ one.
            for (String plain : List.of("deny Unknown app\n", "deny Net app\n", "deny Net Db  app\n",
                                        "pure app\n")) {
                String eff = plain.startsWith("deny Unknown") ? "Unknown" : "Net";
                JsonObject v = only(rep, plain, eff);
                assertFalse(v.has("conditional"),
                        "a rule that does not narrow rests on no condition, and a `conditional` on EVERY "
                        + "violation would train the reader to ignore it: " + plain.trim());
            }

            // ── …and the condition keys on the effect being INTRODUCED, not on the rule merely carrying a
            // bracket. `deny Net[unknown-host] Fs app` asked about `Fs` charges `Fs` unconditionally.
            JsonObject other = only(rep, "deny Net[unknown-host] Fs app\n", "Fs");
            assertEquals("deny Net[unknown-host] Fs app", str(other, "rule"),
                    "the line is still quoted whole");
            assertFalse(other.has("conditional"),
                    "the `Net` filter says nothing about an introduced `Fs` — an off-axis bracket must not "
                    + "manufacture a condition the verdict does not actually rest on");

            // …and the SAME rule asked about the effect it DOES narrow gets exactly one condition, the
            // Net one — proving the two axes are read independently rather than by bracket-presence.
            assertEquals("the `Net` you introduce reaches destination class unknown-host",
                    str(only(rep, "deny Net[unknown-host] Unknown[reflect] app\n", "Net"), "conditional"),
                    "a rule narrowing BOTH axes discloses the axis actually being introduced");
        } finally { rm(app.getParent()); }
    }

    /**
     * THE PROSE CHANNEL CARRIES THE SAME QUALIFIER. {@code whatif} is read by a human and an agent through
     * the same verb, and a condition disclosed only in {@code --json} leaves the human reading the identical
     * unconditional verdict beside the identical narrowed line — the exact defect, in the channel that is
     * consulted more. The MIRROR rides here too: an unfiltered rule prints no {@code …IF} line at all.
     */
    @Test void theProseChannelQualifiesTheVerdictToo() throws Exception {
        Path app = app();
        try {
            Path rep = tmp.resolve("r2.json");
            assertEquals(0, runCli(app.toString(), "--json", rep.toString()).exit());

            Run narrowed = runCli("whatif", "--report", rep.toString(), "app.A.pure", "Net",
                    "--policy", policy("deny Net[unknown-host] app\n").toString());
            assertEquals(1, narrowed.exit(), "the verdict is unchanged — fail-closed, and still a violation");
            assertTrue(narrowed.stdout().contains("(rule: `deny Net[unknown-host] app`)"),
                    "the operator's line, with its bracket: " + narrowed.stdout());
            assertTrue(narrowed.stdout().contains(
                    "…IF the `Net` you introduce reaches destination class unknown-host."),
                    "and the condition beside it: " + narrowed.stdout());
            assertTrue(narrowed.stdout().contains("This rule NARROWS"),
                    "…with the reason it could not be evaluated: " + narrowed.stdout());

            Run plain = runCli("whatif", "--report", rep.toString(), "app.A.pure", "Net",
                    "--policy", policy("deny Net app\n").toString());
            assertEquals(1, plain.exit());
            assertTrue(plain.stdout().contains("(rule: `deny Net app`)"), plain.stdout());
            assertFalse(plain.stdout().contains("…IF"),
                    "MIRROR: an unfiltered rule prints no condition line: " + plain.stdout());
            assertFalse(plain.stdout().contains("NARROWS"), plain.stdout());
        } finally { rm(app.getParent()); }
    }
}
