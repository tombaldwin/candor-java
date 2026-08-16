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
 * ⟨0.29⟩ THE {@code only <A> -> <B> [<C> …]} PERMISSION FORM (SPEC §6.2, AS-EFF-009).
 *
 * <p><b>{@code forbid} FAILS OPEN; {@code only} FAILS SAFE.</b> A dependency you forgot to prohibit is
 * silently permitted, so "this package is a leaf" could only be spelled by enumerating what it must not
 * reach — an ALLOWLIST in the unsafe direction, because a package added tomorrow is not on the list and
 * nothing says so. That is the hazard candor refuses everywhere in the analysis, sitting in the POLICY
 * LANGUAGE. Found by pointing candor's own architecture gate at candor: the natural
 * {@code forbid io.poly.candor.model -> io.poly.candor} SELF-FIRES at 58 violations, because a scope
 * matches a contiguous run of segments and {@code model} sits under the prefix it is protecting itself
 * from.
 */
class OnlyPermissionTest {

    @TempDir Path tmp;

    private record Run(int exit, String stdout, String stderr) {
        /** Both streams. The gate's AS-EFF diagnostics go to STDOUT on an ordinary run and are rerouted to
         *  stderr only when a JSON document owns stdout, so a row asserting on one stream alone is
         *  asserting on the flag it happened to pass. */
        String out() { return stdout + stderr; }
    }

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

    /** `app.M` reaches `app.util` and `app.infra`; `app.util` itself reaches `app.deep`, which no rule
     *  ever permits — the fixture for the stop-at-permitted rule. */
    private Path classes() throws Exception {
        return compile(Map.of(
            "M.java", String.join("\n",
                "package app;",
                "public class M {",
                "  public static int shape() { return app.util.U.helper(); }",
                "  public static int leaks() { return app.infra.I.dbRead(); }",
                "}"),
            "U.java", String.join("\n",
                "package app.util;",
                "public class U { public static int helper() { return app.deep.D.inner(); } }"),
            "I.java", String.join("\n",
                "package app.infra;",
                "public class I { public static int dbRead() { return 9; } }"),
            "D.java", String.join("\n",
                "package app.deep;",
                "public class D { public static int inner() { return 1; } }")));
    }

    private Path policy(String name, String body) throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, body + "\n");
        return p;
    }

    /** The form's whole point: what the list omits is a violation, and what it names is not. */
    @Test void whatThePermissionListOmitsIsAViolation() throws Exception {
        Path cls = classes();
        try {
            Run bad = runCli(cls.toString(), "--policy", policy("a.pol", "only app.M -> app.util").toString());
            assertEquals(1, bad.exit(), bad.stderr());
            // ⟨0.29⟩ ITS OWN CODE, both halves: 011 present AND 009 absent. A rule code is what a CI
            // suppression keys on, and a suppression written for a `forbid` crossing must not mute this.
            assertTrue(bad.out().contains("AS-EFF-011"), bad.out());
            assertFalse(bad.out().contains("AS-EFF-009"),
                "an `only` violation must not also carry `forbid`'s code: " + bad.out());
            assertTrue(bad.out().contains("app.infra.I.dbRead"),
                "the message must name what was reached, not just that something was: " + bad.out());
            assertTrue(bad.out().contains("only app.M -> app.util"),
                "…and the rule that says so: " + bad.out());

            // THE TAIL IS A LIST — that is the one ergonomic difference from `forbid`.
            Run ok = runCli(cls.toString(),
                            "--policy", policy("b.pol", "only app.M -> app.util app.infra").toString());
            assertEquals(0, ok.exit(), ok.stderr());
        } finally { rm(cls.getParent()); }
    }

    /**
     * THE WALK STOPS AT A PERMITTED SCOPE, and this is the row that pins it. `app.util` is permitted and
     * itself reaches `app.deep`, which nothing permits. If the walk descended past a permitted scope this
     * would fire, and `only` would require the transitive closure of everything you permit — the same
     * enumeration-that-rots one level down, which would make the form useless for the leaf case it exists
     * for. A permitted callee's own dependencies are governed by the rules about IT.
     */
    @Test void aPermittedScopesOwnDependenciesAreNotThisRulesBusiness() throws Exception {
        Path cls = classes();
        try {
            Run r = runCli(cls.toString(),
                           "--policy", policy("c.pol", "only app.M -> app.util app.infra").toString());
            assertEquals(0, r.exit(), "app.deep sits BEYOND a permitted scope: " + r.stderr());
            assertFalse(r.out().contains("app.deep"), r.out());
        } finally { rm(cls.getParent()); }
    }

    /**
     * ZERO-MATCH IS MEASURED ON {@code from}, deliberately NOT on either endpoint the way a {@code forbid}
     * counts. A forbid's subject is the pair; an `only`'s subject is the scope it makes a PROMISE about.
     * A rule whose destinations all resolve while its `from` names nothing has bound nothing at all — and
     * that is exactly the typo that leaves an operator believing a leaf is protected.
     */
    @Test void aRuleWhoseFromNamesNothingIsDisclosedEvenWhenItsDestinationsResolve() throws Exception {
        Path cls = classes();
        try {
            Run r = runCli(cls.toString(),
                           "--policy", policy("d.pol", "only nosuch -> app.util").toString());
            assertEquals(0, r.exit(), "a zero-match rule is a DISCLOSURE, never a verdict change");
            assertTrue(r.out().contains("matched NO function"),
                "`app.util` resolves, so counting either endpoint would have hidden this: " + r.out());
            assertTrue(r.out().contains("only nosuch -> app.util"), r.out());
        } finally { rm(cls.getParent()); }
    }

    /**
     * REFUSED ON A REPORT ROUTE, exit 2 — and for a STRICTER reason than `forbid`'s. Both match on NAME,
     * which a report's effect-relevant wire cannot settle; but `forbid` asks whether ONE named crossing is
     * present, while `only` asks whether EVERYTHING reached is on a list, so a report that omits a
     * crossing turns a green into a claim of COMPLETENESS.
     *
     * <p>The `--strict` advisory arms are here because they are where this class of defect hides: the gate
     * got §3.1's rule and its siblings did not, four times running (PART 47's own history).
     */
    @Test void aReportRouteRefusesAnOnlyRuleRatherThanEvaluatingIt() throws Exception {
        Path cls = classes();
        try {
            Path report = tmp.resolve("r.json");
            assertEquals(0, runCli(cls.toString(), "--json", report.toString()).exit());
            Path pol = policy("e.pol", "only app.M -> app.util");

            Run g = runCli("gate", "--report", report.toString(), "--policy", pol.toString());
            assertEquals(2, g.exit(), "an unanswerable rule is refused, never evaluated: " + g.stderr());
            assertTrue(g.out().contains("only app.M -> app.util"), g.out());
            // …and it must be REMOVED from the evaluation, not merely disclosed beside it. A rule left in
            // the context is a rule the gate walks — the disclosure would stand next to the very
            // evaluation it says did not happen.
            assertFalse(g.out().contains("matched NO function"),
                "a refused rule must not also be reported as evaluated-and-bound-nothing: " + g.out());

            for (String verb : List.of("unverified", "fix-gate")) {
                Run a = runCli(verb, "--report", report.toString(), "--policy", pol.toString(), "--strict");
                assertEquals(2, a.exit(), verb + " certified over a rule the gate refuses: " + a.stderr());
            }
        } finally { rm(cls.getParent()); }
    }

    /** An `only`-only policy is ARMED: it must not trip the ⟨0.28⟩ zero-rule refusal, which exists for a
     *  file whose every line was ignored. Counting the new kind is what keeps a live gate out of it. */
    @Test void anOnlyOnlyPolicyIsNotAZeroRuleFile() throws Exception {
        Path cls = classes();
        try {
            Run r = runCli(cls.toString(),
                           "--policy", policy("f.pol", "only app.M -> app.util app.infra").toString());
            assertEquals(0, r.exit(), r.stderr());
            assertFalse(r.out().contains("yielded NO RULES"),
                "the policy is armed — refusing it would be the fail-closed guard turned into a false "
                + "refusal by the rung that added the kind: " + r.out());
        } finally { rm(cls.getParent()); }
    }
}
