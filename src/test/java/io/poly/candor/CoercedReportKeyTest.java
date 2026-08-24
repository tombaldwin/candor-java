package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ⟨0.32⟩ <b>A §2 KEY WHOSE VALUE HAS THE WRONG TYPE IS CORRUPT INPUT, NOT ITS DEFAULT.</b> The sweep that
 * followed the {@code excluded[].peeked} repair, over every remaining coercing read on the gate and query
 * paths.
 *
 * <p><b>The class of defect.</b> Gson's accessors do not fail on a type mismatch, they CONVERT:
 * {@code getAsBoolean} on a string is {@code Boolean.parseBoolean}, {@code getAsString} renders a number,
 * and a shape an accessor cannot read at all falls to the reader's empty default. Every one of those
 * defaults is the SAFE-LOOKING value — an empty {@code inferred} is a purity claim, an empty
 * {@code unanalyzed} is "there is no unanalyzed code", a {@code false} flag is a positive statement — so a
 * report whose only defect is a value's TYPE certifies where the same report with the right type refuses.
 *
 * <p><b>Each row below was MEASURED on the pre-fix build</b>, on one report, one policy
 * ({@code deny Exec}), changing nothing but the type of one value:
 * <pre>
 * "inferred": "Exec"                    exit 1 -> 0   coerced to [], the violator reads PURE
 * "inferred": null                      exit 1 -> 0   same, via the null-is-absent reading
 * "inferred": [ 7 ]                     exit 1 -> 0   the member skipped, the list emptied
 * "interfaceUnion": "true"              exit 1 -> 0   Boolean.parseBoolean; a SYNTHETIC entry is never
 *                                                     reported as a violator
 * "fn": { }                             exit 1 -> 0   coerced to "", Query.load drops the entry
 * "unanalyzed": [ 123 ]                 exit 2 -> 0   a NON-EMPTY manifest of unanalyzed code read as none
 * </pre>
 *
 * <p><b>AND THE LINE IT STOPS AT, which is the half that makes it a repair.</b> SPEC §2 divides these keys
 * by ROLE: SIGNATURE keys carry the claim and a reader must refuse; DECORATIONS — {@code loc}, and
 * {@code hash} on a single-report route — "carry no claim a verdict reads", and the spec's instruction
 * there is to withhold and ANSWER, because "refusing there drops a hedge to be strict about ornament".
 * {@link #decorationsAreNotHardened} is that control: the safe-LOOKING repair is to refuse everything, and
 * it passes every row above while turning a hedge into a hard failure on reports that are merely untidy.
 */
class CoercedReportKeyTest {

    @TempDir Path tmp;

    private record Run(int exit, String stdout, String stderr) {}

    private static Run runCli(String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp",
                System.getProperty("java.class.path"), "io.poly.candor.Candor"));
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

    /** A §2 report in a directory of its own, so a locator's prefix expansion cannot pull in a sibling
     *  row's report and answer a question this row did not ask.
     *
     *  @param envelopeExtra raw text spliced in before `functions` (with its trailing comma), or ""
     *  @param functions     the raw text of the `functions` array */
    private Path report(String name, String envelopeExtra, String functions) throws Exception {
        Path dir = Files.createDirectories(tmp.resolve("r-" + name));
        Path f = dir.resolve(name + ".jvm.json");
        Files.writeString(f, "{\n"
                + "  \"candor\": { \"version\": \"t\", \"toolchain\": \"jdk-21\", \"spec\": \"0.31\" },\n"
                + "  \"packages\": [ \"com.x\" ],\n"
                + "  \"analyzed\": { \"count\": 1, \"digest\": \"0000000000000000\" },\n"
                + "  \"excluded\": [],\n"
                + envelopeExtra
                + "  \"functions\": " + functions + "\n"
                + "}\n");
        return f;
    }

    private Path denyExec(String name) throws Exception {
        Path p = tmp.resolve(name + ".policy");
        Files.writeString(p, "deny Exec\n");
        return p;
    }

    private Run gate(Path rep, String tag) throws Exception {
        return runCli("gate", "--report", rep.toString(), "--policy", denyExec(tag).toString());
    }

    /** The violator, well formed. Every corrupt row below is THIS entry with one value's type changed, so
     *  a row that goes green can only be about the change it makes. */
    private static String violator(String extra) {
        return "[ { \"fn\": \"com.x.Deploy.go\", \"loc\": \"Deploy.java:3\", \"hash\": \"h1\", "
                + "\"inferred\": [ \"Exec\" ], \"direct\": [ \"Exec\" ]" + extra + " } ]";
    }

    // ── THE POSITIVE CONTROL ──────────────────────────────────────────────────────────────────────────

    /** Without this row every assertion below could be satisfied by a build that refuses everything, or by
     *  one whose fixture never carried a violation at all. */
    @Test void theWellFormedReportStillFindsTheViolation() throws Exception {
        Run r = gate(report("ok", "", violator("")), "ok");
        assertEquals(1, r.exit(), "the fixture must actually violate, or the rows below are vacuous: "
                + r.stdout() + r.stderr());
        assertTrue(r.stdout().contains("com.x.Deploy.go"), r.stdout());
    }

    // ── SIGNATURE KEYS: PRESENT AND UNREADABLE ⇒ IMPEACH ──────────────────────────────────────────────

    /**
     * {@code inferred} is named in §2's SIGNATURE list. Coerced to the empty set it makes the strongest
     * claim in the format — this unit is PURE — out of a value the producer never wrote.
     */
    @Test void anUnreadableInferredImpeachesTheDocument() throws Exception {
        // `null` is in here because the reader treated JSON null as ABSENT, and absent is the ⟨0.21⟩
        // purity claim. `Loader` has always read `"inferred": null` on the chained-dep route as UNTRUSTED,
        // so the same key was trusted on one route and not the other.
        List<String> shapes = List.of("\"Exec\"", "null", "{ \"0\": \"Exec\" }", "[ 7 ]", "[ null ]");
        for (String shape : shapes) {
            String tag = "inf" + Math.abs(shape.hashCode());
            Path rep = report(tag, "", "[ { \"fn\": \"com.x.Deploy.go\", \"hash\": \"h1\", "
                    + "\"inferred\": " + shape + ", \"direct\": [ \"Exec\" ] } ]");
            Run r = gate(rep, tag);
            assertEquals(2, r.exit(), "`inferred`: " + shape + " read as [] is a PURITY CLAIM the producer "
                    + "never made: " + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("inferred"), "…and the refusal names the key: " + r.stderr());
        }
    }

    /**
     * {@code interfaceUnion: true} is a NARROW, EXPLICIT producer exemption — a ⟨0.23⟩ CHA union is not a
     * unit, so it is never reported as a violator. Coerced from a string it exempts an ordinary function,
     * and the note it prints on stderr does not change the machine verdict: {@code ok: true}, exit 0.
     */
    @Test void aNonBooleanInterfaceUnionImpeachesTheDocument() throws Exception {
        for (String shape : List.of("\"true\"", "\"false\"", "1", "null", "{ }")) {
            String tag = "iu" + Math.abs(shape.hashCode());
            Run r = gate(report(tag, "", violator(", \"interfaceUnion\": " + shape)), tag);
            assertEquals(2, r.exit(), "`interfaceUnion`: " + shape + " must not carve out a real function: "
                    + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("interfaceUnion"), r.stderr());
        }
        // THE CARVE-OUT ITSELF SURVIVES: a genuine `true` still exempts, or this repair has deleted the
        // ⟨0.23⟩ feature rather than hardened it.
        Run real = gate(report("iuReal", "", violator(", \"interfaceUnion\": true")), "iuReal");
        assertEquals(0, real.exit(), "a real `true` is still a CHA union, not a unit: "
                + real.stdout() + real.stderr());
    }

    /**
     * THE OTHER TWO BOOLEANS THE SAME READER SERVES. {@code interfaceUnion} is the one with a MEASURED
     * exit-code movement, so on its own it pins the INSTANCE; these pin the CLASS, which is the reader.
     * Their fail-open direction is the mirror of {@code interfaceUnion}'s — a value that MEANS true and
     * coerces to {@code false}, e.g. {@code "unresolved": 1}, which silently deletes the
     * {@code ⚠ unresolved (set may be incomplete)} hedge from a set that IS incomplete, and
     * {@code "entryPoint": "true"} which invents a root for {@code tour}/{@code impact} to walk from.
     * Neither moves this verb's exit on its own, which is exactly why a row keyed only on exit codes
     * would have left them coercing.
     */
    @Test void theOtherEntryBooleansTakeTheSameRule() throws Exception {
        for (String key : List.of("entryPoint", "unresolved")) {
            for (String shape : List.of("\"true\"", "1", "null", "[ ]")) {
                String tag = "b" + Math.abs((key + shape).hashCode());
                Run r = gate(report(tag, "", violator(", \"" + key + "\": " + shape)), tag);
                assertEquals(2, r.exit(), "`" + key + "`: " + shape + " is not a boolean: "
                        + r.stdout() + r.stderr());
                assertTrue(r.stderr().contains(key), "…and the refusal names the key: " + r.stderr());
            }
            // …and a genuine boolean is untouched: the violation is still found and still reported.
            Run ok = gate(report("b-ok-" + key, "", violator(", \"" + key + "\": true")), "b-ok-" + key);
            assertEquals(1, ok.exit(), "a real boolean `" + key + "` changes nothing about the gate: "
                    + ok.stdout() + ok.stderr());
        }
    }

    /**
     * AN UNREADABLE {@code fn} DROPS THE ENTRY, and a dropped entry is a deleted violation.
     * {@code Query.load} names the drop on stderr, which is exactly why it survived: the disclosure looks
     * like the engine handling the case, while the VERDICT — the only channel CI reads — says
     * {@code ok: true}. §2 does not list {@code fn} among the signature keys because it is not a claim
     * ABOUT the unit, it is the unit's IDENTITY: every policy scope matches on it and every violation is
     * reported under it, so it is on the signature side of §2's role test, not the ornament side.
     */
    @Test void anUnreadableFnImpeachesTheDocument() throws Exception {
        for (String shape : List.of("{ }", "[ ]", "null", "42", "true")) {
            String tag = "fn" + Math.abs(shape.hashCode());
            Path rep = report(tag, "", "[ { \"fn\": \"com.x.Ok.pure\", \"hash\": \"h0\", "
                    + "\"inferred\": [] }, { \"fn\": " + shape + ", \"hash\": \"h1\", "
                    + "\"inferred\": [ \"Exec\" ] } ]");
            Run r = gate(rep, tag);
            assertEquals(2, r.exit(), "`fn`: " + shape + " silently dropped the entry carrying the "
                    + "violation: " + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("fn"), r.stderr());
        }
    }

    /**
     * {@code unanalyzed}'s MEMBERS, by the rule its own top-level check already states. Its siblings
     * {@code outOfScope} and {@code excluded} both impeach on a non-object member; this one skipped it, so
     * the LENGTH of the list — the whole of what the manifest claims — depended on how well-formed its
     * members happened to be.
     */
    @Test void anUnreadableUnanalyzedMemberImpeachesTheDocument() throws Exception {
        // The CONTROL first, in the same row: a well-formed non-empty manifest refuses, so a green below
        // cannot be "this fixture never triggered incompleteness".
        Run good = gate(report("unGood",
                "  \"unanalyzed\": [ { \"path\": \"a.java\", \"reason\": \"no class\" } ],\n",
                "[ ]"), "unGood");
        assertEquals(2, good.exit(), "a declared-incomplete report refuses: " + good.stdout() + good.stderr());

        for (String shape : List.of("123", "\"a.java\"", "null", "[ ]")) {
            String tag = "un" + Math.abs(shape.hashCode());
            Run r = gate(report(tag, "  \"unanalyzed\": [ " + shape + " ],\n", "[ ]"), tag);
            assertEquals(2, r.exit(), "`unanalyzed`: [" + shape + "] is a NON-EMPTY manifest of code "
                    + "nothing analyzed, read as an empty one: " + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("unanalyzed"), r.stderr());
        }
        // …and an ABSENT `unanalyzed` is still a complete scan (⟨0.26⟩ cannot-answer stays permissive).
        Run absent = gate(report("unAbsent", "", "[ ]"), "unAbsent");
        assertEquals(0, absent.exit(), "no manifest is not a corrupt one: " + absent.stdout() + absent.stderr());
    }

    /**
     * {@code outOfScope}'s FIELDS travel verbatim into the verdict DOCUMENT, and §3.1 binds that document
     * to {@code scan --policy}'s over the same facts. Coerced, {@code "effects": "Exec"} published
     * {@code effects: []} and {@code "effects": [123]} published {@code ["123"]} — a verdict stating
     * something the producer did not.
     */
    @Test void anUnreadableOutOfScopeFieldImpeachesTheDocument() throws Exception {
        String oos = "  \"outOfScope\": [ { \"fn\": \"hidden\", \"path\": \"z.jar\", "
                + "\"class\": \"archive\", \"reason\": \"r\", \"effects\": %s } ],\n";
        Run good = gate(report("oosGood", String.format(oos, "[ \"Exec\" ]"), "[ ]"), "oosGood");
        assertEquals(2, good.exit(), "the well-formed peek finding refuses: " + good.stdout() + good.stderr());

        for (String shape : List.of("\"Exec\"", "123", "[ 123 ]", "null")) {
            String tag = "oos" + Math.abs(shape.hashCode());
            Run r = gate(report(tag, String.format(oos, shape), "[ ]"), tag);
            assertEquals(2, r.exit(), r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("effects"),
                "`effects`: " + shape + " must impeach and NAME the key rather than publish a list the "
                + "producer did not write: " + r.stderr());
        }

        // …AND THE MEMBER'S OTHER FOUR FIELDS, by the same argument and for the same reason `unitKind`
        // got a row: only `effects` was reachable by looking for a moved exit code, and all five go
        // through one reader into one verdict document.
        for (String k : List.of("fn", "path", "class", "reason")) {
            String tag = "oosf" + Math.abs(k.hashCode());
            Run r = gate(report(tag, "  \"outOfScope\": [ { \"" + k + "\": 123, "
                    + "\"effects\": [ \"Exec\" ] } ],\n", "[ ]"), tag);
            assertEquals(2, r.exit(), "`outOfScope[]." + k + "`: 123 renders as the string \"123\" into a "
                    + "MACHINE verdict §3.1 binds to the scan route's: " + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains(k), "…and the refusal names the field: " + r.stderr());
        }
    }

    /**
     * {@code netPartners}, the LAST member reader — and the one whose failure mode is a SILENTLY DROPPED
     * DISCLOSURE rather than a wrong answer. Its top-level shape check landed at ⟨0.31⟩; inside the
     * object, `has(config) && has(hosts) && isJsonArray(hosts)` meant any garbled inner shape dropped the
     * whole key and answered. §3.1 binds the two routes to byte-equal documents, so a dropped
     * `netPartners` is a verdict that differs from `scan --policy`'s over the same facts — which is the
     * exact byte-equality break this disclosure was once REVERTED for.
     *
     * <p>BOTH-OR-NEITHER is ⟨0.26⟩'s key-set rule: a PARTIAL disclosure answers worse than an absent one,
     * because it reads as a complete answer to a question it did not answer.
     */
    @Test void anUnreadableNetPartnersImpeachesTheDocument() throws Exception {
        // CONTROL: a well-formed `netPartners` is carried and changes nothing about the verdict.
        Run good = gate(report("npGood",
                "  \"netPartners\": { \"config\": \"/x/.candor/config\", \"hosts\": [ \"a.example\" ] },\n",
                violator("")), "npGood");
        assertEquals(1, good.exit(), "a well-formed disclosure is carried, not refused: "
                + good.stdout() + good.stderr());

        for (String body : List.of(
                "{ \"config\": \"/x\" }",                              // partial — hosts missing
                "{ \"hosts\": [ \"a\" ] }",                            // partial — config missing
                "{ \"config\": 7, \"hosts\": [ \"a\" ] }",             // config not a string
                "{ \"config\": \"/x\", \"hosts\": \"a\" }",            // hosts not an array
                "{ \"config\": \"/x\", \"hosts\": [ 7 ] }",            // a non-string host
                "{ \"config\": \"/x\", \"hosts\": null }")) {          // null is not absent
            String tag = "np" + Math.abs(body.hashCode());
            Run r = gate(report(tag, "  \"netPartners\": " + body + ",\n", violator("")), tag);
            assertEquals(2, r.exit(), "`netPartners`: " + body + " was silently DROPPED, which publishes a "
                    + "verdict missing a key the scan route has: " + r.stdout() + r.stderr());
            assertTrue(r.stderr().contains("netPartners"), "…naming the key: " + r.stderr());
        }
        // …and ABSENT stays absent: the ordinary case, and it must not become exit 2 on contact.
        Run absent = gate(report("npAbsent", "", violator("")), "npAbsent");
        assertEquals(1, absent.exit(), "no disclosure is not a corrupt one: "
                + absent.stdout() + absent.stderr());
    }

    // ── THE OVER-CHARGE CONTROL ───────────────────────────────────────────────────────────────────────

    /**
     * SPEC §2's DECORATION ruling, held: <i>"DECORATIONS — a coverage ledger's detail, {@code loc}, and
     * {@code hash} ON A SINGLE-REPORT ROUTE — carry no claim a verdict reads. Withhold the decoration,
     * disclose it, and answer. Refusing there drops a hedge to be strict about ornament."</i>
     *
     * <p>This is the row that decides whether the sweep above is a repair or a blanket. A build that
     * refuses on any unreadable key passes every assertion in this file except this one — and it would
     * turn an untidy but perfectly readable report into a hard CI failure, which is the fail-CLOSED
     * regression this project has twice shipped while repairing a fail-open.
     */
    @Test void decorationsAreNotHardened() throws Exception {
        for (String extra : List.of(", \"loc\": 7", ", \"loc\": { }", ", \"hash\": 7")) {
            String tag = "dec" + Math.abs(extra.hashCode());
            Path rep = report(tag, "", "[ { \"fn\": \"com.x.Deploy.go\", \"inferred\": [ \"Exec\" ], "
                    + "\"direct\": [ \"Exec\" ]" + extra + " } ]");
            Run r = gate(rep, tag);
            assertEquals(1, r.exit(), "a DECORATION with the wrong type must be withheld, not refused — §2 "
                    + "puts the line at the key's ROLE, and the verdict still has everything it needs to "
                    + "answer (" + extra + "): " + r.stdout() + r.stderr());
            assertTrue(r.stdout().contains("com.x.Deploy.go"),
                "…and the violation is still reported: " + r.stdout());
        }
    }

    // ── THE READER, EXHAUSTIVELY ──────────────────────────────────────────────────────────────────────

    /**
     * <b>THE WHOLE KEY SET EACH READER SERVES, so this file's claim is COMPLETE and not "the ones I
     * happened to find".</b>
     *
     * <p>The rows above pin four INSTANCES, and every one of them was found because it MOVED AN EXIT
     * CODE. That is a biased sample of exactly the wrong kind: the reader is shared, so a key with no
     * exit-code consequence on this verb sits behind the identical coercion and no exit-driven search
     * will ever surface it. {@code unitKind} and 14 of the 15 string-array keys were in precisely that
     * position after the sweep — the reader was fixed, but nothing asserted it for them.
     *
     * <p>So this row enumerates the key set from {@code ReportJson.parseEntries}'s own argument list:
     * every key passed to {@code str}, {@code bool} and {@code strList}. It is a CHECKABLE claim — if
     * someone adds a §2 entry key and routes it through one of these readers without adding it here, the
     * set stops being complete and this comment stops being true. {@code loc} and {@code hash} are
     * absent by design: they go through {@code decoration} and are pinned by the row above, which
     * asserts the OPPOSITE outcome.
     */
    @Test void everyKeyTheSharedReadersServeTakesTheRule() throws Exception {
        // `str` — the identity keys. `fn` has its own row (it moves an exit code); `unitKind` does not.
        List<String> strings = List.of("fn", "unitKind");
        // `bool` — all three, two of which move no exit code on this verb.
        List<String> booleans = List.of("entryPoint", "unresolved", "interfaceUnion");
        // `strList` — the §2 string-array keys. Only `inferred` was reachable by an exit-code search.
        List<String> arrays = List.of("inferred", "invisible", "direct", "declared", "undeclared",
                "overdeclared", "unknownWhy", "calls", "fs", "hosts", "cmds", "paths", "tables",
                "netClass", "incomplete");

        for (String k : strings) probeCorrupt(k, "{ }");
        for (String k : booleans) probeCorrupt(k, "\"true\"");
        for (String k : arrays) probeCorrupt(k, "\"Exec\"");
        // …and every one of them ALSO under a JSON null, which is the shape that read as ABSENT — i.e.
        // as the ⟨0.21⟩ purity claim — before this repair.
        for (String k : arrays) probeCorrupt(k, "null");
    }

    /** One key, one wrong-shaped value: the document is impeached and the refusal NAMES the key. */
    private void probeCorrupt(String key, String shape) throws Exception {
        String tag = "all" + Math.abs((key + shape).hashCode());
        // The entry already carries `fn`/`inferred`/`direct`; overwrite rather than append when the key
        // under test is one of them, or the object would hold it twice and the last value would win
        // silently — a fixture that tests nothing.
        String entry = "{ \"fn\": \"com.x.Deploy.go\", \"hash\": \"h1\", \"inferred\": [ \"Exec\" ], "
                + "\"direct\": [ \"Exec\" ], \"" + key + "\": " + shape + " }";
        if (key.equals("fn"))
            entry = "{ \"hash\": \"h1\", \"inferred\": [ \"Exec\" ], \"fn\": " + shape + " }";
        else if (key.equals("inferred"))
            entry = "{ \"fn\": \"com.x.Deploy.go\", \"hash\": \"h1\", \"inferred\": " + shape + " }";
        else if (key.equals("direct"))
            entry = "{ \"fn\": \"com.x.Deploy.go\", \"hash\": \"h1\", \"inferred\": [ \"Exec\" ], "
                    + "\"direct\": " + shape + " }";
        Run r = gate(report(tag, "", "[ " + entry + " ]"), tag);
        assertEquals(2, r.exit(), "`" + key + "`: " + shape + " is a §2 key read as its default — the "
                + "SAFE-LOOKING value. It shares a reader with keys that DO move an exit code, so "
                + "leaving it coercing is the same defect nothing would have searched for: "
                + r.stdout() + r.stderr());
        assertTrue(r.stderr().contains(key),
            "…and the refusal must NAME the key (`" + key + "`: " + shape + "): " + r.stderr());
    }
}
