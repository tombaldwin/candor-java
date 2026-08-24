package io.poly.candor;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The report ENVELOPE and --gate-json VERDICT shapes, pinned as WHOLE field sets (present + no extras) —
 * so schema drift is caught HERE, by `./gradlew test`, before the cross-repo conformance suite (which
 * runs later and in another checkout) ever sees it. The per-field semantics live in the behavioural
 * tests; this is purely the wire contract: a consumer (candor-query, candor-ts diff, the SARIF reporter)
 * deserializes these exact keys.
 *
 * <p>Same subprocess harness as {@link CliBehaviourTest} (main() calls System.exit).
 */
class SchemaShapeTest {

    /** Envelope: the v0.2 self-describing header (SPEC §2.1) + coverage + entries. */
    // ⟨0.21⟩ `analyzed` (the completeness-manifest summary) is ALWAYS present; `coverage`/`unanalyzed` are
    // conditional (omitted when fully covered / fully analyzed — this fixture is both).
    // ⟨0.27⟩ `resolves` joins the contract field set DELIBERATELY. This pin is why an envelope field cannot
    // arrive by accident: the assertion below fails on any undeclared key, so adding one is a decision
    // recorded in two places at once (the spec and this list) rather than a diff nobody reads.
    // ⟨0.29⟩ `excluded` joined the set, and it belongs with the ALWAYS-emitted keys rather than the
    // optional ones: `[]` is the positive statement "I looked and excluded nothing", and an absent key
    // would mean "this producer cannot answer" (⟨0.26⟩). This pin failing on the rung's first build is the
    // row doing its job. `outOfScope` is NOT here — this fixture configures no policy, so nothing was
    // asked and the key is correctly absent.
    private static final Set<String> TOP_KEYS =
            Set.of("candor", "packages", "analyzed", "resolves", "excluded", "functions");
    private static final Set<String> PROVENANCE_KEYS = Set.of("version", "toolchain", "spec");
    /** Every key a functions[] entry may carry (the Effector surface). Optional members (calls/fs/
     *  hosts/cmds/paths/tables/invisible/unknownWhy/unitKind) are omitted when empty — allowed, never
     *  required; the core ten are always present. */
    private static final Set<String> FN_REQUIRED = Set.of(
            "fn", "loc", "inferred", "direct", "declared", "undeclared", "overdeclared",
            "entryPoint", "unresolved", "hash");
    private static final Set<String> FN_ALLOWED;
    static {
        Set<String> all = new TreeSet<>(FN_REQUIRED);
        all.addAll(Set.of("calls", "fs", "hosts", "cmds", "paths", "tables",
                // ⟨0.29⟩ `incomplete` — the effects whose LOCATOR a unit could not determine (SPEC §2).
                // The fixture below gained `writesParam` to EXERCISE it: this pin passed the whole time
                // the field was being added, because nothing in the fixture had an undetermined locator,
                // and a schema pin that never sees a field is not pinning it.
                "invisible", "unknownWhy", "unitKind", "netClass", "incomplete"));
        FN_ALLOWED = all;
    }
    /** --gate-json: { spec, ok, violations:[{rule, fn, effects, detail}] } — the SARIF reporter's input. */
    // ⟨0.21⟩ `analyzed` (count) always present; `incomplete`/`unanalyzed` only on an incomplete gate (this
    // fixture is complete).
    private static final Set<String> VERDICT_KEYS = Set.of("spec", "ok", "analyzed", "violations");
    // ⟨0.32⟩ `hash` — SPEC §2: *"a verdict row MUST carry enough identity for a consumer to tell two units
    // apart"*. **THIS PIN IS THE EVIDENCE THAT THE RUNG IS NOT ADDITIVE**, and it is meant to be: a NEW
    // key on the violation record means a verdict document is no longer byte-identical to a pre-⟨0.32⟩
    // one. That is unavoidable — the MUST is that the row carry identity, and no arrangement of the four
    // existing keys does. Everything that CAN be additive is: every pre-existing key keeps its name, its
    // position and its value, and `hash` is OMITTED when the producer has none to give (a hand-authored
    // report), so a row from such a report is byte-identical to its old self. Measured on the two-member
    // twin fixture: without it, two rows come out byte-identical and a reader cannot attribute either.
    private static final Set<String> VIOLATION_KEYS = Set.of("rule", "fn", "hash", "effects", "detail");

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

    private Path scratch;

    @BeforeEach
    void mkScratch() throws Exception {
        scratch = Files.createTempDirectory("candor-schema");
    }

    @AfterEach
    void rmScratch() throws Exception {
        if (scratch == null || !Files.exists(scratch)) return;
        try (Stream<Path> s = Files.walk(scratch)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    /** A fixture exercising the optional surfaces too: Fs (fs/paths), Exec (cmds), reflection (Unknown →
     *  unresolved/unknownWhy), a static initializer (unitKind), and a caller (calls). */
    private Path compileFixture() throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path src = scratch.resolve("Shape.java");
        Files.writeString(src, """
            public class Shape {
                static { System.getenv("HOME"); }
                static void reads() { try { java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/tmp/s")); } catch (Exception e) {} }
                static void spawns() { try { new ProcessBuilder("curl", "http://x").start(); } catch (Exception e) {} }
                static void dyn() { try { Class.forName("X"); } catch (Exception e) {} }
                static void caller() { reads(); spawns(); }
                static void writesParam(String p) { try { java.nio.file.Files.write(java.nio.file.Path.of(p), new byte[0]); } catch (Exception e) {} }
            }
            """);
        Path out = scratch.resolve("cls");
        Files.createDirectories(out);
        assertEquals(0, jc.run(null, null, null, "-d", out.toString(), src.toString()), "fixture must compile");
        return out;
    }

    private static Set<String> keysOf(JsonObject o) {
        return new TreeSet<>(o.keySet());
    }

    @Test
    void reportEnvelopeIsExactlyTheContractFieldSet() throws Exception {
        Path cls = compileFixture();
        Path report = scratch.resolve("r.json");
        Run r = runCli(cls.toString(), "--json", report.toString());
        assertEquals(0, r.exit(), r.stderr());
        JsonObject root = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
        assertEquals(TOP_KEYS, keysOf(root), "envelope top level: exactly candor/packages/functions");
        assertEquals(PROVENANCE_KEYS, keysOf(root.getAsJsonObject("candor")),
                "provenance header: exactly version/toolchain/spec (§2.1 — build id, toolchain, contract)");
        assertEquals(Candor.SPEC_VERSION, root.getAsJsonObject("candor").get("spec").getAsString());
        JsonArray fns = root.getAsJsonArray("functions");
        assertTrue(fns.size() >= 4, "fixture yields entries (Fs/Exec/Unknown/caller), got " + fns.size());
        boolean sawOptional = false;
        for (JsonElement e : fns) {
            Set<String> keys = keysOf(e.getAsJsonObject());
            assertTrue(keys.containsAll(FN_REQUIRED),
                    "entry misses core fields: " + e.getAsJsonObject().get("fn") + " -> " + keys);
            Set<String> extras = new TreeSet<>(keys);
            extras.removeAll(FN_ALLOWED);
            assertTrue(extras.isEmpty(), "UNDECLARED report fields (schema drift — update the spec + this"
                    + " pin together, never silently): " + extras);
            sawOptional |= keys.size() > FN_REQUIRED.size();
        }
        assertTrue(sawOptional, "fixture should exercise at least one optional surface (calls/cmds/paths/unknownWhy)");
    }

    @Test
    void gateVerdictIsExactlyTheContractFieldSet() throws Exception {
        Path cls = compileFixture();
        Path pol = scratch.resolve("arch.policy");
        Files.writeString(pol, "deny Fs Shape\n");
        Path gate = scratch.resolve("gate.json");
        Run r = runCli(cls.toString(), "--policy", pol.toString(), "--gate-json", gate.toString());
        assertEquals(1, r.exit(), "the deny must bite (exit 1)\n" + r.stderr());
        JsonObject v = JsonParser.parseString(Files.readString(gate)).getAsJsonObject();
        assertEquals(VERDICT_KEYS, keysOf(v), "verdict: exactly spec/ok/violations");
        assertEquals(Candor.SPEC_VERSION, v.get("spec").getAsString());
        assertFalse(v.get("ok").getAsBoolean(), "ok mirrors the exit code");
        JsonArray viol = v.getAsJsonArray("violations");
        assertTrue(viol.size() >= 1, "at least the denied Fs");
        for (JsonElement e : viol) {
            assertEquals(VIOLATION_KEYS, keysOf(e.getAsJsonObject()),
                    "violation rows: exactly rule/fn/hash/effects/detail (the SARIF reporter's join keys)");
            // ⟨0.32⟩ …and `fn` is still the NAME, `hash` the §2.2 unit — BESIDE it, never instead of it.
            // A row whose `fn` had been replaced by the qualified form would satisfy the key set above
            // while silently stopping every scoped policy rule matching.
            assertFalse(e.getAsJsonObject().get("hash").getAsString().isEmpty(),
                    "a scan-route row's identity comes from the same map the report's `hash` does: " + e);
        }
    }

    @Test
    void cleanGateVerdictIsOkTrueEmptyViolations() throws Exception {
        Path cls = compileFixture();
        Path pol = scratch.resolve("arch.policy");
        Files.writeString(pol, "deny Db Shape\n");   // nothing does Db — clean
        Path gate = scratch.resolve("gate.json");
        Run r = runCli(cls.toString(), "--policy", pol.toString(), "--gate-json", gate.toString());
        assertEquals(0, r.exit(), r.stderr());
        JsonObject v = JsonParser.parseString(Files.readString(gate)).getAsJsonObject();
        assertEquals(VERDICT_KEYS, keysOf(v));
        assertTrue(v.get("ok").getAsBoolean());
        assertEquals(0, v.getAsJsonArray("violations").size(), "a clean run writes ok:true, []");
    }
}
