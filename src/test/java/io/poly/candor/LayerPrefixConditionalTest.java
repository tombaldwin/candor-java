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
 * ⟨0.28⟩ <b>{@code layerPrefix} IS EMITTED WHEN, AND ONLY WHEN, A PREFIX WAS ACTUALLY COLLAPSED</b> —
 * SPEC §6.1, and conformance PART 45 is the cross-engine row.
 *
 * <p>This engine emitted {@code "layerPrefix": ""} UNCONDITIONALLY from {@code containment}, while the
 * other three engines emit no such key at all. Both halves were wrong: a key one engine emits and
 * another does not is a divergence a consumer sees, and a field that is always present and usually
 * empty is the {@code fs: Vec::new()} defect {@code conformance/field_audit.py}'s header documents —
 * <i>"a present-but-always-empty field asserts 'kind undetermined' … while wearing a schema that
 * implies support"</i>.
 *
 * <p>The field is load-bearing when NON-empty ({@code owner} and {@code placement} are layer names, and
 * a collapsed prefix changes what those names denote), so both directions are pinned here: the collapsed
 * prefix MUST be reported, and its ABSENCE means none was — a real answer under §2's
 * omit-rather-than-guess convention, never a gap.
 */
class LayerPrefixConditionalTest {

    @TempDir Path tmp;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private PrintStream priorOut;
    private PrintStream priorErr;

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
        m.put("hash", "");
        return m;
    }

    private Path report(String name, List<Map<String, Object>> entries) throws Exception {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("candor", Map.of("version", "test", "toolchain", "test", "spec", Candor.SPEC_VERSION));
        env.put("packages", List.of("app"));
        env.put("analyzed", Map.of("count", entries.size(), "digest", "0"));
        env.put("functions", entries);
        Path p = tmp.resolve(name);
        Files.writeString(p, io.poly.candor.model.ReportJson.pretty(env));
        return p;
    }

    private JsonObject containmentJson(Path report) {
        out.reset();
        err.reset();
        int rc = Query.run(new String[]{"containment", "--report", report.toString(), "--json"});
        assertEquals(0, rc, "the containment diagnostic answers at exit 0");
        return JsonParser.parseString(out.toString()).getAsJsonObject();
    }

    /** A shared dotted root IS collapsed → the key is present and is that root, verbatim — the
     *  load-bearing case: every layer name in {@code owner}/{@code placement} is relative to it. */
    @Test void aCollapsedPrefixIsReportedVerbatim() throws Exception {
        Path rep = report("shared.app.jvm.json", List.of(
                entry("com.acme.repo.Save.run", List.of("Fs")),
                entry("com.acme.repo.Load.run", List.of("Fs")),
                entry("com.acme.svc.Fetch.run", List.of("Net"))));
        JsonObject doc = containmentJson(rep);
        assertTrue(doc.has("layerPrefix"), "a collapsed prefix MUST be reported (SPEC §6.1 ⟨0.28⟩)");
        assertEquals("com.acme", doc.get("layerPrefix").getAsString(),
                "the reported prefix is the collapsed root, verbatim");
        assertFalse(doc.getAsJsonArray("contained").isEmpty(),
                "control: the run answered — an asserted key on an empty answer proves nothing");
    }

    /** No shared root → NO key at all. {@code ""} here is the unconditional emission this test exists
     *  to prevent: absence means no prefix was collapsed, and the other engines' consumers already read
     *  it that way. */
    @Test void noCollapseEmitsNoKeyAtAll() throws Exception {
        Path rep = report("split.app.jvm.json", List.of(
                entry("alpha.repo.Save.run", List.of("Fs")),
                entry("beta.svc.Fetch.run", List.of("Net"))));
        JsonObject doc = containmentJson(rep);
        assertFalse(doc.has("layerPrefix"),
                "no prefix was collapsed, so there must be NO layerPrefix key — an empty \"\" is the "
                + "present-but-always-empty defect (field_audit.py), not a hedge");
        // The intact-answer control: withholding the key must not perturb the rest of the document.
        assertEquals(List.of("contained", "ambient"), List.copyOf(doc.keySet()),
                "the document is exactly {contained, ambient} — the fix removes one key, it does not "
                + "reshape the answer");
        assertEquals(2, doc.getAsJsonArray("contained").size(),
                "control: both effects still answered (Fs in alpha, Net in beta)");
    }
}
