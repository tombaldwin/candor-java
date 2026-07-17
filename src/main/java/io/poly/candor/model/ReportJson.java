package io.poly.candor.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The single (de)serialization point for the candor wire format (candor-spec §2). Centralizing it
 * here is what keeps the typed model byte-identical to the hand-built JSON it replaces: the field
 * order, the conditional omission of optional fields, and the spec-name effect ordering all live in
 * one place. The write path does NOT reflect {@link Effector} directly (a record can't express
 * conditional omission); it builds the exact {@link LinkedHashMap} the engine emitted before.
 */
public final class ReportJson {

    private ReportJson() {}

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    /** Pretty-print any value with the one shared Gson (used for the callgraph/hierarchy sidecars,
     *  so every wire write goes through this class's serializer). */
    public static String pretty(Object value) {
        return GSON.toJson(value);
    }

    /** Serialize a report to the §2 envelope JSON, byte-identical to the legacy hand-built form. */
    public static String serialize(Report report) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("version", report.candor().version());
        header.put("toolchain", report.candor().toolchain());
        header.put("spec", report.candor().spec());
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("candor", header);
        envelope.put("packages", report.packages());
        // ⟨0.15 staged⟩ the κ-coverage ledger as data (§2 `coverage`): OMITTED entirely when nothing is
        // uncovered, so a fully-covered report is byte-identical to a pre-⟨0.15⟩ one. Placed before the
        // (large) `functions` array with the other envelope-level facts.
        if (report.coverage() != null && !report.coverage().uncovered().isEmpty()) {
            List<Map<String, Object>> unc = new ArrayList<>();
            for (Coverage.Uncovered u : report.coverage().uncovered()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", u.name());
                m.put("calls", u.calls());
                unc.add(m);
            }
            Map<String, Object> cov = new LinkedHashMap<>();
            cov.put("uncovered", unc);
            envelope.put("coverage", cov);
        }
        List<Map<String, Object>> entries = new ArrayList<>();
        for (Effector e : report.functions()) entries.add(entry(e));
        envelope.put("functions", entries);
        return GSON.toJson(envelope);
    }

    /** One report entry, in the exact field order with the exact conditional-omission rules. */
    private static Map<String, Object> entry(Effector e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fn", e.fn());
        m.put("loc", e.loc());
        m.put("inferred", e.inferred().toNames());
        if (!e.invisible().isEmpty()) m.put("invisible", e.invisible());
        m.put("direct", e.direct().toNames());
        m.put("declared", e.declared().toNames());
        m.put("undeclared", e.undeclared().toNames());
        m.put("overdeclared", e.overdeclared().toNames());
        m.put("entryPoint", e.entryPoint());
        m.put("unresolved", e.unresolved());
        if (e.kind() != EffectorKind.FUNCTION) m.put("unitKind", e.kind().wireName());
        if (!e.unknownWhy().isEmpty())
            m.put("unknownWhy",
                    e.unknownWhy().stream().sorted().map(UnknownReason::format).collect(Collectors.toList()));
        m.put("hash", e.hash());
        if (!e.calls().isEmpty()) m.put("calls", e.calls());
        if (!e.fs().isEmpty()) m.put("fs", e.fs());
        if (!e.hosts().isEmpty()) m.put("hosts", e.hosts());
        if (!e.cmds().isEmpty()) m.put("cmds", e.cmds());
        if (!e.paths().isEmpty()) m.put("paths", e.paths());
        if (!e.tables().isEmpty()) m.put("tables", e.tables());
        if (!e.netClass().isEmpty()) m.put("netClass", e.netClass()); // ⟨0.21⟩ Net destination-class (SPEC §1)
        return m;
    }

    // ---- read side -----------------------------------------------------------------------------

    /**
     * Parse a {@code functions} array into {@link Effector}s, tolerantly: missing fields take their
     * empty/default value (never null), unknown {@code unitKind}/effect names are tolerated (spec §2
     * forward compatibility), and a foreign {@code unknownWhy} prefix is preserved verbatim. No
     * filtering or sorting — the caller (Query) drops un-named entries and sorts, as before.
     */
    public static List<Effector> parseEntries(JsonArray arr) {
        List<Effector> out = new ArrayList<>();
        for (JsonElement el : arr) {
            if (!el.isJsonObject()) continue;
            JsonObject o = el.getAsJsonObject();
            out.add(new Effector(
                    str(o, "fn"),
                    str(o, "loc"),
                    EffectSet.ofNames(strList(o, "inferred")),
                    strList(o, "invisible"),
                    EffectSet.ofNames(strList(o, "direct")),
                    EffectSet.ofNames(strList(o, "declared")),
                    EffectSet.ofNames(strList(o, "undeclared")),
                    EffectSet.ofNames(strList(o, "overdeclared")),
                    bool(o, "entryPoint"),
                    bool(o, "unresolved"),
                    EffectorKind.fromWire(has(o, "unitKind") ? str(o, "unitKind") : null),
                    strList(o, "unknownWhy").stream().map(UnknownReason::parse)
                            .filter(Objects::nonNull).collect(Collectors.toList()),
                    str(o, "hash"),
                    strList(o, "calls"),
                    strList(o, "fs"),
                    strList(o, "hosts"),
                    strList(o, "cmds"),
                    strList(o, "paths"),
                    strList(o, "tables"),
                    strList(o, "netClass")));
        }
        return out;
    }

    private static boolean has(JsonObject o, String k) {
        return o.has(k) && !o.get(k).isJsonNull();
    }

    private static String str(JsonObject o, String k) {
        return has(o, k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : "";
    }

    private static boolean bool(JsonObject o, String k) {
        return has(o, k) && o.get(k).isJsonPrimitive() && o.get(k).getAsBoolean();
    }

    private static List<String> strList(JsonObject o, String k) {
        List<String> r = new ArrayList<>();
        if (has(o, k) && o.get(k).isJsonArray())
            for (JsonElement e : o.getAsJsonArray(k))
                if (e.isJsonPrimitive()) r.add(e.getAsString());
        return r;
    }
}
