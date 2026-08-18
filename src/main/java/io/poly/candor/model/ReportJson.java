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
        // ⟨0.27⟩ SPEC §2.1 `resolves`: the OPTIONAL refinement surfaces this producer computes. Without it
        // the absence of such a field is overloaded between "does not compute this" and "computed and could
        // not determine it", and a consumer cannot read the omission. candor-java resolves `fs` read/write
        // kinds, so it says so. A producer MUST NOT list a surface it does not compute — that turns
        // "unimplemented" into a false "undetermined", the inversion the field exists to prevent.
        // ⟨0.29⟩ `incomplete` joins the list: an optional per-function refinement surface whose absence
        // is overloaded exactly the way `fs`'s was — "does not compute undetermined locators" vs
        // "computed them and found none". Same rule as ever governs membership: this engine computes it,
        // so it declares it, and a producer that did not must not.
        envelope.put("resolves", java.util.List.of("fs", "incomplete"));
        // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 1): the analyzed-universe summary, so a consumer of the bare
        // envelope tells analyzed-pure from never-seen (pure count = analyzed.count − |functions|). Emitted
        // whenever the engine could enumerate its analyzed set (always, here); omitted only if it couldn't.
        if (report.analyzed() != null) {
            Map<String, Object> an = new LinkedHashMap<>();
            an.put("count", report.analyzed().count());
            an.put("digest", report.analyzed().digest());
            envelope.put("analyzed", an);
        }
        // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): the target's own source candor could NOT analyze (skipped
        // unparseable .class). OMITTED when empty (a complete scan is byte-identical to a pre-rung report),
        // so a MACHINE reading --json sees the incompleteness the stderr warning alone used to hide.
        if (report.unanalyzed() != null && !report.unanalyzed().isEmpty()) {
            List<Map<String, Object>> un = new ArrayList<>();
            for (Report.UnanalyzedUnit u : report.unanalyzed()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("path", u.path());
                m.put("reason", u.reason());
                un.add(m);
            }
            envelope.put("unanalyzed", un);
        }
        // ⟨0.29⟩ THE SCOPE: what the scan chose not to OPEN, by class. ALWAYS emitted, `[]` included —
        // ⟨0.27⟩ makes a zero-match a positive statement ("I looked and excluded nothing"), and ⟨0.26⟩
        // makes an ABSENT key mean "this producer cannot answer", a different claim. That is the OPPOSITE
        // rule from `coverage`/`unanalyzed` directly above, deliberately: for a LEDGER, empty and absent
        // can mean the same thing; for a SCOPE they cannot.
        List<Map<String, Object>> exc = new ArrayList<>();
        for (Report.ExcludedClass c
                : report.excluded() == null ? List.<Report.ExcludedClass>of() : report.excluded()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("class", c.cls());
            m.put("count", c.count());
            m.put("peeked", c.peeked());
            m.put("reason", c.reason());
            exc.add(m);
        }
        envelope.put("excluded", exc);
        // ⟨0.29⟩ …and what the PEEK found in them. OMITTED when null — no policy was configured, so nothing
        // was asked and `[]` would be a claim. Present-and-empty means asked-and-clear, and it is a claim
        // about the classes marked `peeked` above and only those.
        if (report.outOfScope() != null) envelope.put("outOfScope", outOfScopeJson(report.outOfScope()));
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
        if (!e.netClass().isEmpty()) m.put("netClass", e.netClass()); // ⟨0.20⟩ Net destination-class (SPEC §1)
        // ⟨0.29⟩ SPEC §2 `incomplete` — the effects whose LOCATOR this unit could not determine. OMITTED
        // when empty, so a scan that determined everything is byte-identical to a pre-rung report. This
        // engine computed the fact and kept it internal; a consumer chaining the report therefore had
        // nothing to carry, and §2's chained-join clause is written about exactly that.
        if (!e.incomplete().isEmpty()) m.put("incomplete", e.incomplete());
        // ⟨0.23⟩ interfaceUnion (SPEC §2, WORKSPACE-CHAINING-DESIGN.md): this entry is SYNTHETIC — the union
        // over a local interface's implementers, published so a CHAINED consumer's cross-package interface
        // dispatch resolves. OMITTED when false, so every ordinary entry (and every report produced without
        // CANDOR_WORKSPACE_CHAIN) is byte-identical to a pre-⟨0.23⟩ one.
        if (e.interfaceUnion()) m.put("interfaceUnion", true);
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
                    strList(o, "netClass"),
                    strList(o, "incomplete"),   // ⟨0.29⟩ absent → nothing was undetermined
                    bool(o, "interfaceUnion")));   // ⟨0.23⟩ absent/false → an ordinary entry
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

    /** ⟨0.30⟩ The peek's findings as wire maps. SHARED by the report envelope above and the `--gate-json`
     *  verdict (Candor.writeGateJson), because ⟨0.30⟩ makes a non-empty {@code outOfScope} suppress
     *  {@code ok} and §3.1 makes byte-equality between `scan --policy` and `gate --report` the acceptance
     *  test — two hand-written serializers of the same records is exactly how those two documents drift.
     */
    public static List<Map<String, Object>> outOfScopeJson(List<Report.OutOfScope> findings) {
        List<Map<String, Object>> oos = new ArrayList<>();
        for (Report.OutOfScope f : findings) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("fn", f.fn());
            m.put("path", f.path());
            m.put("effects", f.effects());
            m.put("class", f.cls());
            m.put("reason", f.reason());
            oos.add(m);
        }
        return oos;
    }
}
