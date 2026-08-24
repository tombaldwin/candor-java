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
            // ⟨0.32⟩ emitted only when TRUE: false is the default and an always-present key would make
            // every pre-rung report differ for a fact that changes nothing.
            if (c.judgedElsewhere()) m.put("judgedElsewhere", true);
            m.put("reason", c.reason());
            exc.add(m);
        }
        envelope.put("excluded", exc);
        // ⟨0.29⟩ …and what the PEEK found in them. OMITTED when null — no policy was configured, so nothing
        // was asked and `[]` would be a claim. Present-and-empty means asked-and-clear, and it is a claim
        // about the classes marked `peeked` above and only those.
        if (report.outOfScope() != null) envelope.put("outOfScope", outOfScopeJson(report.outOfScope()));
        // ⟨0.31⟩ the ambient `net-partner` that MOVED a class — after `outOfScope`, before `functions`, the
        // position ts and rust also use, so key order does not depend on which engine produced the report.
        // NULL (omitted) when nothing participated: a declaration that changed nothing is not provenance,
        // and an always-present key would make every pre-rung report differ.
        if (report.netPartners() != null)
            envelope.put("netPartners", new java.util.LinkedHashMap<>(java.util.Map.of(
                    "config", report.netPartners().config(),
                    "hosts", report.netPartners().hosts())));
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
     *
     * <p><b>⟨0.32⟩ THE TOLERANCE IS ABOUT NAMES, NEVER ABOUT SHAPES.</b> A key that is ABSENT takes its
     * default — that is the ⟨0.21⟩/⟨0.26⟩ cannot-answer reading, and it must survive. A key that is
     * PRESENT but is not of the shape §2 gives it is CORRUPT INPUT and impeaches the whole document
     * (§2's signature-key rule), because every default here is the SAFE-LOOKING value: an empty
     * {@code inferred} is a purity claim and a {@code false} boolean is a positive statement. The three
     * readers below coerced instead, and all three were MEASURED deleting a violation from
     * {@code gate --report} on a report whose only defect was a value's TYPE:
     *
     * <pre>
     * "inferred": "Exec"            -> exit 1 becomes exit 0   (coerced to [], the entry reads PURE)
     * "inferred": null              -> exit 1 becomes exit 0   (same, via the null-is-absent reading)
     * "interfaceUnion": "true"      -> exit 1 becomes exit 0   (Boolean.parseBoolean; a SYNTHETIC entry
     *                                                           is never reported as a violator)
     * "fn": { }                     -> exit 1 becomes exit 0   (coerced to "", Query.load drops the entry)
     * </pre>
     *
     * JSON null is corrupt here rather than absent: it is not any of §2's shapes, and {@link
     * io.poly.candor.Loader} has always read {@code "inferred": null} on the chained-dep route as an
     * UNTRUSTED claim ({@code Unknown}) — two spellings of the same key disagreeing across routes is how
     * a claim comes to be trusted on one and not the other.
     *
     * <p><b>AND NOT ONE KEY FURTHER.</b> §2 draws the line at the key's ROLE, and its DECORATION side is
     * a ruling too: {@code loc} and {@code hash} keep their tolerant read (see {@link #decoration}).
     * Being strict about ornament drops a hedge, which is the same defect with the sign flipped —
     * measured in this project as a fabrication-fix that deleted a surface.
     *
     * @throws IllegalStateException on a present-but-unreadable §2 key. Every caller that can reach a
     *         verdict already routes this to a §3.1 refusal ({@code Query.gate}'s {@code refuse(…)});
     *         {@code Policy.loadBaseline} degrades it to "no baseline", which is the strict direction.
     */
    public static List<Effector> parseEntries(JsonArray arr) {
        List<Effector> out = new ArrayList<>();
        for (JsonElement el : arr) {
            if (!el.isJsonObject()) continue;
            JsonObject o = el.getAsJsonObject();
            out.add(new Effector(
                    str(o, "fn"),
                    decoration(o, "loc"),
                    EffectSet.ofNames(strList(o, "inferred")),
                    strList(o, "invisible"),
                    EffectSet.ofNames(strList(o, "direct")),
                    EffectSet.ofNames(strList(o, "declared")),
                    EffectSet.ofNames(strList(o, "undeclared")),
                    EffectSet.ofNames(strList(o, "overdeclared")),
                    bool(o, "entryPoint"),
                    bool(o, "unresolved"),
                    EffectorKind.fromWire(o.has("unitKind") ? str(o, "unitKind") : null),
                    strList(o, "unknownWhy").stream().map(UnknownReason::parse)
                            .filter(Objects::nonNull).collect(Collectors.toList()),
                    decoration(o, "hash"),
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

    /**
     * ⟨0.24⟩ SPEC §2's OTHER HALF, and it is not an oversight that it stays tolerant: <i>"DECORATIONS —
     * a coverage ledger's detail, {@code loc}, and {@code hash} ON A SINGLE-REPORT ROUTE — carry no claim
     * a verdict reads. Withhold the decoration, disclose it, and answer. Refusing there drops a hedge to
     * be strict about ornament."</i> So {@code loc} and {@code hash} keep the coercing read they have
     * always had; hardening them would have been the fail-CLOSED regression that this project has now
     * twice shipped while repairing a fail-open.
     *
     * <p>The ⟨0.32⟩ carve-out — {@code hash} IS a signature key once several reports are MERGED, because
     * §2.2 makes the join depend on it — is a property of the ROUTE, which this parser does not know and
     * must not guess at. It belongs to the multi-report merge, beside the rest of that route's rules.
     */
    private static String decoration(JsonObject o, String k) {
        return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : "";
    }

    /** The one refusal, worded once. Names the key, the shape §2 gives it, and what was found — an
     *  operator holding a report and a red gate needs all three to know which half is broken. */
    private static IllegalStateException corrupt(String k, String want, JsonElement got) {
        return new IllegalStateException(
                "a report entry's `" + k + "` is " + describe(got) + ", not " + want + " — a §2 key that "
                + "cannot be read impeaches the whole document, because reading it as its default would "
                + "make the SAFE-LOOKING claim (an empty effect set is a purity claim, a false flag is a "
                + "positive statement) and that turns a violation into `policy ✓`");
    }

    private static String describe(JsonElement e) {
        if (e.isJsonNull()) return "null";
        if (e.isJsonArray()) return "an array";
        if (e.isJsonObject()) return "an object";
        var p = e.getAsJsonPrimitive();
        return p.isString() ? "the string " + p : p.isBoolean() ? "the boolean " + p : "the number " + p;
    }

    private static String str(JsonObject o, String k) {
        if (!o.has(k)) return "";   // a JSON null is PRESENT, and therefore corrupt — see above
        JsonElement v = o.get(k);
        if (!v.isJsonPrimitive() || !v.getAsJsonPrimitive().isString()) throw corrupt(k, "a string", v);
        return v.getAsString();
    }

    private static boolean bool(JsonObject o, String k) {
        if (!o.has(k)) return false; // a JSON null is PRESENT, and therefore corrupt — see above
        JsonElement v = o.get(k);
        if (!v.isJsonPrimitive() || !v.getAsJsonPrimitive().isBoolean()) throw corrupt(k, "a boolean", v);
        return v.getAsBoolean();
    }

    private static List<String> strList(JsonObject o, String k) {
        List<String> r = new ArrayList<>();
        if (!o.has(k)) return r;     // a JSON null is PRESENT, and therefore corrupt — see above
        JsonElement v = o.get(k);
        if (!v.isJsonArray()) throw corrupt(k, "an array", v);
        for (JsonElement e : v.getAsJsonArray()) {
            // A MEMBER IS THE SAME RULE ONE LEVEL DOWN. Skipping it silently shortens a list whose
            // LENGTH is the claim — the identical coercion, one nesting in.
            if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString())
                throw corrupt(k, "an array of strings", e);
            r.add(e.getAsString());
        }
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
