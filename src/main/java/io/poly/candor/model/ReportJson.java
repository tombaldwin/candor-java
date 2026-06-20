package io.poly.candor.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    /** Serialize a report to the §2 envelope JSON, byte-identical to the legacy hand-built form. */
    public static String serialize(Report report) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("version", report.candor().version());
        header.put("toolchain", report.candor().toolchain());
        header.put("spec", report.candor().spec());
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("candor", header);
        envelope.put("packages", report.packages());
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
        return m;
    }
}
