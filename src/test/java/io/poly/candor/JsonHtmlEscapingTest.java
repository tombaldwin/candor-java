package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.ReportJson;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A JVM unit name carries `<init>` / `<clinit>`. Gson's default HTML-safe escaping wrote them as
 * {@code <init>}, so a committed baseline (636 of each, in uflexi's) read as Unicode to every
 * reviewer of a baseline diff (uflexi field report, 2026-10-06). The JSON value is identical either way;
 * what this pins is the BYTES a person reads. Both serializers that write reports and query output.
 */
class JsonHtmlEscapingTest {

    private static final String FN = "com.example.Svc.<init>(Ljava/lang/String;)V";

    @Test
    void theReportSerializerWritesAngleBracketsAsThemselves() {
        String out = ReportJson.pretty(Map.of("fn", FN, "clinit", "com.example.Svc.<clinit>()V"));
        assertTrue(out.contains("<init>") && out.contains("<clinit>"), out);
        assertFalse(out.contains("\\u003c") || out.contains("\\u003e"), out);
    }

    @Test
    void theQuerySerializerWritesAngleBracketsAsThemselves() {
        String out = Query.JSON.toJson(Map.of("fn", FN));
        assertTrue(out.contains("<init>"), out);
        assertFalse(out.contains("\\u003c") || out.contains("\\u003e"), out);
    }
}
