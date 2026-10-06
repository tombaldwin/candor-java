package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R796 — root status is the only gate on R17's disclosure (an entry point reading a
 * container-supplied abstract stream discloses {@code Unknown}), so a request handler the root lists miss
 * reads PURE. JAX-RS's list carried six of its seven designators ({@code @OPTIONS} missing) and Micronaut's
 * carried five route annotations of ten.
 *
 * <p>A designator is a RULE, not a list: JAX-RS defines one as any annotation type meta-annotated
 * {@code @HttpMethod}, Micronaut as any meta-annotated {@code @HttpMethodMapping}. Both API jars sit on the
 * CLASSPATH here (lib), not in the scan, exactly as in a real project — so the meta walk cannot read their
 * meta-annotations and the closure must be listed; a team's own designator IS in the scan, and the rule
 * roots it. Every body is identical; only the annotation varies.
 */
class R796DesignatorRootingTest {

    private static String anno(String pkg, String name, String meta) {
        return "package " + pkg + "; import java.lang.annotation.*;\n" + meta
                + " @Retention(RetentionPolicy.RUNTIME) public @interface " + name + " { String value() default \"\"; }";
    }

    @Test
    void everyDesignatorRootsItsHandlerAndNoLookalikeDoes() throws Exception {
        String jr = "jakarta.ws.rs", mn = "io.micronaut.http.annotation";
        String jrMeta = "@jakarta.ws.rs.HttpMethod(\"X\")", mnMeta = "@io.micronaut.http.annotation.HttpMethodMapping";
        Map<String, String> lib = new java.util.HashMap<>();
        lib.put("jakarta/ws/rs/HttpMethod.java", "package jakarta.ws.rs; import java.lang.annotation.*;\n"
                + "@Target(ElementType.ANNOTATION_TYPE) @Retention(RetentionPolicy.RUNTIME) public @interface HttpMethod { String value(); }");
        for (String d : List.of("GET", "HEAD", "OPTIONS")) lib.put("jakarta/ws/rs/" + d + ".java", anno(jr, d, jrMeta));
        lib.put("io/micronaut/http/annotation/HttpMethodMapping.java", anno(mn, "HttpMethodMapping", ""));
        for (String d : List.of("Get", "Head", "Options", "Trace", "CustomHttpMethod", "Error"))
            lib.put("io/micronaut/http/annotation/" + d + ".java", anno(mn, d, mnMeta));
        // the lookalike: Micronaut's @Header targets METHOD (a declarative-client header), is not a route,
        // and its name STARTS WITH "Head" — the root list matches by substring.
        lib.put("io/micronaut/http/annotation/Header.java", anno(mn, "Header", ""));

        String body = "(java.io.InputStream in) throws java.io.IOException { return in.read(); }";
        Path app = compileApp(lib, Map.of(
            "app/PROPFIND.java", "package app; import java.lang.annotation.*;"
                + " @jakarta.ws.rs.HttpMethod(\"PROPFIND\") @Retention(RetentionPolicy.RUNTIME) public @interface PROPFIND {}",
            "app/NotADesignator.java", "package app; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface NotADesignator {}",
            "app/R.java", String.join("\n",
                "package app;",
                "public class R {",
                "  @jakarta.ws.rs.GET public int jGet" + body,
                "  @jakarta.ws.rs.HEAD public int jHead" + body,
                "  @jakarta.ws.rs.OPTIONS public int jOpt" + body,
                "  @PROPFIND public int jPropfind" + body,
                "  @io.micronaut.http.annotation.Get public int mGet" + body,
                "  @io.micronaut.http.annotation.Head public int mHead" + body,
                "  @io.micronaut.http.annotation.Options public int mOpt" + body,
                "  @io.micronaut.http.annotation.Trace public int mTrace" + body,
                "  @io.micronaut.http.annotation.CustomHttpMethod public int mCustom" + body,
                "  @io.micronaut.http.annotation.Error public int mError" + body,
                "  @io.micronaut.http.annotation.Header public int mHeader" + body,
                "  @NotADesignator public int decoy" + body,
                "  public int plain" + body,
                "  public static int callOpt(R r, java.io.InputStream in) throws java.io.IOException { return r.jOpt(in); }",
                "  public static int callMOpt(R r, java.io.InputStream in) throws java.io.IOException { return r.mOpt(in); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : List.of("jGet", "jHead", "jOpt", "jPropfind", "mGet", "mHead", "mOpt", "mTrace",
                    "mCustom", "mError", "callOpt", "callMOpt"))
                assertTrue(unknown(r, "app.R." + m),
                        m + ": a container-invoked handler draining its injected stream must disclose Unknown, got "
                                + r.get("app.R." + m));
            for (String m : List.of("mHeader", "decoy", "plain"))
                assertFalse(unknown(r, "app.R." + m),
                        m + ": not a request designator — must stay unrooted, got " + r.get("app.R." + m));
        } finally { rm(app.getParent()); }
    }

    private static boolean unknown(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty()).toNames().contains("Unknown");
    }
}
