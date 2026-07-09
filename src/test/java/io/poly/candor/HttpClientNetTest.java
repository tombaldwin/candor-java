package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Declarative HTTP-client interfaces → Net (the OpenFeign analog for the rest of the ecosystem). A call to a
 * Retrofit / Micronaut @Client / MicroProfile RegisterRestClient / Spring @*Exchange interface is a wire call,
 * but the interface has no body — so it read `Unknown` (disclosed, not a sin). Modeling it Net is a precision
 * win: `deny Net <layer>` now catches a layer calling one. The Object protocol stays pure (no fabrication).
 */
class HttpClientNetTest {

    @Test
    void declarativeHttpClientsAreNet_objectProtocolStaysPure() throws Exception {
        Path app = compileApp(
            Map.of(
                "retrofit2/http/GET.java",
                "package retrofit2.http; import java.lang.annotation.*;\n"
                    + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface GET { String value(); }",
                "io/micronaut/http/client/annotation/Client.java",
                "package io.micronaut.http.client.annotation; import java.lang.annotation.*;\n"
                    + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface Client { String value() default \"\"; }",
                "org/eclipse/microprofile/rest/client/inject/RegisterRestClient.java",
                "package org.eclipse.microprofile.rest.client.inject; import java.lang.annotation.*;\n"
                    + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface RegisterRestClient {}",
                "jakarta/ws/rs/GET.java",
                "package jakarta.ws.rs; import java.lang.annotation.*;\n"
                    + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface GET {}",
                "org/springframework/web/service/annotation/GetExchange.java",
                "package org.springframework.web.service.annotation; import java.lang.annotation.*;\n"
                    + "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface GetExchange { String value() default \"\"; }"),
            Map.of(
                "app/Clients.java", String.join("\n",
                    "package app;",
                    "interface Retro { @retrofit2.http.GET(\"/u\") Object users(); }",
                    "@io.micronaut.http.client.annotation.Client(\"/s\") interface Mn { Object users(); }",
                    "@org.eclipse.microprofile.rest.client.inject.RegisterRestClient interface Mp { @jakarta.ws.rs.GET Object users(); }",
                    "interface Spx { @org.springframework.web.service.annotation.GetExchange(\"/u\") Object users(); }"),
                "app/Use.java", String.join("\n",
                    "package app;",
                    "public class Use {",
                    "  public static Object retrofit(Retro r){ return r.users(); }",
                    "  public static Object micronaut(Mn m){ return m.users(); }",
                    "  public static Object microprofile(Mp m){ return m.users(); }",
                    "  public static Object spring(Spx s){ return s.users(); }",
                    "  public static String objectProto(Retro r){ return r.toString(); } }")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : List.of("retrofit", "micronaut", "microprofile", "spring")) {
                assertTrue(eff(r, "app.Use." + m).contains(Effect.NET),
                    m + " HTTP-client call must be Net, got " + r.get("app.Use." + m));
            }
            assertFalse(eff(r, "app.Use.objectProto").contains(Effect.NET),
                "toString() on a client interface must not fabricate Net, got " + r.get("app.Use.objectProto"));
        } finally { rm(app.getParent()); }
    }

    // ── two-phase harness: lib → classpath (not scanned), app → scanned ─────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

}
