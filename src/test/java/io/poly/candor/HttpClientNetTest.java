package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
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

    private static Path compileApp(Map<String, String> lib, Map<String, String> app) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path base = Files.createTempDirectory("candor-http");
        Path libOut = compileTo(jc, base.resolve("src-lib"), lib, base.resolve("lib"), null);
        compileTo(jc, base.resolve("src-app"), app, base.resolve("app"), libOut);
        return base.resolve("app");
    }

    private static Path compileTo(javax.tools.JavaCompiler jc, Path src, Map<String, String> sources,
            Path out, Path classpath) throws Exception {
        List<String> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path p = src.resolve(e.getKey());
            Files.createDirectories(p.getParent());
            Files.writeString(p, e.getValue());
            files.add(p.toString());
        }
        Files.createDirectories(out);
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        if (classpath != null) { args.add("-cp"); args.add(classpath.toString()); }
        args.addAll(files);
        assertEquals(0, jc.run(null, null, null, args.toArray(new String[0])), "javac");
        return out;
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    private static void rm(Path dir) throws Exception {
        if (dir == null || !Files.exists(dir)) return;
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> { try { Files.delete(p); } catch (Exception ignored) {} });
        }
    }
}
