package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Round-13 teeth: superclass &lt;clinit&gt;-chain silent-pure, the SQL-driver table-surface gate-evasion
 * (a forbidden jOOQ table must reach the surface), and the new framework-callback roots (UserDetailsService,
 * Spring *Aware, RxJava Observer, JAX-RS ContainerRequestFilter, WebSocket @OnMessage) + a decoy.
 */
class Round13FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-r13");
        List<String> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path p = dir.resolve(e.getKey());
            Files.createDirectories(p.getParent());
            Files.writeString(p, e.getValue());
            files.add(p.toString());
        }
        Path out = dir.resolve("cls");
        Files.createDirectories(out);
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        args.addAll(files);
        assertEquals(0, jc.run(null, null, null, args.toArray(new String[0])), "fixture must compile");
        return out;
    }

    private static void rm(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    /** Touching a subclass runs its SUPERCLASS's &lt;clinit&gt; (JVMS §5.5) — an effect in the base's static
     *  initializer must propagate to the use site, not be silently dropped. */
    @Test
    void superclassClinitChainReached() throws Exception {
        Path cls = compile(Map.of("app/A.java", String.join("\n",
            "package app;",
            "public class A {",
            "  static class Base { static { try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
            "  static class Sub extends Base { static void m(){} }",
            "  void use(){ Sub.m(); }",   // loading Sub runs Base.<clinit> (Net)
            "}")));
        try {
            Map<String, TreeSet<String>> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.A.use", new TreeSet<>()).contains("Net"),
                    "touching Sub must reach Base.<clinit>'s Net, got " + r.get("app.A.use"));
        } finally { rm(cls.getParent()); }
    }

    /** A forbidden jOOQ table must reach the Db table surface — it was dropped (the new SQL driver owner
     *  wasn't in isSqlBearingOwner), so a method mixing an allowed JDBC table with a forbidden jOOQ table
     *  certified under the allowed one (gate-evasion). */
    @Test
    void jooqTableReachesSurface() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("org/jooq/DSLContext.java",
                "package org.jooq; public interface DSLContext { int execute(String sql); }"),
            Map.entry("app/D.java", String.join("\n",
                "package app;",
                "public class D {",
                "  void run(org.jooq.DSLContext dsl){ dsl.execute(\"DELETE FROM accounts WHERE id=1\"); }",
                "}"))));
        try {
            Map<String, TreeSet<String>> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.D.run", new TreeSet<>()).contains("Db"), "jOOQ execute is Db");
            assertTrue(Candor.tablesDirect.getOrDefault("app.D.run", new TreeSet<>()).contains("accounts"),
                    "the jOOQ SQL's table must reach the surface, got " + Candor.tablesDirect.get("app.D.run"));
        } finally { rm(cls.getParent()); }
    }

    /** Spring Security UserDetailsService, Spring *Aware setter, RxJava Observer, JAX-RS ContainerRequestFilter,
     *  and WebSocket @OnMessage are container-invoked roots; a non-implementor decoy is NOT rooted. */
    @Test
    void newFrameworkCallbacksRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("org/springframework/security/core/userdetails/UserDetailsService.java",
                "package org.springframework.security.core.userdetails; public interface UserDetailsService { Object loadUserByUsername(String u); }"),
            Map.entry("org/springframework/context/ApplicationContextAware.java",
                "package org.springframework.context; public interface ApplicationContextAware { void setApplicationContext(Object c); }"),
            Map.entry("io/reactivex/Observer.java",
                "package io.reactivex; public interface Observer<T> { void onNext(T t); void onError(Throwable e); void onComplete(); void onSubscribe(Object d); }"),
            Map.entry("jakarta/ws/rs/container/ContainerRequestFilter.java",
                "package jakarta.ws.rs.container; public interface ContainerRequestFilter { void filter(Object ctx); }"),
            Map.entry("jakarta/websocket/OnMessage.java",
                "package jakarta.websocket; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface OnMessage {}"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "class Uds implements org.springframework.security.core.userdetails.UserDetailsService {",
                "  public Object loadUserByUsername(String u){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }",
                "class Aware implements org.springframework.context.ApplicationContextAware {",
                "  public void setApplicationContext(Object c){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class Obs implements io.reactivex.Observer<Object> {",
                "  public void onNext(Object t){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",
                "  public void onError(Throwable e){} public void onComplete(){} public void onSubscribe(Object d){} }",
                "class Filt implements jakarta.ws.rs.container.ContainerRequestFilter {",
                "  public void filter(Object ctx){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class Ws { @jakarta.websocket.OnMessage public void onMsg(String m){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class NotAware { public void setApplicationContext(Object c){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "public class A {}"))));
        try {
            Candor.runScan(cls);
            assertTrue(Candor.entryPoints.contains("app.Uds.loadUserByUsername"), "UserDetailsService must be rooted");
            assertTrue(Candor.entryPoints.contains("app.Aware.setApplicationContext"), "*Aware setter must be rooted");
            assertTrue(Candor.entryPoints.contains("app.Obs.onNext"), "RxJava Observer must be rooted");
            assertTrue(Candor.entryPoints.contains("app.Filt.filter"), "ContainerRequestFilter must be rooted");
            assertTrue(Candor.entryPoints.contains("app.Ws.onMsg"), "@OnMessage must be rooted");
            assertFalse(Candor.entryPoints.contains("app.NotAware.setApplicationContext"),
                    "a non-implementor setApplicationContext must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }
}
