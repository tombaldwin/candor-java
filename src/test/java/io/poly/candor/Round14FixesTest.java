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
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Round-14 teeth: the remaining framework-callback roots — Micronaut @Scheduled (the inconsistency vs the
 * rooted Spring @Scheduled), Spring Integration @ServiceActivator, Spring StateMachine Action.execute — plus
 * a non-implementor decoy.
 */
class Round14FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-r14");
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

    @Test
    void schedulerAndIntegrationCallbacksRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("io/micronaut/scheduling/annotation/Scheduled.java",
                "package io.micronaut.scheduling.annotation; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Scheduled { String fixedRate() default \"\"; }"),
            Map.entry("org/springframework/integration/annotation/ServiceActivator.java",
                "package org.springframework.integration.annotation; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface ServiceActivator {}"),
            Map.entry("org/springframework/statemachine/action/Action.java",
                "package org.springframework.statemachine.action; public interface Action<S,E> { void execute(Object ctx); }"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "public class A {",
                "  @io.micronaut.scheduling.annotation.Scheduled(fixedRate=\"30s\") public void tick(){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",
                "  @org.springframework.integration.annotation.ServiceActivator public void handle(Object m){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",
                "  public void plain(){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",  // not annotated → not rooted
                "}")),
            Map.entry("app/Sm.java", String.join("\n",
                "package app;",
                "class SmAction implements org.springframework.statemachine.action.Action<String,String> {",
                "  public void execute(Object ctx){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class NotAnAction { public void execute(Object ctx){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} } }",
                "class Sm {}"))));
        try {
            Candor.runScan(cls);
            assertTrue(Candor.entryPoints.contains("app.A.tick"), "Micronaut @Scheduled must be rooted");
            assertTrue(Candor.entryPoints.contains("app.A.handle"), "@ServiceActivator must be rooted");
            assertTrue(Candor.entryPoints.contains("app.SmAction.execute"), "StateMachine Action must be rooted");
            assertFalse(Candor.entryPoints.contains("app.A.plain"), "an unannotated method must NOT be rooted");
            assertFalse(Candor.entryPoints.contains("app.NotAnAction.execute"),
                    "a non-implementor execute must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }
}
