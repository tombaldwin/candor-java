package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * End-to-end teeth for the round-10 orphan-root fixes: JPA AttributeConverter, Hystrix command body,
 * Spring Boot HealthIndicator, CDI {@code @Observes} (a PARAMETER annotation), Guava EventBus
 * {@code @Subscribe}, and GUI listeners — all runtime-invoked with no project call site, so an
 * effectful body must become a reachability root (otherwise silent-pure for a blast-radius walk). Plus
 * a non-implementor decoy proving no over-rooting.
 *
 * <p>Originally review round 10 (Round10FixesTest).
 */
class RuntimeInvokedRootsTest {

    /** JPA AttributeConverter convert* methods are container-invoked roots; Hystrix run()/getFallback and
     *  Spring Boot HealthIndicator.health likewise. A class merely CONTAINING the row name is NOT rooted. */
    @Test
    void converterHystrixHealthRootedNoOverRoot() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("jakarta/persistence/AttributeConverter.java",
                "package jakarta.persistence; public interface AttributeConverter<X,Y> { Y convertToDatabaseColumn(X x); X convertToEntityAttribute(Y y); }"),
            Map.entry("com/netflix/hystrix/HystrixCommand.java",
                "package com.netflix.hystrix; public abstract class HystrixCommand<T> { protected abstract T run() throws Exception; }"),
            Map.entry("org/springframework/boot/actuate/health/HealthIndicator.java",
                "package org.springframework.boot.actuate.health; public interface HealthIndicator { Object health(); }"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "class Conv implements jakarta.persistence.AttributeConverter<String,String> {",
                "  public String convertToDatabaseColumn(String x){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return x; }",
                "  public String convertToEntityAttribute(String y){ return y; } }",
                "class Cmd extends com.netflix.hystrix.HystrixCommand<String> {",
                "  protected String run(){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }",
                "class Health implements org.springframework.boot.actuate.health.HealthIndicator {",
                "  public Object health(){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }",
                "class HealthIndicatorRegistry { public Object health(){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }", // NOT an impl
                "public class A {}"))));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Conv.convertToDatabaseColumn"), "AttributeConverter.convertToDatabaseColumn must be rooted");
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Cmd.run"), "HystrixCommand.run must be rooted");
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Health.health"), "HealthIndicator.health must be rooted");
            assertFalse(AnalysisState.ctx().entryPoints.contains("app.HealthIndicatorRegistry.health"),
                    "a non-implementor merely named *HealthIndicator* must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }

    /** CDI @Observes (a PARAMETER annotation) + Guava EventBus @Subscribe (a METHOD annotation) root the
     *  handler; an unannotated same-shaped method is NOT rooted. */
    @Test
    void observesAndSubscribeRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("jakarta/enterprise/event/Observes.java",
                "package jakarta.enterprise.event; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.PARAMETER) public @interface Observes {}"),
            Map.entry("com/google/common/eventbus/Subscribe.java",
                "package com.google.common.eventbus; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Subscribe {}"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "public class A {",
                "  public void onEvent(@jakarta.enterprise.event.Observes Object e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception ex){} }",
                "  @com.google.common.eventbus.Subscribe public void handle(Object e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception ex){} }",
                "  public void plain(Object e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception ex){} }",  // not rooted
                "}"))));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.A.onEvent"), "@Observes observer must be rooted (param annotation)");
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.A.handle"), "@Subscribe handler must be rooted");
            assertFalse(AnalysisState.ctx().entryPoints.contains("app.A.plain"), "an unannotated method must NOT be rooted");
        } finally { rm(cls.getParent()); }
    }

    /** A Swing ActionListener.actionPerformed is invoked by the EDT with no project call site → rooted. */
    @Test
    void swingActionListenerRooted() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "public class A implements java.awt.event.ActionListener {",
                "  public void actionPerformed(java.awt.event.ActionEvent e){ try{new java.net.Socket(\"h\",80).close();}catch(Exception ex){} }",
                "}"))));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.A.actionPerformed"), "ActionListener.actionPerformed must be rooted");
        } finally { rm(cls.getParent()); }
    }

    /** JDBC silent-pure end-to-end: a method that drives a ResultSet cursor (rs.next()) reports Db even
     *  when it issues no execute* itself — the cursor advance round-trips. */
    @Test
    void resultSetNextIsDb() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "import java.sql.*;",
                "public class A {",
                "  int count(ResultSet rs) throws Exception { int n=0; while(rs.next()) n++; return n; }",
                "}"))));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.A.count", EffectSet.empty()).toNames().contains("Db"),
                    "rs.next() row-fetch must be Db, got " + r.get("app.A.count"));
        } finally { rm(cls.getParent()); }
    }
}
