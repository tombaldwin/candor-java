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
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * End-to-end teeth for the round-9 regression fixes: the literal-host fabrication (a Redis key that looks
 * like host:port must NOT be captured as a Net host), and the reactive-Subscriber / NIO-CompletionHandler
 * orphaned-callback rooting (+ the over-rooting decoy).
 */
class Round9FixesTest {

    private static Path compile(Map<String, String> sources) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler — skip");
        Path dir = Files.createTempDirectory("candor-r9");
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

    /** A Redis KEY that looks like host:port (or a bare IP) must NOT be captured as a Net host — the host
     *  literal sweep is now gated to methods that actually call a host-bearing owner. A genuine
     *  `new Socket("api.x.com", 443)` host is still captured. */
    @Test
    void redisKeyIsNotFabricatedAsAHost() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("redis/clients/jedis/Jedis.java",
                "package redis.clients.jedis; public class Jedis { public String get(String k){return null;} }"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "public class A {",
                "  String redis(redis.clients.jedis.Jedis j){ return j.get(\"10.0.0.1:6379\"); }",   // key, not a host
                "  void real() throws Exception { new java.net.Socket(\"api.x.com\", 443).close(); }",
                "}"))));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(r.getOrDefault("app.A.redis", EffectSet.empty()).toNames().contains("Db"), "the Jedis call is Db (Redis is a datastore — the reconciliation)");
            assertTrue(AnalysisState.ctx().hostsDirect.getOrDefault("app.A.redis", new TreeSet<>()).isEmpty(),
                    "a Redis key must NOT be captured as a host, got " + AnalysisState.ctx().hostsDirect.get("app.A.redis"));
            assertTrue(AnalysisState.ctx().hostsDirect.getOrDefault("app.A.real", new TreeSet<>()).contains("api.x.com:443"),
                    "a genuine Socket host must still be captured");
        } finally { rm(cls.getParent()); }
    }

    /** Reactive Subscriber + NIO CompletionHandler callbacks are rooted; a same-named non-implementor
     *  decoy and a project class whose name merely CONTAINS a row substring are NOT rooted. */
    @Test
    void reactiveAndAsyncCallbacksRootedNoOverRoot() throws Exception {
        Path cls = compile(Map.ofEntries(
            Map.entry("org/reactivestreams/Subscriber.java",
                "package org.reactivestreams; public interface Subscriber<T> { void onNext(T t); void onError(Throwable e); void onComplete(); void onSubscribe(Object s); }"),
            Map.entry("com/fasterxml/jackson/databind/JsonDeserializer.java",
                "package com.fasterxml.jackson.databind; public abstract class JsonDeserializer<T> { public abstract T deserialize(Object p); }"),
            Map.entry("app/A.java", String.join("\n",
                "package app;",
                "class Sub implements org.reactivestreams.Subscriber<Object> {",
                "  public void onNext(Object t){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",
                "  public void onError(Throwable e){} public void onComplete(){} public void onSubscribe(Object s){} }",
                "class Handler implements java.nio.channels.CompletionHandler<Integer,Object> {",
                "  public void completed(Integer n, Object a){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} }",
                "  public void failed(Throwable t, Object a){} }",
                "class JsonDeserializerMetrics { public Object deserialize(Object p){ try{new java.net.Socket(\"h\",80).close();}catch(Exception e){} return null; } }", // NOT a Jackson deser
                "public class A {}"))));
        try {
            Candor.runScan(cls);
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Sub.onNext"), "Subscriber.onNext must be rooted");
            assertTrue(AnalysisState.ctx().entryPoints.contains("app.Handler.completed"), "CompletionHandler.completed must be rooted");
            assertFalse(AnalysisState.ctx().entryPoints.contains("app.JsonDeserializerMetrics.deserialize"),
                    "a class merely CONTAINING 'JsonDeserializer' must NOT be over-rooted");
        } finally { rm(cls.getParent()); }
    }
}
