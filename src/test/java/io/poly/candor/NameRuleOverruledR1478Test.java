package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1478 — an OWNER-WIDE NAME RULE at the consumer's call, against the generated framework table's reading of
 * the exact member. Guards for any fix of R1478: each member below is charged by the rule, its closure reaches a
 * dispatch the table cannot follow, and its body REALLY performs the rule's effect, so it must stay charged at the
 * caller. EXECUTED (driver handles as logging proxies, ~/candor-handoff/java-r1478/gt-exec-*.txt):
 * {@code RedisTemplate.execute(RedisScript, List, Object...)} reaches {@code RedisConnection.evalSha};
 * {@code KafkaTemplate.receive(String, int, long)} reaches {@code Consumer.poll}; the reactive Cassandra repository's
 * {@code findAll()} reaches {@code ReactiveSession.prepare}.
 *
 * <p>The third is the case that refuted a table-only overrule (drop the rule wherever the closure is opaque and no
 * surveyed implementer carries the effect — R1468's step-5a test applied at the call): that rule took it from
 * {@code Db} to {@code Unknown}, among 63 removed (member, effect) pairs an independent ASM checker traces to a Redisson
 * command executor or a reactive Cassandra / Elasticsearch client — the query runs in a deferred lambda or behind a
 * driver interface the table cannot follow. The first two are kept by that rule and by the bare rule alike.
 */
class NameRuleOverruledR1478Test {

    @BeforeEach
    void fresh() { Candor.resetState(); }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        EffectSet e = r.get(fn);
        return e == null ? EffectSet.empty() : e;
    }

    // ── written FIRST: a hedged member whose body really performs the rule's effect stays charged ────────────────────

    @Test
    void aHedgedMemberWhoseBodyReallyQueriesStaysChargedDb() throws Exception {
        Path app = compileApp(
                Map.of("org/springframework/data/redis/core/RedisTemplate.java", String.join("\n",
                                "package org.springframework.data.redis.core;",
                                "public class RedisTemplate<K, V> {",
                                "  public <T> T execute(org.springframework.data.redis.core.script.RedisScript<T> s, java.util.List<K> keys, Object... args) { return null; }",
                                "}"),
                        "org/springframework/data/redis/core/script/RedisScript.java", String.join("\n",
                                "package org.springframework.data.redis.core.script;",
                                "public interface RedisScript<T> {}")),
                Map.of("app/R.java", String.join("\n",
                        "package app;",
                        "import org.springframework.data.redis.core.RedisTemplate;",
                        "import org.springframework.data.redis.core.script.RedisScript;",
                        "public class R {",
                        "  public static Object run(RedisTemplate<String, String> t, RedisScript<Long> s) { return t.execute(s, java.util.List.of(\"k\")); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.R.run").contains(Effect.DB), "deny Db must fire, got " + eff(r, "app.R.run"));
        } finally { rm(app.getParent()); }
    }

    @Test
    void aHedgedMemberWhoseBodyReallyPollsTheBrokerStaysChargedNet() throws Exception {
        Path app = compileApp(
                Map.of("org/springframework/kafka/core/KafkaTemplate.java", String.join("\n",
                                "package org.springframework.kafka.core;",
                                "public class KafkaTemplate<K, V> {",
                                "  public org.apache.kafka.clients.consumer.ConsumerRecord<K, V> receive(String topic, int partition, long offset) { return null; }",
                                "}"),
                        "org/apache/kafka/clients/consumer/ConsumerRecord.java", String.join("\n",
                                "package org.apache.kafka.clients.consumer;",
                                "public class ConsumerRecord<K, V> {}")),
                Map.of("app/K.java", String.join("\n",
                        "package app;",
                        "import org.springframework.kafka.core.KafkaTemplate;",
                        "public class K {",
                        "  public static Object take(KafkaTemplate<String, String> t) { return t.receive(\"t\", 0, 0L); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.K.take").contains(Effect.NET), "deny Net must fire, got " + eff(r, "app.K.take"));
        } finally { rm(app.getParent()); }
    }

    /** The counter-case that stopped the lane: a table-only overrule (opaque closure + no surveyed implementer carrying
     *  the effect) turned this from Db into Unknown. The query runs in a lambda the reactive template defers, so the
     *  table's implementer reads Clock,Log while the repository really queries. EXECUTED: findAll().block() reaches
     *  ReactiveSession.prepare. */
    @Test
    void aReactiveRepositoryWhoseQueryIsDeferredStaysChargedDb() throws Exception {
        Path app = compileApp(
                Map.of("org/springframework/data/cassandra/repository/support/SimpleReactiveCassandraRepository.java", String.join("\n",
                                "package org.springframework.data.cassandra.repository.support;",
                                "public class SimpleReactiveCassandraRepository<T, ID> {",
                                "  public reactor.core.publisher.Flux<T> findAll() { return null; }",
                                "}"),
                        "reactor/core/publisher/Flux.java", String.join("\n",
                                "package reactor.core.publisher;",
                                "public abstract class Flux<T> {}")),
                Map.of("app/C.java", String.join("\n",
                        "package app;",
                        "import org.springframework.data.cassandra.repository.support.SimpleReactiveCassandraRepository;",
                        "public class C {",
                        "  public static Object all(SimpleReactiveCassandraRepository<String, String> r) { return r.findAll(); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.C.all").contains(Effect.DB), "deny Db must fire, got " + eff(r, "app.C.all"));
        } finally { rm(app.getParent()); }
    }
    // ── the fix: hand-listed members executed doing nothing yield to the table at the consumer's call ───────────────

    private static final Map<String, String> REDIS = Map.of(
            "org/springframework/data/redis/core/RedisTemplate.java", String.join("\n",
                    "package org.springframework.data.redis.core;",
                    "public class RedisTemplate<K, V> {",
                    "  public BoundValueOperations<K, V> boundValueOps(K key) { return null; }",
                    "  public BoundValueOperations<K, V> boundValueOps(K key, int unlisted) { return null; }",
                    "}"),
            "org/springframework/data/redis/core/BoundValueOperations.java", String.join("\n",
                    "package org.springframework.data.redis.core;",
                    "public interface BoundValueOperations<K, V> { V get(); }"));

    /** EXECUTED (GtR1478, ~/candor-handoff/java-survey/gt-exec.txt): boundValueOps builds a proxy and calls no driver,
     *  while get() on what it returns opens a connection. The call reads the table's U line, not Db; the later call keeps
     *  Db through the `*Operations` rule. */
    @Test
    void boundValueOpsYieldsToTheTableButItsGetKeepsDb() throws Exception {
        Path app = compileApp(REDIS, Map.of("app/B.java", String.join("\n",
                "package app;",
                "import org.springframework.data.redis.core.RedisTemplate;",
                "public class B {",
                "  public static Object bind(RedisTemplate<Object, Object> t) { return t.boundValueOps(\"k\"); }",
                "  public static Object read(RedisTemplate<Object, Object> t) { return t.boundValueOps(\"k\").get(); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            EffectSet bind = eff(r, "app.B.bind");
            assertFalse(bind.contains(Effect.DB), "boundValueOps does nothing (executed); got " + bind);
            assertTrue(bind.contains(Effect.UNKNOWN), "the table's U line must disclose the call, got " + bind);
            assertTrue(eff(r, "app.B.read").contains(Effect.DB), "get() queries: deny Db must fire, got " + eff(r, "app.B.read"));
        } finally { rm(app.getParent()); }
    }

    /** The guard: a listed member the table has no line for keeps the rule (an over-charge, never a silence). */
    @Test
    void aListedMemberTheTableDoesNotAnswerKeepsTheRule() throws Exception {
        Path app = compileApp(REDIS, Map.of("app/G.java", String.join("\n",
                "package app;",
                "import org.springframework.data.redis.core.RedisTemplate;",
                "public class G {",
                "  public static Object bind(RedisTemplate<Object, Object> t) { return t.boundValueOps(\"k\", 1); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.G.bind").contains(Effect.DB), "no table line: the rule stays, got " + eff(r, "app.G.bind"));
        } finally { rm(app.getParent()); }
    }

    /** EXECUTED: `new RabbitTemplate(cf)` connects to nothing (idle factory, and a factory already holding a connection);
     *  convertAndSend on the same object does. */
    @Test
    void newRabbitTemplateYieldsButItsSendKeepsNet() throws Exception {
        Path app = compileApp(
                Map.of("org/springframework/amqp/rabbit/core/RabbitTemplate.java", String.join("\n",
                                "package org.springframework.amqp.rabbit.core;",
                                "public class RabbitTemplate {",
                                "  public RabbitTemplate(org.springframework.amqp.rabbit.connection.ConnectionFactory cf) {}",
                                "  public void convertAndSend(String routingKey, Object message) {}",
                                "}"),
                        "org/springframework/amqp/rabbit/connection/ConnectionFactory.java", String.join("\n",
                                "package org.springframework.amqp.rabbit.connection;",
                                "public interface ConnectionFactory {}")),
                Map.of("app/Q.java", String.join("\n",
                        "package app;",
                        "import org.springframework.amqp.rabbit.core.RabbitTemplate;",
                        "import org.springframework.amqp.rabbit.connection.ConnectionFactory;",
                        "public class Q {",
                        "  public static Object make(ConnectionFactory cf) { return new RabbitTemplate(cf); }",
                        "  public static void send(ConnectionFactory cf) { new RabbitTemplate(cf).convertAndSend(\"q\", \"x\"); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            EffectSet make = eff(r, "app.Q.make");
            assertFalse(make.contains(Effect.NET), "the constructor opens nothing (executed); got " + make);
            assertTrue(make.contains(Effect.UNKNOWN), "the table's C line must disclose the call, got " + make);
            assertTrue(eff(r, "app.Q.send").contains(Effect.NET), "convertAndSend sends: deny Net must fire, got " + eff(r, "app.Q.send"));
        } finally { rm(app.getParent()); }
    }

    /** EXECUTED: getTableName and setApplicationContext touch no CqlSession; count on the same template does. */
    @Test
    void cassandraTemplateTableNameYieldsButCountKeepsDb() throws Exception {
        Path app = compileApp(
                Map.of("org/springframework/data/cassandra/core/CassandraTemplate.java", String.join("\n",
                                "package org.springframework.data.cassandra.core;",
                                "public class CassandraTemplate {",
                                "  public com.datastax.oss.driver.api.core.CqlIdentifier getTableName(Class<?> c) { return null; }",
                                "  public void setApplicationContext(org.springframework.context.ApplicationContext c) {}",
                                "  public long count(Class<?> c) { return 0L; }",
                                "}"),
                        "com/datastax/oss/driver/api/core/CqlIdentifier.java", String.join("\n",
                                "package com.datastax.oss.driver.api.core;",
                                "public class CqlIdentifier {}"),
                        "org/springframework/context/ApplicationContext.java", String.join("\n",
                                "package org.springframework.context;",
                                "public interface ApplicationContext {}")),
                Map.of("app/T.java", String.join("\n",
                        "package app;",
                        "import org.springframework.data.cassandra.core.CassandraTemplate;",
                        "public class T {",
                        "  public static Object name(CassandraTemplate t) { return t.getTableName(Object.class); }",
                        "  public static void ctx(CassandraTemplate t, org.springframework.context.ApplicationContext c) { t.setApplicationContext(c); }",
                        "  public static long count(CassandraTemplate t) { return t.count(Object.class); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String fn : new String[] { "app.T.name", "app.T.ctx" }) {
                assertFalse(eff(r, fn).contains(Effect.DB), fn + " touches no session (executed); got " + eff(r, fn));
                assertTrue(eff(r, fn).contains(Effect.UNKNOWN), fn + " must stay disclosed, got " + eff(r, fn));
            }
            assertTrue(eff(r, "app.T.count").contains(Effect.DB), "count queries: deny Db must fire, got " + eff(r, "app.T.count"));
        } finally { rm(app.getParent()); }
    }
}
