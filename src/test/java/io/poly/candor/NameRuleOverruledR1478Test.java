package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
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
}
