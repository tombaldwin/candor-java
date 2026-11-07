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
 * SOUNDNESS R1476 — the RETURN-TYPE GUARD on a proven-pure (P) getter. A getter a NAME rule charges keeps that charge
 * when the value it returns can carry the rule's effect to a LATER call the table can only disclose (the fluent-factory
 * guard, FrameworkReachGen#returnTypeInert: {@code MongoTemplate.query(X.class)} is pure and the Db is {@code .all()} on
 * the interface it returns). Since R1471 that guard fired on ANY hedged member of the returned type, so
 * {@code RestTemplate.getUriTemplateHandler()} ({@code getfield; areturn}) lost its P line because
 * {@code UriTemplateHandler.expand} is hedged — while nothing an expand can run sends anything.
 *
 * <p>The guard now asks whether the hidden later call can perform the RULE'S effect: some surveyed implementer reaches
 * it, or reaches code outside the surveyed jars and the JDK (where the table cannot see what happens), or there is no
 * surveyed implementer. EXECUTED (~/candor-handoff/java-r1476/gt-exec.txt, a local listening socket):
 * {@code getUriTemplateHandler().expand(..)} accepts 0 connections (control {@code getForObject}: connects);
 * {@code KafkaTemplate.getProducerFactory()} accepts 0, but {@code .createProducer()} on what it returns accepts 9.
 */
class ReturnTypeGuardR1476Test {

    static final String RT = "org/springframework/web/client/RestTemplate";
    static final String KT = "org/springframework/kafka/core/KafkaTemplate";

    @BeforeEach
    void fresh() { Candor.resetState(); }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        EffectSet e = r.get(fn);
        return e == null ? EffectSet.empty() : e;
    }

    // ── written FIRST: a getter whose returned value really performs the rule's effect later stays charged ───────────

    /** The producer the returned factory creates connects (executed: 9 connections); its body is in kafka-clients, which
     *  the table does not survey, so the factory's implementers read Clock/Log/Unknown and never Net. Only the guard keeps
     *  {@code deny Net} red here. */
    @Test
    void aGetterWhoseReturnedFactoryReallyConnectsStaysChargedNet() throws Exception {
        assertFalse(FrameworkReach.provenPure(KT, "getProducerFactory", "()Lorg/springframework/kafka/core/ProducerFactory;"),
                "the guard must keep KafkaTemplate.getProducerFactory() off the P list");
        Path app = compileApp(
                Map.of("org/springframework/kafka/core/KafkaTemplate.java", String.join("\n",
                                "package org.springframework.kafka.core;",
                                "public class KafkaTemplate<K, V> {",
                                "  public ProducerFactory<K, V> getProducerFactory() { return null; }",
                                "}"),
                        "org/springframework/kafka/core/ProducerFactory.java", String.join("\n",
                                "package org.springframework.kafka.core;",
                                "public interface ProducerFactory<K, V> { Object createProducer(); }")),
                Map.of("app/K.java", String.join("\n",
                        "package app;",
                        "import org.springframework.kafka.core.KafkaTemplate;",
                        "public class K {",
                        "  public static Object producer(KafkaTemplate<String, String> t) { return t.getProducerFactory().createProducer(); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.K.producer").contains(Effect.NET), "deny Net must fire, got " + eff(r, "app.K.producer"));
        } finally { rm(app.getParent()); }
    }

    /** The guard's own measured case, unchanged: the Db is {@code .all()} on the interface {@code query} returns. */
    @Test
    void theFluentFactoryGuardStillHolds() {
        assertFalse(FrameworkReach.provenPure("org/springframework/data/mongodb/core/MongoTemplate", "query",
                "(Ljava/lang/Class;)Lorg/springframework/data/mongodb/core/ExecutableFindOperation$ExecutableFind;"));
    }

    // ── the over-charge: a getter whose returned type is hedged, but cannot perform the rule's effect ─────────────────

    @Test
    void aPureGetterReturningAHedgedTypeThatCannotSendIsNotNet_theLaterCallStaysDisclosed() throws Exception {
        assertTrue(FrameworkReach.provenPure(RT, "getUriTemplateHandler", "()Lorg/springframework/web/util/UriTemplateHandler;"),
                "getUriTemplateHandler is getfield; areturn, and no UriTemplateHandler implementer can send anything");
        Path app = compileApp(
                Map.of("org/springframework/web/client/RestTemplate.java", String.join("\n",
                                "package org.springframework.web.client;",
                                "public class RestTemplate {",
                                "  public org.springframework.web.util.UriTemplateHandler getUriTemplateHandler() { return null; }",
                                "  public <T> T getForObject(String url, Class<T> t, Object... v) { return null; }",
                                "}"),
                        "org/springframework/web/util/UriTemplateHandler.java", String.join("\n",
                                "package org.springframework.web.util;",
                                "public interface UriTemplateHandler { java.net.URI expand(String t, java.util.Map<String, ?> v); }")),
                Map.of("app/U.java", String.join("\n",
                        "package app;",
                        "import org.springframework.web.client.RestTemplate;",
                        "public class U {",
                        "  public static Object handler(RestTemplate rt) { return rt.getUriTemplateHandler(); }",
                        "  public static java.net.URI expand(RestTemplate rt, String t) { return rt.getUriTemplateHandler().expand(t, java.util.Map.of()); }",
                        "  public static String get(RestTemplate rt, String u) { return rt.getForObject(u, String.class); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertFalse(eff(r, "app.U.handler").contains(Effect.NET), "reading the handler sends nothing, got " + eff(r, "app.U.handler"));
            EffectSet x = eff(r, "app.U.expand");
            assertFalse(x.contains(Effect.NET), "expanding a URI template sends nothing (executed), got " + x);
            assertTrue(x.contains(Effect.UNKNOWN), "but the dispatch the table cannot follow is still disclosed, got " + x);
            assertTrue(eff(r, "app.U.get").contains(Effect.NET), "a request stays Net, got " + eff(r, "app.U.get"));
        } finally { rm(app.getParent()); }
    }
}
