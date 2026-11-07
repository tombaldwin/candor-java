package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1468 (the R1052 step-5a stand-in) — where a framework body's closure reaches a dispatch the generated
 * table cannot follow, {@code FrameworkReachGen} step 5a used to put back the OWNER-WIDE NAME RULE's charge of every
 * proven-pure (P) member that closure calls, as a stand-in for the hidden dispatch. That stand-in is a concrete effect
 * the body may never perform: EXECUTED (SecurityManager connect trace, spring-web 5.3.39 and 6.1.10), {@code new
 * RestTemplate()} opens no connection, and the table charged it {@code Net}.
 *
 * <p>Now the stand-in is kept only where an implementer of an unfollowable dispatch in that closure carries the same
 * effect; elsewhere the member is disclosed ({@code C} line: {@code Unknown[dispatch:<the member the table could not
 * follow>]}), never left with nothing.
 *
 * <p>The fixture that must STAY charged was written first, and passes on the table before and after the change:
 * {@code RabbitMessagingTemplate.receiveAndConvert(Class)} reaches the broker through the abstract {@code doReceive},
 * and the blanket on its own pure {@code resolveDestination()} was the only charge standing in for it. EXECUTED
 * (spring-rabbit 3.1.6 against a local listening socket): the call connects.
 */
class OpaqueClosureStandInR1468Test {

    static final String RMT = "org/springframework/amqp/rabbit/core/RabbitMessagingTemplate";
    static final String RT = "org/springframework/web/client/RestTemplate";

    @BeforeEach
    void fresh() { Candor.resetState(); }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        EffectSet e = r.get(fn);
        return e == null ? EffectSet.empty() : e;
    }

    // ── written FIRST: the genuine stand-in stays a concrete charge ──────────────────────────────────────────────────

    @Test
    void anOpaqueClosureThatReallyReachesTheEffectStaysCharged() throws Exception {
        assertTrue(FrameworkReach.charges(RMT, "receiveAndConvert", "(Ljava/lang/Class;)Ljava/lang/Object;").contains(Effect.NET),
                "receiveAndConvert(Class) reaches the broker through the abstract doReceive (executed: it connects)");
        Path app = compileApp(
                Map.of("org/springframework/amqp/rabbit/core/RabbitMessagingTemplate.java", String.join("\n",
                        "package org.springframework.amqp.rabbit.core;",
                        "public class RabbitMessagingTemplate {",
                        "  public <T> T receiveAndConvert(Class<T> c) { return null; }",
                        "}")),
                Map.of("app/Q.java", String.join("\n",
                        "package app;",
                        "import org.springframework.amqp.rabbit.core.RabbitMessagingTemplate;",
                        "public class Q {",
                        "  public static String take(RabbitMessagingTemplate t) { return t.receiveAndConvert(String.class); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.Q.take").contains(Effect.NET), "deny Net must fire, got " + eff(r, "app.Q.take"));
        } finally { rm(app.getParent()); }
    }

    /** `Llm` is a label no body performs, so no implementer can carry it: a model request whose own body is charged
     *  `Net` keeps the stand-in `Llm` (the independent checker caught six of these being dropped in a first cut). */
    @Test
    void aModelRequestKeepsItsLlmLabelBesideItsNet() {
        java.util.List<Effect> c = FrameworkReach.charges("org/springframework/ai/openai/api/OpenAiApi", "embeddings",
                "(Lorg/springframework/ai/openai/api/OpenAiApi$EmbeddingRequest;)Lorg/springframework/http/ResponseEntity;");
        assertTrue(c.contains(Effect.LLM) && c.contains(Effect.NET), "got " + c);
    }

    // ── the over-charge: a stand-in nothing in the closure can perform becomes a disclosure ──────────────────────────

    @Test
    void anOpaqueClosureWhoseStandInNoImplementerPerformsDisclosesInsteadOfCharging() throws Exception {
        assertFalse(FrameworkReach.charges(RT, "<init>", "()V").contains(Effect.NET),
                "new RestTemplate() opens no connection (executed, two major versions); got " + FrameworkReach.charges(RT, "<init>", "()V"));
        assertEquals("C", FrameworkReach.hedgeKind(RT, "<init>", "()V"),
                "and the closure the table could not follow is disclosed, not left silent");
        Path app = compileApp(
                Map.of("org/springframework/web/client/RestTemplate.java", String.join("\n",
                        "package org.springframework.web.client;",
                        "public class RestTemplate {",
                        "  public RestTemplate() {}",
                        "}")),
                Map.of("app/M.java", String.join("\n",
                        "package app;",
                        "import org.springframework.web.client.RestTemplate;",
                        "public class M {",
                        "  public static RestTemplate mk() { return new RestTemplate(); }",
                        "  public static int control(String s) { return s.length(); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            EffectSet mk = eff(r, "app.M.mk");
            assertFalse(mk.contains(Effect.NET), "constructing sends nothing, got " + mk);
            assertTrue(mk.contains(Effect.UNKNOWN), "but the unfollowed closure is disclosed, got " + mk);
            String why = String.valueOf(AnalysisState.ctx().unknownWhy.get("app.M.mk"));
            // the converter set-up registers Jackson modules: Module.setupModule is abstract, and its surveyed implementers
            // are Unknown or charged with other effects — the dispatch the table could not follow, named; not the constructor
            assertTrue(why.contains("dispatch:com.fasterxml.jackson.databind.Module.setupModule")
                    && !why.contains("dispatch:org.springframework.web.client.RestTemplate.<init>"), "reason: " + why);
            assertEquals("com.fasterxml.jackson.databind.Module.setupModule", FrameworkReach.closureTarget(RT, "<init>", "()V"));
            assertTrue(eff(r, "app.M.control").isEmpty(), "control");
        } finally { rm(app.getParent()); }
    }
}
