package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1052 — three LEAF rules over-charged a direct call, and the generated framework table carried each into
 * every member that reaches it. Every test here pins BOTH directions: the over-charge is gone, and the genuine charge
 * of the same shape — the second fixture, written first — survives. Each "must stay" arm was EXECUTED against a
 * logging HTTP server when the fix was built (the lane's fixture set; the server saw the request).
 */
class LeafOverChargeR1052Test {

    @BeforeEach
    void fresh() { Candor.resetState(); }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) { return r.getOrDefault(fn, EffectSet.empty()); }

    // ── (a) URL.openStream / openConnection: Net whatever the scheme ────────────────────────────────────────────────

    @Test
    void classpathResourceOfTheProgramsOwnLoadersIsFsNotNet_everyOtherUrlKeepsNet() throws Exception {
        Path app = compile(Map.of("app/U.java", String.join("\n",
                "package app;",
                "import java.io.InputStream;",
                "import java.net.*;",
                "import java.util.Enumeration;",
                "public class U {",
                // the program's own class path, five spellings — each a getResourceAsStream by another name
                "  public static int lit() throws Exception { return U.class.getResource(\"/a\").openStream().read(); }",
                "  public int self() throws Exception { return getClass().getResource(\"/a\").openStream().read(); }",
                "  public static long ldr() throws Exception { URLConnection c = U.class.getClassLoader().getResource(\"a\").openConnection();",
                "    c.setUseCaches(false); return c.getLastModified() + c.getInputStream().read(); }",
                "  public static int sys() throws Exception { return ClassLoader.getSystemResource(\"a\").openStream().read(); }",
                "  public static int enm() throws Exception { int n = 0; Enumeration<URL> e = ClassLoader.getSystemClassLoader().getResources(\"a\");",
                "    while (e.hasMoreElements()) n += e.nextElement().openStream().read(); return n; }",
                // …and every URL whose origin this pass cannot pin keeps Net
                "  public static int par(URL u) throws Exception { return u.openStream().read(); }",
                "  public static int mrg(boolean c, String s) throws Exception { URL u = c ? U.class.getResource(\"/a\") : new URL(s); return u.openStream().read(); }",
                "  public static int ctx(String spec) throws Exception { return new URL(U.class.getResource(\"/a\"), spec).openStream().read(); }",
                "  public static int rem() throws Exception { return new URLClassLoader(new URL[]{ new URL(\"http://h.example/cp/\") }, null).getResource(\"a\").openStream().read(); }",
                "  public static int tccl() throws Exception { return Thread.currentThread().getContextClassLoader().getResource(\"a\").openStream().read(); }",
                "  public static int ldp(ClassLoader l) throws Exception { return l.getResource(\"a\").openStream().read(); }",
                "  public static int prx() throws Exception { return U.class.getResource(\"/a\").openConnection(Proxy.NO_PROXY).getInputStream().read(); }",
                "  static URL held = U.class.getResource(\"/a\");",
                "  public static int fld() throws Exception { return held.openStream().read(); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : List.of("lit", "self", "ldr", "sys", "enm")) {
                EffectSet e = eff(r, "app.U." + m);
                assertFalse(e.contains(Effect.NET), m + ": a class-path resource read is not Net, got " + e);
                assertTrue(e.contains(Effect.FS), m + ": it is the getResourceAsStream read — Fs, got " + e);
            }
            // EXECUTED for par/mrg/ctx/rem/tccl/ldp/fld: each sent its request to a local HTTP server.
            for (String m : List.of("par", "mrg", "ctx", "rem", "tccl", "ldp", "prx", "fld"))
                assertTrue(eff(r, "app.U." + m).contains(Effect.NET), m + " must keep Net, got " + eff(r, "app.U." + m));
        } finally { rm(app.getParent()); }
    }

    // ── (b) an owner-blanket rule on members that do nothing ────────────────────────────────────────────────────────

    @Test
    void restTemplateConstructionAndAccessorsAreNotNet_itsRequestsAre() throws Exception {
        Path app = compileApp(
                Map.of("org/springframework/web/client/RestTemplate.java", String.join("\n",
                        "package org.springframework.web.client;",
                        "public class RestTemplate {",
                        "  public RestTemplate() {}",
                        "  public RestTemplate(java.util.List<?> l) {}",
                        "  public java.util.List<Object> getMessageConverters() { return null; }",
                        "  public <T> T getForObject(String url, Class<T> t, Object... v) { return null; }",
                        "}")),
                Map.of("app/R.java", String.join("\n",
                        "package app;",
                        "import org.springframework.web.client.RestTemplate;",
                        "public class R {",
                        "  public static RestTemplate mk() { return new RestTemplate(java.util.List.of()); }",
                        "  public static int conv(RestTemplate rt) { return rt.getMessageConverters().size(); }",
                        "  public static String get(RestTemplate rt, String u) { return rt.getForObject(u, String.class); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertFalse(eff(r, "app.R.mk").contains(Effect.NET), "constructing a RestTemplate sends nothing, got " + eff(r, "app.R.mk"));
            assertFalse(eff(r, "app.R.conv").contains(Effect.NET), "getMessageConverters is a field read (P line), got " + eff(r, "app.R.conv"));
            assertTrue(eff(r, "app.R.get").contains(Effect.NET), "a request stays Net, got " + eff(r, "app.R.get"));
        } finally { rm(app.getParent()); }
    }

    // ── (c) the model-SDK blanket on getters ────────────────────────────────────────────────────────────────────────

    @Test
    void springAiPromptGetterIsNotAModelCall_theModelCallIs() throws Exception {
        Path app = compileApp(
                Map.of("org/springframework/ai/chat/prompt/ChatOptions.java",
                        "package org.springframework.ai.chat.prompt; public interface ChatOptions {}",
                        "org/springframework/ai/chat/prompt/Prompt.java", String.join("\n",
                        "package org.springframework.ai.chat.prompt;",
                        "public class Prompt { ChatOptions o; public ChatOptions getOptions() { return o; } }"),
                        "org/springframework/ai/chat/model/ChatModel.java", String.join("\n",
                        "package org.springframework.ai.chat.model;",
                        "public interface ChatModel { Object call(org.springframework.ai.chat.prompt.Prompt p); }")),
                Map.of("app/A.java", String.join("\n",
                        "package app;",
                        "import org.springframework.ai.chat.prompt.Prompt;",
                        "public class A {",
                        "  public static Object opts(Prompt p) { return p.getOptions(); }",
                        "  public static Object ask(org.springframework.ai.chat.model.ChatModel m, Prompt p) { return m.call(p); }",
                        "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            EffectSet o = eff(r, "app.A.opts");
            assertFalse(o.contains(Effect.LLM) || o.contains(Effect.NET), "Prompt.getOptions() is `getfield; areturn`, got " + o);
            EffectSet a = eff(r, "app.A.ask");
            assertTrue(a.contains(Effect.LLM) && a.contains(Effect.NET), "a model call keeps Llm+Net, got " + a);
        } finally { rm(app.getParent()); }
    }

    // ── the generated P list: calibrated in both directions against the surveyed bytecode ───────────────────────────

    @Test
    void provenPureListHoldsTheMeasuredAccessorsAndNoKnownDispatch() {
        for (String[] k : new String[][] {
                { "org/springframework/ai/chat/prompt/Prompt", "getOptions", "()Lorg/springframework/ai/chat/prompt/ChatOptions;" },
                { "org/springframework/web/client/RestTemplate", "validateConverters", "(Ljava/util/List;)V" },
                { "org/springframework/web/client/RestTemplate", "getMessageConverters", "()Ljava/util/List;" } })
            assertTrue(FrameworkReach.provenPure(k[0], k[1], k[2]), "expected a P line for " + String.join(".", k));
        // Every one of these performs (or hands back the handle that performs) the I/O its rule names. A P line on any
        // of them would be a purity claim over real I/O — the classifier proving it CAN refuse.
        for (String[] k : new String[][] {
                { "org/springframework/web/client/RestTemplate", "getForObject", "(Ljava/lang/String;Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;" },
                { "org/springframework/kafka/core/KafkaTemplate", "receive", "(Ljava/lang/String;IJLjava/time/Duration;)Lorg/apache/kafka/clients/consumer/ConsumerRecord;" },
                { "org/springframework/data/mongodb/repository/support/SimpleMongoRepository", "getReadPreference", "()Ljava/util/Optional;" },
                // pure itself, but the Db is `.all()` on the interface it returns — the fluent-factory guard
                { "org/springframework/data/mongodb/core/MongoTemplate", "query", "(Ljava/lang/Class;)Lorg/springframework/data/mongodb/core/ExecutableFindOperation$ExecutableFind;" },
                { "org/springframework/ai/openai/OpenAiChatModel", "call", "(Lorg/springframework/ai/chat/prompt/Prompt;)Lorg/springframework/ai/chat/model/ChatResponse;" } })
            assertFalse(FrameworkReach.provenPure(k[0], k[1], k[2]), "a P line on a dispatching member: " + String.join(".", k));
    }
}
