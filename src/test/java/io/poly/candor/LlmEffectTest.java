package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SPEC §1 ⟨0.13⟩ {@code Llm} — a model-provider call refines {@code Net} the way {@code Db} does. Two
 * classification sources: (a) a HOST-LITERAL refinement (a statically-known request to a known model host
 * carries {@code Llm} + {@code Net}), and (b) a MODEL-SDK surface (a call into a curated provider client).
 * An UNKNOWN host stays bare {@code Net}. The policy gate must name {@code Llm} (deny + the AS-EFF-008
 * allowlist, where a masked model host fails closed).
 */
class LlmEffectTest {

    @BeforeEach
    void fresh() {
        Candor.resetState();
    }

    // ── (a) host-literal refinement ──────────────────────────────────────────────────────────────────

    @Test
    void knownModelHostCarriesBothNetAndLlm_unknownHostIsNetOnly() throws Exception {
        Path app = compile(Map.of(
            "app/Ai.java", String.join("\n",
                "package app;",
                "import java.net.URL;",
                "import java.net.Socket;",
                "public class Ai {",
                // a URL-terminal to a known model host → Net + Llm
                "  public void anthropic() throws Exception { new URL(\"https://api.anthropic.com/v1/messages\").openStream(); }",
                // a bare Socket(host,port) to a known model host → Net + Llm
                "  public void openai() throws Exception { new Socket(\"api.openai.com\", 443); }",
                // a local Ollama endpoint (port 11434) → Net + Llm
                "  public void ollama() throws Exception { new Socket(\"localhost\", 11434); }",
                // an UNKNOWN host → Net only, never Llm (never guessed)
                "  public void other() throws Exception { new URL(\"https://example.com/x\").openStream(); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : List.of("anthropic", "openai", "ollama")) {
                EffectSet e = eff(r, "app.Ai." + m);
                assertTrue(e.contains(Effect.NET), m + " must keep Net (a model call IS network I/O), got " + e);
                assertTrue(e.contains(Effect.LLM), m + " must carry Llm, got " + e);
            }
            EffectSet other = eff(r, "app.Ai.other");
            assertTrue(other.contains(Effect.NET), "an unknown host is Net, got " + other);
            assertFalse(other.contains(Effect.LLM), "an unknown host must NOT be Llm (never guessed), got " + other);
        } finally { rm(app.getParent()); }
    }

    // ── host-predicate PRECISION: no substring / any-port over-match fabricates Llm ───────────────────

    @Test
    void bedrockRuntimeIsLlm_butControlPlaneAndS3SubstringAreNot() {
        // A model-inference runtime host → Llm.
        assertTrue(Literals.isModelHost("bedrock-runtime.us-east-1.amazonaws.com"),
            "bedrock-runtime is the model-inference endpoint");
        assertTrue(Literals.isModelHost("bedrock-agent-runtime.us-west-2.amazonaws.com"),
            "bedrock-agent-runtime is the agent model-inference endpoint");
        assertTrue(Literals.isModelHost("bedrock-runtime.eu-central-1.amazonaws.com:443"),
            "the runtime host with an explicit :port still refines (port stripped)");
        // FINDING 8: a non-model amazonaws host that merely CONTAINS the "bedrock" substring is NOT Llm.
        assertFalse(Literals.isModelHost("bedrock-backups.s3.amazonaws.com"),
            "an S3 bucket whose name contains 'bedrock' is NOT the model runtime");
        // The control plane manages models but runs none → NOT model inference.
        assertFalse(Literals.isModelHost("bedrock.us-east-1.amazonaws.com"),
            "the Bedrock control plane is not model inference");
    }

    @Test
    void ollamaPortIsLlmOnlyOnALocalHost() {
        // Local Ollama endpoint → Llm.
        assertTrue(Literals.isModelHost("localhost:11434"), "localhost:11434 is the local Ollama endpoint");
        assertTrue(Literals.isModelHost("127.0.0.1:11434"), "127.0.0.1:11434 is the local Ollama endpoint");
        assertTrue(Literals.isModelHost("[::1]:11434"), "[::1]:11434 is the local Ollama endpoint");
        // FINDING 11: an arbitrary REMOTE host on :11434 is some other service, NOT an Ollama model call.
        assertFalse(Literals.isModelHost("some-service.example.com:11434"),
            "a remote host on port 11434 is not an Ollama model call");
        assertFalse(Literals.isModelHost("10.0.0.5:11434"),
            "an arbitrary internal host on port 11434 is not an Ollama model call");
    }

    @Test
    void plainKnownProviderHostStillLlm() {
        assertTrue(Literals.isModelHost("api.anthropic.com"), "a plain known model host still refines to Llm");
        assertTrue(Literals.isModelHost("api.anthropic.com:443"),
            "a known model host with an explicit :port still refines (port stripped)");
        assertFalse(Literals.isModelHost("example.com"), "an unknown host is never Llm");
    }

    // ── (b) model-SDK surface (stub client on the classpath, not scanned) ─────────────────────────────

    @Test
    void modelSdkClientClassifiesLlmAndNet() throws Exception {
        Path app = compileApp(
            Map.of(
                // a stub OpenAI-java client (com.openai.*) — a curated model-SDK package. It lives on the
                // classpath (NOT scanned), so classify sees the SDK owner: the model-SDK rule fires.
                "com/openai/client/OpenAIClient.java", String.join("\n",
                    "package com.openai.client;",
                    "public class OpenAIClient { public String complete(String prompt){ return prompt; } }")),
            Map.of(
                "app/Use.java", String.join("\n",
                    "package app;",
                    "import com.openai.client.OpenAIClient;",
                    "public class Use {",
                    "  public static String ask(OpenAIClient c, String p){ return c.complete(p); }",
                    "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            EffectSet e = eff(r, "app.Use.ask");
            assertTrue(e.contains(Effect.LLM), "a call into a curated model-SDK package must be Llm, got " + e);
            assertTrue(e.contains(Effect.NET), "a model-SDK dispatch is also Net, got " + e);
        } finally { rm(app.getParent()); }
    }

    // ── deny Llm gates a model-host reach; the AS-EFF line names Llm (CLI subprocess for the exit code) ─

    @Test
    void denyLlmGatesAModelHostReach_andNamesLlm() throws Exception {
        Path classes = compile(Map.of(
            "ai/Client.java", String.join("\n",
                "package ai;",
                "import java.net.URL;",
                "public class Client {",
                "  public void chat() throws Exception { new URL(\"https://api.openai.com/v1/chat\").openStream(); }",
                "}")));
        try {
            Path pol = Files.createTempFile("pol", ".policy");
            Files.writeString(pol, "deny Llm ai\n");
            Run r = runCli(classes.toString(), "--policy", pol.toString());
            assertEquals(1, r.exit(), "deny Llm on a model-host reach must fail the gate (exit 1)\nSTDERR:\n" + r.stderr());
            // the AS-EFF-006 diagnostic goes to stdout (diagOut); it must name Llm.
            String all = r.stdout() + r.stderr();
            assertTrue(all.contains("AS-EFF-006") && all.contains("Llm"),
                "the AS-EFF-006 diagnostic must name Llm\nSTDOUT:\n" + r.stdout() + "\nSTDERR:\n" + r.stderr());
        } finally { rm(classes.getParent()); }
    }

    // ── AS-EFF-008: a MASKED/opaque model host fails closed under `allow Llm` (gate-evasion defense) ────

    @Test
    void allowLlmFailsClosedOnAMaskedModelHost() throws Exception {
        // The method reaches a runtime-computed host (structurally invisible) → its Net surface is
        // incomplete. Because Llm rides the Net host literal, `allow Llm` must fail closed too (a benign
        // visible model host must not MASK the invisible one).
        Path pol = Files.createTempFile("pol", ".policy");
        Files.writeString(pol, "allow Llm in ai api.openai.com\n");
        // performs Llm, visible host is the allowed one, BUT the Net surface is marked incomplete (a masked host)
        AnalysisState.ctx().hostsDirect.put("ai.Client.chat", new TreeSet<>(List.of("api.openai.com")));
        AnalysisState.ctx().surfaceIncomplete.put("ai.Client.chat", new TreeSet<>(List.of("Net")));
        Map<String, EffectSet> inferred = Map.of("ai.Client.chat", EffectSet.of(Effect.NET, Effect.LLM));
        assertTrue(Policy.checkPolicy(inferred, pol.toString()) >= 1,
            "an incomplete (masked) host surface must fail-close `allow Llm` — a benign model host cannot certify a hidden reach");
    }

    @Test
    void allowLlmPassesAReachedAllowedModelHost() throws Exception {
        Path pol = Files.createTempFile("pol", ".policy");
        Files.writeString(pol, "allow Llm in ai api.openai.com\n");
        AnalysisState.ctx().hostsDirect.put("ai.Client.chat", new TreeSet<>(List.of("api.openai.com")));
        Map<String, EffectSet> inferred = Map.of("ai.Client.chat", EffectSet.of(Effect.NET, Effect.LLM));
        assertEquals(0, Policy.checkPolicy(inferred, pol.toString()),
            "reaching only the allow-listed model host must pass");
    }

    @Test
    void allowLlmFlagsAModelHostOutsideTheList() throws Exception {
        Path pol = Files.createTempFile("pol", ".policy");
        Files.writeString(pol, "allow Llm in ai api.openai.com\n");
        AnalysisState.ctx().hostsDirect.put("ai.Client.chat", new TreeSet<>(List.of("api.anthropic.com")));
        Map<String, EffectSet> inferred = Map.of("ai.Client.chat", EffectSet.of(Effect.NET, Effect.LLM));
        assertTrue(Policy.checkPolicy(inferred, pol.toString()) >= 1,
            "reaching a model host outside the Llm allowlist must be a violation");
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    private record Run(int exit, String stdout, String stderr) {}

    private static Run runCli(String... args) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of(javaBin, "-cp", cp, "io.poly.candor.Candor"));
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).start();
        String out = drain(p.getInputStream()), err = drain(p.getErrorStream());
        int code = p.waitFor();
        return new Run(code, out, err);
    }

    private static String drain(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toString();
    }
}
