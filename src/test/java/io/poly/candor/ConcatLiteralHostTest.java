package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * LITERAL-HEAD HOST EXTRACTION (SPEC §1) — a URL built by a runtime string CONCATENATION with a literal
 * head, {@code new URL("https://api.openai.com/v1/" + path)}, has its authority fully present in the
 * literal prefix, so the host is statically known and the {@code Llm}/{@code Net} host refinement fires.
 * Two javac concat shapes are handled: {@code invokedynamic makeConcatWithConstants} (JDK 9+ default) and
 * the classic {@code StringBuilder.append("lit").append(var)…toString()} chain. SOUNDNESS-CRITICAL: a host
 * is extracted ONLY when the literal prefix carries a COMPLETE authority (a `/` after the `://`); a split
 * authority, a whole-host-dynamic operand, an unterminated host, or a dynamic `:port` stay bare {@code Net}
 * (safe under-report, never a guess). A benign captured host (e.g. a CDN) does NOT gain {@code Llm}.
 */
class ConcatLiteralHostTest {

    @BeforeEach
    void fresh() {
        Candor.resetState();
    }

    // ── string-rule unit tests: pin the exact boundary at the recovered-prefix level ──────────────────

    @Test
    void concatPrefixHost_extractsOnlyWhenAuthorityIsCompleteInThePrefix() {
        // POSITIVE: authority terminated by a `/` within the literal prefix.
        assertEquals("api.openai.com", Literals.concatPrefixHost("https://api.openai.com/v1/"));
        assertEquals("api.openai.com", Literals.concatPrefixHost("https://api.openai.com/"));
        // NEGATIVE: no `/` after `://` in the prefix — a dynamic operand could still be inside the authority.
        assertNull(Literals.concatPrefixHost("https://api."), "split authority — no `/` after `://`");
        assertNull(Literals.concatPrefixHost("https://"), "whole host dynamic — nothing after `://`");
        assertNull(Literals.concatPrefixHost("https://api.openai"), "host not terminated before the dynamic operand");
        assertNull(Literals.concatPrefixHost("https://api.openai.com:"), "dynamic `:port` before the `/`");
        assertNull(Literals.concatPrefixHost("no-scheme/here"), "no scheme at all");
        assertNull(Literals.concatPrefixHost(null), "null prefix");
    }

    @Test
    void concatLiteralPrefix_cutsAtTheFirstPlaceholder() {
        //  = TAG_ARG (a dynamic stack operand);  = TAG_CONST.
        assertEquals("https://api.openai.com/v1/", Literals.concatLiteralPrefix("https://api.openai.com/v1/"));
        assertEquals("https://api.", Literals.concatLiteralPrefix("https://api..com/v1/y"));
        assertEquals("https://api.openai.com/v1/", Literals.concatLiteralPrefix("https://api.openai.com/v1/x"));
        assertNull(Literals.concatLiteralPrefix("leads-with-dynamic"), "a leading placeholder has no literal head");
    }

    // ── end-to-end: scan the bytecode of every boundary case (default makeConcatWithConstants shape) ──

    @Test
    void concatUrlBoundary_indyShape() throws Exception {
        Path cls = compile(Map.of(
            "app/Concat.java", String.join("\n",
                "package app;",
                "import java.net.URL;",
                "public class Concat {",
                // POSITIVE → Llm + Net, host api.openai.com
                "  public void pfx(String p) throws Exception { new URL(\"https://api.openai.com/v1/\" + p).openConnection().getInputStream(); }",
                "  public void root(String p) throws Exception { new URL(\"https://api.openai.com/\" + p).openConnection().getInputStream(); }",
                // NEGATIVE → bare Net, no host
                "  public void split(String x) throws Exception { new URL(\"https://api.\" + x + \".com/v1/y\").openConnection().getInputStream(); }",
                "  public void wholeHost(String h) throws Exception { new URL(\"https://\" + h + \"/v1/y\").openConnection().getInputStream(); }",
                "  public void unterminated(String x) throws Exception { new URL(\"https://api.openai\" + x + \"/v1\").openConnection().getInputStream(); }",
                "  public void dynPort(int port) throws Exception { new URL(\"https://api.openai.com:\" + port + \"/v1\").openConnection().getInputStream(); }",
                // FABRICATION GUARD → Net, host cdn.example.com captured, NOT Llm
                "  public void cdn(String p) throws Exception { new URL(\"https://cdn.example.com/v1/\" + p).openConnection().getInputStream(); }",
                // NO REGRESSION: plain constant URL stays Llm + Net
                "  public void plain() throws Exception { new URL(\"https://api.openai.com/v1/models\").openConnection().getInputStream(); }",
                "}")));
        try {
            assertConcatBoundary(cls);
        } finally { rm(cls.getParent()); }
    }

    // ── the SAME battery on the classic StringBuilder chain (-XDstringConcat=inline) ──────────────────

    @Test
    void concatUrlBoundary_stringBuilderShape() throws Exception {
        Path cls = compile(Map.of(
            "app/Concat.java", String.join("\n",
                "package app;",
                "import java.net.URL;",
                "public class Concat {",
                "  public void pfx(String p) throws Exception { new URL(\"https://api.openai.com/v1/\" + p).openConnection().getInputStream(); }",
                "  public void root(String p) throws Exception { new URL(\"https://api.openai.com/\" + p).openConnection().getInputStream(); }",
                "  public void split(String x) throws Exception { new URL(\"https://api.\" + x + \".com/v1/y\").openConnection().getInputStream(); }",
                "  public void wholeHost(String h) throws Exception { new URL(\"https://\" + h + \"/v1/y\").openConnection().getInputStream(); }",
                "  public void unterminated(String x) throws Exception { new URL(\"https://api.openai\" + x + \"/v1\").openConnection().getInputStream(); }",
                "  public void dynPort(int port) throws Exception { new URL(\"https://api.openai.com:\" + port + \"/v1\").openConnection().getInputStream(); }",
                "  public void cdn(String p) throws Exception { new URL(\"https://cdn.example.com/v1/\" + p).openConnection().getInputStream(); }",
                "  public void plain() throws Exception { new URL(\"https://api.openai.com/v1/models\").openConnection().getInputStream(); }",
                "}")),
            "-XDstringConcat=inline");
        try {
            assertConcatBoundary(cls);
        } finally { rm(cls.getParent()); }
    }

    private void assertConcatBoundary(Path cls) throws Exception {
        Map<String, EffectSet> r = Candor.runScan(cls);

        // POSITIVE: Llm + Net, host api.openai.com
        for (String m : new String[] {"pfx", "root"}) {
            EffectSet e = eff(r, "app.Concat." + m);
            assertTrue(e.contains(Effect.NET), m + " must keep Net, got " + e);
            assertTrue(e.contains(Effect.LLM), m + " must carry Llm (literal-head host is api.openai.com), got " + e);
            assertTrue(hosts("app.Concat." + m).contains("api.openai.com"),
                m + " must capture host api.openai.com, got " + hosts("app.Concat." + m));
        }

        // NEGATIVE: bare Net, NO host, NO Llm
        for (String m : new String[] {"split", "wholeHost", "unterminated", "dynPort"}) {
            EffectSet e = eff(r, "app.Concat." + m);
            assertTrue(e.contains(Effect.NET), m + " must be Net, got " + e);
            assertFalse(e.contains(Effect.LLM), m + " must NOT be Llm (host not statically complete), got " + e);
            assertTrue(hosts("app.Concat." + m).isEmpty(),
                m + " must capture NO host (safe under-report), got " + hosts("app.Concat." + m));
        }

        // FABRICATION GUARD: host captured, but NOT Llm.
        EffectSet cdn = eff(r, "app.Concat.cdn");
        assertTrue(cdn.contains(Effect.NET), "cdn must be Net, got " + cdn);
        assertFalse(cdn.contains(Effect.LLM), "a non-model host (cdn.example.com) must NOT be Llm, got " + cdn);
        assertTrue(hosts("app.Concat.cdn").contains("cdn.example.com"),
            "cdn host must be captured (the concat prefix IS a complete authority), got " + hosts("app.Concat.cdn"));

        // NO REGRESSION: plain constant URL stays Llm + Net.
        EffectSet plain = eff(r, "app.Concat.plain");
        assertTrue(plain.contains(Effect.NET) && plain.contains(Effect.LLM),
            "a plain constant model URL must stay Llm + Net, got " + plain);
        assertTrue(hosts("app.Concat.plain").contains("api.openai.com"),
            "a plain constant URL host must stay captured, got " + hosts("app.Concat.plain"));
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    private static TreeSet<String> hosts(String fn) {
        return AnalysisState.ctx().hostsDirect.getOrDefault(fn, new TreeSet<>());
    }
}
