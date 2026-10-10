package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1078 — A COVARIANT BRIDGE IS FOLDED INTO ITS REAL MEMBER'S ROW, AND ITS ONE CALL — {@code this.<real>()}
 * — WAS CHARGED TO THAT MEMBER.
 *
 * <p>Two halves, each EXECUTED before it was written down (the program ran; the asserted purity is what it did):
 * <ul>
 *   <li>FIXED ({@link Candor#bridgeSelfForward}) — the bridge's CHA fan-out: {@code Base.getOptions()} inherited
 *       {@code Sub}'s {@code Fs}, and so did {@code Sub2.getOptions()}, which is {@code super.getOptions()} and runs
 *       Base's body alone.
 *   <li>DECLINED, and pinned so it moves only on purpose — a NAME rule on the bridge's own owner: a class in
 *       {@code org.springframework.ai.*} is under the model-SDK blanket, so a getter with a bridge reads
 *       {@code direct [Llm, Net]} and the same getter without one reads pure. Removing that charge is R1052's refused
 *       "any call inside the owner" narrowing; measured here it took {@code Net} off
 *       {@code RoutingKafkaTemplate.onApplicationEvent}, whose body closes Kafka producers. Where the body is proven
 *       pure the P lines already drop it.
 * </ul>
 * And the one thing the bridge really does add, kept: a subclass compiled WITHOUT the bridge descriptor (here,
 * against the version of {@code Base} before it implemented the interface) is reached through the interface
 * descriptor only via Base's bridge. EXECUTED: {@code viaIface(new LateSub())} writes the file. A build that drops
 * the whole fan-out reads {@code viaIface} PURE — that seeded arm was run against this fixture.
 */
class BridgeFoldR1078Test {

    private static final String FS_WRITE =
            "try { java.nio.file.Files.writeString(java.nio.file.Path.of(System.getProperty(\"java.io.tmpdir\"), \"r1078.txt\"), \"x\"); } catch (Exception e) { }";

    private static Map<String, EffectSet> scan(Path cls) throws Exception {
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            return Candor.runScan(cls);
        } finally {
            Candor.config = saved;
        }
    }

    private static TreeSet<String> eff(Map<String, EffectSet> r, String fn) {
        TreeSet<String> out = new TreeSet<>();
        EffectSet e = r.get(fn);
        if (e != null) for (var x : e.effects()) out.add(x.name());
        return out;
    }

    private static TreeSet<String> set(String... xs) { return new TreeSet<>(List.of(xs)); }

    @Test
    void aBridgesSelfCallKeepsTheOwnersNameRule() throws Exception {
        Map<String, String> src = new LinkedHashMap<>();
        src.put("org/springframework/ai/rfx/B.java", "package org.springframework.ai.rfx;\npublic class B {\n"
                + "  public interface Opts {}\n  public static class ChatOpts implements Opts {}\n"
                + "  public interface Req { Opts getOptions(); }\n"
                + "  public static class WithBridge implements Req { final ChatOpts o = new ChatOpts();\n"
                + "    public ChatOpts getOptions() { return o; } }\n"
                + "  public static class NoBridge { final ChatOpts o = new ChatOpts();\n"
                + "    public ChatOpts getOptions() { return o; } }\n"
                + "  public static class WithBridgeFs implements Req {\n"
                + "    public ChatOpts getOptions() { " + FS_WRITE + " return new ChatOpts(); } }\n}\n");
        Path cls = compile(src);
        try {
            Map<String, EffectSet> r = scan(cls);
            // the control: the same getter with no supertype has no bridge and reads pure on every build
            assertEquals(set(), eff(r, "org.springframework.ai.rfx.B$NoBridge.getOptions"));
            assertEquals(set("LLM", "NET"), eff(r, "org.springframework.ai.rfx.B$WithBridge.getOptions"),
                    "DECLINED half: a name rule on a member not proven pure stays that member's answer (R1052)");
            assertTrue(eff(r, "org.springframework.ai.rfx.B$WithBridgeFs.getOptions").contains("FS"),
                    "the real member's OWN body still charges its row");
        } finally {
            rm(cls.getParent());
        }
    }

    private static final String COV = "package rfu;\npublic class Cov {\n"
            + "  public interface Opts {}\n  public static class ChatOpts implements Opts {}\n"
            + "  public interface Req { Opts getOptions(); }\n"
            + "  public static class Base implements Req { public ChatOpts getOptions() { return new ChatOpts(); } }\n"
            + "  public static class Sub extends Base { @Override public ChatOpts getOptions() { " + FS_WRITE
            + " return new ChatOpts(); } }\n"
            + "  public static class Sub2 extends Base { @Override public ChatOpts getOptions() { return super.getOptions(); } }\n"
            + "  public static boolean viaIface(Req r) { return r.getOptions() != null; }\n"
            + "  public static boolean viaBase(Base b) { return b.getOptions() != null; }\n}\n";

    @Test
    void aBridgesFanOutDoesNotChargeTheRealMemberWithItsSubclassesOverrides() throws Exception {
        Path cls = compile(Map.of("rfu/Cov.java", COV));
        try {
            Map<String, EffectSet> r = scan(cls);
            assertEquals(set(), eff(r, "rfu.Cov$Base.getOptions"), "Base's body allocates and returns");
            assertEquals(set(), eff(r, "rfu.Cov$Sub2.getOptions"), "super.getOptions() runs Base's body alone");
            // the polymorphic call sites still reach Sub — the caller fans out itself
            assertEquals(set("FS"), eff(r, "rfu.Cov.viaIface"));
            assertEquals(set("FS"), eff(r, "rfu.Cov.viaBase"));
            assertEquals(set("FS"), eff(r, "rfu.Cov$Sub.getOptions"));
        } finally {
            rm(cls.getParent());
        }
    }

    @Test
    void aSubclassWithoutTheBridgeDescriptorIsStillReachedThroughTheBridge() throws Exception {
        // v1: Base does not implement Req, so LateSub (compiled against it) gets no getOptions()Opts bridge.
        Map<String, String> v1 = new LinkedHashMap<>();
        v1.put("rfv/Opts.java", "package rfv;\npublic interface Opts {}\n");
        v1.put("rfv/ChatOpts.java", "package rfv;\npublic class ChatOpts implements Opts {}\n");
        v1.put("rfv/Base.java", "package rfv;\npublic class Base { public ChatOpts getOptions() { return new ChatOpts(); } }\n");
        v1.put("rfv/LateSub.java", "package rfv;\npublic class LateSub extends Base {\n"
                + "  @Override public ChatOpts getOptions() { " + FS_WRITE + " return new ChatOpts(); } }\n");
        Path c1 = compile(v1);
        // v2: Base implements Req (gaining the bridge); LateSub's class file is the v1 one.
        Map<String, String> v2 = new LinkedHashMap<>();
        v2.put("rfv/Opts.java", "package rfv;\npublic interface Opts {}\n");
        v2.put("rfv/ChatOpts.java", "package rfv;\npublic class ChatOpts implements Opts {}\n");
        v2.put("rfv/Req.java", "package rfv;\npublic interface Req { Opts getOptions(); }\n");
        v2.put("rfv/Base.java", "package rfv;\npublic class Base implements Req { public ChatOpts getOptions() { return new ChatOpts(); } }\n");
        v2.put("rfv/Use.java", "package rfv;\npublic class Use {\n"
                + "  public static boolean viaIface(Req r) { return r.getOptions() != null; }\n}\n");
        Path c2 = compile(v2, "-cp", c1.toString());
        try {
            Files.copy(c1.resolve("rfv/LateSub.class"), c2.resolve("rfv/LateSub.class"));
            Map<String, EffectSet> r = scan(c2);
            assertTrue(eff(r, "rfv.LateSub.getOptions").contains("FS"));
            assertEquals(set("FS"), eff(r, "rfv.Use.viaIface"),
                    "Req.getOptions()Opts on a LateSub runs Base's bridge, which dispatches to LateSub's override");
        } finally {
            rm(c1.getParent());
            rm(c2.getParent());
        }
    }
}
