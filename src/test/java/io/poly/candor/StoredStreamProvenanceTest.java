package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R147 — A READ THROUGH A STREAM HANDLE STORED IN A FIELD.
 *
 * <p><b>THE DEFECT.</b> {@code this.in = sock.getInputStream()} charges Net in the constructor;
 * {@code in.read()} in another method charges NOTHING, because the receiver's static type is the abstract
 * {@code java.io.InputStream} and the classifier has no rule for it. The method that actually moves the
 * bytes is reported pure. Pre-existing and PUBLISHED: absent at {@code 2dd1600}, at {@code d8e953c} and at
 * {@code 81f4ceb}. Until {@code 81f4ceb} the CALLER kept a Net that came ENTIRELY from the fabricated
 * {@code get/setSoTimeout} pair — a correct verdict produced by an incorrect mechanism — so removing that
 * over-charge UNMASKED this, and the 0.35.0 release panel measured the result as a RED-TO-GREEN FLIP on
 * upgrade: {@code deny Net SockRead.poll} exit 1 (published 0.34.0) → 0 (release candidate). A fabrication
 * that happens to mask a sin is two defects, not one, so the mask was correctly removed and this is the
 * other half.
 *
 * <p><b>WHAT THE FIX KEYS ON — the acquisition, not the socket.</b> {@code Interp#acquisitionEffects} asks
 * {@code Classifier.classify} what the producing call already charges, so {@code Socket} (Net),
 * {@code URLConnection} (Net), {@code Process} (Exec) and {@code new FileInputStream} (Fs) all fall out of
 * ONE rule and none of them can drift from the classifier's own answer at the acquisition site (§G, §F1 q3).
 * {@code theAcquisitionEffectIsWhateverTheClassifierSaysNotASocketList} is that claim, measured.
 *
 * <p><b>THE BOUNDARY, PINNED RATHER THAN ASSERTED.</b> Two shapes are deliberately NOT closed —
 * a field bound from a PARAM, and a field bound to a FILTER wrapping an acquisition. Both are the
 * pre-existing external-stream question ({@code Candor#externalStreamUtility} answers it with
 * {@code Unknown} for stream-consuming UTILITIES only, {@code Candor#entryAbstractStream} for an entry
 * point's own param), and widening it to every receiver read is a separate decision with its own flood
 * risk. {@code theTwoResidualsThisRowDoesNotClose} pins them AS RESIDUALS, so the next reader meets a
 * measured gap instead of an assumption of coverage — and so that closing one turns this test red rather
 * than passing silently.
 *
 * <p><b>Ground truth EXECUTED, in-process, over real loopback TCP</b>
 * ({@code #socketStreamStoredInAFieldChargesNetWhereItIsRead}): the same shape the fixture compiles is run
 * here against a real {@link ServerSocket}, and {@code poll()} really returns a byte written by the peer
 * while {@code tune()} moves none. An absence-shaped control over a program that cannot run is asserting
 * something about nothing (§E3); these two arms are the reason the absence rows below mean anything.
 */
class StoredStreamProvenanceTest {

    // ── the R147 shape itself ──────────────────────────────────────────────────────────────────────

    private static final String SOCK_READ = String.join("\n",
        "package com.x;",
        "import java.net.Socket;",
        "import java.io.InputStream;",
        "import java.io.OutputStream;",
        "import java.io.IOException;",
        "public class SockRead {",
        "  Socket s; InputStream in; OutputStream out;",
        "  public SockRead(Socket s) throws IOException {",
        "    this.s = s; this.in = s.getInputStream(); this.out = s.getOutputStream(); }",
        "  public int poll() throws IOException { s.setSoTimeout(100); return in.read(); }",
        "  public void push(byte[] b) throws IOException { out.write(b); }",
        "  public void tune() throws IOException { s.setSoTimeout(100); s.setReuseAddress(true); }",
        "}");

    /** RED without the fix: {@code poll} and {@code push} are ABSENT from the report, so {@code deny Net
     *  com.x.SockRead.poll} passes over a method that reads the wire. */
    @Test
    void socketStreamStoredInAFieldChargesNetWhereItIsRead() throws Exception {
        // GROUND TRUTH FIRST, executed over real loopback TCP: poll() moves a byte, tune() does not.
        try (ServerSocket srv = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            Thread peer = new Thread(() -> {
                try (Socket c = srv.accept()) { c.getOutputStream().write(65); c.getOutputStream().flush();
                    Thread.sleep(200); } catch (Exception ignored) { }
            });
            peer.setDaemon(true);
            peer.start();
            try (Socket c = new Socket(srv.getInetAddress(), srv.getLocalPort())) {
                InputStream held = c.getInputStream();          // the acquisition, stored
                c.setSoTimeout(2000);
                c.setReuseAddress(true);                        // the `tune` control: no bytes move
                assertEquals(65, held.read(),
                    "the executed ground truth: reading through the STORED handle really takes a byte off "
                    + "the wire — the effect the report must carry");
            }
        }

        Path cls = compile(Map.of("com/x/SockRead.java", SOCK_READ));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "com.x.SockRead.poll").contains(Effect.NET),
                "a read through an InputStream obtained from a Socket and stored in a field is network "
                + "I/O wherever it happens — got " + r.get("com.x.SockRead.poll"));
            assertTrue(eff(r, "com.x.SockRead.push").contains(Effect.NET),
                "and so is the WRITE side, which is the sibling the trigger did not name (§9) — got "
                + r.get("com.x.SockRead.push"));
            assertTrue(eff(r, "com.x.SockRead.<init>").contains(Effect.NET),
                "the acquisition itself must keep its Net — the fix adds a charge, it does not move one");
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROL FOR THE SAME FIXTURE, and the one that says what this fix is NOT.
     *  {@code tune} touches only the socket-option protocol, which {@code 81f4ceb} correctly stopped
     *  charging (executed there on an UNBOUND socket). It must stay uncharged — passing here in BOTH arms
     *  by construction, so this is a guard on the direction the fix did not intend rather than a
     *  discriminator for it. */
    @Test
    void theSocketOptionProtocolStaysUncharged() throws Exception {
        Path cls = compile(Map.of("com/x/SockRead.java", SOCK_READ));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "com.x.SockRead.tune").contains(Effect.NET),
                "setSoTimeout/setReuseAddress move no bytes (R130 B3, executed on an unbound socket) — "
                + "the stream-provenance charge must not smear back onto them: got "
                + r.get("com.x.SockRead.tune"));
        } finally { rm(cls.getParent()); }
    }

    // ── the acquisition is whatever the classifier already says, not a hand-kept socket list ───────

    /** RED without the fix on every positive row. The point is that ONE rule produces four different
     *  effects: Net from a socket, Net from a URL connection, Exec from a subprocess pipe, Fs from a file
     *  open — because each is the classifier's OWN answer at the acquisition site (§G). And {@code mem}
     *  is the row that proves the rule is not "charge every stored stream": a {@code ByteArrayInputStream}
     *  has no acquisition effect and must stay pure. */
    @Test
    void theAcquisitionEffectIsWhateverTheClassifierSaysNotASocketList() throws Exception {
        Path cls = compile(Map.of("com/x/Holders.java", String.join("\n",
            "package com.x;",
            "import java.io.*;",
            "import java.net.*;",
            "public class Holders {",
            "  public static class Url { InputStream in;",
            "    public Url(URLConnection c) throws IOException { this.in = c.getInputStream(); }",
            "    public int read() throws IOException { return in.read(); } }",
            "  public static class Proc { InputStream in;",
            "    public Proc(Process p) { this.in = p.getInputStream(); }",
            "    public int read() throws IOException { return in.read(); } }",
            "  public static class OnDisk { InputStream in;",
            "    public OnDisk(File f) throws IOException { this.in = new FileInputStream(f); }",
            "    public int read() throws IOException { return in.read(); } }",
            "  public static class Mem { InputStream in;",
            "    public Mem(byte[] b) { this.in = new ByteArrayInputStream(b); }",
            "    public int read() throws IOException { return in.read(); } }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "com.x.Holders$Url.read").contains(Effect.NET),
                "URLConnection.getInputStream is charged Net at the acquisition — got "
                + r.get("com.x.Holders$Url.read"));
            assertTrue(eff(r, "com.x.Holders$Proc.read").contains(Effect.EXEC),
                "reading a subprocess's pipe is Exec, not Net — the effect comes from the ACQUISITION, "
                + "got " + r.get("com.x.Holders$Proc.read"));
            EffectSet disk = eff(r, "com.x.Holders$OnDisk.read");
            assertTrue(disk.contains(Effect.FS), "a file stream read is Fs — got " + disk);
            assertFalse(disk.contains(Effect.NET),
                "…and specifically NOT Net: the charge is keyed on what opened the handle, so a file "
                + "handle can never pick up the socket answer. Got " + disk);
            assertFalse(eff(r, "com.x.Holders$Mem.read").contains(Effect.FS),
                "a ByteArrayInputStream has no acquisition effect at all — a rule that charged every "
                + "stored stream would fabricate here. Got " + r.get("com.x.Holders$Mem.read"));
            assertFalse(eff(r, "com.x.Holders$Mem.read").contains(Effect.NET),
                "…in either direction. Got " + r.get("com.x.Holders$Mem.read"));
        } finally { rm(cls.getParent()); }
    }

    /** A STATIC stream field, which the read side ({@code Interp.ProvInterpreter#newOperation}'s GETSTATIC
     *  arm) already carried a field identity for and which the neighbouring Phase-2 pass does not visit.
     *  Written as its own row because "instance fields only" is exactly the boundary-around-the-trigger
     *  this project keeps paying for (§9). */
    @Test
    void aStaticStreamFieldIsCoveredToo() throws Exception {
        Path cls = compile(Map.of("com/x/Stat.java", String.join("\n",
            "package com.x;",
            "import java.io.*;",
            "import java.net.Socket;",
            "public class Stat {",
            "  static InputStream IN;",
            "  public static void bind(Socket s) throws IOException { IN = s.getInputStream(); }",
            "  public static int read() throws IOException { return IN.read(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "com.x.Stat.read").contains(Effect.NET),
                "a socket stream parked in a STATIC field is read through the same blind spot — got "
                + r.get("com.x.Stat.read"));
        } finally { rm(cls.getParent()); }
    }

    /** THE CONTROL-FLOW ROW (§F1 q1). A field bound on one branch from a socket and on the other from a
     *  file must carry BOTH — the provenance value UNIONS at a join rather than collapsing, because it is
     *  used to CHARGE. Every other field of {@code ProvValue} collapses to null on disagreement, which is
     *  the sound direction for a value used to NARROW; getting this one the same way round would drop
     *  whichever branch merged second, silently. */
    @Test
    void aBranchMergedAcquisitionChargesEveryOriginNotOne() throws Exception {
        Path cls = compile(Map.of("com/x/Both.java", String.join("\n",
            "package com.x;",
            "import java.io.*;",
            "import java.net.Socket;",
            "public class Both {",
            "  InputStream in;",
            "  public Both(boolean net, Socket s, File f) throws IOException {",
            "    this.in = net ? s.getInputStream() : new FileInputStream(f); }",
            "  public int read() throws IOException { return in.read(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            EffectSet e = eff(r, "com.x.Both.read");
            assertTrue(e.contains(Effect.NET) && e.contains(Effect.FS),
                "both branches' acquisitions must survive the join — got " + e);
        } finally { rm(cls.getParent()); }
    }

    // ── the boundary ───────────────────────────────────────────────────────────────────────────────

    /** THE TWO SHAPES THIS ROW DOES NOT CLOSE, pinned as residuals so nobody reads the rows above as
     *  coverage of them.
     *
     *  <ul>
     *    <li>{@code Ext} — the field is bound from a PARAM. The concrete stream is the caller's, which is
     *        the pre-existing external-stream question; Phase 1 answers it with {@code Unknown} only where
     *        the stream is an ARGUMENT to a stream-consuming UTILITY, and R17 only for an entry point's own
     *        param. Widening it to every receiver read is a separate decision with its own flood risk.
     *    <li>{@code Wrap} — the field holds a FILTER constructed over an acquisition
     *        ({@code new InputStreamReader(sock.getInputStream())}); the constructor is not traced through,
     *        so the origin does not reach the field. {@code Rules#SELF_SOURCING_STREAMS} already excludes
     *        filters for the mirror-image reason on the suppressing side.
     *  </ul>
     *
     *  <p>Both are measured here rather than described: if either is later closed this test goes RED,
     *  which is the prompt to move the row rather than to quietly widen the claim. */
    @Test
    void theTwoResidualsThisRowDoesNotClose() throws Exception {
        Path cls = compile(Map.of("com/x/Resid.java", String.join("\n",
            "package com.x;",
            "import java.io.*;",
            "import java.net.Socket;",
            "public class Resid {",
            "  public static class Ext { InputStream in;",
            "    public Ext(InputStream i) { this.in = i; }",
            "    public int read() throws IOException { return in.read(); } }",
            "  public static class Wrap { Reader r;",
            "    public Wrap(Socket s) throws IOException { this.r = new InputStreamReader(s.getInputStream()); }",
            "    public int read() throws IOException { return r.read(); } }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "com.x.Resid$Ext.read").contains(Effect.NET),
                "RESIDUAL, not a claim of correctness: a param-bound stream field carries no provable "
                + "acquisition, so this read is still silent. Got " + r.get("com.x.Resid$Ext.read"));
            assertFalse(eff(r, "com.x.Resid$Wrap.read").contains(Effect.NET),
                "RESIDUAL, not a claim of correctness: the acquisition is inside a filter's constructor "
                + "and is not traced through it. Got " + r.get("com.x.Resid$Wrap.read"));
        } finally { rm(cls.getParent()); }
    }

    /** §E2 — THE ONE ASSUMPTION IN {@code Candor#selfSourcingCtorEffect}, MEASURED INSTEAD OF ASSERTED.
     *  That helper asks {@code Classifier.classify} with a SYNTHETIC {@code ()V} descriptor, which is only
     *  sound if every rule covering a {@code SELF_SOURCING_STREAMS} member is whole-owner. Rather than say
     *  so in a comment, ask each of the ten types with four different constructor descriptors and require
     *  one answer. A member whose rule ever becomes descriptor-gated fails here by name. */
    @Test
    void selfSourcingStreamRulesAreDescriptorIndependent() {
        String[] descs = {"()V", "(Ljava/io/File;)V", "(Ljava/lang/String;)V", "([BII)V"};
        for (String t : Rules.SELF_SOURCING_STREAMS) {
            String owner = t.replace('/', '.');
            Effect first = Classifier.classify(owner, "<init>", descs[0]);
            for (String d : descs)
                assertEquals(first, Classifier.classify(owner, "<init>", d),
                    t + "'s constructor classification depends on the DESCRIPTOR, so "
                    + "Candor#selfSourcingCtorEffect's synthetic ()V probe can no longer stand in for it");
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
