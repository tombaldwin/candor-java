package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R817 — SPEC §2 ⟨0.40⟩, pinned four-way by PART 96: a bind or listen ADDRESS is where the process
 * listens, never a destination it reaches; a bind marks nothing; a unit that ACCEPTS has {@code Net} in
 * {@code incomplete}.
 *
 * <p>MEASURED on this engine before the change (PART 96's java bodies, compiled and scanned):
 * <pre>
 *   a_litbind    new DatagramSocket(new InetSocketAddress("10.0.0.5", 9))
 *                -> hosts ['10.0.0.5','10.0.0.5:9'], incomplete ['Net']     (a FABRICATED destination)
 *   d_ephemeral  new DatagramSocket(0); s.send(new DatagramPacket(b,1,getByName("10.9.9.9"),53))
 *                -> hosts ['10.9.9.9'], incomplete ['Net'], `allow Net 10.9.9.9` EXIT 1
 *   c_accept     ss.accept() beside a benign connect -> incomplete ['Net'], EXIT 1 (correct)
 * </pre>
 *
 * <p>THE SECOND FIXTURES WERE WRITTEN FIRST, and every one of them is fail-closed on the pre-change engine
 * too: this change REMOVES markers and hosts, and a removal is where a silent under-report gets in. They
 * pin the three things that must not move — a send whose packet can be re-aimed, an accept however its
 * server socket arrived, and an address that is used as a destination anywhere.
 *
 * <p>PART 96's {@code b_rtbind} body, {@code new InetSocketAddress(h, 0)}, keeps its mark here and that is
 * NOT the bind: that constructor RESOLVES {@code h}, which sends the computed name to the resolver whatever
 * the address is later used for. The bind beside it no longer marks — {@link #aBindMarksNothing} shows it
 * on a bind whose address is a parameter.
 */
class BindListenSurfaceTest {

    private static final String BENIGN = "    new java.net.Socket(\"ok.example\", 80).close();";
    private static void scan() throws Exception {
        Path cls = compile(Map.of("app/B.java", String.join("\n",
            "package app;",
            "import java.net.*;",
            "import java.nio.ByteBuffer;",
            "import java.nio.channels.*;",
            "public class B {",
            // ── a bind address is not a destination (hosts) ─────────────────────────────────────────────
            "  static Object litBind() throws Exception {",
            "    return new DatagramSocket(new InetSocketAddress(\"10.0.0.5\", 9)); }",
            "  static Object ssBindLit() throws Exception {",
            "    ServerSocket s = new ServerSocket(); s.bind(new InetSocketAddress(\"10.0.0.5\", 9)); return s; }",
            "  static void clientLocalBind() throws Exception {",
            "    Socket s = new Socket(); s.bind(new InetSocketAddress(\"10.0.0.5\", 0));",
            "    s.connect(new InetSocketAddress(\"api.x.com\", 443)); }",
            "  static Object ssBindAddrCtor() throws Exception {", BENIGN,
            "    return new ServerSocket(9, 50, InetAddress.getByName(\"10.0.0.5\")); }",
            "  static Object wrappedBindAddr() throws Exception {",
            "    return new DatagramSocket(new InetSocketAddress(InetAddress.getByName(\"10.0.0.5\"), 9)); }",
            // ── an address used as a DESTINATION anywhere keeps its capture ────────────────────────────
            "  static void bindAndConnect() throws Exception {",
            "    InetSocketAddress a = new InetSocketAddress(\"evil.example\", 9);",
            "    new DatagramSocket(0).connect(a); new ServerSocket().bind(a); }",
            // ── a bind marks nothing ────────────────────────────────────────────────────────────────────
            "  static Object bindParam(SocketAddress a) throws Exception {", BENIGN, " return new DatagramSocket(a); }",
            "  static Object newServerSocketAlone() throws Exception {", BENIGN, " return new ServerSocket(8080); }",
            "  static Object dgram0() throws Exception {", BENIGN, " return new DatagramSocket(0); }",
            "  static void ephemeral() throws Exception {",
            "    DatagramSocket s = new DatagramSocket(0); byte[] b = new byte[1];",
            "    s.send(new DatagramPacket(b, 1, InetAddress.getByName(\"10.9.9.9\"), 53)); }",
            "  static void ephemeralSockAddr() throws Exception {",
            "    new DatagramSocket(0).send(new DatagramPacket(new byte[1], 1, new InetSocketAddress(\"10.9.9.9\", 53))); }",
            // ── an accept marks, however its server socket arrived ──────────────────────────────────────
            "  static void acceptParam(ServerSocket ss) throws Exception {", BENIGN,
            "    ss.accept().getOutputStream().write(1); }",
            "  static Socket acceptLocal() throws Exception {", BENIGN,
            "    ServerSocket ss = new ServerSocket(8080); return ss.accept(); }",
            "  static SocketChannel acceptChannel() throws Exception {", BENIGN,
            "    ServerSocketChannel c = ServerSocketChannel.open(); c.bind(new InetSocketAddress(8080)); return c.accept(); }",
            "  static void acceptAsync(AsynchronousServerSocketChannel c,",
            "      CompletionHandler<AsynchronousSocketChannel, Object> h) throws Exception {", BENIGN,
            "    c.accept(null, h); }",
            "  static class MySS extends ServerSocket { MySS() throws java.io.IOException { super(8080); } }",
            "  static Socket acceptSubclass() throws Exception {", BENIGN, " return new MySS().accept(); }",
            // ── a send whose packet may be re-aimed keeps its mark ──────────────────────────────────────
            "  static void sendRuntimeName(String h) throws Exception {", BENIGN,
            "    new DatagramSocket(0).send(new DatagramPacket(new byte[1], 1, InetAddress.getByName(h), 53)); }",
            "  static void sendParamAddr(InetAddress a) throws Exception {", BENIGN,
            "    new DatagramSocket(0).send(new DatagramPacket(new byte[1], 1, a, 53)); }",
            "  static void sendParamPacket(DatagramPacket p) throws Exception {", BENIGN,
            "    new DatagramSocket(0).send(p); }",
            "  static void sendAfterReceive() throws Exception {", BENIGN,
            "    DatagramSocket s = new DatagramSocket(9);",
            "    DatagramPacket p = new DatagramPacket(new byte[8], 8, InetAddress.getByName(\"10.9.9.9\"), 53);",
            "    s.receive(p); s.send(p); }",
            "  static void sendAfterSetAddress(InetAddress a) throws Exception {", BENIGN,
            "    DatagramPacket p = new DatagramPacket(new byte[1], 1, InetAddress.getByName(\"10.9.9.9\"), 53);",
            "    p.setAddress(a); new DatagramSocket(0).send(p); }",
            "  static void reAim(DatagramPacket p, InetAddress a) { p.setAddress(a); }",
            "  static void sendAfterHelper(InetAddress a) throws Exception {", BENIGN,
            "    DatagramPacket p = new DatagramPacket(new byte[1], 1, InetAddress.getByName(\"10.9.9.9\"), 53);",
            "    reAim(p, a); new DatagramSocket(0).send(p); }",
            "  static void sendMerged(boolean c, InetAddress a) throws Exception {", BENIGN,
            "    DatagramPacket p = c ? new DatagramPacket(new byte[1], 1, InetAddress.getByName(\"10.9.9.9\"), 53)",
            "                         : new DatagramPacket(new byte[1], 1, a, 53);",
            "    new DatagramSocket(0).send(p); }",
            "  static void sendInLoop(InetAddress[] as) throws Exception {", BENIGN,
            "    DatagramSocket s = new DatagramSocket(0);",
            "    DatagramPacket p = new DatagramPacket(new byte[1], 1, InetAddress.getByName(\"10.9.9.9\"), 53);",
            "    for (InetAddress a : as) { s.send(p); p.setAddress(a); } }",
            "  static void sendConnectedNoAddr(SocketAddress a) throws Exception {", BENIGN,
            "    DatagramSocket s = new DatagramSocket(0); s.connect(a); s.send(new DatagramPacket(new byte[1], 1)); }",
            // ── an address that reaches NO bind is not a bind address — a discarded lookup is a DNS query
            //    naming its host. The first cut of R817 read "no use" as "only binds" and certified these.
            "  static void lookupDiscarded() throws Exception {", BENIGN, " InetAddress.getByName(\"evil.example\"); }",
            "  static void isaDiscarded() throws Exception {", BENIGN, " new InetSocketAddress(\"evil.example\", 80); }",
            "  static boolean lookupNullCheck() throws Exception {", BENIGN,
            "    return InetAddress.getByName(\"evil.example\") != null; }",
            // PART 96's b_rtbind body: the resolution of `h`, not the bind, is what marks it.
            "  static Object runtimeNameBind(String h) throws Exception {", BENIGN,
            "    return new DatagramSocket(new InetSocketAddress(h, 0)); }",
            "}")));
        try { Candor.runScan(cls); } finally { rm(cls.getParent()); }
    }

    private static boolean netIncomplete(String fn) {
        Map<String, TreeSet<String>> m = Literals.literalFixpoint(AnalysisState.ctx().surfaceIncomplete);
        return m.getOrDefault("app.B." + fn, new TreeSet<>()).contains("Net");
    }

    private static TreeSet<String> hosts(String fn) {
        return AnalysisState.ctx().hostsDirect.getOrDefault("app.B." + fn, new TreeSet<>());
    }

    private static boolean names(TreeSet<String> hs, String host) {
        return hs.stream().anyMatch(h -> h.equals(host) || h.startsWith(host + ":"));
    }

    @Test
    void aBindAddressIsNeverPublishedAsADestination() throws Exception {
        scan();
        for (String fn : new String[] {"litBind", "ssBindLit", "clientLocalBind", "ssBindAddrCtor", "wrappedBindAddr"})
            assertFalse(names(hosts(fn), "10.0.0.5"),
                    fn + ": 10.0.0.5 is where the process LISTENS — hosts=" + hosts(fn));
        assertTrue(names(hosts("clientLocalBind"), "api.x.com"), "the connect destination beside it is still captured");
        assertTrue(names(hosts("ssBindAddrCtor"), "ok.example"), "and so is the benign sibling");
    }

    @Test
    void anAddressAlsoUsedAsADestinationKeepsItsCapture() throws Exception {
        scan();
        assertTrue(names(hosts("bindAndConnect"), "evil.example"),
                "the same address is CONNECTED to — it is a destination, so it stays in hosts");
    }

    /** A cardinal sin in this row's own first cut, found by reading the corpus A/B: every use of a
     *  discarded value is "accepted", so the walk called it bind-only and dropped both the capture and the
     *  mark. Each of these is a DNS query naming {@code evil.example} beside a benign literal. */
    @Test
    void anAddressThatReachesNoBindIsStillADestination() throws Exception {
        scan();
        for (String fn : new String[] {"lookupDiscarded", "isaDiscarded", "lookupNullCheck"})
            assertTrue(names(hosts(fn), "evil.example") || netIncomplete(fn),
                    fn + ": evil.example is looked up — it must be on the surface or the surface incomplete");
    }

    @Test
    void aBindMarksNothing() throws Exception {
        scan();
        for (String fn : new String[] {"bindParam", "newServerSocketAlone", "dgram0", "ephemeral", "ephemeralSockAddr"})
            assertFalse(netIncomplete(fn), fn + ": a bind (or a send to a captured literal) is no unseen destination");
        assertTrue(names(hosts("ephemeral"), "10.9.9.9"), "the send's destination is on the surface");
    }

    @Test
    void anAcceptMarksHoweverTheServerSocketArrived() throws Exception {
        scan();
        for (String fn : new String[] {"acceptParam", "acceptLocal", "acceptChannel", "acceptAsync", "acceptSubclass"})
            assertTrue(netIncomplete(fn), fn + ": an accept talks to whoever connects — `allow Net ok.example` must fail closed");
    }

    @Test
    void aSendWhosePacketCanBeReAimedStillMarks() throws Exception {
        scan();
        for (String fn : new String[] {"sendRuntimeName", "sendParamAddr", "sendParamPacket", "sendAfterReceive",
                "sendAfterSetAddress", "sendAfterHelper", "sendMerged", "sendInLoop", "sendConnectedNoAddr",
                "runtimeNameBind"})
            assertTrue(netIncomplete(fn), fn + ": the destination is not the captured literal on every path");
    }
}
