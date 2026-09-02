package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R130 (java half), FOLLOW-UP — <b>the over-charge column of the same fix</b>.
 *
 * <p>{@link SecondSpellingRouteTest} pins the thirteen routes that read PURE and now charge. This file
 * pins the direction that fix could fail in, because it did: an adversarial review of {@code d8e953c}
 * found three FABRICATIONS it introduced, each A/B'd absent at {@code 2dd1600} and charged at
 * {@code d8e953c}, and each flipping a {@code deny <E>} gate from exit 0 to exit 1 on code that performs
 * nothing. This is the measured rate the family already carries — four defects in five fabrication-fixes
 * — landing again, so every positive row below has its own second fixture proving the genuinely-effectful
 * spelling still charges.
 *
 * <ul>
 *   <li><b>B2 — {@code FileSystemProvider.getFileAttributeView}.</b> EXECUTED: on a path that does not
 *       exist it returns a live view and throws nothing, while {@code view.readAttributes()} on the same
 *       view throws {@code NoSuchFileException}. The I/O is in the view, and the view is already charged
 *       by the {@code *AttributeView} rule. <b>The deeper defect is the audit boundary, not the member:</b>
 *       {@code d8e953c}'s two carve-outs ({@code getPath}, {@code getFileSystem}) were derived from what
 *       its 395-jar corpus happened to contain, so the member the corpus lacked was missed by exactly the
 *       reasoning that produced them (§9). The replacement boundary is the SPI itself — see the classifier
 *       comment; every I/O member of {@code FileSystemProvider} declares {@code throws IOException} and
 *       exactly five do not.</li>
 *   <li><b>B3 — the socket-option protocol.</b> EXECUTED on an UNBOUND socket: {@code setSoTimeout},
 *       {@code setReuseAddress}, {@code setReceiveBufferSize}, {@code setPerformancePreferences} and
 *       {@code setOption} all succeed and leave it {@code isBound()==false, getLocalPort()==-1}. R130's
 *       new whole-owner rule for {@code SSLServerSocket} charged all of them Net. And the list it added
 *       carved out {@code getReceiveBufferSize} where the {@code java.net.ServerSocket} list it was copied
 *       from does not, so the two ACCEPTOR arms answered one operation two ways (§F1 q3). Both are fixed
 *       by making the three pure groups ONE predicate each, shared by all six socket owners (§G).</li>
 *   <li><b>B4 — {@code new GregorianCalendar(TimeZone)} / {@code (Locale)} / {@code (TimeZone,Locale)}.</b>
 *       The opposite direction and PRE-EXISTING: these read the wall clock and were certified pure. Missed
 *       because the comment one line above asserts <i>"ARITY-PRECISE: {@code new Date(long)} /
 *       {@code new GregorianCalendar(y,m,d)} take a value and are pure"</i> — three valued constructors
 *       take a value AND read the clock (§K: a claim of correctness suppresses the measurement that would
 *       falsify it). EXECUTED: two calls 1.1s apart returned millis differing by 1110-1111 through each
 *       form, and by 0 through the {@code (y,m,d)} control.</li>
 * </ul>
 *
 * <p><b>B1 is the one that was NOT narrowed, and the two tests at the bottom are why.</b> A project class
 * extending {@code java.lang.Process} is charged Exec on the INHERITED CONCRETE members it does not
 * override, because {@code Candor#handleMethodInsn}'s supertype walk re-classifies them against
 * {@code java.lang.Process}. On a test double that spawns nothing, that is a fabrication. Removing the
 * walk for {@code Process} would be worse: {@code processWrapperKeepsItsCapabilityOnlyViaTheWalk} measures
 * that a wrapper over a REAL child reaches its capability through that walk and through nothing else
 * ({@code calls: None}) — so the narrowing would trade a loud over-charge for a silent under-report. Both
 * directions are pinned here rather than argued in a comment; the general mechanism is R131.
 */
class SecondSpellingFabricationTest {

    // ── B2: the FileSystemProvider SPI, swept by specification rather than by corpus ────────────────

    /** RED at {@code d8e953c}: {@code view} was {@code ['Fs']}. The acquisition performs no I/O. */
    @Test
    void providerAttributeViewAcquisitionStaysPure() throws Exception {
        Path cls = compile(Map.of("com/x/A.java", String.join("\n",
            "package com.x;",
            "import java.nio.file.Path;",
            "import java.nio.file.spi.FileSystemProvider;",
            "import java.nio.file.attribute.*;",
            "public class A {",
            "  public BasicFileAttributeView basic(FileSystemProvider pv, Path p) {",
            "    return pv.getFileAttributeView(p, BasicFileAttributeView.class); }",
            "  public PosixFileAttributeView posix(FileSystemProvider pv, Path p) {",
            "    return pv.getFileAttributeView(p, PosixFileAttributeView.class); }",
            "  public String scheme(FileSystemProvider pv) { return pv.getScheme(); }",
            "  public Object path(FileSystemProvider pv, java.net.URI u) { return pv.getPath(u); }",
            "  public Object fs(FileSystemProvider pv, java.net.URI u) { return pv.getFileSystem(u); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"basic", "posix", "scheme", "path", "fs"}) {
                assertFalse(eff(r, "com.x.A." + m).contains(Effect.FS),
                    m + " is one of the five FileSystemProvider members that declare no IOException and "
                        + "perform no I/O — must not be Fs, got " + r.get("com.x.A." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** THE SECOND FIXTURE, and the one that matters: the narrowing above must not have cost a capability.
     *  The SPI's I/O members still charge — including {@code readAttributes}/{@code setAttribute}, the two
     *  nearest neighbours of the carve-out, and {@code installedProviders}, which also declares no
     *  IOException and is deliberately NOT carved out. And the VIEW the carve-out hands back is still
     *  charged on every mutator, which is the reason carving the acquisition out loses nothing. */
    @Test
    void providerIoMembersAndTheViewItselfStillCharge() throws Exception {
        Path cls = compile(Map.of("com/x/B.java", String.join("\n",
            "package com.x;",
            "import java.nio.file.Path;",
            "import java.nio.file.spi.FileSystemProvider;",
            "import java.nio.file.attribute.*;",
            "import java.util.Set;",
            "public class B {",
            "  public Object readAttrs(FileSystemProvider pv, Path p) throws Exception {",
            "    return pv.readAttributes(p, BasicFileAttributes.class); }",
            "  public void setAttr(FileSystemProvider pv, Path p) throws Exception {",
            "    pv.setAttribute(p, \"dos:hidden\", Boolean.TRUE); }",
            "  public void access(FileSystemProvider pv, Path p) throws Exception { pv.checkAccess(p); }",
            "  public void del(FileSystemProvider pv, Path p) throws Exception { pv.delete(p); }",
            "  public Object mount(FileSystemProvider pv, java.net.URI u) throws Exception {",
            "    return pv.newFileSystem(u, java.util.Map.of()); }",
            "  public Object installed() { return FileSystemProvider.installedProviders(); }",
            "  public void chmod(PosixFileAttributeView v, Set<PosixFilePermission> s) throws Exception {",
            "    v.setPermissions(s); }",
            "  public Object statView(BasicFileAttributeView v) throws Exception { return v.readAttributes(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"readAttrs", "setAttr", "access", "del", "mount", "installed",
                                          "chmod", "statView"}) {
                assertTrue(eff(r, "com.x.B." + m).contains(Effect.FS),
                    m + " performs real filesystem I/O — must stay Fs, got " + r.get("com.x.B." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── B3: the socket-option protocol, on BOTH acceptor arms and the connector arms ────────────────

    /** RED at {@code d8e953c} for the {@code s*} rows (the whole-owner SSLServerSocket rule charged them)
     *  and RED at {@code 2dd1600} AND {@code d8e953c} for the {@code p*} rows (pre-existing on
     *  java.net.ServerSocket). The two arms must now AGREE — which is the point of the row, and the reason
     *  {@code pRcvbufGet}/{@code sRcvbufGet} are both here: they were the one member the two arms
     *  answered differently. */
    @Test
    void socketOptionsAreNotNetOnEitherAcceptorArm() throws Exception {
        Path cls = compile(Map.of("com/x/S.java", String.join("\n",
            "package com.x;",
            "import java.net.ServerSocket;",
            "import java.net.StandardSocketOptions;",
            "import javax.net.ssl.SSLServerSocket;",
            "public class S {",
            "  public void sTimeout(SSLServerSocket s) throws Exception { s.setSoTimeout(1); }",
            "  public void sReuse(SSLServerSocket s) throws Exception { s.setReuseAddress(true); }",
            "  public void sRcvbufSet(SSLServerSocket s) throws Exception { s.setReceiveBufferSize(8); }",
            "  public int sRcvbufGet(SSLServerSocket s) throws Exception { return s.getReceiveBufferSize(); }",
            "  public void sPerf(SSLServerSocket s) { s.setPerformancePreferences(0,1,2); }",
            "  public Object sSupported(SSLServerSocket s) { return s.supportedOptions(); }",
            "  public Object sGetOpt(SSLServerSocket s) throws Exception {",
            "    return s.getOption(StandardSocketOptions.SO_REUSEADDR); }",
            "  public void sSetOpt(SSLServerSocket s) throws Exception {",
            "    s.setOption(StandardSocketOptions.SO_REUSEADDR, true); }",
            "  public void pTimeout(ServerSocket s) throws Exception { s.setSoTimeout(1); }",
            "  public void pReuse(ServerSocket s) throws Exception { s.setReuseAddress(true); }",
            "  public void pRcvbufSet(ServerSocket s) throws Exception { s.setReceiveBufferSize(8); }",
            "  public int pRcvbufGet(ServerSocket s) throws Exception { return s.getReceiveBufferSize(); }",
            "  public void pPerf(ServerSocket s) { s.setPerformancePreferences(0,1,2); }",
            "  public Object pSupported(ServerSocket s) { return s.supportedOptions(); }",
            "  public void pSetOpt(ServerSocket s) throws Exception {",
            "    s.setOption(StandardSocketOptions.SO_REUSEADDR, true); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"sTimeout", "sReuse", "sRcvbufSet", "sRcvbufGet", "sPerf",
                                          "sSupported", "sGetOpt", "sSetOpt",
                                          "pTimeout", "pReuse", "pRcvbufSet", "pRcvbufGet", "pPerf",
                                          "pSupported", "pSetOpt"}) {
                assertFalse(eff(r, "com.x.S." + m).contains(Effect.NET),
                    m + " configures a socket descriptor and moves no byte — must not be Net, got "
                        + r.get("com.x.S." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** §A.2 — the fixture for the siblings I was NOT handed. The same predicate now governs the three
     *  CONNECTOR arms and the datagram pair, so the acceptor fix cannot have converged one pair of arms by
     *  splitting another. RED at both {@code 2dd1600} and {@code d8e953c}. */
    @Test
    void socketOptionsAreNotNetOnTheConnectorArms() throws Exception {
        Path cls = compile(Map.of("com/x/K.java", String.join("\n",
            "package com.x;",
            "import java.net.*;",
            "import javax.net.ssl.SSLSocket;",
            "public class K {",
            "  public void tcpTimeout(Socket s) throws Exception { s.setSoTimeout(1); }",
            "  public void tcpNoDelay(Socket s) throws Exception { s.setTcpNoDelay(true); }",
            "  public void tcpLinger(Socket s) throws Exception { s.setSoLinger(true, 0); }",
            "  public void tcpKeep(Socket s) throws Exception { s.setKeepAlive(true); }",
            "  public void tcpSndbuf(Socket s) throws Exception { s.setSendBufferSize(8); }",
            "  public void tcpTos(Socket s) throws Exception { s.setTrafficClass(0); }",
            "  public void tlsTimeout(SSLSocket s) throws Exception { s.setSoTimeout(1); }",
            "  public void udpBroadcast(DatagramSocket s) throws Exception { s.setBroadcast(true); }",
            "  public void udpRcvbuf(DatagramSocket s) throws Exception { s.setReceiveBufferSize(8); }",
            "  public void mcTtl(MulticastSocket s) throws Exception { s.setTimeToLive(1); }",
            "  public void mcIface(MulticastSocket s, NetworkInterface n) throws Exception {",
            "    s.setNetworkInterface(n); }",
            "  public void mcLoop(MulticastSocket s) throws Exception { s.setLoopbackMode(true); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"tcpTimeout", "tcpNoDelay", "tcpLinger", "tcpKeep", "tcpSndbuf",
                                          "tcpTos", "tlsTimeout", "udpBroadcast", "udpRcvbuf",
                                          "mcTtl", "mcIface", "mcLoop"}) {
                assertFalse(eff(r, "com.x.K." + m).contains(Effect.NET),
                    m + " sets a socket option and moves no byte — must not be Net, got "
                        + r.get("com.x.K." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** THE SECOND FIXTURE for both socket rows: the WIRE boundary, on all six owners. This is the whole
     *  guard against the narrowing above turning into a silent under-report — every one of these still has
     *  to charge Net, including {@code joinGroup}/{@code leaveGroup} (which emit IGMP and are NOT options)
     *  and {@code disconnect} (which sends nothing but is the twin of {@code connect} and is deliberately
     *  kept). */
    @Test
    void socketWireBoundaryStillCharges() throws Exception {
        Path cls = compile(Map.of("com/x/W.java", String.join("\n",
            "package com.x;",
            "import java.net.*;",
            "import javax.net.ssl.*;",
            "public class W {",
            "  public Object accept(ServerSocket s) throws Exception { return s.accept(); }",
            "  public Object sslAccept(SSLServerSocket s) throws Exception { return s.accept(); }",
            "  public void bind(ServerSocket s, SocketAddress a) throws Exception { s.bind(a); }",
            "  public void sslBind(SSLServerSocket s, SocketAddress a) throws Exception { s.bind(a); }",
            "  public void closeSs(SSLServerSocket s) throws Exception { s.close(); }",
            "  public void connect(Socket s, SocketAddress a) throws Exception { s.connect(a); }",
            "  public Object in(Socket s) throws Exception { return s.getInputStream(); }",
            "  public Object out(Socket s) throws Exception { return s.getOutputStream(); }",
            "  public void urgent(Socket s) throws Exception { s.sendUrgentData(1); }",
            "  public void shutdown(Socket s) throws Exception { s.shutdownOutput(); }",
            "  public void handshake(SSLSocket s) throws Exception { s.startHandshake(); }",
            "  public Object session(SSLSocket s) { return s.getSession(); }",
            "  public void send(DatagramSocket s, DatagramPacket p) throws Exception { s.send(p); }",
            "  public void recv(DatagramSocket s, DatagramPacket p) throws Exception { s.receive(p); }",
            "  public void disconnect(DatagramSocket s) { s.disconnect(); }",
            "  public void join(MulticastSocket s, InetAddress a) throws Exception { s.joinGroup(a); }",
            "  public void leave(MulticastSocket s, InetAddress a) throws Exception { s.leaveGroup(a); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"accept", "sslAccept", "bind", "sslBind", "closeSs", "connect",
                                          "in", "out", "urgent", "shutdown", "handshake", "session",
                                          "send", "recv", "disconnect", "join", "leave"}) {
                assertTrue(eff(r, "com.x.W." + m).contains(Effect.NET),
                    m + " is the wire boundary — must stay Net, got " + r.get("com.x.W." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── B4: the GregorianCalendar constructors that take a value AND read the clock ─────────────────

    /** RED at {@code d8e953c} and at {@code 2dd1600} — pre-existing, and a silent under-report rather than
     *  a fabrication: all three were absent from {@code functions[]} entirely. */
    @Test
    void gregorianCalendarZoneAndLocaleCtorsReadTheClock() throws Exception {
        Path cls = compile(Map.of("com/x/C.java", String.join("\n",
            "package com.x;",
            "import java.util.*;",
            "public class C {",
            "  public Calendar tz(TimeZone z) { return new GregorianCalendar(z); }",
            "  public Calendar loc(Locale l) { return new GregorianCalendar(l); }",
            "  public Calendar both(TimeZone z, Locale l) { return new GregorianCalendar(z, l); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"tz", "loc", "both"}) {
                assertTrue(eff(r, "com.x.C." + m).contains(Effect.CLOCK),
                    m + " delegates to setTimeInMillis(System.currentTimeMillis()) — must be Clock, got "
                        + r.get("com.x.C." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** THE SECOND FIXTURE: the valued constructors that really are pure. Every one of these takes only
     *  ints; that argument KIND, not the arity, is what separates the two groups. */
    @Test
    void gregorianCalendarValuedCtorsStayPure() throws Exception {
        Path cls = compile(Map.of("com/x/D.java", String.join("\n",
            "package com.x;",
            "import java.util.*;",
            "public class D {",
            "  public Calendar ymd() { return new GregorianCalendar(2020, 1, 1); }",
            "  public Calendar ymdhm() { return new GregorianCalendar(2020, 1, 1, 12, 0); }",
            "  public Calendar ymdhms() { return new GregorianCalendar(2020, 1, 1, 12, 0, 0); }",
            "  public Date fromMillis(long t) { return new Date(t); }",
            "  public Date parsed(String s) { return new Date(s); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"ymd", "ymdhm", "ymdhms", "fromMillis", "parsed"}) {
                assertFalse(eff(r, "com.x.D." + m).contains(Effect.CLOCK),
                    m + " takes its instant as a value and reads no clock — must not be Clock, got "
                        + r.get("com.x.D." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── B1: the over-approximation that was KEPT, and the measurement that says to keep it ──────────

    /** PINS THE OVER-CHARGE AS DELIBERATE, and it is not claimed to discriminate any fix — it passes at
     *  {@code 2dd1600} for {@code destroyForcibly} and at {@code d8e953c} for all three. A project subclass
     *  of {@code java.lang.Process} that overrides every abstract member with in-memory implementations
     *  and spawns nothing is still charged Exec on the INHERITED CONCRETE members, because the supertype
     *  walk re-classifies them against {@code java.lang.Process}. The executed fixture that produced this
     *  row printed zero child processes before and after. Read with the test below, which is the reason
     *  this is not narrowed. */
    @Test
    void inheritedConcreteProcessMembersOnAProjectSubclassAreCharged() throws Exception {
        Path cls = compile(Map.of("com/x/F.java", String.join("\n",
            "package com.x;",
            "import java.io.*;",
            "public class F extends Process {",
            "  private final InputStream in = new ByteArrayInputStream(new byte[]{65});",
            "  public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }",
            "  public InputStream getInputStream() { return in; }",
            "  public InputStream getErrorStream() { return in; }",
            "  public int waitFor() { return 0; }",
            "  public int exitValue() { return 0; }",
            "  public void destroy() {}",
            "}"),
            "com/x/G.java", String.join("\n",
            "package com.x;",
            "public class G {",
            "  public Object onExit(F p) { return p.onExit(); }",
            "  public Object reader(F p) { return p.inputReader(); }",
            "  public Object force(F p) { return p.destroyForcibly(); }",
            "  public F make() { return new F(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"onExit", "reader", "force"}) {
                assertTrue(eff(r, "com.x.G." + m).contains(Effect.EXEC),
                    m + " is an inherited CONCRETE member of java.lang.Process; the supertype walk charges "
                        + "it deliberately (see the classifier's <init> comment) — got " + r.get("com.x.G." + m));
            }
            // …and the `<init>` carve-out still holds: `super()` from the subclass's own constructor is
            // the JDK's protected no-op and must NOT make every such subclass's construction Exec.
            assertFalse(eff(r, "com.x.G.make").contains(Effect.EXEC),
                "constructing the subclass calls Process.<init>, a no-op — must not be Exec, got "
                    + r.get("com.x.G.make"));
            assertFalse(eff(r, "com.x.F.<init>").contains(Effect.EXEC),
                "the subclass constructor itself must not be Exec, got " + r.get("com.x.F.<init>"));
        } finally { rm(cls.getParent()); }
    }

    /** WHY THE ROW ABOVE IS NOT NARROWED. A wrapper over a REAL child reaches its capability through the
     *  supertype walk and through NOTHING ELSE: the JDK body of {@code Process.onExit()} that would call
     *  back into {@code Wrap.waitFor} is never scanned, so the caller has no recorded edge to it (measured:
     *  {@code calls: None}). Carving the inherited concrete members out for project subclasses would
     *  therefore turn this row from a loud over-charge on a test double into a SILENT under-report on a
     *  real subprocess wrapper. If a future change makes the walk precise (R131), this test is the one
     *  that must keep passing. */
    @Test
    void processWrapperKeepsItsCapabilityOnlyViaTheWalk() throws Exception {
        Path cls = compile(Map.of("com/x/H.java", String.join("\n",
            "package com.x;",
            "import java.io.*;",
            "public class H extends Process {",
            "  private final Process d;",
            "  public H(Process d) { this.d = d; }",
            "  public OutputStream getOutputStream() { return d.getOutputStream(); }",
            "  public InputStream getInputStream() { return d.getInputStream(); }",
            "  public InputStream getErrorStream() { return d.getErrorStream(); }",
            "  public int waitFor() throws InterruptedException { return d.waitFor(); }",
            "  public int exitValue() { return d.exitValue(); }",
            "  public void destroy() { d.destroy(); }",
            "}"),
            "com/x/I.java", String.join("\n",
            "package com.x;",
            "public class I {",
            "  public Object viaOnExit(H w) { return w.onExit(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "com.x.I.viaOnExit").contains(Effect.EXEC),
                "a wrapper's inherited onExit() drives a real child; the walk is the only route to that "
                    + "capability — got " + r.get("com.x.I.viaOnExit"));
        } finally { rm(cls.getParent()); }
    }

    /** §9 / item 4 — the same shape reaches the OTHER whole-owner rules R130 added, and it is pinned here
     *  rather than asserted to be absent. {@code java.nio.file.spi.FileSystemProvider} is an abstract class
     *  with ten concrete inheritable members, so a project provider that does not override
     *  {@code newInputStream} has its caller charged Fs by the same walk; {@code RandomGenerator} is an
     *  interface with ~30 defaults over one abstract {@code nextLong()}. Both are the identical trade as
     *  {@code Process} above, in the identical direction. {@code java.lang.ProcessHandle} is NOT affected —
     *  its only concrete inheritable member is {@code default compareTo(Object)}, which the carve-out
     *  already names. */
    @Test
    void inheritedConcreteMembersOfTheOtherNewWholeOwnerRulesAreAlsoCharged() throws Exception {
        Path cls = compile(Map.of("com/x/J.java", String.join("\n",
            "package com.x;",
            "import java.util.random.RandomGenerator;",
            "public class J implements RandomGenerator {",
            "  public long nextLong() { return 4L; }",
            "}"),
            "com/x/L.java", String.join("\n",
            "package com.x;",
            "public class L {",
            "  public int viaDefault(J g) { return g.nextInt(); }",
            "  public int viaAbstract(J g) { return (int) g.nextLong(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "com.x.L.viaDefault").contains(Effect.RAND),
                "RandomGenerator.nextInt() is an inherited DEFAULT method; the supertype walk charges it — "
                    + "got " + r.get("com.x.L.viaDefault"));
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
