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
 * SOUNDNESS R130 (java half) — <b>one rule, one spelling</b>. The question this file pins is not "does
 * candor model the filesystem", it is: <i>for each modelled effect, does the rule cover only the ORDINARY
 * spelling, and what does it do with every OTHER route to the same underlying operation?</i>
 *
 * <p>Asked of candor-rust first, where {@code std::fs::} turned out to be the entire filesystem rule and
 * every platform module under it ({@code std::os::unix::fs::symlink}, {@code chown}, {@code chroot}) read
 * PURE. That is not evidence about this engine, so it was re-asked here and answered by MEASUREMENT
 * against the built jar, with every fixture COMPILED AND EXECUTED first (§E3 — an absence-shaped control
 * whose program cannot run is not weak evidence, it is none). Thirteen routes came back SILENT: scanned
 * {@code functions: []}, {@code excluded: []}, and exit 0 under ALL FIVE policy forms — blanket
 * {@code deny <E>}, {@code deny Unknown}, {@code deny <E> Unknown}, scoped {@code deny <E> fx} and
 * {@code pure fx}. In every case the CONTROL — the ordinary spelling of the same operation, in the same
 * jar, in the same compile, differing ONLY in the route — charged the effect and exited 1.
 *
 * <p>The routes, and the real-world effect each executed fixture was observed to produce:
 * <ul>
 *   <li>{@code java.nio.file.spi.FileSystemProvider} — the SPI every {@code Files.*} method is defined as
 *       a call to, handed to user code by {@code FileSystems.getDefault().provider()}. A real file, a real
 *       directory and a real SYMLINK created on disk through it, silently.</li>
 *   <li>{@code java.nio.file.FileSystem} getFileStores/getRootDirectories/newWatchService/close — 16 file
 *       stores really enumerated.</li>
 *   <li>{@code java.nio.file.attribute.*AttributeView} — a 0400 chmod and a {@code user.candor} xattr both
 *       verified on disk, through a view RECEIVED as a parameter (the acquisition, {@code
 *       Files.getFileAttributeView}, is charged — but acquisition and mutation live in different methods).</li>
 *   <li>{@code UserPrincipalLookupService.lookupPrincipalByName} — a real OS principal resolved.</li>
 *   <li>{@code java.awt.Desktop.moveToTrash} — a real file removed from disk by the one member of the
 *       Desktop verb list that is not a launch.</li>
 *   <li>{@code Process.onExit}/{@code inputReader}/{@code errorReader}/{@code outputWriter} and
 *       {@code ProcessHandle.onExit}/{@code allProcesses}/{@code children}/{@code descendants} — a real
 *       child waited for, its stdout really read, 807 live OS process handles really enumerated.</li>
 *   <li>{@code java.util.random.RandomGenerator$SplittableGenerator} and siblings — real entropy drawn
 *       through a receiver typed as the SUB-INTERFACE.</li>
 *   <li>{@code new InetSocketAddress(String,int)} — a real resolver lookup (localhost resolved; a
 *       {@code .invalid} name came back {@code isUnresolved()}, which only a real lookup can produce),
 *       and {@code InetAddress.getHostName} / an {@code Inet4Address}-typed receiver.</li>
 *   <li>{@code javax.net.ssl.SSLServerSocket.accept} and
 *       {@code ServerSocketFactory.createServerSocket} — a real listening socket bound and accepted on.</li>
 *   <li>{@code GregorianCalendar.getInstance()} — javac emits the QUALIFYING type for a static call.</li>
 * </ul>
 *
 * <p><b>THE MECHANISM, so the next sibling is not found by hand.</b> Every one of these is the classifier
 * keying on the STATIC RECEIVER TYPE emitted in the bytecode, and one of three shapes:
 * (a) a SUBTYPE-typed receiver of a modelled type — {@code Classifier#classify} sees the subtype's name,
 * and the supertype re-classification in {@code Candor#handleMethodInsn} is gated on
 * {@code ctx.byName.containsKey(owner)}, i.e. PROJECT owners only, so no JDK subtype ever gets the walk;
 * (b) the LAYER BELOW a modelled facade (the SPI under {@code Files}, the view under
 * {@code getFileAttributeView}); (c) a VERB ALLOWLIST on a modelled owner that forgot a member. The fixes
 * below are prefix/whole-owner rules with tested DENYLIST carve-outs, because the third shape is what
 * produced most of these and an allowlist under-reports every verb it omits, silently.
 *
 * <p><b>The over-charge controls are the deliverable half.</b> Ten of them, one per carve-out, each also
 * compiled and executed. They are what stops these widenings fabricating an effect on the pure neighbour —
 * which is the cardinal sin in the other direction and the failure mode of most fabrication-fixes.
 */
class SecondSpellingRouteTest {

    // ── Fs: the layer under java.nio.file.Files ─────────────────────────────────────────────────────

    /** The FileSystemProvider SPI. The CONTROL is in the same class and the same scan: `portable` uses
     *  `Files.write`, `spi` reaches the identical syscall through `provider()`. Both must be Fs — before
     *  this rule only `portable` was. */
    @Test
    void fileSystemProviderIsTheSameFilesystem() throws Exception {
        Path cls = compile(Map.of("com/x/P.java", String.join("\n",
            "package com.x;",
            "import java.nio.file.*;",
            "import java.nio.file.spi.FileSystemProvider;",
            "public class P {",
            "  public void portable(Path f) throws Exception { Files.write(f, new byte[]{65}); }",
            "  public void spi(Path f) throws Exception {",
            "    FileSystemProvider pv = FileSystems.getDefault().provider();",
            "    try (java.io.OutputStream os = pv.newOutputStream(f)) { os.write(66); }",
            "  }",
            "  public void mkdir(Path d) throws Exception { FileSystems.getDefault().provider().createDirectory(d); }",
            "  public void link(Path l, Path t) throws Exception { FileSystems.getDefault().provider().createSymbolicLink(l, t); }",
            "  public void rm(Path f) throws Exception { FileSystems.getDefault().provider().delete(f); }",
            "  public void read(Path f) throws Exception { FileSystems.getDefault().provider().readAttributes(f, java.nio.file.attribute.BasicFileAttributes.class); }",
            "  public void mv(Path a, Path b) throws Exception { FileSystems.getDefault().provider().move(a, b); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"portable", "spi", "mkdir", "link", "rm", "read", "mv"}) {
                assertTrue(eff(r, "com.x.P." + m).contains(Effect.FS),
                    m + " performs real filesystem I/O — must be Fs, got " + r.get("com.x.P." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** java.nio.file.FileSystem's four OS-touching verbs, and the file ATTRIBUTE VIEWS received across a
     *  method boundary, and the principal lookup, and Desktop.moveToTrash. */
    @Test
    void fileSystemVerbsAttributeViewsAndTrashAreFs() throws Exception {
        Path cls = compile(Map.of("com/x/V.java", String.join("\n",
            "package com.x;",
            "import java.nio.file.*;",
            "import java.nio.file.attribute.*;",
            "public class V {",
            "  public Object stores() { return FileSystems.getDefault().getFileStores(); }",
            "  public Object roots() { return FileSystems.getDefault().getRootDirectories(); }",
            "  public Object watch() throws Exception { return FileSystems.getDefault().newWatchService(); }",
            "  public void shut(FileSystem fs) throws Exception { fs.close(); }",
            "  public void chmod(PosixFileAttributeView v, java.util.Set<PosixFilePermission> p) throws Exception { v.setPermissions(p); }",
            "  public void chown(FileOwnerAttributeView v, UserPrincipal u) throws Exception { v.setOwner(u); }",
            "  public void xattr(UserDefinedFileAttributeView v, java.nio.ByteBuffer b) throws Exception { v.write(\"k\", b); }",
            "  public void utimes(BasicFileAttributeView v, FileTime t) throws Exception { v.setTimes(t, t, t); }",
            "  public Object acl(AclFileAttributeView v) throws Exception { return v.getAcl(); }",
            "  public Object princ(UserPrincipalLookupService s) throws Exception { return s.lookupPrincipalByName(\"root\"); }",
            "  public boolean trash(java.io.File f) { return java.awt.Desktop.getDesktop().moveToTrash(f); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"stores", "roots", "watch", "shut", "chmod", "chown", "xattr",
                                          "utimes", "acl", "princ", "trash"}) {
                assertTrue(eff(r, "com.x.V." + m).contains(Effect.FS),
                    m + " touches the filesystem — must be Fs, got " + r.get("com.x.V." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── Exec: the two handle types the builder hands you ────────────────────────────────────────────

    /** `waitFor` was charged and `onExit` was not; the three stream getters were charged and their Java 17
     *  charset-decoding twins were not; `destroy` was charged and every call that ACQUIRES a
     *  destroy-capable handle was not. All are the subprocess capability (SPEC §1: spawning / CONTROLLING). */
    @Test
    void processAndProcessHandleDriveVerbsAreExec() throws Exception {
        Path cls = compile(Map.of("com/x/D.java", String.join("\n",
            "package com.x;",
            "public class D {",
            "  public Object await(Process p) { return p.onExit(); }",
            "  public Object awaitH(ProcessHandle h) { return h.onExit(); }",
            "  public Object rd(Process p) { return p.inputReader(); }",
            "  public Object er(Process p) { return p.errorReader(); }",
            "  public Object wr(Process p) { return p.outputWriter(); }",
            "  public long all() { return ProcessHandle.allProcesses().count(); }",
            "  public long kids(ProcessHandle h) { return h.children().count(); }",
            "  public long desc(ProcessHandle h) { return h.descendants().count(); }",
            "  public Object parent(ProcessHandle h) { return h.parent(); }",
            "  public Object byPid(long pid) { return ProcessHandle.of(pid); }",
            "  public Object kidsOfProc(Process p) { return p.children(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"await", "awaitH", "rd", "er", "wr", "all", "kids", "desc",
                                          "parent", "byPid", "kidsOfProc"}) {
                assertTrue(eff(r, "com.x.D." + m).contains(Effect.EXEC),
                    m + " drives or acquires control of a subprocess — must be Exec, got " + r.get("com.x.D." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── Rand: the sub-interfaces ────────────────────────────────────────────────────────────────────

    /** A receiver typed as a RandomGenerator SUB-INTERFACE emits owner
     *  `java/util/random/RandomGenerator$SplittableGenerator`, which the old exact-owner match never saw —
     *  while the rule's own comment asserted that the sub-interfaces "extend it", a statement true about
     *  the type system and false about bytecode. `base` is the control. */
    @Test
    void randomGeneratorSubInterfacesDrawEntropy() throws Exception {
        Path cls = compile(Map.of("com/x/G.java", String.join("\n",
            "package com.x;",
            "import java.util.random.RandomGenerator;",
            "public class G {",
            "  public int base(RandomGenerator g) { return g.nextInt(); }",
            "  public long split(RandomGenerator.SplittableGenerator g) { return g.nextLong(); }",
            "  public Object fork(RandomGenerator.SplittableGenerator g) { return g.split(); }",
            "  public long jump(RandomGenerator.JumpableGenerator g) { g.jump(); return g.nextLong(); }",
            "  public long leap(RandomGenerator.LeapableGenerator g) { g.leap(); return g.nextLong(); }",
            "  public long arb(RandomGenerator.ArbitrarilyJumpableGenerator g) { return g.nextLong(); }",
            "  public long stream(RandomGenerator.StreamableGenerator g) { return g.nextLong(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"base", "split", "fork", "jump", "leap", "arb", "stream"}) {
                assertTrue(eff(r, "com.x.G." + m).contains(Effect.RAND),
                    m + " draws from a PRNG — must be Rand, got " + r.get("com.x.G." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── Net: DNS spellings, the TLS acceptor, the jar: connection ───────────────────────────────────

    /** `InetAddress.getByName` was charged and the constructor that calls it internally was not; the
     *  forward lookups were charged and the REVERSE one (`getHostName`) was not; `Socket`/`SSLSocket` were
     *  charged and the ACCEPTOR side was not. */
    @Test
    void everyResolverAndAcceptorSpellingIsNet() throws Exception {
        Path cls = compile(Map.of("com/x/N.java", String.join("\n",
            "package com.x;",
            "import java.net.*;",
            "public class N {",
            "  public Object byName(String h) throws Exception { return InetAddress.getByName(h); }",  // control
            "  public Object ctor(String h, int p) { return new InetSocketAddress(h, p); }",
            "  public String rev(InetAddress a) { return a.getHostName(); }",
            "  public String rev4(Inet4Address a) { return a.getHostName() + a.getCanonicalHostName(); }",
            "  public String rev6(Inet6Address a) { return a.getCanonicalHostName(); }",
            "  public String revSock(InetSocketAddress a) { return a.getHostName(); }",
            "  public Object accept(javax.net.ssl.SSLServerSocket s) throws Exception { return s.accept(); }",
            "  public Object bind() throws Exception { return javax.net.ServerSocketFactory.getDefault().createServerSocket(0); }",
            "  public Object bindTls() throws Exception { return javax.net.ssl.SSLServerSocketFactory.getDefault().createServerSocket(0); }",
            "  public Object jar(JarURLConnection c) throws Exception { return c.getInputStream(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"byName", "ctor", "rev", "rev4", "rev6", "revSock", "accept",
                                          "bind", "bindTls", "jar"}) {
                assertTrue(eff(r, "com.x.N." + m).contains(Effect.NET),
                    m + " performs a resolver lookup or opens a listening/remote endpoint — must be Net,"
                        + " got " + r.get("com.x.N." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── Clock: the qualifying type of a static call ─────────────────────────────────────────────────

    /** javac emits the QUALIFYING type for a static call, so `GregorianCalendar.getInstance()` — legal,
     *  inherited, and common — emitted owner `java/util/GregorianCalendar` and missed the exact match.
     *  `base` is the control; `valued` is the over-charge control (a ctor with a date reads no clock). */
    @Test
    void gregorianCalendarGetInstanceReadsTheClock() throws Exception {
        Path cls = compile(Map.of("com/x/C.java", String.join("\n",
            "package com.x;",
            "import java.util.*;",
            "public class C {",
            "  public Calendar base() { return Calendar.getInstance(); }",
            "  public Calendar sub() { return GregorianCalendar.getInstance(); }",
            "  public int valued() { return new GregorianCalendar(2020, 0, 1).get(Calendar.YEAR); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "com.x.C.base").contains(Effect.CLOCK), "control: got " + r.get("com.x.C.base"));
            assertTrue(eff(r, "com.x.C.sub").contains(Effect.CLOCK),
                "GregorianCalendar.getInstance() initializes to now — must be Clock, got " + r.get("com.x.C.sub"));
            assertFalse(eff(r, "com.x.C.valued").contains(Effect.CLOCK),
                "a VALUED GregorianCalendar ctor reads no clock — must not be Clock, got " + r.get("com.x.C.valued"));
        } finally { rm(cls.getParent()); }
    }

    // ── OVER-CHARGE CONTROLS ────────────────────────────────────────────────────────────────────────
    // One per denylist carve-out introduced above. Each of these compiled AND RAN in the R130 harness
    // before being written down; none asserts an absence about a program that cannot execute (§E3).

    /** (a) The FileSystemProvider carve-outs. `getScheme()` returns a constant String. The protected
     *  no-op `<init>`, reached by `super()` from a user-written provider subclass, must not make every
     *  custom provider's constructor an Fs violation. */
    @Test
    void control_pureProviderSurfaceStaysPure() throws Exception {
        Path cls = compile(Map.of(
            "com/x/Q.java", String.join("\n",
                "package com.x;",
                "import java.nio.file.*;",
                "public class Q {",
                "  public String scheme() { return FileSystems.getDefault().provider().getScheme(); }",
                "  public Path toPath(java.net.URI u) { return FileSystems.getDefault().provider().getPath(u); }",
                "  public FileSystem existing(java.net.URI u) { return FileSystems.getDefault().provider().getFileSystem(u); }",
                "}"),
            "com/x/Sub.java", String.join("\n",
                "package com.x;",
                "import java.net.URI;",
                "import java.nio.channels.SeekableByteChannel;",
                "import java.nio.file.*;",
                "import java.nio.file.attribute.*;",
                "import java.nio.file.spi.FileSystemProvider;",
                "import java.util.*;",
                "public class Sub extends FileSystemProvider {",
                "  public Sub() { super(); }",
                "  public String getScheme() { return \"x\"; }",
                "  public FileSystem newFileSystem(URI u, Map<String,?> e) { throw new UnsupportedOperationException(); }",
                "  public FileSystem getFileSystem(URI u) { throw new UnsupportedOperationException(); }",
                "  public Path getPath(URI u) { throw new UnsupportedOperationException(); }",
                "  public SeekableByteChannel newByteChannel(Path p, Set<? extends OpenOption> o, FileAttribute<?>... a) { throw new UnsupportedOperationException(); }",
                "  public DirectoryStream<Path> newDirectoryStream(Path d, DirectoryStream.Filter<? super Path> f) { throw new UnsupportedOperationException(); }",
                "  public void createDirectory(Path d, FileAttribute<?>... a) { throw new UnsupportedOperationException(); }",
                "  public void delete(Path p) { throw new UnsupportedOperationException(); }",
                "  public void copy(Path s, Path t, CopyOption... o) { throw new UnsupportedOperationException(); }",
                "  public void move(Path s, Path t, CopyOption... o) { throw new UnsupportedOperationException(); }",
                "  public boolean isSameFile(Path a, Path b) { return false; }",
                "  public boolean isHidden(Path p) { return false; }",
                "  public FileStore getFileStore(Path p) { throw new UnsupportedOperationException(); }",
                "  public void checkAccess(Path p, AccessMode... m) { throw new UnsupportedOperationException(); }",
                "  public <V extends FileAttributeView> V getFileAttributeView(Path p, Class<V> t, LinkOption... o) { return null; }",
                "  public <A extends BasicFileAttributes> A readAttributes(Path p, Class<A> t, LinkOption... o) { throw new UnsupportedOperationException(); }",
                "  public Map<String,Object> readAttributes(Path p, String a, LinkOption... o) { throw new UnsupportedOperationException(); }",
                "  public void setAttribute(Path p, String a, Object v, LinkOption... o) { throw new UnsupportedOperationException(); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "com.x.Q.scheme").contains(Effect.FS),
                "getScheme() returns a constant String — must not be Fs, got " + r.get("com.x.Q.scheme"));
            // These two were MEASURED as fabrications on real code (jetbrains verifier-cli's
            // FileSystemProvider wrapper) by auditing this fix's own 395-jar corpus diff, then carved out.
            assertFalse(eff(r, "com.x.Q.toPath").contains(Effect.FS),
                "getPath(URI) is specified as URI->Path CONVERSION and touches nothing — must not be Fs,"
                    + " got " + r.get("com.x.Q.toPath"));
            assertFalse(eff(r, "com.x.Q.existing").contains(Effect.FS),
                "getFileSystem(URI) returns an ALREADY-CREATED FileSystem (or throws) — must not be Fs,"
                    + " got " + r.get("com.x.Q.existing"));
            assertFalse(eff(r, "com.x.Sub.<init>").contains(Effect.FS),
                "a custom FileSystemProvider's ctor calls the JDK's no-op super() — must not be Fs, got "
                    + r.get("com.x.Sub.<init>"));
        } finally { rm(cls.getParent()); }
    }

    /** (b) java.nio.file.FileSystem is mostly PATH ALGEBRA. A whole-owner rule here would fabricate Fs on
     *  every `fs.getPath(...)` in the corpus, which is why the rule is verb-gated. */
    @Test
    void control_fileSystemPathAlgebraStaysPure() throws Exception {
        Path cls = compile(Map.of("com/x/A.java", String.join("\n",
            "package com.x;",
            "import java.nio.file.*;",
            "public class A {",
            "  public Path p(FileSystem fs) { return fs.getPath(\"a\", \"b\"); }",
            "  public String sep(FileSystem fs) { return fs.getSeparator(); }",
            "  public boolean open(FileSystem fs) { return fs.isOpen(); }",
            "  public boolean ro(FileSystem fs) { return fs.isReadOnly(); }",
            "  public Object views(FileSystem fs) { return fs.supportedFileAttributeViews(); }",
            "  public Object matcher(FileSystem fs) { return fs.getPathMatcher(\"glob:*\"); }",
            "  public Object prov(FileSystem fs) { return fs.provider(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"p", "sep", "open", "ro", "views", "matcher", "prov"}) {
                assertFalse(eff(r, "com.x.A." + m).contains(Effect.FS),
                    m + " is path algebra / a cached flag and touches nothing — must not be Fs, got "
                        + r.get("com.x.A." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** (c) The attribute SNAPSHOT types are the already-taken reading. `PosixFileAttributes` does not end
     *  in `AttributeView`, which is the entire reason the view rule is keyed on that suffix — and
     *  `view.name()` returns the view's constant identifier. */
    @Test
    void control_attributeSnapshotsAndViewNameStayPure() throws Exception {
        Path cls = compile(Map.of("com/x/S.java", String.join("\n",
            "package com.x;",
            "import java.nio.file.attribute.*;",
            "public class S {",
            "  public Object perms(PosixFileAttributes a) { return a.permissions(); }",
            "  public long size(BasicFileAttributes a) { return a.size(); }",
            "  public boolean dir(BasicFileAttributes a) { return a.isDirectory(); }",
            "  public Object owner(PosixFileAttributes a) { return a.owner(); }",
            "  public String name(PosixFileAttributeView v) { return v.name(); }",
            "  public String nameB(BasicFileAttributeView v) { return v.name(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"perms", "size", "dir", "owner", "name", "nameB"}) {
                assertFalse(eff(r, "com.x.S." + m).contains(Effect.FS),
                    m + " reads an already-taken snapshot or a constant view name — must not be Fs, got "
                        + r.get("com.x.S." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** (d) The Process / ProcessHandle value-read surface. Converting those two verb allowlists into
     *  whole-owner rules is only safe because these stay pure: an int, a boolean, or a conversion between
     *  the two handle types for a child that has ALREADY been spawned (and whose spawn was charged where
     *  it happened). A test double that subclasses Process must not have an Exec constructor. */
    @Test
    void control_processValueReadsStayPure() throws Exception {
        Path cls = compile(Map.of(
            "com/x/W.java", String.join("\n",
                "package com.x;",
                "public class W {",
                "  public int code(Process p) { return p.exitValue(); }",
                "  public boolean live(Process p) { return p.isAlive(); }",
                "  public long pid(Process p) { return p.pid(); }",
                "  public Object toH(Process p) { return p.toHandle(); }",
                "  public boolean norm(Process p) { return p.supportsNormalTermination(); }",
                "  public Object me() { return ProcessHandle.current(); }",
                "  public long hpid(ProcessHandle h) { return h.pid(); }",
                "  public boolean hlive(ProcessHandle h) { return h.isAlive(); }",
                "  public String dump(Process p) { return p.toString(); }",
                "}"),
            "com/x/Fake.java", String.join("\n",
                "package com.x;",
                "import java.io.*;",
                "public class Fake extends Process {",
                "  public Fake() { super(); }",
                "  public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }",
                "  public InputStream getInputStream() { return InputStream.nullInputStream(); }",
                "  public InputStream getErrorStream() { return InputStream.nullInputStream(); }",
                "  public int waitFor() { return 0; }",
                "  public int exitValue() { return 0; }",
                "  public void destroy() { }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"code", "live", "pid", "toH", "norm", "me", "hpid", "hlive", "dump"}) {
                assertFalse(eff(r, "com.x.W." + m).contains(Effect.EXEC),
                    m + " reads a value about an already-spawned process — must not be Exec, got "
                        + r.get("com.x.W." + m));
            }
            assertFalse(eff(r, "com.x.Fake.<init>").contains(Effect.EXEC),
                "a Process test double's ctor calls the JDK's no-op super() — must not be Exec, got "
                    + r.get("com.x.Fake.<init>"));
        } finally { rm(cls.getParent()); }
    }

    /** (e) THE `$`-ANCHOR CONTROL. The Rand rule matches `java.util.random.RandomGenerator` exactly plus
     *  the `$`-anchored prefix. A bare `startsWith("java.util.random.RandomGenerator")` — the obvious
     *  spelling — would also swallow the sibling TOP-LEVEL type `RandomGeneratorFactory`, whose
     *  all()/of()/getDefault()/isSplittable()/stateBits() are pure metadata and draw nothing. */
    @Test
    void control_randomGeneratorFactoryMetadataStaysPure() throws Exception {
        Path cls = compile(Map.of("com/x/F.java", String.join("\n",
            "package com.x;",
            "import java.util.random.RandomGeneratorFactory;",
            "public class F {",
            "  public long all() { return RandomGeneratorFactory.all().count(); }",
            "  public boolean splittable() { return RandomGeneratorFactory.of(\"L64X128MixRandom\").isSplittable(); }",
            "  public int bits() { return RandomGeneratorFactory.getDefault().stateBits(); }",
            "  public String nameOf() { return RandomGeneratorFactory.getDefault().name(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"all", "splittable", "bits", "nameOf"}) {
                assertFalse(eff(r, "com.x.F." + m).contains(Effect.RAND),
                    m + " reads factory METADATA and draws no entropy — must not be Rand, got "
                        + r.get("com.x.F." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** (f) SSLServerSocket's handshake-CONFIG surface touches no wire, and it is inherited-plus-own, so
     *  the whole-owner Net rule added for `accept()` needs this carve-out or every TLS server's setup code
     *  becomes a Net violation. */
    @Test
    void control_sslServerSocketConfigStaysPure() throws Exception {
        Path cls = compile(Map.of("com/x/T.java", String.join("\n",
            "package com.x;",
            "import javax.net.ssl.SSLServerSocket;",
            "public class T {",
            "  public void auth(SSLServerSocket s) { s.setNeedClientAuth(false); }",
            "  public void mode(SSLServerSocket s) { s.setUseClientMode(false); }",
            "  public void protos(SSLServerSocket s) { s.setEnabledProtocols(s.getSupportedProtocols()); }",
            "  public void params(SSLServerSocket s) { s.setSSLParameters(s.getSSLParameters()); }",
            "  public Object suites(SSLServerSocket s) { return s.getEnabledCipherSuites(); }",
            "  public int port(SSLServerSocket s) { return s.getLocalPort(); }",
            "  public boolean closed(SSLServerSocket s) { return s.isClosed(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"auth", "mode", "protos", "params", "suites", "port", "closed"}) {
                assertFalse(eff(r, "com.x.T." + m).contains(Effect.NET),
                    m + " configures the handshake and touches no wire — must not be Net, got "
                        + r.get("com.x.T." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** (g) The InetSocketAddress forms that resolve NOTHING — the descriptor gate's whole point.
     *  `createUnresolved` is documented never to resolve, `(InetAddress,int)` takes an address that was
     *  already resolved (and charged) elsewhere, and `(int)` binds the wildcard. */
    @Test
    void control_nonResolvingSocketAddressFormsStayPure() throws Exception {
        Path cls = compile(Map.of("com/x/U.java", String.join("\n",
            "package com.x;",
            "import java.net.*;",
            "public class U {",
            "  public Object unres() { return InetSocketAddress.createUnresolved(\"h\", 80); }",
            "  public Object fromAddr(InetAddress a) { return new InetSocketAddress(a, 80); }",
            "  public Object wildcard() { return new InetSocketAddress(0); }",
            "  public int port(InetSocketAddress a) { return a.getPort(); }",
            "  public boolean unresolvedQ(InetSocketAddress a) { return a.isUnresolved(); }",
            "  public Object addr(InetSocketAddress a) { return a.getAddress(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"unres", "fromAddr", "wildcard", "port", "unresolvedQ", "addr"}) {
                assertFalse(eff(r, "com.x.U." + m).contains(Effect.NET),
                    m + " performs no name lookup — must not be Net, got " + r.get("com.x.U." + m));
            }
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
