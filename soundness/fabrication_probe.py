#!/usr/bin/env python3
"""Fabrication probe for candor-java — a precision regression guard (sibling of the soundness fuzzer).

candor's CARDINAL SIN is FABRICATION: classifying a PURE method as effectful. The whole-owner rules in
`classify()` (File→Fs, Socket→Net, Clock, Random→Rand, ZipFile→Fs, Clipboard, the NIO channels) paint an
effect onto EVERY method of an owner type — including its pure accessors/factories/inert ctors, which
perform no I/O / read no entropy / read no clock. `isPureHandleAccessor` is the per-type allowlist that
SUBTRACTS those proven-pure members back to pure. This probe pins that allowlist down.

For each effect-bearing owner type it emits two kinds of fixture method:
  PURE  — calls a member that is PROVABLY free of I/O / entropy / time-read. candor MUST report it pure
          (omitted from the report or with an empty `inferred`). If it reports an effect => FABRICATION.
  CTRL  — calls a genuinely-effectful member. candor MUST still report the effect. If it goes pure =>
          a LOST CONTROL (an under-report), the OTHER failure direction this probe also guards.

It compiles each fixture, scans it with the installed candor-java launcher, and exits non-zero on ANY
fabrication or ANY lost control — so it gates CI.

SAFETY DISCIPLINE (why this probe has no false alarms): a method appears in PURE_CASES ONLY when its JDK
implementation is verified to do no I/O / draw no entropy / read no clock. When unsure, the method is left
OUT of the pure set entirely (never asserted pure). Two notable exclusions, both verified against the JDK
source and DELIBERATELY treated as CONTROLS (must stay effectful), NOT pure:
  * FileChannel.position() — the no-arg getter LOOKS like a cached accessor but FileChannelImpl.position()
    issues an lseek syscall (nd.seek(fd,-1)) to read the OS file pointer => genuine Fs I/O.
  * FileChannel.size()     — queries the file length (nd.size(fd) syscall) => genuine Fs I/O.

Usage:  fabrication_probe.py            # build (if needed), run all cases, gate
        CJ=/path/to/candor-java fabrication_probe.py   # use a prebuilt launcher (skip the gradle build)
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Each case: (id, import_lines, receiver_decl, pure_calls, ctrl_calls, expect_effect)
#   import_lines  : Java imports the fixture needs
#   receiver_decl : how to obtain a receiver/value without performing the effect (a method PARAMETER, so
#                   no handle is ever opened/connected — the fixture body only makes the probe calls)
#   pure_calls    : statements that MUST classify pure   (each its own fixture method)
#   ctrl_calls    : statements that MUST classify <effect> (each its own fixture method)
#   expect_effect : the effect the controls must report
#
# Every PURE call below is a member whose JDK implementation is verified to do NO I/O / NO entropy /
# NO clock read. The brief rationale per member is in the comment beside it.
CASES = [
    # ---- java.io.File: a File is an immutable PATHNAME object; path ops touch no FS ----
    ("File", "import java.io.File;", "File f",
     [
        ('new File("/x")',  "ctor stores the path string, opens nothing"),
        ("f.getName()",     "returns the last path segment of the cached string"),
        ("f.getPath()",     "returns the cached path string"),
        ("f.getParent()",   "string manipulation of the cached path"),
        ("f.isAbsolute()",  "tests the cached path prefix, no FS stat"),
        ("f.toPath()",      "wraps the path string in a Path object"),
     ],
     [
        ("f.exists()",          "stat() syscall"),
        ("f.delete()",          "unlink() syscall"),
        ("f.getCanonicalPath()","resolves symlinks => FS access"),
     ], "Fs"),

    # ---- java.net.Socket family: accessors read fields cached at construct/connect time ----
    ("Socket", "import java.net.*;", "Socket s",
     [
        ("s.getPort()",        "returns the cached remote port field"),
        ("s.getLocalPort()",   "returns the cached local port field"),
        ("s.getInetAddress()", "returns the cached remote address field"),
        ("s.isClosed()",       "returns the closed flag"),
        ("s.isConnected()",    "returns the connected flag"),
        ("s.isBound()",        "returns the bound flag"),
     ],
     [
        ("s.getInputStream()",  "opens the read side of the connection"),
        ("s.getOutputStream()", "opens the write side of the connection"),
     ], "Net"),

    # ---- java.time.Clock: factories/zone accessors build/read the object, never read the wall clock ----
    ("Clock", "import java.time.*;", "Clock c",
     [
        ("Clock.systemUTC()",         "builds a Clock object, reads no time"),
        ("Clock.systemDefaultZone()", "builds a Clock object, reads no time"),
        ("c.getZone()",               "returns the clock's zone field"),
     ],
     [
        ("c.instant()", "reads the wall clock"),
        ("c.millis()",  "reads the wall clock"),
     ], "Clock"),

    # ---- java.util.Random / SecureRandom: metadata, not entropy ----
    ("SecureRandom", "import java.security.*;", "SecureRandom r",
     [
        ("r.getAlgorithm()", "reads the generator's algorithm name"),
        ("r.getProvider()",  "reads the generator's provider metadata"),
     ],
     [
        ("r.nextInt()",       "draws entropy"),
        ("r.nextBytes(new byte[4])", "draws entropy"),
     ], "Rand"),

    # ---- java.util.concurrent.ThreadLocalRandom: current() is a pure thread-local factory ----
    ("ThreadLocalRandom", "import java.util.concurrent.ThreadLocalRandom;", "ThreadLocalRandom r",
     [
        ("ThreadLocalRandom.current()",
         "returns the singleton; first call seeds thread state from an atomic counter (mixMurmur64), "
         "NOT from OS entropy/a CSPRNG"),
     ],
     [
        ("ThreadLocalRandom.current().nextInt()", "draws entropy"),
     ], "Rand"),

    # ---- java.util.random.RandomGenerator (Java 17+ root interface): isDeprecated is pure metadata ----
    # sweep [22]: the whole-owner Rand rule had NO carve-out for the interface's pure default methods.
    ("RandomGenerator", "import java.util.random.RandomGenerator;", "RandomGenerator g",
     [
        ("g.isDeprecated()", "a pure metadata DEFAULT method — reports whether the algorithm is deprecated, no entropy draw"),
     ],
     [
        ("g.nextInt()",      "draws entropy"),
        ("g.nextLong()",     "draws entropy"),
     ], "Rand"),

    # ---- java.util.zip.ZipFile: cached name/count vs reading the archive ----
    ("ZipFile", "import java.util.zip.ZipFile;", "ZipFile z",
     [
        ("z.getName()", "returns the cached archive path"),
        ("z.size()",    "returns the cached entry count (no archive re-read)"),
     ],
     [
        ("z.entries()", "reads the archive's central directory"),
     ], "Fs"),

    # ---- java.nio.channels.FileChannel: isOpen is a field read; position()/size() are syscalls (CTRL) ----
    ("FileChannel", "import java.nio.channels.FileChannel;", "FileChannel fc",
     [
        ("fc.isOpen()", "returns !closed (AbstractInterruptibleChannel field read)"),
     ],
     [
        # position() (no-arg getter) lseeks the fd; size() queries the file length — both are Fs I/O.
        ("fc.position()", "lseek(fd,-1) syscall to read the OS file pointer"),
        ("fc.size()",     "nd.size(fd) syscall to read the file length"),
        ("fc.read(java.nio.ByteBuffer.allocate(1))", "reads file bytes"),
     ], "Fs"),

    # ---- NIO socket channels: open/state/blocking flags + cached addresses + socket() adaptor ----
    ("SocketChannel", "import java.nio.channels.SocketChannel;", "SocketChannel sc",
     [
        ("sc.isOpen()",             "returns !closed (field read)"),
        ("sc.isConnected()",        "returns state==ST_CONNECTED (field read)"),
        ("sc.isConnectionPending()","returns state==ST_CONNECTIONPENDING (field read)"),
        ("sc.isBlocking()",         "returns !nonBlocking (field read)"),
        ("sc.getLocalAddress()",    "returns the cached local address field"),
        ("sc.getRemoteAddress()",   "returns the cached remote address field"),
        ("sc.socket()",             "lazily wraps the channel in a Socket adaptor object, no wire I/O"),
     ],
     [
        ("sc.read(java.nio.ByteBuffer.allocate(1))",  "reads from the wire"),
        ("sc.write(java.nio.ByteBuffer.allocate(1))", "writes to the wire"),
     ], "Net"),

    ("ServerSocketChannel", "import java.nio.channels.ServerSocketChannel;", "ServerSocketChannel ssc",
     [
        ("ssc.isOpen()",          "returns !closed (field read)"),
        ("ssc.isBlocking()",      "returns !nonBlocking (field read)"),
        ("ssc.getLocalAddress()", "returns the cached local address field"),
        ("ssc.socket()",          "lazily wraps the channel in a ServerSocket adaptor object"),
     ],
     [
        ("ssc.accept()", "blocks on / accepts an incoming connection"),
     ], "Net"),

    ("DatagramChannel", "import java.nio.channels.DatagramChannel;", "DatagramChannel dc",
     [
        ("dc.isOpen()",           "returns !closed (field read)"),
        ("dc.isConnected()",      "returns state==ST_CONNECTED (field read)"),
        ("dc.isBlocking()",       "returns !nonBlocking (field read)"),
        ("dc.getLocalAddress()",  "returns the cached local address field"),
        ("dc.getRemoteAddress()", "returns the cached remote address field"),
        ("dc.socket()",           "lazily wraps the channel in a DatagramSocket adaptor object"),
     ],
     [
        ("dc.receive(java.nio.ByteBuffer.allocate(1))", "receives a datagram from the wire"),
     ], "Net"),

    # ---- java.util.logging: the whole-PACKAGE Log gate would paint Log onto the package's pure value
    # and data types. Level is a pure value object; LogRecord is the DATA carrier (a Handler emits it,
    # the record does not); LogManager is the registry. Only Logger.log/info/... PRODUCE a record. ----
    ("JulLogging", "import java.util.logging.*;", "Logger lg, Level lv, LogRecord rec",
     [
        ("lv.intValue()",   "returns the level's int rank (field read), emits nothing"),
        ("lv.getName()",    "returns the level name string, emits nothing"),
        ("rec.getLevel()",  "reads the record's level field, emits nothing"),
        ("rec.getMessage()","reads the record's message field, emits nothing"),
        ("rec.getMillis()", "reads the record's timestamp field, emits nothing"),
        ("LogManager.getLogManager()", "returns the singleton registry, emits nothing"),
     ],
     [
        ("lg.info(\"x\")",  "PRODUCES a log record at INFO — the genuine emit verb"),
     ], "Log"),

    # ---- java.sql.ResultSet: a LIVE DB cursor. Cursor-movement verbs fetch rows (Db); the metadata/config
    # getters of the cursor object read cached fields and must stay pure (the round-10 ResultSet Db rule
    # must not paint the whole owner). getString-of-the-current-row is in-memory (classify leaves it pure). ----
    ("ResultSet", "import java.sql.ResultSet;", "ResultSet rs",
     [
        ("rs.getRow()",           "returns the current row NUMBER (cached counter), no fetch"),
        ("rs.getType()",          "returns the cursor TYPE constant (config), no fetch"),
        ("rs.getConcurrency()",   "returns the concurrency mode constant (config), no fetch"),
        ("rs.getFetchSize()",     "returns the fetch-size hint field, no fetch"),
        ("rs.getFetchDirection()","returns the fetch-direction field, no fetch"),
        ("rs.getString(1)",       "reads column 1 of the ALREADY-FETCHED current row (in-memory)"),
     ],
     [
        ("rs.next()",       "advances the cursor — fetches the next row (server round-trip)"),
        ("rs.refreshRow()", "re-reads the current row from the DB"),
     ], "Db"),

    # ---- java.sql.DatabaseMetaData: catalog QUERIES round-trip (Db); the capability flags / product-info
    # getters read cached handshake data and must stay pure (the round-10 catalog rule is verb-gated). ----
    ("DatabaseMetaData", "import java.sql.DatabaseMetaData;", "DatabaseMetaData md",
     [
        ("md.getDatabaseProductName()", "returns the product name cached at connect, no query"),
        ("md.getDriverName()",          "returns the driver name string, no query"),
        ("md.supportsTransactions()",   "returns a static capability flag, no query"),
        ("md.getMaxConnections()",      "returns a static capability number, no query"),
     ],
     [
        ("md.getTables(null,null,\"%\",null)", "runs a system-catalog SELECT (round-trip)"),
        ("md.getColumns(null,null,\"%\",\"%\")", "runs a system-catalog SELECT (round-trip)"),
     ], "Db"),

    # ---- java.net.MulticastSocket (extends DatagramSocket) — a receiver typed as the SUBCLASS emits
    # owner=MulticastSocket for the INHERITED pure accessors, which sailed past the Socket carve-out and got
    # fabricated Net by the whole-owner rule. (The 14-round-old cardinal sin, fixed in 0.5.28 — gated here.) ----
    ("MulticastSocket", "import java.net.*;", "MulticastSocket s, DatagramPacket p",
     [
        ("s.getPort()",        "cached remote-port field"),
        ("s.getLocalPort()",   "cached local-port field"),
        ("s.isClosed()",       "closed flag"),
        ("s.getTimeToLive()",  "cached TTL field, no wire"),
        ("s.getInterface()",   "cached multicast-interface field"),
     ],
     [
        ("s.send(p)", "transmits a datagram over the wire"),
     ], "Net"),

    # ---- javax.net.ssl.SSLSocket (extends Socket) — inherited Socket accessors PLUS its own pure handshake-
    # CONFIG surface (cipher/protocol/parameter get+set touch no wire). Only startHandshake / getOutputStream /
    # getInputStream / getSession do I/O. (Whole-owner Net fabricated on the config surface; fixed 0.5.28.) ----
    ("SSLSocket", "import javax.net.ssl.*;", "SSLSocket s",
     [
        ("s.getPort()",                  "cached port field"),
        ("s.getEnabledCipherSuites()",   "handshake config list, no wire"),
        ("s.getSupportedProtocols()",    "static capability list"),
        ("s.getUseClientMode()",         "config flag"),
        ("s.getSSLParameters()",         "config object"),
     ],
     [
        ("s.getOutputStream()", "opens the write side of the TLS connection"),
        ("s.startHandshake()",  "performs the TLS handshake over the wire"),
     ], "Net"),

    # ---- java.util.logging.SocketHandler — a network log handler: publish() transmits the record over the
    # socket (Net, an exfil channel), but the inherited config getters touch nothing. The logging-package gate
    # would swallow publish as `return null` without the resource-handler carve-out (fixed 0.5.27). ----
    ("JulSocketHandler", "import java.util.logging.*;", "SocketHandler h, LogRecord rec",
     [
        ("h.getLevel()",     "config getter, no I/O"),
        ("h.getFormatter()", "config getter, no I/O"),
        ("h.getFilter()",    "config getter, no I/O"),
     ],
     [
        ("h.publish(rec)", "transmits the record over the socket"),
     ], "Net"),

    # ---- java.util.logging.FileHandler — publish() writes the record to the log file (Fs); config getters
    # touch nothing. ----
    ("JulFileHandler", "import java.util.logging.*;", "FileHandler h, LogRecord rec",
     [
        ("h.getLevel()",    "config getter, no I/O"),
        ("h.getEncoding()", "config getter, no I/O"),
     ],
     [
        ("h.publish(rec)", "writes the record to the log file"),
     ], "Fs"),
]


def emit_fixture(case):
    """Return (java_source, {method_name: ('pure'|'ctrl', expect_effect, statement, rationale)})."""
    cid, imports, recv, pure, ctrl, eff = case
    lines = [f"// GENERATED by soundness/fabrication_probe.py — do not edit.", imports,
             f"public class {cid}Probe {{"]
    meta = {}
    for kind, calls in (("pure", pure), ("ctrl", ctrl)):
        for idx, (stmt, why) in enumerate(calls):
            name = f"{kind}{idx}"
            meta[f"{cid}Probe.{name}"] = (kind, eff, stmt, why)
            # The receiver is a PARAMETER, so no handle is ever opened/connected here — the only
            # classified call in the method body is the probe call itself.
            lines.append(f"    static void {name}({recv}) throws Exception {{ {stmt}; }}")
    lines.append("}")
    return "\n".join(lines) + "\n", meta


def run(launcher, case, workdir):
    cid = case[0]
    src, meta = emit_fixture(case)
    cdir = os.path.join(workdir, cid)
    clsdir = os.path.join(cdir, "cls")
    os.makedirs(clsdir, exist_ok=True)
    srcpath = os.path.join(cdir, f"{cid}Probe.java")
    with open(srcpath, "w") as f:
        f.write(src)
    jc = subprocess.run(["javac", "-d", clsdir, srcpath], capture_output=True, text=True)
    if jc.returncode != 0:
        return [f"GEN BUG {cid}: fixture does not compile:\n{jc.stderr.strip()}"], 0, 0
    outpath = os.path.join(cdir, "out.json")
    subprocess.run([launcher, clsdir, "--json", outpath], capture_output=True, text=True)
    if not os.path.exists(outpath):
        return [f"NO REPORT for {cid}"], 0, 0
    report = json.load(open(outpath))
    fns = report.get("functions", report) if isinstance(report, dict) else report
    inferred = {e["fn"]: e.get("inferred", []) for e in fns if isinstance(e, dict)}

    failures = []
    checked = 0
    for fn, (kind, eff, stmt, why) in sorted(meta.items()):
        inf = inferred.get(fn)  # None => omitted => candor judged it pure
        checked += 1
        if kind == "pure":
            if inf:  # any non-empty inferred set on a pure method is a fabrication
                failures.append(f"FABRICATION {fn} [{stmt}] -> {inf}  (provably pure: {why})")
        else:  # control
            if not inf or eff not in inf:
                got = inf if inf else "pure/omitted"
                failures.append(f"LOST CONTROL {fn} [{stmt}] -> {got}  (must report {eff})")
    return failures, checked, len(meta)


def main():
    launcher = os.environ.get("CJ")
    if not launcher:
        launcher = os.path.join(ROOT, "build", "install", "candor-java", "bin", "candor-java")
        if not os.path.exists(launcher):
            print("fabrication-probe: building candor-java…")
            gradle = os.path.join(ROOT, "gradlew")
            gradle = gradle if os.access(gradle, os.X_OK) else "gradle"
            b = subprocess.run([gradle, "-q", "installDist"], cwd=ROOT,
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("FAIL: candor-java did not build\n" + b.stderr)
                sys.exit(1)
    if not os.path.exists(launcher):
        print(f"FAIL: no launcher at {launcher}")
        sys.exit(1)

    all_failures = []
    total_checked = 0
    with tempfile.TemporaryDirectory() as work:
        for case in CASES:
            fails, checked, _ = run(launcher, case, work)
            total_checked += checked
            for f in fails:
                all_failures.append(f)

    print(f"fabrication-probe: {total_checked} probe methods checked across {len(CASES)} owner types")
    if all_failures:
        print(f"fabrication-probe: {len(all_failures)} FAILURE(S):")
        for f in all_failures:
            print("  " + f)
        sys.exit(1)
    print("fabrication-probe: OK — no fabrication, no lost control")


if __name__ == "__main__":
    main()
