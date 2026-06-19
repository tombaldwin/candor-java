#!/usr/bin/env python3
"""kappa_probe.py — the DIRECT effect-leaf κ-coverage gate.

The fuzzer (gen.py) threads KNOWN effects UP call chains and the dynamic differential (dynamic/jfr_diff.py)
finds Fs/Net MODEL gaps at runtime — but neither systematically checks that candor's κ table CLASSIFIES the
common effectful JDK/library leaves in the FIRST place. A leaf candor doesn't know (e.g. `System.Logger.log`
before 0.7.7, or a whole NIO channel surface) makes EVERY method that calls it read silent-pure — the most
basic cardinal sin, invisible to the chain fuzzer (which only plants leaves candor already knows).

This probe closes that hole for ALL TEN effects (the dynamic differential only sees Fs/Net): it calls a
curated set of real effect leaves DIRECTLY, scans, and asserts each surfaces its expected effect (or a
disclosed `Unknown` — a PASS). It also pins a set of deliberately-PURE neighbours (e.g. `System.getProperty`,
`System.Logger.isLoggable`) so a future κ widening cannot over-classify them (the fabrication direction).

It is a developer + CI gate (deterministic, no runtime). EXTEND IT: every new κ entry / newly-supported JDK
API should gain a case here — that is how "keep sweeping" becomes durable. Found the System.Logger gap (0.7.7).

    CJ=build/install/candor-java/bin/candor-java python3 soundness/kappa_probe.py
"""
import json
import os
import subprocess
import sys
import tempfile

IMPORTS = ("import java.io.*; import java.nio.*; import java.nio.file.*; import java.nio.channels.*; "
           "import java.net.*; import java.util.*; import java.security.*; import java.time.*; "
           "import java.util.concurrent.*; import java.sql.*; import java.util.logging.*;")

# (method, expected effect, params, body) — PASS iff candor reports the effect OR a disclosed Unknown.
EFFECT_CASES = [
    # NIO file channels (the dynamic-differential's documented blind spot — confirmed classified)
    ("fileChannelRead", "Fs", "RandomAccessFile r", "r.getChannel().read(ByteBuffer.allocate(8))"),
    ("fileChannelWrite", "Fs", "FileChannel c", "c.write(ByteBuffer.allocate(8))"),
    ("byteChannel", "Fs", "Path p", "Files.newByteChannel(p).read(ByteBuffer.allocate(8))"),
    ("asyncFileChannel", "Fs", "Path p", "AsynchronousFileChannel.open(p).read(ByteBuffer.allocate(8),0)"),
    ("mapChannel", "Fs", "FileChannel c", "c.map(FileChannel.MapMode.READ_ONLY,0,8)"),
    # NIO socket channels
    ("socketChannel", "Net", "", "SocketChannel.open().connect(new InetSocketAddress(\"h\",80))"),
    ("socketChannelRead", "Net", "SocketChannel s", "s.read(ByteBuffer.allocate(8))"),
    ("serverChannel", "Net", "", "ServerSocketChannel.open().accept()"),
    ("datagramChannel", "Net", "", "DatagramChannel.open().receive(ByteBuffer.allocate(8))"),
    # Files.* surface
    ("filesReadAll", "Fs", "Path p", "Files.readAllBytes(p)"),
    ("filesLines", "Fs", "Path p", "Files.lines(p).count()"),
    ("filesWalk", "Fs", "Path p", "Files.walk(p).count()"),
    ("filesDirStream", "Fs", "Path p", "Files.newDirectoryStream(p).iterator()"),
    ("filesDelete", "Fs", "Path p", "Files.delete(p)"),
    ("filesCopy", "Fs", "Path a, Path b", "Files.copy(a,b)"),
    ("filesWrite", "Fs", "Path p", "Files.write(p, new byte[1])"),
    # classic Fs
    ("raf", "Fs", "RandomAccessFile r", "r.read()"),
    ("fos", "Fs", "", "new FileOutputStream(\"f\").write(1)"),
    ("fileWriter", "Fs", "", "new FileWriter(\"f\").write(\"x\")"),
    # Exec / Env
    ("procBuilder", "Exec", "", "new ProcessBuilder(\"ls\").start()"),
    ("runtimeExec", "Exec", "", "Runtime.getRuntime().exec(\"ls\")"),
    ("env", "Env", "", "System.getenv(\"PATH\")"),
    # Random / Clock
    ("secureRandom", "Rand", "", "byte[] b=new byte[8]; new SecureRandom().nextBytes(b)"),
    ("uuid", "Rand", "", "UUID.randomUUID()"),
    ("tlr", "Rand", "", "ThreadLocalRandom.current().nextInt()"),
    ("clockMs", "Clock", "", "long t=System.currentTimeMillis()"),
    ("instantNow", "Clock", "", "Instant.now()"),
    # Net classic + NIO variants
    ("urlOpenStream", "Net", "URL u", "u.openStream()"),
    ("urlConn", "Net", "URLConnection c", "c.getInputStream()"),
    ("datagramSend", "Net", "DatagramSocket s, DatagramPacket p", "s.send(p)"),
    ("inetGetByName", "Net", "", "InetAddress.getByName(\"h\")"),
    ("httpClient", "Net", "", "java.net.http.HttpClient.newHttpClient().send(null,null)"),
    # Db
    ("jdbcConnect", "Db", "", "DriverManager.getConnection(\"x\")"),
    ("stmtExecute", "Db", "Statement s", "s.execute(\"select 1\")"),
    ("prepExecute", "Db", "PreparedStatement p", "p.executeUpdate()"),
    ("resultNext", "Db", "ResultSet rs", "rs.next()"),
    # Log (incl. java.lang.System.Logger — the 0.7.7 fix)
    ("julLog", "Log", "Logger l", "l.info(\"x\")"),
    ("sysLogger", "Log", "System.Logger l", "l.log(System.Logger.Level.INFO, \"x\")"),
    # Clipboard
    ("clipboard", "Clipboard", "", "java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()"),
    # Exec — java.awt.Desktop launches the OS default handler (an external program)
    ("desktopBrowse", "Exec", "java.awt.Desktop d, java.net.URI u", "d.browse(u)"),
    ("desktopOpen", "Exec", "java.awt.Desktop d, java.io.File f", "d.open(f)"),
    # Fs — javax media readers that open a File (ImageIO already modeled; AudioSystem added 0.7.8)
    ("imageReadFile", "Fs", "java.io.File f", "javax.imageio.ImageIO.read(f)"),
    ("audioReadFile", "Fs", "java.io.File f", "javax.sound.sampled.AudioSystem.getAudioInputStream(f)"),
    # XML parse(File) → {Fs, Unknown}: reads the file (Fs) plus the XXE/external-entity disclosure (Unknown)
    ("xmlParseFile", "Fs", "javax.xml.parsers.DocumentBuilder b, java.io.File f", "b.parse(f)"),
]

# Deliberately-PURE neighbours — anti-over-classification anchors (a future κ widening must keep these pure).
PURE_CASES = [
    ("sysPropPure", "System.getProperty(\"user.home\")", ""),          # Env is OS-env/getenv only (spec §1)
    ("isLoggablePure", "boolean b=l.isLoggable(System.Logger.Level.INFO)", "System.Logger l"),
    ("loggerNamePure", "String n=l.getName()", "Logger l"),
    ("desktopGetPure", "java.awt.Desktop d=java.awt.Desktop.getDesktop()", ""),  # factory, not a launch
]


def build_fixture():
    lines = [IMPORTS, "public class K {"]
    for name, _eff, params, body in EFFECT_CASES:
        lines.append(f"  static void {name}({params}) throws Exception {{ {body}; }}")
    for name, body, params in PURE_CASES:
        lines.append(f"  static void {name}({params}) throws Exception {{ {body}; }}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main():
    launcher = os.environ.get("CJ")
    if not launcher or not os.path.exists(launcher):
        print("kappa-probe: FAIL — set CJ to the candor-java launcher"); sys.exit(2)
    with tempfile.TemporaryDirectory() as work:
        src = os.path.join(work, "K.java")
        with open(src, "w") as f:
            f.write(build_fixture())
        cls = os.path.join(work, "cls")
        os.makedirs(cls)
        jc = subprocess.run(["javac", "-d", cls, src], capture_output=True, text=True)
        if jc.returncode != 0:
            print("kappa-probe: GEN BUG — fixture does not compile:\n" + jc.stderr.strip()); sys.exit(2)
        out = os.path.join(work, "out.json")
        subprocess.run([launcher, cls, "--json", out], capture_output=True, text=True)
        if not os.path.exists(out):
            print("kappa-probe: FAIL — no report"); sys.exit(2)
        report = json.load(open(out))
        fns = report.get("functions", []) if isinstance(report, dict) else report
        inferred = {e["fn"].split("(")[0]: e.get("inferred", []) for e in fns if isinstance(e, dict)}

    gaps, fabs = [], []
    for name, eff, _p, body in EFFECT_CASES:
        got = inferred.get("K." + name, [])
        if eff not in got and "Unknown" not in got:
            gaps.append(f"  GAP  K.{name} [{body}] -> {got or 'pure/omitted'}  (must surface {eff} or Unknown)")
    for name, body, _p in PURE_CASES:
        got = inferred.get("K." + name, [])
        if got:
            fabs.append(f"  FABRICATION  K.{name} [{body}] -> {got}  (must stay pure)")

    n = len(EFFECT_CASES) + len(PURE_CASES)
    if gaps or fabs:
        print(f"kappa-probe: {len(gaps)} coverage gap(s), {len(fabs)} over-classification(s) of {n} leaves:")
        for g in gaps + fabs:
            print(g)
        sys.exit(1)
    print(f"kappa-probe: OK — {len(EFFECT_CASES)} effect leaves classified (Fs/Net/Db/Exec/Env/Rand/Clock/"
          f"Log/Clipboard incl. full NIO channel surface), {len(PURE_CASES)} pure neighbours unflooded")


if __name__ == "__main__":
    main()
