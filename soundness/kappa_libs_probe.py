#!/usr/bin/env python3
"""kappa_libs_probe.py — the DIRECT effect-leaf κ-coverage gate for THIRD-PARTY LIBRARIES.

Sibling of kappa_probe.py, which pins the JDK effect leaves. The JVM dogfood showed candor handles
APPLICATION code well (effects land in the right layer, low Unknown) but LIBRARIES are the risk surface:
candor's κ table is NAME-BASED (it matches the call-site owner type, e.g. `okhttp3.Call` or
`org.slf4j.Logger`), so a library leaf whose owner/verb candor doesn't enumerate makes EVERY caller of
it read silent-pure — the cardinal sin, and it hides inside the library, where reviewers rarely look.

This probe calls a curated set of REAL library effect leaves DIRECTLY (the methods an app actually calls:
slf4j Logger.info, ObjectMapper.readValue(File), FileUtils.readFileToString, OkHttpClient.newCall().execute(),
JdbcTemplate.query, DataSource.getConnection, …), compiles the fixture AGAINST the library jars, scans, and
asserts each surfaces its expected effect (or a disclosed `Unknown` — a PASS). A silent-pure is a GAP =
a real soundness finding (a library leaf worth modelling in κ).

κ is name-based, so the library BODIES are NOT needed for classification — candor matches the owner name
emitted in the call instruction; the jars are needed only to COMPILE the fixture (and to give javac the
right declared types so the call instruction carries the owner candor expects). CANDOR_DEPS is for chaining
sibling *reports* (cross-module), NOT for resolving library bytecode, so it is NOT set here. (Empirically
confirmed: the run with no CANDOR_DEPS classifies every modeled leaf — see the report.)

    CJ=build/libs/candor-java-0.7.7-all.jar python3 soundness/kappa_libs_probe.py
    # CJ may be a launcher script OR an -all.jar (auto-detected). LIBDIR defaults to soundness/lib.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LIBDIR = os.environ.get("LIBDIR", os.path.join(HERE, "lib"))

IMPORTS = (
    "import java.io.*; import java.nio.charset.*; import java.util.*; import javax.sql.*;"
    "import java.sql.*;"
    "import org.slf4j.*;"
    "import com.fasterxml.jackson.databind.*;"
    "import com.google.common.io.*;"
    "import org.apache.commons.io.*;"
    "import okhttp3.*;"
    "import org.springframework.jdbc.core.*;"
    "import org.springframework.web.client.*;"
)

# (method, expected effect, params, body) — PASS iff candor reports the effect OR a disclosed Unknown.
# Each body's TERMINAL call is the leaf under test; params supply a correctly-typed receiver so the call
# instruction carries the owner candor's κ keys on. Signatures verified against the downloaded versions.
EFFECT_CASES = [
    # ---- Log (slf4j) ----
    ("slf4jInfo",  "Log", "Logger l", 'l.info("x")'),
    ("slf4jWarn",  "Log", "Logger l", 'l.warn("x")'),
    ("slf4jError", "Log", "Logger l", 'l.error("x")'),
    ("slf4jGetLogger", "Log", "", 'Logger l = LoggerFactory.getLogger("x"); l.info("y")'),

    # ---- Fs/Net (jackson file/url (de)serialization — descriptor-gated κ, modeled 0.7.7) ----
    ("jacksonReadFile",  "Fs",  "ObjectMapper m, File f", 'Object o = m.readValue(f, String.class)'),
    ("jacksonWriteFile", "Fs",  "ObjectMapper m, File f", 'm.writeValue(f, "x")'),
    ("jacksonReadUrl",   "Net", "ObjectMapper m, java.net.URL u", 'Object o = m.readValue(u, String.class)'),

    # ---- Fs (commons-io FileUtils) ----
    ("commonsReadFile",  "Fs", "File f", 'String s = FileUtils.readFileToString(f, "UTF-8")'),
    ("commonsWriteFile", "Fs", "File f", 'FileUtils.writeStringToFile(f, "x", "UTF-8")'),
    ("commonsCopyFile",  "Fs", "File a, File b", 'FileUtils.copyFile(a, b)'),

    # ---- Fs (guava com.google.common.io.Files — eager verbs are modeled) ----
    ("guavaToByteArray", "Fs", "File f", 'byte[] b = Files.toByteArray(f)'),
    ("guavaWrite",       "Fs", "File f", 'Files.write(new byte[1], f)'),
    ("guavaReadLines",   "Fs", "File f", 'List<String> ls = Files.readLines(f, Charset.defaultCharset())'),
    # NOTE: guava's lazy source terminal `Files.asCharSource(f,..).read()` (owner CharSource.read) is an
    # ACCEPTED gap, NOT tested here: the receiver CharSource may be file-backed OR `CharSource.wrap("str")`
    # (in-memory), so candor cannot tell without the receiver's concrete type — the same ambiguous-receiver
    # class as the documented abstract-java.io.Reader boundary (dynamic/README "First real finding").
    # Modeling CharSource.read as Fs would FABRICATE on wrap()-backed sources; left disclosed-by-omission.

    # ---- Net (okhttp) ----
    ("okhttpExecute", "Net", "OkHttpClient c, Request r", 'Response resp = c.newCall(r).execute()'),
    ("okhttpCallExecute", "Net", "Call call", 'Response resp = call.execute()'),

    # ---- Net (spring RestTemplate) ----
    ("restGetForObject", "Net", "RestTemplate rt", 'Object o = rt.getForObject("http://h/", String.class)'),

    # ---- Db (spring JdbcTemplate) ----
    ("jdbcQuery",   "Db", "JdbcTemplate t",
        'List<?> r = t.queryForList("select 1")'),
    ("jdbcUpdate",  "Db", "JdbcTemplate t", 'int n = t.update("update t set x=1")'),
    ("jdbcExecute", "Db", "JdbcTemplate t", 't.execute("create table t(x int)")'),

    # ---- Db (javax.sql.DataSource — JDK type, modeled) ----
    ("dataSourceGetConn", "Db", "DataSource ds", 'java.sql.Connection c = ds.getConnection()'),
]

# Deliberately-PURE neighbours — anti-over-classification anchors (a future κ widening must keep these pure).
PURE_CASES = [
    # slf4j level CHECK reads no record (pure), unlike the emit verbs.
    ("slf4jIsEnabledPure", "boolean b = l.isInfoEnabled()", "Logger l"),
    # guava lazy FACTORY — returns a CharSource view, touches no file until a terminal read (documented in κ).
    ("guavaAsCharSourcePure", "CharSource cs = Files.asCharSource(f, Charset.defaultCharset())", "File f"),
    # ObjectMapper in-memory string (de)serialization touches no file/socket — must stay pure.
    ("jacksonReadStringPure", "Object o = m.readValue(\"{}\", Object.class)", "ObjectMapper m"),
    ("jacksonWriteStringPure", "String s = m.writeValueAsString(new Object())", "ObjectMapper m"),
]


# Library jars FETCHED ON DEMAND from Maven Central into LIBDIR (gitignored — 14 MB, not vendored).
# To test a new library: add its coordinate here and a case to EFFECT_CASES.
_MVN = "https://repo1.maven.org/maven2"
JARS = {
    "slf4j-api-2.0.13.jar": f"{_MVN}/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar",
    "jackson-databind-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/core/jackson-databind/2.17.1/jackson-databind-2.17.1.jar",
    "jackson-core-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/core/jackson-core/2.17.1/jackson-core-2.17.1.jar",
    "jackson-annotations-2.17.1.jar": f"{_MVN}/com/fasterxml/jackson/core/jackson-annotations/2.17.1/jackson-annotations-2.17.1.jar",
    "guava-33.2.1-jre.jar": f"{_MVN}/com/google/guava/guava/33.2.1-jre/guava-33.2.1-jre.jar",
    "okhttp-4.12.0.jar": f"{_MVN}/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar",
    "okio-jvm-3.9.0.jar": f"{_MVN}/com/squareup/okio/okio-jvm/3.9.0/okio-jvm-3.9.0.jar",
    "kotlin-stdlib-1.9.24.jar": f"{_MVN}/org/jetbrains/kotlin/kotlin-stdlib/1.9.24/kotlin-stdlib-1.9.24.jar",
    "commons-io-2.16.1.jar": f"{_MVN}/commons-io/commons-io/2.16.1/commons-io-2.16.1.jar",
    "spring-jdbc-6.1.10.jar": f"{_MVN}/org/springframework/spring-jdbc/6.1.10/spring-jdbc-6.1.10.jar",
    "spring-core-6.1.10.jar": f"{_MVN}/org/springframework/spring-core/6.1.10/spring-core-6.1.10.jar",
    "spring-beans-6.1.10.jar": f"{_MVN}/org/springframework/spring-beans/6.1.10/spring-beans-6.1.10.jar",
    "spring-tx-6.1.10.jar": f"{_MVN}/org/springframework/spring-tx/6.1.10/spring-tx-6.1.10.jar",
    "spring-web-6.1.10.jar": f"{_MVN}/org/springframework/spring-web/6.1.10/spring-web-6.1.10.jar",
}


def classpath():
    os.makedirs(LIBDIR, exist_ok=True)
    missing = [(n, u) for n, u in JARS.items() if not os.path.exists(os.path.join(LIBDIR, n))]
    if missing:
        print(f"kappa-libs: fetching {len(missing)} jar(s) into {LIBDIR} …")
        for name, url in missing:
            dest = os.path.join(LIBDIR, name)
            r = subprocess.run(["curl", "-fsSL", "-o", dest, url])
            if r.returncode != 0 or not os.path.exists(dest):
                print(f"kappa-libs: FAIL — could not fetch {url}", file=sys.stderr); sys.exit(2)
    jars = sorted(glob.glob(os.path.join(LIBDIR, "*.jar")))
    if not jars:
        print(f"kappa-libs: FAIL — no jars in {LIBDIR}", file=sys.stderr); sys.exit(2)
    return os.pathsep.join(jars), jars


def build_fixture():
    lines = [IMPORTS, "public class KL {"]
    for name, _eff, params, body in EFFECT_CASES:
        lines.append(f"  static void {name}({params}) throws Exception {{ {body}; }}")
    for name, body, params in PURE_CASES:
        lines.append(f"  static void {name}({params}) throws Exception {{ {body}; }}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def candor_cmd(launcher, cls, out):
    """CJ may be an -all.jar (run via `java -jar`) or an executable launcher script."""
    if launcher.endswith(".jar"):
        return ["java", "-jar", launcher, cls, "--json", out]
    return [launcher, cls, "--json", out]


def main():
    launcher = os.environ.get("CJ")
    if not launcher:
        # default to the newest -all.jar in build/libs
        cands = sorted(glob.glob(os.path.join(HERE, "..", "build", "libs", "candor-java-*-all.jar")))
        launcher = cands[-1] if cands else None
    if not launcher or not os.path.exists(launcher):
        print("kappa-libs: FAIL — set CJ to the candor-java launcher or -all.jar"); sys.exit(2)

    cp, jars = classpath()
    with tempfile.TemporaryDirectory() as work:
        src = os.path.join(work, "KL.java")
        with open(src, "w") as f:
            f.write(build_fixture())
        cls = os.path.join(work, "cls")
        os.makedirs(cls)
        jc = subprocess.run(["javac", "-cp", cp, "-d", cls, src], capture_output=True, text=True)
        if jc.returncode != 0:
            print("kappa-libs: GEN BUG — fixture does not compile:\n" + jc.stderr.strip()); sys.exit(2)
        out = os.path.join(work, "out.json")
        # NB: no CANDOR_DEPS — κ is name-based; the jars were only needed to compile. The classes dir is
        # scanned alone; candor classifies cross-jar calls from the owner name in the bytecode.
        r = subprocess.run(candor_cmd(launcher, cls, out), capture_output=True, text=True)
        if not os.path.exists(out):
            print("kappa-libs: FAIL — no report\n" + r.stderr.strip()); sys.exit(2)
        report = json.load(open(out))
        fns = report.get("functions", []) if isinstance(report, dict) else report
        inferred = {e["fn"].split("(")[0]: e.get("inferred", []) for e in fns if isinstance(e, dict)}

    rows, gaps, fabs = [], [], []
    for name, eff, _p, body in EFFECT_CASES:
        got = inferred.get("KL." + name, [])
        ok = eff in got or "Unknown" in got
        verdict = f"ok({eff})" if eff in got else ("ok(Unknown)" if "Unknown" in got else "GAP")
        rows.append((name, eff, got or [], verdict))
        if not ok:
            gaps.append(f"  GAP  KL.{name} [{body}] -> {got or 'pure/omitted'}  (must surface {eff} or Unknown)")
    for name, body, _p in PURE_CASES:
        got = inferred.get("KL." + name, [])
        rows.append((name, "(pure)", got or [], "ok(pure)" if not got else "FABRICATION"))
        if got:
            fabs.append(f"  FABRICATION  KL.{name} [{body}] -> {got}  (must stay pure)")

    w = max(len(r[0]) for r in rows)
    print(f"{'leaf'.ljust(w)}  {'expect':8}  {'candor':22}  verdict")
    print("-" * (w + 40))
    for name, eff, got, verdict in rows:
        print(f"{name.ljust(w)}  {eff:8}  {str(got)[:22]:22}  {verdict}")

    n = len(EFFECT_CASES) + len(PURE_CASES)
    if gaps or fabs:
        print(f"\nkappa-libs: {len(gaps)} coverage gap(s), {len(fabs)} over-classification(s) of {n} library leaves:")
        for g in gaps + fabs:
            print(g)
        sys.exit(1)
    print(f"\nkappa-libs: OK — {len(EFFECT_CASES)} library effect leaves classified "
          f"(slf4j/jackson/commons-io/guava/okhttp/spring), {len(PURE_CASES)} pure neighbours unflooded")


if __name__ == "__main__":
    main()
