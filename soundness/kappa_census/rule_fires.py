#!/usr/bin/env python3
"""SOUNDNESS R508/R509 — the "does the rule still FIRE?" probe.

R508 is the structural limit: a kappa rule is keyed on owner+method and cannot say "this owner forks in
<=1.2 and does not in >=1.3", so one rule is necessarily wrong for some published version.  R509 is what
that cost, and it SHIPPED: R493's Exposed rules key on `org.jetbrains.exposed.sql.QueriesKt`, derived
from 0.52.0; Exposed 1.0.0 moved the library to `org.jetbrains.exposed.v1.jdbc.QueriesKt`.  Every
owner-equals missed, the block fell to `return null`, and `org.jetbrains` IS kappa-covered -- so that
null was a CERTIFIED PURITY CLAIM over a complete data layer.  `deny Db` exited 0.

The cheap signal is that the MATCH COUNT against the current jar goes to zero.  That is this instrument.

WHAT IT DELIBERATELY IS NOT.  The R508 sweep argued against making `kappa_census` read N jars per
prefix: it multiplies an exhaustive enumeration by N and answers a question no single user has -- a
phantom-finding generator.  This asks ONE question of ONE jar per library: are these rules still pointed
at code that exists?  One download per library, probe only, no census.

SCOPE is the kappa-COVERED prefixes and no further.  For a non-covered prefix (testcontainers,
net.bramp, commons-exec, zt-exec, im4java) a package rename floors the call to `invisible` and is
DISCLOSED -- loud, not silent.  Coverage is where a rename is a cardinal sin, and that is the only place
the download cost is justified.

    IN SCOPE  = a jar in soundness/lib whose members ALREADY match >=1 kappa rule.  That is the
                authority-derived spelling of "this prefix has owner rules in Classifier.java":
                a prefix with no rules has a baseline of 0 and is out of scope, so a pure-by-grant
                namespace (org.w3c.dom, org.apache.commons.validator) can never raise a phantom.
    ASSERTION = the LATEST published version of that same artifact still matches >=1 rule.

Usage:
    python3 soundness/kappa_census/rule_fires.py [--offline] [--jars DIR] [--only SUBSTR] [--check-coords]

    --offline       do not download; probe whatever is already in the latest-jars dir
    --jars DIR      where latest jars live (default soundness/kappa_census/latest_jars, gitignored --
                    NOT soundness/lib: two versions of one library on kappa_libs_probe's shared compile
                    classpath is the shared-instrument contamination CLAUDE.md warns about)
    --only SUBSTR   restrict to jars/coordinates containing SUBSTR (calibration + iteration)
    --check-coords  resolve every coordinate's maven-metadata and stop

Env: CJ_ALL (candor all-jar), PROBE (dir holding RuleFireProbe.class), JAVA (optional).

Exit 0 = every in-scope library still matches.  Exit 1 = at least one went to zero.  Exit 2 = the
instrument itself could not run (a coordinate would not resolve, a download failed).  A network failure
is NOT a pass: it is exit 2, because "0 matched" and "0 downloaded" print the same way otherwise.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.join(ROOT, "soundness", "kappa_census")
LIB = os.path.join(ROOT, "soundness", "lib")
CENTRAL = "https://repo1.maven.org/maven2"
UA = {"User-Agent": "candor-java/rule_fires (soundness probe)"}

# Adjudicated non-findings: a library whose latest version legitimately matches ZERO rules.  A DENYLIST,
# not a threshold -- every entry states what was measured, so a later rename cannot hide behind a vague
# allowance.  Keyed by "groupId:artifactId".
ADJUDICATED = {
    "org.jetbrains.exposed:exposed-core": (
        "Exposed 1.x SPLIT the module: exposed-core is the pure AST/DSL and the whole execution surface "
        "moved to exposed-jdbc / exposed-r2dbc.  MEASURED on 1.5.0 with javap: zero declarers of any "
        "`exec`/`execute` member across org/jetbrains/exposed/v1/core/Transaction, "
        "core/statements/*.class and core/statements/api/* -- the classes that carried them at 0.52.0.  "
        "The SIBLING artifact exposed-jdbc-1.5.0 matches 239 members, so the RULE SET is live; only this "
        "artifact is empty.  If exposed-jdbc ever goes to zero this entry does not cover it."
    ),
    "io.ktor:ktor-server-host-common-jvm": (
        "Ktor 3 folded host-common INTO ktor-server-core and left a compatibility STUB behind. "
        "MEASURED: ktor-server-host-common-jvm-3.6.0 holds exactly ONE class, "
        "io/ktor/server/host/common/StubKt, whose only member javap -c prints as `stub(); 0: return`. "
        "There is nothing in the artifact for any rule to match.  Of the five owners that matched at "
        "2.3.12, three moved to ktor-server-core-jvm-3.6.0 and still match there (ApplicationEngine, "
        "ApplicationEngineJvmKt, EmbeddedServerKt -- 34 members, up from 8, plus a new EmbeddedServer) "
        "and two (ApplicationEngineEnvironment, ApplicationEngineEnvironmentReloading) were DELETED "
        "with Ktor 3's reloading-environment API.  ktor-server-core-jvm is separately in scope at "
        "58 -> 115 matches, so the io.ktor rule set is live and gated."
    ),
}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def fetch(url, tries=3):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
        except Exception as e:  # noqa: BLE001 - network shapes vary; retried below
            last = e
        time.sleep(1 + i)
    raise RuntimeError(f"{url}: {last}")


PRE = re.compile(r"(?i)(alpha|beta|[-.]rc|[-.]m\d|[-.]cr\d|snapshot|preview|eap|dev\b|milestone)")


def _vkey(v):
    """Numeric-segment ordering, so 1.10 > 1.9 and a trailing qualifier sorts last."""
    return [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-_]", v)]


def latest_version(coord):
    """The latest NON-prerelease version on Central.  Prefers <release>; falls back to the last
    <version> that does not look like a pre-release.  Returns None if the coordinate does not exist."""
    g, a = coord.split(":")
    base = f"{CENTRAL}/{g.replace('.', '/')}/{a}"
    xml = fetch(f"{base}/maven-metadata.xml")
    if xml is None:
        # Pre-2010 uploads (javacsv, struts:struts) predate maven-metadata.xml on Central.  Fall back to
        # the directory listing, which is the same ground truth one level down.  Returning None here
        # instead would exit 2 -- correct as a refusal, but it would take a real library out of the gate.
        idx = fetch(base + "/")
        if idx is None:
            return None
        dirs = re.findall(r'<a href="([^"/]+)/"', idx.decode("utf-8", "replace"))
        cands = [d for d in dirs if d != ".." and not PRE.search(d)]
        return sorted(cands, key=_vkey)[-1] if cands else None
    s = xml.decode("utf-8", "replace")
    versions = re.findall(r"<version>([^<]+)</version>", s)
    rel = re.search(r"<release>([^<]+)</release>", s)
    if rel and not PRE.search(rel.group(1)):
        return rel.group(1)
    for v in reversed(versions):
        if not PRE.search(v):
            return v
    return versions[-1] if versions else None


def download(coord, ver, outdir):
    g, a = coord.split(":")
    name = f"{a}-{ver}.jar"
    dest = os.path.join(outdir, name)
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest
    b = fetch(f"{CENTRAL}/{g.replace('.', '/')}/{a}/{ver}/{name}")
    if b is None:
        return None
    os.makedirs(outdir, exist_ok=True)
    tmp = dest + ".part"
    with open(tmp, "wb") as f:
        f.write(b)
    os.replace(tmp, dest)
    return dest


def run_probe(jars, owners=False):
    """-> {jar basename: (coveredMembers, matched, distinctOwners)}"""
    if not jars:
        return {}
    cj = os.environ.get("CJ_ALL")
    pd = os.environ.get("PROBE")
    if not cj or not pd:
        log("rule_fires: set CJ_ALL (candor all-jar) and PROBE (dir with RuleFireProbe.class)")
        sys.exit(2)
    java = os.environ.get("JAVA", "java")
    cmd = [java, "-cp", pd + os.pathsep + cj, "io.poly.candor.RuleFireProbe"]
    if owners:
        cmd.append("--owners")
    out = subprocess.run(cmd + list(jars), capture_output=True, text=True)
    if out.returncode != 0:
        log("rule_fires: RuleFireProbe failed:", out.stderr[:2000])
        sys.exit(2)
    res = {}
    for line in out.stdout.splitlines():
        p = line.split("\t")
        if p[0] == "JAR":
            res[p[1]] = (int(p[2]), int(p[3]), int(p[4]))
        elif p[0] == "ERR":
            log("rule_fires: probe could not read", p[1], p[2])
            sys.exit(2)
    return res


def main():
    argv = sys.argv[1:]
    offline = "--offline" in argv
    check = "--check-coords" in argv
    jdir = os.path.join(HERE, "latest_jars")
    only = None
    for i, a in enumerate(argv):
        if a == "--jars":
            jdir = argv[i + 1]
        if a == "--only":
            only = argv[i + 1]

    coords = json.load(open(os.path.join(HERE, "probe_coords.json")))
    if only:
        coords = {k: v for k, v in coords.items() if only in k or only in v}

    # Baseline: what the PINNED jar matches today.  Re-measured every run rather than cached -- a rule
    # edit changes it, and a stale baseline would turn a rule DELETION into a silent pass.
    base_jars = [os.path.join(LIB, j) for j in sorted(coords) if os.path.exists(os.path.join(LIB, j))]
    missing_base = [j for j in sorted(coords) if not os.path.exists(os.path.join(LIB, j))]
    if missing_base:
        log("rule_fires: NOT IN soundness/lib (run soundness/kappa_census/README's fetch first):")
        for m in missing_base:
            log("   ", m)
        sys.exit(2)
    base = run_probe(base_jars)

    rows, hard = [], []
    for jar in sorted(coords):
        coord = coords[jar]
        pinned_ver = jar[len(coord.split(":")[1]) + 1: -len(".jar")]
        b_cov, b_match, _ = base[jar]
        if b_match == 0:
            # Not in scope: the rule set says nothing about this library at the pinned version either,
            # so a zero at the latest version is not a regression.  (The manifest is generated from a
            # baseline where every entry matched, so this only fires after a rule is deleted.)
            rows.append((jar, coord, pinned_ver, b_match, "-", 0, "OUT-OF-SCOPE (baseline 0)"))
            continue
        if check or not offline:
            try:
                lv = latest_version(coord)
            except RuntimeError as e:
                log("rule_fires: could not resolve", coord, "--", e)
                sys.exit(2)
            if lv is None:
                log("rule_fires: coordinate does not exist on Central:", coord, f"(from {jar})")
                sys.exit(2)
        else:
            # OFFLINE: no maven-metadata, so the "latest" is whatever the jars dir already holds for
            # this artifact.  Resolved here rather than left None — leaving it None made every offline
            # row print "offline: no jar", which is how the gate's own calibration arm first passed
            # while measuring nothing.
            art = coord.split(":")[1]
            have = [f for f in os.listdir(jdir) if f.startswith(art + "-") and f.endswith(".jar")
                    and re.fullmatch(r"[\d].*", f[len(art) + 1: -4] or "x")] if os.path.isdir(jdir) else []
            lv = sorted((f[len(art) + 1: -4] for f in have), key=_vkey)[-1] if have else None
        if check:
            rows.append((jar, coord, pinned_ver, b_match, lv, -1, "coords-only"))
            continue
        if lv == pinned_ver:
            rows.append((jar, coord, pinned_ver, b_match, lv, b_match, "SAME (pinned IS latest)"))
            continue
        path = None
        if offline:
            cand = os.path.join(jdir, f"{coord.split(':')[1]}-{lv}.jar") if lv else None
            path = cand if cand and os.path.exists(cand) else None
            if path is None:
                rows.append((jar, coord, pinned_ver, b_match, lv, -1, "offline: no jar"))
                continue
        else:
            path = download(coord, lv, jdir)
            if path is None:
                log("rule_fires: no jar artifact for", coord, lv, "-- a POM-only or classified release?")
                sys.exit(2)
        l_cov, l_match, _ = run_probe([path])[os.path.basename(path)]
        note = ""
        if l_match == 0:
            if coord in ADJUDICATED:
                note = "ZERO but ADJUDICATED"
            else:
                note = "*** ZERO MATCHES -- RULES NO LONGER FIRE ***"
                hard.append((jar, coord, pinned_ver, lv, b_match))
        rows.append((jar, coord, pinned_ver, b_match, lv, l_match, note))

    print(f"{'artifact':44} {'pinned':>14} {'base':>7} {'latest':>14} {'now':>7}  note")
    for jar, coord, pv, bm, lv, lm, note in rows:
        print(f"{coord:44} {pv:>14} {bm:>7} {str(lv):>14} "
              f"{('-' if lm < 0 else lm):>7}  {note}")
    print()
    print(f"in scope: {sum(1 for r in rows if r[3] > 0)}   "
          f"zero-at-latest: {len(hard)}   adjudicated: {sum(1 for r in rows if 'ADJUDICATED' in r[6])}")
    if check:
        print("\n--check-coords: coordinates resolved only. NOTHING WAS PROBED, so this is not a pass.")
        return 0
    if hard:
        print()
        print("FAIL -- a kappa-COVERED namespace has rules that match NOTHING in the current release.")
        print("Under coverage that is not a disclosure, it is a certified purity claim (SOUNDNESS R509).")
        for jar, coord, pv, lv, bm in hard:
            print(f"  {coord}: {bm} matches at {pv}, 0 at {lv}")
        return 1
    print("OK -- every in-scope rule set still matches a member of its library's current release.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
