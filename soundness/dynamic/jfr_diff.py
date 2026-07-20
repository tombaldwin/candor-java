#!/usr/bin/env python3
"""Dynamic differential — the REAL-WORLD soundness oracle for candor-java.

Static fixtures and the fuzzer can only plant effect leaves candor ALREADY knows, so they cannot find
MODEL gaps — an effect that actually happens at runtime through a path candor does not connect (an
effect leaf hidden behind an abstract JDK type, an unmodelled library call, a wrapper chain). This tool
closes that hole with a true oracle: it RUNS a real program under JDK Flight Recorder, which records
actual File/Socket I/O events WITH STACK TRACES, maps each event's project stack frames to the effect
the event represents, and diffs the observed per-method effects against candor's STATIC report. Any
method observed performing an effect that candor's report does not predict (no effect, no `Unknown`) is a
CONFIRMED soundness under-report — it really did it, candor missed it.

Coverage: jdk.{File,Socket}{Read,Write} → Fs/Net. This covers java.io AND NIO reads that flow through a
java.io stream wrapper (BufferedInputStream over a channel — the common case). It does NOT see pure-NIO
channel I/O with no java.io wrapper, Exec, or Env; for full coverage a custom leaf-instrumenting agent is
the next step. JFR is the zero-setup 80%.

METHODOLOGY GOTCHAS (each one a real false-positive source, handled here):
  * CLASS-LOAD NOISE — the JVM reads the program's own jar/class files; those FileRead events carry the
    triggering app frames, falsely attributing Fs to whatever was loading a class. FILTER: drop events
    whose path is a .jar/.class/JDK-runtime file; keep only genuine DATA files.
  * STACK TRUNCATION — `jfr print` truncates the stack unless `--stack-depth` is large; deep project
    frames (below the JDK I/O frames) get cut. Use a generous depth.
  * `Unknown` IS A PASS — candor disclosing `Unknown` is sound (honestly unresolvable); only a silent
    effect-free report on an observed-effectful method is a bug. THREE-WAY (mirrors candor-ts verify-core
    + candor-swift realworld oracle): an observed effect is PRECISE (in the non-Unknown claim), HELD BY
    DISCLOSURE (covered only by a disclosed Unknown — honest, and blame-tracked to the fn's `unknownWhy`
    reason so the exact unresolved edge to fix is named), or an UNDER-REPORT (neither = the cardinal sin).

Usage:
    jfr_diff.py --cp <classpath> --main <MainClass> --report <candor.json> [--pkg <frame-prefix>]
                [--data-suffix .html,.txt,...]    # extra data-file suffixes to KEEP (besides auto-detect)
  e.g.  jfr_diff.py --cp "drv:lib.jar" --main Drv --report lib.candor.json --pkg org.jsoup
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

EV2EFF = {"jdk.FileWrite": "Fs", "jdk.FileRead": "Fs", "jdk.SocketWrite": "Net", "jdk.SocketRead": "Net"}
HERE = os.path.dirname(os.path.abspath(__file__))

# A read/write of one of these is class-loading / runtime noise, not the program's data I/O.
# `.jfr` is critical: JFR writes its OWN recording file while the program runs, and those FileWrite
# events carry whatever app method happened to be executing — pure noise that fabricates effects.
CLASSLOAD_SUFFIXES = (".jar", ".class", ".jmod", ".so", ".dylib", ".jfr")
RUNTIME_DIRS = ("/modules", "lib/jrt", "/jdk", "/jmods", "/conf/")
# OS/JDK config files read by internals during legit ops (e.g. socket connect reads /etc/hosts,
# /etc/resolv.conf for name resolution) — real reads, but not the PROGRAM's data I/O. Excluding them
# avoids fabricating Fs on networking methods. (A program that genuinely reads /etc data is rare; for
# those, pass an explicit --data-suffix to whitelist its files.)
SYSTEM_PREFIXES = ("/etc", "/private/etc", "/proc", "/sys", "/dev", "/usr/", "/System/", "/Library/")

def is_data_path(path, keep_suffixes):
    if not path:
        return False  # socket events have no path; handled separately by the caller
    p = path.lower()
    if any(p.endswith(s) for s in CLASSLOAD_SUFFIXES):
        return False
    if any(d in path for d in RUNTIME_DIRS):
        return False
    if any(path.startswith(d) for d in SYSTEM_PREFIXES):
        return False
    if keep_suffixes and not any(p.endswith(s) for s in keep_suffixes):
        return False
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp", required=True)
    ap.add_argument("--main", required=True)
    ap.add_argument("--report", required=True, help="candor --json report of the same classes")
    ap.add_argument("--pkg", default="", help="only attribute frames whose owner type starts with this")
    ap.add_argument("--data-suffix", default="", help="comma-sep file suffixes to KEEP (besides socket I/O)")
    ap.add_argument("--args", nargs=argparse.REMAINDER, default=[])
    a = ap.parse_args()
    keep = tuple(s.strip().lower() for s in a.data_suffix.split(",") if s.strip())

    with tempfile.TemporaryDirectory() as work:
        jfr = os.path.join(work, "rec.jfr")
        cmd = ["java", f"-XX:StartFlightRecording=filename={jfr},settings={HERE}/io.jfc",
               "-cp", a.cp, a.main] + a.args
        subprocess.run(cmd, capture_output=True, text=True)
        if not os.path.exists(jfr):
            print("jfr-diff: FAIL — no recording produced (did the program run?)"); sys.exit(2)
        pr = subprocess.run(["jfr", "print", "--json", "--stack-depth", "128",
                             "--events", ",".join(EV2EFF), jfr], capture_output=True, text=True)
        ev = json.loads(pr.stdout)
        events = ev.get("recording", {}).get("events") or ev.get("events") or ev

    observed, n_io = {}, 0
    for e in events:
        eff = EV2EFF.get(e.get("type") or "")
        if not eff:
            continue
        v = e.get("values", {}) or e
        is_socket = eff == "Net"
        if not is_socket and not is_data_path(v.get("path", ""), keep):
            continue  # class-load / runtime-file noise
        n_io += 1
        for fr in (v.get("stackTrace", {}) or {}).get("frames", []):
            m = fr.get("method", {})
            t = (m.get("type", {}) or {}).get("name", "").replace("/", ".")
            # The runtime lambda/proxy bridge class (`Foo$$Lambda.0x…`) is not a source method — candor
            # names the body `Foo.lambda$…`, which is ALSO on the stack. Skip the synthetic bridge frame.
            if "$$Lambda" in t or "$$" in t:
                continue
            if a.pkg and not t.startswith(a.pkg):
                continue
            observed.setdefault(f"{t}.{m.get('name','')}", set()).add(eff)

    rep = json.load(open(a.report))
    static, why = {}, {}
    for f in rep["functions"]:
        k = f["fn"].split("(")[0]
        static.setdefault(k, set()).update(f.get("inferred", []))
        # The blame data: the `unknownWhy` reasons candor emitted (dispatch:/reflect:/native:/callback:…) —
        # the exact unresolved edge(s) that would have to be resolved for a PRECISE claim (backlog P3).
        for w in (f.get("unknownWhy") or []):
            why.setdefault(k, set()).add(w)

    # THREE-WAY honesty verdict per (method, observed effect), mirroring candor-ts verify-core.mjs and the
    # candor-swift realworld oracle. `Unknown` is a PASS either way (honest disclosure) — this ONLY splits
    # the honest bucket, never changes a pass/fail: `bugs` (the cardinal-sin violations) is computed exactly
    # as before (observed effect neither in the PRECISE claim nor covered by a disclosed Unknown).
    #   (1) PRECISE           — eff ∈ (static ∖ {Unknown}): held tightly.
    #   (2) HELD BY DISCLOSURE — eff ∉ precise but Unknown ∈ static → honest, BLAME-TRACKED to unknownWhy.
    #   (3) UNDER-REPORT       — neither: a silent-pure that really ran = the cardinal sin.
    bugs, held = [], []
    for m in sorted(observed):
        si = static.get(m, set())
        precise = si - {"Unknown"}
        for eff in sorted(observed[m]):
            if eff in precise:
                continue  # precise — held tightly
            if "Unknown" in si:
                held.append((m, eff, sorted(why.get(m, [])) or ["(no reason recorded)"]))
            else:
                bugs.append((m, eff, sorted(si)))

    print(f"jfr-diff: {n_io} data I/O event(s); {len(observed)} project method(s) observed effectful")
    for m, eff, blame in held:
        # Honest (Unknown disclosed), not a precise claim — name the unresolved edge to resolve for precision.
        print(f"  HELD-BY-DISCLOSURE: {m} ran {eff}, covered by disclosed Unknown — blame: {blame}"
              f"  (resolve this edge -> precise {eff})")
    for m, eff, si in bugs:
        print(f"  UNDER-REPORT: {m} ran {eff}, candor static = {si or 'PURE/absent'}")
    if held:
        print(f"jfr-diff: {len(held)} effect(s) HELD BY DISCLOSURE (honest via Unknown, blame-tracked — not a"
              " violation, a precision debt)")
    if bugs:
        print(f"jfr-diff: {len(bugs)} candidate soundness under-report(s) — VERIFY each (rule out wrapper/"
              "abstract-type κ-boundary vs a structural drop)")
        sys.exit(1)
    print("jfr-diff: CLEAN — every observed effect was statically predicted (precise or disclosed Unknown)")

if __name__ == "__main__":
    main()
