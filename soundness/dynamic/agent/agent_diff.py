#!/usr/bin/env python3
"""Agent dynamic differential — the Exec/Db (non-Fs/Net) counterpart to jfr_diff.py.

JFR only emits jdk.{File,Socket}{Read,Write} events, so jfr_diff.py is BLIND to Exec and Db (and
Env/Clock/Rand). This tool fills that hole with a custom leaf-instrumenting Java agent
(build/candor-agent.jar): it runs the program under -javaagent, the agent rewrites application bytecode
to call EffectRecorder.record(effect) immediately before every genuine effect-LEAF call (the LEAF table
in EffectAgent.java — currently Exec + Db), capturing the ACTUAL effect with the live Java call stack.
Each observed (method, effect) is then diffed against candor's STATIC report: an effect observed on a
method whose static `inferred` lacks that effect AND lacks `Unknown` is a CONFIRMED model-gap
under-report — it really did it, candor missed it (and did not disclose Unknown).

`Unknown` in the static set is a PASS (candor honestly disclosed it could not resolve the path). THREE-WAY
verdict per (method, effect), mirroring candor-ts verify-core + the candor-swift realworld oracle: PRECISE
(effect in the non-Unknown claim), HELD BY DISCLOSURE (covered only by a disclosed Unknown — honest, and
BLAME-TRACKED to the fn's `unknownWhy` reason so the exact unresolved edge to resolve is named), or
UNDER-REPORT (neither = the cardinal sin). The three-way only splits the honest bucket — it never changes a
pass/fail verdict.

Usage:
    agent_diff.py --cp <classpath> --main <MainClass> --report <candor.json>
                  [--pkg <frame-prefix>] [--agent <candor-agent.jar>] [--args ...]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AGENT = os.path.join(HERE, "build", "candor-agent.jar")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp", required=True)
    ap.add_argument("--main", required=True)
    ap.add_argument("--report", required=True, help="candor --json report of the same classes")
    ap.add_argument("--pkg", default="", help="only attribute frames whose dotted owner starts with this")
    ap.add_argument("--agent", default=DEFAULT_AGENT, help="path to candor-agent.jar")
    ap.add_argument("--args", nargs=argparse.REMAINDER, default=[])
    a = ap.parse_args()

    if not os.path.exists(a.agent):
        print(f"agent-diff: FAIL — agent jar not found: {a.agent} (run build.sh)"); sys.exit(2)

    with tempfile.TemporaryDirectory() as work:
        obs_path = os.path.join(work, "agent-observed.json")
        cmd = ["java", f"-javaagent:{a.agent}", f"-Dcandor.agent.out={obs_path}",
               "-cp", a.cp, a.main] + a.args
        run = subprocess.run(cmd, capture_output=True, text=True)
        if run.returncode != 0:
            print("agent-diff: program exited non-zero; stderr tail:")
            print("\n".join(run.stderr.strip().splitlines()[-15:]))
        if not os.path.exists(obs_path):
            print("agent-diff: FAIL — no observed file produced (did the agent attach / program run?)")
            print("\n".join(run.stderr.strip().splitlines()[-15:]))
            sys.exit(2)
        observed_raw = json.load(open(obs_path))

    # Filter by --pkg prefix; observed keys are already "dotted.Class.method".
    observed = {}
    for k, effs in observed_raw.items():
        owner = k.rsplit(".", 1)[0]
        if a.pkg and not owner.startswith(a.pkg):
            continue
        observed[k] = set(effs)

    rep = json.load(open(a.report))
    static, why = {}, {}
    for f in rep["functions"]:
        k = f["fn"].split("(")[0]
        static.setdefault(k, set()).update(f.get("inferred", []))
        # Blame data: candor's `unknownWhy` reasons (dispatch:/reflect:/native:/callback:…) — the exact
        # unresolved edge(s) that would have to be resolved for a PRECISE claim (backlog P3).
        for w in (f.get("unknownWhy") or []):
            why.setdefault(k, set()).add(w)

    # THREE-WAY honesty verdict per (method, observed effect), mirroring candor-ts verify-core.mjs + the
    # candor-swift realworld oracle. This ONLY splits the honest bucket into PRECISE vs HELD-BY-DISCLOSURE
    # and names the blame reason — it does NOT change any pass/fail: `bugs` (the cardinal-sin violations) is
    # computed exactly as before (effect neither in the precise claim nor covered by a disclosed Unknown).
    #   (1) PRECISE            — eff ∈ (static ∖ {Unknown}): held tightly (CLEAN).
    #   (2) HELD BY DISCLOSURE — eff ∉ precise but Unknown ∈ static → honest, BLAME-TRACKED to unknownWhy.
    #   (3) UNDER-REPORT       — neither: a silent-pure that really ran = the cardinal sin.
    bugs, held = [], []
    for m in sorted(observed):
        si = static.get(m, set())
        precise = si - {"Unknown"}
        for eff in sorted(observed[m]):
            if eff in precise:
                continue
            if "Unknown" in si:
                held.append((m, eff, sorted(why.get(m, [])) or ["(no reason recorded)"]))
            else:
                bugs.append((m, eff, sorted(si)))

    print(f"agent-diff: {len(observed)} project method(s) observed effectful (after --pkg filter)")
    for m in sorted(observed):
        si = static.get(m, set())
        precise = si - {"Unknown"}
        blame = sorted(why.get(m, []))
        verdict = []
        for eff in sorted(observed[m]):
            if eff in precise:
                verdict.append(f"{eff}=PRECISE(static)")
            elif "Unknown" in si:
                # Held by a disclosed Unknown — honest, and blame-tracked to the reason(s).
                verdict.append(f"{eff}=HELD-BY-DISCLOSURE[{','.join(blame) or '(no reason)'}]")
            else:
                verdict.append(f"{eff}=UNDER-REPORT")
        print(f"  {m}: observed {sorted(observed[m])}; candor static {sorted(si) or 'PURE/absent'} -> "
              + ", ".join(verdict))

    print()
    for m, eff, blame in held:
        print(f"  HELD-BY-DISCLOSURE: {m} ran {eff}, covered by disclosed Unknown — blame: {blame}"
              f"  (resolve this edge -> precise {eff})")
    for m, eff, si in bugs:
        print(f"  UNDER-REPORT: {m} ran {eff}, candor static = {si or 'PURE/absent'}")
    if held:
        print(f"agent-diff: {len(held)} effect(s) HELD BY DISCLOSURE (honest via Unknown, blame-tracked — not"
              " a violation, a precision debt)")
    if bugs:
        print(f"agent-diff: {len(bugs)} candidate model-gap under-report(s) — VERIFY each "
              "(real path candor missed, not a fixture artifact)")
        sys.exit(1)
    print("agent-diff: CLEAN — every observed effect was statically predicted (precise or disclosed Unknown)")


if __name__ == "__main__":
    main()
