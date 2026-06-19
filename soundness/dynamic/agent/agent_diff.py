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

`Unknown` in the static set is a PASS (candor honestly disclosed it could not resolve the path).

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
    static = {}
    for f in rep["functions"]:
        static.setdefault(f["fn"].split("(")[0], set()).update(f.get("inferred", []))

    bugs = []
    for m in sorted(observed):
        si = static.get(m, set())
        for eff in sorted(observed[m]):
            if eff not in si and "Unknown" not in si:
                bugs.append((m, eff, sorted(si)))

    print(f"agent-diff: {len(observed)} project method(s) observed effectful (after --pkg filter)")
    for m in sorted(observed):
        si = static.get(m, set())
        verdict = []
        for eff in sorted(observed[m]):
            if eff in si:
                verdict.append(f"{eff}=CLEAN(static)")
            elif "Unknown" in si:
                verdict.append(f"{eff}=PASS(Unknown)")
            else:
                verdict.append(f"{eff}=UNDER-REPORT")
        print(f"  {m}: observed {sorted(observed[m])}; candor static {sorted(si) or 'PURE/absent'} -> "
              + ", ".join(verdict))

    print()
    for m, eff, si in bugs:
        print(f"  UNDER-REPORT: {m} ran {eff}, candor static = {si or 'PURE/absent'}")
    if bugs:
        print(f"agent-diff: {len(bugs)} candidate model-gap under-report(s) — VERIFY each "
              "(real path candor missed, not a fixture artifact)")
        sys.exit(1)
    print("agent-diff: CLEAN — every observed effect was statically predicted (effect or Unknown)")


if __name__ == "__main__":
    main()
