#!/usr/bin/env python3
"""weaker_claim_census.py — find members κ classifies to a WEAKER effect than their body performs.

SOUNDNESS R494. The inverse of `census.py`, and it exists because the family had NO instrument for this
direction at all.

    census.py            κ says NULL           -> is the namespace grant certifying an unmodelled member?
    weaker_claim_census  κ says X, body does Y -> is a PRESENT answer WRONG in the dangerous direction?

**Why this direction is the worst case, and why nothing caught it.** An ABSENT member floors to
`invisible` and discloses itself (outside a covered prefix). An OVER-charge is loud and the A/B's ADDED
column catches it. But a member classified to a weaker-but-plausible effect emits a positive, confident
answer that satisfies every disclosure channel the engine has — no `invisible`, no advisory, no `Unknown`.
Nothing to notice.

R494 is the measured instance: `software.amazon.awssdk.auth.credentials.ProcessCredentialsProvider` was
charged `Env` — entirely plausible for a credentials provider — while `resolveCredentials()` calls
`executeCommand()`, which does `new ProcessBuilder(List).start()`. The provider whose whole purpose is
running an external credential helper (`aws-vault`, SSO helpers) forked a process under a **passing
`deny Exec`**.

**`inferred`, NOT `direct` — the opposite choice from census.py, deliberately.** census.py reads `direct`
because an `Unknown` in a library body means "I cannot see in", not a capability claim. Here the whole
point is REACH: `resolveCredentials` performs no syscall itself, it CALLS the method that does. Reading
`direct` would miss every instance of this class. The cost is the higher-order smear, which is why the
output is ranked and meant to be read, not thresholded.

**Every hit is a CANDIDATE.** Two false-positive modes, both real:
  1. The body scan is candor scanning the library with the SAME classifier, so a body effect can itself be
     a mis-classification. Confirm with `javap -c`, never from this output.
  2. κ is name-based and deliberately models the CALL SITE contract, which can legitimately be narrower
     than some internal path (a lazy init, a debug-only branch). A hit is a question, not a verdict.

Usage — the report is a candor scan OF THE LIBRARY JAR, same as census.py:

    CJ_ALL=build/libs/candor-java-<v>-all.jar PROBE=<dir with KappaQuery.class> \
      python3 soundness/kappa_census/weaker_claim_census.py <report.json> [prefix,prefix,…]

Omit the prefix list to sweep every owner in the report rather than only covered namespaces — this class
is NOT confined to covered prefixes, which is the difference from census.py that matters most.
"""
import json, subprocess, sys, os, collections

CONCRETE = ["Exec", "Net", "Fs", "Db", "Env", "Proc", "Llm", "Clipboard"]
# Ranked by what a passing gate over it would certify away. Exec first: it is arbitrary code.
SEVERITY = {e: i for i, e in enumerate(CONCRETE)}

report = sys.argv[1]
prefixes = sys.argv[2].split(",") if len(sys.argv) > 2 and sys.argv[2] else None
CJ = os.environ["CJ_ALL"]; PROBE = os.environ["PROBE"]

d = json.load(open(report))
rows = []
for f in d.get("functions", []):
    # inferred, not direct -- see the module docstring; the caller performs it THROUGH a callee.
    body = set(f.get("inferred") or []) & set(CONCRETE)
    if not body:
        continue
    h = f.get("hash") or ""
    if "(" not in h:
        continue
    sig, desc = h.split("(", 1); desc = "(" + desc
    owner, method = sig.rsplit(".", 1); owner = owner.replace("/", ".")
    if prefixes and not any(owner == p or owner.startswith(p + ".") for p in prefixes):
        continue
    rows.append((owner, method, desc, tuple(sorted(body))))

uniq = sorted(set(rows))
inp = "\n".join(f"{o}\t{m}\t{de}" for o, m, de, _ in uniq)
out = subprocess.run(["java", "-cp", PROBE + ":" + CJ, "io.poly.candor.KappaQuery"],
                     input=inp, capture_output=True, text=True).stdout.splitlines()
kappa = {tuple(l.split("\t")[:3]): l.split("\t")[3] for l in out}

# The finding: kappa gave a CONCRETE answer, and the body reaches a concrete effect kappa did not name.
# `k` is the SPEC name ("Env"), so `body - {k}` really removes it -- KappaQuery prints `Effect.specName()`
# for this subtraction's sake. It printed the ENUM CONSTANT ("ENV") until SOUNDNESS R496, and that made
# this loop unable to return a negative: every classified member with any concrete reach was a "hit", and
# every hit listed kappa's own answer under `missing`. The four R496 candidates were real, but they
# arrived inside a report that could not have said otherwise -- the oracle-calibration rule, in the
# instrument written for it.
hits = []
for o, m, de, body in uniq:
    k = kappa.get((o, m, de), "NULL")
    if k == "NULL" or k.startswith("ERR:"):
        continue            # absence is census.py's question, not this one
    missing = set(body) - {k}
    if missing:
        hits.append((o, m, de, k, tuple(sorted(missing, key=lambda e: SEVERITY.get(e, 99)))))

print(f"== {os.path.basename(report)}  members-with-reach={len(uniq)}  kappa-classified="
      f"{sum(1 for r in uniq if kappa.get(tuple(r[:3]), 'NULL') not in ('NULL',))}  WEAKER-CLAIM={len(hits)}")
if not hits:
    print("  none — every classified member's answer covers what its body reaches")
    raise SystemExit(0)

byowner = collections.defaultdict(list)
for o, m, de, k, missing in hits:
    byowner[o].append((m, k, missing))
# worst first: the most severe missing effect, then the count
def rank(owner):
    ms = byowner[owner]
    worst = min(SEVERITY.get(e, 99) for _, _, miss in ms for e in miss)
    return (worst, -len(ms))
for o in sorted(byowner, key=rank):
    ms = byowner[o]
    miss_all = sorted({e for _, _, miss in ms for e in miss}, key=lambda e: SEVERITY.get(e, 99))
    print(f"  {len(ms):4d} {o}   kappa says {sorted({k for _, k, _ in ms})} -- body ALSO reaches {miss_all}")
    for m, k, miss in sorted(ms)[:12]:
        print(f"        {m}  kappa={k}  missing={list(miss)}")
    if len(ms) > 12:
        print(f"        … {len(ms)-12} more")
print("\n  EVERY LINE IS A CANDIDATE. Confirm with `javap -c` before calling any of it a finding —")
print("  see the two declared false-positive modes in this file's docstring.")
