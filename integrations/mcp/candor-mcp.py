#!/usr/bin/env python3
# candor-mcp.py (JVM) — a minimal MCP (Model Context Protocol) stdio server that exposes candor-java's
# INSTANT read-only queries as native agent tools, so an agent reaches for them reflexively in one tool
# call instead of grepping/reading source. The JVM sibling of candor's Rust MCP server — SAME tool names
# and shapes, so an agent uses a Rust project and a Java project identically (the cross-language point).
# No SDK: newline-delimited JSON-RPC 2.0 over stdio.
#
# Register (project-scoped) in your project's .mcp.json:
#   { "mcpServers": { "candor": { "type": "stdio", "command": "python3",
#       "args": ["/abs/path/to/candor-java/integrations/mcp/candor-mcp.py"] } } }
#
# Config via env (sensible Gradle defaults):
#   CANDOR_CLASSES  the dir/jar to analyse        (default: build/classes/java/main)
#   CANDOR_REPORT   where to cache the report     (default: .candor/report.json)
#   CANDOR_POLICY   policy file for whatif        (default: .candor/policy if present)
# The server (re)analyses only when the classes are newer than the cached report, then serves queries.
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.normpath(os.path.join(HERE, "..", "..", "candor"))  # the candor-java ./candor wrapper
CLASSES = os.environ.get("CANDOR_CLASSES", os.path.join("build", "classes", "java", "main"))
REPORT = os.environ.get("CANDOR_REPORT", os.path.join(".candor", "report.json"))

TOOLS = [
    {
        "name": "candor_effects",
        "description": "The effect set of a method (INSTANT, from candor's report). Use before editing to "
                       "see what it does to the outside world without reading its source. Returns its "
                       "transitive `inferred` effects and the `direct` ones it performs itself.",
        "inputSchema": {"type": "object",
                        "properties": {"function": {"type": "string", "description": "method name (substring of the fully-qualified name)"}},
                        "required": ["function"]},
    },
    {
        "name": "candor_where",
        "description": "Which methods perform a given effect (INSTANT), split into direct sources and the "
                       "methods that inherit it transitively. Faster than grepping. Effects: Net Fs Db Exec "
                       "Env Clock Ipc Log Rand Clipboard Unknown.",
        "inputSchema": {"type": "object",
                        "properties": {"effect": {"type": "string", "description": "an effect name, e.g. Net"}},
                        "required": ["effect"]},
    },
    {
        "name": "candor_callers",
        "description": "The blast radius of a method (INSTANT) — every method that TRANSITIVELY calls it, "
                       "i.e. who is affected if you change it. Works for ANY method, including a PURE one "
                       "you're about to make effectful. Use before changing behaviour/signature.",
        "inputSchema": {"type": "object",
                        "properties": {"function": {"type": "string", "description": "method name (substring)"}},
                        "required": ["function"]},
    },
    {
        "name": "candor_whatif",
        "description": "PRE-EDIT VERDICT (INSTANT): before you add a side effect to a method, ask what it "
                       "would do. Given a method and an effect you're about to introduce (e.g. a network "
                       "call), returns the blast radius (every transitive caller that would gain the effect) "
                       "AND — against the project's policy — which methods would VIOLATE a deny/pure "
                       "architecture boundary. Answers 'if I make this network call here, does it break the "
                       "architecture?' deterministically, WITHOUT writing code. Call before introducing "
                       "Net/Fs/Db/Exec/Env to a method instead of editing, running the gate, and reverting.",
        "inputSchema": {"type": "object",
                        "properties": {
                            "function": {"type": "string", "description": "the method you're about to add the effect to (name substring)"},
                            "effect": {"type": "string", "description": "the effect you'd introduce: Net Fs Db Exec Env Clock Ipc Log Rand Clipboard"}},
                        "required": ["function", "effect"]},
    },
]


def newest_class_mtime(path):
    newest = 0.0
    if os.path.isfile(path):
        return os.path.getmtime(path)
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".class"):
                newest = max(newest, os.path.getmtime(os.path.join(root, f)))
    return newest


def ensure_report():
    """(Re)analyse CLASSES into REPORT (+ its callgraph sidecar) when the report is missing or stale."""
    if not os.path.exists(CLASSES):
        return False
    stale = (not os.path.exists(REPORT)) or newest_class_mtime(CLASSES) > os.path.getmtime(REPORT)
    if stale:
        os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
        subprocess.run([WRAPPER, CLASSES, "--json", REPORT], capture_output=True, text=True, timeout=600)
    return os.path.exists(REPORT)


def run_query(args):
    if not ensure_report():
        return (f"candor: nothing to analyse at '{CLASSES}'. Build first (e.g. `gradle classes`), or set "
                f"CANDOR_CLASSES to your classes dir / jar.")
    try:
        r = subprocess.run([WRAPPER, *args], capture_output=True, text=True, timeout=300)
        return r.stdout.strip() or r.stderr.strip() or "(no output)"
    except Exception as e:  # noqa: BLE001 — surface any failure to the agent as text
        return f"candor: query failed ({e})"


def arg(args, key):
    """Required-arg getter. A missing/empty value is a clear error, not a silent whole-report query.
    A leading-dash value is rejected — it would be parsed as a FLAG by candor (argument injection)."""
    v = args.get(key, "")
    if not isinstance(v, str) or v == "":
        raise ValueError(f"missing required argument: {key}")
    if v.startswith("-"):
        raise ValueError(f"argument {key!r} may not start with '-'")
    return v


def dispatch(name, args):
    try:
        if name == "candor_effects":
            return run_query(["show", REPORT, arg(args, "function"), "--json"])
        if name == "candor_where":
            return run_query(["where", REPORT, arg(args, "effect"), "--json"])
        if name == "candor_callers":
            return run_query(["callers", REPORT, arg(args, "function"), "--json"])
        if name == "candor_whatif":
            q = ["whatif", REPORT, arg(args, "function"), arg(args, "effect")]
            pol = os.environ.get("CANDOR_POLICY") or (".candor/policy" if os.path.exists(".candor/policy") else None)
            if pol:
                q.append(pol)
            q.append("--json")
            return run_query(q)
    except ValueError as e:
        return f"candor: {e}"
    return None


def send(mid, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": mid}
    msg["error" if error is not None else "result"] = error if error is not None else result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        mid = req.get("id")
        method = req.get("method")
        if mid is None:
            continue  # a notification — no response
        if method == "initialize":
            send(mid, result={
                "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "candor-java", "version": "1.0.0"},
            })
        elif method == "tools/list":
            send(mid, result={"tools": TOOLS})
        elif method == "tools/call":
            params = req.get("params", {})
            text = dispatch(params.get("name"), params.get("arguments", {}))
            if text is None:
                send(mid, result={"content": [{"type": "text", "text": f"unknown tool: {params.get('name')}"}], "isError": True})
            else:
                send(mid, result={"content": [{"type": "text", "text": text}]})
        else:
            send(mid, error={"code": -32601, "message": "Method not found"})


if __name__ == "__main__":
    main()
