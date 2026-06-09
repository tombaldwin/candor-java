# candor-java MCP server

The JVM sibling of [candor's Rust MCP server](https://github.com/tombaldwin/candor/tree/main/integrations/mcp).
It exposes candor-java's **instant** read-only queries as native [MCP](https://modelcontextprotocol.io)
tools — with the **same tool names and shapes** as the Rust server, so an agent uses a Rust project and a
Java project *identically*. That cross-language sameness is the point: one set of reflexes, any language.

## Tools

| tool | what it answers | replaces |
|---|---|---|
| `candor_effects(function)` | a method's effect set (transitive + direct) | reading its source |
| `candor_where(effect)` | which methods perform an effect (sources vs inheritors) | grepping the codebase |
| `candor_callers(function)` | the **blast radius** — every transitive caller (who's affected if you change it) | tracing callers across files by hand |
| `candor_whatif(function, effect)` | **PRE-EDIT VERDICT** — if I add this effect here, what propagates *and* does it break the deny/pure policy? | edit → run the gate → revert |

`candor_whatif` is the one to reach for *before* introducing a side effect: it crosses the blast radius with
the architecture policy and returns the boundary violations deterministically, without writing code.

## Register

A self-contained Python script (no SDK). Project-scoped, add `.mcp.json` at your project root
(see `mcp.json.example`):

```json
{
  "mcpServers": {
    "candor": {
      "type": "stdio",
      "command": "python3",
      "args": ["/abs/path/to/candor-java/integrations/mcp/candor-mcp.py"]
    }
  }
}
```

## Config (env, with Gradle defaults)

| var | meaning | default |
|---|---|---|
| `CANDOR_CLASSES` | the dir/jar to analyse | `build/classes/java/main` |
| `CANDOR_REPORT` | where to cache the report | `.candor/report.json` |
| `CANDOR_POLICY` | policy file for `whatif` | `.candor/policy` if present |

The server (re)analyses only when the classes are newer than the cached report, then serves queries from
it. Build your classes first (`gradle classes`); the first query generates the report, the rest are instant.
