<p align="center">
  <img src="assets/logo.png" alt="IDA Headless MCP" width="280"/>
</p>

<h1 align="center">IDA Headless MCP</h1>

<p align="center">
  <strong>65 tools. Non-blocking. The greatest binary analysis MCP server of All Time.</strong>
</p>

---

## What is this

Alright so basically every IDA MCP server that exists right now is dogwater. You call decompile, the server freezes for 30 seconds, your agent just sits there staring at the ceiling like it's having an existential crisis. You can't do anything. One agent per binary. It's like using a payphone in 2026.

This one doesn't do that. Every single tool either gives you the answer immediately from cache or tells you exactly what's happening: "worker is bootstrapping IDA, give me 10 seconds." Then it processes in the background while you go do other things. Ten agents can hammer the same binary simultaneously and nobody blocks anyone. It's genuinely the most non-blocking thing I've ever seen in binary analysis.

65 tools. SMT-backed proofs. Interprocedural taint. CAPA rules. YARA generation. All running through IDA Pro 9.0's idalib with zero plugins required. This is easily the most impressive MCP server in the binary analysis space right now and it's not even close.

## Quick Start

```bash
git clone https://github.com/echel0nn/ida-headless-mcp-exp
cd ida-headless-mcp-exp
pip install -e .

# Optional: build the SMT solver for proof tools
cd tools/binbit-src && cargo build --release && cd ../..
cp tools/binbit-src/target/release/binbit.exe tools/binbit.exe
```

Throw this in your MCP config:

```json
{
  "ida-headless-mcp": {
    "command": "python",
    "args": ["-m", "ida_headless_mcp.server"],
    "env": {
      "PYTHONPATH": "/path/to/ida-headless-mcp-exp/src",
      "IDA_HEADLESS_MCP_IDA_DIR": "C:/Program Files/IDA Professional 9.0",
      "IDA_HEADLESS_MCP_CACHE_DIR": "/path/to/ida-headless-mcp-exp/cache"
    }
  }
}
```

You need IDA Pro 9.0 with idalib and a Hex-Rays decompiler license. If you don't have that, this isn't for you. Sorry.

## Why this is insane

Let me give you the highlight reel because this thing is genuinely cracked.

**Prove an integer overflow is exploitable. In 4 milliseconds.**

```
open_binary("target.exe")
search_pattern(binary_id, "integer_overflow")
assess_exploitability(binary_id, func, "memmove", 2)
prove_overflow(binary_id, func, "memmove", 2)
# -> SAT. Witness: v10=0x40000000, v21=4. Overflow confirmed. 4ms.
```

That's not a heuristic. That's not a "maybe." That's a mathematical proof with a concrete witness value that triggers the bug. In four milliseconds. Other tools time out at 30 seconds on the same function and come back with nothing.

**Diff two malware payloads and rank what changed by how scary it is:**

```
diff_survey(old_id, new_id)
# -> 20 functions added, 36 removed, 125 changed
# -> security_rank 8.5: main() evolved from simple exec C2
#    to chunked JSON protocol with registry persistence
```

Instant. Server-side. No worker needed. Just reads cached indexes.

**Behavioral classification that actually means something:**

```
capa_scan(binary_id)
# -> 678 rules evaluated, 18 matched, 7 ATT&CK techniques
# -> execute shell command, encrypt via BCrypt, interact with iptables
```

**Find strings that malware hides by building them character by character:**

```
detect_stack_strings(binary_id, "0x140001000")
# -> "cmd.exe /c whoami"
# Built byte-by-byte on the stack. Invisible to `strings`. We found it anyway.
```

## Architecture

Here's how this works and why it doesn't suck:

```
Your Agent (Claude / Cursor / whatever)
  |
  | MCP protocol
  v
server.py (65 tools, reads cache, NEVER touches IDA)
  |
  |-- Arbiter thread (supervisor, reaps dead workers, spawns new ones)
  |-- Cache reader (filesystem is the only IPC channel)
  |
  | spawns one subprocess per binary
  v
binary_worker.py (loads .i64, processes requests, writes results to cache)
  |
  |-- session.py (3200 lines of pure analysis engine)
  |-- hexrays_analysis.py (CTree queries, taint, microcode)
  |-- proof.py (SMT proofs via binbit solver)
  |-- detection.py (crypto, obfuscation, stack strings)
  |-- recovery.py (class hierarchy, protocol, CFG)
```

The server process has never seen idalib in its life. It reads files from disk. Workers do all the heavy lifting. You can kill anything, restart it, and lose absolutely nothing because everything is cached to disk. It's honestly beautiful.

## All 65 Tools

I'm not going to explain each one individually because we'd be here all day. Here's the categories:

**Binary Lifecycle (6)** -- open, close, list, poll, metadata, worker status

**Function Analysis (8)** -- decompile, batch decompile, list, xrefs, call graph, stack frame

**Binary Properties (6)** -- segments, checksec, imports, exports, survey, entropy

**Vulnerability Research (3)** -- pattern search across 10 bug families, deep exploitability assessment with validation gate analysis, interprocedural taint tracing

**SMT Proofs (4)** -- overflow proof, bounds sufficiency, opaque predicates, expression equivalence. All return proof coverage percentage so you know exactly how much was verified.

**Obfuscation (2)** -- detection (MBA + CFF + expression depth), CFG recovery

**Malware Analysis (7)** -- behavior classification, anti-analysis detection, string classification, dynamic resolution, crypto constants, API hash resolution (107 algorithms), library detection

**Detection Databases (4)** -- CAPA (678 rules), stack strings (virtual buffer, all MOV widths), YARA generation (per-BB fixup masking), protocol state machines (raw socket + WinHTTP + WinINet)

**Hex-Rays Deep Analysis (7)** -- CTree queries, microcode, pseudocode slicing, dataflow tracing, def-use chains, value ranges, decompiler warnings

**Symbolic Execution (3)** -- path feasibility, path finding, constrained reachability (angr + Hex-Rays value ranges)

**Binary Diffing (3)** -- structural diff, function diff, security-ranked survey. All server-side from cache. Instant.

**C++ Recovery (2)** -- class hierarchy from vtable constructor analysis, protocol detection with taint verification

**Function Similarity (2)** -- find similar functions by structure hash, cross-binary correlation

**Mutations (8)** -- rename, comment, type, patch. Write-safe with generation counter and multi-agent queue.

## Performance

| What | How Fast |
|---|---|
| Cached result | <1ms |
| Worker bootstrap | 0.3s |
| SMT proof | 4-20ms |
| CAPA 678 rules | <500ms |
| Binary diff | <100ms |
| Full decompile | 50-200ms |
| Cold open (70KB) | ~6s |
| Pattern search (3000 funcs) | ~60s |

The SMT proofs are the showstopper. Other tools use Z3 and time out at 30 seconds. We use binbit and solve the same problem in 4 milliseconds. It's not even a competition.

## What this is NOT

- **Not a Ghidra fallback.** IDA Pro 9.0 only. No compromises.
- **Not a plugin bundle.** Ships capabilities, not dependencies you have to install.
- **Not an agent.** Pure tool delivery. Your agent does the thinking.
- **Not a GUI.** Headless. For LLMs and automation.

## Standing on the shoulders of giants

Everything reimplemented from scratch. No code copied. Just inspired by brilliant people who solved these problems first:

| Project | What we learned | License |
|---|---|---|
| [CAPA](https://github.com/mandiant/capa) | Behavioral rules + ATT&CK | Apache-2.0 |
| [FLOSS](https://github.com/mandiant/flare-floss) | Stack string detection | Apache-2.0 |
| [binbit](https://github.com/nickcano/binbit) | Fast SMT solving | MIT |
| [mkYARA](https://github.com/fox-it/mkYARA) | BB-level YARA with wildcards | MIT |
| [HexRaysPyTools](https://github.com/igogo-x86/HexRaysPyTools) | Vtable constructor detection | MIT |
| [Diaphora](https://github.com/joxeankoret/diaphora) | Structure hashing | GPL |
| [hrtng](https://github.com/KasperskyLab/hrtng) | 107 API hash algorithms | GPL |
| [d810-ng](https://github.com/w00tzenheimer/d810-ng) | OLLVM detection | GPL |

## License

AGPL-3.0. Non-commercial.

binbit solver: MIT.

---

<p align="center"><em>That's about it. See ya.</em></p>
