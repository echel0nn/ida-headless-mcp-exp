<p align="center">
  <img src="assets/logo.png" alt="IDA Headless MCP" width="280"/><br/>
  <sub>she has crippling depression from staring at OLLVM-flattened control flow graphs all day</sub>
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

Real benchmarks on a Ryzen 9 5900X, Windows 11, IDA Pro 9.0. All times measured with `time.perf_counter()`.

### Per-binary scaling

| Binary | Size | Functions | Cold Analysis | Warm Open | Index Build | Decompile (largest) |
|---|---|---|---|---|---|---|
| ping.exe | 44 KB | 47 | ~3s | 208 ms | 176 ms | 14 ms |
| whoami.exe | 96 KB | 242 | ~4s | 209 ms | 97 ms | 5 ms |
| notepad.exe | 352 KB | 521 | ~6s | 219 ms | 243 ms | 6 ms |
| cmd.exe | 332 KB | 793 | ~8s | 243 ms | 388 ms | 19 ms |
| 7z.exe | 544 KB | 2639 | ~12s | 275 ms | 900 ms | 14 ms |
| curl.exe | 656 KB | 1341 | ~14s | 254 ms | 862 ms | 1201 ms |
| certutil.exe | 1.5 MB | 3678 | ~25s | 405 ms | 2.1 s | 1226 ms |
| ntoskrnl.exe | 12.1 MB | 29328 | ~170s | 1542 ms | 18.8 s | 40 ms |

### Tool-level timing

| Operation | Typical | Notes |
|---|---|---|
| Cached result (any tool) | <1 ms | Filesystem read |
| Worker bootstrap (idalib) | 90-170 ms | One-time per worker process |
| Decompile (average function) | 1-15 ms | Varies by function complexity |
| Decompile (monster function) | 200-1200 ms | curl's SSL handshake, certutil's ASN.1 parser |
| SMT proof (binbit) | 4-20 ms | Integer overflow proof with witness |
| CAPA scan (678 rules) | <500 ms | Index-based evaluation |
| Crypto signature scan | 23-955 ms | Scales with binary data section size |
| Binary diff (server-side) | <100 ms | Reads two cached indexes, pure Python |
| Pattern search (full binary) | 30-90s | Decompiles all functions + regex check |

### The binbit flex

Other tools use Z3 for overflow proofs and time out at 30 seconds on real functions. We use binbit and solve the same problem in 4 milliseconds with a concrete witness value. It's not even a competition.

## What this is NOT

- **Not a Ghidra fallback.** IDA Pro 9.0 only. No compromises.
- **Not a plugin bundle.** Ships capabilities, not dependencies you have to install.
- **Not an agent.** Pure tool delivery. Your agent does the thinking.
- **Not a GUI.** Headless. For LLMs and automation.

## Standing on the shoulders of giants

Everything reimplemented from scratch. No code copied. Just inspired by brilliant people who solved these problems first:

| Project | What we learned | License |
|---|---|---|
| [CAPA](https://github.com/mandiant/capa) | 678 behavioral rules + 106 ATT&CK technique mappings | Apache-2.0 |
| [FLOSS](https://github.com/mandiant/flare-floss) | Stack string detection via virtual stack buffer + MOV width handling | Apache-2.0 |
| [binbit](https://github.com/nickcano/binbit) | QF_BV SMT solver for 4ms overflow proofs | MIT |
| [angr](https://github.com/angr/angr) | Symbolic execution engine for path feasibility + constrained reachability | BSD |
| [mkYARA](https://github.com/fox-it/mkYARA) | Operand wildcarding modes (loose/normal/strict) for YARA generation | MIT |
| [yara_fn](https://gist.github.com/williballenthin/3abc9577bede0aeef25526b201732246) | Per-basic-block YARA with IDA fixup masking (Willi Ballenthin / FLARE) | Public |
| [VulFi](https://github.com/Accenture/VulFi) | Dangerous function xref patterns (our search_pattern surpasses it) | MIT |
| [HexRaysPyTools](https://github.com/igogo-x86/HexRaysPyTools) | Vtable store-to-this+0 constructor detection for class hierarchy | MIT |
| [Diaphora](https://github.com/joxeankoret/diaphora) | Structure hashing for cross-binary function similarity | GPL |
| [Obpo](https://github.com/nickcano/obpo) | Per-block symbolic state solving approach for CFF deflattening | MIT |
| [hrtng](https://github.com/KasperskyLab/hrtng) | 107 API hash algorithm definitions (ROR13, DJB2, CRC32, FNV-1a, malware-specific) | GPL |
| [OALabs HashDB](https://github.com/OALabs/hashdb) | 33,167 precomputed hash-to-API entries across 107 algorithms | MIT |
| [FindCrypt](https://github.com/d3v1l401/FindCrypt-Ghidra) / [signsrch](https://github.com/nihilus/IDA-Signsrch) | Crypto constant signature database (38 signatures, 27 algorithms) | GPL |
| [d810-ng](https://github.com/w00tzenheimer/d810-ng) | OLLVM/Tigress detection signature patterns | GPL |
| gooMBA (IDA built-in) | MBA simplification runs automatically during decompile — we don't reimplement it | IDA license |

## License

AGPL-3.0. Non-commercial.

binbit solver: MIT.

---

<p align="center"><em>That's about it. See ya.</em></p>
