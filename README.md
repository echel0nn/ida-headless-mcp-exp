<p align="center">
  <img src="assets/logo.png" alt="IDA Headless MCP" width="280"/><br/>
  <sub>she has crippling depression from staring at OLLVM-flattened control flow graphs all day</sub>
</p>

<h1 align="center">IDA Headless MCP</h1>

<p align="center">
  <strong>81 tools. Non-blocking. Multi-format. The greatest binary analysis MCP server of All Time.</strong>
</p>

---

## What is this

Every IDA MCP server that exists right now is dogwater. You call decompile, the server freezes for 30 seconds, your agent sits there staring at the ceiling. One agent per binary. It's like using a payphone in 2026.

This one doesn't do that. Every single tool either gives you the answer immediately from cache or tells you exactly what's happening: "worker is bootstrapping IDA, give me 10 seconds." Then it processes in the background while you go do other things. Ten agents can hammer the same binary simultaneously and nobody blocks anyone.

81 tools. SMT-backed proofs. Interprocedural taint. CAPA rules. YARA generation. Miasm symbolic execution. CFF deflattening with pseudocode generation. Multi-format (PE, ELF, Mach-O). API hash resolution (108 algorithms, 1.4M precomputed entries). Encrypted string decryption. Capability verification. All running through IDA Pro 9.0's idalib with zero plugins required.

## Why this exists and why it's different

Other binary analysis MCPs give you `decompile` and maybe `list_functions`. That's it. They're wrappers around one API call.

This is a **cyber reasoning engine**. It doesn't just decompile -- it proves overflows are exploitable, traces taint across function boundaries, deflattens control-flow-flattened malware, decrypts strings, resolves API hashes, verifies capabilities, and generates detection rules. And it does all of this without blocking your agent for a single millisecond.

The fundamental architecture difference:

| Other MCPs | This MCP |
|-----------|----------|
| Server imports idalib directly | Server NEVER imports idalib. Pure cache reader. |
| One request blocks everything | Every request returns instantly (cached or pending) |
| One binary at a time | Arbiter manages worker pool, LRU eviction, auto-restart |
| Crashes lose state | Atomic writes, orphan recovery, crash counters |
| x86 PE only | PE + ELF + Mach-O. x86_32, x86_64, ARM, AArch64. |
| No deobfuscation | Full CFF deflattening with pseudocode output |

## Quick Start

```bash
git clone https://github.com/echel0nn/ida-headless-mcp-exp
cd ida-headless-mcp-exp
pip install -e .

# Optional: build the SMT solver for proof tools
cd tools/binbit-src && cargo build --release && cd ../..
cp tools/binbit-src/target/release/binbit.exe tools/binbit.exe
```

MCP config:

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

You need IDA Pro 9.0 with idalib and a Hex-Rays decompiler license.

For SSE/HTTP transport (recommended for AILA integration -- survives client disconnects):
```bash
IDA_HEADLESS_MCP_TRANSPORT=sse python -m ida_headless_mcp.server
# Listens on http://127.0.0.1:18820/sse
```

## The highlight reel

**Prove an integer overflow is exploitable. In 4 milliseconds.**

```
prove_overflow(binary_id, func, "memmove", 2)
# -> SAT. Witness: v10=0x40000000, v21=4. Overflow confirmed. 4ms.
```

That's not a heuristic. That's a mathematical proof with a concrete witness value. Other tools time out at 30 seconds on the same function.

**Deflat CFF-obfuscated malware and get readable pseudocode:**

```
deflat_function(binary_id, "0x140001000")
# -> 63 states extracted, 44 real handlers, 3 opaque, 16 trampoline
# -> Pseudocode with resolved function names: socket(), bind(), WSAStartup()...
```

Tested on 3 different CFF variants: real-world CFF+BCF malware, OLLVM CFF+BCF+SUB, OLLVM CFF+split. All deflattened correctly with enriched pseudocode.

**Decrypt all encrypted strings in a binary:**

```
decrypt_binary_strings(binary_id, "0x1400947D0")
# -> 312/314 strings decrypted. CAST5/AES/Blowfish auto-detected.
```

**Resolve API hashes from 108 algorithms:**

```
resolve_api_hashes(binary_id)
# -> 108 algorithms x 13,439 APIs = 1.4M precomputed entries
# -> Instant lookup. CRC32, DJB2, ROR13, FNV-1a, and 104 more.
```

**Verify what a binary can actually do:**

```
verify_capabilities(binary_id)
# -> 22 capability categories scanned
# -> Confirmed: crypto, network, registry, process_enum, http_api
# -> Absent: screenshot, cmd_exec (verified at 3 levels: imports, hash table, strings)
```

## Architecture

```
Your Agent (Claude / Cursor / AILA / whatever)
  |
  | MCP protocol (stdio or SSE/HTTP)
  v
server.py (81 tools, reads cache, NEVER touches IDA)
  |
  |-- ThreadPoolExecutor (max_workers=8, server-side analysis)
  |-- Arbiter thread (supervisor, reaps dead workers, crash counter, auto-restart)
  |-- Cache reader (filesystem is the only IPC channel)
  |-- Atomic queue consumption (rename-then-read, no data loss)
  |-- Thread-safe lifecycle manager (_state_lock on all shared state)
  |
  |-- Server-side tools (no IDA needed):
  |     |-- Miasm (4): disassemble, IR lift, simplify, emulate
  |     |-- CFF (5): detect, deflat, disassemble, patch, emulate_concrete
  |     |-- Decrypt (2): per-function, whole-binary string decryption
  |     |-- API tracing (3): call sites, hash xrefs, capability verification
  |     |-- Pseudocode emitter: enriched C-like output from deflat results
  |     |-- Binary format parsers: PE + ELF + Mach-O
  |     `-- Deobfuscation engine: 111 MBA rules, pattern matcher, concrete IR evaluator
  |
  | spawns one subprocess per binary (stdin=DEVNULL, isolated from MCP pipe)
  v
binary_worker.py (loads .i64, processes requests, writes results to cache)
  |
  |-- session.py (analysis engine)
  |-- hexrays_analysis.py (CTree queries, taint, microcode)
  |-- hexrays_cff.py (microcode optimizer for CFF deflattening)
  |-- proof.py (SMT proofs via binbit solver)
  |-- detection.py (crypto, obfuscation, stack strings)
  `-- recovery.py (class hierarchy, protocol, CFG)
```

The server process has never seen idalib in its life. Workers do the heavy lifting. Kill anything, restart it, lose nothing -- everything is cached to disk with atomic writes.

## All 81 Tools

**Binary Lifecycle (6)** -- open, close, list, poll, metadata, worker status

**Function Analysis (8)** -- decompile (with automatic CFF pseudocode fallback), batch decompile, list, xrefs to/from, call graph, call chain, stack frame

**Binary Properties (6)** -- segments, checksec, imports, exports, survey, entropy

**Vulnerability Research (3)** -- pattern search across 10 bug families, deep exploitability assessment with validation gate analysis, interprocedural taint tracing

**SMT Proofs (4)** -- overflow proof, bounds sufficiency, opaque predicates, expression equivalence. All return proof coverage percentage.

**Obfuscation (2)** -- detection (MBA + CFF + expression depth), CFG recovery

**Malware Analysis (7)** -- behavior classification, anti-analysis detection, string classification, dynamic resolution, crypto constants, API hash resolution (108 algorithms, 1.4M entries), library detection

**Detection Databases (4)** -- CAPA (678 rules), stack strings (virtual buffer, all MOV widths), YARA generation (per-BB fixup masking), protocol state machines

**Hex-Rays Deep Analysis (7)** -- CTree queries, microcode, pseudocode slicing, dataflow tracing, def-use chains, value ranges, decompiler warnings

**Symbolic Execution (3)** -- path feasibility, path finding, constrained reachability (angr + Hex-Rays value ranges)

**Binary Diffing (3)** -- structural diff, function diff, security-ranked survey. All server-side from cache. Instant.

**C++ Recovery (2)** -- class hierarchy from vtable constructor analysis, protocol detection with taint verification

**Function Similarity (2)** -- find similar functions by structure hash, cross-binary correlation

**Miasm (4)** -- multi-arch disassembly, IR lifting, expression simplification / de-obfuscation, symbolic execution. Server-side. No worker. Instant. Supports x86_32, x86_64, ARM, AArch64.

**CFF Analysis (5)** -- full function CFG via miasm `dis_multiblock`, CFF detection with 5 signatures (OLLVM, Hikari, LCG-CFF, Tigress, Themida), deflattening with pseudocode generation, byte patch computation for Hex-Rays compatibility, concrete emulation with seeded registers/memory.

|Tool|What it does|
|---|---|
|`disassemble_function`|Full function CFG via miasm. Returns blocks, edges, per-block features.|
|`detect_control_flow_obfuscation`|Detect CFF: dispatcher, opaque predicates, state variable, signature match.|
|`deflat_function`|Recover the state machine. Classify blocks. Generate enriched pseudocode with resolved function names.|
|`patch_cff`|Compute byte patches that linearize the dispatcher. Queue them as IDB mutations.|
|`emulate_concrete`|Concrete emulation with seeded inputs. Hash verification, crypto identification.|
|`batch_cff_scan`|Scan all functions for CFF obfuscation. Returns positives with block counts.|
|`build_call_tree`|Recursive deflat from a root function through its callees.|

Pattern matching is driven by `cff_techniques/` -- a pluggable database of dispatcher patterns (5), opaque predicates (5 including es3n1n BitManip), state variable detectors (4: stack, register, global), and obfuscator signatures (5).

**Decrypt & API Tracing (5)** -- encrypted string decryption (CAST5/AES/Blowfish, multi-cipher trial), API call site tracing (IAT direct, thunk indirect, hash resolved), hash xref tracing, capability verification (22 categories from editable `api_categories.json`).

**Deobfuscation Engine** -- 111 MBA rewrite rules across 10 categories (XOR, ADD, SUB, AND, OR, MUL, BNOT, NEG, constant fold, predicates) + 14 opaque predicate rules. Data-driven: rules are JSON, engine is generic pattern matcher with commutativity support. No z3 -- uses binbit and miasm simplifier.

**API Hash Resolution** -- 108 algorithms cloned from OALabs/HashDB. 13,439 Windows API names from 30 system DLLs. 1.4M precomputed hash entries in `hashdb.json.gz`. Auto-detect which algorithm a binary uses.

**Mutations (8)** -- rename function/variable, set comment, set function/variable type, patch bytes/assemble. Write-safe with generation counter, multi-agent queue, atomic file writes.

## Binary Format Support

The server-side tools (CFF, decrypt, API tracing, capability scan) work on raw binary bytes. They support:

| Format | Detection | Code Section | Architecture |
|--------|-----------|-------------|-------------|
| PE (.exe/.dll/.sys) | MZ magic | `.text` or first `IMAGE_SCN_MEM_EXECUTE` | x86_32, x86_64, ARM, AArch64 |
| ELF (Linux/Android) | `\x7fELF` magic | `.text` or first `SHF_EXECINSTR` | x86_32, x86_64, ARM, AArch64, MIPS |
| Mach-O (macOS/iOS) | `FEEDFACE`/`FEEDFACF` | `__TEXT,__text` | x86_32, x86_64, ARM, AArch64 |

The IDA worker side handles any format IDA supports (including raw firmware, COFF, etc.).

## Concurrency & Durability

This isn't a toy. It's built for production multi-agent workloads:

- **Atomic queue consumption**: worker renames queue to `.processing` before reading. Server appends to a fresh file. No data loss.
- **Thread-safe lifecycle**: `_state_lock` guards all shared state. Arbiter thread and request handlers never race.
- **Crash recovery**: orphaned `.processing` files recovered on worker restart. Crash counter persisted to disk. After 3 crashes, gives up with clear error.
- **Atomic cache writes**: `tmp` + `os.replace`. Daemon thread killed mid-write leaves no corrupt JSON.
- **Error caching**: failed tool results written to standard cache path. No infinite re-queue loops.
- **Thread pool**: `ThreadPoolExecutor(max_workers=8)` for server-side tools. Bounded concurrency.
- **`stdin=DEVNULL`**: workers never inherit the MCP server's JSON-RPC pipe. Root cause of every "worker dies silently" bug in other implementations.

## Performance

Real benchmarks on a Ryzen 9 5900X, Windows 11, IDA Pro 9.0.

### Per-binary scaling

| Binary | Size | Functions | Cold Analysis | Warm Open | Index Build | Decompile (largest) |
|---|---|---|---|---|---|---|
| ping.exe | 44 KB | 47 | ~3s | 208 ms | 176 ms | 14 ms |
| notepad.exe | 352 KB | 521 | ~6s | 219 ms | 243 ms | 6 ms |
| certutil.exe | 1.5 MB | 3678 | ~25s | 405 ms | 2.1 s | 1226 ms |
| ntoskrnl.exe | 12.1 MB | 29328 | ~170s | 1542 ms | 18.8 s | 40 ms |

### Tool-level timing

| Operation | Typical | Notes |
|---|---|---|
| Cached result (any tool) | <1 ms | Filesystem read |
| Worker bootstrap (idalib) | 90-170 ms | One-time per worker |
| Decompile (average) | 1-15 ms | Varies by complexity |
| SMT proof (binbit) | 4-20 ms | With concrete witness |
| CFF deflat (259 blocks) | ~15s | Server-side, no worker |
| CAPA scan (678 rules) | <500 ms | Index-based |
| String decryption (full binary) | ~30s | Multi-cipher trial |
| Capability verification | ~5s | Full API scan + hash resolve |
| Binary diff (server-side) | <100 ms | Reads two cached indexes |

## What this is NOT

- **Not a Ghidra fallback.** IDA Pro 9.0 only. No compromises.
- **Not a plugin bundle.** Ships capabilities, not dependencies you have to install.
- **Not an agent.** Pure tool delivery. Your agent does the thinking.
- **Not a GUI.** Headless. For LLMs and automation.
- **Not PE-only.** PE + ELF + Mach-O. Multi-arch.

## Standing on the shoulders of giants

Everything reimplemented from scratch. No code copied. Just inspired by brilliant people who solved these problems first:

| Project | What we learned | License |
|---|---|---|
| [CAPA](https://github.com/mandiant/capa) | 678 behavioral rules + 106 ATT&CK technique mappings | Apache-2.0 |
| [FLOSS](https://github.com/mandiant/flare-floss) | Stack string detection via virtual buffer + MOV width handling | Apache-2.0 |
| [miasm](https://github.com/cea-sec/miasm) | Multi-arch disassembly, IR lifting, symbolic execution, expression simplification | GPLv2 |
| [binbit](https://github.com/nickcano/binbit) | QF_BV SMT solver for 4ms overflow proofs | MIT |
| [angr](https://github.com/angr/angr) | Symbolic execution engine for path feasibility + constrained reachability | BSD |
| [D-810](https://github.com/RolfRolles/d810) | MBA rewrite rules, CFF unflattening patterns, opaque predicate catalog | GPL |
| [OALabs HashDB](https://github.com/OALabs/hashdb) | 108 hash algorithm definitions, precomputed API hash database | MIT |
| [mkYARA](https://github.com/fox-it/mkYARA) | Operand wildcarding for YARA generation | MIT |
| [VulFi](https://github.com/Accenture/VulFi) | Dangerous function xref patterns | MIT |
| [HexRaysPyTools](https://github.com/igogo-x86/HexRaysPyTools) | Vtable constructor detection for class hierarchy | MIT |
| [Diaphora](https://github.com/joxeankoret/diaphora) | Structure hashing for cross-binary function similarity | GPL |
| [FindCrypt](https://github.com/d3v1l401/FindCrypt-Ghidra) | Crypto constant signature database | GPL |

## License

AGPL-3.0. Non-commercial.

miasm: GPLv2. binbit solver: MIT.

---

<p align="center"><em>81 tools. Zero blocking. Ship it.</em></p>
