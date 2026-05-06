# ida-headless-mcp

Non-blocking binary analysis MCP server for IDA Pro 9.0. 65 tools. Multi-agent safe. No plugins required.

## Why This Exists

Every other IDA MCP server blocks. Agent calls `decompile` → server locks for 30 seconds → agent sits idle. This one returns instantly (cached result or `{"status": "pending"}`) and processes work in background workers. Ten agents can query the same binary simultaneously.

## What Makes It Different

| Capability | This | re-mcp | ida-multi-mcp | Others |
|---|---|---|---|---|
| Non-blocking (cache-or-pending) | Yes | No | No | No |
| Hex-Rays microcode IR API | Yes | No | No | No |
| CTree query engine | Yes | No | No | No |
| Vulnerability pattern search (10 rules) | Yes | No | No | No |
| SMT-backed overflow proofs (binbit) | Yes | No | No | No |
| Deep taint tracing (inter-procedural) | Yes | No | No | No |
| Exploitability assessment with verdict | Yes | No | No | No |
| Obfuscation detection + MBA simplification | Yes | No | No | No |
| angr symbolic execution integration | Yes | No | No | No |
| Binary diff with security ranking | Yes | No | No | No |
| Multi-agent write safety (mutation queue) | Yes | No | No | No |
| Worker auto-restart on code change | Yes | No | No | No |

## Requirements

- IDA Pro 9.0 with idalib (Hex-Rays decompiler license)
- Python 3.11+
- Windows (idalib64.dll)
- Rust toolchain (for binbit SMT solver — `rustup update stable`)

## Installation

```bash
git clone <this-repo>
cd ida-headless-mcp

# Install Python package
pip install -e .

# Build binbit SMT solver
cd tools/binbit-src && cargo build --release && cd ../..
cp tools/binbit-src/target/release/binbit.exe tools/binbit.exe
```

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `IDA_HEADLESS_MCP_IDA_DIR` | `C:/Program Files/IDA Professional 9.0` | IDA installation path |
| `IDA_HEADLESS_MCP_CACHE_DIR` | `./cache` | Per-binary analysis cache |
| `IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA` | `2` | Max simultaneous worker processes |
| `IDA_HEADLESS_MCP_IDLE_TIMEOUT_S` | `900` | Worker idle timeout (seconds) |
| `IDA_HEADLESS_MCP_MAX_BINARY_SIZE_MB` | `200` | Reject binaries larger than this |
| `IDA_HEADLESS_MCP_BINBIT_PATH` | `./tools/binbit.exe` | Path to binbit SMT solver |

## Running

### stdio (for Claude Code, Oh My Pi, Cursor)

```bash
python -m ida_headless_mcp.server
```

### Claude Desktop config

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ida-headless-mcp": {
      "command": "python",
      "args": ["-m", "ida_headless_mcp.server"],
      "cwd": "/path/to/ida-headless-mcp",
      "env": {
        "IDA_HEADLESS_MCP_IDA_DIR": "C:/Program Files/IDA Professional 9.0",
        "IDA_HEADLESS_MCP_CACHE_DIR": "/path/to/ida-headless-mcp/cache",
        "IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA": "2"
      }
    }
  }
}
```

### Oh My Pi / Claude Code config

Add to `.claude/mcp-configs/mcp-servers.json`:

```json
{
  "ida-headless-mcp": {
    "command": "python",
    "args": ["-m", "ida_headless_mcp.server"],
    "cwd": "/path/to/ida-headless-mcp",
    "env": {
      "IDA_HEADLESS_MCP_IDA_DIR": "C:/Program Files/IDA Professional 9.0",
      "IDA_HEADLESS_MCP_CACHE_DIR": "/path/to/ida-headless-mcp/cache",
      "IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA": "2"
    }
  }
}
```

## Architecture

```
Agent (Claude/Cursor/any MCP client)
  |
  | MCP protocol (stdio or streamable-http)
  v
server.py (59 tools, pure cache reader, ZERO idalib imports)
  |
  |-- cache_reader.py (read cached results from filesystem)
  |-- lifecycle.py (binary state machine, worker management)
  |-- mutations.py (write queue, generation counter)
  |-- ctree_to_smt.py (CTree AST to SMT-LIB compiler)
  |
  | spawns subprocess per binary
  v
binary_worker.py (owns one .i64, processes queue, writes cache)
  |
  |-- session.py (IDA analysis engine, 2100+ lines)
  |-- hexrays_analysis.py (CTree, microcode, taint, assessment)
  |-- detection.py (obfuscation, crypto detection)
  |-- proof.py (SMT proofs via binbit)
  |-- recovery.py (CFG, class hierarchy, protocol)
  |-- api_hashes.py (API hash resolution)
  |-- function_index.py (per-binary function metadata)
  |-- diff.py (structural binary comparison)
  |-- smt_prover.py (binbit solver interface)
```

Key principle: **server never touches IDA**. All IDA work happens in worker subprocesses. Server reads from cache, returns instantly.

## Tool Categories (59 total)

### Binary Lifecycle (6)
`open_binary`, `close_binary`, `list_binaries`, `poll_analysis`, `binary_metadata`, `worker_status`

### Function Analysis (8)
`list_functions`, `decompile`, `batch_decompile`, `stack_frame`, `xrefs_to`, `xrefs_from`, `call_graph`, `call_chain`

### Binary Properties (6)
`segments`, `checksec`, `imports`, `exports`, `binary_survey`, `entropy_analysis`

### Vulnerability Detection (3)
`search_pattern` (10 bug families with confidence scoring), `assess_exploitability` (deep taint + validation gates + verdict), `interprocedural_taint`

### SMT Proofs via binbit (4)
`prove_overflow`, `prove_bounds_sufficient`, `prove_predicate_opaque`, `prove_equivalence`

### Obfuscation Analysis (2)
`detect_obfuscation` (CTree expression depth + MBA density), `recover_cfg`

### Malware Analysis (7)
`classify_behavior`, `detect_anti_analysis`, `classify_strings`, `detect_dynamic_resolution`, `detect_crypto_primitives`, `resolve_api_hashes`, `detect_library_functions`

### Hex-Rays Deep Analysis (7)
`query_ctree`, `get_microcode`, `pseudocode_slice_view`, `trace_dataflow`, `def_use`, `value_ranges`, `hexrays_warnings`

### Symbolic Execution (3)
`path_feasibility`, `find_paths`, `constrained_reachability`

### Binary Diffing (3)
`diff_binary`, `diff_function`, `diff_survey` (all server-side from cached indexes, no worker needed)

### C++ Recovery (2)
`recover_class_hierarchy` (vtable xref analysis), `detect_protocol_state_machine`

### Mutations (8)
`rename_function`, `rename_variable`, `set_comment`, `set_function_type`, `set_variable_type`, `patch_bytes`, `poll_mutation`, `get_generation`

## Usage Pattern

The non-blocking pattern:

```
1. open_binary("/path/to/target.exe")     → binary_id
2. poll_analysis(binary_id)               → wait for READY/INDEXED
3. search_pattern(binary_id, "dangerous_function")  → first call: pending
4. (wait, retry)                          → second call: results with confidence
5. assess_exploitability(binary_id, function, "memmove", 2)  → source + gates + verdict
6. prove_overflow(binary_id, function, "memmove", 2)         → SAT/UNSAT in 4ms
```

## Performance

| Binary Size | Cold Open | Warm Open | Index Build |
|---|---|---|---|
| 68 KB | 6s | 0.5s | <1s |
| 2.5 MB (IrfanView) | 17s | 0.5s | ~20s |
| 5.5 MB | 38s | 0.76s | ~40s |
| 10 MB | 57s | 1.0s | ~60s |

SMT proofs (binbit): 4-20ms typical.
Pattern search (3000 functions): ~60s with decompile + verification.
Warm cache reads: <1ms.

## Inspired By

Detection rules, algorithms, and capabilities are inspired by these projects. No code is copied or depended upon — all reimplemented using our own infrastructure (CTree visitors, binbit SMT, function index, ida_bytes).

| Project | What We Took | License |
|---|---|---|
| [binbit](https://github.com/bint-disasm/binbit) | QF_BV SMT solver for overflow proofs and predicate analysis | MIT |
| [d810-ng](https://github.com/w00tzenheimer/d810-ng) | OLLVM/Tigress detection signature patterns | GPL (patterns only, no code) |
| [hrtng](https://github.com/KasperskyLab/hrtng) | API hash algorithm definitions (ROR13, DJB2, CRC32, FNV-1a, SDBM) | GPL (algorithms only) |
| [HexRaysPyTools](https://github.com/igogo-x86/HexRaysPyTools) | Vtable detection algorithm (store-to-this+0 constructor pattern) | MIT (algorithm only) |
| [Obpo](https://github.com/nickcano/obpo) | Per-block state solving approach for CFF deflattening | MIT (approach only) |
| [VulFi](https://github.com/Accenture/VulFi) | Dangerous function xref pattern (our search_pattern surpasses it) | MIT |
| [Diaphora](https://github.com/joxeankoret/diaphora) | Structure hashing concept for binary diffing (planned Phase 8) | GPL (concept only) |
| [CAPA](https://github.com/mandiant/capa) | Behavioral rule format and ATT&CK mapping (planned Phase 8) | Apache-2.0 |
| [FLOSS](https://github.com/mandiant/flare-floss) | Stack-string detection algorithm (planned Phase 8) | Apache-2.0 |
| gooMBA (Hex-Rays built-in) | MBA deobfuscation runs automatically during decompile() | Bundled with IDA |

## License

AGPL-3.0. Non-commercial.

binbit (tools/binbit-src): MIT license, github.com/bint-disasm/binbit.