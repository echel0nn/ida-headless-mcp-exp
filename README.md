# ida-headless-mcp

Non-blocking binary analysis MCP server for IDA Pro 9.0. 59 tools. Multi-agent safe. No plugins required.

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
  |
  | spawns subprocess per binary
  v
binary_worker.py (owns one .i64, processes queue, writes cache)
  |
  |-- session.py (IDA analysis engine, 2100+ lines)
  |-- hexrays_analysis.py (CTree, microcode, taint, assessment)
  |-- detection.py (obfuscation, crypto)
  |-- proof.py (SMT proofs via binbit)
  |-- recovery.py (CFG, class hierarchy, protocol)
  |-- function_index.py (per-binary function metadata)
  |-- diff.py (structural binary comparison)
```

Key principle: **server never touches IDA**. All IDA work happens in worker subprocesses. Server reads from cache, returns instantly.

## Tool Categories (59 total)

### Binary Lifecycle (5)
`open_binary`, `close_binary`, `list_binaries`, `poll_analysis`, `binary_metadata`

### Function Analysis (8)
`list_functions`, `decompile`, `batch_decompile`, `stack_frame`, `xrefs_to`, `xrefs_from`, `call_graph`, `call_chain`

### Binary Properties (6)
`segments`, `checksec`, `imports`, `exports`, `binary_survey`, `entropy_analysis`

### Vulnerability Detection (3)
`search_pattern` (10 bug families), `assess_exploitability`, `interprocedural_taint`

### SMT Proofs (4)
`prove_overflow`, `prove_bounds_sufficient`, `prove_predicate_opaque`, `prove_equivalence`

### Deobfuscation (3)
`detect_obfuscation`, `simplify_expression`, `recover_cfg`

### Malware Analysis (5)
`classify_behavior`, `detect_anti_analysis`, `classify_strings`, `detect_dynamic_resolution`, `detect_crypto_primitives`

### Hex-Rays Deep Analysis (7)
`query_ctree`, `get_microcode`, `pseudocode_slice_view`, `trace_dataflow`, `def_use`, `value_ranges`, `hexrays_warnings`

### Symbolic Execution (3)
`path_feasibility`, `find_paths`, `constrained_reachability`

### Binary Diffing (3)
`diff_binary`, `diff_function`, `diff_survey`

### Recovery (3)
`recover_class_hierarchy`, `detect_protocol_state_machine`, `detect_obfuscation`

### Mutations (8)
`rename_function`, `rename_variable`, `set_comment`, `set_function_type`, `set_variable_type`, `patch_bytes`, `poll_mutation`, `get_generation`

### Diagnostics (1)
`worker_status`

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

## License

AGPL-3.0. Non-commercial.

binbit (tools/binbit-src): MIT license, github.com/bint-disasm/binbit.
