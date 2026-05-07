# ida-headless-mcp — Claude Code Instructions

Non-blocking binary analysis MCP server for IDA Pro 9.0. 69 tools. Python 3.11+, idalib backend, filesystem cache IPC.

## Repository Layout

```
src/ida_headless_mcp/
  server.py            # MCP server (69 tools, pure cache reader, ZERO idalib imports)
  binary_worker.py     # Worker process (owns .i64, processes queue, writes cache)
  session.py           # IDA analysis engine (3200 LOC, all tool implementations)
  hexrays_analysis.py  # CTree queries, microcode, taint, assessment
  detection.py         # Obfuscation, crypto, stack strings
  proof.py             # SMT overflow/bounds proofs via binbit
  recovery.py          # CFG recovery, class hierarchy, protocol detection
  ctree_to_smt.py      # CTree AST to SMT-LIB compiler
  lifecycle.py         # Binary state machine + arbiter supervisor
  bootstrap.py         # idalib activation (fast path skips pip/activation)
  cache_reader.py      # Read-only filesystem cache interface
  function_index.py    # Per-binary function metadata index
  diff.py              # Structural binary diff (server-side)
  mutations.py         # Write queue, generation counter
  config.py            # Settings from env vars
  worker.py            # Tool dispatch router
  guards.py            # @requires decorator for state checks
  smt_prover.py        # binbit solver interface
  api_hashes.py        # API hash DB (107 algorithms)
  capa_rules.py        # CAPA rule evaluation engine
  miasm_tools.py       # Server-side miasm tools (disassemble, IR, simplify, emulate)

data/
  crypto_sigs.json     # 38 cryptographic constant signatures
  hashdb.json.gz       # 33,167 API hash entries (107 algorithms)
  capa_rules.json.gz   # 678 behavioral rules (106 ATT&CK techniques)

tools/
  binbit.exe           # QF_BV SMT solver (compiled from tools/binbit-src/)

test_binaries/
  src/                 # Test binary source code (6 targeted test cases)
  *.exe                # Compiled test binaries (gitignored)

cache/                 # Per-binary analysis cache (gitignored)
```

## Architecture — The One Rule

**server.py NEVER imports idalib.** Not today, not in a hotfix, not for one thing.

```
MCP Client → server.py (reads cache, returns instantly)
                ↓ spawns via arbiter
             binary_worker.py (loads .i64, processes queue, writes cache)
```

The filesystem cache is the only IPC channel. Kill anything, restart, lose nothing.

## Build and Verify

```bash
pip install -e .                                    # install package
cd tools/binbit-src && cargo build --release && cd ../..
cp tools/binbit-src/target/release/binbit.exe tools/binbit.exe

# Quality gates
python -m py_compile src/ida_headless_mcp/*.py      # syntax check
python -m ruff check src/ --select E,F,W            # lint

# Run MCP server
python -m ida_headless_mcp.server                   # stdio mode
```

## Non-Negotiable Rules

See `GOLDEN_RULES.md` for the full 32-rule set. Critical ones:

### 1. No silent failures
Every `except` block either logs, writes to error file, or re-raises. `except Exception: pass` is banned.

### 2. Every tool tells the truth
- Detection tools: report what CAN trigger false positives
- Proof tools: report `proof_coverage` (gates_encoded / gates_total)
- Pending responses: include worker_action, worker_phase, message

### 3. No god objects
session.py split into 4 domain mixins (SessionCore, DetectionMixin, ProofMixin, AnalysisMixin). 500 lines max per implementation file.

### 4. Test on real binaries
Every tool must work on: small (<100KB), medium (1-5MB), large (10MB+). A tool that only works on test_crypto.exe is a demo.

### 5. Cache key determinism
Given (binary_id, tool_name, key), the cache path is always the same. No timestamps, no randomness.

### 6. Endianness is explicit
Crypto signatures have `word_size` and `endian` fields. No implicit x86 assumptions.

## Adding a New Tool

**IDA tool (needs worker):**
1. Implement in `session.py` (or domain mixin) with `@requires(BinaryState.INDEXED)` decorator
2. Add dispatch entry in `worker.py` `_dispatch()` function
3. Add `@mcp.tool()` function in `server.py` that calls `_ida_tool()`
4. Add test against at least one real binary
5. Update README tool count

**Server-side tool (no worker, instant):**
1. Implement in `miasm_tools.py` or similar (reads raw PE bytes, no idalib)
2. Add `@mcp.tool()` function in `server.py` that calls the implementation directly
3. These run in the server process — keep them fast (<1s)

## Adding a New Detection Signature

- Crypto: add entry to `data/crypto_sigs.json` with `name`, `bytes` (hex), `algo`, `word_size`, `endian`
- CAPA: add rule to `data/capa_rules.json.gz` following existing format
- API hash: regenerate `data/hashdb.json.gz` with new algorithm

## Common Mistakes

1. **Importing ida_* at module level** — Only import inside functions. Module-level imports crash the server (which never loads idalib).
2. **Forgetting `_cache_key` in queue request** — The cache filename is derived from this key. Without it, results overwrite each other.
3. **Testing only on tiny binaries** — A 100KB binary has 200 functions. certutil.exe has 3,678. ntoskrnl has 29,328. Performance cliffs appear at scale.
4. **Assuming worker is alive** — Always go through `ensure_worker()`. Never hold a reference to a worker process.
5. **Writing to cache without generation stamp** — Every result dict must include `"generation": current_gen`. Without it, staleness detection breaks.
6. **Hardcoding IDA paths** — All paths come from `config.py` which reads env vars.
7. **Returning raw IDA objects** — Everything returned from session methods must be JSON-serializable dicts/lists/primitives. No ida_* objects in return values.
8. **Missing stdin=DEVNULL on subprocess** — All `subprocess.Popen` and `subprocess.run` calls MUST set `stdin=subprocess.DEVNULL`. Workers inherit the MCP server's stdin (JSON-RPC pipe). idalib reads from stdin during init. Without DEVNULL, workers steal MCP messages and crash silently.

## Verification Checklist

Before yielding any change:
- [ ] `python -m py_compile src/ida_headless_mcp/*.py` — no syntax errors
- [ ] `python -m ruff check src/ --select E,F,W` — clean
- [ ] No new `except Exception: pass` introduced
- [ ] No new hardcoded paths
- [ ] No new functions with 7+ parameters
- [ ] New public functions have Google-style docstrings
- [ ] Tool tested on at least one binary via MCP call
