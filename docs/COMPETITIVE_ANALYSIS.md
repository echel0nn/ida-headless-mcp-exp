# IDA Headless MCP — Competitive Analysis

Honest assessment of what exists, where they fall short for VR workflows, and what we build differently.

---

## The Landscape (May 2026)

7 IDA MCP servers exist on GitHub. Three matter:

| Project | Stars | Architecture | Key trait |
|---|---|---|---|
| **jtsylve/ida-mcp** | 52 | idalib + supervisor/worker | Most mature. Production-stable. Multi-database. pip installable. |
| **mrexodia/ida-pro-mcp** | 1700+ | IDAPython plugin + optional idalib headless | Most popular. Created by x64dbg author. Active community. |
| **symgraph/IDAssistMCP** | ~100 | IDAPython plugin | 38 tools, 8 resources, 7 prompts. Rich but plugin-dependent. |

The rest (fdrechsler, 0xOb5k-J, MeroZemory, susuya233) are thin wrappers — basic decompile/list/search over HTTP. Not serious competition.

---

## Deep Analysis: jtsylve/ida-mcp (strongest competitor)

### What it does well

1. **idalib architecture.** No GUI dependency. IDA runs as a library in a Python process. Clean process lifecycle — supervisor spawns workers, routes requests, workers own one database each.

2. **Multi-database support.** Open multiple binaries simultaneously. Each gets its own worker process. The supervisor routes commands to the right worker by `database` parameter.

3. **Persistent daemon.** Workers survive client disconnections. Analysis state is preserved across sessions. Idle timeout with auto-shutdown.

4. **Meta-tools: `execute` and `batch`.** `execute` runs sandboxed Python that chains multiple `await invoke()` calls in one round trip — supports `asyncio.gather` for parallel queries. `batch` sends up to 50 sequential calls in one request. These reduce round-trip overhead significantly.

5. **Tool discovery.** Only common tools are visible to the LLM. Hidden tools are callable via `call` meta-tool. Keeps context window clean.

6. **Thread safety.** idalib is single-threaded. They solved this with `MainThreadExecutor` — async MCP handlers dispatch IDA calls to the main thread. Clean separation.

7. **MCP prompts.** Ships with `survey_binary`, `analyze_function`, `diff_before_after`, `classify_functions`, `find_crypto_constants`, `auto_rename_strings`, `apply_abi` — guided analysis workflows.

### Where it falls short for VR

**1. No batch decompile with structural filtering.**

`ida-mcp` can decompile one function at a time, or use `batch` to send 50 decompile calls. But there's no `batch_decompile(filter)` that says "decompile all functions that call memcpy where the size argument comes from user input." The LLM must:
- Call `list_functions` (paginated, 100 at a time)
- Identify targets by name/size heuristics only
- Call `decompile_function` one-by-one or in `batch` of 50
- Filter the results itself

For a 5000-function binary where the LLM wants "all parsers reachable from recv," this is:
- 50 `list_functions` calls to paginate
- LLM reads all 5000 names, guesses which are relevant
- 100+ individual decompile calls
- Hundreds of thousands of LLM tokens consumed just on listing

**Our approach:** `batch_decompile` with a filter DSL: `{"callers_of": ["recv", "read"], "min_complexity": 5}`. The MCP resolves callers via IDA's xref database (cheap), then decompiles only the matches. One call, 20 results, 2 seconds.

**2. No pattern search across decompiled output.**

`ida-mcp` has no `search_pattern("dangerous_function")` or `search_pattern("unchecked_length")`. The LLM must:
- Decompile functions one by one
- Read the pseudocode
- Decide itself if the pattern matches

This is token-expensive and unreliable — the LLM misses patterns humans wouldn't, and hallucinates patterns that don't exist.

**Our approach:** Built-in pattern library (`dangerous_function`, `unchecked_length`, `format_string`, `signed_size`, `double_free`, `toctou`, `command_injection`) implemented as deterministic checks over decompiled output + IDA's type system. The LLM gets confirmed matches, not self-assessed guesses.

**3. No function index with computed metrics.**

`ida-mcp` returns function metadata (name, bounds, size, flags). It does NOT compute:
- Cyclomatic complexity per function
- Blast radius (how many functions are transitively reachable)
- Callers/callees count
- String reference count
- Whether the function is reachable from an import (attack surface)

The LLM can't ask "top 10 most complex functions reachable from network input" without doing the traversal itself over hundreds of API calls.

**Our approach:** Build an in-memory function index at `analyze_binary` time. Pre-compute complexity, blast radius, caller/callee counts, string refs. `list_functions(sort_by="blast_radius_desc", filter={"min_complexity": 10})` returns the answer in one call.

**4. No binary diff.**

`ida-mcp` has no `diff_binary` or `diff_function`. For N-day research — the primary v0.1 workflow — the first step is "diff the patched binary against the vulnerable one." Without diff, the LLM must:
- Open both binaries
- List all functions in both
- Compare function lists manually
- Decompile changed functions in both versions
- Diff the pseudocode itself

This is the #1 most common VR operation and it requires dozens of API calls.

**Our approach:** `diff_binary(old, new)` returns added/removed/changed functions in one call. `diff_function(old_addr, new_addr)` returns side-by-side pseudocode with unified diff and a `summary_signal` (bounds_check_added, error_path_added, call_replaced).

**5. No mitigation analysis in binary metadata.**

`ida-mcp`'s `get_database_info` returns processor, bitness, file type, address range, counts. It does NOT return:
- PIE/ASLR status
- NX/DEP
- Stack canary presence
- RELRO level
- Fortify source
- CFI/CET/MTE/shadow stack

The obligation system needs this — the LLM cannot claim "exploitable" without knowing what mitigations are active. Today the LLM would need to run `checksec` separately via SSH.

**Our approach:** `analyze_binary` returns a `mitigations` block with all security-relevant binary properties. This is the evidence the obligation system gates on.

**6. No decompilation cache.**

`ida-mcp` decompiles on every request. For a VR session where the LLM revisits the same function 5 times across 30 turns (normal for exploit development — check the function, write exploit, check again after annotation, verify fix), each call pays the full decompile cost.

**Our approach:** Disk-backed LRU cache keyed on `(binary_sha256, function_address, ida_version)`. Second decompile of the same function is a disk read, not a CPU-bound decompile. Invalidates on annotation changes.

**7. No annotation provenance.**

`ida-mcp` supports renaming and commenting, but annotations don't track who wrote them (LLM vs operator) or when. The obligation system can't distinguish "the LLM renamed this function based on a hypothesis" from "the operator confirmed this name."

**Our approach:** Every annotation has `source` (llm_inference, operator, recovered_from_string, flirt) and `timestamp`. Operator annotations are protected — LLM cannot overwrite them (D-10).

**8. Sandboxed `execute` is powerful but dangerous.**

`ida-mcp`'s `execute` tool runs arbitrary Python inside the IDA process. For an interactive analyst, this is great. For an autonomous LLM, this is an unauditable escape hatch — the LLM can run any code, and the obligation system can't verify what was executed.

**Our approach:** Structured commands only. No arbitrary code execution. Every command has a defined input schema and output schema. The obligation system can trace exactly what was asked and what was returned.

---

## Deep Analysis: mrexodia/ida-pro-mcp (most popular)

### Where it falls short

1. **Plugin-based.** Requires IDA GUI running with the plugin loaded. Not headless. Can't be used in automated pipelines.
2. **Single database.** One binary at a time. Can't diff two binaries without closing one.
3. **No batch operations.** One function per call. No filtering, no sorting by complexity.
4. **Interactive-oriented prompts.** "Explain this function" / "What does this code do" — not "find all unsafe memcpy calls."
5. **idalib mode is optional.** The headless SSE path exists but is a secondary feature, not the primary architecture.

The `idalib-mcp` headless mode is closer to what we need but it's a thin wrapper — same single-function-at-a-time interface.

---

## What None of Them Have

| Capability | ida-mcp | ida-pro-mcp | IDAssistMCP | Ours |
|---|---|---|---|---|
| Headless (no GUI) | Yes (idalib) | Optional | No | Yes |
| Multi-database | Yes | No | No | Yes |
| Batch decompile with filter DSL | No | No | No | **Yes** |
| Pattern search (dangerous_function, unchecked_length) | No | No | No | **Yes** |
| Function index (complexity, blast radius, reachability) | No | No | No | **Yes** |
| Binary diff | No | No | No | **Yes** |
| Function diff with summary signal | No | No | No | **Yes** |
| Mitigation analysis in metadata | No | No | No | **Yes** |
| Decompilation cache | No | No | No | **Yes** |
| Annotation provenance (source tracking) | No | No | No | **Yes** |
| Obligation-system integration | No | No | No | **Yes** |
| Structured-only (no arbitrary code execution) | No (has execute) | No (has script) | No | **Yes** |

---

## Our Unfair Advantages

1. **Filter-first, decompile-second.** Every competitor decompiles to analyze. We filter on cheap metadata (xrefs, function index) first, decompile only the matches. 100x fewer decompilation calls for the same analytical question.

2. **Built-in vulnerability patterns.** The LLM doesn't read pseudocode and guess. The MCP runs deterministic pattern checks and returns confirmed matches. The obligation system can cite "search_pattern(dangerous_function) confirmed unchecked memcpy at 0x4012b8" — not "the LLM thought it saw a memcpy."

3. **Purpose-built for autonomous research, not interactive assistance.** Every competitor designs for "human asks, LLM answers." We design for "LLM hypothesizes, MCP confirms/denies, evidence graph records." Different interaction model, different command set.

4. **Diff as a first-class operation.** N-day research starts with a diff. Every competitor requires manual function-by-function comparison. We return the structural diff in one call with security-relevant signals.

5. **Evidence auditability.** Every command has a `request_id`. Every response is stored. The obligation system can prove "the LLM was shown function X's decompilation at turn N" or "the LLM was never shown the mitigation analysis." No competitor tracks this.

---

## What jtsylve/ida-mcp Has That We Should Learn From

Don't ignore what they got right:

1. **idalib over -S script approach.** idalib is cleaner than spawning `idat64 -Sscript.py`. Direct function calls vs IPC. If we can use idalib with IDA 9.0, we should. If not (licensing, version issues), the bridge worker approach is the fallback.

2. **`execute` for power users.** Our structured-only approach is correct for LLM safety, but we should offer an operator-only `execute_script` command that humans can use for ad-hoc analysis. Gated behind `source: operator`, not available to the LLM.

3. **FastMCP decorator API.** Clean, minimal boilerplate. We should use the same SDK.

4. **Daemon persistence.** Workers surviving client disconnects is the right design. We already plan this (idle timeout with warm process pool).

5. **Thread safety solution.** The `MainThreadExecutor` + `@ida_dispatch` pattern is well-engineered. We should adopt it if using idalib.

---

## Decision: idalib vs Bridge Worker

Two paths to headless IDA:

**Path A: idalib (like jtsylve/ida-mcp)**
- IDA runs as a Python library inside our process
- Direct function calls to ida_* APIs
- Single-threaded constraint (main thread only)
- Requires IDA Pro 9.0+ with idalib support
- Clean, fast, no IPC overhead

**Path B: Bridge worker (our original plan)**
- Spawn `idat64 -A -Sworker.py binary`
- IDA runs in a separate process, bridge speaks JSON-RPC over TCP
- Works with any IDA version that supports -A -S
- IPC overhead (TCP JSON per call)
- More complex process management

**Recommendation: Try idalib first.** IDA 9.0 supports it. If it works with the installed license at `C:\Program Files\IDA Professional 9.0\ida64.exe`, we get a cleaner architecture with less code. If idalib doesn't work (licensing, platform issues), fall back to the bridge approach.

The API surface (tools exposed to the LLM) is identical either way. The backend is an implementation detail.

---

## Benchmarks We Should Publish

To prove we're better, measure and publish:

| Benchmark | What it measures | How |
|---|---|---|
| **Filter query latency** | "All functions calling memcpy with complexity > 10" | Time from query to results. Ours: 1 call, <5s. Theirs: 50+ calls, minutes. |
| **N-day diff workflow** | "Diff two versions, identify the security patch" | Total calls and tokens. Ours: 2 calls (diff_binary + diff_function). Theirs: 100+ calls. |
| **Pattern search coverage** | "Find all dangerous function calls in a 5000-function binary" | Ours: 1 call, deterministic, complete. Theirs: LLM reads 5000 decomps and guesses. |
| **Token efficiency** | Total LLM tokens consumed per analytical question | Ours should be 10-50x less due to server-side filtering. |
| **Decompile cache hit rate** | Cache hits across a 30-turn VR session | Measure how many decompile calls hit cache vs cold decompile. |
| **Total analysis time** | Full N-day workflow: load binary -> diff -> root cause -> PoC | End-to-end wall clock. |

Build the benchmark suite as part of the integration tests. Run against jtsylve/ida-mcp on the same binary with the same questions. Publish the numbers.
