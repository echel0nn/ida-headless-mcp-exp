# Agent Guidelines — ida-headless-mcp

## Who consumes this MCP server

LLM agents (Claude, GPT, Codex) call our 69 tools to analyze binaries. They don't see our source code. They see tool names, descriptions, and return values. Everything we expose must make sense to an agent that has never seen IDA Pro.

## Tool design principles for agents

### 1. Tools are self-contained queries

An agent should be able to call ONE tool and get a useful answer. Don't force multi-step workflows unless the data genuinely requires it (e.g., open_binary must precede decompile — that's real dependency, not artificial sequencing).

### 2. Pending is not failure

When a tool returns `{"status": "pending"}`, it means "ask me again in a few seconds." The agent MUST retry. The pending response includes enough diagnostics for the agent to decide whether to wait or move on:
- `worker_action`: what the server did (alive/spawning/queued/not_ready)
- `worker_phase`: what the worker is doing (bootstrapping/loading/idle/processing)
- `queue_depth`: how many items ahead of this request
- `message`: human-readable explanation

### 3. Error semantics

- `{"status": "ready", ...}` — tool completed, results inline
- `{"status": "pending", ...}` — in progress, retry later
- `{"error": "..."}` — tool failed permanently, don't retry
- A tool that returns ready with empty results is CORRECT (binary has no crypto, function has no stack strings). Don't confuse "nothing found" with "broken."

### 4. Binary lifecycle

Agents must follow this sequence:
```
open_binary(path)         → binary_id + state (may be ANALYZING)
poll_analysis(binary_id)  → wait until state == READY
<any tool>(binary_id)     → results or pending (worker spawns automatically)
```

There's no need to explicitly start workers. The arbiter handles it.

### 5. Tool categories by blocking behavior

**Instant (server-side, no worker):**
- `list_binaries`, `binary_metadata`, `worker_status`, `poll_analysis`
- `checksec`, `segments` (reads PE header directly)
- `diff_binary`, `diff_function`, `diff_survey` (reads cached indexes)
- `find_similar_functions`, `cross_binary_similarity`
- `call_chain`, `list_functions` (reads cached index)
- `miasm_disassemble`, `miasm_lift_ir`, `miasm_simplify_expression`, `miasm_emulate` (reads raw PE bytes, multi-arch)

**Fast (worker processes in <1s):**
- `decompile`, `xrefs_to`, `xrefs_from`, `call_graph`
- `detect_obfuscation`, `detect_stack_strings`, `classify_strings`
- `generate_yara_rule`, `detect_anti_analysis`, `classify_behavior`

**Medium (worker processes in 1-10s):**
- `capa_scan`, `detect_crypto_primitives`, `recover_class_hierarchy`
- `binary_survey`, `entropy_analysis`, `imports`, `exports`
- `prove_overflow`, `prove_bounds_sufficient`

**Slow (10s+, scales with binary size):**
- `search_pattern` (decompiles all functions)
- `batch_decompile` (N functions)
- `interprocedural_taint` (walks call graph)
- `assess_exploitability` (recursive taint + gate analysis)

### 6. What agents should NOT do

- Don't call `worker_status` in a loop to monitor. Just call the tool again.
- Don't open the same binary twice. `open_binary` is idempotent — second call returns existing binary_id.
- Don't assume function names are stable across sessions. Use addresses (0x...) for reliability.
- Don't pass malformed hex addresses. Always prefix with `0x`.

## Agent workflow examples

### Triage an unknown binary
```
open_binary → poll_analysis → binary_survey → capa_scan → classify_behavior → detect_anti_analysis
```

### Find vulnerabilities
```
search_pattern(type="integer_overflow") → assess_exploitability(func, sink, arg) → prove_overflow(func, sink, arg)
```

### Reverse engineer C2 protocol
```
decompile(main) → classify_strings → imports → detect_protocol_state_machine(c2_handler)
```

### Compare malware variants
```
open_binary(sample_a) → open_binary(sample_b) → diff_survey(a, b) → cross_binary_similarity(a, b)
```

## Contributing a new tool

If you're adding a tool that agents will call:

1. **Name it as a verb phrase.** `detect_obfuscation` not `obfuscation_info`. `prove_overflow` not `overflow_check`.
2. **First param is always `binary_id: str`.** Consistency lets agents build workflows without reading docs.
3. **Return a flat dict, not nested.** Agents parse JSON. Deep nesting is hard to reason about.
4. **Include a `status` field.** Always `"ready"` or delegated to `_pending()`.
5. **Include `binary_id` in the response.** Agents juggle multiple binaries. They need to correlate.
6. **Document what "empty" means.** If `stack_strings_found: 0`, that's a real result, not an error.
