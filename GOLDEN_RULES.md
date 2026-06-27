# Golden Rules -- ida-headless-mcp

32 non-negotiable rules for this codebase.
Derived from: AILA GOLDEN_RULES.md, a VR exploit dev who hates false positives,
a malware analyst who's seen tools lie, and the open-source mob that will tear
this apart on Twitter the moment we publish.

---

## Council

- **Linus** (Kernel Lord): No abstraction cancer. No silent failures.
- **Kira** (Exploit Dev): Every proof must say how complete it is. No false confidence.
- **Mace** (Malware Analyst): Every detection must work on real samples or it doesn't ship.
- **Nyx** (Red Team): If the output can't be acted on, it's waste.
- **Mob** (Twitter/Reddit): If it doesn't work on their binary, it's over.

---

## Architecture (8 rules)

1. **Server NEVER imports idalib.** Not today, not in a hotfix, not "just for this one thing." The separation is the architecture. Break it and everything collapses.

2. **Every tool returns in <2 seconds or says WHY it can't.** The pending response must include: worker_action, worker_phase, queue_depth, and a human-readable message. "pending" alone is banned.

3. **One source of truth per datum.** Function index is in `index.json`. Decompile cache is in `decompile/`. Results are in `results/`. No tool stores results in two places. No tool reads from a source it doesn't own.

4. **Workers are cattle, not pets.** Any worker can die at any moment. The arbiter respawns them. No tool assumes a worker is alive. No state lives only in worker memory -- everything is persisted to cache before the tool returns "ready."

5. **No blocking the MCP server thread.** The server is single-threaded (FastMCP). Any computation over 100ms goes to a worker. The arbiter runs in a daemon thread. Zero sleep() in the server hot path.

6. **Filesystem is the IPC channel.** No shared memory, no sockets between server and workers, no multiprocessing.Queue. Files are debuggable, inspectable, and survive crashes. This is a feature.

7. **Cache key must be deterministic from tool inputs.** Given the same (binary_id, tool_name, key), the cache file path is always the same. No timestamps, no random suffixes, no race-prone paths.

8. **Mutations are serialized per-binary.** Write queue processes one mutation at a time. Generation counter increments atomically. Reads never see partial writes.

---

## Correctness (8 rules)

9. **No silent None returns.** If a function can't produce a result, it raises or returns an error dict with `"error"` key. Returning None and hoping the caller checks is a bug factory.

10. **Every detection tool reports false positive rate.** If you can't measure it, at least document WHAT triggers false positives. "AES S-box matched in CRT data section" is honest. Silent match without context is a lie.

11. **Every proof tool reports coverage.** `proof_coverage: {gates_encoded: 5, gates_total: 7, coverage_pct: 71}`. A partial proof presented as complete is worse than no proof.

12. **Endianness must be explicit.** Crypto signatures, constant matchers, and binary readers must document and handle both LE and BE. No implicit "it works on my x86 test" that breaks on ARM samples.

13. **Function resolution must handle all IDA name forms.** `sub_140001000`, `0x140001000`, `_main`, `main`, `?mangled@name`. Every tool that takes `address_or_name` must resolve through the same `_resolve_address` helper.

14. **No heuristic without a threshold constant.** `MIN_NUMBER_OF_MOVS = 5`, `MIN_BB_BYTE_COUNT = 4`. Magic numbers in if-statements are invisible design decisions. Name them.

15. **Test on at least 3 binary sizes.** Every tool must be verified on: a small binary (<100KB), a medium binary (1-5MB), and a large binary (10MB+). A tool that only works on test_crypto.exe is a demo, not a tool.

16. **CTree node coverage must be documented.** `ctree_to_smt.py` handles N of 80+ node types. The README/docstring must say which ones. New proofs that hit unsupported nodes must degrade gracefully with a warning, not silently produce garbage.

---

## Code Quality (8 rules)

17. **No `except Exception: pass`.** 10 instances in this codebase right now. Every one is a bug waiting to happen. Catch specific exceptions. Log or propagate the rest.

18. **No god objects.** `session.py` has a 72-method class. Split by domain: decompile methods, detection methods, proof methods, mutation methods. Each group gets its own mixin or module.

19. **Every public function has a Google-style docstring.** 60 functions missing docstrings right now. Args, Returns, Raises. No exceptions.

20. **No function with 7+ parameters.** 12 instances right now. Use dataclasses or typed dicts for parameter groups. `batch_decompile` has 16 params -- that's not a function, it's a config file.

21. **One file, one responsibility.** `session.py` is 3287 lines doing everything from decompile to YARA to CAPA to stack strings. Split it. 500 lines per file maximum for implementation files.

22. **Hardcoded paths are banned.** `config.py` line 81 has a Windows path. All paths come from settings or environment. Zero assumptions about where IDA or the cache lives.

23. **Every `except` block either logs or re-raises.** If you catch an exception and do nothing with it, you just made the next bug unfindable. Write to stderr, write to error file, or don't catch.

24. **No duplicate pattern implementations.** `_resolve_address` appears in session.py AND binary_worker.py. One canonical implementation, imported by both.

---

## OSS Readiness (8 rules)

25. **README examples must be reproducible.** Every code block in README must work on a fresh clone with a fresh binary. No references to specific malware hashes, internal paths, or tools the user doesn't have.

26. **No leaked paths, hashes, or evidence in git history.** `.gitignore` blocks `*.exe`, `cache/`, `evidence/`, `malware_files/`. `filter-branch` applied before any public push. Check with `git log --all -p | grep -i "C:\\Users"`.

27. **Error messages must be actionable.** "Failed" is not an error message. "open_database failed: .i64 not found at /path/to/workspace/target.exe.i64 -- run open_binary first" is.

28. **No dependency on global state initialization order.** If tool A must be called before tool B, the error from B must say so. No silent empty results because the user called things in the wrong order.

29. **Performance claims must be measured.** Every number in README must have a reproducible benchmark command. "4ms" means you ran it. Not "should be about 4ms."

30. **CHANGELOG exists.** Every version bump gets a human-readable changelog entry. Users who update deserve to know what broke.

31. **Contributing guide exists.** How to add a new tool. How to add a new detection signature. How to run the test suite. Without this, PRs are impossible.

32. **License is clear and unambiguous.** AGPL-3.0 for the main code. MIT for binbit. Apache-2.0 for CAPA rules data. No gray areas.

---

## Enforcement

Run before every commit:

```bash
python -m py_compile src/ida_headless_mcp/*.py         # syntax
python -m ruff check src/ --select E,F,W               # lint
python -c "import ast, sys; [ast.parse(open(f).read()) for f in sys.argv[1:]]" src/ida_headless_mcp/*.py  # parse
```

Rules that should be programmatically enforced (future):

| Check | Rules |
|---|---|
| No bare `except Exception: pass` | 17, 23 |
| No functions with 7+ params | 20 |
| All public functions have docstrings | 19 |
| No hardcoded paths | 22 |
| `__all__` in every module | AILA-16 |
| No TODO in committed code | AILA-9 |
| No silent None returns from tools | 9 |
| Duplicate `_resolve` implementations | 24 |
| Mixed error semantics (raise AND return error dict) | 9, 27 |
| `sha` vs `sha256` parameter naming | 13 |
| `import json as _json` inside functions (use top-level) | AILA-15 |
| Return key naming: `_found` vs `_count` vs `_total` (pick one per concept) | 28 |
| Magic numbers > 100 without named constant | 14 |

---

## Current Violations (honest accounting)

### Structural (blocking release)

| Rule | Violations | Fix |
|---|---|---|
| 17 (no silent except) | 12 remain (all typed, need inline comments) | Add `# reason` to pass lines |
| 18 (no god objects) | 3 classes: session.py (72), lifecycle.py (21), cache_reader.py (15) | Split session.py by domain |
| 19 (docstrings) | 60 public functions missing | Add Google-style docstrings |
| 20 (7+ params) | 12 functions | Use typed dicts or dataclasses |
| 21 (file size) | 3 files >1000 LOC: session(3287), server(1913), hexrays(1700) | Split by responsibility |

### Consistency (quality gate)

| Finding | Count | Fix |
|---|---|---|
| Duplicate `_resolve_address` / `_resolve` | 3 files (binary_worker, cache_reader, session) | Single canonical impl, import everywhere |
| Mixed error semantics (raise + error dict) | 8 functions in session.py | Pick one: raises for programmer errors, error dict for expected failures |
| `sha` vs `sha256` naming | 1 instance in lifecycle.py (`_evict_worker`) | Rename to `sha256` |
| `import json as _json` in function bodies | 5 sites (server, detection, binary_worker) | Import at module level or use existing import |
| Return key naming chaos | `_count` (9), `_found` (6), `_total` (9) | Convention: `X_count` for how many, `X_found` for search results, `total_X` for aggregates |
| Magic number 128 (angr state limit) | 1 in hexrays_analysis | `MAX_ACTIVE_STATES = 128` |
| Magic number 259 (STILL_ACTIVE) | 1 in lifecycle | Already has comment, acceptable |
| `binary_id` added to result inconsistently | 21 `result["binary_id"]=` vs 32 inline in dict literal | Pick one pattern: always add post-hoc in server.py, never in session.py |

### Dead code suspects

| Function | File | Evidence |
|---|---|---|
| `_check_dead_code` | detection.py | Only appears once (definition) |
| `_check_opaque_predicates` | detection.py | Only appears once (definition) |
| `_collect_metadata` | session.py | Only appears once (definition) |
| `_touch_manifest` | session.py | Only appears once (definition) |
| `_workspace_path` | session.py | Only appears once (definition) |

---

## Conventions (decided)

| Topic | Convention | Rationale |
|---|---|---|
| Error reporting | Tools return `{"error": "msg"}` for expected failures. Raise `ValueError`/`KeyError` for programmer errors (invalid binary_id, bad address). | Agents can handle error dicts; raises become MCP error responses. |
| Address format | Always `f"0x{ea:x}"` (lowercase hex, 0x prefix) | Consistent, matches IDA display. |
| Parameter naming | `binary_id`, `sha256`, `address_or_name` | Never abbreviate: no `sha`, `addr`, `bid`. |
| Return key style | `snake_case`. Counts: `X_count`. Search results: `X_found`. Aggregates: `total_X`. | Predictable for agent JSON parsing. |
| Imports | Module-level for stdlib/project. Inside functions ONLY for `ida_*` (which crash server). | `import json as _json` inside functions is banned. |
| `binary_id` in results | session.py methods do NOT add binary_id. server.py adds it post-hoc (`cached["binary_id"] = binary_id`). | Single responsibility: session doesn't know its own binary_id. |