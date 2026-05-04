"""Unified binary worker — owns one .i64, processes all requests.

One worker per binary. Spawned by the lifecycle manager when the .i64
is ready. Watches request_queue.jsonl for work, processes it, writes
results to the shared cache directory.

The MCP server NEVER imports idalib. Only workers do.

Usage:
    python -m ida_headless_mcp.binary_worker \\
        --sha256 <hash> --cache-dir <path> --idle-timeout 900
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

__all__: list[str] = []

QUEUE_FILENAME = "request_queue.jsonl"
POLL_INTERVAL = 0.3


def run_worker(sha256: str, cache_dir: Path, idle_timeout: int = 900) -> None:
    """Run the worker loop: open the .i64, process queued requests, write cache.

    Args:
        sha256: SHA-256 of the binary; identifies its cache subdirectory.
        cache_dir: Root cache directory containing per-binary subdirs.
        idle_timeout: Seconds without activity before the worker exits.
    """
    sha_dir = cache_dir / sha256
    workspace = sha_dir / "workspace"
    queue_path = sha_dir / QUEUE_FILENAME

    # Find the binary in workspace
    exe_files = list(workspace.glob("*.exe")) + list(workspace.glob("*.EXE"))
    if not exe_files:
        _update_state(sha_dir, error="No binary found in workspace")
        sys.exit(1)
    binary_path = exe_files[0]

    # Bootstrap IDA
    src_dir = Path(__file__).resolve().parent.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    from ida_headless_mcp.bootstrap import bootstrap_ida
    from ida_headless_mcp.config import load_settings

    settings = load_settings()
    ida_mod = bootstrap_ida(settings)

    try:
        ida_mod.enable_console_messages(False)
    except Exception:
        pass

    # Clean stale locks
    for ext in ('.id0', '.id1', '.id2', '.nam', '.til'):
        stale = workspace / (binary_path.name + ext)
        if stale.exists():
            try:
                stale.unlink()
            except OSError:
                pass

    # Open database
    rc = ida_mod.open_database(str(binary_path), True)
    if rc != 0:
        _update_state(sha_dir, error=f"open_database failed with code {rc}")
        sys.exit(1)

    import ida_funcs
    import ida_hexrays

    ida_hexrays.init_hexrays_plugin()

    # Update state to ACTIVE
    func_count = ida_funcs.get_func_qty()
    _update_state(sha_dir, state="ACTIVE", function_count=func_count,
                  worker_pid=__import__("os").getpid())

    # Build index if not cached
    index_path = sha_dir / "index.json"
    if not index_path.exists():
        from ida_headless_mcp.function_index import build_function_index
        index = build_function_index()
        index.save(index_path)
        _update_state(sha_dir, state="INDEXED", function_count=func_count)

    # Main loop: process requests from queue
    decompile_dir = sha_dir / "decompile"
    decompile_dir.mkdir(parents=True, exist_ok=True)
    results_dir = sha_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    patterns_dir = sha_dir / "patterns"
    patterns_dir.mkdir(parents=True, exist_ok=True)

    last_activity = time.monotonic()

    while True:
        # Check idle timeout
        if time.monotonic() - last_activity > idle_timeout:
            break

        # Read queue
        if not queue_path.exists():
            time.sleep(POLL_INTERVAL)
            continue

        try:
            raw = queue_path.read_text(encoding="utf-8").strip()
            if raw:
                queue_path.write_text("", encoding="utf-8")  # consume
            else:
                time.sleep(POLL_INTERVAL)
                continue
        except OSError:
            time.sleep(POLL_INTERVAL)
            continue

        for line in raw.splitlines():
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue

            req_type = req.get("type", "")
            last_activity = time.monotonic()

            if req_type == "decompile":
                _handle_decompile(req, sha_dir, decompile_dir)
            elif req_type == "search_pattern":
                _handle_search_pattern(req, sha_dir, patterns_dir)
            elif req_type in ("imports", "exports", "xrefs_to", "xrefs_from",
                              "classify_behavior", "detect_anti_analysis",
                              "entropy_analysis", "binary_survey"):
                _handle_generic(req, sha_dir, results_dir)

    # Clean shutdown
    ida_mod.close_database(True)
    _update_state(sha_dir, state="READY", worker_pid=None)


def _handle_decompile(req: dict, sha_dir: Path, decompile_dir: Path) -> None:
    """Decompile one function, write to cache."""
    import ida_funcs
    import ida_hexrays
    import ida_name

    target = req.get("target", "")
    max_lines = req.get("max_lines", 200)

    # Resolve address
    ea = _resolve(target)
    if ea is None:
        return

    cache_file = decompile_dir / f"0x{ea:x}.json"
    if cache_file.exists():
        return

    func = ida_funcs.get_func(ea)
    if func is None:
        return

    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        pseudocode = str(cfunc)
        lines = pseudocode.splitlines()
        truncated = len(lines) > max_lines
        if truncated:
            lines = lines[:max_lines]

        result = {
            "address": f"0x{func.start_ea:x}",
            "name": ida_name.get_ea_name(func.start_ea),
            "size_bytes": func.size(),
            "pseudocode": "\n".join(lines),
            "line_count": len(lines),
            "truncated": truncated,
            "status": "ready",
        }
        cache_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

        # Also write under the name key for name-based lookups
        name = ida_name.get_ea_name(func.start_ea)
        if name:
            name_file = decompile_dir / f"{name}.json"
            if not name_file.exists():
                name_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    except Exception:
        pass


def _handle_search_pattern(req: dict, sha_dir: Path, patterns_dir: Path) -> None:
    """Run a pattern search, write result to cache."""
    pattern_type = req.get("pattern_type", "")
    cache_file = patterns_dir / f"{pattern_type}_v1.json"
    if cache_file.exists():
        return

    # Import the session manager to run the pattern search
    # This is the WORKER process — it has idalib loaded.

    # We can't easily instantiate a full session manager here,
    # but we can run the pattern logic directly.
    # For now, skip — patterns are cached from prior runs.
    # TODO: implement standalone pattern runner


def _handle_generic(req: dict, sha_dir: Path, results_dir: Path) -> None:
    """Handle generic tool requests by caching their results."""
    # TODO: implement per-tool handlers
    pass


def _resolve(address_or_name: str) -> int | None:
    """Resolve an address or symbol name to an effective address, or None."""
    import ida_idaapi
    import ida_name

    target = address_or_name.strip()
    if target.startswith(("0x", "0X")):
        return int(target, 16)
    try:
        return int(target)
    except ValueError:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, target)
        return None if ea == ida_idaapi.BADADDR else ea


def _update_state(sha_dir: Path, **updates: Any) -> None:
    """Update the lifecycle state.json."""
    state_path = sha_dir / "state.json"
    state: dict[str, Any] = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    state.update(updates)
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--idle-timeout", type=int, default=900)
    args = parser.parse_args()
    run_worker(args.sha256, Path(args.cache_dir), args.idle_timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
