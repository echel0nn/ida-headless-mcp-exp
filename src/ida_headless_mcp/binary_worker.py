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
import threading
import time
from pathlib import Path
from typing import Any

__all__: list[str] = []

QUEUE_FILENAME = "request_queue.jsonl"
POLL_INTERVAL = 0.3
HEARTBEAT_INTERVAL = 2.0  # seconds between heartbeat writes


# Global mutable phase — the heartbeat thread reads this to know what to write
_current_phase: str = "starting"
_current_request: str = ""


def _write_heartbeat(sha_dir: Path, status: str, current_request: str = "") -> None:
    """Write worker heartbeat — proves liveness to the server."""
    hb = {
        "pid": __import__("os").getpid(),
        "timestamp": time.time(),
        "status": status,
        "current_request": current_request,
    }
    try:
        (sha_dir / "worker_heartbeat.json").write_text(
            json.dumps(hb, separators=(',', ':')), encoding="utf-8",
        )
    except OSError as exc:
        print(f"[heartbeat] WRITE FAILED: {exc}", file=sys.stderr, flush=True)


def _write_error(sha_dir: Path, req_type: str, error: str, detail: str = "") -> None:
    """Persist a request processing error so the server can report it."""
    err = {
        "timestamp": time.time(),
        "type": req_type,
        "error": error,
        "detail": detail[:500],
    }
    err_dir = sha_dir / "errors"
    err_dir.mkdir(parents=True, exist_ok=True)
    err_file = err_dir / f"{req_type}_{int(time.time())}.json"
    try:
        err_file.write_text(json.dumps(err, separators=(',', ':')), encoding="utf-8")
    except OSError:
        pass  # Error report write is best-effort; cannot recurse into _write_error if it itself fails



def _heartbeat_thread(sha_dir: Path, stop_event: threading.Event) -> None:
    """Background thread that writes heartbeat every 2s using global phase."""
    global _current_phase, _current_request
    print(f"[heartbeat] thread started for {sha_dir.name[:12]}", file=sys.stderr, flush=True)
    while not stop_event.is_set():
        _write_heartbeat(sha_dir, _current_phase, _current_request)
        stop_event.wait(HEARTBEAT_INTERVAL)


def run_worker(sha256: str, cache_dir: Path, idle_timeout: int = 900) -> None:
    """Run the worker loop: open the .i64, process queued requests, write cache.

    Args:
        sha256: SHA-256 of the binary; identifies its cache subdirectory.
        cache_dir: Root cache directory containing per-binary subdirs.
        idle_timeout: Seconds without activity before the worker exits.
    """
    print(f"[worker] STARTED sha={sha256[:12]} cache_dir={cache_dir}", file=sys.stderr, flush=True)
    sha_dir = cache_dir / sha256
    workspace = sha_dir / "workspace"
    queue_path = sha_dir / QUEUE_FILENAME

    # Find the binary in workspace
    exe_files = list(workspace.glob("*.exe")) + list(workspace.glob("*.EXE"))
    if not exe_files:
        _update_state(sha_dir, error="No binary found in workspace")
        sys.exit(1)
    binary_path = exe_files[0]

    # Start background heartbeat thread — writes every 2s regardless of main thread
    global _current_phase, _current_request
    _current_phase = "bootstrapping_idalib"
    stop_heartbeat = threading.Event()
    hb_thread = threading.Thread(
        target=_heartbeat_thread, args=(sha_dir, stop_heartbeat), daemon=True,
    )
    hb_thread.start()

    # Bootstrap IDA
    import time as _time
    _t0 = _time.perf_counter()
    print(f'[worker] t=0ms: starting bootstrap', file=sys.stderr, flush=True)
    src_dir = Path(__file__).resolve().parent.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    from ida_headless_mcp.bootstrap import bootstrap_ida
    from ida_headless_mcp.config import load_settings

    settings = load_settings()
    _t1 = _time.perf_counter()
    print(f'[worker] t={(_t1-_t0)*1000:.0f}ms: load_settings done, calling bootstrap_ida', file=sys.stderr, flush=True)
    ida_mod = bootstrap_ida(settings)
    _t2 = _time.perf_counter()
    print(f'[worker] t={(_t2-_t0)*1000:.0f}ms: bootstrap_ida done', file=sys.stderr, flush=True)

    try:
        ida_mod.enable_console_messages(False)
    except Exception:
        pass  # Optional API, not all IDA builds expose it

    # Clean stale locks
    for ext in ('.id0', '.id1', '.id2', '.nam', '.til'):
        stale = workspace / (binary_path.name + ext)
        if stale.exists():
            try:
                stale.unlink()
            except OSError:
                pass  # Lock file may not exist or be held by another process

    # Open database — serialized via file lock.
    # idalib loads processor modules, type libs, and plugins from the
    # shared IDA install dir. Concurrent open_database across workers
    # causes Windows DLL file contention and hangs indefinitely.
    # Workers acquire a lock before open_database and release after.
    _current_phase = "loading_database"
    _t3 = _time.perf_counter()
    print(f"[worker] t={(_t3-_t0)*1000:.0f}ms: acquiring idalib lock", file=sys.stderr, flush=True)
    lock_path = cache_dir / "idalib_open.lock"
    lock_fh = open(lock_path, "w")
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
    _t3b = _time.perf_counter()
    print(f"[worker] t={(_t3b-_t0)*1000:.0f}ms: lock acquired, calling open_database", file=sys.stderr, flush=True)
    rc = ida_mod.open_database(str(binary_path), True)
    # Release lock immediately after open_database returns
    if os.name == "nt":
        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
    lock_fh.close()
    _t3c = _time.perf_counter()
    print(f"[worker] t={(_t3c-_t0)*1000:.0f}ms: lock released", file=sys.stderr, flush=True)
    if rc != 0:
        _update_state(sha_dir, error=f"open_database failed with code {rc}")
        stop_heartbeat.set()
        sys.exit(1)

    _t4 = _time.perf_counter()
    print(f"[worker] t={(_t4-_t0)*1000:.0f}ms: open_database returned rc={rc}", file=sys.stderr, flush=True)
    import ida_funcs
    import ida_hexrays

    ida_hexrays.init_hexrays_plugin()

    # Update state to ACTIVE
    func_count = ida_funcs.get_func_qty()
    _update_state(sha_dir, state="ACTIVE", function_count=func_count,
                  worker_pid=__import__("os").getpid())

    _t5 = _time.perf_counter()
    print(f"[worker] t={(_t5-_t0)*1000:.0f}ms: hexrays init done, {func_count} functions", file=sys.stderr, flush=True)
    # Build index if not cached
    index_path = sha_dir / "index.json"
    if not index_path.exists():
        _current_phase = "building_index"
        from ida_headless_mcp.function_index import build_function_index
        index = build_function_index()
        index.save(index_path)
        _update_state(sha_dir, state="INDEXED", function_count=func_count)

    # Main loop: process requests from queue
    _current_phase = "idle"
    decompile_dir = sha_dir / "decompile"
    decompile_dir.mkdir(parents=True, exist_ok=True)
    results_dir = sha_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    patterns_dir = sha_dir / "patterns"
    patterns_dir.mkdir(parents=True, exist_ok=True)
    write_results_dir = sha_dir / "write_results"
    write_results_dir.mkdir(parents=True, exist_ok=True)
    write_queue_path = sha_dir / "write_queue.jsonl"

    from ida_headless_mcp.mutations import Generation

    gen = Generation(sha_dir)
    last_activity = time.monotonic()

    while True:
        if time.monotonic() - last_activity > idle_timeout:
            _current_phase = "exiting_idle"
            time.sleep(HEARTBEAT_INTERVAL + 0.5)
            break

        processed = False
        processed |= _consume_queue(
            write_queue_path,
            lambda req: _handle_mutation(req, sha_dir, gen, write_results_dir, decompile_dir),
            sha_dir,
        )
        processed |= _consume_queue(
            queue_path,
            lambda req: _dispatch_request(
                req, sha_dir, decompile_dir, patterns_dir, results_dir, gen,
            ),
            sha_dir,
        )
        if processed:
            last_activity = time.monotonic()
        else:
            time.sleep(POLL_INTERVAL)


def _consume_queue(queue_path: Path, handler, sha_dir: Path) -> bool:
    """Read and consume a JSONL queue, calling handler per entry.

    On error: persists the error to sha_dir/errors/ so the server can report it.
    Never silently swallows exceptions.
    """
    if not queue_path.exists():
        return False
    try:
        raw = queue_path.read_text(encoding="utf-8").strip()
        if not raw:
            return False
        queue_path.write_text("", encoding="utf-8")
    except OSError:
        return False
    for line in raw.splitlines():
        try:
            req = json.loads(line)
            req_type = req.get("type", "unknown")
            global _current_phase, _current_request
            _current_phase = f"processing:{req_type}"
            _current_request = req_type
            handler(req)
            _current_phase = "idle"
            _current_request = ""
        except Exception as exc:
            _current_phase = "idle"
            _current_request = ""
            req_type = "unknown"
            try:
                req_type = json.loads(line).get("type", "unknown")
            except (ValueError, AttributeError):
                pass  # Malformed line; fall back to "unknown" req_type for error report
            _write_error(sha_dir, req_type, str(exc), __import__('traceback').format_exc())
            print(f"[binary_worker] {req_type} FAILED: {exc}", file=sys.stderr, flush=True)
    return True


def _dispatch_request(req, sha_dir, decompile_dir, patterns_dir, results_dir, gen):
    """Route a read request to the appropriate handler."""
    req_type = req.get("type", "")
    g = gen.read()
    if req_type == "decompile":
        _handle_decompile(req, decompile_dir, g)
    elif req_type == "search_pattern":
        _handle_search_pattern(req, sha_dir, patterns_dir, g)
    else:
        _handle_tool(req, sha_dir, results_dir, g)


def _handle_decompile(req, decompile_dir, current_gen):
    """Decompile one function, write to cache with generation stamp."""
    _t4 = _time.perf_counter()
    print(f"[worker] t={(_t4-_t0)*1000:.0f}ms: open_database returned rc={rc}", file=sys.stderr, flush=True)
    import ida_funcs
    import ida_hexrays
    import ida_name

    target = req.get("target", "")
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
        max_lines = req.get("max_lines", 200)
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
            "generation": current_gen,
        }
        cache_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        name = ida_name.get_ea_name(func.start_ea)
        if name:
            name_file = decompile_dir / f"{name}.json"
            if not name_file.exists():
                name_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"[binary_worker] decompile failed at 0x{ea:x}: {exc}", file=sys.stderr, flush=True)


def _handle_search_pattern(req, sha_dir, patterns_dir, current_gen):
    """Run pattern search using session manager engine."""
    pattern_type = req.get("pattern_type", "")
    cache_file = patterns_dir / f"{pattern_type}_v1.json"
    if cache_file.exists():
        return

    mgr = _build_session_stub(sha_dir)
    try:
        result = mgr.search_pattern(mgr._active_binary_id, pattern_type, limit=50)
        result["generation"] = current_gen
        cache_file.write_text(json.dumps(result, separators=(',', ':')), encoding="utf-8")
    except Exception as exc:
        # Persist error so server can report it instead of silent failure
        _write_error(sha_dir, f"search_pattern_{pattern_type}", str(exc),
                     __import__('traceback').format_exc())
        # Write a partial result so the server doesn't keep re-queuing
        error_result = {
            "binary_id": req.get("binary_id", ""),
            "pattern_type": pattern_type,
            "count": 0,
            "matches": [],
            "error": str(exc),
            "generation": current_gen,
        }
        cache_file.write_text(json.dumps(error_result, separators=(',', ':')), encoding="utf-8")


def _handle_tool(req, sha_dir, results_dir, current_gen):
    """Run any IDA tool via worker dispatch and cache the result.

    Translates queue request format to dispatch params format:
    - queue uses 'target' for address_or_name
    - dispatch expects 'binary_id' and 'address_or_name'
    """
    req_type = req.get("type", "")
    sha = sha_dir.name
    binary_id = f"b_{sha[:12]}"

    # Build dispatch params from queue request
    params = dict(req)
    params["binary_id"] = binary_id
    # Normalize field names: queue uses 'target', dispatch uses 'address_or_name'
    if "target" in params and "address_or_name" not in params:
        params["address_or_name"] = params.pop("target")

    # Cache key: prefer explicit _cache_key from server, fallback to address_or_name
    key = params.pop("_cache_key", "") or params.get("address_or_name", "")
    safe_key = key.replace("/", "_").replace("\\", "_").replace(":", "_")
    filename = f"{req_type}_{safe_key}.json" if safe_key else f"{req_type}.json"
    cache_file = results_dir / filename
    if cache_file.exists():
        return

    mgr = _build_session_stub(sha_dir)
    try:
        from ida_headless_mcp.worker import _dispatch
        result = _dispatch(mgr, req_type, params)
        if isinstance(result, dict):
            result["generation"] = current_gen
            cache_file.write_text(
                json.dumps(result, separators=(',', ':')), encoding="utf-8",
            )
    except Exception as exc:
        import sys
        print(f"[binary_worker] _handle_tool error: {req_type}: {exc}", file=sys.stderr, flush=True)
        err_file = results_dir / f"{req_type}_error.json"
        err_file.write_text(json.dumps({
            "error": str(exc), "type": req_type,
            "params": {k: str(v) for k, v in params.items()}
        }), encoding="utf-8")


def _handle_mutation(req, sha_dir, gen, write_results_dir, decompile_dir):
    """Apply a write mutation to the IDA database."""
    import ida_name

    ticket_id = req.get("ticket_id", "")
    mutation_type = req.get("type", "")
    params = req.get("params", {})
    result = {"ticket_id": ticket_id, "type": mutation_type, "status": "applied"}
    invalidated: list[str] = []

    try:
        if mutation_type == "rename_function":
            ea = int(params["address"], 16)
            ida_name.set_name(ea, params["new_name"])
            index_data = _load_index_data(sha_dir)
            from ida_headless_mcp.mutations import invalidate_for_rename
            invalidated = invalidate_for_rename(sha_dir, params["address"], index_data)

        elif mutation_type == "set_comment":
            import ida_bytes
            ea = int(params["address"], 16)
            ida_bytes.set_cmt(ea, params["comment"], False)
            from ida_headless_mcp.mutations import invalidate_for_comment
            invalidated = invalidate_for_comment(sha_dir, params["address"])

        elif mutation_type == "patch_bytes":
            import ida_bytes
            ea = int(params["address"], 16)
            data = bytes.fromhex(params["hex_bytes"])
            ida_bytes.patch_bytes(ea, data)
            index_data = _load_index_data(sha_dir)
            from ida_headless_mcp.mutations import invalidate_for_patch
            invalidated = invalidate_for_patch(sha_dir, params["address"], index_data)

        new_gen = gen.bump()
        result["generation"] = new_gen
        result["invalidated"] = invalidated
    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"

    if ticket_id:
        result_file = write_results_dir / f"{ticket_id}.json"
        result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")


def _build_session_stub(sha_dir: Path):
    """Build a minimal IDABinarySessionManager over the already-open database.

    The stub provides enough state for @requires decorators and all
    session methods to work. The binary is already loaded in this process,
    so the lifecycle stub always reports INDEXED state.
    """
    import ida_funcs
    import ida_segment

    from ida_headless_mcp.config import load_settings
    from ida_headless_mcp.function_index import FunctionIndex
    from ida_headless_mcp.lifecycle import BinaryLifecycle, BinaryState
    from ida_headless_mcp.session import BinaryRecord, IDABinarySessionManager

    settings = load_settings()
    sha = sha_dir.name
    binary_id = f"b_{sha[:12]}"

    # Read root_filename from persisted state
    root_filename = ""
    state_file = sha_dir / "state.json"
    if state_file.exists():
        try:
            _state = json.loads(state_file.read_text(encoding="utf-8"))
            root_filename = _state.get("root_filename", "")
        except (ValueError, OSError):
            pass  # State file unreadable/malformed; proceed with empty root_filename
    binary_path = sha_dir / "workspace" / root_filename if root_filename else sha_dir / "workspace"

    # Build section list from IDA segments
    sections = []
    seg = ida_segment.get_first_seg()
    while seg:
        sections.append({
            "name": ida_segment.get_segm_name(seg) or "",
            "start": f"0x{seg.start_ea:x}",
            "end": f"0x{seg.end_ea:x}",
            "size": seg.size(),
            "perm": seg.perm,
        })
        seg = ida_segment.get_next_seg(seg.start_ea)

    # Build mitigations from PE headers if available
    mitigations = {}
    try:
        import ida_entry
        mitigations["has_entry"] = ida_entry.get_entry_qty() > 0
    except ImportError:
        pass  # ida_entry not available in all IDA builds; mitigations stays empty

    mgr = IDABinarySessionManager.__new__(IDABinarySessionManager)
    mgr.settings = settings
    mgr._records = {}
    mgr._active_binary_id = binary_id
    mgr._indices = {}
    mgr._manifest_path = settings.cache_dir / "manifest.json"

    rec = BinaryRecord(
        binary_id=binary_id, path=binary_path,
        sha256=sha, size_bytes=binary_path.stat().st_size if binary_path.is_file() else 0,
        format="", arch="", bits=64,
        entry_points=[], function_count=ida_funcs.get_func_qty(),
        segment_count=len(sections), imports_count=0, exports_count=0,
        strings_count=0, mitigations=mitigations, sections=sections,
        active=True, root_filename=root_filename, analysis_ready=True,
    )
    mgr._records[binary_id] = rec

    # Stub lifecycle: binary is always INDEXED in the worker
    class _StubLifecycle:
        """Minimal lifecycle that @requires decorator can call."""
        def __init__(self, bid, s):
            self._lc = BinaryLifecycle(
                binary_id=bid, sha256=s, original_path="",
                root_filename="", size_bytes=0,
            )
            self._lc.state = BinaryState.INDEXED

        def get(self, bid):
            """Return the wrapped lifecycle instance."""
            return self._lc

        def _reconcile(self, lc):
            pass  # No-op: binary is already loaded

    mgr._lifecycle = _StubLifecycle(binary_id, sha)

    index_path = sha_dir / "index.json"
    if index_path.exists():
        mgr._indices[binary_id] = FunctionIndex.load(index_path)
    else:
        from ida_headless_mcp.function_index import build_function_index
        idx = build_function_index()
        idx.save(index_path)
        mgr._indices[binary_id] = idx

    return mgr


def _load_index_data(sha_dir: Path) -> list:
    """Load the cached function index as a list of dicts."""
    index_path = sha_dir / "index.json"
    if not index_path.exists():
        return []
    try:
        return json.loads(index_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


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
            pass  # State file unreadable/corrupt; updates will overwrite with fresh state
    state.update(updates)
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def main() -> int:
    """Entry point for worker subprocess."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--idle-timeout", type=int, default=900)
    args = parser.parse_args()

    # Redirect stderr to log file FIRST — before anything can crash
    log_dir = Path(args.cache_dir) / args.sha256 / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "worker_stderr.log"
    try:
        sys.stderr = open(log_file, "a", encoding="utf-8", buffering=1)  # line-buffered
    except OSError:
        pass  # Log file unavailable; keep original stderr so worker can still report errors

    print(f"[worker] PID={__import__('os').getpid()} sha={args.sha256[:12]} starting", file=sys.stderr, flush=True)

    try:
        run_worker(args.sha256, Path(args.cache_dir), args.idle_timeout)
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
