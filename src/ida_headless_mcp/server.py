"""MCP server — pure cache reader, NEVER imports idalib.

Every tool call either:
  1. Returns a cached result instantly
  2. Queues a request for the background worker and returns {status: "pending"}

All IDA work happens in binary_worker processes spawned by the lifecycle manager.
The shared filesystem cache is the only communication channel.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .cache_reader import CacheReader
from .config import load_settings
from .lifecycle import BinaryState, LifecycleManager

__all__ = ["create_server", "main", "main_http"]

mcp = FastMCP(
    "IDA Headless MCP",
    json_response=True,
    host="127.0.0.1",
    port=int(os.environ.get("IDA_HEADLESS_MCP_PORT", "18820")),
)


import threading
import time as _time



class _Frontend:
    """Pure cache reader and lifecycle manager with zero IDA imports."""

    def __init__(self) -> None:
        self.settings = load_settings()
        self.cache = CacheReader(self.settings.cache_dir)
        self.lifecycle = LifecycleManager(
            self.settings.cache_dir,
            self.settings.ida_dir,
            max_workers=self.settings.max_concurrent_ida,
        )
        self.lifecycle.recover_all()
        self._binaries: dict[str, dict[str, Any]] = {}
        # Server-side task execution state
        self._server_lock = threading.Lock()
        self._server_inflight: dict[str, bool] = {}
        from concurrent.futures import ThreadPoolExecutor
        self._thread_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix='srv')
        # Rebuild binary registry from recovered lifecycles
        for lc in self.lifecycle.all():
            self._binaries[lc.binary_id] = {
                "binary_id": lc.binary_id,
                "sha256": lc.sha256,
                "path": lc.original_path,
                "root_filename": lc.root_filename,
                "size_bytes": lc.size_bytes,
                "state": lc.state.name,
                "function_count": lc.function_count,
            }

    def _sha(self, binary_id: str) -> str:
        rec = self._binaries.get(binary_id)
        if rec is None:
            raise KeyError(f"Unknown binary_id: {binary_id}")
        return rec["sha256"]

    def _workspace_binary(self, sha: str) -> Path:
        """Return the path to the original binary in the workspace dir."""
        ws = self.settings.cache_dir / sha / "workspace"
        skip_suffixes = {".i64", ".idb", ".asm", ".id0", ".id1", ".id2", ".nam", ".til"}
        for ext in ("*.exe", "*.EXE", "*.dll", "*.DLL", "*.sys", "*.SYS", "*.so", "*.dylib", "*"):
            hits = list(ws.glob(ext))
            hits = [h for h in hits if h.suffix.lower() not in skip_suffixes]
            if hits:
                return hits[0]
        raise FileNotFoundError(f"No binary found in {ws}")

    def _pending(self, binary_id: str, lc: Any, worker_action: str = "") -> dict[str, Any]:
        """Build an informative pending response with worker diagnostics."""
        import time as _time

        sha = self._sha(binary_id)
        result: dict[str, Any] = {
            "binary_id": binary_id,
            "status": "pending",
            "state": lc.state.name if lc else "UNKNOWN",
            "queue_depth": self.cache.queue_depth(sha),
        }

        # What did ensure_worker do?
        if worker_action:
            result["worker_action"] = worker_action

        # Read heartbeat for granular worker phase
        hb_path = self.settings.cache_dir / sha / "worker_heartbeat.json"
        if hb_path.exists():
            try:
                hb = json.loads(hb_path.read_text(encoding="utf-8"))
                age = int(_time.time() - hb.get("timestamp", 0))
                result["worker_phase"] = hb.get("status", "unknown")
                result["heartbeat_age_s"] = age
                result["worker_pid"] = hb.get("pid")
            except (ValueError, OSError):
                # Best-effort heartbeat read for diagnostics; missing or corrupt
                # heartbeat just leaves worker_phase/age/pid unset in the response.
                pass

        # Build a human-readable message from best available info
        action_messages = {
            "alive": "Worker is running. Result will be cached shortly.",
            "spawning": "Worker is starting. IDA bootstrap takes ~15s, then your request processes.",
            "queued": "Worker queued. Arbiter spawns on next tick (~2s).",
            "spawn_failed": "CRITICAL: Worker failed to start. Check logs/ directory.",
            "not_ready": "Binary is still being analyzed by idat64. Poll with poll_analysis().",
        }
        phase_messages = {
            "bootstrapping_idalib": "Worker is bootstrapping IDA (~10s).",
            "loading_database": "Worker is loading the .i64 database.",
            "building_index": "Worker is building function index.",
            "idle": "Worker is idle, processing queue now.",
            "ready": "Worker just started, processing queue now.",
        }
        phase = result.get("worker_phase", "")
        if worker_action and worker_action in action_messages:
            result["message"] = action_messages[worker_action]
        elif phase and phase in phase_messages:
            result["message"] = phase_messages[phase]
        elif phase and phase.startswith("processing"):
            result["message"] = f"Worker is {phase}. Your request is queued."
        elif result.get("worker_pid"):
            result["message"] = "Worker is running. Your request is queued."
        else:
            result["message"] = "No worker detected. Request queued but may not process."

        return result

    def _cached_or_pending(
        self,
        binary_id: str,
        tool: str,
        key: str = "",
        params: dict | None = None,
    ) -> dict[str, Any]:
        """Return a cached tool result, or queue the request and return pending."""
        sha = self._sha(binary_id)
        lc = self.lifecycle.get(binary_id)
        if lc and lc.state < BinaryState.READY:
            return self._pending(binary_id, lc, "not_ready")
        cached = self.cache.get_result(sha, tool, key)
        if cached:
            cached["binary_id"] = binary_id
            cached["status"] = "ready"
            return cached
        # Queue the request and ensure worker is alive to process it
        self.cache.queue_request(sha, tool, params or {})
        worker_action = self.lifecycle.ensure_worker(binary_id)
        return self._pending(binary_id, lc, worker_action)



    def server_task(
        self,
        binary_id: str,
        tool_name: str,
        key: str,
        func: Any,
    ) -> dict[str, Any]:
        """Return cached result or spawn in-process background computation.

        Same contract as _cached_or_pending but runs func in a daemon
        thread instead of queuing to a worker subprocess. For tools that
        operate on raw PE bytes (CFF, string decrypt, capability scan).
        """
        sha = self._sha(binary_id)
        cached = self.cache.get_result(sha, tool_name, key)
        if cached:
            cached['binary_id'] = binary_id
            cached['status'] = 'ready'
            return cached
        task_key = f'{sha}:{tool_name}:{key}'
        with self._server_lock:
            if task_key in self._server_inflight:
                return {'binary_id': binary_id, 'status': 'pending',
                        'message': 'Computation in progress.'}
            self._server_inflight[task_key] = True
        safe_key = key.replace('/', '_').replace('\\', '_').replace(':', '_')
        filename = f'{tool_name}_{safe_key}.json' if safe_key else f'{tool_name}.json'
        result_dir = self.settings.cache_dir / sha / 'results'
        result_dir.mkdir(parents=True, exist_ok=True)
        cache_file = result_dir / filename
        def _bg():
            try:
                result = func()
                if isinstance(result, dict):
                    result['status'] = 'ready'
                    tmp = cache_file.with_suffix('.tmp')
                    tmp.write_text(
                        json.dumps(result, indent=2, default=str),
                        encoding='utf-8')
                    os.replace(tmp, cache_file)
            except (ValueError, RuntimeError, KeyError, TypeError, OSError) as exc:
                err = {'status': 'error', 'error': str(exc)}
                tmp = cache_file.with_suffix('.tmp')
                tmp.write_text(json.dumps(err), encoding='utf-8')
                os.replace(tmp, cache_file)
            finally:
                with self._server_lock:
                    self._server_inflight.pop(task_key, None)
        self._thread_pool.submit(_bg)
        return {'binary_id': binary_id, 'status': 'pending',
                'message': f'{tool_name} started. Poll again for result.'}

_frontend_lock = threading.Lock()
_frontend_instance: _Frontend | None = None


def _fe() -> _Frontend:
    """Thread-safe singleton accessor for the frontend."""
    global _frontend_instance
    if _frontend_instance is not None:
        return _frontend_instance
    with _frontend_lock:
        if _frontend_instance is None:
            _frontend_instance = _Frontend()
    return _frontend_instance


# ======================================================================
# TOOLS — lifecycle management (no IDA needed)
# ======================================================================


@mcp.tool()
def open_binary(path: str) -> dict:
    """Open a binary for analysis.

    Returns instantly. Heavy analysis runs in the background worker;
    poll progress with poll_analysis.

    Args:
        path: Filesystem path to the binary.

    Returns:
        Binary registration record with binary_id, sha256, lifecycle
        state, function count, and PE mitigations when applicable.
    """
    fe = _fe()
    target = Path(path).resolve()
    if not target.is_file():
        return {"status": "error", "message": f"File not found: {path}"}

    h = hashlib.sha256()
    with target.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    sha256 = h.hexdigest()
    binary_id = f"b_{sha256[:12]}"

    if binary_id in fe._binaries:
        lc = fe.lifecycle.get(binary_id)
        fe.lifecycle._reconcile(lc)
        fe._binaries[binary_id]["state"] = lc.state.name
        fe._binaries[binary_id]["function_count"] = lc.function_count
        return fe._binaries[binary_id]

    lc = fe.lifecycle.register(binary_id, sha256, target, target.stat().st_size)

    from .cache_reader import pe_mitigations

    is_pe = target.suffix.lower() in {".exe", ".dll", ".sys"}
    mitigations = pe_mitigations(target) if is_pe else {"type": "unknown"}

    rec = {
        "binary_id": binary_id,
        "sha256": sha256,
        "path": str(target),
        "root_filename": target.name,
        "size_bytes": target.stat().st_size,
        "format": "Portable executable for AMD64 (PE)" if is_pe else "unknown",
        "state": lc.state.name,
        "function_count": lc.function_count,
        "mitigations": mitigations,
    }
    fe._binaries[binary_id] = rec
    return rec


@mcp.tool()
def close_binary(binary_id: str, save: bool = False) -> dict:
    """Close a binary and remove it from the active session registry.

    Args:
        binary_id: Opaque handle from open_binary.
        save: Persist analysis on close.

    Returns:
        Acknowledgement record with binary_id and a closed flag.
    """
    fe = _fe()
    fe._binaries.pop(binary_id, None)
    return {"binary_id": binary_id, "closed": True}


@mcp.tool()
def list_binaries() -> list:
    """List all registered binaries with their current lifecycle state.

    Returns:
        List of binary records, each with id, sha256, path, state,
        and function count.
    """
    fe = _fe()
    result = []
    for bid, rec in fe._binaries.items():
        lc = fe.lifecycle.get(bid)
        if lc:
            fe.lifecycle._reconcile(lc)
            rec["state"] = lc.state.name
            rec["function_count"] = lc.function_count
        result.append(rec)
    return result


@mcp.tool()
def binary_metadata(binary_id: str) -> dict:
    """Return metadata for a registered binary.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Binary record with current lifecycle state and function count,
        or an error if the id is unknown.
    """
    fe = _fe()
    rec = fe._binaries.get(binary_id)
    if rec is None:
        return {"status": "error", "message": f"Unknown binary_id: {binary_id}"}
    lc = fe.lifecycle.get(binary_id)
    if lc:
        fe.lifecycle._reconcile(lc)
        rec["state"] = lc.state.name
        rec["function_count"] = lc.function_count
    return rec


@mcp.tool()
def poll_analysis(binary_id: str) -> dict:
    """Check analysis progress for a binary.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Lifecycle state including analysis_ready, index_ready,
        function_count, queue_depth, and any error.
    """
    fe = _fe()
    lc = fe.lifecycle.get(binary_id)
    if lc is None:
        return {"status": "error", "message": f"Unknown binary_id: {binary_id}"}
    fe.lifecycle._reconcile(lc)
    return {
        "binary_id": binary_id,
        "state": lc.state.name,
        "analysis_ready": lc.state >= BinaryState.READY,
        "index_ready": lc.state >= BinaryState.INDEXED,
        "function_count": lc.function_count,
        "queue_depth": fe.cache.queue_depth(lc.sha256),
        "error": lc.error,
    }


@mcp.tool()
def worker_status() -> dict:
    """Return status of all binary workers: heartbeat, queue depth, errors.

    Reads directly from filesystem \u2014 no worker needed. Use to diagnose
    why tools return 'pending' (worker dead, stuck, or still processing).

    Returns:
        Per-binary worker status with heartbeat age, queue depth,
        recent errors, and process liveness.
    """
    import time

    fe = _fe()
    workers: list[dict] = []
    cache_dir = fe.settings.cache_dir
    if not cache_dir.exists():
        return {"workers": [], "total": 0}

    for d in sorted(cache_dir.iterdir()):
        if not d.is_dir() or len(d.name) != 64:
            continue
        sha = d.name
        binary_id = f"b_{sha[:12]}"
        info: dict = {"binary_id": binary_id, "sha256_short": sha[:12]}

        # Heartbeat
        hb = d / "worker_heartbeat.json"
        pid = None
        hb_status = ""
        hb_age = -1
        if hb.exists():
            try:
                h = json.loads(hb.read_text(encoding="utf-8"))
                pid = h.get("pid")
                hb_status = h.get("status", "")
                hb_age = int(time.time() - h.get("timestamp", 0))
                info["worker_pid"] = pid
                info["heartbeat_age_s"] = hb_age
                info["current_request"] = h.get("current_request", "")
            except (ValueError, OSError):
                hb_status = "heartbeat_corrupt"

        # Queue depth
        q = d / "request_queue.jsonl"
        if q.exists():
            text = q.read_text(encoding="utf-8").strip()
            info["queue_depth"] = len(text.splitlines()) if text else 0
        else:
            info["queue_depth"] = 0

        # Definitive liveness verdict
        process_alive = False
        if pid:
            import os
            try:
                os.kill(pid, 0)
                process_alive = True
            except OSError:
                # os.kill(pid, 0) raises OSError when the process is gone; that's
                # exactly the signal we want — process_alive stays False.
                pass

        # Compute definitive worker_status
        if process_alive and hb_age >= 0 and hb_age < 30:
            info["worker_status"] = hb_status or "alive"
        elif process_alive and hb_age >= 30:
            info["worker_status"] = "alive_stale_heartbeat"
        elif not process_alive and hb_status.startswith("exiting"):
            info["worker_status"] = "exited"
        elif not process_alive and hb_age >= 0:
            info["worker_status"] = "dead"
        elif not hb.exists():
            info["worker_status"] = "no_worker"
        else:
            info["worker_status"] = "unknown"
        info["process_alive"] = process_alive

        # Action needed?
        if not process_alive and info["queue_depth"] > 0:
            info["action_needed"] = "respawn"

        # Recent errors
        errors_dir = d / "errors"
        if errors_dir.exists():
            err_files = sorted(errors_dir.glob("*.json"))[-3:]
            info["recent_errors"] = []
            for ef in err_files:
                try:
                    ed = json.loads(ef.read_text(encoding="utf-8"))
                    info["recent_errors"].append({
                        "type": ed.get("type", ""),
                        "error": ed.get("error", "")[:100],
                    })
                except (ValueError, OSError):
                    # Skip a single corrupt or unreadable error file; recent_errors
                    # collection continues with whatever else is present.
                    pass
        else:
            info["recent_errors"] = []

        # Worker stderr log (last 3 lines)
        log_file = d / "logs" / "worker_stderr.log"
        if log_file.exists():
            try:
                lines = log_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                info["recent_log"] = lines[-3:] if lines else []
            except OSError:
                # Best-effort log read; if the log is locked/unreadable we just
                # omit the recent_log field from the worker status.
                pass

        workers.append(info)

    return {"workers": workers, "total": len(workers)}


# ======================================================================
# TOOLS — decompile (cache or pending)
# ======================================================================


@mcp.tool()
def decompile(binary_id: str, address_or_name: str, max_lines: int = 500) -> dict:
    """Decompile a function by address or name.

    Returns cached pseudocode instantly, queues background decompilation,
    or — when Hex-Rays returns None (e.g. CFF-obfuscated code) — falls
    back to the CFF analysis pipeline automatically.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...) or name.
        max_lines: Maximum pseudocode lines to return.

    Returns:
        Decompilation result with pseudocode.  When Hex-Rays fails, the
        response includes ``cff_detection`` and ``cff_deflattened`` keys
        with the recovered analysis instead.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    cached = fe.cache.get_decompile(sha, address_or_name)
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        # CFF fallback: if pseudocode is None, enrich with CFF analysis
        pseudocode = cached.get('pseudocode')
        if pseudocode is None or pseudocode == 'None':
            try:
                pe_path = fe._workspace_binary(sha)
                ea = int(address_or_name, 16) if address_or_name.startswith('0x') else 0
                if ea:
                    # Check if CFF results already cached
                    det_cached = fe.cache.get_result(sha, 'detect_cff', address_or_name)
                    deflat_cached = fe.cache.get_result(sha, 'deflat_function', address_or_name)
                    if det_cached and deflat_cached:
                        # Instant: use cached CFF results
                        cached['cff_detection'] = det_cached
                        cached['cff_deflattened'] = deflat_cached
                        cached['cff_fallback'] = True
                        from .cff_pseudocode import emit_pseudocode
                        name = cached.get('name', '')
                        cached['pseudocode'] = emit_pseudocode(
                            deflat_cached, name,
                            cache_dir=fe.settings.cache_dir, sha=sha)
                        cached['line_count'] = len(cached['pseudocode'].splitlines())
                    else:
                        # Spawn async deflat only — deflat calls detect internally.
                        # Results cached separately for next poll.
                        def _deflat_fn(p=pe_path, a=ea):
                            from .cff_analysis import deflat_function
                            return deflat_function(p, a)
                        fe.server_task(binary_id, 'deflat_function',
                                       address_or_name, _deflat_fn)
                        cached['cff_fallback'] = 'pending'
            except (FileNotFoundError, ValueError, KeyError, OSError):
                pass
        return cached
    fe.cache.queue_decompile(sha, address_or_name)
    worker_action = fe.lifecycle.ensure_worker(binary_id)
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc, worker_action)


# ======================================================================
# TOOLS — index-based (read from cached index or pending)
# ======================================================================


@mcp.tool()
def list_functions(
    binary_id: str,
    offset: int = 0,
    limit: int = 100,
    filter_text: str = "",
    order_by: str = "name",
    min_size_bytes: int = 0,
    min_complexity: int = 0,
    exclude_thunks: bool = False,
    exclude_libraries: bool = False,
) -> dict:
    """List functions from the cached function index.

    Args:
        binary_id: Opaque handle from open_binary.
        offset: Pagination offset.
        limit: Maximum entries to return.
        filter_text: Case-insensitive substring filter on function name.
        order_by: Sort key — name, complexity_desc, or size_desc.
        min_size_bytes: Minimum function size in bytes.
        min_complexity: Minimum cyclomatic complexity.
        exclude_thunks: Drop functions flagged as thunks.
        exclude_libraries: Drop functions flagged as library code.

    Returns:
        Paginated function list with total, offset, limit, and entries,
        or pending status when the index is not yet built.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    index = fe.cache.get_index(sha)
    if index is None:
        lc = fe.lifecycle.get(binary_id)
        return fe._pending(binary_id, lc)
    # Filter in-memory
    entries = index if isinstance(index, list) else []
    ft = filter_text.lower()
    filtered = []
    for e in entries:
        if ft and ft not in e.get("name", "").lower():
            continue
        if min_size_bytes and e.get("size_bytes", 0) < min_size_bytes:
            continue
        if min_complexity and e.get("cyclomatic_complexity", 0) < min_complexity:
            continue
        if exclude_thunks and e.get("is_thunk"):
            continue
        if exclude_libraries and e.get("is_library"):
            continue
        filtered.append(e)
    # Sort
    if order_by == "complexity_desc":
        filtered.sort(key=lambda x: -x.get("cyclomatic_complexity", 0))
    elif order_by == "size_desc":
        filtered.sort(key=lambda x: -x.get("size_bytes", 0))
    else:
        filtered.sort(key=lambda x: x.get("name", "").lower())
    total = len(filtered)
    page = filtered[offset : offset + limit]
    return {"binary_id": binary_id, "total": total, "offset": offset, "limit": limit, "functions": page}


@mcp.tool()
def search_pattern(binary_id: str, pattern_type: str, name_pattern: str = "", limit: int = 50) -> dict:
    """Search for vulnerability patterns across the binary.

    Returns cached results or queues the analysis.

    Args:
        binary_id: Opaque handle from open_binary.
        pattern_type: Pattern identifier to search for.
        name_pattern: Optional function-name filter.
        limit: Maximum hits to return.

    Returns:
        Pattern hits with metadata, or pending status.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    cached = fe.cache.get_pattern(sha, pattern_type)
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        return cached
    fe.cache.queue_pattern(sha, pattern_type)
    worker_action = fe.lifecycle.ensure_worker(binary_id)
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc, worker_action)


@mcp.tool()
def binary_survey(binary_id: str, max_hotspots: int = 10) -> dict:
    """Return a one-call orientation summary for the binary.

    Args:
        binary_id: Opaque handle from open_binary.
        max_hotspots: Maximum hotspot functions to surface.

    Returns:
        Orientation summary built from cached data, or pending status.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    cached = fe.cache.get_result(sha, "binary_survey")
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        return cached
    fe.cache.queue_request(sha, "binary_survey", {"max_hotspots": max_hotspots})
    worker_action = fe.lifecycle.ensure_worker(binary_id)
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc, worker_action)


@mcp.tool()
def call_chain(binary_id: str, target_function: str, depth: int = 5, direction: str = "callers") -> dict:
    """Walk caller or callee chains from the cached function index.

    No IDA work is required when the index is already cached.

    Args:
        binary_id: Opaque handle from open_binary.
        target_function: Function name or address to root the walk.
        depth: Maximum walk depth.
        direction: 'callers' or 'callees'.

    Returns:
        Walk result with target, direction, node count, and chain,
        or pending status when the index is not ready.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    index = fe.cache.get_index(sha)
    if index is None:
        lc = fe.lifecycle.get(binary_id)
        return fe._pending(binary_id, lc)
    # Walk the chain from the index data
    by_name: dict[str, dict] = {}
    for e in index:
        by_name[e["name"].lower()] = e
        by_name[e["address"].lower()] = e
    target_key = target_function.strip().lower()
    root = by_name.get(target_key)
    if root is None:
        for name, entry in by_name.items():
            if target_key in name:
                root = entry
                break
    if root is None:
        return {"binary_id": binary_id, "status": "error", "message": f"Function not found: {target_function}"}
    visited: set[str] = {root["name"].lower()}
    chain: list[dict] = []
    current = [root["name"]]
    for d in range(depth):
        nxt: list[str] = []
        for name in current:
            entry = by_name.get(name.lower())
            if not entry:
                continue
            neighbors = entry.get("callers" if direction == "callers" else "callees", [])
            for nb in neighbors:
                if nb.lower() in visited:
                    continue
                visited.add(nb.lower())
                nb_entry = by_name.get(nb.lower())
                chain.append(
                    {
                        "name": nb,
                        "address": nb_entry["address"] if nb_entry else None,
                        "depth": d + 1,
                        "reached_from": name,
                    }
                )
                nxt.append(nb)
        if not nxt:
            break
        current = nxt
    return {
        "binary_id": binary_id,
        "target": root["name"],
        "target_address": root["address"],
        "direction": direction,
        "nodes_found": len(chain),
        "chain": chain,
        "status": "ready",
    }


@mcp.tool()
def find_similar_functions(binary_id: str, address_or_name: str) -> dict:
    """Find functions in the same binary sharing the target's structure_hash.

    Server-side only — reads the cached function index, no worker needed.
    Two functions with the same ``structure_hash`` have the same control-flow
    shape and call signature, which usually indicates duplicated logic,
    template instantiations, or shared library code.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Target function address (0x...) or name.

    Returns:
        Dict with the resolved ``target`` (name/address/hash), a ``similar``
        list of peers (name/address/size/complexity), and a ``count``, or
        a pending response when the index has not been built yet.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    index = fe.cache.get_index(sha)
    if index is None:
        lc = fe.lifecycle.get(binary_id)
        return fe._pending(binary_id, lc)
    entries = index if isinstance(index, list) else []
    by_key: dict[str, dict] = {}
    for e in entries:
        name_key = e.get("name", "").lower()
        addr_key = e.get("address", "").lower()
        if name_key:
            by_key[name_key] = e
        if addr_key:
            by_key[addr_key] = e
    target_key = address_or_name.strip().lower()
    target = by_key.get(target_key)
    if target is None:
        for name, entry in by_key.items():
            if target_key and target_key in name:
                target = entry
                break
    if target is None:
        return {
            "binary_id": binary_id,
            "status": "error",
            "message": f"Function not found: {address_or_name}",
        }
    target_hash = target.get("structure_hash", "")
    target_addr = target.get("address")
    similar: list[dict[str, Any]] = []
    if target_hash:
        for e in entries:
            if e.get("address") == target_addr:
                continue
            if e.get("structure_hash", "") != target_hash:
                continue
            similar.append(
                {
                    "name": e.get("name"),
                    "address": e.get("address"),
                    "size": e.get("size_bytes", 0),
                    "complexity": e.get("cyclomatic_complexity", 0),
                }
            )
    return {
        "binary_id": binary_id,
        "target": {
            "name": target.get("name"),
            "address": target_addr,
            "hash": target_hash,
        },
        "similar": similar,
        "count": len(similar),
        "status": "ready",
    }


@mcp.tool()
def cross_binary_similarity(binary_id_a: str, binary_id_b: str) -> dict:
    """Match functions across two binaries by ``structure_hash``.

    Server-side only — reads both cached function indexes, no worker needed.
    Trivial matches are suppressed: thunks and functions smaller than 16
    bytes are dropped before pairing, and entries without a
    ``structure_hash`` are ignored.

    Args:
        binary_id_a: Opaque handle for the first binary.
        binary_id_b: Opaque handle for the second binary.

    Returns:
        Dict with a ``matches`` list of ``{hash, binary_a, binary_b}`` pairs
        and ``total_matches``, or a pending/error response when an index is
        unavailable.
    """
    fe = _fe()
    for bid in (binary_id_a, binary_id_b):
        try:
            fe._sha(bid)
        except KeyError:
            return {"status": "error", "message": f"Unknown binary_id: {bid}"}
        lc = fe.lifecycle.get(bid)
        if lc and lc.state < BinaryState.READY:
            return fe._pending(bid, lc)
    sha_a = fe._sha(binary_id_a)
    sha_b = fe._sha(binary_id_b)
    idx_a = fe.cache.get_index(sha_a)
    idx_b = fe.cache.get_index(sha_b)
    if idx_a is None or idx_b is None:
        return {
            "status": "error",
            "message": "Index not cached for one or both binaries.",
        }

    def _eligible(e: dict) -> bool:
        if e.get("is_thunk"):
            return False
        if e.get("size_bytes", 0) < 16:
            return False
        return bool(e.get("structure_hash"))

    by_hash_a: dict[str, list[dict]] = {}
    for e in idx_a:
        if not _eligible(e):
            continue
        by_hash_a.setdefault(e["structure_hash"], []).append(e)
    matches: list[dict[str, Any]] = []
    for e_b in idx_b:
        if not _eligible(e_b):
            continue
        h = e_b["structure_hash"]
        peers = by_hash_a.get(h)
        if not peers:
            continue
        for e_a in peers:
            matches.append(
                {
                    "hash": h,
                    "binary_a": {
                        "name": e_a.get("name"),
                        "addr": e_a.get("address"),
                    },
                    "binary_b": {
                        "name": e_b.get("name"),
                        "addr": e_b.get("address"),
                    },
                }
            )
    return {
        "binary_id_a": binary_id_a,
        "binary_id_b": binary_id_b,
        "matches": matches,
        "total_matches": len(matches),
        "status": "ready",
    }


# ======================================================================
# TOOLS — IDA-dependent (cache or pending, worker does the heavy lifting)
# ======================================================================


def _ida_tool(tool_name: str, binary_id: str, key: str = "", **params: Any) -> dict:
    """Generic dispatcher for IDA-dependent tools: cache hit or queue."""
    fe = _fe()
    sha = fe._sha(binary_id)
    lc = fe.lifecycle.get(binary_id)
    if lc:
        fe.lifecycle._worker_activity[lc.sha256] = __import__('time').monotonic()
    if lc and lc.state < BinaryState.READY:
        return fe._pending(binary_id, lc, "not_ready")
    cached = fe.cache.get_result(sha, tool_name, key)
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        # Check staleness — warn consumer if data may be outdated
        safe_key = key.replace('/', '_').replace('\\', '_').replace(':', '_')
        filename = f"{tool_name}_{safe_key}.json" if safe_key else f"{tool_name}.json"
        cache_file = fe.settings.cache_dir / sha / "results" / filename
        staleness = fe.cache.check_staleness(sha, cache_file)
        if staleness["stale"]:
            cached["_warning"] = "Result may be stale — a write operation occurred after this was cached."
            cached["_stale"] = True
            cached["_generation"] = staleness["generation"]
        return cached
    fe.cache.queue_request(sha, tool_name, {"binary_id": binary_id, "_cache_key": key, **params})
    worker_action = fe.lifecycle.ensure_worker(binary_id)
    return fe._pending(binary_id, lc, worker_action)


def _server_tool(tool_name: str, binary_id: str, key: str, func) -> dict:
    """Generic dispatcher for server-side tools: cache hit or background thread.

    Mirrors _ida_tool but runs func() in-process instead of queueing to a worker.
    Used for tools that operate on raw PE bytes (CFF, decrypt, capability scan).
    """
    return _fe().server_task(binary_id, tool_name, key, func)


@mcp.tool()
def xrefs_to(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references to an address or symbol.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Target address (0x...) or symbol name.

    Returns:
        Cross-references with locations, or pending status.
    """
    return _ida_tool("xrefs_to", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def xrefs_from(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references from a function.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...) or name.

    Returns:
        Outgoing cross-references, or pending status.
    """
    return _ida_tool("xrefs_from", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def imports(binary_id: str) -> dict:
    """List imports for the binary.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Imported symbols grouped by module, or pending status.
    """
    return _ida_tool("imports", binary_id)


@mcp.tool()
def exports(binary_id: str) -> dict:
    """List exports for the binary.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Exported symbols, or pending status.
    """
    return _ida_tool("exports", binary_id)


@mcp.tool()
def segments(binary_id: str) -> dict:
    """List segments for the binary.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Segment table with names, ranges, and permissions, or pending status.
    """
    return _ida_tool("segments", binary_id)


@mcp.tool()
def checksec(binary_id: str) -> dict:
    """Return a binary mitigation summary.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Mitigation flags (NX, ASLR, canary, etc.) for PE binaries,
        or pending status while the worker analyzes other formats.
    """
    fe = _fe()
    rec = fe._binaries.get(binary_id)
    if rec and "mitigations" in rec:
        return {"binary_id": binary_id, "status": "ready", **rec["mitigations"]}
    return _ida_tool("checksec", binary_id)


@mcp.tool()
def stack_frame(binary_id: str, address_or_name: str) -> dict:
    """Return stack frame sizing information for a function.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...) or name.

    Returns:
        Stack frame sizes and locals layout, or pending status.
    """
    return _ida_tool("stack_frame", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def call_graph(binary_id: str, address_or_name: str, depth: int = 2, direction: str = "both") -> dict:
    """Return a bounded call graph rooted at a function.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Root function address (0x...) or name.
        depth: Maximum traversal depth.
        direction: 'callers', 'callees', or 'both'.

    Returns:
        Bounded call graph nodes and edges, or pending status.
    """
    return _ida_tool(
        "call_graph", binary_id, key=address_or_name, address_or_name=address_or_name, depth=depth, direction=direction
    )


@mcp.tool()
def batch_decompile(binary_id: str, name_pattern: str = "", limit: int = 20, **kwargs: Any) -> dict:
    """Decompile multiple functions selected by structured filters.

    Args:
        binary_id: Opaque handle from open_binary.
        name_pattern: Optional function-name filter.
        limit: Maximum functions to decompile.
        **kwargs: Additional structured filters forwarded to the worker.

    Returns:
        Per-function decompilation results, or pending status.
    """
    return _ida_tool("batch_decompile", binary_id, name_pattern=name_pattern, limit=limit, **kwargs)


@mcp.tool()
def diff_binary(binary_id_old: str, binary_id_new: str) -> dict:
    """Diff two analyzed binaries structurally by function metadata.

    Args:
        binary_id_old: Handle for the older/baseline binary.
        binary_id_new: Handle for the newer/target binary.

    Returns:
        Structural diff of added, removed, and changed functions,
        or pending status.
    """
    fe = _fe()
    for bid in (binary_id_old, binary_id_new):
        try:
            fe._sha(bid)
        except KeyError:
            return {"status": "error", "message": f"Unknown binary_id: {bid}"}
        lc = fe.lifecycle.get(bid)
        if lc and lc.state < BinaryState.READY:
            return fe._pending(bid, lc)
    # Server-side diff from cached indexes (no worker needed)
    sha_old = fe._sha(binary_id_old)
    sha_new = fe._sha(binary_id_new)
    idx_old = fe.cache.load_index(sha_old)
    idx_new = fe.cache.load_index(sha_new)
    if idx_old is None or idx_new is None:
        return {"status": "error", "message": "Index not cached for one or both binaries."}
    from .diff import diff_indexes
    result = diff_indexes(idx_old, idx_new)
    result["binary_id_old"] = binary_id_old
    result["binary_id_new"] = binary_id_new
    result["status"] = "ready"
    return result


@mcp.tool()
def diff_function(
    binary_id_old: str, address_or_name_old: str, binary_id_new: str, address_or_name_new: str, max_lines: int = 500
) -> dict:
    """Diff two functions using side-by-side pseudocode and unified diff.

    Args:
        binary_id_old: Handle for the older/baseline binary.
        address_or_name_old: Function in the old binary.
        binary_id_new: Handle for the newer/target binary.
        address_or_name_new: Function in the new binary.
        max_lines: Maximum pseudocode lines per side.

    Returns:
        Side-by-side pseudocode and unified diff, or pending status.
    """
    fe = _fe()
    for bid in (binary_id_old, binary_id_new):
        try:
            fe._sha(bid)
        except KeyError:
            return {"status": "error", "message": f"Unknown binary_id: {bid}"}
    sha_old = fe._sha(binary_id_old)
    sha_new = fe._sha(binary_id_new)
    old_decomp = fe.cache.get_decompile(sha_old, address_or_name_old)
    new_decomp = fe.cache.get_decompile(sha_new, address_or_name_new)
    if old_decomp is None or new_decomp is None:
        if old_decomp is None:
            fe.cache.queue_decompile(sha_old, address_or_name_old)
            fe.lifecycle.ensure_worker(binary_id_old)
        if new_decomp is None:
            fe.cache.queue_decompile(sha_new, address_or_name_new)
            fe.lifecycle.ensure_worker(binary_id_new)
        return {"status": "pending", "message": "Decompiling. Retry."}
    from .diff import diff_function_payloads
    result = diff_function_payloads(old_decomp, new_decomp)
    result["binary_id_old"] = binary_id_old
    result["binary_id_new"] = binary_id_new
    result["status"] = "ready"
    return result


@mcp.tool()
def diff_survey(
    binary_id_old: str, binary_id_new: str, max_changed: int = 20, include_pseudocode_diff: bool = True
) -> dict:
    """Run a full N-day survey diff with security ranking.

    Combines a structural diff, per-function diffs, and a security
    ranking in a single call.

    Args:
        binary_id_old: Handle for the older/baseline binary.
        binary_id_new: Handle for the newer/target binary.
        max_changed: Maximum changed functions to include.
        include_pseudocode_diff: Include pseudocode diffs per function.

    Returns:
        Aggregated survey of changed functions ranked by security
        impact, or pending status.
    """
    fe = _fe()
    for bid in (binary_id_old, binary_id_new):
        try:
            fe._sha(bid)
        except KeyError:
            return {"status": "error", "message": f"Unknown binary_id: {bid}"}
    binary_result = diff_binary(binary_id_old, binary_id_new)
    if binary_result.get("status") != "ready":
        return binary_result
    changed = binary_result.get("changed", [])[:max_changed]
    enriched = []
    for entry in changed:
        item = dict(entry)
        if include_pseudocode_diff:
            fn_diff = diff_function(
                binary_id_old, entry.get("address_old", ""),
                binary_id_new, entry.get("address_new", ""),
            )
            if fn_diff.get("status") == "ready":
                item["diff_preview"] = fn_diff.get("diff_unified", "")[:2000]
        enriched.append(item)
    return {
        "binary_id_old": binary_id_old,
        "binary_id_new": binary_id_new,
        "summary": binary_result.get("summary", {}),
        "changed": enriched,
        "status": "ready",
    }


@mcp.tool()
def query_ctree(
    binary_id: str,
    address_or_name: str,
    target_function: str = "",
    argument_index: int | None = None,
    contains_operation: str = "",
    operand_type_is: str = "",
    limit: int = 50,
) -> dict:
    """Query the decompiler CTree for call expressions matching predicates.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function to scan.
        target_function: Optional callee filter.
        argument_index: Optional argument index filter.
        contains_operation: Optional operation substring filter.
        operand_type_is: Optional operand-type filter.
        limit: Maximum matches to return.

    Returns:
        Matching call expressions with locations, or pending status.
    """
    return _ida_tool(
        "query_ctree",
        binary_id,
        key=address_or_name,
        address_or_name=address_or_name,
        target_function=target_function,
        argument_index=argument_index,
        contains_operation=contains_operation,
        operand_type_is=operand_type_is,
        limit=limit,
    )


@mcp.tool()
def get_microcode(binary_id: str, address_or_name: str, maturity: str = "current") -> dict:
    """Return textual Hex-Rays microcode for a function.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...) or name.
        maturity: Microcode maturity level (e.g., 'current').

    Returns:
        Textual microcode listing, or pending status.
    """
    return _ida_tool(
        "get_microcode", binary_id, key=address_or_name, address_or_name=address_or_name, maturity=maturity
    )


@mcp.tool()
def trace_dataflow(
    binary_id: str,
    address_or_name: str,
    sink_function: str,
    sink_argument_index: int,
    source_contains: list[str] | None = None,
    max_steps: int = 10,
) -> dict:
    """Trace a sink argument backward through local assignment hops.

    Walks from the sink argument back toward an optional source term
    via local assignment hops.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function containing the sink.
        sink_function: Sink callee name.
        sink_argument_index: Index of the sink argument to trace.
        source_contains: Optional source-term substrings to terminate on.
        max_steps: Maximum hops to follow.

    Returns:
        Backward trace with hop chain and source match, or pending status.
    """
    key = f"{address_or_name}_{sink_function}_{sink_argument_index}"
    return _ida_tool(
        "trace_dataflow",
        binary_id,
        key=key,
        address_or_name=address_or_name,
        sink_function=sink_function,
        sink_argument_index=sink_argument_index,
        source_contains=source_contains,
        max_steps=max_steps,
    )


@mcp.tool()
def hexrays_warnings(binary_id: str, address_or_name: str) -> dict:
    """Return Hex-Rays decompiler warnings for a function.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...) or name.

    Returns:
        Decompiler warnings as confidence signals, or pending status.
    """
    return _ida_tool("hexrays_warnings", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def pseudocode_slice_view(
    binary_id: str,
    address_or_name: str,
    focus_callee: str = "",
    focus_address: str = "",
    context_lines: int = 5,
    max_slices: int = 10,
) -> dict:
    """Return focused pseudocode slices around call sites or addresses.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function to slice.
        focus_callee: Optional callee to focus slices on.
        focus_address: Optional address to focus slices on.
        context_lines: Lines of context to include around each slice.
        max_slices: Maximum slices to return.

    Returns:
        Focused pseudocode slices, or pending status.
    """
    key = f"{address_or_name}_{focus_callee}_{focus_address}"
    return _ida_tool(
        "pseudocode_slice",
        binary_id,
        key=key,
        address_or_name=address_or_name,
        focus_callee=focus_callee,
        focus_address=focus_address,
        context_lines=context_lines,
        max_slices=max_slices,
    )


@mcp.tool()
def def_use(binary_id: str, address_or_name: str, target_callee: str = "", max_instructions: int = 200) -> dict:
    """Run microcode-level use/def chain analysis.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function to analyze.
        target_callee: Optional callee to constrain the analysis.
        max_instructions: Maximum instructions to inspect.

    Returns:
        Use/def chains showing instruction reads and writes,
        or pending status.
    """
    key = f"{address_or_name}_{target_callee}"
    return _ida_tool(
        "def_use",
        binary_id,
        key=key,
        address_or_name=address_or_name,
        target_callee=target_callee,
        max_instructions=max_instructions,
    )


@mcp.tool()
def value_ranges(binary_id: str, address_or_name: str) -> dict:
    """Return IR-backed value-range annotations for a function.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...) or name.

    Returns:
        Value-range annotations from microcode analysis, or pending status.
    """
    return _ida_tool("value_ranges", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def interprocedural_taint(
    binary_id: str,
    sink_function: str,
    sink_argument_index: int,
    source_functions: list[str] | None = None,
    max_depth: int = 5,
) -> dict:
    """Trace data flow from a sink argument backward across function boundaries.

    Follows data through call chains: if the sink's argument came from a
    caller's parameter, recurses up the call graph until hitting a source.

    Args:
        binary_id: Opaque handle from open_binary.
        sink_function: Dangerous sink to trace from (e.g., 'system', 'memcpy').
        sink_argument_index: Which argument of the sink to trace (0-based).
        source_functions: Stop when reaching one of these (e.g., ['recv', 'ReadFile']).
        max_depth: Maximum call-chain hops to follow.

    Returns:
        Taint chains showing how data flows from source to sink across functions.
    """
    key = f"{sink_function}_{sink_argument_index}"
    return _ida_tool(
        "interprocedural_taint",
        binary_id,
        key=key,
        sink_function=sink_function,
        sink_argument_index=sink_argument_index,
        source_functions=source_functions,
        max_depth=max_depth,
    )


@mcp.tool()
def constrained_reachability(
    binary_id: str,
    address_or_name: str,
    sink_address: str,
    timeout_seconds: int = 60,
) -> dict:
    """Prove path reachability using angr seeded with Hex-Rays value-range constraints.

    Combines IDA's IR-level value-range analysis with angr symbolic execution.
    Hex-Rays constraints (e.g., 'rax != 0', 'rbx in [0,3]') prune impossible
    paths early, reducing state explosion. Known library functions are hooked
    with angr summaries.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function entry address (exploration start).
        sink_address: Target address to prove reachable.
        timeout_seconds: Maximum symbolic execution time.

    Returns:
        Feasibility verdict with steps, elapsed time, constraints applied,
        and hooks used.
    """
    key = f"{address_or_name}_{sink_address}"
    return _ida_tool(
        "constrained_reachability",
        binary_id,
        key=key,
        address_or_name=address_or_name,
        sink_address=sink_address,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
def recover_cfg(binary_id: str, address_or_name: str) -> dict:
    """Recover true control flow from a flattened function via state analysis."""
    return _ida_tool("recover_cfg", binary_id, key=address_or_name,
                     address_or_name=address_or_name)


@mcp.tool()
def detect_stack_strings(binary_id: str, address_or_name: str) -> dict:
    """Detect strings constructed on the stack (hidden from static scan).

    Scans disassembly for consecutive byte/dword stores to stack variables
    that form printable ASCII when concatenated. Finds strings that malware
    builds at runtime to evade static string extraction.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function to scan.

    Returns:
        Extracted stack-constructed strings with addresses.
    """
    return _ida_tool("detect_stack_strings", binary_id, key=address_or_name,
                     address_or_name=address_or_name)


@mcp.tool()
def generate_yara_rule(binary_id: str, address_or_name: str) -> dict:
    """Generate a YARA detection rule from function bytes."""
    return _ida_tool("generate_yara_rule", binary_id, key=address_or_name,
                     address_or_name=address_or_name)


@mcp.tool()
def patch_assemble(binary_id: str, address: str, assembly: str) -> dict:
    """Assemble instructions and patch at address (e.g., \"nop; nop; ret\")."""
    return _ida_tool("patch_assemble", binary_id, key=address,
                     address=address, assembly=assembly)


@mcp.tool()
def capa_scan(binary_id: str) -> dict:
    """Evaluate 678 behavioral rules against the binary (CAPA-derived).

    Checks function callees and string references against 678 rules
    covering 106 ATT&CK techniques. No CAPA binary needed.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Matched capabilities with ATT&CK mapping and triggering functions.
    """
    return _ida_tool("capa_scan", binary_id)


@mcp.tool()
def resolve_api_hashes(binary_id: str) -> dict:
    """Resolve hash-imported API names (CRC32, DJB2, ROR13, FNV-1a, SDBM).

    Malware imports APIs by hash to evade static analysis. This tool
    resolves hash values back to API names from a precomputed database.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Resolved API names with hash algorithm identified.
    """
    return _ida_tool("resolve_api_hashes", binary_id)


@mcp.tool()
def detect_library_functions(binary_id: str) -> dict:
    """Aggregate library functions by detected library (OpenSSL, zlib, etc).

    Groups FLIRT-identified library functions by name prefix patterns.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Libraries detected with function counts and names.
    """
    return _ida_tool("detect_library_functions", binary_id)


@mcp.tool()
def recover_class_hierarchy(binary_id: str) -> dict:
    """Recover C++ class hierarchy from vtable cross-reference analysis."""
    return _ida_tool("recover_class_hierarchy", binary_id)


@mcp.tool()
def detect_protocol_state_machine(binary_id: str, address_or_name: str) -> dict:
    """Detect network protocol state machine patterns in a function."""
    return _ida_tool("detect_protocol_state_machine", binary_id, key=address_or_name,
                     address_or_name=address_or_name)


@mcp.tool()
def prove_bounds_sufficient(
    binary_id: str, address_or_name: str,
    sink_function: str, sink_argument_index: int,
) -> dict:
    """Prove whether validation gates are mathematically sufficient to prevent overflow.

    UNSAT = gates prevent ALL bad inputs (proven safe).
    SAT = dangerous value possible despite gates (with witness).
    """
    key = f"{address_or_name}_{sink_function}_{sink_argument_index}_bounds"
    return _ida_tool("prove_bounds_sufficient", binary_id, key=key,
                     address_or_name=address_or_name,
                     sink_function=sink_function,
                     sink_argument_index=sink_argument_index)


@mcp.tool()
def prove_predicate_opaque(binary_id: str, address_or_name: str, condition_address: str) -> dict:
    """Prove whether a branch condition is opaque (always true/false)."""
    key = f"{address_or_name}_opaque"
    return _ida_tool("prove_predicate_opaque", binary_id, key=key,
                     address_or_name=address_or_name, condition_address=condition_address)


@mcp.tool()
def prove_equivalence(binary_id: str, expr_a: str, expr_b: str, address_or_name: str) -> dict:
    """Prove two expressions equivalent for all inputs via SMT."""
    key = f"{address_or_name}_equiv"
    return _ida_tool("prove_equivalence", binary_id, key=key,
                     address_or_name=address_or_name, expr_a=expr_a, expr_b=expr_b)


@mcp.tool()
def detect_obfuscation(binary_id: str, address_or_name: str) -> dict:
    """Detect obfuscation techniques in a function.

    Checks for: MBA substitution, control flow flattening, opaque predicates,
    instruction substitution, dead code insertion.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function to analyze.

    Returns:
        Detection results with techniques found and confidence level.
    """
    return _ida_tool("detect_obfuscation", binary_id, key=address_or_name,
                     address_or_name=address_or_name)


@mcp.tool()
def detect_crypto_primitives(binary_id: str) -> dict:
    """Detect known cryptographic constants and patterns in the binary.

    Scans data sections for: AES S-box, SHA-256/SHA-1 constants, CRC32
    polynomials, Base64 alphabets, and heuristic XOR cipher patterns.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        List of detected primitives with addresses and confidence.
    """
    return _ida_tool("detect_crypto_primitives", binary_id)


@mcp.tool()
def prove_overflow(
    binary_id: str,
    address_or_name: str,
    sink_function: str,
    sink_argument_index: int,
) -> dict:
    """Prove whether an integer overflow is feasible despite validation gates.

    Runs assess_exploitability first, then encodes the overflow condition
    and validation gates as a bitvector SMT formula. Solves with binbit
    in milliseconds.

    Returns proven_exploitable (with witness values that trigger the overflow),
    proven_defended (UNSAT — gates prevent overflow for ALL inputs),
    or inconclusive (solver timeout).

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function containing the sink.
        sink_function: The dangerous callee (e.g., 'memmove').
        sink_argument_index: Which argument to check (e.g., 2 for size).

    Returns:
        Proof result with feasibility, witness, and verdict.
    """
    key = f"{address_or_name}_{sink_function}_{sink_argument_index}_proof"
    return _ida_tool(
        "prove_overflow",
        binary_id,
        key=key,
        address_or_name=address_or_name,
        sink_function=sink_function,
        sink_argument_index=sink_argument_index,
    )


@mcp.tool()
def assess_exploitability(
    binary_id: str,
    address_or_name: str,
    sink_function: str,
    sink_argument_index: int,
) -> dict:
    """Deep exploitability assessment for a specific sink in a function.

    Combines three analyses:
    1. Deep taint: traces the sink argument backward, classifying its source
       (file_header_field, function_parameter, constant, call_result).
    2. Arithmetic tracking: identifies multiplication, shifts, additions on
       the tainted value (potential integer overflow).
    3. Validation gate detection: finds if-checks (bounds, overflow, null)
       between the source and the sink call.

    Produces a verdict: likely_exploitable, defended, low_risk, needs_review.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function containing the sink call.
        sink_function: The dangerous callee (e.g., 'memmove', 'memcpy').
        sink_argument_index: Which argument to assess (e.g., 2 for size).

    Returns:
        Assessment with source_type, arithmetic_chain, validation_gates,
        and exploitability verdict.
    """
    key = f"{address_or_name}_{sink_function}_{sink_argument_index}"
    return _ida_tool(
        "assess_exploitability",
        binary_id,
        key=key,
        address_or_name=address_or_name,
        sink_function=sink_function,
        sink_argument_index=sink_argument_index,
    )


@mcp.tool()
def classify_behavior(binary_id: str) -> dict:
    """Map imported APIs to ATT&CK-aligned behavioral categories.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Behavior classification grouped by category, or pending status.
    """
    return _ida_tool("classify_behavior", binary_id)


@mcp.tool()
def detect_anti_analysis(binary_id: str) -> dict:
    """Detect anti-debug, anti-VM, and anti-sandbox techniques.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Detected anti-analysis techniques with locations, or pending status.
    """
    return _ida_tool("detect_anti_analysis", binary_id)


@mcp.tool()
def entropy_analysis(binary_id: str) -> dict:
    """Compute per-section Shannon entropy for packing detection.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Per-section entropy scores indicating packing or encryption,
        or pending status.
    """
    return _ida_tool("entropy_analysis", binary_id)


@mcp.tool()
def classify_strings(binary_id: str, limit: int = 200) -> dict:
    """Classify string references by format.

    Categories include URLs, IPs, registry paths, file paths, and
    base64 blobs.

    Args:
        binary_id: Opaque handle from open_binary.
        limit: Maximum strings to classify.

    Returns:
        String references grouped by classification, or pending status.
    """
    return _ida_tool("classify_strings", binary_id, limit=limit)


@mcp.tool()
def detect_dynamic_resolution(binary_id: str, limit: int = 50) -> dict:
    """Find dynamic API resolution and extract resolved names.

    Locates GetProcAddress and LoadLibrary call sites and extracts
    the dynamically resolved API names.

    Args:
        binary_id: Opaque handle from open_binary.
        limit: Maximum resolutions to return.

    Returns:
        Dynamic resolution sites with resolved API names, or pending status.
    """
    return _ida_tool("detect_dynamic_resolution", binary_id, limit=limit)


@mcp.tool()
def path_feasibility(
    binary_id: str, source_address: str, sink_address: str, timeout_seconds: int = 60, max_steps: int = 200000
) -> dict:
    """Check feasibility of a source-to-sink path with angr.

    Args:
        binary_id: Opaque handle from open_binary.
        source_address: Symbolic-execution start address.
        sink_address: Target address to reach.
        timeout_seconds: Per-call symbolic execution timeout.
        max_steps: Maximum symbolic steps before giving up.

    Returns:
        Feasibility verdict with witness state when reachable,
        or pending status.
    """
    key = f"{source_address}_{sink_address}"
    return _ida_tool(
        "path_feasibility",
        binary_id,
        key=key,
        source_address=source_address,
        sink_address=sink_address,
        timeout_seconds=timeout_seconds,
        max_steps=max_steps,
    )


@mcp.tool()
def find_paths(
    binary_id: str,
    from_address: str,
    to_address: str,
    avoid_addresses: list[str] | None = None,
    timeout_seconds: int = 60,
    max_paths: int = 3,
) -> dict:
    """Find execution paths between two points using angr exploration.

    Args:
        binary_id: Opaque handle from open_binary.
        from_address: Path start address.
        to_address: Path end address.
        avoid_addresses: Addresses to avoid during exploration.
        timeout_seconds: Per-call exploration timeout.
        max_paths: Maximum distinct paths to return.

    Returns:
        Discovered execution paths, or pending status.
    """
    key = f"{from_address}_{to_address}"
    return _ida_tool(
        "find_paths",
        binary_id,
        key=key,
        from_address=from_address,
        to_address=to_address,
        avoid_addresses=avoid_addresses,
        timeout_seconds=timeout_seconds,
        max_paths=max_paths,
    )


# ======================================================================
# TOOLS — write operations (queued to worker, serialized)
# ======================================================================


def _mutate(binary_id: str, mutation_type: str, agent_id: str = "", **params: Any) -> dict:
    """Submit a write operation to the mutation queue."""
    fe = _fe()
    sha = fe._sha(binary_id)
    from .mutations import MutationQueue

    mq = MutationQueue(fe.settings.cache_dir)
    return mq.submit(sha, mutation_type, params, agent_id=agent_id)


@mcp.tool()
def rename_function(binary_id: str, address: str, new_name: str, agent_id: str = "") -> dict:
    """Rename a function.

    Queued — invalidates the decompile cache for this function and
    all of its callers.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Function address.
        new_name: New function name.
        agent_id: Optional caller identifier for audit.

    Returns:
        Mutation ticket for polling with poll_mutation.
    """
    return _mutate(binary_id, "rename_function", agent_id, address=address, new_name=new_name)


@mcp.tool()
def rename_variable(
    binary_id: str, function_address: str, old_name: str, new_name: str, agent_id: str = ""
) -> dict:
    """Rename a local variable.

    Queued — invalidates the decompile cache for the function.

    Args:
        binary_id: Opaque handle from open_binary.
        function_address: Address of the containing function.
        old_name: Current variable name.
        new_name: New variable name.
        agent_id: Optional caller identifier for audit.

    Returns:
        Mutation ticket for polling with poll_mutation.
    """
    return _mutate(
        binary_id, "rename_variable", agent_id,
        function_address=function_address, old_name=old_name, new_name=new_name,
    )


@mcp.tool()
def set_comment(binary_id: str, address: str, comment: str, agent_id: str = "") -> dict:
    """Set a comment at an address.

    Queued — invalidates the decompile cache for the containing function.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Address to annotate.
        comment: Comment text.
        agent_id: Optional caller identifier for audit.

    Returns:
        Mutation ticket for polling with poll_mutation.
    """
    return _mutate(binary_id, "set_comment", agent_id, address=address, comment=comment)


@mcp.tool()
def set_function_type(
    binary_id: str, function_address: str, prototype: str, agent_id: str = ""
) -> dict:
    """Set a function's prototype/type.

    Queued — invalidates the decompile cache.

    Args:
        binary_id: Opaque handle from open_binary.
        function_address: Address of the function.
        prototype: New C prototype string.
        agent_id: Optional caller identifier for audit.

    Returns:
        Mutation ticket for polling with poll_mutation.
    """
    return _mutate(
        binary_id, "set_function_type", agent_id,
        function_address=function_address, prototype=prototype,
    )


@mcp.tool()
def set_variable_type(
    binary_id: str, function_address: str, variable_name: str, new_type: str, agent_id: str = ""
) -> dict:
    """Set a local variable's type.

    Queued — invalidates the decompile cache.

    Args:
        binary_id: Opaque handle from open_binary.
        function_address: Address of the containing function.
        variable_name: Variable to retype.
        new_type: New C type string.
        agent_id: Optional caller identifier for audit.

    Returns:
        Mutation ticket for polling with poll_mutation.
    """
    return _mutate(
        binary_id, "set_variable_type", agent_id,
        function_address=function_address, variable_name=variable_name, new_type=new_type,
    )


@mcp.tool()
def patch_bytes(binary_id: str, address: str, hex_bytes: str, agent_id: str = "") -> dict:
    """Patch bytes at an address.

    Queued — invalidates the decompile cache for the containing function.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Address to patch.
        hex_bytes: Replacement bytes as a hex string.
        agent_id: Optional caller identifier for audit.

    Returns:
        Mutation ticket for polling with poll_mutation.
    """
    return _mutate(binary_id, "patch_bytes", agent_id, address=address, hex_bytes=hex_bytes)


@mcp.tool()
def poll_mutation(binary_id: str, ticket_id: str) -> dict:
    """Check whether a queued mutation has been applied.

    Args:
        binary_id: Opaque handle from open_binary.
        ticket_id: Ticket returned by a write tool.

    Returns:
        Mutation result if applied, otherwise a 'queued' status.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    from .mutations import MutationQueue

    mq = MutationQueue(fe.settings.cache_dir)
    result = mq.poll_result(sha, ticket_id)
    if result:
        return result
    return {"ticket_id": ticket_id, "status": "queued", "message": "Still processing."}


@mcp.tool()
def get_generation(binary_id: str) -> dict:
    """Get the current generation counter for a binary.

    The counter increments on every write operation and is used by
    cache consumers to detect stale results.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Current generation counter for the binary.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    from .mutations import Generation

    gen = Generation(fe.settings.cache_dir / sha)
    return {"binary_id": binary_id, "generation": gen.read()}


# -----------------------------------------------------------------------
# TOOLS — miasm (server-side, instant, no worker needed)
# -----------------------------------------------------------------------


@mcp.tool()
def miasm_disassemble(
    binary_id: str,
    address: str,
    size: int = 64,
) -> dict[str, Any]:
    """Disassemble bytes using miasm's multi-arch engine.

    Independent of Hex-Rays. Supports x86_32, x86_64, ARM, AArch64.
    Runs server-side — no worker needed, instant result.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Virtual address to start disassembly (0x...).
        size: Maximum bytes to read (default 64).

    Returns:
        Instruction list with address, mnemonic, operands, size.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    ea = int(address, 16)
    from .miasm_tools import miasm_disassemble as _disasm
    result = _disasm(pe_path, ea, size=size)
    result["binary_id"] = binary_id
    return result


@mcp.tool()
def miasm_lift_ir(
    binary_id: str,
    address: str,
    size: int = 64,
) -> dict[str, Any]:
    """Lift bytes to miasm's intermediate representation (IR).

    Shows the semantic effect of each instruction as symbolic assignments.
    Useful for understanding obfuscated code at the IR level.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Virtual address to start lifting (0x...).
        size: Maximum bytes to read.

    Returns:
        IR blocks with dst/src assignment pairs.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    ea = int(address, 16)
    from .miasm_tools import miasm_lift_ir as _lift
    result = _lift(pe_path, ea, size=size)
    result["binary_id"] = binary_id
    return result


@mcp.tool()
def miasm_simplify_expression(
    expression: str,
) -> dict[str, Any]:
    """Simplify a symbolic expression using miasm's rewrite engine.

    De-obfuscates Mixed Boolean-Arithmetic (MBA) and opaque predicates.
    Input uses Python-like syntax with register names.

    Examples:
        "RAX ^ RAX" -> "0x0"
        "(RAX & RBX) | (RAX & ~RBX)" -> "RAX"
        "RAX + 0" -> "RAX"

    Args:
        expression: Expression in miasm syntax with register names.

    Returns:
        Original and simplified expression strings.
    """
    from .miasm_tools import miasm_simplify_expression as _simp
    return _simp(expression)


@mcp.tool()
def miasm_emulate(
    binary_id: str,
    address: str,
    size: int = 256,
    max_instructions: int = 100,
) -> dict[str, Any]:
    """Symbolically execute a code snippet using miasm.

    Tracks register and memory modifications through the block.
    Shows what a code block does without running it.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Virtual address to start emulation (0x...).
        size: Maximum bytes to read.
        max_instructions: Stop after this many instructions.

    Returns:
        Final symbolic state of modified registers.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    ea = int(address, 16)
    from .miasm_tools import miasm_emulate_snippet as _emulate
    result = _emulate(pe_path, ea, size=size, max_instructions=max_instructions)
    result["binary_id"] = binary_id
    return result


# -----------------------------------------------------------------------
# TOOLS — CFF analysis (server-side, instant, no worker needed)
# -----------------------------------------------------------------------


@mcp.tool()
def disassemble_function(
    binary_id: str,
    address_or_name: str,
) -> dict[str, Any]:
    """Disassemble a complete function via miasm CFG recovery.

    Returns the full control-flow graph with per-block feature extraction.
    Uses dis_multiblock to follow all branches within the function.
    Critical for CFF-obfuscated code where linear disassembly fails.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...).

    Returns:
        Blocks with instructions, edges, and topology stats.
    """
    fe = _fe()
    pe_path = fe._workspace_binary(fe._sha(binary_id))
    ea = int(address_or_name, 16)
    def _compute():
        from .cff_analysis import disassemble_function as _fn
        r = _fn(pe_path, ea)
        r.pop('_blocks_obj', None); r.pop('_addr_to_block', None)
        return r
    return _server_tool('disassemble_function', binary_id, address_or_name, _compute)


@mcp.tool()
def detect_control_flow_obfuscation(
    binary_id: str,
    address_or_name: str,
) -> dict[str, Any]:
    """Detect CFF obfuscation in a function.

    Topology-based detection: finds dispatchers by abnormal in-degree,
    identifies opaque predicates via pattern matching and simplification,
    matches against known obfuscator signatures (OLLVM, Hikari, LCG-CFF, Tigress, Themida).

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...).

    Returns:
        CFF detection result with dispatcher, state variable, opaque predicates,
        matched signature, and confidence.
    """
    fe = _fe()
    pe_path = fe._workspace_binary(fe._sha(binary_id))
    ea = int(address_or_name, 16)
    def _compute():
        from .cff_analysis import detect_cff as _fn
        return _fn(pe_path, ea)
    return _server_tool('detect_cff', binary_id, address_or_name, _compute)


@mcp.tool()
def deflat_function(
    binary_id: str,
    address_or_name: str,
) -> dict[str, Any]:
    """Deflat a CFF-obfuscated function.

    Full deflattening pipeline: recovers the original control flow from
    a flattened function. Returns classified blocks (real/trampoline/opaque),
    state transition graph, recovered execution flow, and prologue analysis.

    Combines miasm CFG recovery with the CFF technique database to handle
    OLLVM, Hikari, LCG-CFF, Tigress, and Themida CFF variants.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...).

    Returns:
        Deflattened function with states, flow, calls, and block classification.
    """
    fe = _fe()
    pe_path = fe._workspace_binary(fe._sha(binary_id))
    ea = int(address_or_name, 16)
    def _compute():
        from .cff_analysis import deflat_function as _fn
        return _fn(pe_path, ea)
    return _server_tool('deflat_function', binary_id, address_or_name, _compute)


@mcp.tool()
def patch_cff(
    binary_id: str,
    address_or_name: str,
) -> dict[str, Any]:
    """Patch a CFF-obfuscated function to make it decompilable by Hex-Rays.

    Runs disassemble + deflat, computes byte patches that replace dispatcher
    jumps with direct handler-to-handler jumps, queues all patches as mutations.
    After patches apply, decompile() should return clean pseudocode.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...).

    Returns:
        Patch summary with count and mutation tickets.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    ea = int(address_or_name, 16)
    # Run disassembly and deflattening (from cache or compute)
    from .cff_analysis import disassemble_function as _disasm
    from .cff_analysis import detect_cff as _detect
    cfg = _disasm(pe_path, ea)
    det = _detect(pe_path, ea)
    if not det.get('is_cff'):
        return {'binary_id': binary_id, 'status': 'error',
                'error': 'Function is not CFF-obfuscated'}
    from .cff_analysis import deflat_function as _deflat
    deflat = _deflat(pe_path, ea)
    dispatcher_addr = det.get('dispatcher_address', '')
    if isinstance(dispatcher_addr, str):
        dispatcher_addr = int(dispatcher_addr, 16)
    from .cff_patcher import compute_patches
    patches = compute_patches(cfg['blocks'], deflat['states'], dispatcher_addr)
    if not patches:
        return {'binary_id': binary_id, 'status': 'error',
                'error': 'No patches computed'}
    # Queue all patches as mutations
    tickets: list[dict] = []
    for p in patches:
        fe.cache.queue_write_mutation(sha, {
            'type': 'patch_bytes',
            'params': {'address': p['address'], 'hex_bytes': p['hex_bytes']},
        })
        tickets.append({'address': p['address'], 'description': p['description']})
    # Ensure worker is alive to process mutations
    fe.lifecycle.ensure_worker(binary_id)
    # Invalidate decompile cache for this function
    decompile_cache = fe.settings.cache_dir / sha / 'decompile'
    for f in [decompile_cache / f'0x{ea:x}.json', decompile_cache / f'sub_{ea:X}.json']:
        if f.exists():
            f.unlink(missing_ok=True)
    return {
        'binary_id': binary_id,
        'status': 'patches_queued',
        'patch_count': len(patches),
        'patches': tickets,
        'message': f'{len(patches)} patches queued. Worker will apply them. Then call decompile() to get clean pseudocode.',
    }

@mcp.tool()
def emulate_concrete(
    binary_id: str,
    address: str,
    max_instructions: int = 100,
    initial_registers: str = "",
    initial_memory: str = "",
) -> dict[str, Any]:
    """Concrete emulation with seeded register and memory values.

    Unlike symbolic emulation, this feeds real values to get real outputs.
    Use for hash function verification, crypto algorithm identification,
    and opaque predicate evaluation.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Virtual address to start emulation (0x...).
        max_instructions: Stop after this many instructions.
        initial_registers: JSON object mapping register names to int values.
            Example: '{"RAX": 0, "RCX": 4919384}'
        initial_memory: JSON object mapping hex addresses to hex byte strings.
            Example: '{"0x140000000": "4B45524E454C33322E444C4C00"}'

    Returns:
        Final register state with concrete values where resolved.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    ea = int(address, 16)
    regs = json.loads(initial_registers) if initial_registers else None
    mem_raw = json.loads(initial_memory) if initial_memory else None
    mem = None
    if mem_raw:
        mem = {int(k, 16): bytes.fromhex(v) for k, v in mem_raw.items()}
    from .cff_analysis import emulate_concrete as _emulate
    result = _emulate(pe_path, ea, max_instructions=max_instructions,
                      initial_regs=regs, initial_memory=mem)
    result["binary_id"] = binary_id
    return result


@mcp.tool()
def batch_cff_scan(
    binary_id: str,
    min_blocks: int = 20,
    limit: int = 50,
) -> dict[str, Any]:
    """Scan all functions for CFF obfuscation.

    Server-side batch scan. For each function with at least ``min_blocks``
    basic blocks, runs CFF detection and returns a summary.

    Args:
        binary_id: Opaque handle from open_binary.
        min_blocks: Skip functions smaller than this (CFF inflates block count).
        limit: Maximum functions to scan.

    Returns:
        List of CFF-positive functions with signature, confidence, state count.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    def _compute():
        from .cff_analysis import disassemble_function as _disasm, detect_cff as _detect
        from .cff_helpers import _load_text_section, _detect_arch
        import logging
        logging.getLogger('asmblock').setLevel(logging.CRITICAL)
        text_bytes, text_base, text_size = _load_text_section(pe_path)
        if not text_bytes:
            return {'error': 'Cannot locate .text section', 'functions': []}
        idx = fe.cache.get_result(sha, 'function_index', '')
        func_addrs = []
        if idx and 'entries' in idx:
            func_addrs = [int(e['address'], 16) for e in idx['entries']
                          if e.get('address', '').startswith('0x')]
        if not func_addrs:
            return {'error': 'No function index. Run list_functions first.', 'functions': []}
        results = []
        scanned = 0
        for addr in func_addrs:
            if scanned >= limit:
                break
            if not (text_base <= addr < text_base + text_size):
                continue
            try:
                cfg = _disasm(pe_path, addr)
                bc = cfg.get('stats', {}).get('block_count', 0)
                if bc < min_blocks:
                    continue
                scanned += 1
                det = _detect(pe_path, addr)
                if det.get('is_cff'):
                    results.append({'address': f'0x{addr:x}', 'block_count': bc,
                        'signature': det.get('matched_signature'),
                        'confidence': det.get('confidence'),
                        'opaque_count': len(det.get('opaque_predicates', []))})
            except (ValueError, RuntimeError, KeyError, TypeError):
                continue
        return {'scanned': scanned, 'cff_positive': len(results), 'functions': results}
    return _server_tool('batch_cff_scan', binary_id, f'{min_blocks}_{limit}', _compute)


@mcp.tool()
def decrypt_function_strings(
    binary_id: str,
    decryptor_address: str,
    caller_address: str,
    max_instructions: int = 500,
) -> dict[str, Any]:
    """Decrypt all encrypted strings in a single function.

    Extracts CAST5/AES/Blowfish keys from the function prologue,
    finds every call to the decryptor within the function's CFG,
    resolves per-call key offset and ciphertext pointer, decrypts.

    Args:
        binary_id: Opaque handle from open_binary.
        decryptor_address: Address of the decryption function (0x...).
        caller_address: Entry address of the function to scan (0x...).
        max_instructions: Unused (kept for API compat).

    Returns:
        Per-call decrypted strings with cipher, key size, and plaintext.
    """
    fe = _fe()
    pe_path = fe._workspace_binary(fe._sha(binary_id))
    func_ea = int(caller_address, 16)
    decryptor_ea = int(decryptor_address, 16)
    def _compute():
        from .string_decrypt import decrypt_all_strings as _fn
        return _fn(pe_path, func_ea, decryptor_ea)
    return _server_tool('decrypt_function_strings', binary_id,
                        f'{caller_address}_{decryptor_address}', _compute)


@mcp.tool()
def build_call_tree(
    binary_id: str,
    root_address: str,
    max_depth: int = 3,
    max_functions: int = 20,
) -> dict[str, Any]:
    """Build a call tree from deflattened CFF functions.

    Starting from a root function, deflats it, extracts call targets,
    then recursively deflats those callees up to ``max_depth``.

    Args:
        binary_id: Opaque handle from open_binary.
        root_address: Root function address (0x...).
        max_depth: Maximum recursion depth.
        max_functions: Maximum total functions to deflat.

    Returns:
        Tree of deflattened functions with their call relationships.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    root_ea = int(root_address, 16)
    def _compute():
        from .cff_analysis import deflat_function as _deflat
        tree = []
        visited = set()
        q = [(root_ea, 0)]
        while q and len(tree) < max_functions:
            addr, depth = q.pop(0)
            if addr in visited or depth > max_depth:
                continue
            visited.add(addr)
            try:
                df = _deflat(pe_path, addr)
            except (ValueError, RuntimeError, KeyError, TypeError):
                continue
            states = df.get('states', [])
            calls = set()
            for s in states:
                for c in s.get('calls', []):
                    if isinstance(c, str) and c.startswith('0x'):
                        c = int(c, 16)
                    if isinstance(c, int) and c > 0:
                        calls.add(c)
            tree.append({'address': f'0x{addr:x}', 'depth': depth,
                         'state_count': len(states), 'callees': sorted(f'0x{c:x}' for c in calls)})
            if depth < max_depth:
                for c in calls:
                    if c not in visited:
                        q.append((c, depth + 1))
        return {'root': root_address, 'functions_analyzed': len(tree), 'tree': tree}
    return _server_tool('build_call_tree', binary_id,
                        f'{root_address}_{max_depth}', _compute)


@mcp.tool()
def decrypt_binary_strings(
    binary_id: str,
    decryptor_address: str,
) -> dict[str, Any]:
    """Decrypt ALL encrypted strings across the entire binary.

    Finds every function containing calls to the decryptor,
    runs per-function decryption with prologue key extraction,
    deduplicates by ciphertext address. Tries CAST-128, AES-128, Blowfish.

    Args:
        binary_id: Opaque handle from open_binary.
        decryptor_address: Address of the string decryption function (0x...).

    Returns:
        All decrypted strings with cipher detected, call addresses, and plaintext.
    """
    fe = _fe()
    pe_path = fe._workspace_binary(fe._sha(binary_id))
    decryptor_ea = int(decryptor_address, 16)
    def _compute():
        from .string_decrypt import decrypt_binary_strings as _fn
        return _fn(pe_path, decryptor_ea)
    return _server_tool('decrypt_binary_strings', binary_id,
                        decryptor_address, _compute)


@mcp.tool()
def find_api_call_sites(
    binary_id: str,
    api_name: str,
) -> dict[str, Any]:
    """Find all call sites for a specific API in the binary.

    Searches three resolution paths:
    1. IAT direct: FF 15 calls to IAT slot
    2. Thunk indirect: E8 calls to JMP [IAT] wrappers
    3. Hash resolved: Custom hash constants in .rdata

    Handles ordinal imports (WS2_32, OLEAUT32).

    Args:
        binary_id: Opaque handle from open_binary.
        api_name: API function name (e.g. 'TerminateProcess', 'socket').

    Returns:
        Call site addresses, IAT address, thunk address, hash locations.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    from .api_tracer import find_api_call_sites as _find
    result = _find(pe_path, api_name)
    result['binary_id'] = binary_id
    return result


@mcp.tool()
def trace_hash_xrefs(
    binary_id: str,
    api_name: str,
) -> dict[str, Any]:
    """Find which functions reference a hash constant for a dynamically resolved API.

    Computes the API hash, finds it in .rdata, then scans .text for
    instructions that reference that address. Returns xref locations.

    Args:
        binary_id: Opaque handle from open_binary.
        api_name: API function name to trace.

    Returns:
        Hash value, .rdata locations, and xref instruction addresses.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    from .api_tracer import trace_hash_xrefs as _trace
    result = _trace(pe_path, api_name)
    result['binary_id'] = binary_id
    return result


@mcp.tool()
def verify_capabilities(
    binary_id: str,
) -> dict[str, Any]:
    """Scan binary APIs and classify into capabilities from database.

    Enumerates all APIs the binary actually uses (imports, thunks, hash
    table), then classifies using ``data/api_categories.json``. The
    database is editable — add new APIs/categories without code changes.

    Args:
        binary_id: Opaque handle from open_binary.

    Returns:
        Per-capability verdict (confirmed/absent) with API evidence.
        Includes uncategorized APIs that don't match any known category.
    """
    fe = _fe()
    pe_path = fe._workspace_binary(fe._sha(binary_id))
    def _compute():
        from .api_tracer import classify_capabilities as _fn
        return _fn(pe_path)
    return _server_tool('verify_capabilities', binary_id, '', _compute)


# ======================================================================
# TOOLS \u2014 PE reader (synchronous, no worker required)
#
# These three tools read the binary file directly off disk via
# pe_reader.PEReader. No IDA round-trip, no cache poll, no pending
# status. They give the agent the "enumerate strings" and "read memory"
# surface that was missing from the existing catalog -- without those
# the agent cannot find URL constants like the XRed C2 URLs unless
# classify_strings happens to pick them up (which it routinely does not).
# ======================================================================


@mcp.tool()
def list_strings(
    binary_id: str,
    min_length: int = 4,
    encoding: str = "all",
    section: str | None = None,
    offset: int = 0,
    limit: int = 2000,
    filter_text: str = "",
) -> dict[str, Any]:
    """Enumerate every printable string in the binary file.

    Synchronous \u2014 reads the PE off disk and walks each section's
    bytes. Returns ASCII and UTF-16LE runs >= ``min_length`` chars.

    Args:
        binary_id: Opaque handle from open_binary.
        min_length: Minimum string length to surface (default 4).
        encoding: ``"ascii"``, ``"utf16"``, or ``"all"`` (default).
        section: Optional section name to limit the scan
            (``"CODE"``, ``".rdata"``, ``"DATA"``, ...). ``None`` walks
            every section with non-zero raw size.
        offset: Pagination offset into the full result list.
        limit: Maximum strings to return (default 2000).
        filter_text: Case-insensitive substring filter on the string
            value. Empty disables filtering.

    Returns:
        Dict with ``binary_id``, ``status``, ``total``, ``offset``,
        ``limit``, and ``strings`` (list of dicts with ``address``,
        ``section``, ``encoding``, ``length``, ``value``).
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    from .pe_reader import PEReader
    reader = PEReader(pe_path)
    ft = filter_text.lower()
    all_hits: list[dict[str, Any]] = []
    for hit in reader.iter_strings(
        min_length=min_length, encoding=encoding, section=section,
    ):
        if ft and ft not in hit["value"].lower():
            continue
        all_hits.append(hit)
    total = len(all_hits)
    page = all_hits[offset:offset + limit]
    return {
        "binary_id": binary_id,
        "status": "ready",
        "total": total,
        "offset": offset,
        "limit": limit,
        "strings": page,
    }


@mcp.tool()
def read_memory(
    binary_id: str,
    address: str,
    size: int = 64,
) -> dict[str, Any]:
    """Read raw bytes from the loaded image at a virtual address.

    Synchronous \u2014 translates VA to file offset via the PE section
    table and reads bytes off disk. Returns ``b''`` (empty bytes) for
    VAs that aren't backed by on-disk bytes (BSS / uninitialized).

    Args:
        binary_id: Opaque handle from open_binary.
        address: Virtual address as a hex string (``"0x401000"``) or
            decimal int-string.
        size: Number of bytes to read (default 64). Clipped at the
            owning section's raw end so the read never bleeds across
            section boundaries.

    Returns:
        Dict with ``binary_id``, ``status``, ``address``, ``section``,
        ``size``, ``hex`` (raw bytes hex-encoded), and ``ascii`` (a
        printable rendering: printable chars as-is, others as ``.``).
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    from .pe_reader import PEReader
    reader = PEReader(pe_path)
    va = int(address, 0)
    raw = reader.read_va(va, max(1, size))
    ascii_render = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw)
    return {
        "binary_id": binary_id,
        "status": "ready",
        "address": f"0x{va:08x}",
        "section": reader.section_for_va(va),
        "size": len(raw),
        "hex": raw.hex(),
        "ascii": ascii_render,
    }


@mcp.tool()
def get_string_at(
    binary_id: str,
    address: str,
    max_length: int = 512,
    encoding: str = "ascii",
) -> dict[str, Any]:
    """Read a null-terminated string at a virtual address.

    Convenience wrapper over ``read_memory`` for the common case of
    "resolve this string-pointer constant in code to the actual
    string value". Caps at ``max_length`` to bound corrupt-pointer
    blast radius.

    Args:
        binary_id: Opaque handle from open_binary.
        address: Virtual address as a hex string (``"0x49b000"``).
        max_length: Hard cap on bytes scanned for the null terminator.
        encoding: ``"ascii"`` (read_cstring) or ``"utf16"``
            (read_wstring \u2014 UTF-16LE, two bytes per char).

    Returns:
        Dict with ``binary_id``, ``status``, ``address``, ``section``,
        ``encoding``, ``value`` (the decoded string), and ``length``
        (in characters, not bytes).
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    pe_path = fe._workspace_binary(sha)
    from .pe_reader import PEReader
    reader = PEReader(pe_path)
    va = int(address, 0)
    if encoding == "utf16":
        raw = reader.read_wstring(va, max_length)
        value = raw.decode("utf-16-le", errors="replace")
    else:
        raw = reader.read_cstring(va, max_length)
        value = raw.decode("latin-1", errors="replace")
    return {
        "binary_id": binary_id,
        "status": "ready",
        "address": f"0x{va:08x}",
        "section": reader.section_for_va(va),
        "encoding": encoding,
        "length": len(value),
        "value": value,
    }


def create_server() -> FastMCP:
    """Create and return the FastMCP server instance."""
    return mcp


def main() -> None:
    """Entry point for stdio MCP server."""
    transport = os.environ.get("IDA_HEADLESS_MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)


def main_http() -> None:
    """Entry point for HTTP API server (mirrors every MCP tool as POST)."""
    from .http_api import run_http
    run_http()


if __name__ == "__main__":
    main()
