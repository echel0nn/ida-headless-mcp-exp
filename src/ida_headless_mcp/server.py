"""MCP server — pure cache reader, NEVER imports idalib.

Every tool call either:
  1. Returns a cached result instantly
  2. Queues a request for the background worker and returns {status: "pending"}

All IDA work happens in binary_worker processes spawned by the lifecycle manager.
The shared filesystem cache is the only communication channel.
"""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .cache_reader import CacheReader
from .config import load_settings
from .lifecycle import BinaryState, LifecycleManager

__all__ = ["create_server", "main"]

mcp = FastMCP(
    "IDA Headless MCP",
    json_response=True,
    host="127.0.0.1",
    port=int(os.environ.get("IDA_HEADLESS_MCP_PORT", "18820")),
)


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

    def _pending(self, binary_id: str, lc: Any) -> dict[str, Any]:
        return {
            "binary_id": binary_id,
            "status": "pending",
            "state": lc.state.name if lc else "UNKNOWN",
            "queue_depth": self.cache.queue_depth(self._sha(binary_id)),
            "message": "Background worker is processing. Retry or poll with poll_analysis().",
        }

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
            return self._pending(binary_id, lc)
        cached = self.cache.get_result(sha, tool, key)
        if cached:
            cached["binary_id"] = binary_id
            cached["status"] = "ready"
            return cached
        # Queue the request and ensure worker is alive to process it
        self.cache.queue_request(sha, tool, params or {})
        self.lifecycle.ensure_worker(binary_id)
        return self._pending(binary_id, lc)


@lru_cache(maxsize=1)
def _fe() -> _Frontend:
    return _Frontend()


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

    Reads directly from filesystem — no worker needed. Use to diagnose
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
        if hb.exists():
            try:
                import json as _json
                h = _json.loads(hb.read_text(encoding="utf-8"))
                info["worker_pid"] = h.get("pid")
                info["worker_status"] = h.get("status")
                info["heartbeat_age_s"] = int(time.time() - h.get("timestamp", 0))
                info["current_request"] = h.get("current_request", "")
            except (ValueError, OSError):
                info["worker_status"] = "heartbeat_corrupt"
        else:
            info["worker_status"] = "no_heartbeat"

        # Queue depth
        q = d / "request_queue.jsonl"
        if q.exists():
            text = q.read_text(encoding="utf-8").strip()
            info["queue_depth"] = len(text.splitlines()) if text else 0
        else:
            info["queue_depth"] = 0

        # Recent errors
        errors_dir = d / "errors"
        if errors_dir.exists():
            err_files = sorted(errors_dir.glob("*.json"))[-3:]
            info["recent_errors"] = []
            for ef in err_files:
                try:
                    import json as _json
                    ed = _json.loads(ef.read_text(encoding="utf-8"))
                    info["recent_errors"].append({
                        "type": ed.get("type", ""),
                        "error": ed.get("error", "")[:100],
                    })
                except (ValueError, OSError):
                    pass
        else:
            info["recent_errors"] = []

        # Check process liveness
        if info.get("worker_pid"):
            import os
            try:
                os.kill(info["worker_pid"], 0)
                info["process_alive"] = True
            except OSError:
                info["process_alive"] = False

        workers.append(info)

    return {"workers": workers, "total": len(workers)}


# ======================================================================
# TOOLS — decompile (cache or pending)
# ======================================================================


@mcp.tool()
def decompile(binary_id: str, address_or_name: str, max_lines: int = 500) -> dict:
    """Decompile a function by address or name.

    Returns the cached result instantly or queues a background
    decompilation and returns a pending status.

    Args:
        binary_id: Opaque handle from open_binary.
        address_or_name: Function address (0x...) or name.
        max_lines: Maximum pseudocode lines to return.

    Returns:
        Decompilation result with pseudocode, or pending status.
    """
    fe = _fe()
    sha = fe._sha(binary_id)
    cached = fe.cache.get_decompile(sha, address_or_name)
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        return cached
    fe.cache.queue_decompile(sha, address_or_name)
    fe.lifecycle.ensure_worker(binary_id)
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc)


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
    fe.lifecycle.ensure_worker(binary_id)
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc)


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
    fe.lifecycle.ensure_worker(binary_id)
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc)


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
        return fe._pending(binary_id, lc)
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
    fe.lifecycle.ensure_worker(binary_id)
    return fe._pending(binary_id, lc)


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
    return _ida_tool(
        "diff_binary", binary_id_old,
        key=binary_id_new, binary_id_new=binary_id_new,
    )


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
        lc = fe.lifecycle.get(bid)
        if lc and lc.state < BinaryState.READY:
            return fe._pending(bid, lc)
    key = f"{address_or_name_old}_{binary_id_new}_{address_or_name_new}"
    return _ida_tool(
        "diff_function", binary_id_old, key=key,
        binary_id_new=binary_id_new, address_or_name_old=address_or_name_old,
        address_or_name_new=address_or_name_new, max_lines=max_lines,
    )


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
        lc = fe.lifecycle.get(bid)
        if lc and lc.state < BinaryState.READY:
            return fe._pending(bid, lc)
    return _ida_tool(
        "diff_survey", binary_id_old, key=binary_id_new,
        binary_id_new=binary_id_new, max_changed=max_changed,
        include_pseudocode_diff=include_pseudocode_diff,
    )


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
def simplify_expression(binary_id: str, address_or_name: str, expression: str) -> dict:
    """Simplify an obfuscated expression by proving equivalence to simpler forms."""
    key = f"{address_or_name}_simplify"
    return _ida_tool("simplify_expression", binary_id, key=key,
                     address_or_name=address_or_name, expression=expression)


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


def create_server() -> FastMCP:
    return mcp


def main() -> None:
    transport = os.environ.get("IDA_HEADLESS_MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
