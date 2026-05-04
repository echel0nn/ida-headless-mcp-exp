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
    """Pure cache reader + lifecycle manager. Zero IDA imports."""

    def __init__(self) -> None:
        self.settings = load_settings()
        self.cache = CacheReader(self.settings.cache_dir)
        self.lifecycle = LifecycleManager(self.settings.cache_dir, self.settings.ida_dir)
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
        """Generic: return cached result or queue and return pending."""
        sha = self._sha(binary_id)
        lc = self.lifecycle.get(binary_id)
        if lc and lc.state < BinaryState.READY:
            return self._pending(binary_id, lc)
        cached = self.cache.get_result(sha, tool, key)
        if cached:
            cached["binary_id"] = binary_id
            cached["status"] = "ready"
            return cached
        # Queue the request
        self.cache.queue_request(sha, tool, params or {})
        return self._pending(binary_id, lc)


@lru_cache(maxsize=1)
def _fe() -> _Frontend:
    return _Frontend()


# ======================================================================
# TOOLS — lifecycle management (no IDA needed)
# ======================================================================


@mcp.tool()
def open_binary(path: str) -> dict:
    """Open a binary for analysis. Returns INSTANTLY — analysis runs in background."""
    fe = _fe()
    target = Path(path).resolve()
    if not target.is_file():
        return {"status": "error", "message": f"File not found: {path}"}

    sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
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
    """Close a binary and remove from active sessions."""
    fe = _fe()
    fe._binaries.pop(binary_id, None)
    return {"binary_id": binary_id, "closed": True}


@mcp.tool()
def list_binaries() -> list:
    """List all registered binaries with their lifecycle state."""
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
    """Return metadata for a binary."""
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
    """Check analysis progress. Returns lifecycle state."""
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


# ======================================================================
# TOOLS — decompile (cache or pending)
# ======================================================================


@mcp.tool()
def decompile(binary_id: str, address_or_name: str, max_lines: int = 500) -> dict:
    """Decompile a function. Returns cached result or queues for background decompilation."""
    fe = _fe()
    sha = fe._sha(binary_id)
    cached = fe.cache.get_decompile(sha, address_or_name)
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        return cached
    fe.cache.queue_decompile(sha, address_or_name)
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
    """List functions from the cached function index."""
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
    """Search for vulnerability patterns. Returns cached results or queues analysis."""
    fe = _fe()
    sha = fe._sha(binary_id)
    cached = fe.cache.get_pattern(sha, pattern_type)
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        return cached
    fe.cache.queue_pattern(sha, pattern_type)
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc)


@mcp.tool()
def binary_survey(binary_id: str, max_hotspots: int = 10) -> dict:
    """One-call orientation from cached data."""
    fe = _fe()
    sha = fe._sha(binary_id)
    cached = fe.cache.get_result(sha, "binary_survey")
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        return cached
    fe.cache.queue_request(sha, "binary_survey", {"max_hotspots": max_hotspots})
    lc = fe.lifecycle.get(binary_id)
    return fe._pending(binary_id, lc)


@mcp.tool()
def call_chain(binary_id: str, target_function: str, depth: int = 5, direction: str = "callers") -> dict:
    """Walk call chains from cached index. No IDA needed if index is cached."""
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
    """Generic handler for IDA-dependent tools: cache hit or queue."""
    fe = _fe()
    sha = fe._sha(binary_id)
    lc = fe.lifecycle.get(binary_id)
    if lc and lc.state < BinaryState.READY:
        return fe._pending(binary_id, lc)
    cached = fe.cache.get_result(sha, tool_name, key)
    if cached:
        cached["binary_id"] = binary_id
        cached["status"] = "ready"
        return cached
    fe.cache.queue_request(sha, tool_name, {"binary_id": binary_id, **params})
    return fe._pending(binary_id, lc)


@mcp.tool()
def xrefs_to(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references to an address or symbol."""
    return _ida_tool("xrefs_to", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def xrefs_from(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references from a function."""
    return _ida_tool("xrefs_from", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def imports(binary_id: str) -> dict:
    """List imports for the binary."""
    return _ida_tool("imports", binary_id)


@mcp.tool()
def exports(binary_id: str) -> dict:
    """List exports for the binary."""
    return _ida_tool("exports", binary_id)


@mcp.tool()
def segments(binary_id: str) -> dict:
    """List segments for the binary."""
    return _ida_tool("segments", binary_id)


@mcp.tool()
def checksec(binary_id: str) -> dict:
    """Return binary mitigation summary."""
    fe = _fe()
    rec = fe._binaries.get(binary_id)
    if rec and "mitigations" in rec:
        return {"binary_id": binary_id, "status": "ready", **rec["mitigations"]}
    return _ida_tool("checksec", binary_id)


@mcp.tool()
def stack_frame(binary_id: str, address_or_name: str) -> dict:
    """Return stack frame sizing information for a function."""
    return _ida_tool("stack_frame", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def call_graph(binary_id: str, address_or_name: str, depth: int = 2, direction: str = "both") -> dict:
    """Return a bounded call graph rooted at the requested function."""
    return _ida_tool(
        "call_graph", binary_id, key=address_or_name, address_or_name=address_or_name, depth=depth, direction=direction
    )


@mcp.tool()
def batch_decompile(binary_id: str, name_pattern: str = "", limit: int = 20, **kwargs: Any) -> dict:
    """Decompile multiple functions selected by structured filters."""
    return _ida_tool("batch_decompile", binary_id, name_pattern=name_pattern, limit=limit, **kwargs)


@mcp.tool()
def diff_binary(binary_id_old: str, binary_id_new: str) -> dict:
    """Diff two analyzed binaries structurally by function metadata."""
    return _ida_tool("diff_binary", binary_id_old, key=binary_id_new, binary_id_new=binary_id_new)


@mcp.tool()
def diff_function(
    binary_id_old: str, address_or_name_old: str, binary_id_new: str, address_or_name_new: str, max_lines: int = 500
) -> dict:
    """Diff two functions using side-by-side pseudocode and unified diff."""
    key = f"{address_or_name_old}_{binary_id_new}_{address_or_name_new}"
    return _ida_tool(
        "diff_function",
        binary_id_old,
        key=key,
        binary_id_new=binary_id_new,
        address_or_name_old=address_or_name_old,
        address_or_name_new=address_or_name_new,
        max_lines=max_lines,
    )


@mcp.tool()
def diff_survey(
    binary_id_old: str, binary_id_new: str, max_changed: int = 20, include_pseudocode_diff: bool = True
) -> dict:
    """One-call N-day survey: structural diff + per-function diffs + security ranking."""
    return _ida_tool(
        "diff_survey",
        binary_id_old,
        key=binary_id_new,
        binary_id_new=binary_id_new,
        max_changed=max_changed,
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
    """Query the decompiler CTree for call expressions matching structural predicates."""
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
    """Return textual Hex-Rays microcode for a function."""
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
    """Trace a sink argument backward through local assignment hops to a source term."""
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
    """Return Hex-Rays decompiler warnings for a function."""
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
    """Return focused pseudocode slices around specific call sites or addresses."""
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
    """Microcode-level use/def chain analysis."""
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
    """IR-backed value-range annotations from the decompiler's microcode analysis."""
    return _ida_tool("value_ranges", binary_id, key=address_or_name, address_or_name=address_or_name)


@mcp.tool()
def classify_behavior(binary_id: str) -> dict:
    """Map imported APIs to ATT&CK-aligned behavioral categories."""
    return _ida_tool("classify_behavior", binary_id)


@mcp.tool()
def detect_anti_analysis(binary_id: str) -> dict:
    """Detect anti-debug, anti-VM, and anti-sandbox techniques."""
    return _ida_tool("detect_anti_analysis", binary_id)


@mcp.tool()
def entropy_analysis(binary_id: str) -> dict:
    """Per-section Shannon entropy for packing/encryption detection."""
    return _ida_tool("entropy_analysis", binary_id)


@mcp.tool()
def classify_strings(binary_id: str, limit: int = 200) -> dict:
    """Classify string references by format: URLs, IPs, registry paths, file paths, base64."""
    return _ida_tool("classify_strings", binary_id, limit=limit)


@mcp.tool()
def detect_dynamic_resolution(binary_id: str, limit: int = 50) -> dict:
    """Find GetProcAddress/LoadLibrary calls and extract dynamically resolved API names."""
    return _ida_tool("detect_dynamic_resolution", binary_id, limit=limit)


@mcp.tool()
def path_feasibility(
    binary_id: str, source_address: str, sink_address: str, timeout_seconds: int = 60, max_steps: int = 200000
) -> dict:
    """Check path feasibility using angr symbolic execution."""
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
    """Find execution paths between two points using angr exploration."""
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
    """Rename a function. Queued — invalidates decompile cache for this function and all callers."""
    return _mutate(binary_id, "rename_function", agent_id, address=address, new_name=new_name)


@mcp.tool()
def rename_variable(
    binary_id: str, function_address: str, old_name: str, new_name: str, agent_id: str = ""
) -> dict:
    """Rename a local variable. Queued — invalidates decompile cache for the function."""
    return _mutate(
        binary_id, "rename_variable", agent_id,
        function_address=function_address, old_name=old_name, new_name=new_name,
    )


@mcp.tool()
def set_comment(binary_id: str, address: str, comment: str, agent_id: str = "") -> dict:
    """Set a comment at an address. Queued — invalidates decompile cache for the function."""
    return _mutate(binary_id, "set_comment", agent_id, address=address, comment=comment)


@mcp.tool()
def set_function_type(
    binary_id: str, function_address: str, prototype: str, agent_id: str = ""
) -> dict:
    """Set a function's prototype/type. Queued — invalidates decompile cache."""
    return _mutate(
        binary_id, "set_function_type", agent_id,
        function_address=function_address, prototype=prototype,
    )


@mcp.tool()
def set_variable_type(
    binary_id: str, function_address: str, variable_name: str, new_type: str, agent_id: str = ""
) -> dict:
    """Set a local variable's type. Queued — invalidates decompile cache."""
    return _mutate(
        binary_id, "set_variable_type", agent_id,
        function_address=function_address, variable_name=variable_name, new_type=new_type,
    )


@mcp.tool()
def patch_bytes(binary_id: str, address: str, hex_bytes: str, agent_id: str = "") -> dict:
    """Patch bytes at an address. Queued — invalidates decompile cache for containing function."""
    return _mutate(binary_id, "patch_bytes", agent_id, address=address, hex_bytes=hex_bytes)


@mcp.tool()
def poll_mutation(binary_id: str, ticket_id: str) -> dict:
    """Check if a mutation has been applied. Returns result or 'queued'."""
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
    """Get the current generation counter. Increments on every write operation."""
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
