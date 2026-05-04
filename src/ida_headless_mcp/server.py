from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import load_settings

__all__ = ["create_server", "main"]

mcp = FastMCP("IDA Headless MCP", json_response=True)

_pool_mode = os.environ.get("IDA_HEADLESS_MCP_POOL", "").strip().lower() in ("1", "true", "yes")


class _Backend:
    """Unified backend — routes to either in-process manager or worker pool."""

    def __init__(self) -> None:
        settings = load_settings()
        if _pool_mode or settings.max_concurrent_ida > 1:
            from .pool import WorkerPool
            self._pool: Any = WorkerPool(settings)
            self._mgr = None
        else:
            from .session import IDABinarySessionManager
            self._mgr = IDABinarySessionManager(settings)
            self._pool = None

    def call(self, method: str, params: dict) -> Any:
        if self._pool is not None:
            return self._pool.call(method, params)
        from .worker import _dispatch
        return _dispatch(self._mgr, method, params)

    def __getattr__(self, name: str):
        """Proxy attribute access to .call() for tool compatibility."""
        if self._mgr is not None:
            # Direct mode: call the method on the manager directly
            return getattr(self._mgr, name)
        # Pool mode: serialize args into params dict for the worker
        import inspect

        from .session import IDABinarySessionManager
        method = getattr(IDABinarySessionManager, name, None)
        if method is None:
            raise AttributeError(name)
        sig = inspect.signature(method)
        def _proxy(*args, **kwargs):
            bound = sig.bind(None, *args, **kwargs)  # None for self
            bound.apply_defaults()
            params = dict(bound.arguments)
            params.pop('self', None)
            return self.call(name, params)
        return _proxy


@lru_cache(maxsize=1)
def _backend() -> _Backend:
    return _Backend()

@mcp.tool()
def open_binary(path: str) -> dict:
    """Open a binary in IDA headless and return metadata."""
    return _backend().call("open_binary", {"path": path})


@mcp.tool()
def close_binary(binary_id: str, save: bool = False) -> dict:
    """Close a previously opened binary."""
    return _backend().call("close_binary", {"binary_id": binary_id, "save": save})


@mcp.tool()
def list_binaries() -> dict:
    """List currently registered binary sessions."""
    return _backend().call("list_binaries", {})


@mcp.tool()
def binary_metadata(binary_id: str) -> dict:
    """Return metadata for an opened binary."""
    return _backend().call("binary_metadata", {"binary_id": binary_id})


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
    """List functions in a binary with optional structured filtering."""
    return _backend().list_functions(
        binary_id,
        offset=offset,
        limit=limit,
        filter_text=filter_text,
        order_by=order_by,
        min_size_bytes=min_size_bytes,
        min_complexity=min_complexity,
        exclude_thunks=exclude_thunks,
        exclude_libraries=exclude_libraries,
    )


@mcp.tool()
def decompile(binary_id: str, address_or_name: str, max_lines: int = 500) -> dict:
    """Decompile a function by address or name."""
    return _backend().decompile(binary_id, address_or_name, max_lines=max_lines)


@mcp.tool()
def xrefs_to(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references to an address or symbol."""
    return _backend().xrefs_to(binary_id, address_or_name)


@mcp.tool()
def xrefs_from(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references from a function."""
    return _backend().xrefs_from(binary_id, address_or_name)


@mcp.tool()
def imports(binary_id: str) -> dict:
    """List imports for the binary."""
    return _backend().imports(binary_id)


@mcp.tool()
def exports(binary_id: str) -> dict:
    """List exports for the binary."""
    return _backend().exports(binary_id)


@mcp.tool()
def segments(binary_id: str) -> dict:
    """List segments for the binary."""
    return _backend().segments(binary_id)


@mcp.tool()
def checksec(binary_id: str) -> dict:
    """Return binary mitigation summary."""
    return _backend().checksec(binary_id)


@mcp.tool()
def stack_frame(binary_id: str, address_or_name: str) -> dict:
    """Return stack frame sizing information for a function."""
    return _backend().stack_frame(binary_id, address_or_name)


@mcp.tool()
def call_graph(binary_id: str, address_or_name: str, depth: int = 2, direction: str = "both") -> dict:
    """Return a bounded call graph rooted at the requested function."""
    return _backend().call_graph(binary_id, address_or_name, depth=depth, direction=direction)

@mcp.tool()
def batch_decompile(
    binary_id: str,
    name_pattern: str = "",
    callers_of: list[str] | None = None,
    called_by: list[str] | None = None,
    min_size_bytes: int = 0,
    max_size_bytes: int | None = None,
    min_complexity: int = 0,
    max_complexity: int | None = None,
    has_string_ref_matching: str = "",
    exclude_thunks: bool = True,
    exclude_libraries: bool = True,
    order_by: str = "complexity_desc",
    offset: int = 0,
    limit: int = 20,
    max_lines: int = 250,
) -> dict:
    """Decompile multiple functions selected by structured filters."""
    return _backend().batch_decompile(
        binary_id,
        name_pattern=name_pattern,
        callers_of=callers_of,
        called_by=called_by,
        min_size_bytes=min_size_bytes,
        max_size_bytes=max_size_bytes,
        min_complexity=min_complexity,
        max_complexity=max_complexity,
        has_string_ref_matching=has_string_ref_matching,
        exclude_thunks=exclude_thunks,
        exclude_libraries=exclude_libraries,
        order_by=order_by,
        offset=offset,
        limit=limit,
        max_lines=max_lines,
    )


@mcp.tool()
def search_pattern(
    binary_id: str,
    pattern_type: str,
    name_pattern: str = "",
    limit: int = 50,
    max_lines: int = 120,
) -> dict:
    """Search for deterministic vulnerability patterns across indexed functions."""
    return _backend().search_pattern(
        binary_id,
        pattern_type,
        name_pattern=name_pattern,
        limit=limit,
        max_lines=max_lines,
    )

@mcp.tool()
def diff_binary(binary_id_old: str, binary_id_new: str) -> dict:
    """Diff two analyzed binaries structurally by function metadata."""
    return _backend().diff_binary(binary_id_old, binary_id_new)


@mcp.tool()
def diff_function(
    binary_id_old: str,
    address_or_name_old: str,
    binary_id_new: str,
    address_or_name_new: str,
    max_lines: int = 500,
) -> dict:
    """Diff two functions using side-by-side pseudocode and unified diff."""
    return _backend().diff_function(
        binary_id_old,
        address_or_name_old,
        binary_id_new,
        address_or_name_new,
        max_lines=max_lines,
    )

@mcp.tool()
def diff_survey(
    binary_id_old: str,
    binary_id_new: str,
    max_changed: int = 20,
    include_pseudocode_diff: bool = True,
    max_diff_lines: int = 60,
) -> dict:
    """One-call N-day survey: structural diff + per-function diffs + security ranking."""
    return _backend().diff_survey(
        binary_id_old, binary_id_new,
        max_changed=max_changed,
        include_pseudocode_diff=include_pseudocode_diff,
        max_diff_lines=max_diff_lines,
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
    return _backend().query_ctree(
        binary_id,
        address_or_name,
        target_function=target_function,
        argument_index=argument_index,
        contains_operation=contains_operation,
        operand_type_is=operand_type_is,
        limit=limit,
    )


@mcp.tool()
def get_microcode(binary_id: str, address_or_name: str, maturity: str = "current") -> dict:
    """Return textual Hex-Rays microcode for a function at the requested maturity level."""
    return _backend().get_microcode(binary_id, address_or_name, maturity=maturity)

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
    return _backend().trace_dataflow(
        binary_id,
        address_or_name,
        sink_function=sink_function,
        sink_argument_index=sink_argument_index,
        source_contains=source_contains,
        max_steps=max_steps,
    )


@mcp.tool()
def hexrays_warnings(binary_id: str, address_or_name: str) -> dict:
    """Return Hex-Rays decompiler warnings for a function (confidence signals)."""
    return _backend().hexrays_warnings(binary_id, address_or_name)


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
    return _backend().pseudocode_slice_fn(
        binary_id,
        address_or_name,
        focus_callee=focus_callee,
        focus_address=focus_address,
        context_lines=context_lines,
        max_slices=max_slices,
    )


@mcp.tool()
def binary_survey(binary_id: str, max_hotspots: int = 10) -> dict:
    """One-call binary orientation: metadata, attack surface, hotspots, cached pattern hits."""
    return _backend().binary_survey(binary_id, max_hotspots=max_hotspots)


@mcp.tool()
def call_chain(
    binary_id: str,
    target_function: str,
    depth: int = 5,
    direction: str = "callers",
) -> dict:
    """Walk caller/callee chains from a target function. No decompilation needed."""
    return _backend().call_chain(
        binary_id, target_function, depth=depth, direction=direction,
    )


@mcp.tool()
def def_use(
    binary_id: str,
    address_or_name: str,
    target_callee: str = "",
    max_instructions: int = 200,
) -> dict:
    """Microcode-level use/def chain analysis. Shows what each instruction reads and writes."""
    return _backend().def_use(
        binary_id,
        address_or_name,
        target_callee=target_callee,
        max_instructions=max_instructions,
    )



@mcp.tool()
def value_ranges(binary_id: str, address_or_name: str) -> dict:
    """IR-backed value-range annotations from the decompiler's microcode analysis."""
    return _backend().value_ranges(binary_id, address_or_name)



@mcp.tool()
def classify_behavior(binary_id: str) -> dict:
    """Map imported APIs to ATT&CK-aligned behavioral categories (C2, persistence, execution, etc)."""
    return _backend().classify_behavior(binary_id)


@mcp.tool()
def detect_anti_analysis(binary_id: str) -> dict:
    """Detect anti-debug, anti-VM, and anti-sandbox techniques."""
    return _backend().detect_anti_analysis(binary_id)


@mcp.tool()
def entropy_analysis(binary_id: str) -> dict:
    """Per-section Shannon entropy for packing/encryption detection."""
    return _backend().entropy_analysis(binary_id)


@mcp.tool()
def classify_strings(binary_id: str, limit: int = 200) -> dict:
    """Classify string references by format: URLs, IPs, registry paths, file paths, base64."""
    return _backend().classify_strings(binary_id, limit=limit)


@mcp.tool()
def detect_dynamic_resolution(binary_id: str, limit: int = 50) -> dict:
    """Find GetProcAddress/LoadLibrary calls and extract dynamically resolved API names."""
    return _backend().detect_dynamic_resolution(binary_id, limit=limit)


@mcp.tool()
def path_feasibility(
    binary_id: str,
    source_address: str,
    sink_address: str,
    timeout_seconds: int = 60,
    max_steps: int = 200000,
) -> dict:
    """Check if a path from source to sink is feasible using angr symbolic execution."""
    return _backend().path_feasibility(
        binary_id, source_address, sink_address,
        timeout_seconds=timeout_seconds, max_steps=max_steps,
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
    return _backend().find_paths(
        binary_id, from_address, to_address,
        avoid_addresses=avoid_addresses,
        timeout_seconds=timeout_seconds, max_paths=max_paths,
    )


def create_server() -> FastMCP:
    return mcp


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
