from __future__ import annotations

from functools import lru_cache

from mcp.server.fastmcp import FastMCP

from .config import load_settings
from .session import IDABinarySessionManager

__all__ = ["create_server", "main"]

mcp = FastMCP("IDA Headless MCP", json_response=True)


@lru_cache(maxsize=1)
def _manager() -> IDABinarySessionManager:
    settings = load_settings()
    return IDABinarySessionManager(settings)


@mcp.tool()
def open_binary(path: str) -> dict:
    """Open a binary in IDA headless and return metadata.

    Args:
        path: Absolute or relative path to a binary file.
    """
    rec = _manager().open_binary(path)
    return _manager().binary_metadata(rec.binary_id)


@mcp.tool()
def close_binary(binary_id: str, save: bool = False) -> dict:
    """Close a previously opened binary.

    Args:
        binary_id: Opaque handle returned by open_binary.
        save: When True, persist database changes before closing.
    """
    return _manager().close_binary(binary_id, save=save)


@mcp.tool()
def list_binaries() -> list[dict]:
    """List currently registered binary sessions."""
    return _manager().list_binaries()


@mcp.tool()
def binary_metadata(binary_id: str) -> dict:
    """Return metadata for an opened binary."""
    return _manager().binary_metadata(binary_id)


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
    return _manager().list_functions(
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
    return _manager().decompile(binary_id, address_or_name, max_lines=max_lines)


@mcp.tool()
def xrefs_to(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references to an address or symbol."""
    return _manager().xrefs_to(binary_id, address_or_name)


@mcp.tool()
def xrefs_from(binary_id: str, address_or_name: str) -> dict:
    """Return cross-references from a function."""
    return _manager().xrefs_from(binary_id, address_or_name)


@mcp.tool()
def imports(binary_id: str) -> dict:
    """List imports for the binary."""
    return _manager().imports(binary_id)


@mcp.tool()
def exports(binary_id: str) -> dict:
    """List exports for the binary."""
    return _manager().exports(binary_id)


@mcp.tool()
def segments(binary_id: str) -> dict:
    """List segments for the binary."""
    return _manager().segments(binary_id)


@mcp.tool()
def checksec(binary_id: str) -> dict:
    """Return binary mitigation summary."""
    return _manager().checksec(binary_id)


@mcp.tool()
def stack_frame(binary_id: str, address_or_name: str) -> dict:
    """Return stack frame sizing information for a function."""
    return _manager().stack_frame(binary_id, address_or_name)


@mcp.tool()
def call_graph(binary_id: str, address_or_name: str, depth: int = 2, direction: str = "both") -> dict:
    """Return a bounded call graph rooted at the requested function."""
    return _manager().call_graph(binary_id, address_or_name, depth=depth, direction=direction)

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
    return _manager().batch_decompile(
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
    return _manager().search_pattern(
        binary_id,
        pattern_type,
        name_pattern=name_pattern,
        limit=limit,
        max_lines=max_lines,
    )

@mcp.tool()
def diff_binary(binary_id_old: str, binary_id_new: str) -> dict:
    """Diff two analyzed binaries structurally by function metadata."""
    return _manager().diff_binary(binary_id_old, binary_id_new)


@mcp.tool()
def diff_function(
    binary_id_old: str,
    address_or_name_old: str,
    binary_id_new: str,
    address_or_name_new: str,
    max_lines: int = 500,
) -> dict:
    """Diff two functions using side-by-side pseudocode and unified diff."""
    return _manager().diff_function(
        binary_id_old,
        address_or_name_old,
        binary_id_new,
        address_or_name_new,
        max_lines=max_lines,
    )


def create_server() -> FastMCP:
    return mcp


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
