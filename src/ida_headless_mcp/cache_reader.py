"""Cache reader — the MCP server's only data source.

The MCP server NEVER imports idalib. It reads results from the shared
cache directory. If a result isn't cached, it queues the request and
returns {"status": "pending"}.

Workers write to cache. The server reads from cache. The filesystem
is the only communication channel.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = ["CacheReader"]


class CacheReader:
    """Read-only interface to the shared cache directory."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def get_lifecycle(self, sha256: str) -> dict[str, Any] | None:
        """Read lifecycle state for a binary."""
        path = self.cache_dir / sha256 / "state.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def all_lifecycles(self) -> list[dict[str, Any]]:
        """Read all lifecycle states."""
        result = []
        if not self.cache_dir.exists():
            return result
        for d in self.cache_dir.iterdir():
            if d.is_dir() and len(d.name) == 64:
                lc = self.get_lifecycle(d.name)
                if lc:
                    result.append(lc)
        return result

    # ------------------------------------------------------------------
    # Decompile cache
    # ------------------------------------------------------------------

    def get_decompile(self, sha256: str, address_or_name: str) -> dict[str, Any] | None:
        """Read a cached decompilation result."""
        # Try exact key first
        path = self._decompile_path(sha256, address_or_name)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return None

        # Try name->address resolution from index
        resolved = self._resolve_name(sha256, address_or_name)
        if resolved and resolved != address_or_name:
            path = self._decompile_path(sha256, resolved)
            if path.exists():
                try:
                    return json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    return None
        return None

    def queue_decompile(self, sha256: str, address_or_name: str) -> None:
        """Append a decompile request to the worker queue."""
        queue = self.cache_dir / sha256 / "request_queue.jsonl"
        queue.parent.mkdir(parents=True, exist_ok=True)
        entry = json.dumps({"type": "decompile", "target": address_or_name})
        with queue.open("a", encoding="utf-8") as fh:
            fh.write(entry + "\n")

    # ------------------------------------------------------------------
    # Index cache
    # ------------------------------------------------------------------

    def get_index(self, sha256: str) -> dict[str, Any] | None:
        """Read the cached function index."""
        path = self.cache_dir / sha256 / "index.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    # ------------------------------------------------------------------
    # Pattern cache
    # ------------------------------------------------------------------

    def get_pattern(self, sha256: str, pattern_type: str) -> dict[str, Any] | None:
        """Read a cached pattern search result."""
        path = self.cache_dir / sha256 / "patterns" / f"{pattern_type}_v1.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def queue_pattern(self, sha256: str, pattern_type: str) -> None:
        """Queue a pattern search request."""
        queue = self.cache_dir / sha256 / "request_queue.jsonl"
        queue.parent.mkdir(parents=True, exist_ok=True)
        entry = json.dumps({"type": "search_pattern", "pattern_type": pattern_type})
        with queue.open("a", encoding="utf-8") as fh:
            fh.write(entry + "\n")

    # ------------------------------------------------------------------
    # Generic result cache
    # ------------------------------------------------------------------

    def get_result(self, sha256: str, tool_name: str, key: str = "") -> dict[str, Any] | None:
        """Read a cached tool result."""
        safe_key = key.replace("/", "_").replace("\\", "_").replace(":", "_")
        filename = f"{tool_name}_{safe_key}.json" if safe_key else f"{tool_name}.json"
        path = self.cache_dir / sha256 / "results" / filename
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def queue_request(self, sha256: str, tool_name: str, params: dict[str, Any]) -> None:
        """Queue a generic tool request for the worker."""
        queue = self.cache_dir / sha256 / "request_queue.jsonl"
        queue.parent.mkdir(parents=True, exist_ok=True)
        entry = json.dumps({"type": tool_name, **params})
        with queue.open("a", encoding="utf-8") as fh:
            fh.write(entry + "\n")

    def check_staleness(self, sha256: str, cache_file: Path) -> dict[str, Any]:
        """Check if a cache file is stale relative to the generation counter.

        A file is stale if it was written BEFORE the last generation bump.

        Args:
            sha256: Hash identifying the binary.
            cache_file: Path to the cache file to check.

        Returns:
            Staleness info to embed in every read response.
        """
        gen_path = self.cache_dir / sha256 / "generation.txt"
        if not gen_path.exists():
            # No writes have ever happened — nothing is stale
            return {"stale": False, "generation": 0, "cache_generation": 0}

        try:
            current_gen = int(gen_path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return {"stale": False, "generation": 0, "cache_generation": 0}

        if not cache_file.exists():
            return {"stale": True, "generation": current_gen, "cache_generation": -1}

        # Compare: gen file mtime vs cache file mtime
        # If gen file is newer than cache file, cache is stale
        gen_mtime = gen_path.stat().st_mtime
        cache_mtime = cache_file.stat().st_mtime
        is_stale = gen_mtime > cache_mtime

        return {
            "stale": is_stale,
            "generation": current_gen,
            "cache_mtime": cache_mtime,
            "generation_mtime": gen_mtime,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _decompile_path(self, sha256: str, address_or_name: str) -> Path:
        safe = address_or_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        return self.cache_dir / sha256 / "decompile" / f"{safe}.json"

    def _resolve_name(self, sha256: str, name: str) -> str | None:
        """Try to resolve a function name to an address using the cached index."""
        index_data = self.get_index(sha256)
        if not index_data:
            return None
        name_lower = name.lower()
        for entry in index_data:
            if isinstance(entry, dict) and entry.get("name", "").lower() == name_lower:
                return entry.get("address")
        return None

    def queue_depth(self, sha256: str) -> int:
        """Count pending requests in the queue."""
        queue = self.cache_dir / sha256 / "request_queue.jsonl"
        if not queue.exists():
            return 0
        try:
            return len(queue.read_text(encoding="utf-8").strip().splitlines())
        except OSError:
            return 0



def pe_mitigations(path: Path) -> dict[str, Any]:
    """Parse PE header for security mitigations. No IDA needed."""
    import struct

    data = path.read_bytes()
    if data[:2] != b"MZ":
        return {"type": "not_pe"}
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        return {"type": "bad_pe"}
    opt_off = pe_off + 4 + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    dll_off = opt_off + (70 if magic == 0x20B else 66)
    dll_chars = struct.unpack_from("<H", data, dll_off)[0]
    return {
        "type": "pe",
        "aslr_pie": bool(dll_chars & 0x0040),
        "nx": bool(dll_chars & 0x0100),
        "cfg": bool(dll_chars & 0x4000),
        "raw_dll_characteristics": hex(dll_chars),
    }
