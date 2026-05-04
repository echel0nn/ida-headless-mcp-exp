"""Mutation queue — serialized write operations for multi-agent collaboration.

10 agents can read concurrently from cache. All writes go through a single
serial queue processed by the binary_worker. After each write, affected
cache entries are invalidated and the generation counter is bumped.

Write operations:
  rename_function(binary_id, address, new_name)
  rename_variable(binary_id, function_address, old_name, new_name)
  set_comment(binary_id, address, comment)
  set_type(binary_id, function_address, variable_name, new_type)
  patch_bytes(binary_id, address, hex_bytes)

Each mutation response includes:
  - generation: the new generation counter after the write
  - invalidated: list of cache entries that were deleted
  - status: "applied" or "conflict" or "error"
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

__all__ = ["MutationQueue", "Generation"]


class Generation:
    """Read/write the generation counter for a binary's cache."""

    def __init__(self, sha_dir: Path) -> None:
        self._path = sha_dir / "generation.txt"

    def read(self) -> int:
        if not self._path.exists():
            return 0
        try:
            return int(self._path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return 0

    def bump(self) -> int:
        gen = self.read() + 1
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(str(gen), encoding="utf-8")
        return gen


class MutationQueue:
    """Append mutations to the write queue. The worker processes them."""

    QUEUE_FILENAME = "write_queue.jsonl"

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir

    def submit(
        self,
        sha256: str,
        mutation_type: str,
        params: dict[str, Any],
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Queue a mutation. Returns immediately with a ticket."""
        queue_path = self.cache_dir / sha256 / self.QUEUE_FILENAME
        queue_path.parent.mkdir(parents=True, exist_ok=True)

        ticket_id = f"m_{int(time.time() * 1000)}"
        entry = {
            "ticket_id": ticket_id,
            "type": mutation_type,
            "params": params,
            "agent_id": agent_id,
            "timestamp": time.time(),
            "status": "queued",
        }
        with queue_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

        return {
            "ticket_id": ticket_id,
            "status": "queued",
            "message": "Mutation queued for the binary worker.",
        }

    def poll_result(self, sha256: str, ticket_id: str) -> dict[str, Any] | None:
        """Check if a mutation has been processed."""
        result_path = (
            self.cache_dir / sha256 / "write_results" / f"{ticket_id}.json"
        )
        if not result_path.exists():
            return None
        try:
            return json.loads(result_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None


def invalidate_for_rename(sha_dir: Path, address: str, index_data: list) -> list[str]:
    """Delete cache entries affected by a function rename.

    Affected:
      - The renamed function's decompile cache
      - All callers' decompile caches (they reference the old name)
      - The function index (names changed)
      - Pattern results (may reference old name)
    """
    invalidated: list[str] = []
    decompile_dir = sha_dir / "decompile"

    # Delete the renamed function's cache (by address)
    for f in decompile_dir.glob(f"{address}*"):
        f.unlink(missing_ok=True)
        invalidated.append(str(f.name))

    # Find callers from index and delete their caches too
    addr_lower = address.lower()
    for entry in index_data:
        if isinstance(entry, dict):
            callees = entry.get("callees", [])
            # Check if this function calls the renamed one
            for callee in callees:
                if addr_lower in callee.lower():
                    caller_addr = entry.get("address", "")
                    for f in decompile_dir.glob(f"{caller_addr}*"):
                        f.unlink(missing_ok=True)
                        invalidated.append(str(f.name))
                    # Also delete by name
                    caller_name = entry.get("name", "")
                    if caller_name:
                        name_cache = decompile_dir / f"{caller_name}.json"
                        if name_cache.exists():
                            name_cache.unlink(missing_ok=True)
                            invalidated.append(caller_name)
                    break

    # Delete index (will be rebuilt)
    index_path = sha_dir / "index.json"
    if index_path.exists():
        index_path.unlink(missing_ok=True)
        invalidated.append("index.json")

    # Delete all pattern results (names may have changed)
    patterns_dir = sha_dir / "patterns"
    if patterns_dir.exists():
        for f in patterns_dir.glob("*.json"):
            f.unlink(missing_ok=True)
            invalidated.append(f"patterns/{f.name}")

    return invalidated


def invalidate_for_patch(sha_dir: Path, address: str, index_data: list) -> list[str]:
    """Delete cache entries affected by a byte patch.

    Affected:
      - The containing function's decompile cache
      - Pattern results (code changed)
    """
    invalidated: list[str] = []
    decompile_dir = sha_dir / "decompile"

    # Find which function contains this address
    patch_ea = int(address, 16) if address.startswith("0x") else int(address)
    for entry in index_data:
        if not isinstance(entry, dict):
            continue
        func_addr = entry.get("address", "")
        func_size = entry.get("size_bytes", 0)
        if func_addr:
            func_ea = int(func_addr, 16)
            if func_ea <= patch_ea < func_ea + func_size:
                # This function contains the patched address
                for f in decompile_dir.glob(f"{func_addr}*"):
                    f.unlink(missing_ok=True)
                    invalidated.append(str(f.name))
                name = entry.get("name", "")
                if name:
                    name_cache = decompile_dir / f"{name}.json"
                    if name_cache.exists():
                        name_cache.unlink(missing_ok=True)
                        invalidated.append(name)
                break

    # Delete pattern results
    patterns_dir = sha_dir / "patterns"
    if patterns_dir.exists():
        for f in patterns_dir.glob("*.json"):
            f.unlink(missing_ok=True)
            invalidated.append(f"patterns/{f.name}")

    return invalidated


def invalidate_for_comment(sha_dir: Path, address: str) -> list[str]:
    """Delete cache entries affected by a comment change. Only the function's decompile."""
    invalidated: list[str] = []
    decompile_dir = sha_dir / "decompile"
    # Comments only affect the decompile output of the containing function
    # We don't know which function contains this address without the index
    # Delete by address prefix
    addr_prefix = address.split("+")[0]  # handle address+offset
    for f in decompile_dir.glob(f"{addr_prefix}*"):
        f.unlink(missing_ok=True)
        invalidated.append(str(f.name))
    return invalidated
