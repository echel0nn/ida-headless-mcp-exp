"""API hash resolution — resolve hash-imported Windows API names.

Uses a precomputed database of 33,000+ hash entries across 107 algorithms
derived from OALabs HashDB (MIT license). The database covers 310 Windows
APIs commonly used in malware across algorithms from real malware families
including Cobalt Strike, LockBit, Conti, DanaBot, Emotet, and more.

Database: data/hashdb.json.gz (248 KB compressed)
Algorithms: 107 (ROR13, DJB2, CRC32, FNV-1a, SDBM, Conti, LockBit, ...)
APIs: 310 (kernel32, ntdll, ws2_32, winhttp, advapi32, crypt32, ...)
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

__all__ = ["resolve_api_hashes", "list_algorithms"]

# Lazy-loaded database
_DB: dict[str, dict[str, str]] | None = None
_DB_PATH = Path(__file__).parent.parent.parent / "data" / "hashdb.json.gz"


def _load_db() -> dict[str, dict[str, str]]:
    """Load the compressed hash database."""
    global _DB  # noqa: PLW0603
    if _DB is not None:
        return _DB
    if not _DB_PATH.exists():
        _DB = {}
        return _DB
    with gzip.open(_DB_PATH, "rt", encoding="utf-8") as f:
        _DB = json.load(f)
    return _DB


def list_algorithms() -> list[str]:
    """Return all supported hash algorithm names."""
    return sorted(_load_db().keys())


def resolve_api_hashes(
    hash_values: list[int],
    *,
    algorithms: list[str] | None = None,
) -> dict[str, Any]:
    """Resolve a list of hash values to API names.

    Tries each algorithm against each hash value. Returns all matches.
    With 107 algorithms and 310 APIs, this is a 33K-entry lookup.

    Args:
        hash_values: List of integer hash values found in the binary.
        algorithms: Which algorithms to try (default: all 107).

    Returns:
        Dict with resolved names, algorithm identified, and unresolved hashes.
    """
    db = _load_db()
    algos = algorithms or list(db.keys())

    resolved: list[dict[str, Any]] = []
    unresolved: list[int] = []

    for hval in hash_values:
        hval_str = str(hval & 0xFFFFFFFF)
        found = False
        for algo in algos:
            table = db.get(algo, {})
            if hval_str in table:
                resolved.append({
                    "hash": f"0x{hval:08x}",
                    "api_name": table[hval_str],
                    "algorithm": algo,
                })
                found = True
                break  # first match wins
        if not found:
            unresolved.append(hval)

    return {
        "resolved_count": len(resolved),
        "unresolved_count": len(unresolved),
        "resolved": resolved,
        "unresolved": [f"0x{h:08x}" for h in unresolved[:50]],
        "algorithms_available": len(db),
        "algorithms_checked": len(algos),
    }
