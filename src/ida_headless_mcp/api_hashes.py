"""Multi-algorithm API hash engine -- 107 algorithms from HashDB.

Dynamically loads ALL hash algorithm implementations from
``data/hashdb_algorithms/`` (cloned from OALabs/hashdb). No hardcoded
algorithms. Auto-detection tries every algorithm against the API name
corpus and picks the best match.

Algorithms cover: CRC32, DJB2 variants, FNV-1/1a, ROR13 variants,
ROL variants, Conti, LockBit, Emotet, SmokeLoader, GuLoader,
MurmurHash, and 90+ more malware-specific hash functions.
"""
from __future__ import annotations

import importlib.util
import struct
from pathlib import Path
from typing import Any

__all__ = ["hash_api", "list_algorithms", "auto_detect", "get_algorithm", "resolve_api_hashes"]

_ALGO_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "hashdb_algorithms"
_LOADED: dict[str, Any] = {}  # name -> module
_LOADED_FLAG = False


def _ensure_loaded() -> None:
    """Lazy-load all algorithm modules on first use."""
    global _LOADED_FLAG
    if _LOADED_FLAG:
        return
    _LOADED_FLAG = True
    if not _ALGO_DIR.is_dir():
        return
    for f in sorted(_ALGO_DIR.iterdir()):
        if not f.name.endswith(".py") or f.name == "__init__.py":
            continue
        name = f.stem
        try:
            spec = importlib.util.spec_from_file_location(name, str(f))
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "hash"):
                _LOADED[name] = mod
        except (ImportError, SyntaxError, AttributeError, OSError):
            continue


def list_algorithms() -> list[dict[str, Any]]:
    """Return metadata for all loaded hash algorithms."""
    _ensure_loaded()
    result = []
    for name, mod in sorted(_LOADED.items()):
        result.append({
            "name": name,
            "description": getattr(mod, "DESCRIPTION", ""),
            "type": getattr(mod, "TYPE", "unsigned_int"),
            "bits": 64 if getattr(mod, "TYPE", "") == "unsigned_long" else 32,
        })
    return result


def get_algorithm(name: str) -> Any:
    """Get a loaded algorithm module by name."""
    _ensure_loaded()
    return _LOADED.get(name)


def hash_api(name: str, algorithm: str) -> int | None:
    """Hash a string with the specified algorithm.

    Args:
        name: String to hash (API name, DLL name, etc.).
        algorithm: Algorithm name (must match a file in hashdb_algorithms/).

    Returns:
        Hash value as integer, or None if algorithm not found.
    """
    _ensure_loaded()
    mod = _LOADED.get(algorithm)
    if mod is None:
        return None
    try:
        return mod.hash(name.encode("ascii", "replace"))
    except (TypeError, ValueError, OverflowError):
        return None


def _load_api_names() -> list[str]:
    """Load the API name corpus."""
    corpus = Path(__file__).resolve().parent.parent.parent / "data" / "api_names.txt"
    if not corpus.exists():
        return []
    return [l.strip() for l in corpus.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]


def auto_detect(
    pe_data: bytes,
    min_matches: int = 3,
    top_n: int = 5,
    algorithms: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Auto-detect which hash algorithm(s) a binary uses.

    Scans the binary for 4-byte (and optionally 8-byte) constants,
    tries every loaded algorithm against the API name corpus, and
    returns algorithms ranked by match count.

    Args:
        pe_data: Raw PE file bytes.
        min_matches: Minimum matches to report.
        top_n: Return top N algorithms.
        algorithms: Limit to these algorithms (None = try all).

    Returns:
        List of {algorithm, match_count, sample_matches} ranked by matches.
    """
    _ensure_loaded()
    api_names = _load_api_names()
    if not api_names:
        return [{"error": "No API corpus at data/api_names.txt"}]

    # Build set of all 4-byte constants in the binary (skip first 0x400 = PE header)
    constants_32: set[int] = set()
    for i in range(0x400, len(pe_data) - 4, 4):
        val = struct.unpack_from("<I", pe_data, i)[0]
        if val > 0xFFFF:  # skip small values
            constants_32.add(val)

    constants_64: set[int] = set()
    for i in range(0x400, len(pe_data) - 8, 8):
        val = struct.unpack_from("<Q", pe_data, i)[0]
        if val > 0xFFFFFFFF:
            constants_64.add(val)

    algos_to_try = algorithms or list(_LOADED.keys())
    results: list[dict[str, Any]] = []

    for algo_name in algos_to_try:
        mod = _LOADED.get(algo_name)
        if mod is None:
            continue
        is_64 = getattr(mod, "TYPE", "") == "unsigned_long"
        constants = constants_64 if is_64 else constants_32

        # Precompute hashes for corpus
        matches: list[dict[str, str]] = []
        for api in api_names:
            try:
                h = mod.hash(api.encode("ascii", "replace"))
            except (TypeError, ValueError, OverflowError):
                continue
            if h is None or h == 0xFFFFFFFE:  # HashDB invalid marker
                continue
            if h in constants:
                matches.append({"api": api, "hash": f"0x{h:08x}"})
                if len(matches) >= 50:  # cap per algorithm
                    break

        if len(matches) >= min_matches:
            results.append({
                "algorithm": algo_name,
                "description": getattr(mod, "DESCRIPTION", ""),
                "match_count": len(matches),
                "sample_matches": matches[:10],
            })

    results.sort(key=lambda x: x["match_count"], reverse=True)
    return results[:top_n]



# Precomputed database for instant hash lookup
_HASHDB: dict[str, dict[int, str]] | None = None
_HASHDB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "hashdb.json.gz"


def _ensure_hashdb() -> dict[str, dict[int, str]]:
    """Lazy-load the precomputed hashdb.json.gz database."""
    global _HASHDB
    if _HASHDB is not None:
        return _HASHDB
    import gzip
    import json
    if not _HASHDB_PATH.exists():
        _HASHDB = {}
        return _HASHDB
    with gzip.open(_HASHDB_PATH, 'rt', encoding='utf-8') as fh:
        raw = json.load(fh)
    # Convert string keys back to int for fast lookup
    _HASHDB = {}
    for algo_name, entries in raw.items():
        _HASHDB[algo_name] = {int(k): v for k, v in entries.items()}
    return _HASHDB


def resolve_api_hashes(
    hash_candidates: list[int],
) -> dict[str, Any]:
    """Resolve a list of hash values to API names using the precomputed database.

    Tries every algorithm against each candidate. Returns matches grouped
    by algorithm with the resolved API name.

    Args:
        hash_candidates: List of 32/64-bit integer hash values to resolve.

    Returns:
        Dict with resolved_count, resolved list, and algorithm summary.
    """
    db = _ensure_hashdb()
    if not db:
        return {'resolved_count': 0, 'resolved': [],
                'error': 'hashdb.json.gz not found'}
    resolved: list[dict[str, Any]] = []
    seen: set[int] = set()
    for val in hash_candidates:
        if val in seen:
            continue
        seen.add(val)
        for algo_name, entries in db.items():
            api = entries.get(val)
            if api:
                resolved.append({
                    'hash': f'0x{val:08x}',
                    'api': api,
                    'algorithm': algo_name,
                })
                break  # first algorithm match wins
    return {
        'resolved_count': len(resolved),
        'resolved': resolved,
    }