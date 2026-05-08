"""Trace API call sites and classify capabilities from a loadable database.

Scans what the binary actually uses (imports, thunks, hash table, decrypted
strings), then classifies into capabilities using ``data/api_categories.json``.
No hardcoded API lists — the database is editable.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

__all__ = [
    "find_api_call_sites",
    "scan_all_apis",
    "classify_capabilities",
]

# Ordinal databases for common DLLs
_ORDINALS: dict[str, dict[int, str]] = {
    "WS2_32": {
        1: "accept", 2: "bind", 3: "closesocket", 4: "connect",
        6: "getpeername", 7: "getsockname", 8: "getsockopt", 9: "htonl",
        10: "htons", 11: "ioctlsocket", 12: "inet_addr", 13: "inet_ntoa",
        14: "listen", 16: "ntohl", 17: "ntohs", 18: "recv", 19: "recvfrom",
        20: "select", 21: "send", 22: "sendto", 23: "setsockopt",
        24: "shutdown", 25: "socket", 52: "gethostbyname",
        111: "WSAGetLastError", 115: "WSAStartup", 116: "WSACleanup",
        151: "WSASocketW",
    },
    "OLEAUT32": {
        2: "SysAllocString", 4: "SysAllocStringLen", 6: "SysFreeString",
        7: "SysStringLen", 8: "VariantInit", 9: "VariantClear",
        10: "VariantCopy",
    },
}


def _hash_name(name: str, algorithm: str | None) -> int | None:
    """Hash a name with any algorithm from api_hashes. None = skip."""
    if algorithm is None:
        return None
    from .api_hashes import hash_api
    return hash_api(name, algorithm)


def _auto_detect_hash(pe_data: bytes) -> str | None:
    """Auto-detect hash algorithm from binary data."""
    try:
        from .api_hashes import auto_detect
        results = auto_detect(pe_data, min_matches=3, top_n=1)
        if results and 'algorithm' in results[0]:
            return results[0]['algorithm']
    except (ImportError, ValueError, RuntimeError):
        pass
    return None

def _parse_pe(data: bytes) -> tuple[int, list[tuple[str, int, int, int]]]:
    """Return (image_base, [(name, va_abs, raw_size, raw_offset)])."""
    if len(data) < 0x40:
        return 0, []
    elf = struct.unpack_from("<I", data, 0x3C)[0]
    if data[elf:elf + 4] != b"PE\x00\x00":
        return 0, []
    coff = elf + 4
    ns = struct.unpack_from("<H", data, coff + 2)[0]
    opt_sz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    ib = (struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B
          else struct.unpack_from("<I", data, opt + 28)[0] if magic == 0x10B else 0)
    if ib == 0:
        return 0, []
    sects = []
    so = opt + opt_sz
    for i in range(ns):
        s = so + i * 40
        nm = data[s:s + 8].rstrip(b"\x00").decode("ascii", "replace")
        va = ib + struct.unpack_from("<I", data, s + 12)[0]
        rsz = struct.unpack_from("<I", data, s + 16)[0]
        roff = struct.unpack_from("<I", data, s + 20)[0]
        sects.append((nm, va, rsz, roff))
    return ib, sects


def _build_iat(data: bytes, ib: int, sections: list) -> dict[int, str]:
    """Build IAT with ordinal resolution."""
    elf = struct.unpack_from("<I", data, 0x3C)[0]
    opt = elf + 4 + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    dd_off = opt + (120 if magic == 0x20B else 104)
    imp_rva = struct.unpack_from("<I", data, dd_off)[0]
    psz = 8 if magic == 0x20B else 4
    hi = 1 << (psz * 8 - 1)

    def r2f(rva: int) -> int | None:
        for _, sva, srsz, sroff in sections:
            if sva - ib <= rva < sva - ib + srsz:
                return sroff + (rva - (sva - ib))
        return None

    imp_off = r2f(imp_rva)
    if imp_off is None:
        return {}
    iat: dict[int, str] = {}
    idx = 0
    while True:
        d = imp_off + idx * 20
        if d + 20 > len(data):
            break
        ilt_rva = struct.unpack_from("<I", data, d)[0]
        name_rva = struct.unpack_from("<I", data, d + 12)[0]
        iat_rva = struct.unpack_from("<I", data, d + 16)[0]
        if ilt_rva == 0 and name_rva == 0:
            break
        noff = r2f(name_rva)
        dll = data[noff:noff + 128].split(b"\x00")[0].decode("ascii", "replace") if noff else "?"
        dll_key = dll.upper().replace(".DLL", "")
        ioff = r2f(ilt_rva)
        ei = 0
        while ioff is not None:
            entry = struct.unpack_from("<Q" if psz == 8 else "<I", data, ioff + ei * psz)[0]
            if entry == 0:
                break
            va = ib + iat_rva + ei * psz
            if entry & hi:
                ordinal = entry & 0xFFFF
                fname = _ORDINALS.get(dll_key, {}).get(ordinal, f"ord#{ordinal}")
            else:
                hoff = r2f(entry & 0x7FFFFFFF)
                fname = (data[hoff + 2:hoff + 130].split(b"\x00")[0].decode("ascii", "replace")
                         if hoff else "?")
            iat[va] = f"{dll}!{fname}"
            ei += 1
        idx += 1
    return iat


def _find_call_sites(tb: bytes, text_base: int, target_iat: int) -> list[dict]:
    """Find FF 15 direct + FF 25/E8 thunk calls to an IAT entry."""
    sites: list[dict] = []
    thunk_va: int | None = None
    # FF 15 direct
    for i in range(len(tb) - 6):
        if tb[i] == 0xFF and tb[i + 1] == 0x15:
            disp = struct.unpack_from("<i", tb, i + 2)[0]
            if text_base + i + 6 + disp == target_iat:
                sites.append({"address": f"0x{text_base + i:x}", "method": "FF15_direct"})
    # FF 25 thunk -> E8 callers
    for i in range(len(tb) - 6):
        if tb[i] == 0xFF and tb[i + 1] == 0x25:
            disp = struct.unpack_from("<i", tb, i + 2)[0]
            if text_base + i + 6 + disp == target_iat:
                thunk_va = text_base + i
                for j in range(len(tb) - 5):
                    if tb[j] == 0xE8:
                        rel = struct.unpack_from("<i", tb, j + 1)[0]
                        if text_base + j + 5 + rel == thunk_va:
                            sites.append({"address": f"0x{text_base + j:x}",
                                          "method": "E8_thunk"})
                break
    return sites


def find_api_call_sites(pe_path: Path, api_name: str,
                        hash_func: str | None = None) -> dict[str, Any]:
    """Find all call sites for a named API."""
    data = pe_path.read_bytes()
    ib, sections = _parse_pe(data)
    if not sections:
        return {"error": "Cannot parse PE", "api": api_name}
    text_sec = next((s for s in sections if s[0] == '.text'), None)
    if not text_sec:
        # Fallback: first executable section (handles .code, packed, etc.)
        text_sec = next((s for s in sections if s[3] > 0), None)
    if not text_sec:
        return {'error': 'No executable section', 'api': api_name}
    _, text_base, text_rsz, text_roff = text_sec
    tb = data[text_roff:text_roff + text_rsz]
    iat = _build_iat(data, ib, sections)
    sites: list[dict] = []
    iat_addr: str | None = None
    # Find IAT entry
    for va, name in iat.items():
        short = name.split("!")[-1]
        if short.lower() == api_name.lower():
            iat_addr = f"0x{va:x}"
            sites.extend(_find_call_sites(tb, text_base, va))
            break
    # Hash search in .rdata
    hash_locs: list[str] = []
    if hash_func is not None:
        h = _hash_name(api_name, hash_func)
        needle = struct.pack("<I", h)
        for _, sva, srsz, sroff in sections:
            if sva == text_base:
                continue
            region = data[sroff:sroff + srsz]
            pos = 0
            while True:
                pos = region.find(needle, pos)
                if pos == -1:
                    break
                hash_locs.append(f"0x{sva + pos:x}")
                pos += 4
    return {"api": api_name, "iat_address": iat_addr,
            "call_sites": sites, "call_count": len(sites),
            "hash_locations": hash_locs}


def scan_all_apis(pe_path: Path) -> list[dict[str, Any]]:
    """Enumerate every API the binary uses: imports, thunks, and indirect calls.

    Scans for:
    - FF 15 direct IAT calls
    - E8 calls to JMP [IAT] thunks
    - FF 15 / CALL [RIP+disp] to non-IAT addresses (dynamic dispatch table)
    """
    data = pe_path.read_bytes()
    ib, sections = _parse_pe(data)
    if not sections:
        return []
    text_sec = next((s for s in sections if s[0] == '.text'), None)
    if not text_sec:
        text_sec = next((s for s in sections if s[3] > 0), None)
    if not text_sec:
        return []
    _, text_base, text_rsz, text_roff = text_sec
    tb = data[text_roff:text_roff + text_rsz]
    iat = _build_iat(data, ib, sections)
    results: list[dict[str, Any]] = []
    seen_apis: set[str] = set()
    # 1. IAT imports with call sites (direct + thunk)
    for va, full_name in sorted(iat.items()):
        dll, fname = full_name.split('!', 1) if '!' in full_name else ('?', full_name)
        if fname.startswith('ord#'):
            continue
        sites = _find_call_sites(tb, text_base, va)
        if sites:
            results.append({'api': fname, 'dll': dll, 'iat_address': f'0x{va:x}',
                            'call_sites': sites, 'call_count': len(sites),
                            'resolution': 'import'})
            seen_apis.add(fname.lower())
    # 2. Find all FF 15 calls to NON-IAT addresses (dynamic dispatch table)
    iat_set = set(iat.keys())
    indirect_targets: dict[int, list[str]] = {}  # target_va -> [call_site_va]
    for i in range(len(tb) - 6):
        if tb[i] == 0xFF and tb[i + 1] == 0x15:
            disp = struct.unpack_from('<i', tb, i + 2)[0]
            target = text_base + i + 6 + disp
            if target not in iat_set:
                indirect_targets.setdefault(target, []).append(
                    f'0x{text_base + i:x}')
    if indirect_targets:
        results.append({'api': '_indirect_dispatch', 'dll': 'dynamic',
                        'targets': len(indirect_targets),
                        'call_count': sum(len(v) for v in indirect_targets.values()),
                        'resolution': 'indirect',
                        'note': 'Calls through dynamic resolution table, not IAT'})
    return results


def trace_hash_xrefs(pe_path: Path, api_name: str,
                     hash_func: str | None = None) -> dict[str, Any]:
    """Find hash constant and references to its containing table."""
    data = pe_path.read_bytes()
    ib, sections = _parse_pe(data)
    if not sections:
        return {'error': 'Cannot parse PE', 'api': api_name}
    text_sec = next((s for s in sections if s[0] == '.text'), None)
    if not text_sec:
        text_sec = next((s for s in sections if s[3] > 0), None)
    if not text_sec:
        return {'error': 'No executable section', 'api': api_name}
    _, text_base, text_rsz, text_roff = text_sec
    tb = data[text_roff:text_roff + text_rsz]
    if hash_func is None:
        return {'api': api_name, 'found': False, 'hash_locations': [], 'table_refs': []}
    h = _hash_name(api_name, hash_func)
    needle = struct.pack('<I', h)
    hash_vas: list[int] = []
    hash_foffs: list[int] = []
    for _, sva, srsz, sroff in sections:
        if sva == text_base:
            continue
        region = data[sroff:sroff + srsz]
        pos = 0
        while True:
            pos = region.find(needle, pos)
            if pos == -1:
                break
            hash_vas.append(sva + pos)
            hash_foffs.append(sroff + pos)
            pos += 4
    if not hash_vas:
        return {'api': api_name, 'hash': f'0x{h:08x}', 'found': False,
                'hash_locations': [], 'table_refs': []}
    # Detect table stride and base
    table_base_va: int | None = None
    table_stride = 0
    foff = hash_foffs[0]
    for stride in (0x18, 0x10, 0x20, 0x08):
        prev = foff - stride
        if 0 <= prev < len(data) - 4:
            v = struct.unpack_from('<I', data, prev)[0]
            if v > 0x10000:
                table_stride = stride
                pos = foff
                while pos - stride >= 0:
                    v2 = struct.unpack_from('<I', data, pos - stride)[0]
                    if v2 < 0x10000:
                        break
                    pos -= stride
                for _, sva, srsz, sroff in sections:
                    if sroff <= pos < sroff + srsz:
                        table_base_va = sva + (pos - sroff)
                break
    # Find LEA references to table region
    table_refs: list[dict] = []
    if table_base_va is not None:
        table_end = hash_vas[-1] + 0x200
        for i in range(len(tb) - 7):
            if tb[i] in (0x48, 0x4C) and tb[i + 1] == 0x8D:
                modrm = tb[i + 2]
                if (modrm & 0xC7) == 0x05:
                    disp = struct.unpack_from('<i', tb, i + 3)[0]
                    target = text_base + i + 7 + disp
                    if table_base_va <= target <= table_end:
                        table_refs.append({'instruction': f'0x{text_base + i:x}',
                                           'target': f'0x{target:x}'})
    return {'api': api_name, 'hash': f'0x{h:08x}', 'found': True,
            'hash_locations': [f'0x{v:x}' for v in hash_vas],
            'table_base': f'0x{table_base_va:x}' if table_base_va else None,
            'table_stride': table_stride,
            'table_refs': table_refs, 'table_ref_count': len(table_refs)}

def _load_categories() -> dict[str, list[str]]:
    """Load the API category database from data/api_categories.json."""
    db_path = Path(__file__).resolve().parent.parent.parent / "data" / "api_categories.json"
    if not db_path.exists():
        return {}
    raw = json.loads(db_path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if k != "_meta" and isinstance(v, list)}


def classify_capabilities(pe_path: Path,
                          hash_func: str | None = None) -> dict[str, Any]:
    """Scan binary, classify all APIs into capabilities from the database.

    1. Enumerate all APIs with call sites (imports + thunks)
    2. Search hash table for dynamically resolved APIs
    3. Classify each API using data/api_categories.json
    4. Return per-category evidence + uncategorized APIs
    """
    categories = _load_categories()
    if not categories:
        return {"error": "Cannot load api_categories.json"}

    # Build reverse map: api_name_lower -> [category, ...]
    api_to_cats: dict[str, list[str]] = {}
    all_known_apis: set[str] = set()
    for cat, apis in categories.items():
        for api in apis:
            api_lower = api.lower()
            all_known_apis.add(api_lower)
            api_to_cats.setdefault(api_lower, []).append(cat)

    # Scan static imports + thunks
    found_apis = scan_all_apis(pe_path)

    # Precompute hash->api table, scan sections ONCE (O(M) not O(N*M))
    data = pe_path.read_bytes()
    _, sections = _parse_pe(data)
    hash_found: list[dict] = []
    if hash_func is None:
        hash_func = _auto_detect_hash(data)
    if hash_func is not None and sections:
        hash_to_api: dict[int, str] = {}
        for api in all_known_apis:
            h = _hash_name(api, hash_func)
            if h is not None and h != 0xFFFFFFFE:
                hash_to_api[h] = api
        for nm, sva, srsz, sroff in sections:
            if nm == '.text':
                continue
            region = data[sroff:sroff + srsz]
            for i in range(0, len(region) - 4, 4):
                val = struct.unpack_from('<I', region, i)[0]
                if val in hash_to_api:
                    hash_found.append({'api': hash_to_api[val],
                                       'hash': f'0x{val:08x}',
                                       'section_va': f'0x{sva + i:x}'})
    # Classify
    cap_evidence: dict[str, list[dict]] = {cat: [] for cat in categories}
    uncategorized: list[dict] = []
    seen: set[str] = set()

    for entry in found_apis:
        api_lower = entry["api"].lower()
        cats = api_to_cats.get(api_lower, [])
        for cat in cats:
            cap_evidence[cat].append(entry)
        if not cats:
            uncategorized.append(entry)
        seen.add(api_lower)

    for entry in hash_found:
        api_lower = entry["api"].lower()
        if api_lower in seen:
            continue
        seen.add(api_lower)
        cats = api_to_cats.get(api_lower, [])
        for cat in cats:
            cap_evidence[cat].append({"api": entry["api"],
                                       "resolution": "hash",
                                       "hash": entry["hash"]})

    # Build results
    results: dict[str, Any] = {}
    for cat in sorted(cap_evidence):
        evidence = cap_evidence[cat]
        verdict = "confirmed" if evidence else "absent"
        apis = sorted({e["api"] for e in evidence})
        calls = sum(e.get("call_count", 0) for e in evidence)
        results[cat] = {"verdict": verdict, "api_count": len(apis),
                        "call_count": calls, "apis": apis,
                        "evidence": evidence}
    if uncategorized:
        results["_uncategorized"] = {
            "api_count": len(uncategorized),
            "apis": sorted({e["api"] for e in uncategorized}),
            "evidence": uncategorized,
        }
    return results
