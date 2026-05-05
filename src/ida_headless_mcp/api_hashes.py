"""API hash resolution — resolve hash-imported Windows API names.

Malware often imports APIs by hash instead of name to evade static
analysis. This module implements common hash algorithms and maintains
a lookup table to resolve hash values back to API names.
"""
from __future__ import annotations

from typing import Any

__all__ = ["resolve_api_hashes", "compute_hash"]

# Common Windows API names (subset — the most security-relevant ones)
_COMMON_APIS: list[str] = [
    # Process
    "CreateProcessA", "CreateProcessW", "CreateRemoteThread",
    "OpenProcess", "TerminateProcess", "ExitProcess",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "VirtualFree", "WriteProcessMemory", "ReadProcessMemory",
    "NtCreateThreadEx", "RtlCreateUserThread",
    # Library loading
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
    "LdrLoadDll", "LdrGetProcedureAddress",
    # File
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
    "DeleteFileA", "DeleteFileW", "CopyFileA", "CopyFileW",
    "MoveFileA", "MoveFileW", "GetTempPathA", "GetTempPathW",
    "GetTempFileNameA", "GetTempFileNameW",
    # Registry
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteKeyA", "RegDeleteKeyW",
    "RegQueryValueExA", "RegQueryValueExW",
    # Network
    "WSAStartup", "socket", "connect", "bind", "listen", "accept",
    "send", "recv", "sendto", "recvfrom", "closesocket",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetConnectA", "InternetConnectW", "InternetReadFile",
    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
    "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData",
    "URLDownloadToFileA", "URLDownloadToFileW",
    # Crypto
    "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
    "CryptEncrypt", "CryptDecrypt", "CryptGenRandom",
    "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey",
    "BCryptEncrypt", "BCryptDecrypt",
    # Shell
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "WinExec", "system", "_wsystem",
    # Service
    "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
    "OpenSCManagerA", "OpenSCManagerW",
    # Misc
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "OutputDebugStringA", "OutputDebugStringW",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    "Sleep", "SleepEx", "WaitForSingleObject",
    "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW",
    "GetComputerNameA", "GetComputerNameW",
    "GetUserNameA", "GetUserNameW",
    "GetWindowsDirectoryA", "GetWindowsDirectoryW",
    "GetSystemDirectoryA", "GetSystemDirectoryW",
    "GlobalAlloc", "GlobalFree", "HeapAlloc", "HeapFree",
    "CloseHandle", "GetLastError", "SetLastError",
]


def _ror13(val: int) -> int:
    """ROR13 on 32-bit value."""
    return ((val >> 13) | (val << 19)) & 0xFFFFFFFF


def _djb2(name: str) -> int:
    """DJB2 hash."""
    h = 5381
    for c in name.encode("ascii"):
        h = ((h * 33) + c) & 0xFFFFFFFF
    return h


def _ror13_hash(name: str) -> int:
    """ROR13 hash (common in shellcode/malware)."""
    h = 0
    for c in name.encode("ascii"):
        h = (_ror13(h) + c) & 0xFFFFFFFF
    return h


def _crc32(name: str) -> int:
    """CRC32 hash."""
    import binascii
    return binascii.crc32(name.encode("ascii")) & 0xFFFFFFFF


def _fnv1a(name: str) -> int:
    """FNV-1a 32-bit hash."""
    h = 0x811C9DC5
    for c in name.encode("ascii"):
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h


def _sdbm(name: str) -> int:
    """SDBM hash."""
    h = 0
    for c in name.encode("ascii"):
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


_HASH_ALGORITHMS: dict[str, Any] = {
    "ror13": _ror13_hash,
    "djb2": _djb2,
    "crc32": _crc32,
    "fnv1a": _fnv1a,
    "sdbm": _sdbm,
}

# Precomputed lookup tables: {algorithm: {hash_value: api_name}}
_LOOKUP: dict[str, dict[int, str]] | None = None


def _build_lookup() -> dict[str, dict[int, str]]:
    """Build precomputed hash → name lookup tables."""
    global _LOOKUP  # noqa: PLW0603
    if _LOOKUP is not None:
        return _LOOKUP
    _LOOKUP = {}
    for algo_name, algo_fn in _HASH_ALGORITHMS.items():
        table: dict[int, str] = {}
        for api in _COMMON_APIS:
            table[algo_fn(api)] = api
        _LOOKUP[algo_name] = table
    return _LOOKUP


def compute_hash(name: str, algorithm: str = "ror13") -> int | None:
    """Compute hash of an API name using a specific algorithm."""
    fn = _HASH_ALGORITHMS.get(algorithm)
    if fn is None:
        return None
    return fn(name)


def resolve_api_hashes(
    hash_values: list[int],
    *,
    algorithms: list[str] | None = None,
) -> dict[str, Any]:
    """Resolve a list of hash values to API names.

    Tries each algorithm against each hash value. Returns all matches.

    Args:
        hash_values: List of integer hash values found in the binary.
        algorithms: Which algorithms to try (default: all).

    Returns:
        Dict with resolved names and unresolved hashes.
    """
    lookup = _build_lookup()
    algos = algorithms or list(_HASH_ALGORITHMS.keys())

    resolved: list[dict[str, Any]] = []
    unresolved: list[int] = []

    for hval in hash_values:
        found = False
        for algo in algos:
            table = lookup.get(algo, {})
            if hval in table:
                resolved.append({
                    "hash": f"0x{hval:08x}",
                    "api_name": table[hval],
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
        "algorithms_checked": algos,
    }
