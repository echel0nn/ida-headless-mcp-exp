"""Shared address-resolution and API-name normalization helpers.

These helpers are deliberately split out of ``session.py`` so that mixin
modules (such as :mod:`session_detection`) can import them without creating
a circular import back into ``session``.
"""

from __future__ import annotations


def _resolve_address(address_or_name: str) -> int:
    import ida_idaapi
    import ida_name

    target = address_or_name.strip()
    if target.startswith(("0x", "0X")):
        return int(target, 16)
    try:
        return int(target)
    except ValueError:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, target)
        if ea == ida_idaapi.BADADDR:
            raise ValueError(f"Cannot resolve address or function name: {address_or_name!r}")
        return ea


def _normalize_api_name(name: str) -> str:
    """Normalize a Windows API name for matching.

    Strips the ``j_`` prefix and trailing ``A``/``W``/``Ex`` suffix, then
    lowercases the result.

    Examples:
        ``CreateProcessW`` -> ``createprocess``
        ``j_IsDebuggerPresent`` -> ``isdebuggerpresent``
        ``LoadLibraryExW`` -> ``loadlibrary``
    """
    n = name.strip().lower()
    if n.startswith('j_'):
        n = n[2:]
    # Strip trailing W, A, ExW, ExA (but not single-char names)
    if len(n) > 3:
        if n.endswith('exw') or n.endswith('exa'):
            n = n[:-3]
        elif n.endswith('w') or n.endswith('a'):
            # Only strip if it looks like a suffix (preceded by lowercase)
            if len(n) > 1 and n[-2].islower():
                n = n[:-1]
    return n
