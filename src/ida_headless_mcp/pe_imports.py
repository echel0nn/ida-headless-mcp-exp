"""Pure-Python PE import-table parser.

Walks the import directory of a PE32 or PE32+ binary and produces a
mapping from each IAT slot virtual address to a ``"<dll>!<function>"``
descriptor. Used by CFF analysis to resolve RIP-relative indirect
``CALL`` instructions to readable import names without external deps.
"""
from __future__ import annotations

import struct
from pathlib import Path

__all__ = ["build_iat_map"]

_NAME_CAP = 128


def _rva_to_offset(sections: list[tuple[int, int, int, int]], rva: int) -> int | None:
    """Translate an RVA to a file offset using the PE section table."""
    for vaddr, vsize, rptr, rsize in sections:
        size = max(vsize, rsize)
        if size and vaddr <= rva < vaddr + size:
            return rptr + (rva - vaddr)
    return None


def _read_cstring(data: bytes, offset: int, cap: int = _NAME_CAP) -> str:
    """Read a NUL-terminated ASCII string from ``data`` starting at ``offset``."""
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(offset + cap + 1, len(data)))
    if end < 0:
        end = min(offset + cap, len(data))
    return data[offset:end].decode("ascii", errors="replace")


def build_iat_map(pe_path: Path) -> dict[int, str]:
    """Parse the PE import directory, return ``{iat_va: 'DLL!Function'}``.

    Walks the ``IMAGE_IMPORT_DESCRIPTOR`` chain (terminated by an
    all-zero entry) and resolves each ILT entry to a function name
    (or ``ord#N`` for ordinal imports), keyed by the IAT slot's
    absolute VA. Handles PE32 and PE32+. Returns ``{}`` on malformed
    input or when no imports are present.
    """
    try:
        data = pe_path.read_bytes()
    except OSError:
        return {}
    if len(data) < 0x40:
        return {}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {}
    num_sections, _, _, _, optional_size = struct.unpack_from("<HIIIH", data, e_lfanew + 6)
    opt = e_lfanew + 24
    if opt + 2 > len(data):
        return {}
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        import_dir_off, ptr_size = opt + 120, 8
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        import_dir_off, ptr_size = opt + 104, 4
    else:
        return {}
    if import_dir_off + 8 > len(data):
        return {}
    import_rva, import_size = struct.unpack_from("<II", data, import_dir_off)
    if import_rva == 0 or import_size == 0:
        return {}

    sect_off = opt + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for i in range(num_sections):
        s = sect_off + i * 40
        if s + 40 > len(data):
            break
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((vaddr, vsize, rptr, rsize))

    iat_map: dict[int, str] = {}
    desc_off = _rva_to_offset(sections, import_rva)
    if desc_off is None:
        return {}
    ordinal_bit = 1 << (ptr_size * 8 - 1)
    name_mask = ordinal_bit - 1
    fmt = "<Q" if ptr_size == 8 else "<I"
    while desc_off + 20 <= len(data):
        ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", data, desc_off)
        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
            break
        desc_off += 20
        if iat_rva == 0:
            continue
        # Stripped binaries leave ILT zero and overwrite IAT in place.
        nt_off = _rva_to_offset(sections, ilt_rva or iat_rva)
        dll_off = _rva_to_offset(sections, name_rva) if name_rva else None
        dll_name = _read_cstring(data, dll_off) if dll_off is not None else ""
        if not dll_name or nt_off is None:
            continue
        index = 0
        while nt_off + ptr_size <= len(data):
            entry = struct.unpack_from(fmt, data, nt_off)[0]
            if entry == 0:
                break
            if entry & ordinal_bit:
                fn_name = f"ord#{entry & 0xFFFF}"
            else:
                hn_off = _rva_to_offset(sections, entry & name_mask)
                fn_name = _read_cstring(data, hn_off + 2) if hn_off is not None else ""
            if fn_name:
                iat_va = image_base + iat_rva + index * ptr_size
                iat_map[iat_va] = f"{dll_name}!{fn_name}"[:_NAME_CAP]
            nt_off += ptr_size
            index += 1
    return iat_map
