"""Binary format detection and code section loading.

Supports PE (.exe/.dll/.sys), ELF (Linux/Android/BSD), and
Mach-O (macOS/iOS). Provides format-agnostic code section
extraction and architecture detection for the CFF pipeline.
"""
from __future__ import annotations

import struct
from pathlib import Path

__all__ = ["load_code_section", "detect_arch", "ptr_size"]


def load_code_section(binary_path: Path) -> tuple[bytes, int, int]:
    """Return (section_bytes, base_va, vsize) for the code section.

    Supports PE, ELF, and Mach-O. Falls back to first executable
    section if .text / __text is not found.
    """
    data = binary_path.read_bytes()
    if len(data) < 4:
        return b"", 0, 0
    if data[:4] == b"\x7fELF":
        return _load_elf_text(data)
    if data[:2] == b"MZ" and len(data) >= 0x40:
        return _load_pe_text(data)
    if len(data) >= 4:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF, 0xBEBAFECA, 0xCAFEBABE):
            return _load_macho_text(data)
    return b"", 0, 0


def detect_arch(binary_path: Path) -> str:
    """Detect architecture from binary headers. Supports PE, ELF, Mach-O.

    Returns miasm arch string ('x86_64', 'x86_32', 'arml', 'aarch64l')
    or empty string if format/arch is unknown.
    """
    data = binary_path.read_bytes()
    if len(data) < 4:
        return ""
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        e_machine = struct.unpack_from("<H", data, 18)[0]
        return {
            0x03: "x86_32", 0x3E: "x86_64", 0x28: "arml",
            0xB7: "aarch64l", 0x08: "mips32l",
        }.get(e_machine, "")
    if data[:2] == b"MZ" and len(data) >= 0x40:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 6 <= len(data):
            machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
            return {
                0x14C: "x86_32", 0x8664: "x86_64",
                0x1C0: "arml", 0xAA64: "aarch64l",
            }.get(machine, "")
    if len(data) >= 8:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF):
            cputype = struct.unpack_from("<I", data, 4)[0]
            return {
                7: "x86_32", 0x01000007: "x86_64",
                12: "arml", 0x0100000C: "aarch64l",
            }.get(cputype, "")
    return ""


def ptr_size(arch: str) -> int:
    """Pointer width in bits."""
    return 64 if arch in ("x86_64", "aarch64l") else 32


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------

def _load_pe_text(data: bytes) -> tuple[bytes, int, int]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return b"", 0, 0
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    else:
        return b"", 0, 0
    sect = opt + optional_size
    fallback: tuple[bytes, int, int] | None = None
    for i in range(num_sections):
        s = sect + i * 40
        name = bytes(data[s:s + 8]).rstrip(b"\x00")
        vsize = struct.unpack_from("<I", data, s + 8)[0]
        vaddr = struct.unpack_from("<I", data, s + 12)[0]
        rsize = struct.unpack_from("<I", data, s + 16)[0]
        rptr = struct.unpack_from("<I", data, s + 20)[0]
        chars = struct.unpack_from("<I", data, s + 36)[0]
        body = data[rptr:rptr + min(rsize, vsize or rsize)]
        size = max(vsize, rsize)
        if name == b".text":
            return body, image_base + vaddr, size
        if fallback is None and chars & 0x20000000:
            fallback = (body, image_base + vaddr, size)
    return fallback if fallback is not None else (b"", 0, 0)


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

def _load_elf_text(data: bytes) -> tuple[bytes, int, int]:
    ei_class = data[4]  # 1=32-bit, 2=64-bit
    ei_data = data[5]   # 1=LE, 2=BE
    end = "<" if ei_data == 1 else ">"
    if ei_class == 2:
        e_shoff = struct.unpack_from(f"{end}Q", data, 40)[0]
        e_shentsize = struct.unpack_from(f"{end}H", data, 58)[0]
        e_shnum = struct.unpack_from(f"{end}H", data, 60)[0]
        e_shstrndx = struct.unpack_from(f"{end}H", data, 62)[0]
        fmt_a = f"{end}Q"
        sh_addr_off, sh_offset_off, sh_size_off = 16, 24, 32
    else:
        e_shoff = struct.unpack_from(f"{end}I", data, 32)[0]
        e_shentsize = struct.unpack_from(f"{end}H", data, 46)[0]
        e_shnum = struct.unpack_from(f"{end}H", data, 48)[0]
        e_shstrndx = struct.unpack_from(f"{end}H", data, 50)[0]
        fmt_a = f"{end}I"
        sh_addr_off, sh_offset_off, sh_size_off = 12, 16, 20
    if not e_shoff or not e_shnum or e_shoff + e_shnum * e_shentsize > len(data):
        return b"", 0, 0
    strtab_hdr = e_shoff + e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from(fmt_a, data, strtab_hdr + sh_offset_off)[0]
    fallback: tuple[bytes, int, int] | None = None
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_idx = struct.unpack_from(f"{end}I", data, sh)[0]
        sh_flags = struct.unpack_from(fmt_a, data, sh + 8)[0]
        sh_addr = struct.unpack_from(fmt_a, data, sh + sh_addr_off)[0]
        sh_off = struct.unpack_from(fmt_a, data, sh + sh_offset_off)[0]
        sh_size = struct.unpack_from(fmt_a, data, sh + sh_size_off)[0]
        nm_start = strtab_off + name_idx
        nm_end = data.index(b"\x00", nm_start) if nm_start < len(data) else nm_start
        sec_name = data[nm_start:nm_end]
        body = data[sh_off:sh_off + sh_size]
        if sec_name == b".text":
            return body, sh_addr, sh_size
        if fallback is None and sh_flags & 0x4:  # SHF_EXECINSTR
            fallback = (body, sh_addr, sh_size)
    return fallback if fallback is not None else (b"", 0, 0)


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

def _load_macho_text(data: bytes) -> tuple[bytes, int, int]:
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:
        ncmds = struct.unpack_from("<I", data, 16)[0]
        hdr_size = 32
    elif magic == 0xFEEDFACE:
        ncmds = struct.unpack_from("<I", data, 16)[0]
        hdr_size = 28
    else:
        return b"", 0, 0
    off = hdr_size
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd = struct.unpack_from("<I", data, off)[0]
        cmdsize = struct.unpack_from("<I", data, off + 4)[0]
        if cmd in (0x19, 0x01):  # LC_SEGMENT_64, LC_SEGMENT
            is64 = cmd == 0x19
            segname = data[off + 8:off + 24].rstrip(b"\x00")
            nsects = struct.unpack_from("<I", data, off + (48 if is64 else 36))[0]
            sect_off = off + (72 if is64 else 56)
            for _ in range(nsects):
                if sect_off + (80 if is64 else 68) > len(data):
                    break
                sectname = data[sect_off:sect_off + 16].rstrip(b"\x00")
                if is64:
                    addr = struct.unpack_from("<Q", data, sect_off + 32)[0]
                    size = struct.unpack_from("<Q", data, sect_off + 40)[0]
                    foff = struct.unpack_from("<I", data, sect_off + 48)[0]
                else:
                    addr = struct.unpack_from("<I", data, sect_off + 32)[0]
                    size = struct.unpack_from("<I", data, sect_off + 36)[0]
                    foff = struct.unpack_from("<I", data, sect_off + 40)[0]
                if sectname == b"__text" and segname == b"__TEXT":
                    return data[foff:foff + size], addr, size
                sect_off += 80 if is64 else 68
        off += cmdsize
    return b"", 0, 0
