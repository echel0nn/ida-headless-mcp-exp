"""Pure-python PE reader: VA->file translation, string extraction, memory reads.

The frontend already has the binary file on disk (workspace dir) before IDA
ever touches it. Anything that boils down to "read bytes from this address
in the loaded image" or "walk every printable string" does NOT need to wait
for the worker -- it can be computed synchronously from the PE on disk.

This module backs the ``list_strings``, ``read_memory``, and
``get_string_at`` MCP tools. Pure stdlib (struct + re), no pefile / lief
dependency, so it loads instantly and works for the malware-analysis common
case (PE32 + PE32+ Windows binaries). The exact-same heuristic IDA's
``strings`` window uses for printable ASCII / UTF-16LE is replicated here
so the agent sees consistent output between IDA's view and this tool's
output.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator


__all__ = ["PEReader", "PEReadError"]


class PEReadError(ValueError):
    """Raised when the file at ``path`` is not a recognizable PE."""


# Printable ASCII range used by every strings(1) implementation: SP..~
# plus the common whitespace TAB / LF / CR. Anything outside terminates
# a candidate run.
_ASCII_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


class PEReader:
    """Minimal PE parser focused on VA <-> file-offset translation.

    Construction parses the headers in one shot; per-VA reads are O(log n)
    against the section table (small, typically 4-12 sections).

    Example:
        >>> pe = PEReader("/path/to/sample.exe")
        >>> pe.image_base
        4194304
        >>> pe.read_va(0x401000, 16)
        b'\\x55\\x8b\\xec...'
        >>> for s in pe.iter_strings(min_length=8):
        ...     print(s)
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.data: bytes = self.path.read_bytes()
        self._parse()

    # -------- header parsing --------

    def _parse(self) -> None:
        data = self.data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEReadError(f"Not a PE: missing MZ header at {self.path}")
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 0x18 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            raise PEReadError(f"Not a PE: missing 'PE\\0\\0' at offset 0x{pe_off:x}")

        # IMAGE_FILE_HEADER at pe_off+4
        num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe_off + 0x14)[0]

        # IMAGE_OPTIONAL_HEADER at pe_off+0x18; first 2 bytes = Magic
        opt_off = pe_off + 0x18
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x10B:  # PE32
            self.is_pe32_plus = False
            self.image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
            self.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        elif magic == 0x20B:  # PE32+
            self.is_pe32_plus = True
            self.image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
            self.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        else:
            raise PEReadError(f"Unknown PE optional-header magic 0x{magic:04x}")

        # Section table follows the optional header.
        sec_off = opt_off + opt_size
        self.sections: list[dict] = []
        for i in range(num_sec):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            name = data[base:base + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
            vsize = struct.unpack_from("<I", data, base + 8)[0]
            vaddr = struct.unpack_from("<I", data, base + 12)[0]
            rsize = struct.unpack_from("<I", data, base + 16)[0]
            raddr = struct.unpack_from("<I", data, base + 20)[0]
            chars = struct.unpack_from("<I", data, base + 36)[0]
            self.sections.append({
                "name": name,
                "virtual_address": vaddr,
                "virtual_size": vsize,
                "raw_address": raddr,
                "raw_size": rsize,
                "characteristics": chars,
            })

    # -------- address translation --------

    def va_to_file(self, va: int) -> int | None:
        """Translate an absolute VA (image_base + RVA) to a file offset.

        Returns ``None`` for VAs that don't map to any on-disk section --
        e.g. uninitialized BSS (raw_size = 0) where the page exists at
        runtime but has no bytes on disk.
        """
        if va < self.image_base:
            return None
        rva = va - self.image_base
        for s in self.sections:
            if s["raw_size"] == 0:
                continue  # BSS / uninitialized: no on-disk bytes
            vstart = s["virtual_address"]
            # max(vsize, rsize) covers tail-padding cases. A VA past the
            # raw bytes but inside the virtual range is "in" the section
            # for purposes of the loader; we still bound the file read
            # below by raw_size so we don't run past the section's bytes
            # on disk.
            vend = vstart + max(s["virtual_size"], s["raw_size"])
            if vstart <= rva < vend:
                file_off = s["raw_address"] + (rva - vstart)
                if file_off < s["raw_address"] + s["raw_size"]:
                    return file_off
                return None
        return None

    def file_to_va(self, file_off: int) -> int | None:
        """Inverse of :meth:`va_to_file`. Used by ``list_strings`` to stamp
        a real VA on every extracted hit."""
        for s in self.sections:
            if s["raw_size"] == 0:
                continue
            if s["raw_address"] <= file_off < s["raw_address"] + s["raw_size"]:
                return self.image_base + s["virtual_address"] + (file_off - s["raw_address"])
        return None

    def section_for_va(self, va: int) -> str | None:
        """Return the section name that owns ``va``, or None."""
        if va < self.image_base:
            return None
        rva = va - self.image_base
        for s in self.sections:
            vstart = s["virtual_address"]
            vend = vstart + max(s["virtual_size"], s["raw_size"])
            if vstart <= rva < vend:
                return s["name"]
        return None

    # -------- raw reads --------

    def read_va(self, va: int, size: int) -> bytes:
        """Read ``size`` bytes starting at virtual address ``va``.

        Returns ``b""`` when the VA isn't backed by on-disk bytes (BSS /
        outside the image). Reads are clipped at the section boundary so
        the result is never spliced across two sections.
        """
        if size <= 0:
            return b""
        file_off = self.va_to_file(va)
        if file_off is None:
            return b""
        # Clip to the owning section's raw end so we don't bleed.
        for s in self.sections:
            if s["raw_address"] <= file_off < s["raw_address"] + s["raw_size"]:
                end_limit = s["raw_address"] + s["raw_size"]
                actual = min(size, end_limit - file_off)
                return self.data[file_off:file_off + actual]
        return b""

    def read_cstring(self, va: int, max_length: int = 512) -> bytes:
        """Read a null-terminated byte string starting at ``va``.

        Caps at ``max_length`` even if no null is found, so a runaway
        read on a corrupt VA doesn't dump the whole section.
        """
        raw = self.read_va(va, max_length)
        nul = raw.find(b"\x00")
        return raw if nul == -1 else raw[:nul]

    def read_wstring(self, va: int, max_length: int = 512) -> bytes:
        """Read a UTF-16LE null-terminated string starting at ``va``.

        ``max_length`` is the byte cap, not the char cap.
        """
        raw = self.read_va(va, max_length)
        # Walk by pairs looking for a null U16.
        for i in range(0, len(raw) - 1, 2):
            if raw[i] == 0 and raw[i + 1] == 0:
                return raw[:i]
        return raw[: (len(raw) // 2) * 2]

    # -------- string extraction --------

    def iter_strings(
        self,
        min_length: int = 4,
        encoding: str = "all",
        section: str | None = None,
    ) -> Iterator[dict]:
        """Walk the binary and yield every printable string >= ``min_length``.

        Args:
            min_length: Minimum character length to surface.
            encoding: ``"ascii"``, ``"utf16"``, or ``"all"`` (default).
            section: Limit to a named section (``"CODE"``, ``".rdata"``,
                ``"DATA"``, etc.). ``None`` walks every section with
                non-zero raw size.

        Yields dicts shaped:
            ``{"address": "0x..", "section": "DATA", "encoding": "ascii",
               "length": N, "value": "..."}``
        """
        sections_to_scan = self.sections
        if section is not None:
            sections_to_scan = [s for s in self.sections if s["name"] == section]
        for s in sections_to_scan:
            if s["raw_size"] == 0:
                continue
            chunk = self.data[s["raw_address"]:s["raw_address"] + s["raw_size"]]
            base_va = self.image_base + s["virtual_address"]
            if encoding in ("ascii", "all"):
                yield from self._scan_ascii(chunk, base_va, s["name"], min_length)
            if encoding in ("utf16", "all"):
                yield from self._scan_utf16le(chunk, base_va, s["name"], min_length)

    @staticmethod
    def _scan_ascii(
        chunk: bytes, base_va: int, section_name: str, min_length: int,
    ) -> Iterator[dict]:
        run_start = -1
        for i, b in enumerate(chunk):
            if b in _ASCII_PRINTABLE:
                if run_start == -1:
                    run_start = i
            else:
                if run_start != -1:
                    length = i - run_start
                    if length >= min_length:
                        yield {
                            "address": f"0x{base_va + run_start:08x}",
                            "section": section_name,
                            "encoding": "ascii",
                            "length": length,
                            "value": chunk[run_start:i].decode("latin-1", errors="replace"),
                        }
                    run_start = -1
        # Tail run if the section ends inside a string.
        if run_start != -1 and (len(chunk) - run_start) >= min_length:
            yield {
                "address": f"0x{base_va + run_start:08x}",
                "section": section_name,
                "encoding": "ascii",
                "length": len(chunk) - run_start,
                "value": chunk[run_start:].decode("latin-1", errors="replace"),
            }

    @staticmethod
    def _scan_utf16le(
        chunk: bytes, base_va: int, section_name: str, min_length: int,
    ) -> Iterator[dict]:
        # UTF-16LE printable runs: every other byte is 0x00 AND the
        # preceding byte is printable ASCII. We scan with a stride of 2.
        n = len(chunk) - 1
        run_start = -1
        for i in range(0, n, 2):
            lo, hi = chunk[i], chunk[i + 1]
            if hi == 0 and lo in _ASCII_PRINTABLE:
                if run_start == -1:
                    run_start = i
            else:
                if run_start != -1:
                    char_count = (i - run_start) // 2
                    if char_count >= min_length:
                        raw = chunk[run_start:i]
                        try:
                            text = raw.decode("utf-16-le")
                        except UnicodeDecodeError:
                            text = raw.hex()
                        yield {
                            "address": f"0x{base_va + run_start:08x}",
                            "section": section_name,
                            "encoding": "utf16le",
                            "length": char_count,
                            "value": text,
                        }
                    run_start = -1
        if run_start != -1:
            char_count = (n - run_start) // 2
            if char_count >= min_length:
                raw = chunk[run_start:n]
                yield {
                    "address": f"0x{base_va + run_start:08x}",
                    "section": section_name,
                    "encoding": "utf16le",
                    "length": char_count,
                    "value": raw.decode("utf-16-le", errors="replace"),
                }
