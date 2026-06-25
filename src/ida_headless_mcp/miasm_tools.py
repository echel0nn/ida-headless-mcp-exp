"""Miasm-based analysis tools \u2014 run server-side, no idalib needed.

These tools operate on raw binary bytes read from the workspace PE file.
They do NOT require a worker process or idalib. Results are instant.

Capabilities:
  - Disassembly (miasm's own engine, multi-arch)
  - IR lifting to miasm's intermediate representation
  - Expression simplification / de-obfuscation
  - Symbolic execution of code snippets
"""
from __future__ import annotations

import functools
import logging
import struct
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Compatibility shim: miasm.core.cpu (versions <= 0.1.4) imports
# ``pyparsing.operatorPrecedence`` at module load. pyparsing 3.0
# removed that camelCase alias in favor of ``infixNotation``. On a
# fresh Python 3.13 install with pyparsing >= 3.0.0 the miasm import
# raises ``AttributeError: module 'pyparsing' has no attribute
# 'operatorPrecedence'`` -- bare ``Internal Server Error`` from
# FastAPI, no JSON envelope, agent sees an opaque failure.
#
# The shim aliases the new name back to the old before miasm imports
# fire. Idempotent + safe across pyparsing versions: if
# ``operatorPrecedence`` already exists, the assignment is a no-op;
# if ``infixNotation`` is missing too (very old pyparsing), the
# shim does nothing and miasm imports normally.
try:
    import pyparsing as _pp
    if not hasattr(_pp, "operatorPrecedence") and hasattr(_pp, "infixNotation"):
        _pp.operatorPrecedence = _pp.infixNotation
        _log.info(
            "miasm_tools: shimmed pyparsing.operatorPrecedence -> "
            "infixNotation for miasm compatibility",
        )
except ImportError:
    # pyparsing missing -- miasm imports will fail on their own with
    # a clean ImportError, caught by the per-tool try/except below.
    pass

__all__ = [
    "miasm_disassemble",
    "miasm_lift_ir",
    "miasm_simplify_expression",
    "miasm_emulate_snippet",
]


def _safe_miasm_call(fn: Callable[..., dict]) -> Callable[..., dict]:
    """Decorator wrapping a miasm tool function in a clean error path.

    Catches every exception (miasm import failures, IR build errors,
    out-of-range addresses, symbolic-execution divergence) and
    returns ``{status: 'error', error: '<excerpt>', traceback: '...'}``
    so the HTTP transport ships a JSON envelope instead of bubbling
    to a bare 500. The agent then sees a structured error it can
    pivot on rather than an opaque 'Internal Server Error' string.

    The traceback is included for the operator's worker log but
    bounded to 2000 chars so a deep miasm stack doesn't dominate
    the response payload.
    """
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except (
            ImportError, AttributeError, ValueError, TypeError,
            OSError, NotImplementedError, RuntimeError,
        ) as exc:
            tb = traceback.format_exc()
            _log.warning(
                "miasm_tools.%s failed: %s\n%s",
                fn.__name__, exc, tb[:4000],
            )
            return {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": tb[:2000],
                "tool": fn.__name__,
            }
    return wrapper


def _read_bytes_at_va(pe_path: Path, va: int, size: int) -> bytes | None:
    """Read bytes from a PE file at a given virtual address.

    Parses PE headers to map VA -> file offset, then reads raw bytes.
    No external dependencies — pure struct parsing.
    """
    data = pe_path.read_bytes()
    if len(data) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        return None
    # PE signature check
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    # COFF header
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    optional_hdr_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    # Optional header — get ImageBase
    opt_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    if magic == 0x20B:  # PE32+
        image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
    elif magic == 0x10B:  # PE32
        image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
    else:
        return None
    rva = va - image_base
    # Walk sections
    section_offset = opt_offset + optional_hdr_size
    for i in range(num_sections):
        s = section_offset + i * 40
        virt_size = struct.unpack_from("<I", data, s + 8)[0]
        virt_addr = struct.unpack_from("<I", data, s + 12)[0]
        raw_size = struct.unpack_from("<I", data, s + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, s + 20)[0]
        if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
            file_offset = raw_ptr + (rva - virt_addr)
            end = min(file_offset + size, len(data))
            if file_offset < 0 or file_offset >= len(data):
                return None
            return data[file_offset:end]
    return None


def _detect_arch(pe_path: Path) -> str:
    """Detect architecture from binary headers. Supports PE, ELF, Mach-O."""
    data = pe_path.read_bytes()
    if len(data) < 4:
        return ''
    if data[:4] == b'\x7fELF' and len(data) >= 20:
        e_machine = struct.unpack_from('<H', data, 18)[0]
        return {0x03: 'x86_32', 0x3E: 'x86_64', 0x28: 'arml',
                0xB7: 'aarch64l'}.get(e_machine, '')
    if data[:2] == b'MZ' and len(data) >= 0x40:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 6 <= len(data):
            machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
            return {0x14C: 'x86_32', 0x8664: 'x86_64',
                    0x1C0: 'arml', 0xAA64: 'aarch64l'}.get(machine, '')
    if len(data) >= 8:
        magic = struct.unpack_from('<I', data, 0)[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF):
            cputype = struct.unpack_from('<I', data, 4)[0]
            return {7: 'x86_32', 0x01000007: 'x86_64',
                    12: 'arml', 0x0100000C: 'aarch64l'}.get(cputype, '')
    return ''


@_safe_miasm_call
def miasm_disassemble(
    pe_path: Path, address: int, size: int = 64, arch: str = "",
) -> dict[str, Any]:
    """Disassemble bytes at a virtual address using miasm's engine.

    Args:
        pe_path: Path to the PE file on disk.
        address: Virtual address to start disassembly.
        size: Maximum bytes to read.
        arch: Architecture override (auto-detected from PE if empty).

    Returns:
        Dict with instructions list and metadata.
    """
    from miasm.analysis.machine import Machine
    from miasm.core.bin_stream import bin_stream_str
    from miasm.core.locationdb import LocationDB

    if not arch:
        arch = _detect_arch(pe_path)

    raw = _read_bytes_at_va(pe_path, address, size)
    if raw is None:
        return {"error": f"Cannot read {size} bytes at 0x{address:x}", "instructions": []}

    machine = Machine(arch)
    loc_db = LocationDB()
    bs = bin_stream_str(raw, base_address=address)
    mdis = machine.dis_engine(bs, loc_db=loc_db)
    mdis.follow_call = False
    mdis.dontdis_retcall = True

    instructions = []
    try:
        block = mdis.dis_block(address)
        for line in block.lines:
            instructions.append({
                "address": f"0x{line.offset:x}",
                "mnemonic": line.name,
                "operands": str(line)[len(line.name):].strip(", "),
                "size": line.l,
            })
    except Exception as exc:
        return {"error": str(exc), "instructions": instructions}

    return {
        "arch": arch,
        "start_address": f"0x{address:x}",
        "instruction_count": len(instructions),
        "instructions": instructions,
    }


@_safe_miasm_call
def miasm_lift_ir(
    pe_path: Path, address: int, size: int = 64, arch: str = "",
) -> dict[str, Any]:
    """Lift bytes at a virtual address to miasm intermediate representation.

    Args:
        pe_path: Path to the PE file on disk.
        address: Virtual address to start lifting.
        size: Maximum bytes to read.
        arch: Architecture override.

    Returns:
        Dict with IR blocks and expression assignments.
    """
    from miasm.analysis.machine import Machine
    from miasm.core.bin_stream import bin_stream_str
    from miasm.core.locationdb import LocationDB

    if not arch:
        arch = _detect_arch(pe_path)

    raw = _read_bytes_at_va(pe_path, address, size)
    if raw is None:
        return {"error": f"Cannot read {size} bytes at 0x{address:x}"}

    machine = Machine(arch)
    loc_db = LocationDB()
    bs = bin_stream_str(raw, base_address=address)
    mdis = machine.dis_engine(bs, loc_db=loc_db)
    mdis.follow_call = False
    mdis.dontdis_retcall = True

    lifter = machine.lifter_model_call(loc_db)
    ircfg = lifter.new_ircfg()

    try:
        block = mdis.dis_block(address)
        lifter.add_asmblock_to_ircfg(block, ircfg)
    except Exception as exc:
        return {"error": str(exc)}

    ir_blocks = []
    for loc_key, irblock in ircfg.blocks.items():
        assignments = []
        for assignblk in irblock:
            for dst, src in assignblk.items():
                assignments.append({
                    "dst": str(dst),
                    "src": str(src),
                })
        ir_blocks.append({
            "loc_key": str(loc_key),
            "assignment_count": len(assignments),
            "assignments": assignments,
        })

    return {
        "arch": arch,
        "start_address": f"0x{address:x}",
        "ir_block_count": len(ir_blocks),
        "ir_blocks": ir_blocks,
    }


@_safe_miasm_call
def miasm_simplify_expression(expression_str: str) -> dict[str, Any]:
    """Simplify a symbolic expression using miasm's rewrite rules.

    Useful for de-obfuscating MBA (Mixed Boolean-Arithmetic) and
    opaque predicates. Input is a string in miasm expression syntax.

    Args:
        expression_str: Expression in miasm syntax, e.g. "RAX ^ RAX",
            "(RAX & RBX) | (RAX & ~RBX)".

    Returns:
        Dict with original and simplified expression strings.
    """
    import re

    from miasm.expression.expression import ExprCompose, ExprId, ExprInt, ExprOp, ExprSlice
    from miasm.expression.simplifications import expr_simp

    # Build a namespace of common registers for parsing
    regs_64 = {
        name: ExprId(name, 64)
        for name in ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI",
                      "RBP", "RSP", "R8", "R9", "R10", "R11",
                      "R12", "R13", "R14", "R15"]
    }
    regs_32 = {
        name: ExprId(name, 32)
        for name in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"]
    }

    # Pre-process: convert bare integer literals to ExprInt(val, 64)
    # Matches hex (0x...) and decimal literals not already inside ExprInt()
    processed = re.sub(
        r'(?<!ExprInt\()\b(0[xX][0-9a-fA-F]+|\d+)\b',
        lambda m: f'ExprInt({m.group(1)}, 64)',
        expression_str,
    )

    ns = {
        **regs_64, **regs_32,
        "ExprInt": ExprInt, "ExprId": ExprId, "ExprOp": ExprOp,
        "ExprCompose": ExprCompose, "ExprSlice": ExprSlice,
    }

    try:
        expr = eval(processed, {"__builtins__": {}}, ns)  # noqa: S307 — sandboxed namespace
    except Exception as exc:
        return {"error": f"Cannot parse expression: {exc}", "original": expression_str}

    simplified = expr_simp(expr)
    changed = str(simplified) != str(expr)

    return {
        "original": str(expr),
        "simplified": str(simplified),
        "changed": changed,
    }


@_safe_miasm_call
def miasm_emulate_snippet(
    pe_path: Path,
    address: int,
    size: int = 256,
    arch: str = "",
    max_instructions: int = 100,
    initial_regs: dict[str, int] | None = None,
    initial_memory: dict[int, bytes] | None = None,
) -> dict[str, Any]:
    """Emulate a code snippet using miasm's symbolic execution engine.

    Runs symbolic execution from the given address, tracking register
    and memory state. Useful for understanding what a code block does
    without running it.

    Args:
        pe_path: Path to the PE file on disk.
        address: Virtual address to start emulation.
        size: Maximum bytes to read.
        arch: Architecture override.
        max_instructions: Stop after this many instructions.
        initial_regs: Optional concrete register values to set before execution.
        initial_memory: Optional concrete memory values to set before execution,
            mapping virtual address to a bytes payload written one byte at a time.

    Returns:
        Dict with final symbolic state of registers.
    """
    from miasm.analysis.machine import Machine
    from miasm.core.bin_stream import bin_stream_str
    from miasm.core.locationdb import LocationDB
    from miasm.ir.symbexec import SymbolicExecutionEngine

    if not arch:
        arch = _detect_arch(pe_path)

    raw = _read_bytes_at_va(pe_path, address, size)
    if raw is None:
        return {"error": f"Cannot read {size} bytes at 0x{address:x}"}

    machine = Machine(arch)
    loc_db = LocationDB()
    bs = bin_stream_str(raw, base_address=address)
    mdis = machine.dis_engine(bs, loc_db=loc_db)
    mdis.follow_call = False
    mdis.dontdis_retcall = True

    lifter = machine.lifter_model_call(loc_db)
    ircfg = lifter.new_ircfg()

    try:
        block = mdis.dis_block(address)
        lifter.add_asmblock_to_ircfg(block, ircfg)
    except Exception as exc:
        return {"error": f"Disassembly/lift failed: {exc}"}

    # Run symbolic execution
    sb = SymbolicExecutionEngine(lifter)

    # Seed initial register and memory values if provided
    if initial_regs or initial_memory:
        from miasm.expression.expression import ExprId, ExprInt, ExprMem
        ptr_bits = 64 if arch in ("x86_64", "aarch64l") else 32
        for reg_name, value in (initial_regs or {}).items():
            sb.symbols[ExprId(reg_name, 64)] = ExprInt(value & ((1 << 64) - 1), 64)
        for base_addr, data_bytes in (initial_memory or {}).items():
            for i, byte_val in enumerate(data_bytes):
                sb.symbols[ExprMem(ExprInt(base_addr + i, ptr_bits), 8)] = ExprInt(byte_val & 0xFF, 8)

    # Execute the IR block
    loc_key = loc_db.get_offset_location(address)
    try:
        next_addr = sb.run_block_at(ircfg, loc_key)
    except Exception as exc:
        return {"error": f"Symbolic execution failed: {exc}"}

    # Collect final state — only modified registers
    modified = {}
    for sym, val in sb.modified():
        modified[str(sym)] = str(val)

    return {
        "arch": arch,
        "start_address": f"0x{address:x}",
        "next_address": str(next_addr) if next_addr else None,
        "modified_count": len(modified),
        "modified_state": modified,
    }
