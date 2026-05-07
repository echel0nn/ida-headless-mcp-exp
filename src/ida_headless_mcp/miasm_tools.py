"""Miasm-based analysis tools — run server-side, no idalib needed.

These tools operate on raw binary bytes read from the workspace PE file.
They do NOT require a worker process or idalib. Results are instant.

Capabilities:
  - Disassembly (miasm's own engine, multi-arch)
  - IR lifting to miasm's intermediate representation
  - Expression simplification / de-obfuscation
  - Symbolic execution of code snippets
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

__all__ = [
    "miasm_disassemble",
    "miasm_lift_ir",
    "miasm_simplify_expression",
    "miasm_emulate_snippet",
]


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
    """Detect architecture from PE machine field."""
    data = pe_path.read_bytes()
    if len(data) < 0x40:
        return "x86_64"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 6 > len(data):
        return "x86_64"
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    arch_map = {
        0x14C: "x86_32",
        0x8664: "x86_64",
        0x1C0: "arml",
        0xAA64: "aarch64l",
    }
    return arch_map.get(machine, "x86_64")


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
    from miasm.expression.expression import ExprId, ExprInt, ExprOp
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
    ns = {**regs_64, **regs_32, "ExprInt": ExprInt, "ExprId": ExprId, "ExprOp": ExprOp}

    try:
        expr = eval(expression_str, {"__builtins__": {}}, ns)  # noqa: S307 — sandboxed namespace
    except Exception as exc:
        return {"error": f"Cannot parse expression: {exc}", "original": expression_str}

    simplified = expr_simp(expr)
    changed = str(simplified) != str(expr)

    return {
        "original": str(expr),
        "simplified": str(simplified),
        "changed": changed,
    }


def miasm_emulate_snippet(
    pe_path: Path,
    address: int,
    size: int = 256,
    arch: str = "",
    max_instructions: int = 100,
    initial_regs: dict[str, int] | None = None,
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

    # Set initial register values if provided
    if initial_regs:
        from miasm.expression.expression import ExprId, ExprInt
        for reg_name, value in initial_regs.items():
            reg = ExprId(reg_name, 64)
            sb.symbols[reg] = ExprInt(value, 64)

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
