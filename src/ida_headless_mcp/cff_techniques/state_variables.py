"""Detectors for the state variable of a flattened control-flow graph.

The dispatcher of a CFF-protected function reads a single value -- the
state variable -- to select which handler runs next. Four shapes are
recognised: stack slot at a fixed offset, stack slot inferred from write
frequency, RIP-relative global, and a register pinned across handlers.

Detectors accept ``BlockInfo`` whose ``instructions`` are dict records of
the form ``{"offset", "mnemonic", "operands", "size"}`` produced by
``cff_analysis._extract_block_info``. The helpers also accept attr-style
objects so unit tests can use simple namespaces.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, ClassVar

from ._types import BlockInfo, StateVarDetector, StateVarInfo

__all__ = [
    "StackFixedOffsetDetector", "StackAnyOffsetDetector",
    "GlobalVariableDetector", "RegisterBasedDetector",
    "ALL_STATE_VAR_DETECTORS",
]

# ``[RSP + 0x24]`` / ``[ESP+24]`` / ``[RBP - 0x10]`` -- capture the offset.
_STACK_MEM_RE = re.compile(
    r"\[\s*(?P<base>R?[ESRB]P)\s*(?P<sign>[+\-])\s*"
    r"(?P<off>0[xX][0-9a-fA-F]+|[0-9]+)\s*\]", re.IGNORECASE,
)

_RIP_MEM_RE = re.compile(  # RIP-relative addressing for globals.
    r"\[\s*RIP\s*(?P<sign>[+\-])\s*"
    r"(?P<off>0[xX][0-9a-fA-F]+|[0-9]+)\s*\]", re.IGNORECASE,
)

# Bare GP register names; longer names first so ``RAX`` beats ``EAX``.
_GP_REGS = (
    "RAX RBX RCX RDX RSI RDI RBP RSP R8 R9 R10 R11 R12 R13 R14 R15 "
    "EAX EBX ECX EDX ESI EDI EBP ESP R8D R9D R10D R11D R12D R13D R14D R15D"
).split()
_REG_RE = re.compile(
    r"\b(" + "|".join(sorted(_GP_REGS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

_MOV_LIKE = {"MOV", "MOVZX", "MOVSX", "MOVSXD", "MOVSS", "MOVSD"}
_ADDR_BASES = {"RSP", "RBP", "RIP", "ESP", "EBP", "EIP"}

_PTR_PREFIX_RE = re.compile(r"^(?:DWORD|QWORD|WORD|BYTE)\s+PTR\s+", re.IGNORECASE)


def _instructions(block: BlockInfo) -> list[Any]:
    """Return the block's instruction list, defensively."""
    return list(getattr(block, "instructions", None) or [])


def _mnem(insn: Any) -> str:
    """Return the upper-case mnemonic, accepting dicts or attr-style objects."""
    if isinstance(insn, dict):
        return (insn.get("mnemonic", "") or "").upper()
    return (getattr(insn, "mnemonic", "") or "").upper()


def _operands(insn: Any) -> str:
    """Return the operand text, accepting dicts or attr-style objects."""
    if isinstance(insn, dict):
        return insn.get("operands", "") or ""
    return getattr(insn, "operands", "") or ""


def _split_operands(text: str) -> list[str]:
    """Split an operand string on top-level commas, ignoring those in ``[...]``."""
    parts: list[str] = []
    depth, buf = 0, []
    for ch in text:
        if ch == "[":
            depth += 1
            buf.append(ch)
        elif ch == "]":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _signed_offset(sign: str, raw: str) -> int:
    """Convert a captured ``[base +/- N]`` pair into a signed integer."""
    value = int(raw, 0)
    return -value if sign == "-" else value


def _parse_stack_offset(text: str) -> int | None:
    """Return the signed stack offset in ``text`` or ``None``."""
    m = _STACK_MEM_RE.search(text)
    return _signed_offset(m.group("sign"), m.group("off")) if m else None


def _parse_rip_offset(text: str) -> int | None:
    """Return the signed RIP-relative displacement, or ``None``."""
    m = _RIP_MEM_RE.search(text)
    return _signed_offset(m.group("sign"), m.group("off")) if m else None


def _has_stack_ref(ops_str: str, offset: int | None = None) -> bool:
    """Return True if ``ops_str`` references ``[RSP+/-N]`` or ``[RBP+/-N]``.

    When ``offset`` is given, the stack reference must use that signed offset.
    """
    found = _parse_stack_offset(ops_str)
    if found is None:
        return False
    return offset is None or found == offset


def _has_rip_ref(ops_str: str) -> int | None:
    """Return the signed displacement of a ``[RIP+/-N]`` reference, or ``None``."""
    return _parse_rip_offset(ops_str)


def _operand_size_hint(operand_text: str) -> int:
    """Return 32 or 64 for ``DWORD/QWORD PTR`` operands, else 0."""
    upper = operand_text.upper()
    if "QWORD" in upper:
        return 64
    if "DWORD" in upper:
        return 32
    return 0


def _operand_is_immediate(text: str) -> bool:
    """True if ``text`` reads as a bare integer immediate (with optional PTR)."""
    cleaned = _PTR_PREFIX_RE.sub("", text.strip()).lstrip("+-").strip()
    if not cleaned or "[" in cleaned or "]" in cleaned:
        return False
    try:
        int(cleaned, 0)
        return True
    except ValueError:
        return False


def _parse_immediate(text: str) -> int | None:
    """Parse a bare integer immediate operand, or ``None`` if not an immediate."""
    cleaned = _PTR_PREFIX_RE.sub("", text.strip()).strip().lstrip("+")
    if not cleaned or "[" in cleaned or "]" in cleaned:
        return None
    try:
        return int(cleaned, 0)
    except ValueError:
        return None


def _registers_referenced(operand: str) -> list[str]:
    """Return all GP register names appearing in ``operand`` (uppercased)."""
    return [m.group(1).upper() for m in _REG_RE.finditer(operand)]


def _block_address(block: BlockInfo) -> int:
    """Return the block's start VA, defaulting to 0."""
    return int(getattr(block, "address", 0) or 0)


def _extract_imm_writes(
    block: BlockInfo,
    parser: Any,
) -> dict[int, int]:
    """Return ``{key: imm}`` for ``MOV [parser-target], imm`` writes in ``block``.

    ``parser`` maps the destination operand to a stack offset or RIP
    displacement (or ``None``). First write wins per key.
    """
    out: dict[int, int] = {}
    for insn in _instructions(block):
        if _mnem(insn) not in _MOV_LIKE:
            continue
        ops = _split_operands(_operands(insn))
        if len(ops) != 2:
            continue
        key = parser(ops[0])
        if key is None or key in out:
            continue
        imm = _parse_immediate(ops[1])
        if imm is None:
            continue
        out[key] = imm
    return out


def _dispatcher_first_load(
    dispatcher: BlockInfo, parser: Any,
) -> tuple[int | None, int]:
    """Return the first ``parser``-matching offset the dispatcher reads.

    The width hint (32, 64, or 0) is taken from the source operand.
    """
    for insn in _instructions(dispatcher):
        if _mnem(insn) not in _MOV_LIKE:
            continue
        ops = _split_operands(_operands(insn))
        if len(ops) != 2:
            continue
        offset = parser(ops[1])
        if offset is not None:
            return offset, _operand_size_hint(ops[1])
    return None, 0


def _count_handler_writes(
    blocks: list[BlockInfo],
    dispatcher: BlockInfo,
    target_offset: int,
    parser: Any,
) -> tuple[int, list[int]]:
    """Count blocks (!= dispatcher) that write an immediate to ``target_offset``."""
    writers, widths = 0, []
    for block in blocks:
        if block is dispatcher:
            continue
        for insn in _instructions(block):
            if _mnem(insn) not in _MOV_LIKE:
                continue
            ops = _split_operands(_operands(insn))
            if len(ops) != 2 or parser(ops[0]) != target_offset:
                continue
            if not _operand_is_immediate(ops[1]):
                continue
            writers += 1
            hint = _operand_size_hint(ops[0])
            if hint:
                widths.append(hint)
            break  # one match per block is enough
    return writers, widths


class StackFixedOffsetDetector(StateVarDetector):
    """State variable at a fixed stack slot, e.g. ``[RSP+0x24]``.

    Read the dispatcher's first MOV-like load; if it sources a stack slot,
    confirm by counting how many other blocks write that same offset.
    """

    name: ClassVar[str] = "stack_fixed_offset"
    description: ClassVar[str] = (
        "State variable at a constant stack offset (default OLLVM/LCG-CFF shape)."
    )
    _MIN_HANDLER_WRITES: ClassVar[int] = 2

    @classmethod
    def detect(
        cls,
        blocks: list[BlockInfo],
        dispatcher: BlockInfo | None = None,
    ) -> StateVarInfo | None:
        """Return a ``StateVarInfo`` if the dispatcher reads a fixed slot."""
        if dispatcher is None:
            return None
        candidate, width = _dispatcher_first_load(dispatcher, _parse_stack_offset)
        if candidate is None:
            return None
        writes, widths = _count_handler_writes(
            blocks, dispatcher, candidate, _parse_stack_offset,
        )
        if writes < 1:
            return None
        if width == 0 and widths:
            width = max(widths)
        confidence = 0.9 if writes >= cls._MIN_HANDLER_WRITES else 0.6
        return StateVarInfo(
            location_type='stack', operand_pattern=f'DWORD PTR [RSP + 0x{candidate:X}]',
            offset=candidate, register=None,
            confidence=confidence, detector_name=cls.name,
            metadata={'handler_write_count': writes, 'width_bits': width or None},
        )


class StackAnyOffsetDetector(StateVarDetector):
    """State variable on the stack with offset detected by write frequency.

    Tally every ``MOV [RSP+/-N], imm`` across blocks; discard scratch-sized
    offsets and offsets written by a single block; pick the offset with the
    most distinct writers (ties: largest absolute offset).
    """

    name: ClassVar[str] = "stack_any_offset"
    description: ClassVar[str] = (
        "State variable at a stack offset detected by write-frequency analysis."
    )
    _SCRATCH_OFFSET_MAX: ClassVar[int] = 7
    _MIN_DISTINCT_WRITERS: ClassVar[int] = 2

    @classmethod
    def detect(
        cls,
        blocks: list[BlockInfo],
        dispatcher: BlockInfo | None = None,
    ) -> StateVarInfo | None:
        """Return the most-written stack offset, or ``None`` if uncertain."""
        writers: dict[int, set[int]] = {}
        widths: dict[int, int] = {}
        for block in blocks:
            block_va = _block_address(block)
            for insn in _instructions(block):
                if _mnem(insn) not in _MOV_LIKE:
                    continue
                ops = _split_operands(_operands(insn))
                if len(ops) != 2:
                    continue
                off = _parse_stack_offset(ops[0])
                if off is None:
                    continue
                widths.setdefault(off, _operand_size_hint(ops[0]) or 32)
                if abs(off) > cls._SCRATCH_OFFSET_MAX and _operand_is_immediate(ops[1]):
                    writers.setdefault(off, set()).add(block_va)

        if not writers:
            return None
        best_offset, best_writers = max(
            writers.items(), key=lambda kv: (len(kv[1]), abs(kv[0])),
        )
        if len(best_writers) < cls._MIN_DISTINCT_WRITERS:
            return None
        confidence = min(0.5 + 0.1 * len(best_writers), 0.95)
        return StateVarInfo(
            location_type='stack', operand_pattern=f'DWORD PTR [RSP + 0x{best_offset:X}]',
            offset=best_offset, register=None,
            confidence=confidence, detector_name=cls.name,
            metadata={'handler_write_count': len(best_writers)},
        )


class GlobalVariableDetector(StateVarDetector):
    """State variable in a global slot, loaded as ``[RIP+disp]``.

    Inspect the dispatcher's first MOV-like read for RIP-relative form and
    confirm by handler writes to the same displacement. ``offset`` is the
    raw displacement; absolute VA is ``next_instruction_va + offset``.
    """

    name: ClassVar[str] = "global_variable"
    description: ClassVar[str] = (
        "State variable at a global address, loaded RIP-relative."
    )

    @classmethod
    def detect(
        cls,
        blocks: list[BlockInfo],
        dispatcher: BlockInfo | None = None,
    ) -> StateVarInfo | None:
        """Return a ``StateVarInfo`` if the dispatcher reads ``[RIP+disp]``."""
        if dispatcher is None:
            return None
        candidate, width = _dispatcher_first_load(dispatcher, _parse_rip_offset)
        if candidate is None:
            return None
        writes, _ = _count_handler_writes(
            blocks, dispatcher, candidate, _parse_rip_offset,
        )
        confidence = 0.85 if writes >= 1 else 0.4
        return StateVarInfo(
            location_type='global', operand_pattern=f'[RIP + 0x{candidate:X}]',
            offset=candidate, register=None,
            confidence=confidence, detector_name=cls.name,
            metadata={'handler_write_count': writes},
        )


class RegisterBasedDetector(StateVarDetector):
    """State variable kept in a register (e.g. ``EBX``) across handlers.

    Find a register read by the dispatcher with no prior local write (it
    was inherited from upstream); confirm handler blocks write the same
    register before jumping back, and pick the highest write count.
    """

    name: ClassVar[str] = "register_based"
    description: ClassVar[str] = (
        "State variable kept in a callee-saved or pinned register across blocks."
    )
    _MIN_HANDLER_WRITES: ClassVar[int] = 2

    @classmethod
    def detect(
        cls,
        blocks: list[BlockInfo],
        dispatcher: BlockInfo | None = None,
    ) -> StateVarInfo | None:
        """Return a ``StateVarInfo`` for a register state variable, if any."""
        if dispatcher is None:
            return None
        candidates = _dispatcher_register_inputs(dispatcher)
        if not candidates:
            return None

        write_counts: Counter[str] = Counter()
        for block in blocks:
            if block is dispatcher:
                continue
            for reg in _handler_register_writes(block, candidates):
                write_counts[reg] += 1

        if not write_counts:
            return None
        reg, count = write_counts.most_common(1)[0]
        if count < cls._MIN_HANDLER_WRITES:
            return None
        confidence = min(0.5 + 0.1 * count, 0.9)
        return StateVarInfo(
            location_type='register', operand_pattern=reg,
            offset=None, register=reg,
            confidence=confidence, detector_name=cls.name,
            metadata={'handler_write_count': count},
        )


def _dispatcher_register_inputs(dispatcher: BlockInfo) -> set[str]:
    """Return registers read in the dispatcher with no prior local write.

    Excludes addressing bases (``RSP``/``RBP``/``RIP`` and 32-bit forms) --
    those are not state carriers.
    """
    written: set[str] = set()
    candidates: set[str] = set()
    for insn in _instructions(dispatcher):
        ops = _split_operands(_operands(insn))
        if not ops:
            continue
        mnem = _mnem(insn)
        # MOV-like writes ops[0] from ops[1]. Other forms (CMP/TEST/arith)
        # are treated as reading every operand and writing only ops[0].
        if mnem in _MOV_LIKE and len(ops) == 2:
            read_side, write_side = [ops[1]], [ops[0]]
        else:
            read_side = ops
            write_side = [ops[0]] if len(ops) > 1 else []

        for src in read_side:
            for reg in _registers_referenced(src):
                if reg in _ADDR_BASES or reg in written:
                    continue
                candidates.add(reg)

        for dst in write_side:
            if "[" in dst:  # memory writes don't write the register operand
                continue
            for reg in _registers_referenced(dst):
                written.add(reg)
    return candidates


def _handler_register_writes(
    block: BlockInfo, candidates: set[str],
) -> list[str]:
    """Return distinct candidate registers that ``block`` writes via MOV."""
    hits: set[str] = set()
    for insn in _instructions(block):
        if _mnem(insn) not in _MOV_LIKE:
            continue
        ops = _split_operands(_operands(insn))
        if len(ops) != 2:
            continue
        dst = ops[0].strip()
        if "[" in dst:
            continue
        for reg in _registers_referenced(dst):
            if reg in candidates:
                hits.add(reg)
    return sorted(hits)


ALL_STATE_VAR_DETECTORS: tuple[type[StateVarDetector], ...] = (
    StackFixedOffsetDetector,
    StackAnyOffsetDetector,
    GlobalVariableDetector,
    RegisterBasedDetector,
)
