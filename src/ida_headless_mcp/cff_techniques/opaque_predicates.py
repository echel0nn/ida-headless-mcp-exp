"""Opaque predicate patterns used by control-flow flattening obfuscators.

Each pattern recognizes a class of always-true (or always-false) conditional
branches inserted to confuse static analysis. A matched pattern signals that
exactly one of the block's two successors is dead code / a trap.

Patterns are pure detectors -- they read a ``BlockInfo`` and return a
confidence in ``[0.0, 1.0]`` plus extracted constants. They never mutate
state and never require a worker process.
"""
from __future__ import annotations

import re
from typing import Any, ClassVar

from ._types import BlockInfo, OpaquePattern

__all__ = [
    "LcgOpaquePredicate",
    "QuadraticOpaquePredicate",
    "MbaOpaquePredicate",
    "ConstantFoldOpaquePredicate",
    "ALL_OPAQUE_PATTERNS",
]


# ---------------------------------------------------------------------------
# Helpers -- kept local so the module stays self-contained.
# ---------------------------------------------------------------------------

# Hex/decimal literal not preceded by alnum/underscore -- skips R10-style names.
_IMMEDIATE_RE = re.compile(r"(?<![0-9A-Za-z_])(0[xX][0-9a-fA-F]+|[0-9]+)")
# Memory displacements ([RIP+N], [RSP+8]) are addresses, not predicate constants.
_MEM_REF_RE = re.compile(r"\[[^\]]*\]")
# Constant text classification for simplifier output.
_CONST_TEXT_RE = re.compile(r"^-?(0[xX][0-9a-fA-F]+|[0-9]+)$")


def _instructions(block: BlockInfo) -> list[Any]:
    """Return the instruction list of ``block`` defensively."""
    return list(getattr(block, "instructions", None) or [])


def _mn(insn: Any) -> str:
    """Return upper-cased mnemonic from a dict or attr-bearing record."""
    name = insn.get("mnemonic", "") if isinstance(insn, dict) else getattr(insn, "mnemonic", "")
    return (name or "").upper()


def _ops(insn: Any) -> str:
    """Return operand text from a dict or attr-bearing record."""
    val = insn.get("operands", "") if isinstance(insn, dict) else getattr(insn, "operands", "")
    return val or ""


def _has_call(block: BlockInfo) -> bool:
    """Return True when ``block`` contains a CALL."""
    if getattr(block, "has_call", False):
        return True
    return any(_mn(i).startswith("CALL") for i in _instructions(block))


def _successor_count(block: BlockInfo) -> int:
    """Return the number of successors known on the block."""
    return len(getattr(block, "successors", None) or [])


def _has_conditional_branch(block: BlockInfo) -> bool:
    """True if the last instruction is a Jcc (``JMP``/``JMPF``/``JMPN`` excluded)."""
    insns = _instructions(block)
    if not insns:
        return False
    last = _mn(insns[-1])
    return last.startswith("J") and last not in {"JMP", "JMPF", "JMPN"}


def _extract_immediates(operands: str) -> list[int]:
    """Return literal integer immediates in ``operands`` with memory refs stripped."""
    cleaned = _MEM_REF_RE.sub("", operands)
    out: list[int] = []
    for match in _IMMEDIATE_RE.finditer(cleaned):
        try:
            out.append(int(match.group(1), 0))
        except ValueError:
            continue
    return out


def _last_immediate(operands: str) -> int | None:
    """Return the rightmost immediate (typical ``IMUL r, r, imm``)."""
    imms = _extract_immediates(operands)
    return imms[-1] if imms else None


def _first_immediate(operands: str) -> int | None:
    """Return the leftmost immediate."""
    imms = _extract_immediates(operands)
    return imms[0] if imms else None


def _imul_same_reg(operands: str) -> bool:
    """True when the first two operand tokens are the same register name."""
    cleaned = _MEM_REF_RE.sub("", operands)
    parts = [p.strip().upper() for p in cleaned.split(",") if p.strip()]
    return len(parts) >= 2 and parts[0] == parts[1] and parts[0][:1].isalpha()


# ---------------------------------------------------------------------------
# Pattern 1 -- Linear Congruential Generator (LCG-CFF variants, Hikari)
# ---------------------------------------------------------------------------


class LcgOpaquePredicate(OpaquePattern):
    """LCG predicate ``y == (A*x mod m + K) mod m``. Always true. IMUL+DIV+CMP/CMOV, no CALL."""

    name: ClassVar[str] = "lcg"
    description: ClassVar[str] = (
        "Linear congruential opaque predicate: y == (A*x mod m + K) mod m. "
        "Seen in LCG-CFF variants and some Hikari forks."
    )

    @classmethod
    def detect(cls, block: BlockInfo) -> float:
        """Return confidence in ``[0.0, 1.0]`` for the LCG predicate.

        Two variants are supported: control-flow (IMUL+DIV+CMP+Jcc, two
        successors) and data-flow (IMUL+DIV+CMOVZ/NZ, single successor).
        """
        if _has_call(block):
            return 0.0
        has_imul = has_div = has_sub_or_cmp = has_cmov = False
        for insn in _instructions(block):
            mnem = _mn(insn)
            if mnem.startswith('IMUL'):
                has_imul = True
            elif mnem in {'DIV', 'IDIV'}:
                has_div = True
            elif mnem in {'SUB', 'CMP'}:
                imm = _last_immediate(_ops(insn))
                if imm is not None and imm > 0xFFFF:
                    has_sub_or_cmp = True
            elif mnem in {'CMOVZ', 'CMOVE', 'CMOVNZ', 'CMOVNE'}:
                has_cmov = True
        if not (has_imul and has_div):
            return 0.0
        if has_cmov:
            return 0.9
        if not _has_conditional_branch(block):
            return 0.3 if has_sub_or_cmp else 0.0
        if _successor_count(block) not in (0, 2):
            return 0.0
        return 0.9 if has_sub_or_cmp else 0.3

    @classmethod
    def extract_constants(cls, block: BlockInfo) -> dict[str, Any]:
        """Return ``{"A", "m", "K"}`` recovered from IMUL/DIV/SUB operands."""
        a: int | None = None
        m: int | str | None = None
        k: int | None = None
        for insn in _instructions(block):
            mnem = _mn(insn)
            ops = _ops(insn)
            if mnem.startswith("IMUL") and a is None:
                a = _last_immediate(ops)
            elif mnem in {"DIV", "IDIV"} and m is None:
                imm = _first_immediate(ops)
                m = imm if imm is not None else (ops.strip() or "register")
            elif mnem in {"SUB", "CMP"} and k is None:
                imm = _last_immediate(ops)
                if imm is not None and imm > 0xFFFF:
                    k = imm
        return {"A": a, "m": m, "K": k}


# ---------------------------------------------------------------------------
# Pattern 2 -- Quadratic predicate (OLLVM ``-bcf`` default)
# ---------------------------------------------------------------------------


class QuadraticOpaquePredicate(OpaquePattern):
    """OLLVM parity predicate ``x*(x+1) % 2 == 0``: MUL/IMUL(same reg) + AND/TEST 1 + Jcc, no CALL."""

    name: ClassVar[str] = "quadratic"
    description: ClassVar[str] = (
        "Quadratic opaque predicate x*(x+1)%2==0 from OLLVM bogus-control-flow."
    )

    @classmethod
    def detect(cls, block: BlockInfo) -> float:
        """Return confidence that ``block`` carries the parity predicate.

        Signals: a multiply (unary ``MUL`` or ``IMUL`` whose first two operand
        tokens are the same register), a modulo-2 test (``AND`` or ``TEST``
        with immediate ``1``), a trailing ``Jcc`` and no ``CALL``.
        """
        if _has_call(block) or not _has_conditional_branch(block):
            return 0.0
        has_mul = mod2 = False
        for insn in _instructions(block):
            mnem = _mn(insn)
            ops = _ops(insn)
            if mnem == "MUL" or (mnem.startswith("IMUL") and _imul_same_reg(ops)):
                has_mul = True
            elif mnem in {"AND", "TEST"} and 1 in _extract_immediates(ops):
                mod2 = True
        return 0.85 if (has_mul and mod2) else 0.0

    @classmethod
    def extract_constants(cls, block: BlockInfo) -> dict[str, Any]:
        """Return the canonical formula string for reporting."""
        return {"formula": "x*(x+1)%2==0", "always": True}


# ---------------------------------------------------------------------------
# Pattern 3 -- Mixed Boolean-Arithmetic identity (Tigress, Pluto, OLLVM forks)
# ---------------------------------------------------------------------------


class MbaOpaquePredicate(OpaquePattern):
    """MBA tautology like ``(x&y)+(x|y)==x+y``; bool/arith density heuristic."""

    name: ClassVar[str] = "mba"
    description: ClassVar[str] = (
        "Mixed Boolean-Arithmetic tautology, e.g. (x&y)+(x|y)==x+y. "
        "Seen in Tigress, Pluto, and advanced OLLVM forks."
    )

    _MIN_BOOL_OPS: ClassVar[int] = 2
    _MIN_ARITH_OPS: ClassVar[int] = 1

    @classmethod
    def detect(cls, block: BlockInfo) -> float:
        """Confidence based on density of boolean and arithmetic ops before a Jcc.

        Pure-string disassembly cannot reliably reconstruct the symbolic
        expression of the branch condition, so this detector grades by op
        density. When the trailing ``TEST``/``CMP`` operand is a single
        register, a best-effort call to miasm's expression simplifier may
        upgrade the confidence -- failures are silently tolerated.
        """
        if _has_call(block) or not _has_conditional_branch(block):
            return 0.0
        bool_ops = arith_ops = 0
        last_test_target: str | None = None
        for insn in _instructions(block):
            mnem = _mn(insn)
            ops = _ops(insn)
            if mnem in {"AND", "OR", "XOR", "NOT"}:
                bool_ops += 1
            elif mnem in {"ADD", "SUB", "NEG", "INC", "DEC"}:
                arith_ops += 1
            if mnem in {"TEST", "CMP"}:
                parts = [p.strip() for p in _MEM_REF_RE.sub("", ops).split(",") if p.strip()]
                last_test_target = parts[0] if parts and parts[0][:1].isalpha() else None
        if bool_ops < cls._MIN_BOOL_OPS or arith_ops < cls._MIN_ARITH_OPS:
            return 0.0
        if bool_ops >= 3 and arith_ops >= 2 and last_test_target:
            try:
                from ..miasm_tools import miasm_simplify_expression
                res = miasm_simplify_expression(last_test_target)
            except (ImportError, ValueError, KeyError, RuntimeError, TypeError):
                res = None
            if isinstance(res, dict) and res.get("changed"):
                simp = (res.get("simplified") or "").strip()
                if _CONST_TEXT_RE.match(simp):
                    return 0.95
                return 0.7
        if bool_ops >= 3:
            return 0.7
        return 0.6

    @classmethod
    def extract_constants(cls, block: BlockInfo) -> dict[str, Any]:
        """Return the original branch condition text and its simplification, if any."""
        insns = _instructions(block)
        last = insns[-1] if insns else None
        original = f"{_mn(last)} {_ops(last)}".strip() if last else ""
        return {"expression": original, "simplified": None}


# ---------------------------------------------------------------------------
# Pattern 4 -- Generic catch-all
# ---------------------------------------------------------------------------


class ConstantFoldOpaquePredicate(OpaquePattern):
    """Weak catch-all for any Jcc with two successors not matched by a stronger pattern."""

    name: ClassVar[str] = "constant_fold"
    description: ClassVar[str] = (
        "Generic opaque predicate catch-all: conditional branch with two "
        "successors that does not match a more specific pattern."
    )

    @classmethod
    def detect(cls, block: BlockInfo) -> float:
        """Return ``0.3`` for any Jcc block with no ``CALL`` and two successors.

        Suppressed when the block exhibits stronger signatures (LCG: IMUL+DIV;
        Quadratic: IMUL+AND/TEST 1; dense MBA: 3+ bitwise ops). Those have
        dedicated detectors that should win on confidence.
        """
        if _has_call(block) or not _has_conditional_branch(block):
            return 0.0
        if _successor_count(block) not in (0, 2):
            return 0.0
        has_imul = has_div = has_and1 = False
        bool_ops = 0
        for insn in _instructions(block):
            mnem = _mn(insn)
            if mnem.startswith("IMUL"):
                has_imul = True
            elif mnem in {"DIV", "IDIV"}:
                has_div = True
            elif mnem in {"AND", "TEST"} and 1 in _extract_immediates(_ops(insn)):
                has_and1 = True
            elif mnem in {"AND", "OR", "XOR"}:
                bool_ops += 1
        if has_imul and (has_div or has_and1):
            return 0.0
        if bool_ops >= 3:
            return 0.0
        return 0.3

    @classmethod
    def extract_constants(cls, block: BlockInfo) -> dict[str, Any]:
        """Return placeholder metadata -- the catch-all has no specific constants."""
        return {"matched_by": "catch_all", "simplified_to": None}


class BitManipOpaquePredicate(OpaquePattern):
    """Bitwise opaque predicate (es3n1n obfuscator, 67 variants).

    Pattern: SHL/SHR/AND/XOR/ADD/SUB with small immediates, then CMP+JZ.
    Example: ``((x << 16) & 6) == 0`` is always true.
    """
    name: ClassVar[str] = 'bitmanip'
    description: ClassVar[str] = 'Bitwise identity predicate (SHL/AND/XOR + CMP small)'
    always_true: ClassVar[bool] = True

    @classmethod
    def detect(cls, block: BlockInfo) -> float:
        """Detect 2+ bit ops + CMP small constant + conditional branch + no CALL."""
        if _has_call(block):
            return 0.0
        if not _has_conditional_branch(block):
            return 0.0
        bit_ops = 0
        has_cmp_small = False
        for insn in _instructions(block):
            mn = _mnemonic(insn)
            if mn in ('SHL', 'SHR', 'SAR', 'ROL', 'ROR', 'AND', 'OR', 'XOR'):
                bit_ops += 1
            elif mn in ('CMP', 'TEST'):
                imm = _last_immediate(_operands(insn))
                if imm is not None and imm <= 32:
                    has_cmp_small = True
        if bit_ops >= 2 and has_cmp_small:
            return 0.85
        if bit_ops >= 1 and has_cmp_small:
            return 0.5
        return 0.0

    @classmethod
    def extract_constants(cls, block: BlockInfo) -> dict[str, Any]:
        """Extract bit manipulation operations and CMP target."""
        ops = []
        cmp_val = None
        for insn in _instructions(block):
            mn = _mnemonic(insn)
            op = _operands(insn)
            if mn in ('SHL', 'SHR', 'AND', 'OR', 'XOR', 'ADD', 'SUB'):
                imm = _last_immediate(op)
                if imm is not None:
                    ops.append(f'{mn} {imm}')
            elif mn in ('CMP', 'TEST'):
                imm = _last_immediate(op)
                if imm is not None:
                    cmp_val = imm
        return {'operations': ops, 'cmp_value': cmp_val}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


ALL_OPAQUE_PATTERNS: tuple[type[OpaquePattern], ...] = (
    LcgOpaquePredicate,
    QuadraticOpaquePredicate,
    MbaOpaquePredicate,
    ConstantFoldOpaquePredicate,
    BitManipOpaquePredicate,
)
