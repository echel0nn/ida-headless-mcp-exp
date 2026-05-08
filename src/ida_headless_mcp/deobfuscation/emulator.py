"""Concrete evaluator for miasm IR expressions.

Evaluates miasm expression trees with concrete integer values. Used for:
- CFF dispatcher state resolution (set state variable, run dispatcher, observe target)
- Opaque predicate evaluation (compute both sides, check if always equal)
- String decryption argument extraction (emulate prologue to read register values)

Port of D-810's MicroCodeInterpreter concept to miasm's expression model.
Does NOT use z3 — uses direct integer arithmetic with bitmask truncation.
"""
from __future__ import annotations

from typing import Any

from miasm.expression.expression import (
    Expr, ExprId, ExprInt, ExprOp, ExprMem, ExprLoc,
    ExprCompose, ExprSlice, ExprCond,
)

__all__ = ["ConcreteEvaluator", "evaluate_expression"]


def _mask(bits: int) -> int:
    """Bitmask for n-bit value."""
    return (1 << bits) - 1


def _signed(val: int, bits: int) -> int:
    """Interpret unsigned value as signed."""
    if val & (1 << (bits - 1)):
        return val - (1 << bits)
    return val


def _unsigned(val: int, bits: int) -> int:
    """Convert signed to unsigned representation."""
    return val & _mask(bits)


class ConcreteEvaluator:
    """Evaluate miasm expressions with concrete values.

    Stores a symbol table mapping ExprId/ExprMem to integer values.
    Evaluates any expression tree to a concrete integer.
    """

    def __init__(self, ptr_size: int = 64):
        self.symbols: dict[str, int] = {}
        self.memory: dict[int, int] = {}  # addr -> byte
        self.ptr_size = ptr_size

    def set_register(self, name: str, value: int, size: int = 64) -> None:
        """Set a register to a concrete value."""
        self.symbols[name] = value & _mask(size)

    def set_memory(self, addr: int, data: bytes) -> None:
        """Write bytes to concrete memory."""
        for i, b in enumerate(data):
            self.memory[addr + i] = b

    def read_memory(self, addr: int, size_bytes: int) -> int | None:
        """Read an integer from concrete memory (little-endian)."""
        result = 0
        for i in range(size_bytes):
            b = self.memory.get(addr + i)
            if b is None:
                return None
            result |= b << (8 * i)
        return result

    def evaluate(self, expr: Expr) -> int | None:
        """Evaluate a miasm expression to a concrete integer.

        Returns None if any operand is unresolvable (missing symbol/memory).
        """
        if isinstance(expr, ExprInt):
            return int(expr) & _mask(expr.size)

        if isinstance(expr, ExprId):
            val = self.symbols.get(expr.name)
            if val is not None:
                return val & _mask(expr.size)
            return None

        if isinstance(expr, ExprMem):
            addr = self.evaluate(expr.ptr)
            if addr is None:
                return None
            return self.read_memory(addr, expr.size // 8)

        if isinstance(expr, ExprSlice):
            val = self.evaluate(expr.arg)
            if val is None:
                return None
            return (val >> expr.start) & _mask(expr.stop - expr.start)

        if isinstance(expr, ExprCompose):
            result = 0
            for arg in expr.args:
                if isinstance(arg, ExprSlice):
                    val = self.evaluate(arg.arg)
                    if val is None:
                        return None
                    result |= ((val >> arg.start) & _mask(arg.stop - arg.start)) << arg.start
                else:
                    val = self.evaluate(arg)
                    if val is None:
                        return None
                    result |= val
            return result & _mask(expr.size)

        if isinstance(expr, ExprCond):
            cond = self.evaluate(expr.cond)
            if cond is None:
                return None
            if cond != 0:
                return self.evaluate(expr.src1)
            return self.evaluate(expr.src2)

        if isinstance(expr, ExprLoc):
            return None  # can't resolve location keys

        if isinstance(expr, ExprOp):
            return self._eval_op(expr)

        return None

    def _eval_op(self, expr: ExprOp) -> int | None:
        """Evaluate an ExprOp with concrete values."""
        op = expr.op
        args = expr.args
        sz = expr.size
        m = _mask(sz)

        # Unary
        if len(args) == 1:
            a = self.evaluate(args[0])
            if a is None:
                return None
            if op == "-":
                return (-a) & m
            if op == "~":
                return (a ^ m) & m
            if op == "!":
                return 1 if a == 0 else 0
            if op == "parity":
                return bin(a & 0xFF).count("1") % 2
            if op in ("sext", "sign_ext"):
                return _unsigned(_signed(a, args[0].size), sz)
            if op in ("zext", "zero_ext"):
                return a & m
            return None

        # Binary
        if len(args) == 2:
            a = self.evaluate(args[0])
            b = self.evaluate(args[1])
            if a is None or b is None:
                return None

            if op == "+":
                return (a + b) & m
            if op == "-":
                return (a - b) & m
            if op == "*":
                return (a * b) & m
            if op in ("udiv", "/"):
                return (a // b) & m if b != 0 else None
            if op == "sdiv":
                sa, sb = _signed(a, sz), _signed(b, sz)
                return _unsigned(int(sa / sb) if sb != 0 else 0, sz)
            if op in ("umod", "%"):
                return (a % b) & m if b != 0 else None
            if op == "smod":
                sa, sb = _signed(a, sz), _signed(b, sz)
                return _unsigned(sa % sb if sb != 0 else 0, sz)
            if op == "&":
                return (a & b) & m
            if op == "|":
                return (a | b) & m
            if op == "^":
                return (a ^ b) & m
            if op == "<<":
                return (a << (b & 0x3F)) & m
            if op == ">>":
                return (a >> (b & 0x3F)) & m
            if op == "a>>":  # arithmetic shift right
                return _unsigned(_signed(a, sz) >> (b & 0x3F), sz)
            if op == ">>>":  # rotate right
                b_mod = b % sz
                return ((a >> b_mod) | (a << (sz - b_mod))) & m
            if op == "<<<":  # rotate left
                b_mod = b % sz
                return ((a << b_mod) | (a >> (sz - b_mod))) & m

            # Comparison
            if op == "==":
                return 1 if a == b else 0
            if op == "!=":
                return 1 if a != b else 0
            if op == "<u":
                return 1 if a < b else 0
            if op == "<=u":
                return 1 if a <= b else 0
            if op == ">u":
                return 1 if a > b else 0
            if op == ">=u":
                return 1 if a >= b else 0
            if op == "<s":
                return 1 if _signed(a, sz) < _signed(b, sz) else 0
            if op == "<=s":
                return 1 if _signed(a, sz) <= _signed(b, sz) else 0

            # Flags
            if op == "FLAG_EQ":
                return 1 if a == b else 0
            if op == "FLAG_NE":
                return 1 if a != b else 0
            if op == "FLAG_SIGN":
                return 1 if (a - b) & (1 << (sz - 1)) else 0

        return None


def evaluate_expression(expr: Expr,
                       registers: dict[str, int] | None = None,
                       memory: dict[int, bytes] | None = None,
                       ptr_size: int = 64) -> int | None:
    """Convenience function: evaluate an expression with given state."""
    ev = ConcreteEvaluator(ptr_size)
    if registers:
        for name, val in registers.items():
            ev.set_register(name, val)
    if memory:
        for addr, data in memory.items():
            ev.set_memory(addr, data)
    return ev.evaluate(expr)
