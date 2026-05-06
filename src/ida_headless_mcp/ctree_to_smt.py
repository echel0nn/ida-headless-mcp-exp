"""CTree-to-SMT-LIB compiler.

Walks Hex-Rays CTree expression nodes and emits QF_BV SMT-LIB terms.
Each cot_* node maps to one bitvector operation. This replaces the
regex-based _gate_to_smt/_expr_to_smt that could only handle 3 patterns.

Used by: prove_overflow, prove_bounds_sufficient, prove_predicate_opaque,
prove_equivalence.
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "expr_to_smt",
    "condition_to_smt",
    "expr_to_smt_with_coverage",
    "SMTContext",
]


class SMTContext:
    """Tracks declared variables and their widths during SMT emission."""

    def __init__(self, default_width: int = 32) -> None:
        self.default_width = default_width
        self.declarations: dict[str, int] = {}  # var_name → width in bits

    def declare(self, name: str, width: int) -> str:
        """Register a variable. Returns the SMT name."""
        if name not in self.declarations:
            self.declarations[name] = width
        return name

    def get_declarations_smt(self) -> str:
        """Return all (declare-const ...) statements."""
        lines = []
        for name, width in sorted(self.declarations.items()):
            lines.append(f"(declare-const {name} (_ BitVec {width}))")
        return "\n".join(lines)


def expr_to_smt(
    expr: Any,
    ctx: SMTContext,
    _unsupported: list[str] | None = None,
) -> str | None:
    """Convert a CTree expression node to an SMT-LIB bitvector term.

    Args:
        expr: A Hex-Rays cexpr_t node.
        ctx: SMT context for tracking variable declarations.
        _unsupported: Optional list. When provided, every CTree op that
            falls through to the free-variable fallback is appended as
            ``cot_<op>``. Used by ``expr_to_smt_with_coverage``; callers
            that ignore coverage may leave it as ``None``.

    Returns:
        SMT-LIB term string, or None if the expression can't be encoded.
    """
    import ida_hexrays

    if expr is None:
        return None

    op = expr.op
    width = _expr_width(expr)

    # Constants
    if op == ida_hexrays.cot_num:
        val = expr.n._value & ((1 << width) - 1)
        return f"(_ bv{val} {width})"

    # Variables
    if op == ida_hexrays.cot_var:
        name = f"v{expr.v.idx}"
        ctx.declare(name, width)
        return name

    # Function arguments (a1, a2, ...)
    if op == ida_hexrays.cot_var and hasattr(expr.v, 'idx'):
        name = f"v{expr.v.idx}"
        ctx.declare(name, width)
        return name

    # Unary operations
    if op == ida_hexrays.cot_bnot:
        inner = expr_to_smt(expr.x, ctx, _unsupported)
        return f"(bvnot {inner})" if inner else None

    if op == ida_hexrays.cot_neg:
        inner = expr_to_smt(expr.x, ctx, _unsupported)
        return f"(bvneg {inner})" if inner else None

    if op == ida_hexrays.cot_lnot:
        # Logical not — returns bool, encode as bv == 0
        inner = expr_to_smt(expr.x, ctx, _unsupported)
        if inner:
            inner_w = _expr_width(expr.x)
            return f"(= {inner} (_ bv0 {inner_w}))"
        return None

    # Cast operations
    if op == ida_hexrays.cot_cast:
        inner = expr_to_smt(expr.x, ctx, _unsupported)
        if inner is None:
            return None
        src_width = _expr_width(expr.x)
        dst_width = width
        if dst_width > src_width:
            # Extend
            ext = dst_width - src_width
            if _is_signed_type(expr.type):
                return f"((_ sign_extend {ext}) {inner})"
            else:
                return f"((_ zero_extend {ext}) {inner})"
        elif dst_width < src_width:
            # Truncate
            return f"((_ extract {dst_width - 1} 0) {inner})"
        return inner  # same width

    # Binary arithmetic
    _binops = {
        ida_hexrays.cot_add: "bvadd",
        ida_hexrays.cot_sub: "bvsub",
        ida_hexrays.cot_mul: "bvmul",
        ida_hexrays.cot_band: "bvand",
        ida_hexrays.cot_bor: "bvor",
        ida_hexrays.cot_xor: "bvxor",
        ida_hexrays.cot_shl: "bvshl",
        ida_hexrays.cot_sshr: "bvashr",
        ida_hexrays.cot_ushr: "bvlshr",
        ida_hexrays.cot_sdiv: "bvsdiv",
        ida_hexrays.cot_udiv: "bvudiv",
        ida_hexrays.cot_smod: "bvsrem",
        ida_hexrays.cot_umod: "bvurem",
    }

    if op in _binops:
        left = expr_to_smt(expr.x, ctx, _unsupported)
        right = expr_to_smt(expr.y, ctx, _unsupported)
        if left and right:
            return f"({_binops[op]} {left} {right})"
        return None

    # Comparison operations (return Bool)
    _cmpops = {
        ida_hexrays.cot_ult: "bvult",
        ida_hexrays.cot_ule: "bvule",
        ida_hexrays.cot_ugt: "bvugt",
        ida_hexrays.cot_uge: "bvuge",
        ida_hexrays.cot_slt: "bvslt",
        ida_hexrays.cot_sle: "bvsle",
        ida_hexrays.cot_sgt: "bvsgt",
        ida_hexrays.cot_sge: "bvsge",
        ida_hexrays.cot_eq: "=",
        ida_hexrays.cot_ne: "distinct",
    }

    if op in _cmpops:
        left = expr_to_smt(expr.x, ctx, _unsupported)
        right = expr_to_smt(expr.y, ctx, _unsupported)
        if left and right:
            return f"({_cmpops[op]} {left} {right})"
        return None

    # Logical AND/OR (operate on booleans)
    if op == ida_hexrays.cot_land:
        left = condition_to_smt(expr.x, ctx, _unsupported)
        right = condition_to_smt(expr.y, ctx, _unsupported)
        if left and right:
            return f"(and {left} {right})"
        return None

    if op == ida_hexrays.cot_lor:
        left = condition_to_smt(expr.x, ctx, _unsupported)
        right = condition_to_smt(expr.y, ctx, _unsupported)
        if left and right:
            return f"(or {left} {right})"
        return None

    # Ternary (ITE)
    if op == ida_hexrays.cot_ternary:
        cond = condition_to_smt(expr.x, ctx, _unsupported)
        then_val = expr_to_smt(expr.y, ctx, _unsupported)
        else_val = expr_to_smt(expr.z, ctx, _unsupported)
        if cond and then_val and else_val:
            return f"(ite {cond} {then_val} {else_val})"
        return None

    # Memory dereference — treat as free variable (can't reason about memory)
    if op in (ida_hexrays.cot_ptr, ida_hexrays.cot_memptr,
              ida_hexrays.cot_memref, ida_hexrays.cot_idx):
        name = f"mem_{expr.ea & 0xFFFF:04x}"
        ctx.declare(name, width)
        return name

    # Object reference (global variable)
    if op == ida_hexrays.cot_obj:
        name = f"obj_{expr.obj_ea & 0xFFFFFF:06x}"
        ctx.declare(name, width)
        return name

    # Function call — treat result as free variable
    if op == ida_hexrays.cot_call:
        name = f"call_{expr.ea & 0xFFFF:04x}"
        ctx.declare(name, width)
        return name

    # Assignment — return the RHS
    if op == ida_hexrays.cot_asg:
        return expr_to_smt(expr.y, ctx, _unsupported)

    # Fallback: unknown op → free variable
    if _unsupported is not None:
        _unsupported.append(f"cot_{op}")
    name = f"unk_{op}_{expr.ea & 0xFFFF:04x}"
    ctx.declare(name, width)
    return name


def condition_to_smt(
    expr: Any,
    ctx: SMTContext,
    _unsupported: list[str] | None = None,
) -> str | None:
    """Convert a CTree expression to an SMT-LIB boolean term.

    If the expression is already a comparison (returns bool), emit directly.
    Otherwise, emit `(distinct expr (_ bv0 W))` (non-zero = true).

    Args:
        expr: A Hex-Rays cexpr_t node.
        ctx: SMT context for tracking variable declarations.
        _unsupported: Optional list. Forwarded to ``expr_to_smt`` so that
            unsupported CTree ops encountered during encoding are recorded.
    """
    import ida_hexrays

    if expr is None:
        return None

    op = expr.op

    # Already boolean operations
    bool_ops = {
        ida_hexrays.cot_ult, ida_hexrays.cot_ule,
        ida_hexrays.cot_ugt, ida_hexrays.cot_uge,
        ida_hexrays.cot_slt, ida_hexrays.cot_sle,
        ida_hexrays.cot_sgt, ida_hexrays.cot_sge,
        ida_hexrays.cot_eq, ida_hexrays.cot_ne,
        ida_hexrays.cot_land, ida_hexrays.cot_lor,
        ida_hexrays.cot_lnot,
    }

    if op in bool_ops:
        return expr_to_smt(expr, ctx, _unsupported)

    # Non-boolean expression: treat as "!= 0"
    inner = expr_to_smt(expr, ctx, _unsupported)
    if inner:
        width = _expr_width(expr)
        return f"(distinct {inner} (_ bv0 {width}))"
    return None


def _expr_width(expr: Any) -> int:
    """Get the bitvector width of a CTree expression."""
    try:
        size = expr.type.get_size()
        if size > 0:
            return size * 8
    except (AttributeError, TypeError):
        pass
    return 32  # fallback


def _is_signed_type(tinfo: Any) -> bool:
    """Check if a type_t represents a signed integer."""
    try:
        return tinfo.is_signed()
    except (AttributeError, TypeError):
        return True  # default to signed for safety



def expr_to_smt_with_coverage(
    expr: Any,
    ctx: SMTContext,
) -> tuple[str | None, list[str]]:
    """Encode an expression and report unsupported CTree node types.

    Same encoding behaviour as :func:`expr_to_smt`, but also returns a
    list of every CTree op that fell through to the free-variable
    fallback. An empty list means full structural coverage.

    Args:
        expr: A Hex-Rays cexpr_t node.
        ctx: SMT context for tracking variable declarations.

    Returns:
        Tuple of (smt_term_or_none, list_of_unsupported_node_types).
        Each unsupported entry is formatted as ``cot_<op>``.
    """
    unsupported: list[str] = []
    smt = expr_to_smt(expr, ctx, unsupported)
    return smt, unsupported


def condition_to_smt_with_coverage(
    expr: Any,
    ctx: SMTContext,
) -> tuple[str | None, list[str]]:
    """Boolean-coercing variant of :func:`expr_to_smt_with_coverage`."""
    unsupported: list[str] = []
    smt = condition_to_smt(expr, ctx, unsupported)
    return smt, unsupported