from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "decompile_cfunc",
    "query_ctree_calls",
    "get_microcode_text",
]


@dataclass(frozen=True, slots=True)
class _CallMatch:
    address: str
    callee_name: str | None
    callee_expr: str
    arg_count: int
    args_preview: list[str]
    matches_filters: bool
    detail: str | None


def decompile_cfunc(func: Any) -> Any:
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler not available")
    return ida_hexrays.decompile_func(func)


class _CallCollector:  # subclassing ida class at runtime to avoid import at module load
    pass


def query_ctree_calls(
    cfunc: Any,
    *,
    target_function: str = "",
    argument_index: int | None = None,
    contains_operation: str = "",
    operand_type_is: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    import ida_hexrays

    target_fn = target_function.strip().lower()
    contains_op = _op_name_to_const(contains_operation)
    operand_type_need = operand_type_is.strip().lower()

    matches: list[dict[str, Any]] = []

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST | ida_hexrays.CV_PARENTS)

        def visit_expr(self, expr):  # type: ignore[override]
            nonlocal matches
            if expr.op != ida_hexrays.cot_call:
                return 0
            if len(matches) >= limit:
                return 1

            callee_name = _callee_name(expr)
            callee_expr = _expr_preview(expr.x, cfunc)
            args = list(expr.a) if expr.a is not None else []
            args_preview = [_expr_preview(a, cfunc) for a in args]
            detail: str | None = None
            ok = True

            if target_fn:
                if not callee_name or target_fn not in callee_name.lower():
                    ok = False
                    detail = f"callee {callee_name!r} does not match target_function"

            target_arg = None
            if ok and argument_index is not None:
                if argument_index < 0 or argument_index >= len(args):
                    ok = False
                    detail = f"argument_index {argument_index} out of range for {len(args)} args"
                else:
                    target_arg = args[argument_index]

            if ok and contains_op is not None and target_arg is not None:
                if target_arg.find_op(contains_op) is None:
                    ok = False
                    detail = f"argument {argument_index} does not contain operation {contains_operation!r}"

            if ok and operand_type_need and target_arg is not None:
                operand_match = _operand_type_matches(target_arg, contains_op, operand_type_need)
                if not operand_match:
                    ok = False
                    detail = f"argument {argument_index} does not satisfy operand_type_is={operand_type_need!r}"

            matches.append(
                {
                    "address": f"0x{expr.ea:x}",
                    "callee_name": callee_name,
                    "callee_expr": callee_expr,
                    "arg_count": len(args),
                    "args_preview": args_preview,
                    "matches_filters": ok,
                    "detail": detail,
                }
            )
            return 0

    visitor = Visitor()
    visitor.apply_to_exprs(cfunc.body, None)
    filtered = [m for m in matches if m["matches_filters"]]
    return {
        "entry_ea": f"0x{cfunc.entry_ea:x}",
        "function_name": _function_name(cfunc),
        "matches": filtered,
        "scanned_calls": len(matches),
        "returned": len(filtered),
    }


def get_microcode_text(cfunc: Any, maturity: str = "current") -> dict[str, Any]:
    import ida_hexrays

    mba = cfunc.mba
    requested = maturity.strip().lower()
    if requested != "current":
        mat = _maturity_name_to_const(requested)
        if mat is None:
            raise ValueError(f"Unknown microcode maturity: {maturity!r}")
        try:
            mba.set_maturity(mat)
        except Exception:
            # Keep current maturity if set_maturity fails; report it in output.
            pass

    printer = ida_hexrays.qstring_printer_t(cfunc, False)
    mba._print(printer)
    text = str(printer.s)
    return {
        "entry_ea": f"0x{cfunc.entry_ea:x}",
        "function_name": _function_name(cfunc),
        "maturity": _maturity_const_to_name(getattr(mba, "maturity", None)),
        "text": text,
        "line_count": len(text.splitlines()),
    }


def _function_name(cfunc: Any) -> str:
    import ida_funcs

    return ida_funcs.get_func_name(cfunc.entry_ea)


def _callee_name(call_expr: Any) -> str | None:
    import ida_hexrays
    import ida_name

    x = call_expr.x
    if x is None:
        return None
    if x.op == ida_hexrays.cot_obj:
        try:
            return ida_name.get_ea_name(x.obj_ea)
        except Exception:
            return None
    if x.op == ida_hexrays.cot_helper:
        try:
            return str(x.helper)
        except Exception:
            return None
    if x.op == ida_hexrays.cot_var:
        try:
            return str(x.v.idx)
        except Exception:
            return None
    return None


def _expr_preview(expr: Any, cfunc: Any) -> str:
    try:
        raw = str(expr.print1(cfunc))
    except Exception:
        try:
            raw = str(expr.dstr())
        except Exception:
            return f"<expr op={getattr(expr, 'op', '?')}>"
    try:
        import ida_lines

        return ida_lines.tag_remove(raw)
    except Exception:
        return raw


def _op_name_to_const(name: str):
    import ida_hexrays

    if not name:
        return None
    mapping = {
        "mul": ida_hexrays.cot_mul,
        "add": ida_hexrays.cot_add,
        "sub": ida_hexrays.cot_sub,
        "call": ida_hexrays.cot_call,
        "cast": ida_hexrays.cot_cast,
        "memptr": ida_hexrays.cot_memptr,
        "memref": ida_hexrays.cot_memref,
        "idx": ida_hexrays.cot_idx,
        "obj": ida_hexrays.cot_obj,
        "num": ida_hexrays.cot_num,
    }
    key = name.strip().lower()
    if key not in mapping:
        raise ValueError(f"Unknown ctree operation name: {name!r}")
    return mapping[key]


def _operand_type_matches(expr: Any, op_const: int | None, want: str) -> bool:
    want = want.lower().strip()
    target = expr.find_op(op_const) if op_const is not None else expr
    if target is None:
        target = expr
    operand_candidates = (
        getattr(target, 'x', None),
        getattr(target, 'y', None),
        getattr(target, 'z', None),
    )
    operands = [x for x in operand_candidates if x is not None]
    if not operands:
        operands = [target]
    signed_tokens = ('int', 'char', 'short', 'long', '__int')
    for op in operands:
        try:
            tname = str(op.type.dstr()).lower()
        except Exception:
            try:
                tname = str(op.type).lower()
            except Exception:
                continue
        is_signedish = any(tok in tname for tok in signed_tokens) and 'unsigned' not in tname
        if want == 'signed' and is_signedish:
            return True
        if want == 'unsigned' and 'unsigned' in tname:
            return True
        if want == 'pointer' and '*' in tname:
            return True
    return False


def _maturity_name_to_const(name: str):
    import ida_hexrays

    mapping = {
        'generated': ida_hexrays.MMAT_GENERATED,
        'preoptimized': ida_hexrays.MMAT_PREOPTIMIZED,
        'locopt': ida_hexrays.MMAT_LOCOPT,
        'calls': ida_hexrays.MMAT_CALLS,
        'glbopt1': ida_hexrays.MMAT_GLBOPT1,
        'glbopt2': ida_hexrays.MMAT_GLBOPT2,
        'glbopt3': ida_hexrays.MMAT_GLBOPT3,
        'lvars': ida_hexrays.MMAT_LVARS,
    }
    return mapping.get(name)


def _maturity_const_to_name(mat: Any) -> str:
    import ida_hexrays

    mapping = {
        ida_hexrays.MMAT_GENERATED: 'generated',
        ida_hexrays.MMAT_PREOPTIMIZED: 'preoptimized',
        ida_hexrays.MMAT_LOCOPT: 'locopt',
        ida_hexrays.MMAT_CALLS: 'calls',
        ida_hexrays.MMAT_GLBOPT1: 'glbopt1',
        ida_hexrays.MMAT_GLBOPT2: 'glbopt2',
        ida_hexrays.MMAT_GLBOPT3: 'glbopt3',
        ida_hexrays.MMAT_LVARS: 'lvars',
    }
    return mapping.get(mat, str(mat))
