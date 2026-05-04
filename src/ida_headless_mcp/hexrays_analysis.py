from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "decompile_cfunc",
    "query_ctree_calls",
    "get_microcode_text",
    "trace_ctree_dataflow",
    "get_argument_names",
    "query_ctree_call_sequences",
    "query_ctree_unchecked_calls",
    "get_hexrays_warnings",
    "pseudocode_slice",
    "microcode_def_use",
    "microcode_value_ranges",
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


def get_argument_names(cfunc: Any) -> list[str]:
    out: list[str] = []
    try:
        for arg in cfunc.arguments:
            out.append(str(arg.name))
    except Exception:
        pass
    return out


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
            arg_ops = [_op_const_to_name(getattr(a, 'op', None)) for a in args]
            args_string_literal = [getattr(a, 'op', None) == ida_hexrays.cot_str for a in args]
            detail: str | None = None
            ok = True
            guarded_by_if = any(getattr(parent, 'op', None) == ida_hexrays.cit_if for parent in self.parents)

            if target_fn:
                candidate = (callee_name or callee_expr).lower()
                if target_fn not in candidate:
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
                    "arg_ops": arg_ops,
                    "args_string_literal": args_string_literal,
                    "guarded_by_if": guarded_by_if,
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


def trace_ctree_dataflow(
    cfunc: Any,
    *,
    sink_function: str,
    sink_argument_index: int,
    source_contains: list[str] | None = None,
    max_steps: int = 10,
) -> dict[str, Any]:
    sink = query_ctree_calls(cfunc, target_function=sink_function, argument_index=sink_argument_index, limit=1)
    if not sink["matches"]:
        return {
            "entry_ea": f"0x{cfunc.entry_ea:x}",
            "function_name": _function_name(cfunc),
            "sink_found": False,
            "sink_function": sink_function,
            "sink_argument_index": sink_argument_index,
            "chain": [],
            "source_hit": False,
            "source_term": None,
        }

    sink_match = sink["matches"][0]
    target_expr = sink_match["args_preview"][sink_argument_index]
    current_expr = _normalize_expr(target_expr)
    assignments = _collect_assignments(cfunc)
    src_terms = [s.lower() for s in (source_contains or []) if str(s).strip()]
    chain: list[dict[str, Any]] = []
    source_hit = any(term in current_expr.lower() for term in src_terms)
    source_term = next((term for term in src_terms if term in current_expr.lower()), None)
    seen_exprs: set[str] = set()

    while not source_hit and current_expr and len(chain) < max_steps:
        if current_expr in seen_exprs:
            break
        seen_exprs.add(current_expr)
        match = None
        for item in reversed(assignments):
            if item["lhs_norm"] == current_expr:
                match = item
                break
        if match is None:
            break
        chain.append({
            "address": match["address"],
            "lhs": match["lhs"],
            "rhs": match["rhs"],
        })
        current_expr = match["rhs_norm"]
        for term in src_terms:
            if term in current_expr.lower():
                source_hit = True
                source_term = term
                break

    return {
        "entry_ea": f"0x{cfunc.entry_ea:x}",
        "function_name": _function_name(cfunc),
        "sink_found": True,
        "sink_function": sink_function,
        "sink_argument_index": sink_argument_index,
        "sink_expression": target_expr,
        "chain": chain,
        "source_hit": source_hit,
        "source_term": source_term,
        "truncated": len(chain) >= max_steps,
    }


def _collect_assignments(cfunc: Any) -> list[dict[str, Any]]:
    import ida_hexrays

    out: list[dict[str, Any]] = []
    assign_ops = {
        ida_hexrays.cot_asg,
        ida_hexrays.cot_asgadd,
        ida_hexrays.cot_asgsub,
        ida_hexrays.cot_asgmul,
        ida_hexrays.cot_asgband,
        ida_hexrays.cot_asgbor,
        ida_hexrays.cot_asgxor,
    }

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):  # type: ignore[override]
            if expr.op not in assign_ops:
                return 0
            lhs = _expr_preview(expr.x, cfunc)
            rhs = _expr_preview(expr.y, cfunc)
            out.append({
                "address": f"0x{expr.ea:x}",
                "lhs": lhs,
                "rhs": rhs,
                "lhs_norm": _normalize_expr(lhs),
                "rhs_norm": _normalize_expr(rhs),
            })
            return 0

    Visitor().apply_to_exprs(cfunc.body, None)
    return out


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


def _normalize_expr(text: str) -> str:
    s = text.strip()
    # strip repeated leading C-style casts like (unsigned int)(size_t)
    while True:
        m = re.match(r"^\((?:unsigned\s+)?[\w\s:*]+\)\s*(.+)$", s)
        if not m:
            break
        s = m.group(1).strip()
    # strip one pair of outer parentheses when balanced
    if s.startswith("(") and s.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(s):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    balanced = False
                    break
        if balanced and depth == 0:
            s = s[1:-1].strip()
    return re.sub(r"\s+", " ", s)


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


def _op_const_to_name(op: Any) -> str | None:
    import ida_hexrays

    mapping = {
        ida_hexrays.cot_call: 'call',
        ida_hexrays.cot_cast: 'cast',
        ida_hexrays.cot_add: 'add',
        ida_hexrays.cot_sub: 'sub',
        ida_hexrays.cot_mul: 'mul',
        ida_hexrays.cot_obj: 'obj',
        ida_hexrays.cot_str: 'str',
        ida_hexrays.cot_num: 'num',
        ida_hexrays.cot_var: 'var',
        ida_hexrays.cot_memref: 'memref',
        ida_hexrays.cot_memptr: 'memptr',
        ida_hexrays.cot_ptr: 'ptr',
        ida_hexrays.cot_idx: 'idx',
        ida_hexrays.cot_helper: 'helper',
    }
    return mapping.get(op)


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



def query_ctree_call_sequences(
    cfunc: Any,
    *,
    first_functions: set[str],
    second_functions: set[str],
    shared_argument_index: int | None = None,
    first_arg_index: int = 0,
    match_any_second_arg: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    """Find ordered pairs of calls where a first-set call precedes a second-set call.

    Argument matching modes:
      * ``shared_argument_index=N``: both calls must have the same preview
        at argument ``N``.
      * ``match_any_second_arg=True``: argument ``first_arg_index`` of the
        first call must match ANY argument of the second call (useful for
        use-after-free where ``free(p)`` then ``printf(fmt, p)`` shares
        ``p`` at different positions).
      * ``shared_argument_index=None`` and ``match_any_second_arg=False``:
        no argument constraint.

    Args:
        cfunc: Decompiled function (Hex-Rays ``cfunc_t``) to scan.
        first_functions: Lower-cased names that the first call must match.
        second_functions: Lower-cased names that the second call must match.
        shared_argument_index: When set, require both calls to share the
            same preview at this argument index.
        first_arg_index: Argument index of the first call to use when
            ``match_any_second_arg`` is enabled.
        match_any_second_arg: When True, the chosen first-call argument
            must appear at any position in the second call.
        limit: Maximum number of pairs to return.

    Returns:
        A dict with the function entry address and name, the count of
        pairs found, and the list of matching pairs.
    """
    import ida_hexrays

    first_fn = {f.lower() for f in first_functions}
    second_fn = {f.lower() for f in second_functions}
    calls: list[dict[str, Any]] = []

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):  # type: ignore[override]
            if expr.op != ida_hexrays.cot_call:
                return 0
            callee = _callee_name(expr)
            if callee is None:
                return 0
            callee_lower = callee.lower()
            callee_stripped = callee_lower[2:] if callee_lower.startswith('j_') else callee_lower
            is_first = callee_stripped in first_fn
            is_second = callee_stripped in second_fn
            if not is_first and not is_second:
                return 0
            args = list(expr.a) if expr.a is not None else []
            all_previews = [_expr_preview(a, cfunc) for a in args]
            calls.append({
                'ea': expr.ea,
                'address': f'0x{expr.ea:x}',
                'callee': callee,
                'callee_stripped': callee_stripped,
                'is_first': is_first,
                'is_second': is_second,
                'all_previews': all_previews,
            })
            return 0

    Visitor().apply_to_exprs(cfunc.body, None)
    calls.sort(key=lambda c: c['ea'])

    def _arg_at(call: dict[str, Any], idx: int) -> str | None:
        previews = call['all_previews']
        return previews[idx] if idx < len(previews) else None

    pairs: list[dict[str, Any]] = []
    for i, first in enumerate(calls):
        if not first['is_first']:
            continue
        first_key = _arg_at(first, first_arg_index)
        for second in calls[i + 1:]:
            if not second['is_second']:
                continue
            shared_arg: str | None = None
            if shared_argument_index is not None:
                a = _arg_at(first, shared_argument_index)
                b = _arg_at(second, shared_argument_index)
                if a is None or b is None or a != b:
                    continue
                shared_arg = a
            elif match_any_second_arg and first_key is not None:
                if first_key not in second['all_previews']:
                    continue
                shared_arg = first_key
            pairs.append({
                'first_callee': first['callee'],
                'first_address': first['address'],
                'second_callee': second['callee'],
                'second_address': second['address'],
                'shared_arg': shared_arg,
            })
            if len(pairs) >= limit:
                break
        if len(pairs) >= limit:
            break

    return {
        'entry_ea': f'0x{cfunc.entry_ea:x}',
        'function_name': _function_name(cfunc),
        'pairs_found': len(pairs),
        'pairs': pairs,
    }


def query_ctree_unchecked_calls(
    cfunc: Any,
    *,
    target_functions: set[str],
    must_deref: bool = True,
    limit: int = 20,
) -> dict[str, Any]:
    """Find calls whose return value is used without a NULL/error check.

    Detects patterns such as:
      * ``null_deref``: ``p = malloc(n); *p = x;`` (no ``if(p)`` guard).
      * ``unchecked_alloc``: ``buf = realloc(old, n); buf[0] = ...;``.

    Args:
        cfunc: Decompiled function to scan.
        target_functions: Lower-cased names of allocator-style callees to
            check.
        must_deref: Require a subsequent dereference of the returned value
            when True.
        limit: Maximum number of unchecked-call findings to return.

    Returns:
        A dict with the function entry address and name, the matched
        unchecked-call sites, and the count returned.
    """
    import ida_hexrays

    target_fn = {f.lower() for f in target_functions}
    # Collect all assignments whose RHS is a call to a target function
    alloc_assignments: list[dict[str, Any]] = []
    # Collect all if-guarded variable names
    guarded_vars: set[str] = set()

    class AssignVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):  # type: ignore[override]
            if expr.op != ida_hexrays.cot_asg:
                return 0
            rhs = expr.y
            if rhs is None or rhs.op != ida_hexrays.cot_call:
                return 0
            callee = _callee_name(rhs)
            if callee is None:
                return 0
            callee_lower = callee.lower()
            callee_stripped = callee_lower[2:] if callee_lower.startswith('j_') else callee_lower
            if callee_stripped not in target_fn:
                return 0
            lhs_preview = _expr_preview(expr.x, cfunc)
            alloc_assignments.append({
                'address': f'0x{expr.ea:x}',
                'ea': expr.ea,
                'lhs': lhs_preview,
                'callee': callee,
            })
            return 0

    class IfGuardVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_insn(self, insn):  # type: ignore[override]
            if insn.op != ida_hexrays.cit_if:
                return 0
            cond = insn.cif.expr
            cond_preview = _expr_preview(cond, cfunc).lower()
            # extract variable names from simple conditions like 'if ( v1 )' or 'if ( !v1 )'
            for token in _normalize_expr(cond_preview).replace('!', ' ').split():
                guarded_vars.add(token.strip())
            return 0

    AssignVisitor().apply_to_exprs(cfunc.body, None)
    IfGuardVisitor().apply_to(cfunc.body, None)

    matches: list[dict[str, Any]] = []
    for alloc in alloc_assignments:
        lhs_norm = _normalize_expr(alloc['lhs']).lower()
        if lhs_norm in guarded_vars:
            continue
        matches.append({
            'address': alloc['address'],
            'variable': alloc['lhs'],
            'callee': alloc['callee'],
            'guarded': False,
        })
        if len(matches) >= limit:
            break

    return {
        'entry_ea': f'0x{cfunc.entry_ea:x}',
        'function_name': _function_name(cfunc),
        'matches': matches,
        'returned': len(matches),
    }



def get_hexrays_warnings(cfunc: Any) -> dict[str, Any]:
    """Extract decompiler warnings emitted by Hex-Rays for this function.

    Warnings signal degraded confidence: bad stack analysis, unrecovered
    types, inconsistent CFG, etc. The obligation system should treat
    downstream claims as weaker when warnings are present.

    Args:
        cfunc: Decompiled function whose warnings should be reported.

    Returns:
        A dict with the function entry address and name, the warning
        count, the per-warning details, and an overall ``confidence``
        label (``degraded`` if any warning fired, otherwise ``normal``).
    """
    warnings: list[dict[str, Any]] = []
    try:
        raw = cfunc.get_warnings()
        if raw:
            for w in raw:
                ea = getattr(w, 'ea', None)
                text = str(w) if not hasattr(w, 'text') else str(w.text)
                warnings.append({
                    'address': f'0x{ea:x}' if ea is not None else None,
                    'text': text,
                })
    except (AttributeError, TypeError):
        # IDA version may not expose get_warnings() — degrade gracefully
        pass
    return {
        'entry_ea': f'0x{cfunc.entry_ea:x}',
        'function_name': _function_name(cfunc),
        'warning_count': len(warnings),
        'warnings': warnings,
        'confidence': 'degraded' if warnings else 'normal',
    }


def pseudocode_slice(
    cfunc: Any,
    *,
    focus_callee: str = "",
    focus_address: str = "",
    context_lines: int = 5,
    max_slices: int = 10,
) -> dict[str, Any]:
    """Return only the pseudocode lines around specific call sites or addresses.

    Instead of returning a 400-line function, return the 10-20 lines that
    matter: the code paths reaching each instance of ``focus_callee`` or
    ``focus_address``, with ``context_lines`` of surrounding context.

    Args:
        cfunc: Decompiled function whose pseudocode is sliced.
        focus_callee: Callee name to anchor slices on. Matched
            case-insensitively against tokens in each line.
        focus_address: Hex address (e.g. ``"0x401000"``) to anchor slices
            on, resolved through the line-to-EA map when available.
        context_lines: Number of pseudocode lines to include on each side
            of every focus line.
        max_slices: Maximum number of slice windows to return.

    Returns:
        A dict with the function entry address and name, the total
        pseudocode line count, the slice count, and the slice windows.
    """
    # Get full pseudocode lines
    try:
        sv = cfunc.get_pseudocode()
    except (AttributeError, TypeError):
        sv = None

    lines: list[str] = []
    if sv is not None:
        import ida_lines
        for i in range(sv.size()):
            raw_line = str(sv[i].line)
            lines.append(ida_lines.tag_remove(raw_line))
    else:
        lines = str(cfunc).splitlines()

    total_lines = len(lines)
    focus_fn = focus_callee.strip().lower()
    focus_addr: int | None = None
    if focus_address.strip():
        try:
            focus_addr = int(focus_address.strip(), 16)
        except ValueError:
            pass

    # Find matching lines
    hit_indices: list[int] = []
    for i, line in enumerate(lines):
        line_lower = line.lower()
        if focus_fn and focus_fn + '(' in line_lower:
            hit_indices.append(i)
        elif focus_fn and focus_fn in line_lower:
            hit_indices.append(i)

    # If we have a CTree, also match by address via eamap
    if focus_addr is not None and sv is not None:
        try:
            cfunc.get_eamap()  # ensure eamap is built
            for i in range(sv.size()):
                item = cfunc.get_line_item(i)
                if item is not None and hasattr(item, 'ea') and item.ea == focus_addr:
                    if i not in hit_indices:
                        hit_indices.append(i)
        except (AttributeError, TypeError):
            pass

    # Deduplicate and limit
    hit_indices = sorted(set(hit_indices))[:max_slices]

    # Build slices with context
    slices: list[dict[str, Any]] = []
    for idx in hit_indices:
        start = max(0, idx - context_lines)
        end = min(total_lines, idx + context_lines + 1)
        slice_lines = lines[start:end]
        slices.append({
            'focus_line': idx + 1,
            'range': f'{start + 1}-{end}',
            'pseudocode': '\n'.join(slice_lines),
            'focus_text': lines[idx].strip(),
        })

    return {
        'entry_ea': f'0x{cfunc.entry_ea:x}',
        'function_name': _function_name(cfunc),
        'total_lines': total_lines,
        'slices_count': len(slices),
        'slices': slices,
    }



def microcode_def_use(
    cfunc: Any,
    *,
    target_callee: str = "",
    max_instructions: int = 200,
) -> dict[str, Any]:
    """Extract microcode-level use/def lists for instructions in a function.

    For each microcode instruction, return what locations it reads (uses)
    and writes (defs). When ``target_callee`` is set, only report
    instructions that are calls to that callee.

    Also reports if the same use-list appears in multiple call instructions
    (same-argument evidence for double-free or use-after-free).

    Args:
        cfunc: Decompiled function whose microcode is inspected.
        target_callee: When non-empty, restrict reporting to call
            instructions whose callee name (after stripping a ``j_`` thunk
            prefix) contains this token.
        max_instructions: Upper bound on instructions scanned across all
            microcode blocks.

    Returns:
        A dict with the function entry address and name, the microcode
        maturity, block count, scanned and matched instruction counts,
        the per-instruction use/def lists, and any shared use-list
        patterns detected across calls.
    """
    import ida_hexrays

    mba = cfunc.mba
    target_fn = target_callee.strip().lower()
    instructions: list[dict[str, Any]] = []
    total_scanned = 0

    for bi in range(mba.qty):
        blk = mba.get_mblock(bi)
        ins = blk.head
        while ins and total_scanned < max_instructions:
            total_scanned += 1
            use = blk.build_use_list(ins, ida_hexrays.MUST_ACCESS)
            defs = blk.build_def_list(ins, ida_hexrays.MUST_ACCESS)
            u_str = use.dstr() if hasattr(use, 'dstr') else ''
            d_str = defs.dstr() if hasattr(defs, 'dstr') else ''

            # Determine if this is a call and the callee name
            callee_name: str | None = None
            is_call = ins.opcode == ida_hexrays.m_call
            if is_call:
                import ida_name as _ida_name
                try:
                    if hasattr(ins.l, 'helper') and ins.l.helper:
                        callee_name = str(ins.l.helper)
                    elif hasattr(ins.l, 'g'):
                        raw_g = ins.l.g
                        if isinstance(raw_g, int):
                            callee_name = _ida_name.get_ea_name(raw_g) or f'0x{raw_g:x}'
                        else:
                            callee_name = str(raw_g)
                except Exception:
                    pass

            # Filter by target callee if requested
            if target_fn:
                if not is_call:
                    ins = ins.next
                    continue
                callee_check = (callee_name or '').lower()
                callee_stripped = callee_check[2:] if callee_check.startswith('j_') else callee_check
                if target_fn not in callee_stripped:
                    ins = ins.next
                    continue

            instructions.append({
                'block': bi,
                'address': f'0x{ins.ea:x}',
                'opcode': ins.opcode,
                'is_call': is_call,
                'callee': callee_name,
                'use_list': u_str,
                'def_list': d_str,
            })
            ins = ins.next

    # Detect shared-use patterns (same use_list in multiple calls)
    call_uses: dict[str, list[dict[str, Any]]] = {}
    for entry in instructions:
        if entry['is_call'] and entry['use_list']:
            key = entry['use_list']
            call_uses.setdefault(key, []).append(entry)
    shared_args = [
        {
            'use_list': k,
            'call_count': len(v),
            'calls': [{'address': c['address'], 'callee': c['callee']} for c in v],
        }
        for k, v in call_uses.items()
        if len(v) > 1
    ]

    return {
        'entry_ea': f'0x{cfunc.entry_ea:x}',
        'function_name': _function_name(cfunc),
        'maturity': _maturity_const_to_name(getattr(mba, 'maturity', None)),
        'blocks': mba.qty,
        'instructions_scanned': total_scanned,
        'instructions_matched': len(instructions),
        'instructions': instructions,
        'shared_arg_patterns': shared_args,
    }



def microcode_value_ranges(cfunc: Any) -> dict[str, Any]:
    """Extract value-range annotations from the decompiler's microcode.

    IDA's value-range analysis computes constraints on variables at each
    basic block boundary (e.g. ``rcx.8:!=0`` means ``rcx`` is known
    non-zero). These are IR-backed bounds proofs, not heuristic guesses.

    We extract them from the microcode text representation because the
    programmatic ``get_valranges()`` API is fragile across maturity
    levels.

    Args:
        cfunc: Decompiled function whose microcode is inspected.

    Returns:
        A dict with the function entry address and name, microcode
        maturity, block count, the raw range annotations, and the
        variables classified as bounded versus unbounded.
    """
    import ida_hexrays

    mba = cfunc.mba
    printer = ida_hexrays.qstring_printer_t(cfunc, False)
    mba._print(printer)
    text = str(printer.s)

    # Parse VALRANGES lines from the microcode text
    # Format: '; VALRANGES: rcx.8:!=0' or '; VALRANGES: rsi.4:[0,0x40]'
    ranges: list[dict[str, Any]] = []
    current_block = -1
    for line in text.splitlines():
        stripped = line.strip()

        # Track block numbers (lines like '2. 0 ; 2WAY-BLOCK 2 ...')
        if '. 0 ;' in stripped and '-BLOCK' in stripped:
            parts = stripped.split('. 0 ;')[0].strip()
            try:
                current_block = int(parts)
            except ValueError:
                pass

        # Match VALRANGES annotation
        if 'VALRANGES:' in stripped:
            vr_text = stripped.split('VALRANGES:', 1)[1].strip()
            # Parse individual range entries (comma-separated)
            for entry in vr_text.split(','):
                entry = entry.strip()
                if not entry:
                    continue
                # Split variable:constraint (e.g., 'rcx.8:!=0')
                if ':' in entry:
                    parts = entry.split(':', 1)
                    var_name = parts[0].strip()
                    constraint = parts[1].strip()
                else:
                    var_name = entry
                    constraint = 'present'
                ranges.append({
                    'block': current_block,
                    'variable': var_name,
                    'constraint': constraint,
                })

    # Classify each variable's boundedness
    unbounded_vars: list[str] = []
    bounded_vars: list[dict[str, Any]] = []
    seen_vars = set()
    for r in ranges:
        v = r['variable']
        if v in seen_vars:
            continue
        seen_vars.add(v)
        c = r['constraint']
        # If constraint is just !=0 or similar, the value is still unbounded
        # If constraint contains a range like [0,64], it's bounded
        if '[' in c and ',' in c:
            bounded_vars.append({'variable': v, 'constraint': c})
        else:
            unbounded_vars.append(v)

    return {
        'entry_ea': f'0x{cfunc.entry_ea:x}',
        'function_name': _function_name(cfunc),
        'maturity': _maturity_const_to_name(getattr(mba, 'maturity', None)),
        'blocks': mba.qty,
        'range_annotations': ranges,
        'bounded_vars': bounded_vars,
        'unbounded_vars': unbounded_vars,
    }
