from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "decompile_cfunc",
    "query_ctree_calls",
    "get_microcode_text",
    "trace_ctree_dataflow",
    "interprocedural_taint",
    "get_argument_names",
    "query_ctree_call_sequences",
    "query_ctree_unchecked_calls",
    "get_hexrays_warnings",
    "pseudocode_slice",
    "microcode_def_use",
    "microcode_value_ranges",
    "constrained_reachability",
    "assess_exploitability",
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



# ======================================================================
# Inter-procedural taint tracing
# ======================================================================


def interprocedural_taint(
    sink_function: str,
    sink_argument_index: int,
    source_functions: list[str] | None = None,
    max_depth: int = 5,
) -> dict[str, Any]:
    """Trace data flow from sink argument backward across function boundaries.

    Algorithm:
    1. Find all call sites of sink_function
    2. For each call site, identify the argument expression
    3. If the argument is a function parameter, follow callers
    4. Recurse until hitting a source function or max_depth

    Args:
        sink_function: Name of the dangerous sink (e.g., 'system', 'memcpy').
        sink_argument_index: Which argument to trace (0-based).
        source_functions: Stop tracing when we reach one of these
            (e.g., ['recv', 'ReadFile', 'WinHttpReadData']).
        max_depth: Maximum call-chain hops.

    Returns:
        Dict with chains showing data propagation paths from sources to sink.
    """
    import ida_funcs
    import ida_name
    import idautils

    sources = [s.lower() for s in (source_functions or [])]

    # Step 1: Find all xrefs to the sink
    sink_ea = None
    for ea in idautils.Functions():
        name = ida_name.get_ea_name(ea).lower()
        norm = name.lstrip('_').replace('j_', '')
        # Strip A/W/Ex suffixes for API matching
        for suffix in ('exa', 'exw', 'a', 'w'):
            if norm.endswith(suffix) and len(norm) > len(suffix):
                norm = norm[:-len(suffix)]
                break
        if norm == sink_function.lower() or name == sink_function.lower():
            sink_ea = ea
            break

    if sink_ea is None:
        return {
            "sink_function": sink_function,
            "sink_found": False,
            "chains": [],
            "message": f"Sink function '{sink_function}' not found in binary.",
        }

    # Step 2: Find all callers of the sink
    caller_sites: list[tuple[int, int]] = []  # (caller_func_ea, call_site_ea)
    for xref in idautils.XrefsTo(sink_ea, 0):
        caller_func = ida_funcs.get_func(xref.frm)
        if caller_func:
            caller_sites.append((caller_func.start_ea, xref.frm))

    chains: list[dict[str, Any]] = []

    for caller_ea, site_ea in caller_sites:
        # Decompile the caller and trace the argument
        chain = _trace_interprocedural_chain(
            caller_ea, site_ea, sink_function, sink_argument_index,
            sources, max_depth, depth=0,
        )
        if chain:
            chains.append(chain)

    return {
        "sink_function": sink_function,
        "sink_argument_index": sink_argument_index,
        "sink_found": True,
        "call_sites": len(caller_sites),
        "chains": chains,
        "source_functions": source_functions or [],
    }


def _trace_interprocedural_chain(
    func_ea: int,
    call_site_ea: int,
    sink_function: str,
    arg_index: int,
    sources: list[str],
    max_depth: int,
    depth: int,
) -> dict[str, Any] | None:
    """Recursively trace one argument backward through the call chain."""
    import ida_funcs
    import ida_hexrays
    import ida_name
    import idautils

    if depth > max_depth:
        return None

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return None

    func_name = ida_name.get_ea_name(func.start_ea)

    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except ida_hexrays.DecompilationFailure:
        return None

    # Find the sink call in this function's CTree
    call_info = query_ctree_calls(
        cfunc, target_function=sink_function,
        argument_index=arg_index, limit=10,
    )

    # Find the specific call site
    target_arg_expr = None
    for match in call_info.get("matches", []):
        if match.get("address") == f"0x{call_site_ea:x}":
            args = match.get("args_preview", [])
            if arg_index < len(args):
                target_arg_expr = args[arg_index]
            break

    # If we couldn't find the exact site, try the first match
    if target_arg_expr is None and call_info.get("matches"):
        args = call_info["matches"][0].get("args_preview", [])
        if arg_index < len(args):
            target_arg_expr = args[arg_index]

    if target_arg_expr is None:
        return {
            "function": func_name,
            "address": f"0x{func_ea:x}",
            "depth": depth,
            "argument_expression": None,
            "origin": "unknown",
            "upstream": None,
        }

    # Trace backward within this function
    trace = trace_ctree_dataflow(
        cfunc,
        sink_function=sink_function,
        sink_argument_index=arg_index,
        source_contains=sources,
        max_steps=15,
    )

    # Determine origin
    origin = "local"  # data originates in this function
    final_expr = target_arg_expr
    if trace.get("chain"):
        final_expr = trace["chain"][-1].get("rhs", target_arg_expr)

    # Check if it's a source hit
    if trace.get("source_hit"):
        return {
            "function": func_name,
            "address": f"0x{func_ea:x}",
            "depth": depth,
            "argument_expression": target_arg_expr,
            "origin": "source",
            "source_term": trace.get("source_term"),
            "chain": trace.get("chain", []),
            "upstream": None,
        }

    # Check if the final expression is a function parameter (a1, a2, etc.)
    param_match = re.match(r'^a(\d+)$', _normalize_expr(final_expr))
    if param_match:
        param_idx = int(param_match.group(1)) - 1  # a1 → index 0
        # This argument came from a caller — recurse up
        upstream_chains: list[dict[str, Any]] = []
        for xref in idautils.XrefsTo(func_ea, 0):
            caller_func = ida_funcs.get_func(xref.frm)
            if caller_func is None:
                continue
            up = _trace_interprocedural_chain(
                caller_func.start_ea, xref.frm, func_name, param_idx,
                sources, max_depth, depth + 1,
            )
            if up:
                upstream_chains.append(up)
            if len(upstream_chains) >= 3:  # limit fan-out
                break

        return {
            "function": func_name,
            "address": f"0x{func_ea:x}",
            "depth": depth,
            "argument_expression": target_arg_expr,
            "origin": "parameter",
            "parameter_index": param_idx,
            "chain": trace.get("chain", []),
            "upstream": upstream_chains if upstream_chains else None,
        }

    # Check if it comes from a call to something (e.g., recv() result)
    for src in sources:
        if src in final_expr.lower():
            return {
                "function": func_name,
                "address": f"0x{func_ea:x}",
                "depth": depth,
                "argument_expression": target_arg_expr,
                "origin": "source",
                "source_term": src,
                "chain": trace.get("chain", []),
                "upstream": None,
            }

    return {
        "function": func_name,
        "address": f"0x{func_ea:x}",
        "depth": depth,
        "argument_expression": target_arg_expr,
        "origin": origin,
        "final_expression": final_expr,
        "chain": trace.get("chain", []),
        "upstream": None,
    }


# ======================================================================
# Constrained reachability (Hex-Rays ranges + angr)
# ======================================================================


def constrained_reachability(
    binary_path: str,
    function_ea: int,
    sink_ea: int,
    value_ranges: list[dict[str, Any]],
    *,
    timeout_seconds: int = 60,
    max_steps: int = 200000,
) -> dict[str, Any]:
    """Prove reachability from function entry to sink using angr with IR constraints.

    Uses Hex-Rays value-range annotations to pre-constrain angr's initial
    state, pruning impossible paths early and reducing state explosion.

    Also hooks common library functions (strlen, memcpy, etc.) with
    summaries to avoid symbolic execution of known code.

    Args:
        binary_path: Path to the PE/ELF binary file.
        function_ea: Function entry address (source).
        sink_ea: Target address to prove reachable.
        value_ranges: Output from microcode_value_ranges — list of
            {block, variable, constraint} dicts.
        timeout_seconds: Maximum seconds for symbolic execution.
        max_steps: Maximum exploration steps.

    Returns:
        Dict with feasibility verdict, steps, elapsed time, and
        constraints used to seed the exploration.
    """
    import time

    import angr

    proj = angr.Project(binary_path, auto_load_libs=False)

    # Build initial state at function entry
    state = proj.factory.blank_state(addr=function_ea)

    # Apply Hex-Rays value-range constraints to initial state
    constraints_applied = []
    for vr in value_ranges:
        var = vr.get('variable', '')
        constraint = vr.get('constraint', '')

        # Parse register constraints (e.g., 'rbx.8:!=3', 'rax.8:!=0')
        reg_match = re.match(r'^(r\w+|e\w+)\.(\d+)$', var)
        if not reg_match:
            continue
        reg_name = reg_match.group(1)
        _reg_bytes = int(reg_match.group(2))  # noqa: F841

        try:
            reg_val = getattr(state.regs, reg_name, None)
            if reg_val is None:
                continue
        except (AttributeError, KeyError):
            continue

        # Parse constraint type
        if constraint.startswith('!='):
            # != value constraint
            try:
                raw = constraint[2:]
                is_hex = 'x' in raw.lower() or any(c in raw for c in 'abcdefABCDEF')
                val = int(raw, 16) if is_hex else int(raw)
                state.solver.add(reg_val != val)
                constraints_applied.append(f"{reg_name} != {val}")
            except ValueError:
                pass
        elif constraint.startswith('[') and ',' in constraint:
            # Range constraint [low, high]
            try:
                parts = constraint.strip('[]').split(',')
                low = int(parts[0].strip(), 0)
                high = int(parts[1].strip(), 0)
                state.solver.add(reg_val >= low)
                state.solver.add(reg_val <= high)
                constraints_applied.append(f"{reg_name} in [{low}, {high}]")
            except (ValueError, IndexError):
                pass

    # Hook common library functions with simprocedures to avoid explosion
    hooked = []
    for name in ('strlen', 'strcmp', 'memcpy', 'memset', 'malloc', 'free',
                 'fopen', 'fclose', 'fwrite', 'fread', 'printf', 'puts'):
        if proj.loader.find_symbol(name):
            proj.hook_symbol(name, angr.SIM_PROCEDURES['libc'][name](), replace=True)
            hooked.append(name)

    simgr = proj.factory.simulation_manager(state)

    t0 = time.monotonic()
    deadline = t0 + timeout_seconds
    steps_taken = 0
    found = False
    timed_out = False

    try:
        while simgr.active and steps_taken < max_steps:
            if time.monotonic() > deadline:
                timed_out = True
                break
            simgr.step()
            steps_taken += 1
            # Check if any state reached the sink
            simgr.move(from_stash='active', to_stash='found',
                      filter_func=lambda s: s.addr == sink_ea)
            if simgr.found:
                found = True
                break
            # Cap active states
            if len(simgr.active) > 128:
                simgr.active = simgr.active[:128]
    except Exception:
        pass

    elapsed = time.monotonic() - t0

    result: dict[str, Any] = {
        'source': f'0x{function_ea:x}',
        'sink': f'0x{sink_ea:x}',
        'feasible': found,
        'verdict': 'reachable' if found else ('timeout' if timed_out else 'unreachable'),
        'steps': steps_taken,
        'elapsed_s': round(elapsed, 2),
        'constraints_applied': constraints_applied,
        'hooks_applied': hooked,
        'active_states_at_end': len(simgr.active),
    }

    # If found, extract witness
    if found and simgr.found:
        witness = simgr.found[0]
        result['witness_constraints'] = len(witness.solver.constraints)

    return result



# ======================================================================
# Exploitability assessment - deep taint + validation gate detection
# ======================================================================


def assess_exploitability(
    cfunc: Any,
    sink_function: str,
    sink_argument_index: int,
) -> dict[str, Any]:
    """Assess whether a sink argument is exploitable in this function.

    Performs three analyses:
    1. Deep backward taint with arithmetic tracking and source classification.
    2. Validation gate detection via CTree if-statement walking.
    3. Verdict computation combining source + arithmetic + gates.

    Args:
        cfunc: Decompiled function (from decompile_cfunc).
        sink_function: Dangerous callee name.
        sink_argument_index: Which argument to assess (0-based).

    Returns:
        Dict with source_type, arithmetic_chain, validation_gates, and verdict.
    """
    import ida_hexrays

    func_name = _function_name(cfunc)
    func_ea = f"0x{cfunc.entry_ea:x}"

    # Try multiple name variants to find the sink call
    # IDA may name it differently: memmove, j_memmove, _memmove, etc.
    sink_lower = sink_function.lower().lstrip('_')
    variants = [
        sink_function,
        f"j_{sink_function}",
        f"_{sink_function}",
        sink_lower,
    ]

    sink_info = None
    for variant in variants:
        info = query_ctree_calls(
            cfunc, target_function=variant,
            argument_index=sink_argument_index, limit=5,
        )
        if info["matches"]:
            sink_info = info
            break

    # Fallback: scan ALL calls and match by substring
    if sink_info is None:
        info = query_ctree_calls(cfunc, target_function="", limit=200)
        for m in info.get("matches", []):
            callee = (m.get("callee_name") or m.get("callee_expr") or "").lower()
            if sink_lower in callee and m.get("arg_count", 0) > sink_argument_index:
                sink_info = {"matches": [m]}
                break

    if sink_info is None or not sink_info["matches"]:
        return {
            "function": func_name, "address": func_ea,
            "sink_function": sink_function, "sink_found": False,
            "verdict": "not_applicable",
        }

    match = sink_info["matches"][0]
    sink_expr = match["args_preview"][sink_argument_index]
    sink_addr = match["address"]

    # Deep backward trace with arithmetic tracking
    assignments = _collect_assignments(cfunc)
    arithmetic_ops: list[str] = []
    source_type = "unknown"
    current = _normalize_expr(sink_expr)
    chain: list[dict[str, str]] = []
    seen: set[str] = set()

    for _ in range(20):
        if current in seen:
            break
        seen.add(current)
        if _is_parameter(current):
            source_type = "function_parameter"
            break
        if _is_struct_field_read(current):
            source_type = "struct_field"
            break
        if _is_constant(current):
            source_type = "constant"
            break
        if _contains_call(current):
            source_type = "call_result"
            break
        found = None
        for item in reversed(assignments):
            if item["lhs_norm"] == current:
                found = item
                break
        if found is None:
            break
        rhs = found["rhs"]
        chain.append({"lhs": found["lhs"], "rhs": rhs, "address": found["address"]})
        if any(op in rhs for op in ("*", "<<", "+", "-", "/", "%")):
            arithmetic_ops.append(rhs)
        current = found["rhs_norm"]

    if source_type == "struct_field":
        source_type = "file_header_field"
    elif source_type == "call_result":
        if any(f in current.lower() for f in ("fread", "readfile", "recv")):
            source_type = "external_read"

    # Validation gate detection
    sink_var = _normalize_expr(sink_expr)
    tainted_vars = {sink_var} | {_normalize_expr(c["lhs"]) for c in chain}

    class _GateVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.found_gates: list[dict[str, str]] = []
            self.sink_ea = int(sink_addr, 16) if sink_addr.startswith("0x") else 0

        def visit_insn(self, insn):
            if insn.op != ida_hexrays.cit_if:
                return 0
            cond_preview = _expr_preview(insn.cif.expr, cfunc)
            for tvar in tainted_vars:
                if tvar.lower() in cond_preview.lower():
                    gate_type = _classify_gate(cond_preview, tvar)
                    if insn.ea < self.sink_ea or insn.ea == 0:
                        self.found_gates.append({
                            "address": f"0x{insn.ea:x}",
                            "condition": cond_preview,
                            "variable": tvar,
                            "gate_type": gate_type,
                        })
            return 0

    gv = _GateVisitor()
    gv.apply_to(cfunc.body, None)
    gates = gv.found_gates

    has_upper = any(g["gate_type"] == "upper_bound" for g in gates)
    has_ovf = any(g["gate_type"] == "overflow_check" for g in gates)
    has_mul = any("*" in op or "<<" in op for op in arithmetic_ops)
    is_ext = source_type in ("file_header_field", "external_read", "function_parameter")

    if not is_ext:
        verdict, reason = "low_risk", f"Source is '{source_type}' - not attacker-controlled."
    elif has_ovf:
        verdict, reason = "defended", "Overflow check detected before the sink."
    elif has_upper and not has_mul:
        verdict, reason = "defended", "Upper bound check caps the value."
    elif has_mul and not has_upper:
        verdict, reason = "likely_exploitable", (
            "Unchecked multiplication on attacker-controlled value. Integer overflow.")
    elif is_ext and not gates:
        verdict, reason = "likely_exploitable", (
            "Attacker-controlled value reaches the sink with no validation.")
    elif is_ext and has_upper:
        verdict, reason = "possibly_defended", "Bound exists but arithmetic may bypass."
    else:
        verdict, reason = "needs_review", "Mixed signals."

    return {
        "function": func_name, "address": func_ea,
        "sink_function": sink_function,
        "sink_argument_index": sink_argument_index,
        "sink_expression": sink_expr, "sink_found": True,
        "source_type": source_type, "source_expression": current,
        "arithmetic_chain": arithmetic_ops,
        "assignment_chain": chain,
        "validation_gates": gates,
        "has_multiplication": has_mul,
        "has_upper_bound": has_upper,
        "has_overflow_check": has_ovf,
        "verdict": verdict, "verdict_reason": reason,
    }


def _is_parameter(expr: str) -> bool:
    return bool(re.match(r"^a\d+$", expr))


def _is_struct_field_read(expr: str) -> bool:
    return ("*(" in expr or "->" in expr
            or bool(re.search(r"\*\(_\w+\s*\*\)", expr))
            or ("+" in expr and "*" in expr and "(" in expr))


def _is_constant(expr: str) -> bool:
    e = expr.strip().rstrip("uUlL")
    if e.startswith("0x") or e.startswith("-0x"):
        return True
    try:
        int(e)
        return True
    except ValueError:
        return False


def _contains_call(expr: str) -> bool:
    return bool(re.search(r"\w+\s*\(", expr))


def _classify_gate(condition: str, variable: str) -> str:
    cond = condition.lower()
    if "/" in cond and "*" in cond:
        return "overflow_check"
    if "overflow" in cond:
        return "overflow_check"
    if any(op in cond for op in (">", ">=", "<=", "<")):
        if variable.lower() in cond:
            if ">" in cond or ">=" in cond:
                return "upper_bound"
            if "<" in cond or "<=" in cond:
                return "lower_bound"
    if "== 0" in cond or "!= 0" in cond:
        return "null_check"
    if "size" in cond or "len" in cond or "max" in cond:
        return "size_bound"
    return "conditional"
