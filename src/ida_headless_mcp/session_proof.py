from __future__ import annotations

from typing import Any

from .guards import requires
from .lifecycle import BinaryState

__all__ = ["ProofMixin"]


class ProofMixin:
    """Proof and taint tool implementations."""

    @requires(BinaryState.ACTIVE)
    def trace_dataflow(
        self,
        binary_id: str,
        address_or_name: str,
        *,
        sink_function: str,
        sink_argument_index: int,
        source_contains: list[str] | None = None,
        max_steps: int = 10,
    ) -> dict[str, Any]:
        import ida_funcs

        from .hexrays_analysis import decompile_cfunc, trace_ctree_dataflow
        from .session import _resolve_address

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        payload = trace_ctree_dataflow(
            cfunc,
            sink_function=sink_function,
            sink_argument_index=sink_argument_index,
            source_contains=source_contains,
            max_steps=max_steps,
        )
        payload["binary_id"] = binary_id

        return payload

    @requires(BinaryState.ACTIVE)
    def interprocedural_taint(
        self,
        binary_id: str,
        sink_function: str,
        sink_argument_index: int,
        *,
        source_functions: list[str] | None = None,
        max_depth: int = 5,
    ) -> dict[str, Any]:
        """Trace data flow from sink backward across function boundaries."""
        from .hexrays_analysis import interprocedural_taint
        result = interprocedural_taint(
            sink_function=sink_function,
            sink_argument_index=sink_argument_index,
            source_functions=source_functions,
            max_depth=max_depth,
        )
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def prove_bounds_sufficient(
        self, binary_id: str, address_or_name: str,
        sink_function: str, sink_argument_index: int,
    ) -> dict[str, Any]:
        """Prove whether validation gates are sufficient to prevent overflow."""
        assess = self.assess_exploitability(
            binary_id, address_or_name, sink_function, sink_argument_index,
        )
        if not assess.get("sink_found"):
            return {**assess, "sufficient": None}
        from .proof import prove_bounds_sufficient
        result = prove_bounds_sufficient(assess)
        result["binary_id"] = binary_id
        result["function"] = assess.get("function", "")
        return result

    @requires(BinaryState.ACTIVE)
    def prove_predicate_opaque(self, binary_id: str, address_or_name: str, condition_address: str) -> dict[str, Any]:
        """Prove whether a branch condition is opaque."""
        import ida_funcs
        import re as _re
        from .hexrays_analysis import decompile_cfunc
        from .proof import prove_predicate_opaque
        from .session import _resolve_address
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        variables = sorted(set(_re.findall(r"\bv\d+\b", str(cfunc))))[:8]
        result = prove_predicate_opaque(condition_address, variables)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def prove_equivalence(self, binary_id: str, expr_a: str, expr_b: str, address_or_name: str) -> dict[str, Any]:
        """Prove two expressions equivalent."""
        import ida_funcs
        import re as _re
        from .hexrays_analysis import decompile_cfunc
        from .proof import prove_equivalence
        from .session import _resolve_address
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        variables = sorted(set(_re.findall(r"\bv\d+\b", str(cfunc))))[:8]
        result = prove_equivalence(expr_a, expr_b, variables)
        result["binary_id"] = binary_id
        return result

    @requires(BinaryState.ACTIVE)
    def prove_overflow(
        self,
        binary_id: str,
        address_or_name: str,
        sink_function: str,
        sink_argument_index: int,
    ) -> dict[str, Any]:
        """Prove overflow using CTree-to-SMT encoding + binbit solver."""
        import ida_funcs
        import ida_hexrays

        from .ctree_to_smt import SMTContext, condition_to_smt
        from .hexrays_analysis import (
            decompile_cfunc,
            query_ctree_calls,
        )
        from .session import _resolve_address
        from .smt_prover import binbit_available, solve_smtlib

        # Get the assess result first (for verdict context)
        assess = self.assess_exploitability(
            binary_id, address_or_name, sink_function, sink_argument_index,
        )
        if not assess.get('sink_found'):
            return {**assess, 'proof': 'not_applicable'}
        if not assess.get('has_multiplication'):
            return {**assess, 'verdict': 'no_multiplication'}

        # Decompile and find the sink + gates via CTree
        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            return {**assess, 'verdict': 'decompile_failed'}
        cfunc = decompile_cfunc(func)

        # Find sink call in CTree
        sink_info = query_ctree_calls(
            cfunc, target_function=sink_function,
            argument_index=sink_argument_index, limit=5,
        )
        if not sink_info.get('matches'):
            # Fallback to text-based proof
            from .proof import prove_overflow
            result = prove_overflow(assess)
            result['binary_id'] = binary_id
            result['encoding'] = 'text_fallback'
            return result

        # Build SMT script from CTree
        ctx = SMTContext()
        script_lines = ['; CTree-encoded overflow proof']

        # Encode validation gates from CTree if-conditions
        gates_encoded = 0
        class _GateFinder(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)
                self.gate_smts: list[str] = []
                self.sink_ea = int(sink_info['matches'][0]['address'], 16)

            def visit_insn(self, insn):
                if insn.op != ida_hexrays.cit_if:
                    return 0
                if insn.ea < self.sink_ea or insn.ea == 0:
                    smt = condition_to_smt(insn.cif.expr, ctx)
                    if smt:
                        self.gate_smts.append(smt)
                return 0

        gf = _GateFinder()
        gf.apply_to(cfunc.body, None)

        # Add declarations
        script_lines.append(ctx.get_declarations_smt())
        script_lines.append('')

        # Assert gate negations (at sink, gates did NOT fire)
        for smt in gf.gate_smts:
            script_lines.append(f'(assert (not {smt}))')
            gates_encoded += 1

        # Find multiplication operands from sink expression
        match = sink_info['matches'][0]
        if sink_argument_index < len(match.get('args_preview', [])):
            # Add overflow predicate for all declared vars
            vars_list = sorted(ctx.declarations.keys())
            if len(vars_list) >= 2:
                a, b = vars_list[0], vars_list[1]
                w = ctx.declarations[a]
                script_lines.append('')
                script_lines.append(f'(assert (bvsgt {a} (_ bv0 {w})))')
                script_lines.append(f'(assert (bvsgt {b} (_ bv0 {w})))')
                script_lines.append(f'(declare-const _pf (_ BitVec {w*2}))')
                script_lines.append(
                    f'(assert (= _pf (bvmul '
                    f'((_ sign_extend {w}) {a}) '
                    f'((_ sign_extend {w}) {b}))))'
                )
                script_lines.append(
                    f'(assert (not (= _pf '
                    f'((_ sign_extend {w}) (bvmul {a} {b})))))'
                )
        script_lines.append('')
        script_lines.append('(check-sat)')
        witness_vars = ' '.join(sorted(ctx.declarations.keys()))
        if witness_vars:
            script_lines.append(f'(get-value ({witness_vars}))')

        script = '\n'.join(script_lines)

        if not binbit_available():
            return {
                **assess, 'verdict': 'solver_unavailable',
                'gates_encoded': gates_encoded,
                'encoding': 'ctree',
            }

        result = solve_smtlib(script)
        verdict = 'inconclusive'
        if result['result'] == 'sat':
            verdict = 'proven_exploitable'
        elif result['result'] == 'unsat':
            verdict = 'proven_defended'

        return {
            'binary_id': binary_id,
            'function': assess.get('function', ''),
            'address': assess.get('address', ''),
            'sink_expression': assess.get('sink_expression', ''),
            'verdict': verdict,
            'feasible': result['result'] == 'sat',
            'witness': result.get('model', {}),
            'time_ms': result.get('time_ms', 0),
            'gates_encoded': gates_encoded,
            'encoding': 'ctree',
            'source_type': assess.get('source_type', ''),
            'script': script,
        }

    @requires(BinaryState.ACTIVE)
    def assess_exploitability(
        self,
        binary_id: str,
        address_or_name: str,
        sink_function: str,
        sink_argument_index: int,
    ) -> dict[str, Any]:
        """Assess exploitability of a sink in a specific function."""
        import ida_funcs

        from .hexrays_analysis import assess_exploitability, decompile_cfunc
        from .session import _resolve_address

        ea = _resolve_address(address_or_name)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address_or_name!r}")
        cfunc = decompile_cfunc(func)
        result = assess_exploitability(cfunc, sink_function, sink_argument_index)
        result["binary_id"] = binary_id
        return result
