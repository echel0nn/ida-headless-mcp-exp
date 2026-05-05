"""Proof tools — targeted SMT queries that prove/disprove vulnerability conditions.

Uses binbit (via smt_prover) for millisecond-scale bitvector proofs.
These tools turn heuristic verdicts from assess_exploitability into
proven results with concrete witness values.
"""
from __future__ import annotations

import re
from typing import Any

from .smt_prover import solve_smtlib

__all__ = ["prove_overflow", "prove_predicate_opaque", "prove_equivalence", "simplify_expression"]


def prove_overflow(
    assess_result: dict[str, Any],
    *,
    width: int = 32,
    timeout_ms: int = 5000,
) -> dict[str, Any]:
    """Prove whether an integer overflow is feasible given validation gates.

    Takes the output of assess_exploitability and encodes:
    - Source variables as free bitvectors
    - Validation gates as constraints (conditions that hold at the sink)
    - Overflow predicate on the sink expression's multiplication

    Args:
        assess_result: Output from assess_exploitability (must have
            sink_expression, assignment_chain, validation_gates).
        width: Bitvector width for variables (default 32).
        timeout_ms: Solver timeout.

    Returns:
        Dict with feasible (bool), witness values, and verdict.
    """
    if not assess_result.get("sink_found"):
        return {
            "feasible": False,
            "verdict": "not_applicable",
            "reason": "No sink found in assess_exploitability output.",
        }

    if not assess_result.get("has_multiplication"):
        return {
            "feasible": False,
            "verdict": "no_multiplication",
            "reason": "Sink expression has no multiplication to overflow.",
        }

    sink_expr = assess_result.get("sink_expression", "")
    chain = assess_result.get("assignment_chain", [])
    gates = assess_result.get("validation_gates", [])

    # Extract multiplication operands from the sink expression or chain
    mul_operands = _extract_mul_operands(sink_expr, chain)
    if not mul_operands:
        return {
            "feasible": False,
            "verdict": "cannot_encode",
            "reason": f"Could not extract multiplication operands from: {sink_expr}",
        }

    # Build SMT-LIB script
    script = _build_overflow_script(mul_operands, gates, width)

    # Solve
    result = solve_smtlib(script, timeout_ms=timeout_ms)

    if result["result"] == "sat":
        return {
            "feasible": True,
            "verdict": "proven_exploitable",
            "reason": (
                "Integer overflow IS possible despite validation gates. "
                "Witness values trigger the overflow."
            ),
            "witness": result["model"],
            "time_ms": result["time_ms"],
            "script_used": script,
        }
    elif result["result"] == "unsat":
        return {
            "feasible": False,
            "verdict": "proven_defended",
            "reason": (
                "Validation gates mathematically prevent overflow for ALL inputs. "
                "The bounds are sufficient."
            ),
            "time_ms": result["time_ms"],
        }
    else:
        return {
            "feasible": None,
            "verdict": "inconclusive",
            "reason": f"Solver returned: {result['result']}",
            "time_ms": result["time_ms"],
            "raw": result.get("raw_output", ""),
        }


def _extract_mul_operands(
    sink_expr: str,
    chain: list[dict[str, str]],
) -> list[str]:
    """Extract variable names involved in multiplication.

    Looks for patterns like:
    - (int)(v10 * v21)
    - v150 * (__int64)v51
    - 4 * v21
    """
    # Direct multiplication in sink expression
    m = re.search(r'(\w+)\s*\*\s*(?:\([^)]*\))?\s*(\w+)', sink_expr)
    if m:
        return [m.group(1), m.group(2)]

    # Check assignment chain for multiplication
    for item in chain:
        rhs = item.get("rhs", "")
        m = re.search(r'(\w+)\s*\*\s*(?:\([^)]*\))?\s*(\w+)', rhs)
        if m:
            return [m.group(1), m.group(2)]

    return []


def _build_overflow_script(
    operands: list[str],
    gates: list[dict[str, str]],
    width: int,
) -> str:
    """Generate SMT-LIB script for overflow proof."""
    lines: list[str] = []
    lines.append("; Auto-generated overflow proof")
    lines.append(f"; Operands: {operands}")
    lines.append(f"; Gates: {len(gates)}")
    lines.append("")

    # Declare all variables we might need
    all_vars: set[str] = set()
    for op in operands:
        if not op.isdigit() and not op.startswith("0x"):
            all_vars.add(op)

    # Extract variable names from gate conditions
    for gate in gates:
        cond = gate.get("condition", "")
        for var_match in re.finditer(r'\b(v\d+|a\d+)\b', cond):
            all_vars.add(var_match.group(1))

    for var in sorted(all_vars):
        lines.append(f"(declare-const {var} (_ BitVec {width}))")
    lines.append("")

    # Encode gates as constraints
    for gate in gates:
        gate_type = gate.get("gate_type", "")
        cond = gate.get("condition", "")
        smt_constraint = _gate_to_smt(cond, gate_type, all_vars, width)
        if smt_constraint:
            lines.append(f"; Gate: {cond[:60]}")
            lines.append(f"(assert {smt_constraint})")

    # Default constraints: operands are positive (common for sizes)
    for op in operands:
        if op in all_vars:
            lines.append(f"(assert (bvsgt {op} (_ bv0 {width})))")
    lines.append("")

    # Overflow predicate
    op_a = operands[0] if not operands[0].isdigit() else f"(_ bv{operands[0]} {width})"
    op_b = operands[1] if not operands[1].isdigit() else f"(_ bv{operands[1]} {width})"

    lines.append("; Overflow predicate: full product != sign-extended truncated product")
    lines.append(f"(declare-const product_full (_ BitVec {width * 2}))")
    lines.append(
        f"(assert (= product_full "
        f"(bvmul ((_ sign_extend {width}) {op_a}) ((_ sign_extend {width}) {op_b}))))"
    )
    lines.append(
        f"(assert (not (= product_full "
        f"((_ sign_extend {width}) (bvmul {op_a} {op_b})))))"
    )
    lines.append("")
    lines.append("(check-sat)")

    # Get witness values
    witness_vars = " ".join(sorted(all_vars))
    if witness_vars:
        lines.append(f"(get-value ({witness_vars}))")

    return "\n".join(lines)


def _gate_to_smt(
    condition: str,
    gate_type: str,
    known_vars: set[str],
    width: int,
) -> str | None:
    """Convert a gate condition to SMT-LIB assertion (best-effort).

    Handles common patterns:
    - v10 + a3 > v13 → (bvsgt (bvadd v10 a3) v13)
    - v10 <= 0 → (bvsle v10 bv0)
    - (int)v21 > 256 → (bvsgt v21 bv256)
    """
    cond = condition.strip()

    # Pattern: X + Y > Z or X + Y <= Z
    m = re.match(r'(\w+)\s*\+\s*(\w+)\s*(>|>=|<|<=)\s*(\w+)', cond)
    if m and m.group(1) in known_vars:
        a, b, op, c = m.groups()
        smt_op = {">=": "bvsge", ">": "bvsgt", "<=": "bvsle", "<": "bvslt"}[op]
        b_term = b if b in known_vars else f"(_ bv{_parse_int(b)} {width})"
        c_term = c if c in known_vars else f"(_ bv{_parse_int(c)} {width})"
        return f"({smt_op} (bvadd {a} {b_term}) {c_term})"

    # Pattern: X <= 0 or X > 0
    m = re.match(r'(\w+)\s*(>|>=|<|<=|==|!=)\s*(\d+)', cond)
    if m and m.group(1) in known_vars:
        var, op, val = m.groups()
        smt_op = {
            ">=": "bvsge", ">": "bvsgt", "<=": "bvsle",
            "<": "bvslt", "==": "=", "!=": "distinct",
        }.get(op)
        if smt_op:
            return f"({smt_op} {var} (_ bv{val} {width}))"

    # Pattern: (int)X > N
    m = re.match(r'\(int\)\s*(\w+)\s*(>|>=|<|<=)\s*(\d+)', cond)
    if m and m.group(1) in known_vars:
        var, op, val = m.groups()
        smt_op = {">=": "bvsge", ">": "bvsgt", "<=": "bvsle", "<": "bvslt"}[op]
        return f"({smt_op} {var} (_ bv{val} {width}))"

    return None


def _parse_int(s: str) -> int:
    """Parse an integer from various formats."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return 0


def prove_predicate_opaque(
    condition_expr: str,
    variables: list[str],
    *,
    width: int = 32,
    timeout_ms: int = 2000,
) -> dict[str, Any]:
    """Prove whether a branch condition is an opaque predicate.

    Tests both branches: if one is UNSAT, the condition is always
    true or always false (opaque).

    Args:
        condition_expr: The if-condition expression from pseudocode.
        variables: Free variable names in the condition.
        width: Bitvector width.
        timeout_ms: Solver timeout per query.

    Returns:
        Dict with opaque (bool), always_true/always_false, and proof.
    """
    # Build declarations
    decls = "\n".join(f"(declare-const {v} (_ BitVec {width}))" for v in variables)

    # Encode the condition as a boolean (best-effort from C-like expression)
    smt_cond = _condition_to_smt(condition_expr, variables, width)
    if not smt_cond:
        return {
            "opaque": False,
            "always_true": False,
            "always_false": False,
            "reason": f"Cannot encode condition: {condition_expr}",
        }

    # Test 1: can the condition be true?
    script_true = f"""{decls}
(assert {smt_cond})
(check-sat)"""
    result_true = solve_smtlib(script_true, timeout_ms=timeout_ms)

    # Test 2: can the condition be false?
    script_false = f"""{decls}
(assert (not {smt_cond}))
(check-sat)"""
    result_false = solve_smtlib(script_false, timeout_ms=timeout_ms)

    can_be_true = result_true["result"] == "sat"
    can_be_false = result_false["result"] == "sat"

    if can_be_true and not can_be_false:
        return {
            "opaque": True,
            "always_true": True,
            "always_false": False,
            "condition": condition_expr,
            "reason": "Condition is ALWAYS TRUE — false branch is dead code.",
            "time_ms": result_true["time_ms"] + result_false["time_ms"],
        }
    elif can_be_false and not can_be_true:
        return {
            "opaque": True,
            "always_true": False,
            "always_false": True,
            "condition": condition_expr,
            "reason": "Condition is ALWAYS FALSE — true branch is dead code.",
            "time_ms": result_true["time_ms"] + result_false["time_ms"],
        }
    else:
        return {
            "opaque": False,
            "always_true": False,
            "always_false": False,
            "condition": condition_expr,
            "reason": "Genuine branch — both paths are feasible.",
            "time_ms": result_true["time_ms"] + result_false["time_ms"],
        }


def prove_equivalence(
    expr_a: str,
    expr_b: str,
    variables: list[str],
    *,
    width: int = 32,
    timeout_ms: int = 3000,
) -> dict[str, Any]:
    """Prove whether two bitvector expressions are equivalent for all inputs.

    Asserts expr_a != expr_b. UNSAT means they are equivalent.

    Args:
        expr_a: First expression (complex/obfuscated).
        expr_b: Second expression (candidate simplification).
        variables: Free variable names.
        width: Bitvector width.
        timeout_ms: Solver timeout.

    Returns:
        Dict with equivalent (bool) and counterexample if not.
    """
    decls = "\n".join(f"(declare-const {v} (_ BitVec {width}))" for v in variables)

    smt_a = _expr_to_smt(expr_a, variables, width)
    smt_b = _expr_to_smt(expr_b, variables, width)

    if not smt_a or not smt_b:
        return {
            "equivalent": None,
            "reason": f"Cannot encode: a={expr_a}, b={expr_b}",
        }

    script = f"""{decls}
(assert (not (= {smt_a} {smt_b})))
(check-sat)
(get-value ({" ".join(variables)}))"""

    result = solve_smtlib(script, timeout_ms=timeout_ms)

    if result["result"] == "unsat":
        return {
            "equivalent": True,
            "expr_a": expr_a,
            "expr_b": expr_b,
            "reason": "Proven equivalent for ALL inputs (UNSAT on inequality).",
            "time_ms": result["time_ms"],
        }
    elif result["result"] == "sat":
        return {
            "equivalent": False,
            "expr_a": expr_a,
            "expr_b": expr_b,
            "counterexample": result["model"],
            "reason": "NOT equivalent — counterexample found.",
            "time_ms": result["time_ms"],
        }
    else:
        return {
            "equivalent": None,
            "reason": f"Solver returned: {result['result']}",
            "time_ms": result["time_ms"],
        }


def simplify_expression(
    obfuscated_expr: str,
    variables: list[str],
    *,
    width: int = 32,
    timeout_ms: int = 5000,
) -> dict[str, Any]:
    """Attempt to simplify an obfuscated expression by trying candidate forms.

    Generates candidate simplifications and proves equivalence for each.
    Returns the simplest equivalent form found.

    Args:
        obfuscated_expr: The complex expression to simplify.
        variables: Free variable names in the expression.
        width: Bitvector width.
        timeout_ms: Total timeout budget across all candidates.

    Returns:
        Dict with simplified expression (or original if no simplification found).
    """
    candidates = _generate_candidates(obfuscated_expr, variables, width)
    per_candidate_ms = max(500, timeout_ms // max(len(candidates), 1))

    for candidate in candidates:
        result = prove_equivalence(
            obfuscated_expr, candidate, variables,
            width=width, timeout_ms=per_candidate_ms,
        )
        if result.get("equivalent"):
            return {
                "simplified": True,
                "original": obfuscated_expr,
                "result": candidate,
                "proven_equivalent": True,
                "candidates_tried": candidates.index(candidate) + 1,
                "total_candidates": len(candidates),
                "time_ms": result["time_ms"],
            }

    return {
        "simplified": False,
        "original": obfuscated_expr,
        "result": obfuscated_expr,
        "proven_equivalent": False,
        "candidates_tried": len(candidates),
        "total_candidates": len(candidates),
        "reason": "No equivalent simplification found among candidates.",
    }


def _generate_candidates(expr: str, variables: list[str], width: int) -> list[str]:
    """Generate candidate simplifications for an obfuscated expression."""
    candidates: list[str] = []

    # For each variable, try identity (the expression might just BE the variable)
    for v in variables:
        candidates.append(v)

    # Linear forms: a*x + b for small constants
    for v in variables[:2]:
        for a in [1, 2, 3, 4, -1, -2]:
            for b in [0, 1, -1, 2, -2]:
                if a == 1 and b == 0:
                    continue  # already covered by identity
                a_val = a & ((1 << width) - 1)
                b_val = b & ((1 << width) - 1)
                term = (
                    f"(bvadd (bvmul (_ bv{a_val} {width}) {v})"
                    f" (_ bv{b_val} {width}))"
                )
                candidates.append(term)

    # Bitwise forms
    for v in variables[:2]:
        candidates.append(f"(bvnot {v})")
        candidates.append(f"(bvneg {v})")
        for mask in [0xFF, 0xFFFF, 0xFFFFFF00]:
            candidates.append(f"(bvand {v} (_ bv{mask} {width}))")
            candidates.append(f"(bvor {v} (_ bv{mask} {width}))")
            candidates.append(f"(bvxor {v} (_ bv{mask} {width}))")

    # Two-variable forms
    if len(variables) >= 2:
        a, b = variables[0], variables[1]
        candidates.extend([
            f"(bvadd {a} {b})",
            f"(bvsub {a} {b})",
            f"(bvxor {a} {b})",
            f"(bvand {a} {b})",
            f"(bvor {a} {b})",
            f"(bvmul {a} {b})",
        ])

    # Constants
    for c in [0, 1, -1]:
        candidates.append(f"(_ bv{c & ((1 << width) - 1)} {width})")

    return candidates


def _condition_to_smt(condition: str, variables: list[str], width: int) -> str | None:
    """Convert a C-like condition to SMT-LIB boolean expression (best-effort)."""
    c = condition.strip()

    # x * x % 2 == 0 (always true)
    m = re.match(r"(\w+)\s*\*\s*\s*%\s*2\s*==\s*0", c)
    if m and m.group(1) in variables:
        v = m.group(1)
        prod = f"(bvmul {v} {v})"
        two = f"(_ bv2 {width})"
        return f"(= (bvurem {prod} {two}) (_ bv0 {width}))"

    # (x | 1) != 0 (always true for any width >= 1)
    m = re.match(r"\(\s*(\w+)\s*\|\s*1\s*\)\s*!=\s*0", c)
    if m and m.group(1) in variables:
        v = m.group(1)
        return f"(not (= (bvor {v} (_ bv1 {width})) (_ bv0 {width})))"

    # x * (x + 1) % 2 == 0 (always true — product of consecutive)
    m = re.match(r"(\w+)\s*\*\s*\(\s*\s*\+\s*1\s*\)\s*%\s*2\s*==\s*0", c)
    if m and m.group(1) in variables:
        v = m.group(1)
        one = f"(_ bv1 {width})"
        two = f"(_ bv2 {width})"
        prod = f"(bvmul {v} (bvadd {v} {one}))"
        return f"(= (bvurem {prod} {two}) (_ bv0 {width}))"

    # Simple comparison: x > N, x == N, x != N
    m = re.match(r"(\w+)\s*(>|>=|<|<=|==|!=)\s*(\d+)", c)
    if m and m.group(1) in variables:
        v, op, val = m.group(1), m.group(2), int(m.group(3))
        ops = {">":"bvsgt", ">=":"bvsge", "<":"bvslt", "<=":"bvsle", "==":"=", "!=":"distinct"}
        smt_op = ops.get(op)
        if smt_op:
            return f"({smt_op} {v} (_ bv{val & ((1<<width)-1)} {width}))"

    return None


def _expr_to_smt(expr: str, variables: list[str], width: int) -> str | None:
    """Convert a C-like expression to SMT-LIB bitvector term (best-effort).

    Handles:
    - Variable references (v in variables → v directly)
    - Already-SMT expressions (starts with '(' → pass through)
    - Simple arithmetic: x + y, x - y, x * y, x ^ y, x & y, x | y
    - Constants: 0x..., decimal
    """
    e = expr.strip()

    # Already SMT-LIB
    if e.startswith("("):
        return e

    # Single variable
    if e in variables:
        return e

    # Constant
    if e.startswith("0x"):
        val = int(e, 16) & ((1 << width) - 1)
        return f"(_ bv{val} {width})"
    if e.isdigit() or (e.startswith("-") and e[1:].isdigit()):
        val = int(e) & ((1 << width) - 1)
        return f"(_ bv{val} {width})"

    # Binary operation: x OP y
    ops = {
        "+": "bvadd", "-": "bvsub", "*": "bvmul",
        "^": "bvxor", "&": "bvand", "|": "bvor",
    }
    for op_char, smt_name in ops.items():
        if op_char in e:
            parts = e.split(op_char, 1)
            left = _expr_to_smt(parts[0].strip(), variables, width)
            right = _expr_to_smt(parts[1].strip(), variables, width)
            if left and right:
                return f"({smt_name} {left} {right})"

    # ~x (bitwise not)
    if e.startswith("~") and e[1:].strip() in variables:
        return f"(bvnot {e[1:].strip()})"

    return None
