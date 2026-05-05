"""Proof tools — targeted SMT queries that prove/disprove vulnerability conditions.

Uses binbit (via smt_prover) for millisecond-scale bitvector proofs.
These tools turn heuristic verdicts from assess_exploitability into
proven results with concrete witness values.
"""
from __future__ import annotations

import re
from typing import Any

from .smt_prover import solve_smtlib

__all__ = ["prove_overflow"]


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
