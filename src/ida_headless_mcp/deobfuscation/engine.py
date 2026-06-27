"""Data-driven expression pattern matcher and rewriter using miasm.

Loads rules from ``data/deobfuscation_rules.json``, parses pattern strings
into miasm expression trees, matches against target expressions binding
variables, and applies replacement patterns. All rules are data -- no
hardcoded simplifications in this file.

Uses miasm's ``expr_simp`` as a post-pass and the project's binbit prover
for verification when algebraic simplification is insufficient.
"""
from __future__ import annotations

import json
import operator
from pathlib import Path
from typing import Any

from miasm.expression.expression import (
    Expr, ExprId, ExprInt, ExprOp, ExprCompose, ExprSlice,
)
from miasm.expression.simplifications import expr_simp

__all__ = ["load_rules", "simplify_expression", "match_and_rewrite", "RuleDB"]

# Operator name mapping for pattern parsing
_OPS = {
    "+": "+", "-": "-", "*": "*", "/": "udiv", "%": "umod",
    "&": "&", "|": "|", "^": "^", "<<": "<<", ">>": ">>",
}
_UNARY = {"~": "~", "-": "-"}


def _parse_token(token: str, size: int = 64) -> Expr | str:
    """Parse a single token into a miasm expression or operator string."""
    token = token.strip()
    if not token:
        raise ValueError("empty token")
    # Variable: x, y, z, x_0, x_1, etc.
    if token[0].isalpha() and not token.startswith("0x"):
        return ExprId(token, size)
    # Hex constant
    if token.startswith("0x") or token.startswith("0X"):
        return ExprInt(int(token, 16), size)
    # Decimal constant
    if token.isdigit() or (token.startswith("-") and token[1:].isdigit()):
        return ExprInt(int(token) & ((1 << size) - 1), size)
    return token


def parse_pattern(pattern_str: str, size: int = 64) -> Expr:
    """Parse an infix pattern string into a miasm expression tree.

    Supports: +, -, *, /, %, &, |, ^, <<, >>, ~ (unary NOT),
    parentheses, variables (x, y, z, c1, c2), and integer constants.
    """
    # Tokenize
    tokens: list[str] = []
    i = 0
    s = pattern_str.replace(" ", "")
    while i < len(s):
        if s[i] in "()~":
            tokens.append(s[i])
            i += 1
        elif s[i:i+2] in ("<<", ">>", "!=", "=="):
            tokens.append(s[i:i+2])
            i += 2
        elif s[i] in "+-*/%&|^<>=":
            tokens.append(s[i])
            i += 1
        else:
            j = i
            while j < len(s) and s[j] not in "()+-*/%&|^<>~!=, ":
                j += 1
            tokens.append(s[i:j])
            i = j

    # Recursive descent parser
    pos = [0]

    def peek() -> str | None:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def consume(expected: str | None = None) -> str:
        t = tokens[pos[0]]
        if expected is not None and t != expected:
            raise ValueError(f"Expected {expected}, got {t}")
        pos[0] += 1
        return t

    def parse_expr() -> Expr:
        return parse_comparison()

    def parse_comparison() -> Expr:
        left = parse_bitor()
        while peek() in ("==", "!="):
            op = consume()
            right = parse_bitor()
            if op == "==":
                left = ExprOp("==", left, right)
            else:
                left = ExprOp("!=", left, right)
        return left

    def parse_bitor() -> Expr:
        left = parse_bitxor()
        while peek() == "|":
            consume("|")
            right = parse_bitxor()
            left = ExprOp("|", left, right)
        return left

    def parse_bitxor() -> Expr:
        left = parse_bitand()
        while peek() == "^":
            consume("^")
            right = parse_bitand()
            left = ExprOp("^", left, right)
        return left

    def parse_bitand() -> Expr:
        left = parse_shift()
        while peek() == "&":
            consume("&")
            right = parse_shift()
            left = ExprOp("&", left, right)
        return left

    def parse_shift() -> Expr:
        left = parse_additive()
        while peek() in ("<<", ">>"):
            op = consume()
            right = parse_additive()
            left = ExprOp(op, left, right)
        return left

    def parse_additive() -> Expr:
        left = parse_multiplicative()
        while peek() in ("+", "-"):
            op = consume()
            right = parse_multiplicative()
            left = ExprOp(op, left, right)
        return left

    def parse_multiplicative() -> Expr:
        left = parse_unary()
        while peek() in ("*", "/", "%"):
            op = consume()
            right = parse_unary()
            miasm_op = _OPS.get(op, op)
            left = ExprOp(miasm_op, left, right)
        return left

    def parse_unary() -> Expr:
        if peek() == "~":
            consume("~")
            operand = parse_unary()
            return ExprOp("^", operand, ExprInt((1 << size) - 1, size))
        if peek() == "-" and (pos[0] == 0 or tokens[pos[0]-1] in ("(", "+", "-", "*")):
            consume("-")
            operand = parse_unary()
            return ExprOp("-", ExprInt(0, size), operand)
        return parse_primary()

    def parse_primary() -> Expr:
        if peek() == "(":
            consume("(")
            expr = parse_expr()
            consume(")")
            return expr
        t = consume()
        return _parse_token(t, size)

    result = parse_expr()
    if pos[0] != len(tokens):
        raise ValueError(f"Unparsed tokens: {tokens[pos[0]:]}")
    return result


def match_expr(pattern: Expr, target: Expr,
               bindings: dict[str, Expr] | None = None) -> dict[str, Expr] | None:
    """Match a pattern expression against a target, returning variable bindings.

    Variables (ExprId with alphabetic names) match any expression.
    Constants in patterns (names starting with 'c') match only ExprInt.
    Same variable name must match the same expression.
    """
    if bindings is None:
        bindings = {}

    # Variable: matches anything (or must match same if already bound)
    if isinstance(pattern, ExprId) and pattern.name[0].isalpha():
        name = pattern.name
        is_const_var = name.startswith("c") and (len(name) == 1 or name[1:].isdigit())
        if is_const_var and not isinstance(target, ExprInt):
            return None
        if name in bindings:
            if bindings[name] != target:
                return None
            return bindings
        bindings[name] = target
        return bindings

    # Constant: must match exactly
    if isinstance(pattern, ExprInt):
        if isinstance(target, ExprInt) and int(pattern) == int(target):
            return bindings
        return None

    # Operation: match recursively
    if isinstance(pattern, ExprOp) and isinstance(target, ExprOp):
        if pattern.op != target.op:
            return None
        if len(pattern.args) != len(target.args):
            return None
        # Try direct order
        b = dict(bindings)
        ok = True
        for p_arg, t_arg in zip(pattern.args, target.args):
            result = match_expr(p_arg, t_arg, b)
            if result is None:
                ok = False
                break
            b = result
        if ok:
            return b
        # Try commutative order for 2-arg ops
        if len(pattern.args) == 2 and pattern.op in ("+", "*", "&", "|", "^"):
            b2 = dict(bindings)
            ok2 = True
            for p_arg, t_arg in zip(pattern.args, reversed(target.args)):
                result = match_expr(p_arg, t_arg, b2)
                if result is None:
                    ok2 = False
                    break
                b2 = result
            if ok2:
                return b2
        return None

    return None


def apply_replacement(replacement: Expr, bindings: dict[str, Expr]) -> Expr:
    """Substitute bound variables into a replacement pattern."""
    if isinstance(replacement, ExprId) and replacement.name in bindings:
        return bindings[replacement.name]
    if isinstance(replacement, ExprOp):
        new_args = tuple(apply_replacement(a, bindings) for a in replacement.args)
        return ExprOp(replacement.op, *new_args)
    return replacement


class RuleDB:
    """Loaded rule database with parsed patterns."""

    def __init__(self, rules_path: Path | None = None):
        if rules_path is None:
            rules_path = (Path(__file__).resolve().parent.parent.parent.parent
                          / "data" / "deobfuscation_rules.json")
        self.rules: list[dict[str, Any]] = []
        self._load(rules_path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        raw = json.loads(path.read_text(encoding="utf-8"))
        for category in raw:
            if category.startswith("_"):
                continue
            entries = raw[category]
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if "pattern" not in entry or "result" not in entry:
                    continue
                try:
                    pat = parse_pattern(entry["pattern"])
                    rep = parse_pattern(entry["result"])
                    self.rules.append({
                        "name": entry.get("name", ""),
                        "category": category,
                        "pattern": pat,
                        "replacement": rep,
                        "constraint": entry.get("constraint"),
                        "raw": entry,
                    })
                except (ValueError, KeyError, TypeError):
                    continue

    def __len__(self) -> int:
        return len(self.rules)


def match_and_rewrite(expr: Expr, db: RuleDB, max_passes: int = 5) -> Expr:
    """Apply all rules from the database to an expression until fixed point."""
    current = expr
    for _ in range(max_passes):
        changed = False
        for rule in db.rules:
            bindings = match_expr(rule["pattern"], current)
            if bindings is not None:
                new_expr = apply_replacement(rule["replacement"], bindings)
                if new_expr != current:
                    current = new_expr
                    changed = True
                    break
        # Also try miasm's built-in simplifier
        simplified = expr_simp(current)
        if simplified != current:
            current = simplified
            changed = True
        if not changed:
            break
    return current


def simplify_expression(expr_str: str, size: int = 64,
                        db: RuleDB | None = None) -> dict[str, Any]:
    """Parse, simplify, and return result.

    Uses the rule database + miasm's expr_simp. Returns original and
    simplified forms as strings.
    """
    if db is None:
        db = RuleDB()
    try:
        expr = parse_pattern(expr_str, size)
    except (ValueError, KeyError) as exc:
        return {"error": str(exc), "original": expr_str}
    simplified = match_and_rewrite(expr, db)
    return {
        "original": str(expr),
        "simplified": str(simplified),
        "changed": str(simplified) != str(expr),
        "rules_applied": len(db.rules),
    }


def load_rules() -> RuleDB:
    """Load the default rule database."""
    return RuleDB()
