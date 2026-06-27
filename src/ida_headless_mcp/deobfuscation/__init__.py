"""Deobfuscation engine -- data-driven expression rewriting + concrete emulation.

All rewrite rules live in ``data/deobfuscation_rules.json``. The engine
parses pattern strings into miasm expression trees, matches against IR
expressions, and applies replacements. No hardcoded rules in Python code.

Uses miasm's ``expr_simp`` for algebraic simplification and the project's
own binbit SMT prover for verification when simplification alone is
insufficient.
"""
from __future__ import annotations

__all__ = ["load_rules", "simplify_expression", "evaluate_concrete"]
